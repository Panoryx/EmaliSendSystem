package httpapi

import (
	"bytes"
	"context"
	"emailsendsystem/internal/app"
	"emailsendsystem/internal/domain"
	"emailsendsystem/internal/security"
	"emailsendsystem/internal/store"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type blockingRepository struct {
	app.MessageRepository
	entered chan struct{}
	release chan struct{}
}

func (b *blockingRepository) Enqueue(ctx context.Context, m domain.Message, key, hash string) (domain.Message, error) {
	close(b.entered)
	select {
	case <-b.release:
		return b.MessageRepository.Enqueue(ctx, m, key, hash)
	case <-ctx.Done():
		return m, ctx.Err()
	}
}
func TestHTTPAdmissionAndTokenRateLimit(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "mail.db"), store.Limits{QueueCount: 10, QueueBytes: 10000, Accounts: 128, Tokens: 256})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err = db.CreateToken(context.Background(), domain.Token{ID: "admin", Name: "admin", Admin: true, Hash: security.Hash("secret")}); err != nil {
		t.Fatal(err)
	}
	cipher, _ := security.New(bytes.Repeat([]byte{1}, 32))
	blocking := &blockingRepository{db, make(chan struct{}), make(chan struct{})}
	service := app.NewService(db, blocking, db, cipher, domain.RealClock{}, app.NewRegistry())
	handler := New(service, slog.New(slog.NewTextHandler(io.Discard, nil)), db.Ping, 1, 256, 20, 40)
	request := func(method, path, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer secret")
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Idempotency-Key", "once")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		done <- request("POST", "/api/v1/messages", `{"to":"to@example.com","subject":"s","text":"b"}`)
	}()
	select {
	case <-blocking.entered:
	case <-time.After(time.Second):
		t.Fatal("request did not enter")
	}
	second := request("GET", "/health/live", "")
	if second.Code != 503 {
		t.Fatal("admission is unbounded", second.Code)
	}
	close(blocking.release)
	if first := <-done; first.Code != 202 {
		t.Fatal(first.Code)
	}
	limited := false
	for i := 0; i < 100; i++ {
		if request(http.MethodGet, "/api/v1/accounts", "").Code == 429 {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatal("token bucket did not limit")
	}
}
