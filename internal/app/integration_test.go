package app_test

import (
	"bytes"
	"context"
	"emailsendsystem/internal/app"
	"emailsendsystem/internal/domain"
	"emailsendsystem/internal/httpapi"
	"emailsendsystem/internal/security"
	"emailsendsystem/internal/store"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type clock struct{ at time.Time }

func (c *clock) Now() time.Time { return c.at }

type fixture struct {
	s     *app.Service
	db    *store.Store
	admin domain.Token
	raw   string
	clock *clock
	path  string
}

func setup(t testing.TB, queue int) *fixture {
	t.Helper()
	path := filepath.Join(t.TempDir(), "mail.db")
	db, err := store.Open(path, store.Limits{QueueCount: queue, QueueBytes: 32 * 1024 * 1024, Accounts: 128, Tokens: 256})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	c, _ := security.New(bytes.Repeat([]byte{7}, 32))
	at := &clock{time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)}
	s := app.NewService(db, db, db, c, at, app.NewRegistry())
	admin := domain.Token{ID: "admin", Admin: true, Name: "admin", Hash: security.Hash("test-admin-token")}
	if err = db.CreateToken(context.Background(), admin); err != nil {
		t.Fatal(err)
	}
	return &fixture{s, db, admin, "test-admin-token", at, path}
}
func (f *fixture) account(t testing.TB, name string) domain.Account {
	t.Helper()
	a, err := f.s.CreateAccount(context.Background(), app.AccountRequest{Name: name, Host: "smtp.qq.com", Port: 465, TLS: "implicit", Username: "sender@example.com", Secret: "hidden-authorization", From: "sender@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	return a
}
func (f *fixture) submit(t testing.TB, key, account string) domain.Message {
	t.Helper()
	m, err := f.s.Submit(context.Background(), f.admin, domain.Input{AccountID: account, To: "to@example.com", Subject: "test", Text: "body"}, key, "")
	if err != nil {
		t.Fatal(err)
	}
	return m
}
func TestConcurrentIdempotencyAndCapacity(t *testing.T) {
	f := setup(t, 2)
	ctx := context.Background()
	input := domain.Input{To: "to@example.com", Subject: "test", Text: "body"}
	var wg sync.WaitGroup
	ids := make(chan string, 20)
	fail := make(chan error, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m, err := f.s.Submit(ctx, f.admin, input, "same", "")
			if err != nil {
				fail <- err
			} else {
				ids <- m.ID
			}
		}()
	}
	wg.Wait()
	close(ids)
	close(fail)
	for err := range fail {
		t.Fatal(err)
	}
	first := ""
	for id := range ids {
		if first == "" {
			first = id
		}
		if id != first {
			t.Fatal("duplicate task")
		}
	}
	input.Text = "changed"
	if _, err := f.s.Submit(ctx, f.admin, input, "same", ""); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("want conflict: %v", err)
	}
	f.submit(t, "second", "")
	if _, err := f.s.Submit(ctx, f.admin, input, "third", ""); !errors.Is(err, domain.ErrFull) {
		t.Fatalf("want full: %v", err)
	}
}
func TestClaimBudgetRetryAndUnknown(t *testing.T) {
	f := setup(t, 10)
	a := f.account(t, "a")
	f.submit(t, "first", a.ID)
	f.submit(t, "second", a.ID)
	ctx := context.Background()
	now := f.clock.Now().Unix()
	m, chosen, err := f.db.Claim(ctx, now, domain.LeastRecentlyUsed{})
	if err != nil {
		t.Fatal(err)
	}
	if chosen.DailyUsed != 1 || chosen.Active != 1 {
		t.Fatal("budget not reserved")
	}
	if _, _, err = f.db.Claim(ctx, now, domain.LeastRecentlyUsed{}); !errors.Is(err, domain.ErrNotFound) {
		t.Fatal("account concurrency exceeded")
	}
	if err = f.db.Finish(ctx, m, domain.Result{Category: domain.Uncertain, Stage: "data_ack", Code: "missing"}, now); err != nil {
		t.Fatal(err)
	}
	saved, _ := f.db.Message(ctx, m.ID)
	if saved.State != domain.Unknown {
		t.Fatal(saved.State)
	}
	if _, err = f.s.Resend(ctx, f.admin, m.ID, "resend", false); err == nil {
		t.Fatal("unconfirmed duplicate")
	}
	m, _, err = f.db.Claim(ctx, now, domain.LeastRecentlyUsed{})
	if err != nil {
		t.Fatal(err)
	}
	if err = f.db.Finish(ctx, m, domain.Result{Category: domain.Temporary, Stage: "connect"}, now); err != nil {
		t.Fatal(err)
	}
	saved, _ = f.db.Message(ctx, m.ID)
	if saved.State != domain.RetryWait || saved.NextAt != now+60 {
		t.Fatal("retry schedule")
	}
	if _, _, err = f.db.Claim(ctx, now, domain.LeastRecentlyUsed{}); !errors.Is(err, domain.ErrNotFound) {
		t.Fatal("minute budget bypass")
	}
	m, _, err = f.db.Claim(ctx, now+60, domain.LeastRecentlyUsed{})
	if err != nil {
		t.Fatal(err)
	}
	if err = f.db.Finish(ctx, m, domain.Result{Category: domain.Accepted, Stage: "data_ack"}, now+60); err != nil {
		t.Fatal(err)
	}
	saved, _ = f.db.Message(ctx, m.ID)
	if saved.State != domain.Submitted || len(saved.History) != 2 {
		t.Fatalf("%#v", saved)
	}
}
func TestRecoveryRetentionAndBackup(t *testing.T) {
	f := setup(t, 10)
	a := f.account(t, "a")
	m := f.submit(t, "first", a.ID)
	ctx := context.Background()
	now := f.clock.Now().Unix()
	if _, _, err := f.db.Claim(ctx, now, domain.LeastRecentlyUsed{}); err != nil {
		t.Fatal(err)
	}
	if err := f.db.Recover(ctx, now+1); err != nil {
		t.Fatal(err)
	}
	saved, _ := f.db.Message(ctx, m.ID)
	if saved.State != domain.Unknown {
		t.Fatal(saved.State)
	}
	account, _ := f.db.Account(ctx, a.ID)
	if account.Active != 0 {
		t.Fatal("stale slot")
	}
	backup := filepath.Join(t.TempDir(), "backup.db")
	if err := f.db.Backup(ctx, backup); err != nil {
		t.Fatal(err)
	}
	restored, err := store.Open(backup, store.Limits{QueueCount: 10, QueueBytes: 1000000, Accounts: 128, Tokens: 256})
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	if _, err = restored.Message(ctx, m.ID); err != nil {
		t.Fatal(err)
	}
	if err = f.db.Backup(ctx, backup); err == nil {
		t.Fatal("backup overwrote file")
	}
	if err = f.db.Maintain(ctx, now+8*86400); err != nil {
		t.Fatal(err)
	}
	saved, _ = f.db.Message(ctx, m.ID)
	if !saved.BodyExpired || saved.Text != "" {
		t.Fatal("body not purged")
	}
	if err = f.db.Maintain(ctx, now+31*86400); err != nil {
		t.Fatal(err)
	}
	if _, err = f.db.Message(ctx, m.ID); !errors.Is(err, domain.ErrNotFound) {
		t.Fatal("metadata not purged")
	}
}
func TestTokenIsolationAndRevocation(t *testing.T) {
	f := setup(t, 10)
	a := f.account(t, "a")
	b := f.account(t, "b")
	token, raw, err := f.s.NewToken(context.Background(), "script", []string{a.ID})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err = f.s.Submit(ctx, token, domain.Input{AccountID: b.ID, To: "to@example.com", Subject: "s", Text: "b"}, "bad", ""); err == nil {
		t.Fatal("account permission bypass")
	}
	own, err := f.s.Submit(ctx, token, domain.Input{To: "to@example.com", Subject: "s", Text: "b"}, "ok", "")
	if err != nil {
		t.Fatal(err)
	}
	adminTask := f.submit(t, "admin-task", "")
	if _, err = f.s.OwnedMessage(ctx, token, adminTask.ID); err == nil {
		t.Fatal("owner isolation bypass")
	}
	if err = f.db.RevokeToken(ctx, token.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = f.db.Authenticate(ctx, security.Hash(raw)); !errors.Is(err, domain.ErrNotFound) {
		t.Fatal("revoked token accepted")
	}
	if err = f.db.Maintain(ctx, f.clock.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	saved, _ := f.db.Message(ctx, own.ID)
	if saved.State != domain.Failed {
		t.Fatal("revoked queued task remains")
	}
}
func TestAccountVersionAndDailyReset(t *testing.T) {
	f := setup(t, 10)
	a := f.account(t, "a")
	f.submit(t, "first", a.ID)
	ctx := context.Background()
	now := f.clock.Now().Unix()
	m, _, err := f.db.Claim(ctx, now, domain.LeastRecentlyUsed{})
	if err != nil {
		t.Fatal(err)
	}
	if err = f.db.UpdateAccount(ctx, a); !errors.Is(err, domain.ErrConflict) {
		t.Fatal("stale write accepted")
	}
	if err = f.db.Finish(ctx, m, domain.Result{Category: domain.Accepted}, now); err != nil {
		t.Fatal(err)
	}
	a, _ = f.db.Account(ctx, a.ID)
	a.DailyLimit = 1
	if err = f.db.UpdateAccount(ctx, a); err != nil {
		t.Fatal(err)
	}
	f.submit(t, "second", a.ID)
	if _, _, err = f.db.Claim(ctx, now+60, domain.LeastRecentlyUsed{}); !errors.Is(err, domain.ErrNotFound) {
		t.Fatal("daily cap bypass")
	}
	if _, chosen, err := f.db.Claim(ctx, now+86400-1, domain.LeastRecentlyUsed{}); err != nil || chosen.DailyUsed != 1 {
		t.Fatalf("daily reset: %v %#v", err, chosen)
	}
}
func TestCancellationAndRetryExhaustion(t *testing.T) {
	f := setup(t, 10)
	a := f.account(t, "a")
	ctx := context.Background()
	cancelled := f.submit(t, "cancel", a.ID)
	if err := f.db.Cancel(ctx, cancelled.ID, f.clock.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	if err := f.db.Cancel(ctx, cancelled.ID, f.clock.Now().Unix()); !errors.Is(err, domain.ErrConflict) {
		t.Fatal("invalid state transition")
	}
	m := f.submit(t, "retry", a.ID)
	now := f.clock.Now().Unix()
	for i := 0; i < 3; i++ {
		claimed, _, err := f.db.Claim(ctx, now, domain.LeastRecentlyUsed{})
		if err != nil {
			t.Fatal(err)
		}
		if err = f.db.Cancel(ctx, claimed.ID, now); !errors.Is(err, domain.ErrConflict) {
			t.Fatal("cancel active")
		}
		if err = f.db.Finish(ctx, claimed, domain.Result{Category: domain.Temporary}, now); err != nil {
			t.Fatal(err)
		}
		now += 300
	}
	saved, _ := f.db.Message(ctx, m.ID)
	if saved.State != domain.Failed || saved.Attempts != 3 {
		t.Fatal("retry exhaustion")
	}
}
func TestHTTPContractAndSecretRedaction(t *testing.T) {
	f := setup(t, 10)
	f.account(t, "qq")
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := httpapi.New(f.s, log, f.db.Ping, 64, 256, 20, 40)
	request := func(method, path, body, token, key string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		if key != "" {
			r.Header.Set("Idempotency-Key", key)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	if w := request("GET", "/api/v1/accounts", "", "", ""); w.Code != 401 {
		t.Fatal(w.Code)
	}
	w := request("GET", "/api/v1/accounts", "", f.raw, "")
	if w.Code != 200 || strings.Contains(w.Body.String(), "hidden-authorization") || strings.Contains(w.Body.String(), "encrypted_secret") {
		t.Fatal(w.Body.String())
	}
	body := `{"to":"to@example.com","subject":"test","text":"body"}`
	w = request("POST", "/api/v1/messages", body, f.raw, "once")
	if w.Code != 202 {
		t.Fatal(w.Code, w.Body.String())
	}
	var task map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &task)
	second := request("POST", "/api/v1/messages", body, f.raw, "once")
	if !strings.Contains(second.Body.String(), task["id"].(string)) {
		t.Fatal("HTTP idempotency")
	}
	if w = request("POST", "/api/v1/messages", body, f.raw, ""); w.Code != 400 {
		t.Fatal(w.Code)
	}
	if w = request("POST", "/api/v1/messages", `{"to":"to@example.com","subject":"a\r\nb","text":"b"}`, f.raw, "inject"); w.Code != 400 {
		t.Fatal("header injection")
	}
	if w = request("POST", "/api/v1/messages", `{"to":"to@example.com","subject":"a","text":"b","attachment":"x"}`, f.raw, "field"); w.Code != 400 {
		t.Fatal("unknown field")
	}
	if w = request("GET", "/api/v1/messages?page_size=101", "", f.raw, ""); w.Code != 400 {
		t.Fatal("unbounded pagination")
	}
	oversized := fmt.Sprintf(`{"text":"%s"}`, strings.Repeat("x", 600*1024))
	if w = request("POST", "/api/v1/messages", oversized, f.raw, "large"); w.Code != 400 {
		t.Fatal("body limit")
	}
	if w = request("GET", "/health/ready", "", "", ""); w.Code != 200 {
		t.Fatal("readiness")
	}
}
func TestQueueByteLimit(t *testing.T) {
	f := setup(t, 1000)
	ctx := context.Background()
	input := domain.Input{To: "to@example.com", Subject: "s", Text: strings.Repeat("b", 256*1024)}
	for i := 0; i < 128; i++ {
		if _, err := f.s.Submit(ctx, f.admin, input, fmt.Sprint(i), ""); err != nil {
			t.Fatal(i, err)
		}
	}
	if _, err := f.s.Submit(ctx, f.admin, input, "over", ""); !errors.Is(err, domain.ErrFull) {
		t.Fatal("queue bytes unbounded", err)
	}
}

func TestConcurrentClaimAndCooldown(t *testing.T) {
	f := setup(t, 100)
	a := f.account(t, "only-account")
	ctx := context.Background()
	for i := 0; i < 20; i++ {
		f.submit(t, fmt.Sprintf("task-%d", i), a.ID)
	}
	var wg sync.WaitGroup
	claimed := make(chan domain.Message, 20)
	failures := make(chan error, 20)
	now := f.clock.Now().Unix()
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m, _, err := f.db.Claim(ctx, now, domain.LeastRecentlyUsed{})
			if err == nil {
				claimed <- m
			} else if !errors.Is(err, domain.ErrNotFound) {
				failures <- err
			}
		}()
	}
	wg.Wait()
	close(claimed)
	close(failures)
	for err := range failures {
		t.Fatal(err)
	}
	if len(claimed) != 1 {
		t.Fatal("concurrent account slot reservation failed", len(claimed))
	}
	m := <-claimed
	if err := f.db.Finish(ctx, m, domain.Result{Category: domain.RateLimited}, now); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.db.Claim(ctx, now+60, domain.LeastRecentlyUsed{}); !errors.Is(err, domain.ErrNotFound) {
		t.Fatal("cooldown bypass")
	}
	if _, _, err := f.db.Claim(ctx, now+1800, domain.LeastRecentlyUsed{}); err != nil {
		t.Fatal("cooldown did not expire", err)
	}
}

func TestCredentialRotationDuringSendAndResend(t *testing.T) {
	f := setup(t, 10)
	a := f.account(t, "rotate")
	ctx := context.Background()
	now := f.clock.Now().Unix()
	m := f.submit(t, "rotation", a.ID)
	claimed, _, err := f.db.Claim(ctx, now, domain.LeastRecentlyUsed{})
	if err != nil {
		t.Fatal(err)
	}
	patch := map[string]json.RawMessage{"secret": json.RawMessage(`"replacement-secret"`)}
	updated, err := f.s.PatchAccount(ctx, a.ID, patch)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.db.Finish(ctx, claimed, domain.Result{Category: domain.Authentication}, now); err != nil {
		t.Fatal(err)
	}
	current, err := f.db.Account(ctx, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if current.State != domain.Available || current.DailyUsed != 1 || current.Active != 0 {
		t.Fatal("old credential failure overwrote new configuration", current)
	}
	secret, err := f.s.Cipher.Decrypt(current.Ciphertext)
	if err != nil || secret != "replacement-secret" {
		t.Fatal("rotation not persisted", err)
	}
	if updated.Revision <= a.Revision {
		t.Fatal("configuration version did not advance")
	}
	if _, err = f.s.PatchAccount(ctx, a.ID, map[string]json.RawMessage{"from": json.RawMessage(`"bad\r\naddress"`)}); err == nil {
		t.Fatal("header injection accepted")
	}
	if _, err = f.s.PatchAccount(ctx, a.ID, map[string]json.RawMessage{"enabled": json.RawMessage(`false`)}); err != nil {
		t.Fatal(err)
	}
	if _, _, err = f.db.Claim(ctx, now+60, domain.LeastRecentlyUsed{}); !errors.Is(err, domain.ErrNotFound) {
		t.Fatal("disabled account selected")
	}
	if _, err = f.s.PatchAccount(ctx, a.ID, map[string]json.RawMessage{"enabled": json.RawMessage(`true`)}); err != nil {
		t.Fatal(err)
	}
	claimed, _, err = f.db.Claim(ctx, now+60, domain.LeastRecentlyUsed{})
	if err != nil {
		t.Fatal(err)
	}
	if err = f.db.Finish(ctx, claimed, domain.Result{Category: domain.Uncertain}, now+60); err != nil {
		t.Fatal(err)
	}
	resent, err := f.s.Resend(ctx, f.admin, m.ID, "confirmed-resend", true)
	if err != nil {
		t.Fatal(err)
	}
	if resent.ID == m.ID || resent.ParentID != m.ID {
		t.Fatal("resend mutated original")
	}
	if err = f.s.ValidateKey(ctx); err != nil {
		t.Fatal(err)
	}
}

type fakeTransport struct{}

func (fakeTransport) Test(context.Context, domain.Account, string) domain.Result {
	return domain.Result{Category: domain.Accepted}
}
func (fakeTransport) Send(context.Context, domain.Account, string, domain.Message, string) domain.Result {
	return domain.Result{Category: domain.Accepted, Stage: "data_ack", Code: "smtp_250"}
}
func TestSchedulerEndToEnd(t *testing.T) {
	f := setup(t, 10)
	a := f.account(t, "scheduler")
	m := f.submit(t, "background", a.ID)
	if err := f.s.Transports.Register("smtp", func() domain.MailTransport { return fakeTransport{} }); err != nil {
		t.Fatal(err)
	}
	if err := f.s.Transports.Register("smtp", func() domain.MailTransport { return fakeTransport{} }); err == nil {
		t.Fatal("duplicate transport registration")
	}
	if result, err := f.s.TestAccount(context.Background(), a.ID); err != nil || result.Category != domain.Accepted {
		t.Fatal("test adapter dispatch", err)
	}
	scheduler := app.NewScheduler(f.s, domain.LeastRecentlyUsed{}, 4, slog.New(slog.NewTextHandler(io.Discard, nil)))
	scheduler.Start()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := scheduler.Stop(ctx); err != nil {
			t.Error(err)
		}
	}()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		saved, err := f.db.Message(context.Background(), m.ID)
		if err != nil {
			t.Fatal(err)
		}
		if saved.State == domain.Submitted {
			if !scheduler.Healthy() {
				t.Fatal("healthy scheduler flagged failed")
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("background task not submitted")
}
