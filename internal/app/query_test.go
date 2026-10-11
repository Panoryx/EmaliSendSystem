package app_test

import (
	"context"
	"emailsendsystem/internal/domain"
	"emailsendsystem/internal/httpapi"
	"encoding/json"
	"io"
	"log/slog"
	"net/http/httptest"
	"testing"
	"time"
)

func TestMessageFiltersAndOwnership(t *testing.T) {
	f := setup(t, 20)
	ctx := context.Background()
	first := f.submit(t, "query-first", "")
	if err := f.db.Cancel(ctx, first.ID, f.clock.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	f.clock.at = f.clock.at.Add(time.Minute)
	second := f.submit(t, "query-second", "")
	user, raw, err := f.s.NewToken(ctx, "restricted", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.s.Submit(ctx, user, domain.Input{To: "self@example.com", Subject: "private", Text: "private body"}, "user-query", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, owner string
		filter      domain.MessageFilter
		total       int
	}{
		{"all", "", domain.MessageFilter{}, 3},
		{"owner", f.admin.ID, domain.MessageFilter{}, 2},
		{"cancelled", "", domain.MessageFilter{State: domain.Cancelled}, 1},
		{"id", "", domain.MessageFilter{ID: second.ID}, 1},
		{"inclusive range", "", domain.MessageFilter{CreatedFrom: first.Created, CreatedTo: first.Created}, 1},
		{"combined empty", "", domain.MessageFilter{State: domain.Queued, ID: first.ID}, 0},
		{"other owner id", user.ID, domain.MessageFilter{ID: second.ID}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := f.db.Messages(ctx, tc.owner, 1, 1, tc.filter)
			if err != nil || out.Total != tc.total {
				t.Fatalf("got %#v, %v", out, err)
			}
			if len(out.Items) > 1 {
				t.Fatal("pagination ignored")
			}
			for _, m := range out.Items {
				if m.Text != "" || m.HTML != "" {
					t.Fatal("list returned bodies")
				}
			}
		})
	}
	out, err := f.db.Messages(ctx, f.admin.ID, 3, 1, domain.MessageFilter{})
	if err != nil || out.Total != 2 || len(out.Items) != 0 {
		t.Fatal("out-of-range page lost total", out, err)
	}
	handler := httpapi.New(f.s, slog.New(slog.NewTextHandler(io.Discard, nil)), f.db.Ping, 64, 256, 20, 40)
	r := httptest.NewRequest("GET", "/api/v1/messages?id="+second.ID, nil)
	r.Header.Set("Authorization", "Bearer "+raw)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	var result struct {
		Total int              `json:"total"`
		Items []domain.Message `json:"items"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if w.Code != 200 || result.Total != 0 || len(result.Items) != 0 {
		t.Fatal("filter exposed another owner's task", w.Code, w.Body.String())
	}
}
