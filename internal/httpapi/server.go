// Package httpapi 负责 HTTP 契约、鉴权和有界请求处理，不直接访问 SQL。
package httpapi

import (
	"context"
	"emailsendsystem/internal/app"
	"emailsendsystem/internal/domain"
	"emailsendsystem/internal/security"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// API 是路由及中间件容器，限流状态不随请求数增长。
type API struct {
	service     *app.Service
	log         *slog.Logger
	ready       func(context.Context) error
	slots       chan struct{}
	mu          sync.Mutex
	buckets     map[string]*bucket
	rate, burst float64
	maxBuckets  int
}
type bucket struct {
	credit float64
	at     time.Time
}
type contextKey int

const (
	identityKey contextKey = iota
	requestIDKey
)

// New 创建 HTTP handler；Token 总数与限流器容量一致。
func New(s *app.Service, log *slog.Logger, ready func(context.Context) error, active, tokenCap int, rate, burst float64) http.Handler {
	a := &API{service: s, log: log, ready: ready, slots: make(chan struct{}, active), buckets: map[string]*bucket{}, rate: rate, burst: burst, maxBuckets: tokenCap}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health/live", func(w http.ResponseWriter, r *http.Request) { a.reply(w, 200, map[string]string{"status": "ok"}) })
	mux.HandleFunc("GET /health/ready", func(w http.ResponseWriter, r *http.Request) {
		if err := ready(r.Context()); err != nil {
			a.failure(w, r, domain.Fail(503, "not_ready", "服务未就绪"))
			return
		}
		a.reply(w, 200, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("/api/v1/", a.auth(a.dispatch))
	return a.bound(mux)
}
func (a *API) bound(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, err := security.Random(12)
		if err != nil {
			http.Error(w, "unavailable", 503)
			return
		}
		r = r.WithContext(context.WithValue(r.Context(), requestIDKey, id))
		w.Header().Set("X-Request-ID", id)
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		select {
		case a.slots <- struct{}{}:
			defer func() { <-a.slots }()
		default:
			a.failure(w, r, domain.Fail(503, "http_busy", "请求并发已达上限"))
			return
		}
		defer func() {
			if recover() != nil {
				a.log.Error("request panic", "request_id", id)
				a.failure(w, r, domain.Fail(500, "internal_error", "内部错误"))
			}
		}()
		r.Body = http.MaxBytesReader(w, r.Body, 512*1024)
		next.ServeHTTP(w, r)
	})
}
func (a *API) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("Authorization")
		if !strings.HasPrefix(header, "Bearer ") || len(header) > 256 {
			a.failure(w, r, domain.Fail(401, "unauthorized", "需要有效 Bearer Token"))
			return
		}
		t, err := a.service.Tokens.Authenticate(r.Context(), security.Hash(strings.TrimPrefix(header, "Bearer ")))
		if err != nil {
			if errors.Is(err, domain.ErrNotFound) {
				a.failure(w, r, domain.Fail(401, "unauthorized", "需要有效 Bearer Token"))
			} else {
				a.failure(w, r, err)
			}
			return
		}
		if !a.take(t.ID) {
			w.Header().Set("Retry-After", "1")
			a.failure(w, r, domain.Fail(429, "rate_limited", "请求过于频繁"))
			return
		}
		r = r.WithContext(context.WithValue(r.Context(), identityKey, t))
		next(w, r)
	}
}
func (a *API) take(id string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.service.Clock.Now()
	b := a.buckets[id]
	if b == nil {
		if len(a.buckets) >= a.maxBuckets {
			return false
		}
		b = &bucket{credit: a.burst, at: now}
		a.buckets[id] = b
	}
	elapsed := now.Sub(b.at).Seconds()
	if elapsed > 0 {
		b.credit = min(a.burst, b.credit+elapsed*a.rate)
		b.at = now
	}
	if b.credit < 1 {
		return false
	}
	b.credit--
	return true
}
func (a *API) decode(w http.ResponseWriter, r *http.Request, dst any) bool {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		a.failure(w, r, domain.Fail(400, "invalid_content_type", "需要 application/json"))
		return false
	}
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err = d.Decode(dst); err != nil {
		a.failure(w, r, domain.Fail(400, "invalid_json", "JSON 不合法或请求体过大"))
		return false
	}
	var extra any
	if err = d.Decode(&extra); !errors.Is(err, io.EOF) {
		a.failure(w, r, domain.Fail(400, "invalid_json", "仅允许一个 JSON 对象"))
		return false
	}
	return true
}
func (a *API) dispatch(w http.ResponseWriter, r *http.Request) {
	t := r.Context().Value(identityKey).(domain.Token)
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/"), "/")
	resource := parts[0]
	id := ""
	action := ""
	if len(parts) > 1 {
		id = parts[1]
	}
	if len(parts) > 2 {
		action = parts[2]
	}
	if len(parts) > 3 {
		a.failure(w, r, domain.ErrNotFound)
		return
	}
	if resource == "accounts" || resource == "tokens" || resource == "stats" {
		if !t.Admin {
			a.failure(w, r, domain.Fail(403, "admin_required", "需要管理员权限"))
			return
		}
	}
	ctx := r.Context()
	switch {
	case resource == "accounts" && id == "" && r.Method == http.MethodGet:
		out, err := a.service.Accounts.Accounts(ctx)
		a.respond(w, r, 200, out, err)
	case resource == "accounts" && id == "" && r.Method == http.MethodPost:
		var in app.AccountRequest
		if !a.decode(w, r, &in) {
			return
		}
		out, err := a.service.CreateAccount(ctx, in)
		a.respond(w, r, 201, out, err)
	case resource == "accounts" && id != "" && action == "" && r.Method == http.MethodPatch:
		var in map[string]json.RawMessage
		if !a.decode(w, r, &in) {
			return
		}
		if in == nil {
			a.failure(w, r, domain.Fail(400, "invalid_json", "需要 JSON 对象"))
			return
		}
		out, err := a.service.PatchAccount(ctx, id, in)
		a.respond(w, r, 200, out, err)
	case resource == "accounts" && id != "" && action == "test" && r.Method == http.MethodPost:
		testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()
		out, err := a.service.TestAccount(testCtx, id)
		a.respond(w, r, 200, out, err)
	case resource == "tokens" && id == "" && r.Method == http.MethodGet:
		out, err := a.service.Tokens.Tokens(ctx)
		a.respond(w, r, 200, out, err)
	case resource == "tokens" && id == "" && r.Method == http.MethodPost:
		var in struct {
			Name     string   `json:"name"`
			Accounts []string `json:"account_ids"`
		}
		if !a.decode(w, r, &in) {
			return
		}
		token, raw, err := a.service.NewToken(ctx, in.Name, in.Accounts)
		a.respond(w, r, 201, map[string]any{"token": token, "secret": raw}, err)
	case resource == "tokens" && id != "" && action == "" && r.Method == http.MethodDelete:
		err := a.service.Tokens.RevokeToken(ctx, id)
		a.respond(w, r, 200, map[string]bool{"revoked": true}, err)
	case resource == "messages" && id == "" && r.Method == http.MethodPost:
		var in domain.Input
		if !a.decode(w, r, &in) {
			return
		}
		out, err := a.service.Submit(ctx, t, in, r.Header.Get("Idempotency-Key"), "")
		a.taskReply(w, r, out, err)
	case resource == "messages" && id == "" && r.Method == http.MethodGet:
		page, size, err := pagination(r)
		if err != nil {
			a.failure(w, r, err)
			return
		}
		owner := t.ID
		if t.Admin {
			owner = ""
		}
		out, err := a.service.Messages.Messages(ctx, owner, page, size)
		a.respond(w, r, 200, map[string]any{"items": out, "page": page, "page_size": size}, err)
	case resource == "messages" && id != "" && action == "" && r.Method == http.MethodGet:
		out, err := a.service.OwnedMessage(ctx, t, id)
		a.respond(w, r, 200, out, err)
	case resource == "messages" && id != "" && action == "cancel" && r.Method == http.MethodPost:
		_, err := a.service.OwnedMessage(ctx, t, id)
		if err == nil {
			err = a.service.Messages.Cancel(ctx, id, a.service.Clock.Now().Unix())
		}
		a.respond(w, r, 200, map[string]string{"status": "cancelled"}, err)
	case resource == "messages" && id != "" && action == "resend" && r.Method == http.MethodPost:
		var in struct {
			Confirm bool `json:"confirm_possible_duplicate"`
		}
		if !a.decode(w, r, &in) {
			return
		}
		out, err := a.service.Resend(ctx, t, id, r.Header.Get("Idempotency-Key"), in.Confirm)
		a.taskReply(w, r, out, err)
	case resource == "stats" && id == "" && r.Method == http.MethodGet:
		out, err := a.service.Messages.Stats(ctx)
		if err == nil {
			var mem runtime.MemStats
			runtime.ReadMemStats(&mem)
			out["process"] = map[string]any{"heap_alloc_bytes": mem.HeapAlloc, "goroutines": runtime.NumGoroutine()}
			accounts, e := a.service.Accounts.Accounts(ctx)
			err = e
			out["accounts"] = accounts
		}
		a.respond(w, r, 200, out, err)
	default:
		a.failure(w, r, domain.ErrNotFound)
	}
}
func pagination(r *http.Request) (int, int, error) {
	page, size := 1, 20
	var err error
	if raw := r.URL.Query().Get("page"); raw != "" {
		page, err = strconv.Atoi(raw)
		if err != nil {
			return 0, 0, domain.Fail(400, "invalid_page", "分页参数不合法")
		}
	}
	if raw := r.URL.Query().Get("page_size"); raw != "" {
		size, err = strconv.Atoi(raw)
		if err != nil {
			return 0, 0, domain.Fail(400, "invalid_page", "分页参数不合法")
		}
	}
	if page < 1 || page > 100000 || size < 1 || size > 100 {
		return 0, 0, domain.Fail(400, "invalid_page", "分页参数不合法")
	}
	return page, size, nil
}
func (a *API) taskReply(w http.ResponseWriter, r *http.Request, m domain.Message, err error) {
	if err != nil {
		a.failure(w, r, err)
		return
	}
	url := "/api/v1/messages/" + m.ID
	w.Header().Set("Location", url)
	a.reply(w, 202, map[string]any{"id": m.ID, "status": m.State, "status_url": url})
}
func (a *API) respond(w http.ResponseWriter, r *http.Request, status int, out any, err error) {
	if err != nil {
		a.failure(w, r, err)
		return
	}
	a.reply(w, status, out)
}
func (a *API) reply(w http.ResponseWriter, status int, out any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(out)
}
func (a *API) failure(w http.ResponseWriter, r *http.Request, err error) {
	f := &domain.Fault{Status: 500, Code: "internal_error", Message: "内部错误"}
	var business *domain.Fault
	switch {
	case errors.As(err, &business):
		f = business
	case errors.Is(err, domain.ErrNotFound):
		f = &domain.Fault{Status: 404, Code: "not_found", Message: "资源不存在"}
	case errors.Is(err, domain.ErrConflict):
		f = &domain.Fault{Status: 409, Code: "conflict", Message: "状态、版本或幂等键冲突"}
	case errors.Is(err, domain.ErrFull):
		f = &domain.Fault{Status: 503, Code: "capacity_exceeded", Message: "容量已达上限"}
	}
	if f.Status == 500 {
		a.log.Error("request failed", "request_id", r.Context().Value(requestIDKey))
	}
	a.reply(w, f.Status, map[string]any{"error": map[string]any{"code": f.Code, "message": f.Message, "request_id": r.Context().Value(requestIDKey)}})
}
