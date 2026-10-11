package app

import (
	"context"
	"emailsendsystem/internal/domain"
	"emailsendsystem/internal/security"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"strings"
	"sync"
)

// Registry 是渠道工厂注册表，在启动阶段构建，启动后只读。
type Registry struct {
	factories map[string]func() domain.MailTransport
}

// NewRegistry 创建注册表。
func NewRegistry() *Registry {
	return &Registry{factories: make(map[string]func() domain.MailTransport)}
}

// Register 拒绝重复类型，避免渠道实现被静默覆盖。
func (r *Registry) Register(name string, factory func() domain.MailTransport) error {
	if name == "" || factory == nil {
		return fmt.Errorf("invalid transport factory")
	}
	if _, ok := r.factories[name]; ok {
		return fmt.Errorf("duplicate transport")
	}
	r.factories[name] = factory
	return nil
}

// Build 创建具体投递适配器。
func (r *Registry) Build(name string) (domain.MailTransport, error) {
	factory, ok := r.factories[name]
	if !ok {
		return nil, fmt.Errorf("unsupported transport")
	}
	return factory(), nil
}

// Service 编排账号、授权及入队，不拥有数据库事务或 HTTP 类型。
type Service struct {
	Accounts   AccountRepository
	Messages   MessageRepository
	Tokens     TokenRepository
	Cipher     SecretCipher
	Clock      domain.Clock
	Transports *Registry
	testSlots  chan struct{}
	// 管理配置修改串行；调度器的并发预算更新另由存储版本检查保护。
	accountMu sync.Mutex
}

// NewService 明确注入依赖；不使用全局数据库或密钥。
func NewService(a AccountRepository, m MessageRepository, t TokenRepository, c SecretCipher, clock domain.Clock, r *Registry) *Service {
	return &Service{Accounts: a, Messages: m, Tokens: t, Cipher: c, Clock: clock, Transports: r, testSlots: make(chan struct{}, 2)}
}

// AccountRequest 是账号写入契约，Secret 是 SMTP 授权码，不是普通登录密码。
type AccountRequest struct {
	Name        string `json:"name"`
	Host        string `json:"host"`
	Port        int    `json:"port"`
	TLS         string `json:"tls"`
	Username    string `json:"username"`
	Secret      string `json:"secret"`
	From        string `json:"from"`
	DisplayName string `json:"display_name"`
	PerMinute   int    `json:"per_minute"`
	DailyLimit  int    `json:"daily_limit"`
	Enabled     *bool  `json:"enabled,omitempty"`
}

// ValidateEmail 只接受裸地址，拒绝显示名称及邮件头注入。
func ValidateEmail(s string) bool {
	if len(s) > 254 || strings.ContainsAny(s, "\r\n") {
		return false
	}
	a, err := mail.ParseAddress(s)
	return err == nil && a.Address == s && strings.Contains(s, "@")
}
func validAccount(r AccountRequest) bool {
	if r.Name == "" || len(r.Name) > 100 || len(r.Host) > 253 || r.Host == "" || len(r.Username) > 254 || r.Username == "" || len(r.Secret) > 4096 || len(r.DisplayName) > 200 {
		return false
	}
	if r.Port != 465 && r.Port != 587 {
		return false
	}
	if r.TLS != "implicit" && r.TLS != "starttls" {
		return false
	}
	if (r.Port == 465) != (r.TLS == "implicit") {
		return false
	}
	if strings.ContainsAny(r.Host, " /\\:\r\n") || strings.ContainsAny(r.Username+r.DisplayName, "\r\n") {
		return false
	}
	if ip := net.ParseIP(r.Host); ip != nil {
		return false
	}
	return ValidateEmail(r.From) && r.PerMinute > 0 && r.PerMinute <= 60 && r.DailyLimit > 0 && r.DailyLimit <= 10000
}

// CreateAccount 加密凭据并应用保守预算默认值。
func (s *Service) CreateAccount(ctx context.Context, r AccountRequest) (domain.Account, error) {
	var a domain.Account
	if r.PerMinute == 0 {
		r.PerMinute = 2
	}
	if r.DailyLimit == 0 {
		r.DailyLimit = 100
	}
	if !validAccount(r) || r.Secret == "" {
		return a, domain.Fail(400, "invalid_account", "账号参数不合法")
	}
	id, err := security.Random(16)
	if err != nil {
		return a, err
	}
	secret, err := s.Cipher.Encrypt(r.Secret)
	if err != nil {
		return a, err
	}
	a = domain.Account{ID: id, Name: r.Name, Transport: "smtp", Host: r.Host, Port: r.Port, TLS: r.TLS, Username: r.Username, From: r.From, DisplayName: r.DisplayName, Ciphertext: secret, State: domain.Available, PerMinute: r.PerMinute, DailyLimit: r.DailyLimit, Revision: 1}
	if r.Enabled != nil && !*r.Enabled {
		a.State = domain.Disabled
	}
	err = s.Accounts.CreateAccount(ctx, a)
	return a, err
}

// PatchAccount 合并已提供的配置；空授权码不覆盖原凭据。
func (s *Service) PatchAccount(ctx context.Context, id string, patch map[string]json.RawMessage) (domain.Account, error) {
	s.accountMu.Lock()
	defer s.accountMu.Unlock()
	a, err := s.Accounts.Account(ctx, id)
	if err != nil {
		return a, err
	}
	r := AccountRequest{Name: a.Name, Host: a.Host, Port: a.Port, TLS: a.TLS, Username: a.Username, From: a.From, DisplayName: a.DisplayName, PerMinute: a.PerMinute, DailyLimit: a.DailyLimit}
	base, _ := json.Marshal(r)
	var merged map[string]json.RawMessage
	_ = json.Unmarshal(base, &merged)
	for k, v := range patch {
		if _, ok := merged[k]; !ok && k != "enabled" {
			return a, domain.Fail(400, "invalid_field", "不支持的账号字段")
		}
		if string(v) == "null" {
			return a, domain.Fail(400, "invalid_field", "账号字段不能为 null")
		}
		merged[k] = v
	}
	data, _ := json.Marshal(merged)
	if err = json.Unmarshal(data, &r); err != nil || !validAccount(r) {
		return a, domain.Fail(400, "invalid_account", "账号参数不合法")
	}
	old := a
	a.Name = r.Name
	a.Host = r.Host
	a.Port = r.Port
	a.TLS = r.TLS
	a.Username = r.Username
	a.From = r.From
	a.DisplayName = r.DisplayName
	a.PerMinute = r.PerMinute
	a.DailyLimit = r.DailyLimit
	if r.Secret != "" {
		a.Ciphertext, err = s.Cipher.Encrypt(r.Secret)
		if err != nil {
			return a, err
		}
		if a.State == domain.Reauthorize {
			a.State = domain.Available
		}
	}
	if r.Enabled != nil {
		if *r.Enabled {
			if old.State == domain.Disabled {
				a.State = domain.Available
			}
		} else {
			a.State = domain.Disabled
		}
	}
	err = s.Accounts.UpdateAccount(ctx, a)
	if err == nil {
		a.Revision++
	}
	return a, err
}

// TestAccount 不发送邮件，并限制测试并发，防止管理接口占满网络连接。
func (s *Service) TestAccount(ctx context.Context, id string) (domain.Result, error) {
	select {
	case s.testSlots <- struct{}{}:
		defer func() { <-s.testSlots }()
	default:
		return domain.Result{}, domain.Fail(429, "test_busy", "账号测试繁忙")
	}
	a, err := s.Accounts.Account(ctx, id)
	if err != nil {
		return domain.Result{}, err
	}
	secret, err := s.Cipher.Decrypt(a.Ciphertext)
	if err != nil {
		return domain.Result{}, err
	}
	t, err := s.Transports.Build(a.Transport)
	if err != nil {
		return domain.Result{}, err
	}
	return t.Test(ctx, a, secret), nil
}

// NewToken 仅签发发送身份，可选限制账号；空列表允许全部账号。
func (s *Service) NewToken(ctx context.Context, name string, ids []string) (domain.Token, string, error) {
	var t domain.Token
	if name == "" || len(name) > 100 || len(ids) > 128 {
		return t, "", domain.Fail(400, "invalid_token", "Token 参数不合法")
	}
	seen := map[string]bool{}
	for _, id := range ids {
		if seen[id] {
			return t, "", domain.Fail(400, "duplicate_account", "账号重复")
		}
		seen[id] = true
		if _, err := s.Accounts.Account(ctx, id); err != nil {
			return t, "", err
		}
	}
	id, err := security.Random(16)
	if err != nil {
		return t, "", err
	}
	raw, err := security.Random(32)
	if err != nil {
		return t, "", err
	}
	t = domain.Token{ID: id, Name: name, Hash: security.Hash(raw), AccountIDs: ids, Created: s.Clock.Now().Unix()}
	err = s.Tokens.CreateToken(ctx, t)
	return t, raw, err
}
func permits(ids []string, id string) bool {
	if len(ids) == 0 {
		return true
	}
	for _, v := range ids {
		if v == id {
			return true
		}
	}
	return false
}

// Submit 校验任务，持久化幂等键；每个任务只允许一个收件人。
func (s *Service) Submit(ctx context.Context, t domain.Token, input domain.Input, key, parent string) (domain.Message, error) {
	var m domain.Message
	if key == "" || len(key) > 128 || strings.ContainsAny(key, "\r\n") {
		return m, domain.Fail(400, "invalid_idempotency_key", "必须提供长度不超过 128 的 Idempotency-Key")
	}
	if !ValidateEmail(input.To) || strings.ContainsAny(input.Subject, "\r\n") || len(input.Subject) > 998 || input.Subject == "" || len(input.Text)+len(input.HTML) > 256*1024 || (input.Text == "" && input.HTML == "") {
		return m, domain.Fail(400, "invalid_message", "收件人、标题或正文不合法")
	}
	if input.AccountID != "" {
		if !permits(t.AccountIDs, input.AccountID) {
			return m, domain.Fail(403, "account_forbidden", "Token 不允许使用该账号")
		}
		if _, err := s.Accounts.Account(ctx, input.AccountID); err != nil {
			return m, err
		}
	}
	id, err := security.Random(16)
	if err != nil {
		return m, err
	}
	now := s.Clock.Now().Unix()
	m = domain.Message{ID: id, Owner: t.ID, Input: input, State: domain.Queued, Created: now, Updated: now, NextAt: now, ParentID: parent, Allowed: t.AccountIDs}
	b, _ := json.Marshal(struct {
		Input  domain.Input
		Parent string
	}{input, parent})
	return s.Messages.Enqueue(ctx, m, key, security.Hash(string(b)))
}

// OwnedMessage 管理员可查看全部，发送身份仅能访问自己的任务。
func (s *Service) OwnedMessage(ctx context.Context, t domain.Token, id string) (domain.Message, error) {
	m, err := s.Messages.Message(ctx, id)
	if err != nil {
		return m, err
	}
	if !t.Admin && m.Owner != t.ID {
		return domain.Message{}, domain.Fail(403, "message_forbidden", "不能访问其他 Token 的任务")
	}
	return m, nil
}

// Resend 创建关联的新任务；unknown 必须由调用方确认重复风险。
func (s *Service) Resend(ctx context.Context, t domain.Token, id, key string, confirm bool) (domain.Message, error) {
	m, err := s.OwnedMessage(ctx, t, id)
	if err != nil {
		return m, err
	}
	if m.State != domain.Failed && m.State != domain.Unknown {
		return m, domain.ErrConflict
	}
	if m.BodyExpired {
		return m, domain.Fail(409, "body_expired", "正文已过期，不能直接重发")
	}
	if m.State == domain.Unknown && !confirm {
		return m, domain.Fail(409, "confirmation_required", "结果不确定，重发必须确认可能重复")
	}
	return s.Submit(ctx, t, m.Input, key, m.ID)
}

// ValidateKey 在启动前检查全部加密凭据，错误密钥不能带病运行。
func (s *Service) ValidateKey(ctx context.Context) error {
	accounts, err := s.Accounts.Accounts(ctx)
	if err != nil {
		return err
	}
	for _, a := range accounts {
		if _, err = s.Cipher.Decrypt(a.Ciphertext); err != nil {
			return errors.New("master key cannot decrypt account credentials")
		}
	}
	return nil
}
