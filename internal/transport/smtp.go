// Package transport 将外部投递协议适配为统一业务结果。
package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"emailsendsystem/internal/domain"
	"errors"
	gomail "github.com/wneessen/go-mail"
	"github.com/wneessen/go-mail/smtp"
	"net"
	"net/mail"
	"net/textproto"
	"strconv"
	"strings"
	"time"
)

// SMTP 使用 go-mail 的 MIME 和 SMTP 协议实现，显式控制 DATA 阶段。
type SMTP struct {
	// Dial 和 Roots 仅由构造代码注入，生产配置不支持跳过证书验证。
	Dial  func(context.Context, string) (net.Conn, error)
	Roots *x509.CertPool
}

// NewSMTP 创建使用系统可信证书的适配器。
func NewSMTP() *SMTP { return &SMTP{} }
func (s *SMTP) connect(ctx context.Context, a domain.Account, secret string) (*smtp.Client, func(), domain.Result) {
	addr := net.JoinHostPort(a.Host, strconv.Itoa(a.Port))
	dial := s.Dial
	if dial == nil {
		dial = func(ctx context.Context, addr string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 15 * time.Second}).DialContext(ctx, "tcp", addr)
		}
	}
	conn, err := dial(ctx, addr)
	if err != nil {
		return nil, func() {}, classify(err, "connect", false)
	}
	deadline := time.Now().Add(60 * time.Second)
	if d, ok := ctx.Deadline(); ok {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)
	raw := conn
	stop := context.AfterFunc(ctx, func() { _ = raw.Close() })
	cleanup := func() { stop(); _ = raw.Close() }
	config := &tls.Config{ServerName: a.Host, MinVersion: tls.VersionTLS12, RootCAs: s.Roots}
	if a.TLS == "implicit" {
		secured := tls.Client(conn, config)
		if err = secured.HandshakeContext(ctx); err != nil {
			cleanup()
			return nil, func() {}, classify(err, "tls", false)
		}
		conn = secured
	}
	client, err := smtp.NewClient(conn, a.Host)
	if err != nil {
		cleanup()
		return nil, func() {}, classify(err, "greeting", false)
	}
	if err = client.Hello("localhost"); err != nil {
		cleanup()
		return nil, func() {}, classify(err, "hello", false)
	}
	if a.TLS == "starttls" {
		if ok, _ := client.Extension("STARTTLS"); !ok {
			cleanup()
			return nil, func() {}, domain.Result{Category: domain.Permanent, Stage: "tls", Code: "starttls_required"}
		}
		if err = client.StartTLS(config); err != nil {
			cleanup()
			return nil, func() {}, classify(err, "tls", false)
		}
	}
	ok, mechanisms := client.Extension("AUTH")
	if !ok {
		cleanup()
		return nil, func() {}, domain.Result{Category: domain.Permanent, Stage: "auth", Code: "auth_not_supported"}
	}
	var auth smtp.Auth
	if strings.Contains(" "+mechanisms+" ", " PLAIN ") {
		auth = smtp.PlainAuth("", a.Username, secret, a.Host, false)
	} else if strings.Contains(" "+mechanisms+" ", " LOGIN ") {
		auth = smtp.LoginAuth(a.Username, secret, a.Host, false)
	} else {
		cleanup()
		return nil, func() {}, domain.Result{Category: domain.Permanent, Stage: "auth", Code: "auth_method_not_supported"}
	}
	if err = client.Auth(auth); err != nil {
		cleanup()
		return nil, func() {}, classify(err, "auth", false)
	}
	return client, cleanup, domain.Result{Category: domain.Accepted, Stage: "auth", Code: "authenticated"}
}

// Test 完成 TLS 和认证即结束，不执行 MAIL、RCPT 或 DATA。
func (s *SMTP) Test(ctx context.Context, a domain.Account, secret string) domain.Result {
	_, cleanup, result := s.connect(ctx, a, secret)
	defer cleanup()
	return result
}

// Send 在最终 250 确认后才返回 accepted，不把 QUIT 失败改写成发送失败。
func (s *SMTP) Send(ctx context.Context, a domain.Account, secret string, m domain.Message, messageID string) domain.Result {
	msg := gomail.NewMsg()
	msg.FromMailAddress(&mail.Address{Name: a.DisplayName, Address: a.From})
	if err := msg.To(m.To); err != nil {
		return domain.Result{Category: domain.Permanent, Stage: "mime", Code: "invalid_recipient"}
	}
	msg.Subject(m.Subject)
	msg.SetMessageIDWithValue(messageID)
	if m.Text != "" {
		msg.SetBodyString(gomail.TypeTextPlain, m.Text)
		if m.HTML != "" {
			msg.AddAlternativeString(gomail.TypeTextHTML, m.HTML)
		}
	} else {
		msg.SetBodyString(gomail.TypeTextHTML, m.HTML)
	}
	client, cleanup, result := s.connect(ctx, a, secret)
	defer cleanup()
	if client == nil {
		return result
	}
	if err := client.Mail(a.From); err != nil {
		return classify(err, "mail", false)
	}
	if err := client.Rcpt(m.To); err != nil {
		return classify(err, "rcpt", false)
	}
	writer, err := client.Data()
	if err != nil {
		return classify(err, "data_command", false)
	}
	// 内容开始写出后，不确认接受的网络错误一律 unknown，不能自动换账号。
	if _, err = msg.WriteTo(writer); err != nil {
		return classify(err, "data_write", true)
	}
	if err = writer.Close(); err != nil {
		return classify(err, "data_ack", true)
	}
	return domain.Result{Category: domain.Accepted, Stage: "data_ack", Code: "smtp_250"}
}
func classify(err error, stage string, mayAccept bool) domain.Result {
	r := domain.Result{Category: domain.Temporary, Stage: stage, Code: "network_error"}
	var response *textproto.Error
	if errors.As(err, &response) {
		r.Code = "smtp_" + strconv.Itoa(response.Code)
		switch {
		case stage == "auth" && (response.Code == 535 || response.Code == 534):
			r.Category = domain.Authentication
		case response.Code == 421 || response.Code == 454:
			r.Category = domain.RateLimited
		case response.Code >= 400 && response.Code < 500:
			r.Category = domain.Temporary
		case response.Code >= 500 && response.Code < 600:
			r.Category = domain.Permanent
		default:
			if mayAccept {
				r.Category = domain.Uncertain
			}
		}
		return r
	}
	var certErr *tls.CertificateVerificationError
	if errors.As(err, &certErr) {
		r.Category = domain.Permanent
		r.Code = "certificate_invalid"
		return r
	}
	if mayAccept {
		r.Category = domain.Uncertain
		r.Code = "acknowledgement_missing"
	}
	return r
}
