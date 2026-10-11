// Package domain 定义与 HTTP、数据库及 SMTP 库无关的业务模型。
package domain

import (
	"context"
	"errors"
	"time"
)

// State 是邮件任务状态；Submitted 只说明上游接受，不代表最终投递。
type State string

const (
	Queued    State = "queued"
	Sending   State = "sending"
	RetryWait State = "retry_wait"
	Submitted State = "submitted"
	Failed    State = "failed"
	Unknown   State = "unknown"
	Cancelled State = "cancelled"
)

// CanTransition 是唯一的状态转换规则。重发创建新任务，不改变终态。
func CanTransition(from, to State) bool {
	switch from {
	case Queued, RetryWait:
		return to == Sending || to == Cancelled || to == Failed
	case Sending:
		return to == Submitted || to == RetryWait || to == Failed || to == Unknown
	default:
		return false
	}
}

// AccountState 是渠道健康状态，与账号是否有剩余额度分开管理。
type AccountState string

const (
	Available   AccountState = "available"
	Cooling     AccountState = "cooling"
	Reauthorize AccountState = "reauthorize"
	Disabled    AccountState = "disabled"
)

// Account 包含固定发件身份。Ciphertext 不会通过 JSON 返回。
type Account struct {
	ID            string       `json:"id"`
	Name          string       `json:"name"`
	Transport     string       `json:"transport"`
	Host          string       `json:"host"`
	Port          int          `json:"port"`
	TLS           string       `json:"tls"`
	Username      string       `json:"username"`
	From          string       `json:"from"`
	DisplayName   string       `json:"display_name"`
	Ciphertext    string       `json:"-"`
	State         AccountState `json:"state"`
	PerMinute     int          `json:"per_minute"`
	DailyLimit    int          `json:"daily_limit"`
	DailyUsed     int          `json:"daily_used"`
	BudgetDay     string       `json:"budget_day"`
	MinuteStart   int64        `json:"-"`
	MinuteUsed    int          `json:"-"`
	LastUsed      int64        `json:"last_used"`
	CooldownUntil int64        `json:"cooldown_until"`
	Active        int          `json:"active"`
	Revision      int          `json:"revision"`
}

// Input 是任务的不可变业务内容；AccountID 为空允许自动选择。
type Input struct {
	AccountID string `json:"account_id"`
	To        string `json:"to"`
	Subject   string `json:"subject"`
	Text      string `json:"text"`
	HTML      string `json:"html"`
}

// Message 是持久化队列任务；Allowed 保存提交时的授权范围。
type Message struct {
	ID    string `json:"id"`
	Owner string `json:"-"`
	Input
	State         State     `json:"status"`
	Created       int64     `json:"created_at"`
	NextAt        int64     `json:"next_at"`
	Updated       int64     `json:"updated_at"`
	Attempts      int       `json:"attempt_count"`
	ActualAccount string    `json:"actual_account_id,omitempty"`
	ParentID      string    `json:"parent_id,omitempty"`
	BodyExpired   bool      `json:"body_expired"`
	Allowed       []string  `json:"-"`
	History       []Attempt `json:"attempts,omitempty"`
}

// Category 表达投递结论，不将未知结果当成普通失败。
type Category string

const (
	Accepted       Category = "accepted"
	Temporary      Category = "temporary"
	Authentication Category = "authentication"
	RateLimited    Category = "rate_limited"
	Permanent      Category = "permanent"
	Uncertain      Category = "uncertain"
)

// Result 不携带服务商原始回复，防止泄露收件人或认证信息。
type Result struct {
	Category Category `json:"category"`
	Stage    string   `json:"stage"`
	Code     string   `json:"code"`
}

// Attempt 记录已预留预算的发送尝试；MessageID 不能保证收件方去重。
type Attempt struct {
	Number          int    `json:"number"`
	AccountID       string `json:"account_id"`
	AccountRevision int    `json:"account_revision"`
	From            string `json:"from"`
	MessageID       string `json:"message_id"`
	Started         int64  `json:"started_at"`
	Finished        int64  `json:"finished_at"`
	Result
}

// Token 保存授权身份，Hash 永不暴露，原始 Token 仅创建时返回。
type Token struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Hash       string   `json:"-"`
	Admin      bool     `json:"admin"`
	AccountIDs []string `json:"account_ids"`
	Revoked    bool     `json:"revoked"`
	Created    int64    `json:"created_at"`
}

// Fault 是可安全向 API 输出的业务错误。
type Fault struct {
	Status        int
	Code, Message string
}

// Error 返回稳定业务代码，不包含凭据或服务商原始回复。
func (f *Fault) Error() string { return f.Code }

// Fail 创建稳定、无敏感信息的业务错误。
func Fail(status int, code, message string) error { return &Fault{status, code, message} }

// ErrNotFound 和 ErrConflict 用于跨存储实现的错误判断。
var (
	ErrNotFound = errors.New("not found")
	ErrConflict = errors.New("conflict")
	ErrFull     = errors.New("queue full")
)

// Clock 注入时间源，生产使用 RealClock，测试无需实际等待。
type Clock interface{ Now() time.Time }

// RealClock 使用系统时钟。
type RealClock struct{}

// Now 返回当前时间，预算日边界由业务规则转换为北京时间。
func (RealClock) Now() time.Time { return time.Now() }

// MailTransport 隔离邮件库和其他发送 API，实现必须说明通信阶段。
type MailTransport interface {
	Test(context.Context, Account, string) Result
	Send(context.Context, Account, string, Message, string) Result
}

// AccountSelector 是独立账号选择策略，输入只含符合条件的候选者。
type AccountSelector interface {
	Select([]Account) (Account, bool)
}

// LeastRecentlyUsed 选择最久未使用者，同时间按 ID 保持确定性。
type LeastRecentlyUsed struct{}

func (LeastRecentlyUsed) Select(accounts []Account) (Account, bool) {
	if len(accounts) == 0 {
		return Account{}, false
	}
	chosen := accounts[0]
	for _, a := range accounts[1:] {
		if a.LastUsed < chosen.LastUsed || (a.LastUsed == chosen.LastUsed && a.ID < chosen.ID) {
			chosen = a
		}
	}
	return chosen, true
}
