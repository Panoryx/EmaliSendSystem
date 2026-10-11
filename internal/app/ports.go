// Package app 编排业务流程，接口放在使用方，由基础设施层实现。
package app

import (
	"context"
	"emailsendsystem/internal/domain"
)

// AccountRepository 支持带版本号更新，避免配置更新覆盖调度器的预算。
type AccountRepository interface {
	Accounts(context.Context) ([]domain.Account, error)
	Account(context.Context, string) (domain.Account, error)
	CreateAccount(context.Context, domain.Account) error
	UpdateAccount(context.Context, domain.Account) error
}

// MessageRepository 在存储层实现跨实体原子操作，不向业务层泄露 SQL。
type MessageRepository interface {
	Enqueue(context.Context, domain.Message, string, string) (domain.Message, error)
	Message(context.Context, string) (domain.Message, error)
	Messages(context.Context, string, int, int, domain.MessageFilter) (domain.MessagePage, error)
	Cancel(context.Context, string, int64) error
	Claim(context.Context, int64, domain.AccountSelector) (domain.Message, domain.Account, error)
	Finish(context.Context, domain.Message, domain.Result, int64) error
	Recover(context.Context, int64) error
	Maintain(context.Context, int64) error
	Stats(context.Context) (map[string]any, error)
}

// TokenRepository 持久化 Token 的哈希及授权，不存原始 Token。
type TokenRepository interface {
	Authenticate(context.Context, string) (domain.Token, error)
	Tokens(context.Context) ([]domain.Token, error)
	CreateToken(context.Context, domain.Token) error
	RevokeToken(context.Context, string) error
}

// SecretCipher 将主密钥管理与业务服务解耦。
type SecretCipher interface {
	Encrypt(string) (string, error)
	Decrypt(string) (string, error)
}
