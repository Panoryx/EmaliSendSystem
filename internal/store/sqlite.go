// Package store 实现 SQLite Repository；所有跨实体修改在短事务内完成。
package store

import (
	"context"
	"database/sql"
	"emailsendsystem/internal/domain"
	"emailsendsystem/internal/security"
	"encoding/json"
	"errors"
	"fmt"
	_ "modernc.org/sqlite"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Limits 控制队列与持久化身份数量，避免无界增长。
type Limits struct {
	QueueCount int
	QueueBytes int64
	Accounts   int
	Tokens     int
}

// Store 使用独立读写连接池；一个写连接串行化预算及幂等事务。
type Store struct {
	write, read *sql.DB
	limits      Limits
}

// Open 初始化数据库。migration 前使用 VACUUM INTO 创建一致性快照。
func Open(path string, limits Limits) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	// URL 形式避免 Windows 驱动器路径与 SQLite URI 参数混淆。
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	uri := "file:" + filepath.ToSlash(abs) + "?_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=synchronous(FULL)&_pragma=cache_size(-2048)"
	w, err := sql.Open("sqlite", uri)
	if err != nil {
		return nil, err
	}
	w.SetMaxOpenConns(1)
	s := &Store{write: w, limits: limits}
	if err = w.Ping(); err != nil {
		w.Close()
		return nil, err
	}
	var version int
	if err = w.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		w.Close()
		return nil, err
	}
	if version > 1 {
		w.Close()
		return nil, fmt.Errorf("database schema is newer than this application")
	}
	if version == 0 {
		// WAL 可能尚未写回主文件；不能通过文件大小判断是否有旧数据。
		var tableCount int
		if err = w.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").Scan(&tableCount); err != nil {
			w.Close()
			return nil, err
		}
		if tableCount > 0 {
			if err = s.Backup(context.Background(), path+".pre-migration-"+time.Now().UTC().Format("20060102T150405")+".db"); err != nil {
				w.Close()
				return nil, err
			}
		}
		tx, err := w.Begin()
		if err != nil {
			w.Close()
			return nil, err
		}
		defer tx.Rollback()
		_, err = tx.Exec(schema)
		if err != nil {
			w.Close()
			return nil, err
		}
		if err = tx.Commit(); err != nil {
			w.Close()
			return nil, err
		}
	}
	r, err := sql.Open("sqlite", uri)
	if err != nil {
		w.Close()
		return nil, err
	}
	r.SetMaxOpenConns(2)
	s.read = r
	return s, nil
}

const schema = `
CREATE TABLE IF NOT EXISTS accounts(id TEXT PRIMARY KEY,payload TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS tokens(id TEXT PRIMARY KEY,hash TEXT UNIQUE NOT NULL,revoked INTEGER NOT NULL DEFAULT 0,payload TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS messages(
 id TEXT PRIMARY KEY,owner TEXT NOT NULL REFERENCES tokens(id),payload TEXT NOT NULL,
 state TEXT NOT NULL,created INTEGER NOT NULL,updated INTEGER NOT NULL,next_at INTEGER NOT NULL,
 attempts INTEGER NOT NULL DEFAULT 0,actual_account TEXT NOT NULL DEFAULT '',body_bytes INTEGER NOT NULL,
 body_expired INTEGER NOT NULL DEFAULT 0,parent_id TEXT NOT NULL DEFAULT '',
 idem_key TEXT NOT NULL,request_hash TEXT NOT NULL,UNIQUE(owner,idem_key));
CREATE INDEX IF NOT EXISTS messages_pending ON messages(state,next_at,created);
CREATE INDEX IF NOT EXISTS messages_owner ON messages(owner,created);
CREATE TABLE IF NOT EXISTS attempts(
 message_id TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,number INTEGER NOT NULL,payload TEXT NOT NULL,
 PRIMARY KEY(message_id,number));
PRAGMA user_version=1;`

// Close 关闭数据库连接。
func (s *Store) Close() error {
	if s.read != nil {
		s.read.Close()
	}
	return s.write.Close()
}

// Ping 用于 readiness 检查，不执行写入。
func (s *Store) Ping(ctx context.Context) error { return s.read.PingContext(ctx) }

// Backup 由 SQLite 创建一致性数据库，禁止覆盖现有文件。
func (s *Store) Backup(ctx context.Context, path string) error {
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		return fmt.Errorf("backup destination must not exist")
	}
	_, err := s.write.ExecContext(ctx, "VACUUM INTO ?", path)
	return err
}
func encode(v any) string { b, _ := json.Marshal(v); return string(b) }
func accountFrom(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, id string) (domain.Account, error) {
	var a domain.Account
	var raw string
	err := q.QueryRowContext(ctx, "SELECT payload FROM accounts WHERE id=?", id).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return a, domain.ErrNotFound
	}
	if err != nil {
		return a, err
	}
	err = json.Unmarshal([]byte(raw), &a)
	// ciphertext 被 JSON 输出标签排除，持久化使用显式信封。
	var envelope accountRecord
	if err == nil {
		err = json.Unmarshal([]byte(raw), &envelope)
		a.Ciphertext = envelope.Secret
	}
	return a, err
}

type accountRecord struct {
	domain.Account
	Secret string `json:"encrypted_secret"`
}

func accountJSON(a domain.Account) string { return encode(accountRecord{a, a.Ciphertext}) }

// Accounts 返回账号配置和额度，返回列表上限由创建限制保证。
func (s *Store) Accounts(ctx context.Context) ([]domain.Account, error) {
	rows, err := s.read.QueryContext(ctx, "SELECT id FROM accounts ORDER BY id")
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	result := make([]domain.Account, 0, len(ids))
	for _, id := range ids {
		a, err := s.Account(ctx, id)
		if err != nil {
			return nil, err
		}
		result = append(result, a)
	}
	return result, nil
}

// Account 查询账号，敏感凭据只在内部使用。
func (s *Store) Account(ctx context.Context, id string) (domain.Account, error) {
	return accountFrom(ctx, s.read, id)
}

// CreateAccount 原子检查账号总数，避免并发绕过容量限制。
func (s *Store) CreateAccount(ctx context.Context, a domain.Account) error {
	tx, err := s.write.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var n int
	if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM accounts").Scan(&n); err != nil {
		return err
	}
	if n >= s.limits.Accounts {
		return domain.ErrFull
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO accounts VALUES(?,?)", a.ID, accountJSON(a))
	if err != nil {
		return err
	}
	return tx.Commit()
}

// UpdateAccount 使用乐观版本检查，拒绝覆盖调度器已更新的预算。
func (s *Store) UpdateAccount(ctx context.Context, a domain.Account) error {
	tx, err := s.write.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	old, err := accountFrom(ctx, tx, a.ID)
	if err != nil {
		return err
	}
	if old.Revision != a.Revision {
		return domain.ErrConflict
	}
	a.Revision++
	if err = saveAccount(ctx, tx, a); err != nil {
		return err
	}
	return tx.Commit()
}
func saveAccount(ctx context.Context, tx *sql.Tx, a domain.Account) error {
	_, err := tx.ExecContext(ctx, "UPDATE accounts SET payload=? WHERE id=?", accountJSON(a), a.ID)
	return err
}

// Authenticate 每次查库，Token 撤销立即对后续请求生效。
func (s *Store) Authenticate(ctx context.Context, hash string) (domain.Token, error) {
	var t domain.Token
	var raw string
	err := s.read.QueryRowContext(ctx, "SELECT payload FROM tokens WHERE hash=? AND revoked=0", hash).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return t, domain.ErrNotFound
	}
	if err != nil {
		return t, err
	}
	err = json.Unmarshal([]byte(raw), &t)
	return t, err
}

// Tokens 列出身份，不返回哈希。
func (s *Store) Tokens(ctx context.Context) ([]domain.Token, error) {
	rows, err := s.read.QueryContext(ctx, "SELECT payload FROM tokens ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []domain.Token{}
	for rows.Next() {
		var raw string
		var t domain.Token
		if err = rows.Scan(&raw); err != nil {
			return nil, err
		}
		if err = json.Unmarshal([]byte(raw), &t); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// CreateToken 限制所有身份数量，撤销后保留审计引用。
func (s *Store) CreateToken(ctx context.Context, t domain.Token) error {
	tx, err := s.write.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var n int
	if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM tokens").Scan(&n); err != nil {
		return err
	}
	if n >= s.limits.Tokens {
		return domain.ErrFull
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO tokens(id,hash,payload) VALUES(?,?,?)", t.ID, t.Hash, encode(t))
	if err != nil {
		return err
	}
	return tx.Commit()
}

// RevokeToken 不允许撤销管理员，避免锁死唯一管理入口。
func (s *Store) RevokeToken(ctx context.Context, id string) error {
	tx, err := s.write.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var raw string
	err = tx.QueryRowContext(ctx, "SELECT payload FROM tokens WHERE id=?", id).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.ErrNotFound
	}
	if err != nil {
		return err
	}
	var t domain.Token
	if err = json.Unmarshal([]byte(raw), &t); err != nil {
		return err
	}
	if t.Admin {
		return domain.ErrConflict
	}
	t.Revoked = true
	_, err = tx.ExecContext(ctx, "UPDATE tokens SET revoked=1,payload=? WHERE id=?", encode(t), id)
	if err != nil {
		return err
	}
	return tx.Commit()
}

// Enqueue 幂等查询、容量检查与任务写入必须属于同一事务。
func (s *Store) Enqueue(ctx context.Context, m domain.Message, key, hash string) (domain.Message, error) {
	tx, err := s.write.BeginTx(ctx, nil)
	if err != nil {
		return m, err
	}
	defer tx.Rollback()
	var existing, oldHash string
	err = tx.QueryRowContext(ctx, "SELECT id,request_hash FROM messages WHERE owner=? AND idem_key=?", m.Owner, key).Scan(&existing, &oldHash)
	if err == nil {
		if oldHash != hash {
			return m, domain.ErrConflict
		}
		return messageFrom(ctx, tx, existing)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return m, err
	}
	var count int
	var bytes int64
	err = tx.QueryRowContext(ctx, "SELECT count(*),coalesce(sum(body_bytes),0) FROM messages WHERE state IN ('queued','retry_wait','sending')").Scan(&count, &bytes)
	if err != nil {
		return m, err
	}
	size := len(m.Text) + len(m.HTML)
	if count >= s.limits.QueueCount || bytes+int64(size) > s.limits.QueueBytes {
		return m, domain.ErrFull
	}
	// payload 仅保存不可变内容，状态由可索引列维护。
	_, err = tx.ExecContext(ctx, `INSERT INTO messages(id,owner,payload,state,created,updated,next_at,body_bytes,parent_id,idem_key,request_hash) VALUES(?,?,?,?,?,?,?,?,?,?,?)`, m.ID, m.Owner, encode(messagePayload{m.Input, m.Allowed}), m.State, m.Created, m.Updated, m.NextAt, size, m.ParentID, key, hash)
	if err != nil {
		return m, err
	}
	return m, tx.Commit()
}

type messagePayload struct {
	domain.Input
	Allowed []string `json:"allowed"`
}
type rowQuerier interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func messageFrom(ctx context.Context, q rowQuerier, id string) (domain.Message, error) {
	var m domain.Message
	var raw string
	err := q.QueryRowContext(ctx, `SELECT id,owner,payload,state,created,updated,next_at,attempts,actual_account,parent_id,body_expired FROM messages WHERE id=?`, id).Scan(&m.ID, &m.Owner, &raw, &m.State, &m.Created, &m.Updated, &m.NextAt, &m.Attempts, &m.ActualAccount, &m.ParentID, &m.BodyExpired)
	if errors.Is(err, sql.ErrNoRows) {
		return m, domain.ErrNotFound
	}
	if err != nil {
		return m, err
	}
	var p messagePayload
	err = json.Unmarshal([]byte(raw), &p)
	m.Input = p.Input
	m.Allowed = p.Allowed
	return m, err
}

// Message 包含尝试历史，历史最多三条。
func (s *Store) Message(ctx context.Context, id string) (domain.Message, error) {
	m, err := messageFrom(ctx, s.read, id)
	if err != nil {
		return m, err
	}
	rows, err := s.read.QueryContext(ctx, "SELECT payload FROM attempts WHERE message_id=? ORDER BY number", id)
	if err != nil {
		return m, err
	}
	defer rows.Close()
	for rows.Next() {
		var raw string
		var a domain.Attempt
		if err = rows.Scan(&raw); err != nil {
			return m, err
		}
		if err = json.Unmarshal([]byte(raw), &a); err != nil {
			return m, err
		}
		m.History = append(m.History, a)
	}
	return m, rows.Err()
}

// Messages 仅返回元数据，列表不读取或返回邮件正文。
func (s *Store) Messages(ctx context.Context, owner string, page, size int) ([]domain.Message, error) {
	rows, err := s.read.QueryContext(ctx, `SELECT id,owner,state,created,updated,next_at,attempts,actual_account,parent_id,body_expired FROM messages WHERE (?='' OR owner=?) ORDER BY created DESC,id DESC LIMIT ? OFFSET ?`, owner, owner, size, (page-1)*size)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []domain.Message{}
	for rows.Next() {
		var m domain.Message
		err = rows.Scan(&m.ID, &m.Owner, &m.State, &m.Created, &m.Updated, &m.NextAt, &m.Attempts, &m.ActualAccount, &m.ParentID, &m.BodyExpired)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// Cancel 使用数据库条件更新解决取消与领取之间的竞争。
func (s *Store) Cancel(ctx context.Context, id string, now int64) error {
	r, err := s.write.ExecContext(ctx, "UPDATE messages SET state='cancelled',updated=? WHERE id=? AND state IN ('queued','retry_wait')", now, id)
	if err != nil {
		return err
	}
	n, _ := r.RowsAffected()
	if n == 0 {
		return domain.ErrConflict
	}
	return nil
}

var shanghai = time.FixedZone("Asia/Shanghai", 8*60*60)

func allowed(ids []string, id string) bool {
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

// Claim 在同一事务中领取任务、预留预算、记录尝试，网络发送必须在返回后执行。
func (s *Store) Claim(ctx context.Context, now int64, selector domain.AccountSelector) (domain.Message, domain.Account, error) {
	var zero domain.Message
	var noAccount domain.Account
	tx, err := s.write.BeginTx(ctx, nil)
	if err != nil {
		return zero, noAccount, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, "SELECT payload FROM accounts ORDER BY id")
	if err != nil {
		return zero, noAccount, err
	}
	var accounts []domain.Account
	day := time.Unix(now, 0).In(shanghai).Format("2006-01-02")
	for rows.Next() {
		var raw string
		var p accountRecord
		if err = rows.Scan(&raw); err != nil {
			rows.Close()
			return zero, noAccount, err
		}
		if err = json.Unmarshal([]byte(raw), &p); err != nil {
			rows.Close()
			return zero, noAccount, err
		}
		a := p.Account
		a.Ciphertext = p.Secret
		if a.State == domain.Cooling && a.CooldownUntil <= now {
			a.State = domain.Available
		}
		if a.BudgetDay != day {
			a.BudgetDay = day
			a.DailyUsed = 0
		}
		if now-a.MinuteStart >= 60 {
			a.MinuteStart = now
			a.MinuteUsed = 0
		}
		if a.State == domain.Available && a.Active == 0 && a.DailyUsed < a.DailyLimit && a.MinuteUsed < a.PerMinute {
			accounts = append(accounts, a)
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return zero, noAccount, err
	}
	if len(accounts) == 0 {
		return zero, noAccount, domain.ErrNotFound
	}
	// 仅加载有界 ID 列表；正文按候选任务逐条读取，不把积压队列搬进内存。
	rows, err = tx.QueryContext(ctx, "SELECT id FROM messages WHERE state IN ('queued','retry_wait') AND next_at<=? AND created>? ORDER BY created,id LIMIT ?", now, now-86400, s.limits.QueueCount)
	if err != nil {
		return zero, noAccount, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return zero, noAccount, err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return zero, noAccount, err
	}
	for _, id := range ids {
		m, err := messageFrom(ctx, tx, id)
		if err != nil {
			return zero, noAccount, err
		}
		var revoked int
		if err = tx.QueryRowContext(ctx, "SELECT revoked FROM tokens WHERE id=?", m.Owner).Scan(&revoked); err != nil {
			return zero, noAccount, err
		}
		if revoked != 0 {
			continue
		}
		candidates := make([]domain.Account, 0, len(accounts))
		for _, a := range accounts {
			if (m.AccountID == "" || m.AccountID == a.ID) && allowed(m.Allowed, a.ID) {
				candidates = append(candidates, a)
			}
		}
		a, ok := selector.Select(candidates)
		if !ok {
			continue
		}
		m.State = domain.Sending
		m.Attempts++
		m.ActualAccount = a.ID
		m.Updated = now
		a.Active = 1
		a.DailyUsed++
		a.MinuteUsed++
		a.LastUsed = now
		a.Revision++
		if err = saveAccount(ctx, tx, a); err != nil {
			return zero, noAccount, err
		}
		_, err = tx.ExecContext(ctx, "UPDATE messages SET state=?,attempts=?,actual_account=?,updated=? WHERE id=?", m.State, m.Attempts, a.ID, now, m.ID)
		if err != nil {
			return zero, noAccount, err
		}
		random, err := security.Random(16)
		if err != nil {
			return zero, noAccount, err
		}
		domainPart := a.From[strings.LastIndex(a.From, "@")+1:]
		attempt := domain.Attempt{Number: m.Attempts, AccountID: a.ID, AccountRevision: a.Revision, From: a.From, MessageID: random + "@" + domainPart, Started: now, Result: domain.Result{Category: domain.Uncertain, Stage: "claimed", Code: "unfinished"}}
		_, err = tx.ExecContext(ctx, "INSERT INTO attempts VALUES(?,?,?)", m.ID, m.Attempts, encode(attempt))
		if err != nil {
			return zero, noAccount, err
		}
		m.History = []domain.Attempt{attempt}
		return m, a, tx.Commit()
	}
	return zero, noAccount, domain.ErrNotFound
}

// Finish 原子释放账号槽位并保存结果；明确失败才能进入重试队列。
func (s *Store) Finish(ctx context.Context, m domain.Message, result domain.Result, now int64) error {
	tx, err := s.write.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	current, err := messageFrom(ctx, tx, m.ID)
	if err != nil {
		return err
	}
	if current.State != domain.Sending || current.Attempts != m.Attempts {
		return domain.ErrConflict
	}
	a, err := accountFrom(ctx, tx, current.ActualAccount)
	if err != nil {
		return err
	}
	a.Active = 0
	a.Revision++
	state := domain.Failed
	next := now
	switch result.Category {
	case domain.Accepted:
		state = domain.Submitted
	case domain.Uncertain:
		state = domain.Unknown
	case domain.Temporary, domain.Authentication, domain.RateLimited:
		if m.Attempts < 3 {
			state = domain.RetryWait
			next = now + 60
			if m.Attempts == 2 {
				next = now + 300
			}
		}
	}
	var raw string
	if err = tx.QueryRowContext(ctx, "SELECT payload FROM attempts WHERE message_id=? AND number=?", m.ID, m.Attempts).Scan(&raw); err != nil {
		return err
	}
	var attempt domain.Attempt
	if err = json.Unmarshal([]byte(raw), &attempt); err != nil {
		return err
	}
	// 发送期间管理员可能更换授权码。旧配置的失败不能污染新配置的健康状态。
	// 此时 Revision 已因释放槽位增加一次，因此比较释放前的版本。
	if a.State != domain.Disabled && a.Revision-1 == attempt.AccountRevision {
		if result.Category == domain.Authentication {
			a.State = domain.Reauthorize
		}
		if result.Category == domain.RateLimited {
			a.State = domain.Cooling
			a.CooldownUntil = now + 1800
		}
	}
	if !domain.CanTransition(current.State, state) {
		return domain.ErrConflict
	}
	if err = saveAccount(ctx, tx, a); err != nil {
		return err
	}
	attempt.Finished = now
	attempt.Result = result
	_, err = tx.ExecContext(ctx, "UPDATE attempts SET payload=? WHERE message_id=? AND number=?", encode(attempt), m.ID, m.Attempts)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, "UPDATE messages SET state=?,next_at=?,updated=? WHERE id=?", state, next, now, m.ID)
	if err != nil {
		return err
	}
	return tx.Commit()
}

// Recover 不推断崩溃前是否发送成功，所有残留活跃任务转为 unknown。
func (s *Store) Recover(ctx context.Context, now int64) error {
	tx, err := s.write.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// 在任务改为终态前，补齐最后一次尝试的崩溃诊断，不保留模糊的 unfinished。
	_, err = tx.ExecContext(ctx, `UPDATE attempts SET payload=json_set(payload,'$.finished_at',?,'$.category','uncertain','$.stage','recovery','$.code','process_interrupted') WHERE (message_id,number) IN (SELECT id,attempts FROM messages WHERE state='sending')`, now)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, "UPDATE messages SET state='unknown',updated=? WHERE state='sending'", now)
	if err != nil {
		return err
	}
	rows, err := tx.QueryContext(ctx, "SELECT payload FROM accounts")
	if err != nil {
		return err
	}
	var all []domain.Account
	for rows.Next() {
		var raw string
		var p accountRecord
		if err = rows.Scan(&raw); err != nil {
			rows.Close()
			return err
		}
		if err = json.Unmarshal([]byte(raw), &p); err != nil {
			rows.Close()
			return err
		}
		a := p.Account
		a.Ciphertext = p.Secret
		all = append(all, a)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, a := range all {
		a.Active = 0
		a.Revision++
		if err = saveAccount(ctx, tx, a); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// Maintain 小批清理终态数据；过期正文不可用于重发。
func (s *Store) Maintain(ctx context.Context, now int64) error {
	tx, err := s.write.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, "UPDATE messages SET state='failed',updated=? WHERE state IN ('queued','retry_wait') AND (created<=? OR owner IN (SELECT id FROM tokens WHERE revoked=1))", now, now-86400)
	if err != nil {
		return err
	}
	rows, err := tx.QueryContext(ctx, "SELECT id,payload FROM messages WHERE body_expired=0 AND state NOT IN ('queued','retry_wait','sending') AND created<? LIMIT 100", now-7*86400)
	if err != nil {
		return err
	}
	type item struct{ id, raw string }
	var items []item
	for rows.Next() {
		var i item
		if err = rows.Scan(&i.id, &i.raw); err != nil {
			rows.Close()
			return err
		}
		items = append(items, i)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, i := range items {
		var p messagePayload
		if err = json.Unmarshal([]byte(i.raw), &p); err != nil {
			return err
		}
		p.Text = ""
		p.HTML = ""
		_, err = tx.ExecContext(ctx, "UPDATE messages SET payload=?,body_bytes=0,body_expired=1 WHERE id=?", encode(p), i.id)
		if err != nil {
			return err
		}
	}
	_, err = tx.ExecContext(ctx, "DELETE FROM messages WHERE id IN (SELECT id FROM messages WHERE created<? AND state NOT IN ('queued','retry_wait','sending') LIMIT 100)", now-30*86400)
	if err != nil {
		return err
	}
	return tx.Commit()
}

// Stats 返回队列状态及占用，不包含正文或凭据。
func (s *Store) Stats(ctx context.Context) (map[string]any, error) {
	rows, err := s.read.QueryContext(ctx, "SELECT state,count(*),coalesce(sum(body_bytes),0) FROM messages GROUP BY state")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]any{}
	for rows.Next() {
		var state string
		var count, bytes int64
		if err = rows.Scan(&state, &count, &bytes); err != nil {
			return nil, err
		}
		out[state] = map[string]int64{"count": count, "body_bytes": bytes}
	}
	return out, rows.Err()
}
