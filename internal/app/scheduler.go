package app

import (
	"context"
	"emailsendsystem/internal/domain"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// Scheduler 控制 worker 生命周期，停止领取与取消正在发送分开处理。
type Scheduler struct {
	service  *Service
	selector domain.AccountSelector
	workers  int
	log      *slog.Logger
	stop     context.CancelFunc
	wg       sync.WaitGroup
	healthy  atomic.Bool
}

// NewScheduler 配置有界 worker 数量。
func NewScheduler(s *Service, selector domain.AccountSelector, workers int, log *slog.Logger) *Scheduler {
	return &Scheduler{service: s, selector: selector, workers: workers, log: log}
}

// Start 从重启恢复后的数据库领取任务。只应调用一次。
func (s *Scheduler) Start() {
	s.healthy.Store(true)
	ctx, cancel := context.WithCancel(context.Background())
	s.stop = cancel
	for i := 0; i < s.workers; i++ {
		s.wg.Add(1)
		go s.worker(ctx)
	}
	s.wg.Add(1)
	go s.maintenance(ctx)
}

// Healthy 在结果无法落库时返回 false；readiness 不应继续报告可用。
func (s *Scheduler) Healthy() bool { return s.healthy.Load() }

// Stop 先停止领取，保留正在发送的 60 秒上下文；调用方最多等待 65 秒。
func (s *Scheduler) Stop(ctx context.Context) error {
	s.stop()
	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (s *Scheduler) worker(ctx context.Context) {
	defer s.wg.Done()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		m, a, err := s.service.Messages.Claim(ctx, s.service.Clock.Now().Unix(), s.selector)
		if err != nil {
			if !errors.Is(err, domain.ErrNotFound) && ctx.Err() == nil {
				s.log.Error("task claim failed")
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				continue
			}
		}
		// 领取后使用独立上下文，正常关闭不能使已提交的 SMTP 中途断开。
		sendCtx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		secret, err := s.service.Cipher.Decrypt(a.Ciphertext)
		result := domain.Result{Category: domain.Permanent, Stage: "configuration", Code: "credential_unavailable"}
		if err == nil {
			transport, e := s.service.Transports.Build(a.Transport)
			if e == nil {
				result = transport.Send(sendCtx, a, secret, m, m.History[0].MessageID)
			}
		}
		cancel()
		// Finish 失败时停止该 worker，不能释放或重发结果不确定的领取任务。
		saveCtx, saveCancel := context.WithTimeout(context.Background(), 5*time.Second)
		err = s.service.Messages.Finish(saveCtx, m, result, s.service.Clock.Now().Unix())
		saveCancel()
		if err != nil {
			s.healthy.Store(false)
			s.log.Error("task result persistence failed", "task_id", m.ID)
			return
		}
		s.log.Info("mail attempt finished", "task_id", m.ID, "account_id", a.ID, "category", result.Category)
	}
}
func (s *Scheduler) maintenance(ctx context.Context) {
	defer s.wg.Done()
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.service.Messages.Maintain(ctx, s.service.Clock.Now().Unix()); err != nil && ctx.Err() == nil {
				s.log.Error("maintenance failed")
			}
		}
	}
}
