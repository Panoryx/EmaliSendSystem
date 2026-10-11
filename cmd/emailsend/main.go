// Command emailsend 提供初始化、服务运行和一致性备份命令。
package main

import (
	"context"
	"crypto/rand"
	"emailsendsystem/internal/app"
	"emailsendsystem/internal/config"
	"emailsendsystem/internal/domain"
	"emailsendsystem/internal/httpapi"
	"emailsendsystem/internal/security"
	"emailsendsystem/internal/store"
	"emailsendsystem/internal/transport"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"github.com/gofrs/flock"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strings"
	"syscall"
	"time"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "emailsend:", err)
		os.Exit(1)
	}
}
func run() error {
	if len(os.Args) < 2 {
		return fmt.Errorf("usage: emailsend init|serve|backup [-config config.json] [-data-dir data] [-out backup.db]")
	}
	command := os.Args[1]
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	conf := flags.String("config", "", "JSON configuration path")
	data := flags.String("data-dir", "", "override data directory")
	out := flags.String("out", "", "backup destination (new file)")
	if err := flags.Parse(os.Args[2:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected arguments")
	}
	c, err := config.Load(*conf)
	if err != nil {
		return err
	}
	if *data != "" {
		c.DataDir = *data
	}
	if command == "init" {
		return initialize(c)
	}
	if command != "serve" && command != "backup" {
		return fmt.Errorf("unknown command")
	}
	key, err := os.ReadFile(filepath.Join(c.DataDir, "master.key"))
	if err != nil {
		return fmt.Errorf("run init first: %w", err)
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(key)))
	if err != nil {
		return fmt.Errorf("invalid master key encoding")
	}
	cipher, err := security.New(decoded)
	if err != nil {
		return err
	}
	check, err := os.ReadFile(filepath.Join(c.DataDir, "key.check"))
	if err != nil {
		return err
	}
	plain, err := cipher.Decrypt(strings.TrimSpace(string(check)))
	if err != nil || plain != "EmailSendSystem master key" {
		return fmt.Errorf("master key check failed")
	}
	lock := flock.New(filepath.Join(c.DataDir, "process.lock"))
	locked, err := lock.TryLock()
	if err != nil {
		return err
	}
	if !locked {
		return fmt.Errorf("data directory is in use; stop the service before offline backup")
	}
	defer lock.Unlock()
	db, err := store.Open(filepath.Join(c.DataDir, "mail.db"), store.Limits{QueueCount: c.QueueCount, QueueBytes: c.QueueBytes, Accounts: c.AccountCap, Tokens: c.TokenCap})
	if err != nil {
		return err
	}
	defer db.Close()
	if command == "backup" {
		if *out == "" {
			return fmt.Errorf("backup requires -out")
		}
		return db.Backup(context.Background(), *out)
	}
	debug.SetMemoryLimit(c.MemoryLimit)
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	registry := app.NewRegistry()
	if err = registry.Register("smtp", func() domain.MailTransport { return transport.NewSMTP() }); err != nil {
		return err
	}
	service := app.NewService(db, db, db, cipher, domain.RealClock{}, registry)
	if err = service.ValidateKey(context.Background()); err != nil {
		return err
	}
	if err = db.Recover(context.Background(), time.Now().Unix()); err != nil {
		return err
	}
	if err = db.Maintain(context.Background(), time.Now().Unix()); err != nil {
		return err
	}
	scheduler := app.NewScheduler(service, domain.LeastRecentlyUsed{}, c.Workers, logger)
	handler := httpapi.New(service, logger, func(ctx context.Context) error {
		if !scheduler.Healthy() {
			return errors.New("scheduler unhealthy")
		}
		return db.Ping(ctx)
	}, c.HTTPActive, c.TokenCap, c.TokenRate, c.TokenBurst)
	server := &http.Server{Addr: c.Listen, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 70 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 * 1024}
	signals, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	scheduler.Start()
	failures := make(chan error, 1)
	go func() { failures <- server.ListenAndServe() }()
	logger.Info("server started", "listen", c.Listen, "workers", c.Workers)
	select {
	case <-signals.Done():
	case err = <-failures:
		if !errors.Is(err, http.ErrServerClosed) {
			logger.Error("HTTP listener failed")
		}
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 65*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- scheduler.Stop(shutdown) }()
	httpErr := server.Shutdown(shutdown)
	workerErr := <-done
	if httpErr != nil || workerErr != nil {
		return fmt.Errorf("shutdown timeout; active tasks will recover as unknown")
	}
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	logger.Info("server stopped")
	return nil
}
func initialize(c config.Config) error {
	// 数据目录必须全新；失败时保留诊断文件，绝不重写已有密钥或 Token。
	if err := os.MkdirAll(filepath.Dir(c.DataDir), 0700); err != nil {
		return err
	}
	if err := os.Mkdir(c.DataDir, 0700); err != nil {
		return fmt.Errorf("initialization requires a new data directory: %w", err)
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return err
	}
	cipher, err := security.New(key)
	if err != nil {
		return err
	}
	check, err := cipher.Encrypt("EmailSendSystem master key")
	if err != nil {
		return err
	}
	for name, value := range map[string]string{"master.key": base64.StdEncoding.EncodeToString(key), "key.check": check} {
		if err = os.WriteFile(filepath.Join(c.DataDir, name), []byte(value+"\n"), 0600); err != nil {
			return err
		}
	}
	db, err := store.Open(filepath.Join(c.DataDir, "mail.db"), store.Limits{QueueCount: c.QueueCount, QueueBytes: c.QueueBytes, Accounts: c.AccountCap, Tokens: c.TokenCap})
	if err != nil {
		return err
	}
	defer db.Close()
	id, err := security.Random(16)
	if err != nil {
		return err
	}
	raw, err := security.Random(32)
	if err != nil {
		return err
	}
	if err = db.CreateToken(context.Background(), domain.Token{ID: id, Name: "administrator", Hash: security.Hash(raw), Admin: true, Created: time.Now().Unix()}); err != nil {
		return err
	}
	path := filepath.Join(c.DataDir, "admin.token")
	if err = os.WriteFile(path, []byte(raw+"\n"), 0600); err != nil {
		return err
	}
	fmt.Println("Initialized. Administrator token file:", path)
	return nil
}
