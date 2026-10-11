// Package config 解析运行配置，所有容量限制在启动时校验。
package config

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
)

// Config 是进程级配置；SMTP 账号配置通过管理员 API 管理。
type Config struct {
	Listen      string  `json:"listen"`
	DataDir     string  `json:"data_dir"`
	Workers     int     `json:"workers"`
	HTTPActive  int     `json:"http_active"`
	QueueCount  int     `json:"queue_count"`
	QueueBytes  int64   `json:"queue_bytes"`
	AccountCap  int     `json:"account_cap"`
	TokenCap    int     `json:"token_cap"`
	TokenRate   float64 `json:"token_rate"`
	TokenBurst  float64 `json:"token_burst"`
	MemoryLimit int64   `json:"memory_limit_bytes"`
}

// Default 适用于低内存单机部署。
func Default() Config {
	return Config{Listen: "127.0.0.1:8080", DataDir: "data", Workers: 4, HTTPActive: 64, QueueCount: 1000, QueueBytes: 32 * 1024 * 1024, AccountCap: 128, TokenCap: 256, TokenRate: 20, TokenBurst: 40, MemoryLimit: 128 * 1024 * 1024}
}

// Load 可在未提供配置文件时使用默认值；未知字段会报错。
func Load(path string) (Config, error) {
	c := Default()
	if path != "" {
		f, err := os.Open(path)
		if err != nil {
			return c, err
		}
		defer f.Close()
		d := json.NewDecoder(f)
		d.DisallowUnknownFields()
		if err = d.Decode(&c); err != nil {
			return c, err
		}
	}
	host, _, err := net.SplitHostPort(c.Listen)
	if err != nil {
		return c, err
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return c, fmt.Errorf("listen must be a loopback IP; use HTTPS reverse proxy")
	}
	if c.DataDir == "" || c.Workers < 1 || c.Workers > 32 || c.HTTPActive < 1 || c.HTTPActive > 256 || c.QueueCount < 1 || c.QueueCount > 10000 || c.QueueBytes < 1 || c.QueueBytes > 256*1024*1024 || c.AccountCap < 1 || c.AccountCap > 128 || c.TokenCap < 1 || c.TokenCap > 256 || c.TokenRate <= 0 || c.TokenRate > 1000 || c.TokenBurst < 1 || c.TokenBurst > 2000 || c.MemoryLimit < 32*1024*1024 {
		return c, fmt.Errorf("configuration limits out of range")
	}
	return c, nil
}
