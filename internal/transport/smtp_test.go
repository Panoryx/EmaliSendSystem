package transport

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"emailsendsystem/internal/domain"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// smtpFixture 用真实 TLS 和协议会话测试投递阶段，不访问外网。
func smtpFixture(t *testing.T, mode string, startTLS bool) (*SMTP, domain.Account, *atomic.Int32) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "smtp.test"}, DNSNames: []string{"smtp.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool.AddCert(parsed)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	mailCount := &atomic.Int32{}
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		config := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
		if !startTLS {
			conn = tls.Server(conn, config)
		}
		reader := bufio.NewReader(conn)
		fmt.Fprint(conn, "220 smtp.test ESMTP\r\n")
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			cmd := strings.TrimSpace(line)
			switch {
			case strings.HasPrefix(cmd, "EHLO"):
				if startTLS {
					fmt.Fprint(conn, "250-smtp.test\r\n250-STARTTLS\r\n250 AUTH PLAIN LOGIN\r\n")
				} else {
					fmt.Fprint(conn, "250-smtp.test\r\n250 AUTH PLAIN LOGIN\r\n")
				}
			case cmd == "STARTTLS":
				fmt.Fprint(conn, "220 ready\r\n")
				conn = tls.Server(conn, config)
				reader = bufio.NewReader(conn)
			case strings.HasPrefix(cmd, "AUTH"):
				if mode == "auth" {
					fmt.Fprint(conn, "535 5.7.8 bad credentials\r\n")
				} else {
					fmt.Fprint(conn, "235 authenticated\r\n")
				}
			case strings.HasPrefix(cmd, "MAIL FROM"):
				mailCount.Add(1)
				fmt.Fprint(conn, "250 ok\r\n")
			case strings.HasPrefix(cmd, "RCPT TO"):
				if mode == "rcpt" {
					fmt.Fprint(conn, "550 no such user\r\n")
				} else if mode == "limit" {
					fmt.Fprint(conn, "421 rate limited\r\n")
				} else {
					fmt.Fprint(conn, "250 ok\r\n")
				}
			case cmd == "DATA":
				fmt.Fprint(conn, "354 send data\r\n")
				for {
					body, err := reader.ReadString('\n')
					if err != nil {
						return
					}
					if body == ".\r\n" {
						break
					}
				}
				switch mode {
				case "drop":
					return
				case "temp":
					fmt.Fprint(conn, "451 try later\r\n")
				default:
					fmt.Fprint(conn, "250 accepted\r\n")
				}
			case cmd == "QUIT":
				fmt.Fprint(conn, "221 bye\r\n")
				return
			default:
				fmt.Fprint(conn, "250 ok\r\n")
			}
		}
	}()
	t.Cleanup(func() {
		listener.Close()
		select {
		case <-finished:
		case <-time.After(6 * time.Second):
			t.Error("SMTP fixture did not stop")
		}
	})
	smtp := &SMTP{Roots: pool, Dial: func(ctx context.Context, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", listener.Addr().String())
	}}
	a := domain.Account{Host: "smtp.test", Port: 465, TLS: "implicit", Username: "sender@example.com", From: "sender@example.com"}
	if startTLS {
		a.Port = 587
		a.TLS = "starttls"
	}
	return smtp, a, mailCount
}
func TestSMTPStages(t *testing.T) {
	for _, tc := range []struct {
		mode     string
		category domain.Category
	}{{"ok", domain.Accepted}, {"auth", domain.Authentication}, {"rcpt", domain.Permanent}, {"limit", domain.RateLimited}, {"temp", domain.Temporary}, {"drop", domain.Uncertain}} {
		t.Run(tc.mode, func(t *testing.T) {
			s, a, _ := smtpFixture(t, tc.mode, false)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			result := s.Send(ctx, a, "secret", domain.Message{Input: domain.Input{To: "receiver@example.com", Subject: "中文标题", Text: "hello", HTML: "<p>hello</p>"}}, "test@example.com")
			if result.Category != tc.category {
				t.Fatalf("got %#v, want %s", result, tc.category)
			}
		})
	}
}
func TestSMTPTestDoesNotSend(t *testing.T) {
	for _, startTLS := range []bool{false, true} {
		t.Run(fmt.Sprint(startTLS), func(t *testing.T) {
			s, a, count := smtpFixture(t, "ok", startTLS)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			result := s.Test(ctx, a, "secret")
			if result.Category != domain.Accepted {
				t.Fatalf("%#v", result)
			}
			if count.Load() != 0 {
				t.Fatal("connection test sent MAIL")
			}
		})
	}
}
func TestCertificateVerification(t *testing.T) {
	s, a, _ := smtpFixture(t, "ok", false)
	s.Roots = x509.NewCertPool()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	result := s.Test(ctx, a, "secret")
	if result.Category != domain.Permanent || result.Code != "certificate_invalid" {
		t.Fatalf("%#v", result)
	}
}
