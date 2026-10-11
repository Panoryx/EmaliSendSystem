package main

import (
	"bytes"
	"emailsendsystem/internal/config"
	"encoding/base64"
	"github.com/gofrs/flock"
	"os"
	"path/filepath"
	"testing"
)

func TestInitializationKeyAndProcessLock(t *testing.T) {
	c := config.Default()
	c.DataDir = filepath.Join(t.TempDir(), "data")
	if err := initialize(c); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(c.DataDir, "master.key")
	key, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if err = initialize(c); err == nil {
		t.Fatal("init overwrote existing directory")
	}
	after, _ := os.ReadFile(keyPath)
	if !bytes.Equal(key, after) {
		t.Fatal("key changed")
	}
	saved := os.Args
	t.Cleanup(func() { os.Args = saved })
	os.Args = []string{"emailsend", "backup", "-data-dir", c.DataDir, "-out", filepath.Join(t.TempDir(), "backup.db")}
	if err = run(); err != nil {
		t.Fatal(err)
	}
	lock := flock.New(filepath.Join(c.DataDir, "process.lock"))
	if err = lock.Lock(); err != nil {
		t.Fatal(err)
	}
	if err = run(); err == nil {
		t.Fatal("parallel process accepted")
	}
	lock.Unlock()
	bad := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
	if err = os.WriteFile(keyPath, []byte(bad), 0600); err != nil {
		t.Fatal(err)
	}
	if err = run(); err == nil {
		t.Fatal("wrong master key accepted")
	}
}
