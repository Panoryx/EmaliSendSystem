package store

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
)

func TestMigrationSnapshotIncludesWALData(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mail.db")
	legacy, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	legacy.SetMaxOpenConns(1)
	if _, err = legacy.Exec("PRAGMA journal_mode=WAL; CREATE TABLE legacy(value TEXT); INSERT INTO legacy VALUES('preserve')"); err != nil {
		t.Fatal(err)
	}
	defer legacy.Close()
	db, err := Open(path, Limits{QueueCount: 10, QueueBytes: 10000, Accounts: 128, Tokens: 256})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	matches, err := filepath.Glob(path + ".pre-migration-*.db")
	if err != nil || len(matches) != 1 {
		t.Fatal("snapshot missing", err)
	}
	snapshot, err := sql.Open("sqlite", matches[0])
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Close()
	var value string
	if err = snapshot.QueryRowContext(context.Background(), "SELECT value FROM legacy").Scan(&value); err != nil || value != "preserve" {
		t.Fatal("WAL data not backed up", err)
	}
}
func TestRejectFutureSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mail.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("PRAGMA user_version=99"); err != nil {
		t.Fatal(err)
	}
	db.Close()
	if _, err = Open(path, Limits{}); err == nil {
		t.Fatal("future schema accepted")
	}
	if _, err = os.Stat(path); err != nil {
		t.Fatal("future schema removed")
	}
}
