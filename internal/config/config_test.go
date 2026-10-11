package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConfigurationGuards(t *testing.T) {
	for _, tc := range []struct {
		body string
		ok   bool
	}{{`{"workers":4}`, true}, {`{"workers":0}`, false}, {`{"listen":"0.0.0.0:8080"}`, false}, {`{"unknown":1}`, false}, {`{"queue_bytes":9999999999}`, false}} {
		path := filepath.Join(t.TempDir(), "config.json")
		if err := os.WriteFile(path, []byte(tc.body), 0600); err != nil {
			t.Fatal(err)
		}
		_, err := Load(path)
		if (err == nil) != tc.ok {
			t.Fatalf("%s: %v", tc.body, err)
		}
	}
}
