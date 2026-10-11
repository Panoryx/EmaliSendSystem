package security

import (
	"bytes"
	"testing"
)

func TestCredentialProtection(t *testing.T) {
	c, err := New(bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	first, err := c.Encrypt("smtp-authorization-secret")
	if err != nil {
		t.Fatal(err)
	}
	second, _ := c.Encrypt("smtp-authorization-secret")
	if first == second {
		t.Fatal("nonce reused")
	}
	plain, err := c.Decrypt(first)
	if err != nil || plain != "smtp-authorization-secret" {
		t.Fatal("round trip")
	}
	wrong, _ := New(bytes.Repeat([]byte{2}, 32))
	if _, err = wrong.Decrypt(first); err == nil {
		t.Fatal("wrong key accepted")
	}
	if _, err = c.Decrypt("broken"); err == nil {
		t.Fatal("malformed ciphertext accepted")
	}
}
