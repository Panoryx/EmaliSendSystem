// Package security 提供凭据加密和随机身份工具，不记录明文。
package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// Cipher 使用 AES-256-GCM；每次加密生成独立 nonce。
type Cipher struct{ aead cipher.AEAD }

// New 只接受 32 字节主密钥。
func New(key []byte) (*Cipher, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("master key must contain 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Cipher{aead}, nil
}

// Encrypt 加密 SMTP 授权凭据，认证附加数据区分应用用途。
func (c *Cipher) Encrypt(secret string) (string, error) {
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := c.aead.Seal(nonce, nonce, []byte(secret), []byte("EmailSendSystem/credentials/v1"))
	return base64.RawStdEncoding.EncodeToString(sealed), nil
}

// Decrypt 在认证失败时不返回部分明文。
func (c *Cipher) Decrypt(encoded string) (string, error) {
	b, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}
	n := c.aead.NonceSize()
	if len(b) < n {
		return "", fmt.Errorf("invalid ciphertext")
	}
	plain, err := c.aead.Open(nil, b[:n], b[n:], []byte("EmailSendSystem/credentials/v1"))
	return string(plain), err
}

// Random 返回密码学随机值，适合 Token 和任务标识。
func Random(bytes int) (string, error) {
	b := make([]byte, bytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// Hash 对高熵随机 Token 做 SHA-256 摘要，不用于用户密码。
func Hash(s string) string { sum := sha256.Sum256([]byte(s)); return hex.EncodeToString(sum[:]) }
