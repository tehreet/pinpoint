// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only

//go:build integration

package harness

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// MintAppToken returns a GitHub token for integration tests.
// Prefers GITHUB_TOKEN (backward compat with PAT), falls back to
// GitHub App auth via PINPOINT_APP_ID + PINPOINT_APP_KEY_PATH.
func MintAppToken(t *testing.T) string {
	t.Helper()

	if token := os.Getenv("GITHUB_TOKEN"); token != "" {
		return token
	}

	appID := os.Getenv("PINPOINT_APP_ID")
	keyPath := os.Getenv("PINPOINT_APP_KEY_PATH")
	if appID == "" || keyPath == "" {
		t.Fatal("Set GITHUB_TOKEN or PINPOINT_APP_ID + PINPOINT_APP_KEY_PATH")
	}

	return mintTokenFromKey(t, appID, keyPath)
}

// mintTokenFromKey creates a JWT from the App private key, exchanges it
// for an installation access token. Uses only stdlib crypto.
func mintTokenFromKey(t *testing.T, appID, keyPath string) string {
	t.Helper()

	// 1. Read and parse PEM private key
	pemData, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("Failed to read App private key from %s: %v", keyPath, err)
	}
	block, _ := pem.Decode(pemData)
	if block == nil {
		t.Fatalf("Failed to decode PEM block from %s", keyPath)
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		// Try PKCS8 as fallback
		parsed, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err2 != nil {
			t.Fatalf("Failed to parse private key: PKCS1: %v, PKCS8: %v", err, err2)
		}
		var ok bool
		key, ok = parsed.(*rsa.PrivateKey)
		if !ok {
			t.Fatalf("Private key is not RSA")
		}
	}

	// 2. Create JWT: iss=appID, iat=now-60s, exp=now+600s
	now := time.Now()
	header := base64URLEncode([]byte(`{"alg":"RS256","typ":"JWT"}`))
	claims := fmt.Sprintf(`{"iss":%s,"iat":%d,"exp":%d}`,
		appID, now.Add(-60*time.Second).Unix(), now.Add(600*time.Second).Unix())
	payload := base64URLEncode([]byte(claims))

	signingInput := header + "." + payload
	hashed := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hashed[:])
	if err != nil {
		t.Fatalf("Failed to sign JWT: %v", err)
	}
	jwt := signingInput + "." + base64URLEncode(sig)

	// 3. GET /app/installations → get installation_id
	client := &http.Client{Timeout: 30 * time.Second}

	req, _ := http.NewRequest("GET", "https://api.github.com/app/installations", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to list App installations: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("GET /app/installations returned %d: %s", resp.StatusCode, string(body))
	}

	var installations []struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(body, &installations); err != nil {
		t.Fatalf("Failed to parse installations response: %v", err)
	}
	if len(installations) == 0 {
		t.Fatal("No installations found for GitHub App")
	}
	installID := installations[0].ID

	// 4. POST /app/installations/{id}/access_tokens → get token
	tokenURL := fmt.Sprintf("https://api.github.com/app/installations/%d/access_tokens", installID)
	req, _ = http.NewRequest("POST", tokenURL, nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp2, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to create installation token: %v", err)
	}
	defer resp2.Body.Close()
	body2, _ := io.ReadAll(resp2.Body)
	if resp2.StatusCode != 201 {
		t.Fatalf("POST access_tokens returned %d: %s", resp2.StatusCode, string(body2))
	}

	var tokenResp struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(body2, &tokenResp); err != nil {
		t.Fatalf("Failed to parse token response: %v", err)
	}
	if tokenResp.Token == "" {
		t.Fatal("Empty token in installation access_tokens response")
	}

	return tokenResp.Token
}

// base64URLEncode encodes bytes as unpadded base64url (RFC 7515).
func base64URLEncode(data []byte) string {
	s := base64.StdEncoding.EncodeToString(data)
	s = strings.TrimRight(s, "=")
	s = strings.ReplaceAll(s, "+", "-")
	s = strings.ReplaceAll(s, "/", "_")
	return s
}
