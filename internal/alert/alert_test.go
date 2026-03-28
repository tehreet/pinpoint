// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only

package alert

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tehreet/pinpoint/internal/risk"
)

// sampleAlert returns a populated Alert for use in tests.
func sampleAlert() risk.Alert {
	return risk.Alert{
		Severity:    risk.SeverityCritical,
		Type:        "TAG_REPOINTED",
		Action:      "actions/checkout",
		Tag:         "v4",
		PreviousSHA: "aabbccdd1122334455667788990011223344556677",
		CurrentSHA:  "deadbeef1122334455667788990011223344556677",
		DetectedAt:  time.Date(2026, 3, 28, 12, 0, 0, 0, time.UTC),
		Signals:     []string{"semver tag moved", "entry point changed"},
		SelfHosted:  false,
	}
}

func TestFormatJSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		alert         risk.Alert
		wantFields    []string
		wantNotFields []string
	}{
		{
			name:       "basic alert serializes expected fields",
			alert:      sampleAlert(),
			wantFields: []string{`"severity"`, `"CRITICAL"`, `"type"`, `"TAG_REPOINTED"`, `"action"`, `"actions/checkout"`, `"tag"`, `"v4"`},
		},
		{
			name: "self-hosted flag included",
			alert: func() risk.Alert {
				a := sampleAlert()
				a.SelfHosted = true
				return a
			}(),
			wantFields: []string{`"self_hosted_runners": true`},
		},
		{
			name: "signals array present",
			alert: func() risk.Alert {
				a := sampleAlert()
				a.Signals = []string{"signal-one", "signal-two"}
				return a
			}(),
			wantFields: []string{`"signals"`, `"signal-one"`, `"signal-two"`},
		},
		{
			name: "empty signals field still present",
			alert: func() risk.Alert {
				a := sampleAlert()
				a.Signals = nil
				return a
			}(),
			wantFields: []string{`"signals"`},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			out, err := FormatJSON(tc.alert)
			if err != nil {
				t.Fatalf("FormatJSON: unexpected error: %v", err)
			}

			// Verify it is valid JSON.
			var parsed map[string]interface{}
			if err := json.Unmarshal([]byte(out), &parsed); err != nil {
				t.Fatalf("output is not valid JSON: %v\noutput: %s", err, out)
			}

			for _, want := range tc.wantFields {
				if !strings.Contains(out, want) {
					t.Errorf("FormatJSON output missing %q\nfull output:\n%s", want, out)
				}
			}
		})
	}
}

func TestEmitSlackWebhook(t *testing.T) {
	t.Parallel()

	var received []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		received = body
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	emitter := NewEmitter(false, srv.URL, "")
	if err := emitter.Emit(sampleAlert()); err != nil {
		t.Fatalf("Emit: unexpected error: %v", err)
	}

	if len(received) == 0 {
		t.Fatal("Slack server received no request body")
	}

	// Slack payload is {"text": "..."}
	var payload map[string]string
	if err := json.Unmarshal(received, &payload); err != nil {
		t.Fatalf("Slack payload not valid JSON: %v\nbody: %s", err, received)
	}
	text, ok := payload["text"]
	if !ok {
		t.Fatalf("Slack payload missing 'text' key, got keys: %v", keysOf(payload))
	}
	if !strings.Contains(text, "actions/checkout") {
		t.Errorf("Slack text should mention action name, got: %s", text)
	}
}

func TestEmitGenericWebhook(t *testing.T) {
	t.Parallel()

	var received []byte
	var contentType string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		received = body
		contentType = r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	emitter := NewEmitter(false, "", srv.URL)
	alert := sampleAlert()
	if err := emitter.Emit(alert); err != nil {
		t.Fatalf("Emit: unexpected error: %v", err)
	}

	if len(received) == 0 {
		t.Fatal("webhook server received no request body")
	}
	if !strings.Contains(contentType, "application/json") {
		t.Errorf("want Content-Type application/json, got %s", contentType)
	}

	var parsedAlert risk.Alert
	if err := json.Unmarshal(received, &parsedAlert); err != nil {
		t.Fatalf("webhook body not a valid Alert JSON: %v\nbody: %s", err, received)
	}
	if parsedAlert.Action != alert.Action {
		t.Errorf("webhook body action: want %s, got %s", alert.Action, parsedAlert.Action)
	}
	if parsedAlert.Type != alert.Type {
		t.Errorf("webhook body type: want %s, got %s", alert.Type, parsedAlert.Type)
	}
}

func TestEmitSlackWebhookError(t *testing.T) {
	t.Parallel()

	// Server returns 500 — emitter should return an error, not panic.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	emitter := NewEmitter(false, srv.URL, "")
	err := emitter.Emit(sampleAlert())
	if err == nil {
		t.Fatal("want error for 500 response, got nil")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error should mention status code 500, got: %s", err.Error())
	}
}

func TestEmitGenericWebhookError(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	emitter := NewEmitter(false, "", srv.URL)
	err := emitter.Emit(sampleAlert())
	if err == nil {
		t.Fatal("want error for 502 response, got nil")
	}
}

func TestEmitStdoutDoesNotPanic(t *testing.T) {
	t.Parallel()

	// Stdout emitter writes to os.Stdout — we just verify it doesn't panic or error.
	emitter := NewEmitter(true, "", "")
	if err := emitter.Emit(sampleAlert()); err != nil {
		t.Fatalf("Emit to stdout: unexpected error: %v", err)
	}
}

func TestEmitStdoutWithSelfHosted(t *testing.T) {
	t.Parallel()

	a := sampleAlert()
	a.SelfHosted = true
	emitter := NewEmitter(true, "", "")
	// Just verify no panic; output goes to os.Stdout.
	if err := emitter.Emit(a); err != nil {
		t.Fatalf("Emit with SelfHosted: unexpected error: %v", err)
	}
}

func TestNewEmitter(t *testing.T) {
	t.Parallel()

	t.Run("fields stored correctly", func(t *testing.T) {
		t.Parallel()
		e := NewEmitter(true, "https://hooks.slack.com/abc", "https://example.com/hook")
		if !e.stdout {
			t.Error("want stdout=true")
		}
		if e.slackWebhook != "https://hooks.slack.com/abc" {
			t.Errorf("unexpected slackWebhook: %s", e.slackWebhook)
		}
		if e.webhookURL != "https://example.com/hook" {
			t.Errorf("unexpected webhookURL: %s", e.webhookURL)
		}
	})

	t.Run("no destinations — emit returns nil", func(t *testing.T) {
		t.Parallel()
		e := NewEmitter(false, "", "")
		if err := e.Emit(sampleAlert()); err != nil {
			t.Fatalf("Emit with no destinations: unexpected error: %v", err)
		}
	})
}

func TestTruncSHA(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input string
		want  string
	}{
		{"", ""},
		{"abcdef", "abcdef"},
		{"abcdefghijkl", "abcdefghijkl"}, // exactly 12
		{"abcdefghijklm", "abcdefghijkl"}, // 13 chars → truncated to 12
		{"aabbccdd1122334455667788990011223344556677", "aabbccdd1122"}, // full SHA
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			t.Parallel()
			got := truncSHA(tc.input)
			if got != tc.want {
				t.Errorf("truncSHA(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

// keysOf returns the keys of a map for use in error messages.
func keysOf(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
