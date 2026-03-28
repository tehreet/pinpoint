// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only

package config

import (
	"os"
	"strings"
	"testing"
)

func TestLoadFromBytes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		input       string
		wantErr     bool
		errContains string
		check       func(t *testing.T, cfg *Config)
	}{
		{
			name: "valid config with actions and allow rules",
			input: `
actions:
  - repo: actions/checkout
    tags: ["v4"]
  - repo: docker/build-push-action
    tags: ["v5"]
allow:
  - repo: actions/checkout
    tags: ["v4"]
    reason: "Trusted GitHub-maintained action"
alerts:
  min_severity: critical
  stdout: false
`,
			check: func(t *testing.T, cfg *Config) {
				t.Helper()
				if len(cfg.Actions) != 2 {
					t.Fatalf("want 2 actions, got %d", len(cfg.Actions))
				}
				if cfg.Actions[0].Repo != "actions/checkout" {
					t.Errorf("want actions/checkout, got %s", cfg.Actions[0].Repo)
				}
				if len(cfg.AllowRules) != 1 {
					t.Fatalf("want 1 allow rule, got %d", len(cfg.AllowRules))
				}
				if cfg.Alerts.MinSeverity != "critical" {
					t.Errorf("want critical severity, got %s", cfg.Alerts.MinSeverity)
				}
				if cfg.Alerts.Stdout {
					t.Error("want stdout=false")
				}
			},
		},
		{
			name:        "invalid YAML returns error",
			input:       "actions: [\nunclosed bracket",
			wantErr:     true,
			errContains: "parsing config",
		},
		{
			name: "allow rule without reason fails validation",
			input: `
allow:
  - repo: actions/checkout
    tags: ["v4"]
`,
			wantErr:     true,
			errContains: "reason",
		},
		{
			name: "allow rule with reason succeeds",
			input: `
allow:
  - repo: actions/checkout
    tags: ["v4"]
    reason: "Trusted upstream"
`,
			check: func(t *testing.T, cfg *Config) {
				t.Helper()
				if len(cfg.AllowRules) != 1 {
					t.Fatalf("want 1 allow rule, got %d", len(cfg.AllowRules))
				}
				if cfg.AllowRules[0].Reason != "Trusted upstream" {
					t.Errorf("unexpected reason: %s", cfg.AllowRules[0].Reason)
				}
			},
		},
		{
			name: "wildcard tags sets AllTags true",
			input: `
actions:
  - repo: actions/checkout
    tags: ["*"]
`,
			check: func(t *testing.T, cfg *Config) {
				t.Helper()
				if len(cfg.Actions) != 1 {
					t.Fatalf("want 1 action, got %d", len(cfg.Actions))
				}
				if !cfg.Actions[0].AllTags {
					t.Error("want AllTags=true for wildcard tags")
				}
			},
		},
		{
			name: "wildcard among other tags still sets AllTags true",
			input: `
actions:
  - repo: actions/checkout
    tags: ["v3", "*", "v4"]
`,
			check: func(t *testing.T, cfg *Config) {
				t.Helper()
				if !cfg.Actions[0].AllTags {
					t.Error("want AllTags=true when * is among tags")
				}
			},
		},
		{
			name: "non-wildcard tags leaves AllTags false",
			input: `
actions:
  - repo: actions/checkout
    tags: ["v4", "v5"]
`,
			check: func(t *testing.T, cfg *Config) {
				t.Helper()
				if cfg.Actions[0].AllTags {
					t.Error("want AllTags=false for non-wildcard tags")
				}
			},
		},
		{
			name:  "empty config returns defaults",
			input: "",
			check: func(t *testing.T, cfg *Config) {
				t.Helper()
				if cfg.Alerts.MinSeverity != "medium" {
					t.Errorf("want default medium severity, got %s", cfg.Alerts.MinSeverity)
				}
				if !cfg.Alerts.Stdout {
					t.Error("want default stdout=true")
				}
				if cfg.Store.Path != ".pinpoint-state.json" {
					t.Errorf("want default store path, got %s", cfg.Store.Path)
				}
				if len(cfg.Actions) != 0 {
					t.Errorf("want no actions, got %d", len(cfg.Actions))
				}
			},
		},
		{
			name: "multiple allow rules all require reason",
			input: `
allow:
  - repo: actions/checkout
    reason: "OK"
  - repo: docker/build-push-action
`,
			wantErr:     true,
			errContains: "reason",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg, err := LoadFromBytes([]byte(tc.input))
			if tc.wantErr {
				if err == nil {
					t.Fatal("want error, got nil")
				}
				if tc.errContains != "" && !strings.Contains(err.Error(), tc.errContains) {
					t.Errorf("error %q should contain %q", err.Error(), tc.errContains)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.check != nil {
				tc.check(t, cfg)
			}
		})
	}
}

func TestDefault(t *testing.T) {
	t.Parallel()

	cfg := Default()

	if cfg == nil {
		t.Fatal("Default() returned nil")
	}
	if cfg.Alerts.MinSeverity != "medium" {
		t.Errorf("want medium severity, got %s", cfg.Alerts.MinSeverity)
	}
	if !cfg.Alerts.Stdout {
		t.Error("want stdout=true")
	}
	if cfg.Store.Path != ".pinpoint-state.json" {
		t.Errorf("want .pinpoint-state.json, got %s", cfg.Store.Path)
	}
	if cfg.Actions == nil {
		t.Error("want non-nil Actions slice")
	}
	if len(cfg.Actions) != 0 {
		t.Errorf("want empty Actions, got %d", len(cfg.Actions))
	}
}

func TestLoad(t *testing.T) {
	t.Parallel()

	t.Run("missing file returns error", func(t *testing.T) {
		t.Parallel()
		_, err := Load("/nonexistent/path/pinpoint.yml")
		if err == nil {
			t.Fatal("want error for missing file, got nil")
		}
	})

	t.Run("valid file loads successfully", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		path := dir + "/pinpoint.yml"

		content := `
actions:
  - repo: actions/checkout
    tags: ["v4"]
`
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatalf("writing temp file: %v", err)
		}

		cfg, err := Load(path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(cfg.Actions) != 1 {
			t.Errorf("want 1 action, got %d", len(cfg.Actions))
		}
	})

	t.Run("invalid file content returns error", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		path := dir + "/pinpoint.yml"

		if err := os.WriteFile(path, []byte("actions: [\nunclosed"), 0644); err != nil {
			t.Fatalf("writing temp file: %v", err)
		}

		_, err := Load(path)
		if err == nil {
			t.Fatal("want error for invalid YAML, got nil")
		}
	})
}
