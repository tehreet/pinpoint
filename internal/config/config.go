// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only

package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config represents the pinpoint configuration file.
type Config struct {
	Actions    []ActionConfig `yaml:"actions"`
	AllowRules []AllowRule    `yaml:"allow"`
	Alerts     AlertConfig    `yaml:"alerts"`
	Store      StoreConfig    `yaml:"store"`
}

// AllowRule defines a false-positive suppression rule.
type AllowRule struct {
	Repo      string   `yaml:"repo"`      // Glob pattern: "actions/*", "docker/build-push-action"
	Tags      []string `yaml:"tags"`      // Glob patterns: ["v*"], ["v1", "v2"]
	Actor     string   `yaml:"actor"`     // Committer/pusher: "github-actions[bot]"
	Condition string   `yaml:"condition"` // "major_tag_advance", "descendant", "any"
	Suppress  bool     `yaml:"suppress"`  // true = suppress ALL alerts for this match
	Reason    string   `yaml:"reason"`    // Human-readable justification (required)
}

// ActionConfig defines an action to monitor.
type ActionConfig struct {
	Repo     string   `yaml:"repo"`     // e.g. "aquasecurity/trivy-action"
	Tags     []string `yaml:"tags"`     // Specific tags, or ["*"] for all
	AllTags  bool     `yaml:"-"`        // Derived: true if tags contains "*"
	Discover bool     `yaml:"discover"` // Auto-discover from workflow files
	SelfHostedRunners bool `yaml:"self_hosted_runners"` // Flag for alert enrichment
}

// AlertConfig controls alerting behavior.
type AlertConfig struct {
	MinSeverity  string `yaml:"min_severity"` // "low", "medium", "critical"
	SlackWebhook string `yaml:"slack_webhook"`
	WebhookURL   string `yaml:"webhook_url"`
	Stdout       bool   `yaml:"stdout"`
}

// StoreConfig controls state persistence.
type StoreConfig struct {
	Path string `yaml:"path"` // Path to state JSON file
}

// Load reads and parses a pinpoint config file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config %s: %w", path, err)
	}

	cfg, err := LoadFromBytes(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}

	return cfg, nil
}

// LoadFromBytes parses config from raw YAML bytes.
func LoadFromBytes(data []byte) (*Config, error) {
	cfg := &Config{
		Alerts: AlertConfig{
			MinSeverity: "medium",
			Stdout:      true,
		},
		Store: StoreConfig{
			Path: ".pinpoint-state.json",
		},
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	// Process wildcard tags
	for i := range cfg.Actions {
		for _, t := range cfg.Actions[i].Tags {
			if t == "*" {
				cfg.Actions[i].AllTags = true
				break
			}
		}
	}

	// Validate allow rules
	for i, rule := range cfg.AllowRules {
		if rule.Reason == "" {
			return nil, fmt.Errorf("allow rule %d: 'reason' is required. Explain why this suppression is safe so future readers understand the risk acceptance", i+1)
		}
	}

	return cfg, nil
}

// Default returns a minimal default config for bootstrapping.
func Default() *Config {
	return &Config{
		Actions: []ActionConfig{},
		Alerts: AlertConfig{
			MinSeverity: "medium",
			Stdout:      true,
		},
		Store: StoreConfig{
			Path: ".pinpoint-state.json",
		},
	}
}
