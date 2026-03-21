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
	Actions []ActionConfig `yaml:"actions"`
	Alerts  AlertConfig    `yaml:"alerts"`
	Store   StoreConfig    `yaml:"store"`
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
	MinSeverity   string `yaml:"min_severity"`   // "low", "medium", "critical"
	SlackWebhook  string `yaml:"slack_webhook"`
	WebhookURL    string `yaml:"webhook_url"`
	GitHubIssues  bool   `yaml:"github_issues"`
	Stdout        bool   `yaml:"stdout"`
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

	cfg := &Config{
		// Defaults
		Alerts: AlertConfig{
			MinSeverity: "medium",
			Stdout:      true,
		},
		Store: StoreConfig{
			Path: ".pinpoint-state.json",
		},
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config %s: %w", path, err)
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
