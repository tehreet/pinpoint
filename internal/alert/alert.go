// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only

package alert

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/tehreet/pinpoint/internal/risk"
)

// Emitter sends alerts to configured destinations.
type Emitter struct {
	stdout       bool
	slackWebhook string
	webhookURL   string
}

// NewEmitter creates an alert emitter from config.
func NewEmitter(stdout bool, slackWebhook, webhookURL string) *Emitter {
	return &Emitter{
		stdout:       stdout,
		slackWebhook: slackWebhook,
		webhookURL:   webhookURL,
	}
}

// Emit sends an alert to all configured destinations.
func (e *Emitter) Emit(alert risk.Alert) error {
	if e.stdout {
		e.emitStdout(alert)
	}
	if e.slackWebhook != "" {
		if err := e.emitSlack(alert); err != nil {
			return fmt.Errorf("slack alert: %w", err)
		}
	}
	if e.webhookURL != "" {
		if err := e.emitWebhook(alert); err != nil {
			return fmt.Errorf("webhook alert: %w", err)
		}
	}
	return nil
}

func (e *Emitter) emitStdout(alert risk.Alert) {
	severityColors := map[risk.Severity]string{
		risk.SeverityLow:      "\033[33m",  // Yellow
		risk.SeverityMedium:   "\033[38;5;208m", // Orange
		risk.SeverityCritical: "\033[31m",  // Red
	}
	reset := "\033[0m"
	bold := "\033[1m"

	color := severityColors[alert.Severity]

	fmt.Printf("\n%s%s[%s]%s %s%s%s\n", color, bold, alert.Severity, reset, bold, alert.Type, reset)
	fmt.Printf("  Action: %s\n", alert.Action)
	fmt.Printf("  Tag:    %s\n", alert.Tag)
	if alert.PreviousSHA != "" {
		fmt.Printf("  Before: %s\n", alert.PreviousSHA)
		fmt.Printf("  After:  %s\n", alert.CurrentSHA)
	}
	fmt.Printf("  Time:   %s\n", alert.DetectedAt.Format(time.RFC3339))

	if alert.SelfHosted {
		fmt.Printf("  %s⚠ SELF-HOSTED RUNNERS: Assume persistent compromise. Rotate all credentials.%s\n", "\033[31m", reset)
	}

	if len(alert.Signals) > 0 {
		fmt.Println("  Signals:")
		for _, sig := range alert.Signals {
			fmt.Printf("    • %s\n", sig)
		}
	}

	if len(alert.Enrichment) > 0 {
		for k, v := range alert.Enrichment {
			fmt.Printf("  %s: %s\n", k, v)
		}
	}
	fmt.Println()
}

func (e *Emitter) emitSlack(alert risk.Alert) error {
	emoji := map[risk.Severity]string{
		risk.SeverityLow:      "⚠️",
		risk.SeverityMedium:   "🟠",
		risk.SeverityCritical: "🚨",
	}

	var signals strings.Builder
	for _, s := range alert.Signals {
		signals.WriteString("• " + s + "\n")
	}

	selfHostedWarning := ""
	if alert.SelfHosted {
		selfHostedWarning = "\n*⚠ This action runs on self-hosted runners. Assume persistent compromise.*"
	}

	text := fmt.Sprintf(
		"%s *pinpoint: %s %s*\n\n*Action:* `%s`\n*Tag:* `%s`\n*Previous SHA:* `%s`\n*Current SHA:* `%s`\n\n*Signals:*\n%s%s",
		emoji[alert.Severity],
		alert.Severity,
		alert.Type,
		alert.Action,
		alert.Tag,
		truncSHA(alert.PreviousSHA),
		truncSHA(alert.CurrentSHA),
		signals.String(),
		selfHostedWarning,
	)

	payload := map[string]string{"text": text}
	return postJSON(e.slackWebhook, payload)
}

func (e *Emitter) emitWebhook(alert risk.Alert) error {
	return postJSON(e.webhookURL, alert)
}

func postJSON(url string, payload interface{}) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	resp, err := http.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.ReadAll(resp.Body)

	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned %d", resp.StatusCode)
	}
	return nil
}

func truncSHA(sha string) string {
	if len(sha) > 12 {
		return sha[:12]
	}
	return sha
}

// FormatJSON outputs the alert as JSON for machine consumption.
func FormatJSON(alert risk.Alert) (string, error) {
	data, err := json.MarshalIndent(alert, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}
