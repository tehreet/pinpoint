// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only

package risk

import (
	"strings"
	"testing"
)

func TestSizeAnomalyOverridesMajorTagAdvance(t *testing.T) {
	sev, signals := Score(ScoreContext{
		TagName:       "v4",
		IsDescendant:  true,
		EntryPointOld: 1000,
		EntryPointNew: 5000, // +400%
		ReleaseExists: true,
	})
	if sev != SeverityCritical {
		t.Errorf("expected CRITICAL, got %s (signals: %v)", sev, signals)
	}
	hasSize := false
	hasMajor := false
	for _, s := range signals {
		if strings.HasPrefix(s, "SIZE_ANOMALY") {
			hasSize = true
		}
		if strings.HasPrefix(s, "MAJOR_TAG_ADVANCE") {
			hasMajor = true
		}
	}
	if !hasSize || !hasMajor {
		t.Errorf("expected both SIZE_ANOMALY and MAJOR_TAG_ADVANCE signals, got: %v", signals)
	}
}

func TestScoreSemverRepoint(t *testing.T) {
	sev, _ := Score(ScoreContext{TagName: "v1.2.3", IsDescendant: false})
	if sev != SeverityCritical {
		t.Errorf("expected CRITICAL for semver repoint, got %s", sev)
	}
}

func TestScoreMassRepoint(t *testing.T) {
	sev, _ := Score(ScoreContext{TagName: "v1", BatchSize: 10})
	if sev != SeverityCritical {
		t.Errorf("expected CRITICAL for mass repoint, got %s", sev)
	}
}

func TestScoreLegitimateAdvance(t *testing.T) {
	sev, _ := Score(ScoreContext{
		TagName: "v4", IsDescendant: true, ReleaseExists: true,
	})
	if sev != SeverityLow {
		t.Errorf("expected LOW for legitimate major tag advance, got %s", sev)
	}
}
