// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only

package risk

import (
	"strings"
	"testing"
	"time"
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

func TestScore_AllSignalsCritical(t *testing.T) {
	sev, signals := Score(ScoreContext{
		BatchSize:     10,
		IsDescendant:  false,
		EntryPointOld: 100,
		EntryPointNew: 5000,
		TagName:       "v1.2.3",
		CommitDate:    time.Now().Add(-180 * 24 * time.Hour),
		ReleaseExists: false,
		SelfHosted:    true,
	})
	if sev != SeverityCritical {
		t.Errorf("expected CRITICAL, got %s", sev)
	}
	if len(signals) < 7 {
		t.Errorf("expected at least 7 signals, got %d: %v", len(signals), signals)
	}
	expected := []string{"MASS_REPOINT", "OFF_BRANCH", "SIZE_ANOMALY", "SEMVER_REPOINT", "BACKDATED_COMMIT", "NO_RELEASE", "SELF_HOSTED"}
	for _, prefix := range expected {
		found := false
		for _, s := range signals {
			if strings.HasPrefix(s, prefix) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing signal %s in %v", prefix, signals)
		}
	}
}

func TestScore_MajorTagDescendantWithSizeAnomaly(t *testing.T) {
	sev, signals := Score(ScoreContext{
		TagName:       "v4",
		IsDescendant:  true,
		EntryPointOld: 1000,
		EntryPointNew: 5000,
		ReleaseExists: true,
		CommitDate:    time.Now(), // prevent BACKDATED from firing
	})
	if sev != SeverityCritical {
		t.Errorf("expected CRITICAL, got %s", sev)
	}
	found := false
	for _, s := range signals {
		if strings.HasPrefix(s, "SCORE_FLOOR") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected SCORE_FLOOR signal, got: %v", signals)
	}
}

func TestScore_MajorTagDescendantNoAnomaly(t *testing.T) {
	sev, _ := Score(ScoreContext{
		TagName:       "v4",
		IsDescendant:  true,
		EntryPointOld: 0,
		EntryPointNew: 0,
		ReleaseExists: true,
	})
	if sev != SeverityLow {
		t.Errorf("expected LOW, got %s", sev)
	}
}

func TestScore_SingleTagNonDescendant(t *testing.T) {
	sev, _ := Score(ScoreContext{
		TagName:       "v1.5.0",
		IsDescendant:  false,
		AheadBy:       0,
		ReleaseExists: true,
	})
	if sev != SeverityCritical {
		t.Errorf("expected CRITICAL (SEMVER_REPOINT+OFF_BRANCH=130), got %s", sev)
	}
}

func TestScore_BackdatedWithRelease(t *testing.T) {
	sev, _ := Score(ScoreContext{
		TagName:       "v1",
		CommitDate:    time.Now().Add(-60 * 24 * time.Hour),
		ReleaseExists: true,
		IsDescendant:  true,
	})
	if sev != SeverityLow {
		t.Errorf("expected LOW (BACKDATED+MAJOR_TAG_ADVANCE=10), got %s", sev)
	}
}

func TestScore_ZeroBatchSize(t *testing.T) {
	sev, signals := Score(ScoreContext{
		BatchSize:     0,
		TagName:       "v1",
		IsDescendant:  true,
		ReleaseExists: true,
	})
	for _, s := range signals {
		if strings.HasPrefix(s, "MASS_REPOINT") {
			t.Errorf("MASS_REPOINT should not fire with BatchSize=0, got: %v", signals)
		}
	}
	if sev != SeverityLow {
		t.Errorf("expected LOW, got %s", sev)
	}
}

func TestScore_ExactlyFiveBatchSize(t *testing.T) {
	_, signals := Score(ScoreContext{
		BatchSize: 5,
		TagName:   "v1",
	})
	for _, s := range signals {
		if strings.Contains(s, "MASS_REPOINT") {
			t.Errorf("MASS_REPOINT should not fire at exactly BatchSize=5, got: %v", signals)
		}
	}
}

func TestScore_SixBatchSize(t *testing.T) {
	sev, signals := Score(ScoreContext{
		BatchSize: 6,
		TagName:   "v1",
	})
	if sev != SeverityCritical {
		t.Errorf("expected CRITICAL, got %s", sev)
	}
	found := false
	for _, s := range signals {
		if strings.Contains(s, "MASS_REPOINT") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected MASS_REPOINT signal, got: %v", signals)
	}
}
