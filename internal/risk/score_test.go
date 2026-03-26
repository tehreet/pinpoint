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

// === Spec 019: IMPOSSIBLE_TIMESTAMP tests ===

func TestImpossibleTimestamp(t *testing.T) {
	// Child dated 2022, parent dated 2026 → +70, signal present
	sev, signals := Score(ScoreContext{
		TagName:    "v1.2.3",
		CommitDate: time.Date(2022, 6, 15, 0, 0, 0, 0, time.UTC),
		ParentDate: time.Date(2026, 3, 19, 0, 0, 0, 0, time.UTC),
		ParentSHA:  "abc123",
	})
	if sev != SeverityCritical {
		t.Errorf("expected CRITICAL, got %s", sev)
	}
	found := false
	for _, s := range signals {
		if strings.HasPrefix(s, "IMPOSSIBLE_TIMESTAMP") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected IMPOSSIBLE_TIMESTAMP signal, got: %v", signals)
	}
}

func TestNormalTimestampOrder(t *testing.T) {
	// Child dated 2026-03-20, parent dated 2026-03-19 → no signal
	_, signals := Score(ScoreContext{
		TagName:    "v1",
		CommitDate: time.Now(),
		ParentDate: time.Now().Add(-24 * time.Hour),
		ParentSHA:  "abc123",
		IsDescendant: true,
		ReleaseExists: true,
	})
	for _, s := range signals {
		if strings.HasPrefix(s, "IMPOSSIBLE_TIMESTAMP") {
			t.Errorf("IMPOSSIBLE_TIMESTAMP should not fire for normal order, got: %v", signals)
		}
	}
}

func TestSameDate(t *testing.T) {
	// Child and parent same date → no signal
	now := time.Now()
	_, signals := Score(ScoreContext{
		TagName:    "v1",
		CommitDate: now,
		ParentDate: now,
		ParentSHA:  "abc123",
		IsDescendant: true,
		ReleaseExists: true,
	})
	for _, s := range signals {
		if strings.HasPrefix(s, "IMPOSSIBLE_TIMESTAMP") {
			t.Errorf("IMPOSSIBLE_TIMESTAMP should not fire for same date, got: %v", signals)
		}
	}
}

func TestNoParent(t *testing.T) {
	// ParentDate is zero → no signal (root commits are fine)
	_, signals := Score(ScoreContext{
		TagName:    "v1",
		CommitDate: time.Date(2022, 1, 1, 0, 0, 0, 0, time.UTC),
	})
	for _, s := range signals {
		if strings.HasPrefix(s, "IMPOSSIBLE_TIMESTAMP") {
			t.Errorf("IMPOSSIBLE_TIMESTAMP should not fire with zero ParentDate, got: %v", signals)
		}
	}
}

func TestImpossibleWithBackdated(t *testing.T) {
	// Both IMPOSSIBLE_TIMESTAMP and BACKDATED_COMMIT fire independently, scores stack
	sev, signals := Score(ScoreContext{
		TagName:    "v1.2.3",
		CommitDate: time.Date(2022, 6, 15, 0, 0, 0, 0, time.UTC),
		ParentDate: time.Date(2026, 3, 19, 0, 0, 0, 0, time.UTC),
		ParentSHA:  "abc123",
	})
	if sev != SeverityCritical {
		t.Errorf("expected CRITICAL, got %s", sev)
	}
	hasImpossible := false
	hasBackdated := false
	for _, s := range signals {
		if strings.HasPrefix(s, "IMPOSSIBLE_TIMESTAMP") {
			hasImpossible = true
		}
		if strings.HasPrefix(s, "BACKDATED_COMMIT") {
			hasBackdated = true
		}
	}
	if !hasImpossible || !hasBackdated {
		t.Errorf("expected both IMPOSSIBLE_TIMESTAMP and BACKDATED_COMMIT, got: %v", signals)
	}
}

func TestTrivyFullReplay(t *testing.T) {
	// All signals fire together, total score >400
	sev, signals := Score(ScoreContext{
		BatchSize:     76,
		IsDescendant:  false,
		AheadBy:       0,
		EntryPointOld: 1000,
		EntryPointNew: 5000,
		TagName:       "v0.18.0",
		CommitDate:    time.Date(2022, 6, 15, 0, 0, 0, 0, time.UTC),
		ParentDate:    time.Date(2026, 3, 19, 0, 0, 0, 0, time.UTC),
		ParentSHA:     "57a97c7e",
		ReleaseExists: false,
		SelfHosted:    false,
		WasGPGSigned:  true,
		IsGPGSigned:   false,
	})
	if sev != SeverityCritical {
		t.Errorf("expected CRITICAL, got %s", sev)
	}
	expected := []string{
		"MASS_REPOINT", "OFF_BRANCH", "IMPOSSIBLE_TIMESTAMP",
		"SIZE_ANOMALY", "SEMVER_REPOINT", "BACKDATED_COMMIT",
		"SIGNATURE_DROPPED", "NO_RELEASE",
	}
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
	if len(signals) < 8 {
		t.Errorf("expected at least 8 signals, got %d: %v", len(signals), signals)
	}
}

// === Spec 017: SIGNATURE_DROPPED tests ===

func TestSignatureDropped(t *testing.T) {
	sev, signals := Score(ScoreContext{
		TagName:      "v1.2.3",
		WasGPGSigned: true,
		IsGPGSigned:  false,
		IsDescendant: false,
	})
	if sev != SeverityCritical {
		t.Errorf("expected CRITICAL, got %s", sev)
	}
	found := false
	for _, s := range signals {
		if strings.HasPrefix(s, "SIGNATURE_DROPPED") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected SIGNATURE_DROPPED signal, got: %v", signals)
	}
}

func TestSignatureStillSigned(t *testing.T) {
	_, signals := Score(ScoreContext{
		TagName:      "v1",
		WasGPGSigned: true,
		IsGPGSigned:  true,
		IsDescendant: true,
		ReleaseExists: true,
	})
	for _, s := range signals {
		if strings.HasPrefix(s, "SIGNATURE_DROPPED") {
			t.Errorf("SIGNATURE_DROPPED should not fire when both signed, got: %v", signals)
		}
	}
}

func TestSignatureNeverSigned(t *testing.T) {
	_, signals := Score(ScoreContext{
		TagName:      "v1",
		WasGPGSigned: false,
		IsGPGSigned:  false,
		IsDescendant: true,
		ReleaseExists: true,
	})
	for _, s := range signals {
		if strings.HasPrefix(s, "SIGNATURE_DROPPED") {
			t.Errorf("SIGNATURE_DROPPED should not fire when both unsigned, got: %v", signals)
		}
	}
}

func TestSignatureLockfileNoData(t *testing.T) {
	_, signals := Score(ScoreContext{
		TagName:      "v1",
		WasGPGSigned: false,
		IsGPGSigned:  true,
		IsDescendant: true,
		ReleaseExists: true,
	})
	for _, s := range signals {
		if strings.HasPrefix(s, "SIGNATURE_DROPPED") {
			t.Errorf("SIGNATURE_DROPPED should not fire when lockfile had no data, got: %v", signals)
		}
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

// === Spec 025: Behavioral Anomaly Signal tests ===

func TestContributorAnomaly_NewContributor(t *testing.T) {
	// Known contributors [A, B], new release has commit from C → +35
	sev, signals := Score(ScoreContext{
		TagName:         "v4",
		IsDescendant:    true,
		ReleaseExists:   true,
		CommitDate:      time.Now(),
		NewContributors: []string{"attacker-account"},
	})
	found := false
	for _, s := range signals {
		if strings.HasPrefix(s, "CONTRIBUTOR_ANOMALY") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected CONTRIBUTOR_ANOMALY signal, got: %v", signals)
	}
	// Score: -30 (MAJOR_TAG_ADVANCE) + 35 (CONTRIBUTOR_ANOMALY) = 5 → LOW
	if sev != SeverityLow {
		t.Errorf("expected LOW (score=5), got %s", sev)
	}
}

func TestContributorAnomaly_AllKnown(t *testing.T) {
	_, signals := Score(ScoreContext{
		TagName:         "v4",
		IsDescendant:    true,
		ReleaseExists:   true,
		CommitDate:      time.Now(),
		NewContributors: []string{},
	})
	for _, s := range signals {
		if strings.HasPrefix(s, "CONTRIBUTOR_ANOMALY") {
			t.Errorf("CONTRIBUTOR_ANOMALY should not fire when all authors known, got: %v", signals)
		}
	}
}

func TestContributorAnomaly_FirstLock(t *testing.T) {
	_, signals := Score(ScoreContext{
		TagName:         "v4",
		IsDescendant:    true,
		ReleaseExists:   true,
		CommitDate:      time.Now(),
		NewContributors: nil,
	})
	for _, s := range signals {
		if strings.HasPrefix(s, "CONTRIBUTOR_ANOMALY") {
			t.Errorf("CONTRIBUTOR_ANOMALY should not fire on first lock, got: %v", signals)
		}
	}
}

func TestDiffAnomaly_SuspiciousMixedWithNormal(t *testing.T) {
	sev, signals := Score(ScoreContext{
		TagName:         "v4",
		IsDescendant:    true,
		ReleaseExists:   true,
		CommitDate:      time.Now(),
		SuspiciousFiles: []string{"dist/index.js"},
		DiffOnly:        false,
	})
	found := false
	for _, s := range signals {
		if strings.HasPrefix(s, "DIFF_ANOMALY") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected DIFF_ANOMALY signal, got: %v", signals)
	}
	if sev != SeverityLow {
		t.Errorf("expected LOW (-30+40=10), got %s", sev)
	}
}

func TestDiffAnomaly_NormalOnly(t *testing.T) {
	_, signals := Score(ScoreContext{
		TagName:         "v4",
		IsDescendant:    true,
		ReleaseExists:   true,
		CommitDate:      time.Now(),
		SuspiciousFiles: []string{},
	})
	for _, s := range signals {
		if strings.HasPrefix(s, "DIFF_ANOMALY") {
			t.Errorf("DIFF_ANOMALY should not fire for normal-only diff, got: %v", signals)
		}
	}
}

func TestDiffAnomaly_SuspiciousOnly(t *testing.T) {
	_, signals := Score(ScoreContext{
		TagName:         "v4",
		IsDescendant:    true,
		ReleaseExists:   true,
		CommitDate:      time.Now(),
		SuspiciousFiles: []string{".github/workflows/ci.yml"},
		DiffOnly:        true,
	})
	found := false
	for _, s := range signals {
		if strings.HasPrefix(s, "DIFF_ANOMALY") {
			found = true
			if !strings.Contains(s, "suspicious files only") {
				t.Errorf("expected 'suspicious files only' in signal, got: %s", s)
			}
			break
		}
	}
	if !found {
		t.Errorf("expected DIFF_ANOMALY signal, got: %v", signals)
	}
}

func TestDiffAnomaly_NilSuspicious(t *testing.T) {
	_, signals := Score(ScoreContext{
		TagName:         "v4",
		IsDescendant:    true,
		ReleaseExists:   true,
		CommitDate:      time.Now(),
		SuspiciousFiles: nil,
	})
	for _, s := range signals {
		if strings.HasPrefix(s, "DIFF_ANOMALY") {
			t.Errorf("DIFF_ANOMALY should not fire with nil SuspiciousFiles, got: %v", signals)
		}
	}
}

func TestReleaseCadence_BurstRelease(t *testing.T) {
	_, signals := Score(ScoreContext{
		TagName:              "v4",
		IsDescendant:         true,
		ReleaseExists:        true,
		CommitDate:           time.Now(),
		MeanReleaseInterval:  30 * 24 * time.Hour,
		TimeSinceLastRelease: 2 * time.Hour,
		ReleaseHistoryLen:    5,
	})
	found := false
	for _, s := range signals {
		if strings.HasPrefix(s, "RELEASE_CADENCE_ANOMALY") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected RELEASE_CADENCE_ANOMALY signal, got: %v", signals)
	}
}

func TestReleaseCadence_NormalTiming(t *testing.T) {
	_, signals := Score(ScoreContext{
		TagName:              "v4",
		IsDescendant:         true,
		ReleaseExists:        true,
		CommitDate:           time.Now(),
		MeanReleaseInterval:  30 * 24 * time.Hour,
		TimeSinceLastRelease: 20 * 24 * time.Hour,
		ReleaseHistoryLen:    5,
	})
	for _, s := range signals {
		if strings.HasPrefix(s, "RELEASE_CADENCE_ANOMALY") {
			t.Errorf("RELEASE_CADENCE_ANOMALY should not fire for normal timing, got: %v", signals)
		}
	}
}

func TestReleaseCadence_HighCadenceExcluded(t *testing.T) {
	_, signals := Score(ScoreContext{
		TagName:              "v4",
		IsDescendant:         true,
		ReleaseExists:        true,
		CommitDate:           time.Now(),
		MeanReleaseInterval:  2 * 24 * time.Hour,
		TimeSinceLastRelease: 1 * time.Hour,
		ReleaseHistoryLen:    10,
	})
	for _, s := range signals {
		if strings.HasPrefix(s, "RELEASE_CADENCE_ANOMALY") {
			t.Errorf("RELEASE_CADENCE_ANOMALY should not fire for high-cadence projects, got: %v", signals)
		}
	}
}

func TestReleaseCadence_TooFewReleases(t *testing.T) {
	_, signals := Score(ScoreContext{
		TagName:              "v4",
		IsDescendant:         true,
		ReleaseExists:        true,
		CommitDate:           time.Now(),
		MeanReleaseInterval:  30 * 24 * time.Hour,
		TimeSinceLastRelease: 1 * time.Hour,
		ReleaseHistoryLen:    2,
	})
	for _, s := range signals {
		if strings.HasPrefix(s, "RELEASE_CADENCE_ANOMALY") {
			t.Errorf("RELEASE_CADENCE_ANOMALY should not fire with < 3 releases, got: %v", signals)
		}
	}
}

func TestReleaseCadence_DormantAction(t *testing.T) {
	_, signals := Score(ScoreContext{
		TagName:              "v4",
		IsDescendant:         true,
		ReleaseExists:        true,
		CommitDate:           time.Now(),
		MeanReleaseInterval:  30 * 24 * time.Hour,
		TimeSinceLastRelease: 180 * 24 * time.Hour,
		ReleaseHistoryLen:    5,
	})
	found := false
	for _, s := range signals {
		if strings.HasPrefix(s, "RELEASE_CADENCE_ANOMALY") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected RELEASE_CADENCE_ANOMALY for dormant action, got: %v", signals)
	}
}

func TestReleaseCadence_RapidFire(t *testing.T) {
	_, signals := Score(ScoreContext{
		TagName:              "v4",
		IsDescendant:         true,
		ReleaseExists:        true,
		CommitDate:           time.Now(),
		MeanReleaseInterval:  30 * 24 * time.Hour,
		TimeSinceLastRelease: 1 * time.Hour,
		ReleasesLast24h:      4,
		ReleaseHistoryLen:    10,
	})
	found := false
	for _, s := range signals {
		if strings.HasPrefix(s, "RELEASE_CADENCE_ANOMALY") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected RELEASE_CADENCE_ANOMALY for rapid-fire releases, got: %v", signals)
	}
}
