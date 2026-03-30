// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only

package risk

import (
	"strings"
	"testing"
	"time"
)

func TestSizeAnomalyOverridesMajorTagAdvance(t *testing.T) {
	t.Parallel()
	sev, signals := Score(ScoreContext{
		TagName:       "v4",
		IsDescendant:  true,
		EntryPointOld: 1000,
		EntryPointNew: 5000, // +400%

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
	t.Parallel()
	sev, _ := Score(ScoreContext{TagName: "v1.2.3", IsDescendant: false})
	if sev != SeverityCritical {
		t.Errorf("expected CRITICAL for semver repoint, got %s", sev)
	}
}

func TestScoreMassRepoint(t *testing.T) {
	t.Parallel()
	sev, _ := Score(ScoreContext{TagName: "v1", BatchSize: 10})
	if sev != SeverityCritical {
		t.Errorf("expected CRITICAL for mass repoint, got %s", sev)
	}
}

func TestScoreLegitimateAdvance(t *testing.T) {
	t.Parallel()
	sev, _ := Score(ScoreContext{
		TagName: "v4", IsDescendant: true,
	})
	if sev != SeverityLow {
		t.Errorf("expected LOW for legitimate major tag advance, got %s", sev)
	}
}

func TestScore_AllSignalsCritical(t *testing.T) {
	t.Parallel()
	sev, signals := Score(ScoreContext{
		BatchSize:     10,
		IsDescendant:  false,
		EntryPointOld: 100,
		EntryPointNew: 5000,
		TagName:       "v1.2.3",
		CommitDate:    time.Now().Add(-180 * 24 * time.Hour),

		SelfHosted:    true,
	})
	if sev != SeverityCritical {
		t.Errorf("expected CRITICAL, got %s", sev)
	}
	if len(signals) < 6 {
		t.Errorf("expected at least 6 signals, got %d: %v", len(signals), signals)
	}
	expected := []string{"MASS_REPOINT", "OFF_BRANCH", "SIZE_ANOMALY", "SEMVER_REPOINT", "BACKDATED_COMMIT", "SELF_HOSTED"}
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
	t.Parallel()
	sev, signals := Score(ScoreContext{
		TagName:       "v4",
		IsDescendant:  true,
		EntryPointOld: 1000,
		EntryPointNew: 5000,

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
	t.Parallel()
	sev, _ := Score(ScoreContext{
		TagName:       "v4",
		IsDescendant:  true,
		EntryPointOld: 0,
		EntryPointNew: 0,

	})
	if sev != SeverityLow {
		t.Errorf("expected LOW, got %s", sev)
	}
}

func TestScore_SingleTagNonDescendant(t *testing.T) {
	t.Parallel()
	sev, _ := Score(ScoreContext{
		TagName:       "v1.5.0",
		IsDescendant:  false,
		AheadBy:       0,

	})
	if sev != SeverityCritical {
		t.Errorf("expected CRITICAL (SEMVER_REPOINT+OFF_BRANCH=130), got %s", sev)
	}
}

func TestScore_BackdatedWithRelease(t *testing.T) {
	t.Parallel()
	sev, _ := Score(ScoreContext{
		TagName:       "v1",
		CommitDate:    time.Now().Add(-60 * 24 * time.Hour),

		IsDescendant:  true,
	})
	if sev != SeverityLow {
		t.Errorf("expected LOW (BACKDATED+MAJOR_TAG_ADVANCE=10), got %s", sev)
	}
}

func TestScore_ZeroBatchSize(t *testing.T) {
	t.Parallel()
	sev, signals := Score(ScoreContext{
		BatchSize:     0,
		TagName:       "v1",
		IsDescendant:  true,

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
	t.Parallel()
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
	t.Parallel()
	// Child dated 2026-03-20, parent dated 2026-03-19 → no signal
	_, signals := Score(ScoreContext{
		TagName:    "v1",
		CommitDate: time.Now(),
		ParentDate: time.Now().Add(-24 * time.Hour),
		ParentSHA:  "abc123",
		IsDescendant: true,

	})
	for _, s := range signals {
		if strings.HasPrefix(s, "IMPOSSIBLE_TIMESTAMP") {
			t.Errorf("IMPOSSIBLE_TIMESTAMP should not fire for normal order, got: %v", signals)
		}
	}
}

func TestSameDate(t *testing.T) {
	t.Parallel()
	// Child and parent same date → no signal
	now := time.Now()
	_, signals := Score(ScoreContext{
		TagName:    "v1",
		CommitDate: now,
		ParentDate: now,
		ParentSHA:  "abc123",
		IsDescendant: true,

	})
	for _, s := range signals {
		if strings.HasPrefix(s, "IMPOSSIBLE_TIMESTAMP") {
			t.Errorf("IMPOSSIBLE_TIMESTAMP should not fire for same date, got: %v", signals)
		}
	}
}

func TestNoParent(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
		"SIGNATURE_DROPPED",
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
	if len(signals) < 7 {
		t.Errorf("expected at least 7 signals, got %d: %v", len(signals), signals)
	}
}

// === Spec 017: SIGNATURE_DROPPED tests ===

func TestSignatureDropped(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
	_, signals := Score(ScoreContext{
		TagName:      "v1",
		WasGPGSigned: true,
		IsGPGSigned:  true,
		IsDescendant: true,

	})
	for _, s := range signals {
		if strings.HasPrefix(s, "SIGNATURE_DROPPED") {
			t.Errorf("SIGNATURE_DROPPED should not fire when both signed, got: %v", signals)
		}
	}
}

func TestSignatureNeverSigned(t *testing.T) {
	t.Parallel()
	_, signals := Score(ScoreContext{
		TagName:      "v1",
		WasGPGSigned: false,
		IsGPGSigned:  false,
		IsDescendant: true,

	})
	for _, s := range signals {
		if strings.HasPrefix(s, "SIGNATURE_DROPPED") {
			t.Errorf("SIGNATURE_DROPPED should not fire when both unsigned, got: %v", signals)
		}
	}
}

func TestSignatureLockfileNoData(t *testing.T) {
	t.Parallel()
	_, signals := Score(ScoreContext{
		TagName:      "v1",
		WasGPGSigned: false,
		IsGPGSigned:  true,
		IsDescendant: true,

	})
	for _, s := range signals {
		if strings.HasPrefix(s, "SIGNATURE_DROPPED") {
			t.Errorf("SIGNATURE_DROPPED should not fire when lockfile had no data, got: %v", signals)
		}
	}
}

func TestScore_ExactlyFiveBatchSize(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
	// Known contributors [A, B], new release has commit from C → +35
	sev, signals := Score(ScoreContext{
		TagName:         "v4",
		IsDescendant:    true,

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
	t.Parallel()
	_, signals := Score(ScoreContext{
		TagName:         "v4",
		IsDescendant:    true,

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
	t.Parallel()
	_, signals := Score(ScoreContext{
		TagName:         "v4",
		IsDescendant:    true,

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
	t.Parallel()
	sev, signals := Score(ScoreContext{
		TagName:         "v4",
		IsDescendant:    true,

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
	t.Parallel()
	_, signals := Score(ScoreContext{
		TagName:         "v4",
		IsDescendant:    true,

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
	t.Parallel()
	_, signals := Score(ScoreContext{
		TagName:         "v4",
		IsDescendant:    true,

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
	t.Parallel()
	_, signals := Score(ScoreContext{
		TagName:         "v4",
		IsDescendant:    true,

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
	t.Parallel()
	_, signals := Score(ScoreContext{
		TagName:              "v4",
		IsDescendant:         true,

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
	t.Parallel()
	_, signals := Score(ScoreContext{
		TagName:              "v4",
		IsDescendant:         true,

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
	t.Parallel()
	_, signals := Score(ScoreContext{
		TagName:              "v4",
		IsDescendant:         true,

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
	t.Parallel()
	_, signals := Score(ScoreContext{
		TagName:              "v4",
		IsDescendant:         true,

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
	t.Parallel()
	_, signals := Score(ScoreContext{
		TagName:              "v4",
		IsDescendant:         true,

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
	t.Parallel()
	_, signals := Score(ScoreContext{
		TagName:              "v4",
		IsDescendant:         true,

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

func TestComposite_AllBehavioralSignals_Critical(t *testing.T) {
	t.Parallel()
	// Legitimate-looking attack: descendant, release exists, but all 3 behavioral signals fire
	// Score: -30 (MAJOR_TAG_ADVANCE) + 35 (CONTRIBUTOR) + 40 (DIFF) + 25 (CADENCE) = +70 → CRITICAL
	sev, signals := Score(ScoreContext{
		TagName:              "v4",
		IsDescendant:         true,

		CommitDate:           time.Now(),
		NewContributors:      []string{"attacker"},
		SuspiciousFiles:      []string{"dist/index.js", "action.yml"},
		DiffOnly:             false,
		MeanReleaseInterval:  30 * 24 * time.Hour,
		TimeSinceLastRelease: 2 * time.Hour,
		ReleaseHistoryLen:    5,
	})
	if sev != SeverityCritical {
		t.Errorf("expected CRITICAL for composite behavioral anomaly, got %s (signals: %v)", sev, signals)
	}
	expected := []string{"MAJOR_TAG_ADVANCE", "CONTRIBUTOR_ANOMALY", "DIFF_ANOMALY", "RELEASE_CADENCE_ANOMALY"}
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

func TestComposite_LegitimateRelease_Low(t *testing.T) {
	t.Parallel()
	sev, signals := Score(ScoreContext{
		TagName:              "v4",
		IsDescendant:         true,

		CommitDate:           time.Now(),
		NewContributors:      []string{},
		SuspiciousFiles:      []string{},
		MeanReleaseInterval:  30 * 24 * time.Hour,
		TimeSinceLastRelease: 25 * 24 * time.Hour,
		ReleaseHistoryLen:    10,
	})
	if sev != SeverityLow {
		t.Errorf("expected LOW for legitimate release, got %s (signals: %v)", sev, signals)
	}
}

func TestClassifyDiffFiles_MixedSuspicious(t *testing.T) {
	t.Parallel()
	files := []string{"src/main.ts", "dist/index.js", ".github/workflows/ci.yml"}
	suspicious, diffOnly := ClassifyDiffFiles(files)
	if len(suspicious) != 2 {
		t.Errorf("expected 2 suspicious files, got %d: %v", len(suspicious), suspicious)
	}
	if diffOnly {
		t.Error("expected diffOnly=false when normal files present")
	}
}

func TestClassifyDiffFiles_NormalOnly(t *testing.T) {
	t.Parallel()
	files := []string{"src/main.ts", "README.md", "package.json"}
	suspicious, _ := ClassifyDiffFiles(files)
	if len(suspicious) != 0 {
		t.Errorf("expected 0 suspicious files, got %d: %v", len(suspicious), suspicious)
	}
}

func TestClassifyDiffFiles_SuspiciousOnly(t *testing.T) {
	t.Parallel()
	files := []string{".github/workflows/ci.yml", "Makefile"}
	suspicious, diffOnly := ClassifyDiffFiles(files)
	if len(suspicious) != 2 {
		t.Errorf("expected 2 suspicious files, got %d: %v", len(suspicious), suspicious)
	}
	if !diffOnly {
		t.Error("expected diffOnly=true when only suspicious files")
	}
}

func TestClassifyDiffFiles_EntrypointSh(t *testing.T) {
	t.Parallel()
	files := []string{"entrypoint.sh", "src/main.go"}
	suspicious, diffOnly := ClassifyDiffFiles(files)
	if len(suspicious) != 1 || suspicious[0] != "entrypoint.sh" {
		t.Errorf("expected [entrypoint.sh], got: %v", suspicious)
	}
	if diffOnly {
		t.Error("expected diffOnly=false")
	}
}

func TestClassifyDiffFiles_Dockerfile(t *testing.T) {
	t.Parallel()
	files := []string{"Dockerfile", "src/index.ts"}
	suspicious, _ := ClassifyDiffFiles(files)
	if len(suspicious) != 1 {
		t.Errorf("expected 1 suspicious file, got %d: %v", len(suspicious), suspicious)
	}
}

func TestClassifyDiffFiles_ActionYml(t *testing.T) {
	t.Parallel()
	files := []string{"action.yml", "src/index.ts"}
	suspicious, _ := ClassifyDiffFiles(files)
	if len(suspicious) != 1 || suspicious[0] != "action.yml" {
		t.Errorf("expected [action.yml], got: %v", suspicious)
	}
}

func TestClassifyDiffFiles_DocsOnly(t *testing.T) {
	t.Parallel()
	files := []string{"docs/guide.md", "README.md", "LICENSE"}
	suspicious, _ := ClassifyDiffFiles(files)
	if len(suspicious) != 0 {
		t.Errorf("expected 0 suspicious for docs-only, got: %v", suspicious)
	}
}

func TestScore_BranchRefSkipsTagSignals(t *testing.T) {
	// A branch named "v1.2.3" should NOT trigger SEMVER_REPOINT
	_, signals := Score(ScoreContext{
		TagName:    "v1.2.3",
		IsBranch:   true,
		CommitDate: time.Now(),
	})
	for _, s := range signals {
		if strings.HasPrefix(s, "SEMVER_REPOINT") {
			t.Errorf("SEMVER_REPOINT should not fire for branch ref, got: %s", s)
		}
	}
}

func TestScore_BranchRefSkipsMajorTagAdvance(t *testing.T) {
	// A branch named "v2" should NOT get the -30 MAJOR_TAG_ADVANCE deduction
	_, signals := Score(ScoreContext{
		TagName:      "v2",
		IsBranch:     true,
		IsDescendant: true,
		CommitDate:   time.Now(),
	})
	for _, s := range signals {
		if strings.HasPrefix(s, "MAJOR_TAG_ADVANCE") {
			t.Errorf("MAJOR_TAG_ADVANCE should not fire for branch ref, got: %s", s)
		}
	}
}
