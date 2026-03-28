// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only

package sarif

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/tehreet/pinpoint/internal/audit"
	"github.com/tehreet/pinpoint/internal/risk"
	"github.com/tehreet/pinpoint/internal/util"
)

const sarifSchema = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
const sarifVersion = "2.1.0"
const informationURI = "https://github.com/tehreet/pinpoint"

// SARIF 2.1.0 types — only what we need.

// Log is the top-level SARIF document.
type Log struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []Run  `json:"runs"`
}

// Run represents a single analysis run.
type Run struct {
	Tool    Tool     `json:"tool"`
	Results []Result `json:"results"`
}

// Tool describes the analysis tool.
type Tool struct {
	Driver Driver `json:"driver"`
}

// Driver describes the primary analysis tool component.
type Driver struct {
	Name           string `json:"name"`
	Version        string `json:"version"`
	InformationURI string `json:"informationUri"`
	Rules          []Rule `json:"rules"`
}

// Rule defines a single rule (finding type).
type Rule struct {
	ID                   string          `json:"id"`
	ShortDescription     Message         `json:"shortDescription"`
	FullDescription      Message         `json:"fullDescription"`
	DefaultConfiguration Configuration   `json:"defaultConfiguration"`
	HelpURI              string          `json:"helpUri"`
	Properties           *RuleProperties `json:"properties,omitempty"`
}

// Configuration holds rule default configuration.
type Configuration struct {
	Level string `json:"level"`
}

// RuleProperties holds additional rule metadata.
type RuleProperties struct {
	Tags []string `json:"tags,omitempty"`
}

// Result is a single finding.
type Result struct {
	RuleID     string           `json:"ruleId"`
	Level      string           `json:"level"`
	Message    Message          `json:"message"`
	Locations  []Location       `json:"locations,omitempty"`
	Properties *ResultProperties `json:"properties,omitempty"`
}

// Message holds text content.
type Message struct {
	Text string `json:"text"`
}

// Location identifies where a result was found.
type Location struct {
	PhysicalLocation PhysicalLocation `json:"physicalLocation"`
}

// PhysicalLocation describes the file and region.
type PhysicalLocation struct {
	ArtifactLocation ArtifactLocation `json:"artifactLocation"`
	Region           *Region          `json:"region,omitempty"`
}

// ArtifactLocation identifies a file.
type ArtifactLocation struct {
	URI string `json:"uri"`
}

// Region identifies a region within a file.
type Region struct {
	StartLine int `json:"startLine"`
}

// ResultProperties holds additional result metadata.
type ResultProperties struct {
	Severity    string   `json:"severity,omitempty"`
	PreviousSHA string   `json:"previousSHA,omitempty"`
	CurrentSHA  string   `json:"currentSHA,omitempty"`
	Signals     []string `json:"signals,omitempty"`
	UsedInRepos int      `json:"usedInRepos,omitempty"`
	Risk        string   `json:"risk,omitempty"`
}

// The 5 rules pinpoint can report.
var rules = []Rule{
	{
		ID:               "pinpoint/tag-repointed",
		ShortDescription: Message{Text: "Action tag has been repointed"},
		FullDescription:  Message{Text: "A GitHub Action version tag now points to a different commit SHA than previously recorded. This could indicate a supply chain attack."},
		DefaultConfiguration: Configuration{Level: "error"},
		HelpURI:          informationURI + "#tag-repointing",
		Properties:       &RuleProperties{Tags: []string{"security", "supply-chain"}},
	},
	{
		ID:               "pinpoint/tag-unpinned",
		ShortDescription: Message{Text: "Action is not SHA-pinned"},
		FullDescription:  Message{Text: "This action reference uses a mutable tag instead of a commit SHA. It is vulnerable to tag repointing attacks."},
		DefaultConfiguration: Configuration{Level: "warning"},
		HelpURI:          informationURI + "#sha-pinning",
	},
	{
		ID:               "pinpoint/branch-pinned",
		ShortDescription: Message{Text: "Action is pinned to a branch"},
		FullDescription:  Message{Text: "This action uses a branch reference which changes on every commit. This is the least secure form of action pinning."},
		DefaultConfiguration: Configuration{Level: "error"},
		HelpURI:          informationURI + "#branch-pinning",
	},
	{
		ID:               "pinpoint/no-immutable-release",
		ShortDescription: Message{Text: "Action lacks immutable releases"},
		FullDescription:  Message{Text: "This action's upstream repository does not have immutable releases enabled, making tag repointing easier for attackers."},
		DefaultConfiguration: Configuration{Level: "note"},
		HelpURI:          informationURI + "#immutable-releases",
	},
	{
		ID:               "pinpoint/no-gate",
		ShortDescription: Message{Text: "Workflow has no pinpoint gate"},
		FullDescription:  Message{Text: "This workflow does not include a pinpoint gate step. Actions used in this workflow are not verified before execution."},
		DefaultConfiguration: Configuration{Level: "warning"},
		HelpURI:          informationURI + "#gate",
	},
	{
		ID:               "PNPT-TRIGGER-001",
		ShortDescription: Message{Text: "Dangerous pull_request_target trigger"},
		FullDescription:  Message{Text: "Workflow uses pull_request_target which runs with write tokens on external PRs. This is the root cause of both the tj-actions and Trivy supply chain attacks."},
		DefaultConfiguration: Configuration{Level: "error"},
		HelpURI:          "https://securitylab.github.com/research/github-actions-preventing-pwn-requests/",
		Properties:       &RuleProperties{Tags: []string{"security", "supply-chain"}},
	},
}

func newLog(toolVersion string) *Log {
	return &Log{
		Schema:  sarifSchema,
		Version: sarifVersion,
		Runs: []Run{
			{
				Tool: Tool{
					Driver: Driver{
						Name:           "pinpoint",
						Version:        toolVersion,
						InformationURI: informationURI,
						Rules:          rules,
					},
				},
				Results: []Result{},
			},
		},
	}
}

// severityToLevel maps pinpoint severity to SARIF level.
func severityToLevel(s risk.Severity) string {
	switch s {
	case risk.SeverityCritical:
		return "error"
	case risk.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

// FormatScanSARIF converts scan alerts to a SARIF log.
func FormatScanSARIF(alerts []risk.Alert, toolVersion string) (string, error) {
	log := newLog(toolVersion)

	for _, a := range alerts {
		r := Result{
			RuleID:  "pinpoint/tag-repointed",
			Level:   severityToLevel(a.Severity),
			Message: Message{Text: fmt.Sprintf("%s@%s tag has been repointed from %s to %s. This may indicate a supply chain attack.", a.Action, a.Tag, util.ShortSHA(a.PreviousSHA), util.ShortSHA(a.CurrentSHA))},
			Properties: &ResultProperties{
				Severity:    string(a.Severity),
				PreviousSHA: a.PreviousSHA,
				CurrentSHA:  a.CurrentSHA,
				Signals:     a.Signals,
			},
		}

		if a.Type == "TAG_DELETED" {
			r.Message = Message{Text: fmt.Sprintf("%s@%s tag has been deleted. This may indicate a supply chain attack.", a.Action, a.Tag)}
		}

		log.Runs[0].Results = append(log.Runs[0].Results, r)
	}

	return marshalSARIF(log)
}

// FormatAuditSARIF converts audit results to a SARIF log.
func FormatAuditSARIF(result *audit.AuditResult, toolVersion string) (string, error) {
	log := newLog(toolVersion)

	for _, action := range result.UniqueActions {
		for _, ref := range action.Refs {
			switch ref.Type {
			case "tag":
				r := Result{
					RuleID:  "pinpoint/tag-unpinned",
					Level:   "warning",
					Message: Message{Text: fmt.Sprintf("%s@%s in %d repos is not SHA-pinned. Pin to a commit SHA for immutability.", action.Repo, ref.Ref, action.UsedInRepos)},
					Properties: &ResultProperties{
						UsedInRepos: action.UsedInRepos,
						Risk:        action.Risk,
					},
				}
				log.Runs[0].Results = append(log.Runs[0].Results, r)

			case "branch":
				r := Result{
					RuleID:  "pinpoint/branch-pinned",
					Level:   "error",
					Message: Message{Text: fmt.Sprintf("%s@%s in %d repos is pinned to a branch. Branch refs change on every commit and are the least secure form of action pinning.", action.Repo, ref.Ref, action.UsedInRepos)},
					Properties: &ResultProperties{
						UsedInRepos: action.UsedInRepos,
						Risk:        action.Risk,
					},
				}
				log.Runs[0].Results = append(log.Runs[0].Results, r)
			}
		}

		// No immutable releases
		if action.ImmutableRelease != nil && !*action.ImmutableRelease {
			r := Result{
				RuleID:  "pinpoint/no-immutable-release",
				Level:   "note",
				Message: Message{Text: fmt.Sprintf("%s does not have immutable releases enabled. Used in %d repos.", action.Repo, action.UsedInRepos)},
				Properties: &ResultProperties{
					UsedInRepos: action.UsedInRepos,
					Risk:        action.Risk,
				},
			}
			log.Runs[0].Results = append(log.Runs[0].Results, r)
		}
	}

	// Dangerous triggers
	for _, finding := range result.DangerousTriggers {
		level := "note"
		switch finding.Risk {
		case "critical":
			level = "error"
		case "high":
			level = "warning"
		}
		r := Result{
			RuleID:  "PNPT-TRIGGER-001",
			Level:   level,
			Message: Message{Text: fmt.Sprintf("%s/%s: %s", finding.Repo, finding.WorkflowFile, finding.Reason)},
			Locations: []Location{
				{PhysicalLocation: PhysicalLocation{
					ArtifactLocation: ArtifactLocation{URI: ".github/workflows/" + finding.WorkflowFile},
				}},
			},
			Properties: &ResultProperties{
				Risk: finding.Risk,
			},
		}
		log.Runs[0].Results = append(log.Runs[0].Results, r)
	}

	// Unprotected workflows
	for _, wf := range result.UnprotectedWorkflows {
		// wf is "repo-name/.github/workflows/ci.yml"
		parts := strings.SplitN(wf, "/", 2)
		uri := wf
		if len(parts) == 2 {
			uri = parts[1]
		}
		r := Result{
			RuleID:  "pinpoint/no-gate",
			Level:   "warning",
			Message: Message{Text: fmt.Sprintf("%s does not include a pinpoint gate step. Actions are not verified before execution.", wf)},
			Locations: []Location{
				{PhysicalLocation: PhysicalLocation{ArtifactLocation: ArtifactLocation{URI: uri}}},
			},
		}
		log.Runs[0].Results = append(log.Runs[0].Results, r)
	}

	return marshalSARIF(log)
}

func marshalSARIF(log *Log) (string, error) {
	data, err := json.MarshalIndent(log, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshaling SARIF: %w", err)
	}
	return string(data) + "\n", nil
}

