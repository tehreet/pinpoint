// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only

package verify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/tehreet/pinpoint/internal/util"
)

const (
	maxBatchSize           = 50
	defaultChronoTolerance = 48 * time.Hour
)

// StatusClean indicates all integrity signals passed.
const StatusClean = "clean"

// StatusLimited indicates the action could not be fully verified (e.g., no releases).
const StatusLimited = "limited"

// StatusFailed indicates one or more integrity signals failed.
const StatusFailed = "failed"

// VerifyResult holds the aggregate results of a verify run.
type VerifyResult struct {
	Actions []ActionVerification `json:"actions"`
	Clean   int                  `json:"clean"`
	Limited int                  `json:"limited"`
	Failed  int                  `json:"failed"`
}

// ActionVerification holds the verification result for a single action.
type ActionVerification struct {
	Repo             string   `json:"repo"`
	Tag              string   `json:"tag"`
	CurrentSHA       string   `json:"current_sha"`
	Status           string   `json:"status"` // "clean", "limited", "failed"
	ReleaseSHAMatch  *bool    `json:"release_sha_match,omitempty"`
	ReleaseSHA       string   `json:"release_sha,omitempty"`
	ReleaseTag       string   `json:"release_tag,omitempty"` // The release tag used (may differ for major tags)
	GPGSigned        *bool    `json:"gpg_signed,omitempty"`
	GPGDiscontinuity bool     `json:"gpg_discontinuity"`
	ChronologyValid  *bool    `json:"chronology_valid,omitempty"`
	AuthoredDate     string   `json:"authored_date,omitempty"`
	ParentDate       string   `json:"parent_date,omitempty"`
	Advisories       []string `json:"advisories,omitempty"`
	Notes            []string `json:"notes,omitempty"`
}

// VerifyOptions configures the verify command.
type VerifyOptions struct {
	ChronologyTolerance time.Duration
	GraphQLEndpoint     string
	RESTEndpoint        string
	Token               string
	HTTPClient          *http.Client
}

// ActionInput represents an action to verify (repo + tag).
type ActionInput struct {
	Repo string
	Tag  string
}

// knownCompromisedSHAs is a hardcoded list of known-bad commit SHAs from major incidents.
var knownCompromisedSHAs = map[string]string{
	"0e58ed8": "tj-actions/changed-files (CVE-2025-30066)",
	"a12a390": "tj-actions/changed-files (CVE-2025-30066)",
	"c4469e0": "reviewdog/action-setup (March 2025)",
	"4f7d56f": "aquasecurity/trivy-action (CVE-2026-28353)",
}

// graphqlRequest is the JSON body for a GraphQL API call.
type graphqlRequest struct {
	Query string `json:"query"`
}

// graphqlResponse is the top-level response from the GraphQL API.
type graphqlResponse struct {
	Data   map[string]json.RawMessage `json:"data"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

// releasesPayload wraps the releases list in a GraphQL response.
type releasesPayload struct {
	Nodes []releaseNode `json:"nodes"`
}

// refsPayload wraps the refs list in a GraphQL response.
type refsPayload struct {
	Nodes []refNode `json:"nodes"`
}

// repoVerifyPayload holds the parsed GraphQL response for a single repo.
type repoVerifyPayload struct {
	Releases releasesPayload `json:"releases"`
	Refs     refsPayload     `json:"refs"`
}

type releaseNode struct {
	TagName   string `json:"tagName"`
	CreatedAt string `json:"createdAt"`
	TagCommit struct {
		OID       string `json:"oid"`
		Signature *struct {
			IsValid bool `json:"isValid"`
			Signer  *struct {
				Login string `json:"login"`
			} `json:"signer"`
		} `json:"signature"`
		AuthoredDate  string `json:"authoredDate"`
		CommittedDate string `json:"committedDate"`
		Parents       struct {
			Nodes []struct {
				OID           string `json:"oid"`
				CommittedDate string `json:"committedDate"`
			} `json:"nodes"`
		} `json:"parents"`
	} `json:"tagCommit"`
}

type refNode struct {
	Name   string `json:"name"`
	Target struct {
		TypeName string `json:"__typename"`
		OID      string `json:"oid"`
		Target   *struct {
			OID string `json:"oid"`
		} `json:"target,omitempty"`
	} `json:"target"`
}

// advisory represents a GitHub security advisory.
type advisory struct {
	GHSAID          string `json:"ghsa_id"`
	CVEID           string `json:"cve_id"`
	Vulnerabilities []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
	} `json:"vulnerabilities"`
}

// Verify checks integrity signals for a set of actions.
func Verify(ctx context.Context, actions []ActionInput, opts VerifyOptions) (*VerifyResult, error) {
	if opts.ChronologyTolerance == 0 {
		opts.ChronologyTolerance = defaultChronoTolerance
	}
	if opts.HTTPClient == nil {
		opts.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	}
	if opts.GraphQLEndpoint == "" {
		opts.GraphQLEndpoint = "https://api.github.com/graphql"
	}
	if opts.RESTEndpoint == "" {
		opts.RESTEndpoint = "https://api.github.com"
	}

	// Deduplicate repos
	repoSet := make(map[string]bool)
	for _, a := range actions {
		repoSet[a.Repo] = true
	}
	var repos []string
	for r := range repoSet {
		repos = append(repos, r)
	}

	// Fetch GraphQL data in batches
	repoData := make(map[string]*repoVerifyPayload)
	for i := 0; i < len(repos); i += maxBatchSize {
		end := i + maxBatchSize
		if end > len(repos) {
			end = len(repos)
		}
		batch := repos[i:end]
		aliasToRepo := buildAliasMap(batch)
		query := buildVerifyQuery(aliasToRepo)

		respData, err := doGraphQL(ctx, opts.HTTPClient, opts.GraphQLEndpoint, opts.Token, query)
		if err != nil {
			return nil, fmt.Errorf("graphql batch %d: %w", i/maxBatchSize, err)
		}

		for alias, repo := range aliasToRepo {
			raw, ok := respData.Data[alias]
			if !ok {
				continue
			}
			var payload repoVerifyPayload
			if err := json.Unmarshal(raw, &payload); err != nil {
				continue
			}
			repoData[repo] = &payload
		}
	}

	// Fetch advisories
	advisoryMap := fetchAdvisories(ctx, opts.HTTPClient, opts.RESTEndpoint, opts.Token)

	// Verify each action
	result := &VerifyResult{}
	for _, action := range actions {
		av := verifyAction(action, repoData[action.Repo], advisoryMap, opts.ChronologyTolerance)
		result.Actions = append(result.Actions, av)
		switch av.Status {
		case StatusClean:
			result.Clean++
		case StatusLimited:
			result.Limited++
		case StatusFailed:
			result.Failed++
		}
	}

	return result, nil
}

// verifyAction runs all 4 signals against a single action.
func verifyAction(action ActionInput, data *repoVerifyPayload, advisoryMap map[string][]string, chronoTolerance time.Duration) ActionVerification {
	av := ActionVerification{
		Repo:   action.Repo,
		Tag:    action.Tag,
		Status: StatusClean,
	}

	if data == nil {
		av.Status = StatusLimited
		av.Notes = append(av.Notes, "could not fetch repository data")
		return av
	}

	// Resolve current tag SHA
	currentSHA := resolveTagSHA(action.Tag, data.Refs.Nodes)
	if currentSHA == "" {
		av.Status = StatusLimited
		av.Notes = append(av.Notes, fmt.Sprintf("tag %s not found in repository refs", action.Tag))
		return av
	}
	av.CurrentSHA = currentSHA

	// Signal 4: Known compromised SHA check (check prefix matches)
	for prefix, desc := range knownCompromisedSHAs {
		if strings.HasPrefix(currentSHA, prefix) {
			av.Status = StatusFailed
			av.Advisories = append(av.Advisories, desc)
			av.Notes = append(av.Notes, fmt.Sprintf("KNOWN_BAD_SHA: current SHA matches known compromised commit (%s)", desc))
		}
	}

	// Signal 1: Release/Tag SHA mismatch
	release := findMatchingRelease(action.Tag, currentSHA, data.Releases.Nodes)
	if release != nil {
		av.ReleaseTag = release.TagName
		av.ReleaseSHA = release.TagCommit.OID
		match := release.TagCommit.OID == currentSHA
		av.ReleaseSHAMatch = &match
		if !match {
			av.Status = StatusFailed
			av.Notes = append(av.Notes, fmt.Sprintf("RELEASE_MISMATCH: release %s recorded SHA %s but tag currently points to %s",
				release.TagName, util.ShortSHA(release.TagCommit.OID), util.ShortSHA(currentSHA)))
		}

		// Signal 2: GPG signature discontinuity
		checkGPGSignature(&av, release, data.Releases.Nodes)

		// Signal 3: Impossible chronology
		checkChronology(&av, release, chronoTolerance)
	} else {
		av.Notes = append(av.Notes, fmt.Sprintf("no release found for %s (limited verification)", action.Tag))
		if av.Status == StatusClean {
			av.Status = StatusLimited
		}
	}

	// Signal 4 (continued): Advisory database check
	if advs, ok := advisoryMap[action.Repo]; ok {
		av.Advisories = append(av.Advisories, advs...)
		av.Status = StatusFailed
		av.Notes = append(av.Notes, fmt.Sprintf("ADVISORY: %s has known security advisories: %s",
			action.Repo, strings.Join(advs, ", ")))
	}

	// Summary note for multiple failures
	failCount := 0
	for _, n := range av.Notes {
		if strings.HasPrefix(n, "RELEASE_MISMATCH") || strings.HasPrefix(n, "GPG_DISCONTINUITY") ||
			strings.HasPrefix(n, "IMPOSSIBLE_CHRONOLOGY") || strings.HasPrefix(n, "KNOWN_BAD_SHA") ||
			strings.HasPrefix(n, "ADVISORY") {
			failCount++
		}
	}
	if failCount > 1 {
		av.Notes = append(av.Notes, "MULTIPLE INTEGRITY SIGNALS FAILED — investigate immediately")
	}

	return av
}

// resolveTagSHA finds the commit SHA for a tag name from the refs list.
func resolveTagSHA(tagName string, refs []refNode) string {
	for _, ref := range refs {
		if ref.Name == tagName {
			// Dereference annotated tags
			if ref.Target.TypeName == "Tag" && ref.Target.Target != nil {
				return ref.Target.Target.OID
			}
			return ref.Target.OID
		}
	}
	return ""
}

// findMatchingRelease implements smart major tag resolution.
// For an exact tag like "v4.2.2", it looks for a release with that tagName.
// For a major tag like "v4", it looks for any release whose tagCommit.oid matches the current SHA.
func findMatchingRelease(tag, currentSHA string, releases []releaseNode) *releaseNode {
	// First: direct match by tag name
	for i := range releases {
		if releases[i].TagName == tag {
			return &releases[i]
		}
	}

	// Smart resolution: find a release whose tagCommit SHA matches currentSHA
	for i := range releases {
		if releases[i].TagCommit.OID == currentSHA {
			return &releases[i]
		}
	}

	return nil
}

// checkGPGSignature checks for GPG signature discontinuity (Signal 2).
func checkGPGSignature(av *ActionVerification, release *releaseNode, allReleases []releaseNode) {
	if release.TagCommit.Signature != nil && release.TagCommit.Signature.IsValid {
		signed := true
		av.GPGSigned = &signed
		return
	}

	// Check if other releases were signed (discontinuity detection)
	priorSigned := false
	for _, r := range allReleases {
		if r.TagName == release.TagName {
			continue
		}
		if r.TagCommit.Signature != nil && r.TagCommit.Signature.IsValid {
			priorSigned = true
			break
		}
	}

	signed := false
	av.GPGSigned = &signed

	if priorSigned {
		av.GPGDiscontinuity = true
		av.Status = StatusFailed
		av.Notes = append(av.Notes, "GPG_DISCONTINUITY: prior releases were GPG-signed but current tag commit is not")
	} else {
		av.Notes = append(av.Notes, "not GPG signed (no prior signed releases to compare)")
	}
}

// checkChronology checks for impossible chronology (Signal 3).
func checkChronology(av *ActionVerification, release *releaseNode, tolerance time.Duration) {
	if len(release.TagCommit.Parents.Nodes) == 0 {
		return
	}

	authoredStr := release.TagCommit.AuthoredDate
	parentDateStr := release.TagCommit.Parents.Nodes[0].CommittedDate

	if authoredStr == "" || parentDateStr == "" {
		return
	}

	authored, err := time.Parse(time.RFC3339, authoredStr)
	if err != nil {
		return
	}
	parentDate, err := time.Parse(time.RFC3339, parentDateStr)
	if err != nil {
		return
	}

	av.AuthoredDate = authoredStr
	av.ParentDate = parentDateStr

	// Impossible if authored date is before parent's committed date (minus tolerance)
	if authored.Before(parentDate.Add(-tolerance)) {
		valid := false
		av.ChronologyValid = &valid
		av.Status = StatusFailed
		av.Notes = append(av.Notes, fmt.Sprintf("IMPOSSIBLE_CHRONOLOGY: commit authored %s but parent committed %s (backdated by %s)",
			authored.Format("2006-01-02"), parentDate.Format("2006-01-02"),
			parentDate.Sub(authored).Round(time.Hour).String()))
	} else {
		valid := true
		av.ChronologyValid = &valid
	}
}

// fetchAdvisories fetches GitHub security advisories for the actions ecosystem.
// Returns a map of repo name -> list of advisory IDs.
func fetchAdvisories(ctx context.Context, client *http.Client, restEndpoint, token string) map[string][]string {
	result := make(map[string][]string)

	url := restEndpoint + "/advisories?type=reviewed&ecosystem=actions&per_page=100"
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return result
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := client.Do(req)
	if err != nil {
		return result
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return result
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return result
	}

	var advisories []advisory
	if err := json.Unmarshal(body, &advisories); err != nil {
		return result
	}

	for _, adv := range advisories {
		id := adv.CVEID
		if id == "" {
			id = adv.GHSAID
		}
		for _, vuln := range adv.Vulnerabilities {
			if vuln.Package.Ecosystem == "actions" && vuln.Package.Name != "" {
				result[vuln.Package.Name] = append(result[vuln.Package.Name], id)
			}
		}
	}

	return result
}

// buildAliasMap generates unique GraphQL aliases for repo names.
func buildAliasMap(repos []string) map[string]string {
	aliasToRepo := make(map[string]string)
	for _, repo := range repos {
		alias := repoToAlias(repo)
		if _, exists := aliasToRepo[alias]; exists {
			for i := 2; ; i++ {
				candidate := fmt.Sprintf("%s_%d", alias, i)
				if _, exists := aliasToRepo[candidate]; !exists {
					alias = candidate
					break
				}
			}
		}
		aliasToRepo[alias] = repo
	}
	return aliasToRepo
}

// repoToAlias converts "owner/repo" to a valid GraphQL alias.
func repoToAlias(ownerRepo string) string {
	alias := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			return r
		}
		return '_'
	}, ownerRepo)
	if len(alias) > 0 && alias[0] >= '0' && alias[0] <= '9' {
		alias = "_" + alias
	}
	return alias
}

// buildVerifyQuery constructs a GraphQL query fetching releases and current tag refs.
func buildVerifyQuery(aliasToRepo map[string]string) string {
	var b strings.Builder
	b.WriteString("{\n")
	for alias, repo := range aliasToRepo {
		parts := strings.SplitN(repo, "/", 2)
		owner, name := parts[0], parts[1]
		fmt.Fprintf(&b, `  %s: repository(owner: %q, name: %q) {
    releases(first: 10, orderBy: {field: CREATED_AT, direction: DESC}) {
      nodes {
        tagName
        createdAt
        tagCommit {
          oid
          signature { isValid signer { login } }
          authoredDate
          committedDate
          parents(first: 1) {
            nodes { oid committedDate }
          }
        }
      }
    }
    refs(refPrefix: "refs/tags/", first: 100) {
      nodes {
        name
        target {
          __typename
          oid
          ... on Tag { target { oid } }
        }
      }
    }
  }
`, alias, owner, name)
	}
	b.WriteString("}")
	return b.String()
}

// doGraphQL executes a GraphQL query against the given endpoint.
func doGraphQL(ctx context.Context, client *http.Client, endpoint, token, query string) (*graphqlResponse, error) {
	reqBody, err := json.Marshal(graphqlRequest{Query: query})
	if err != nil {
		return nil, fmt.Errorf("marshaling query: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("graphql request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("graphql API returned %d: %s", resp.StatusCode, string(body))
	}

	var gqlResp graphqlResponse
	if err := json.Unmarshal(body, &gqlResp); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	return &gqlResp, nil
}

// FormatText produces human-readable output for verify results.
func FormatText(result *VerifyResult) string {
	var b strings.Builder
	for _, av := range result.Actions {
		switch av.Status {
		case StatusClean:
			fmt.Fprintf(&b, "\n✓ %s@%s\n", av.Repo, av.Tag)
		case StatusLimited:
			fmt.Fprintf(&b, "\n⚠ %s@%s\n", av.Repo, av.Tag)
		case StatusFailed:
			fmt.Fprintf(&b, "\n✗ %s@%s\n", av.Repo, av.Tag)
		}

		if av.CurrentSHA != "" {
			fmt.Fprintf(&b, "    Tag %s → %s\n", av.Tag, util.ShortSHA(av.CurrentSHA))
		}

		if av.ReleaseSHAMatch != nil {
			if *av.ReleaseSHAMatch {
				fmt.Fprintf(&b, "    Release SHA matches current tag: ✓\n")
			} else {
				fmt.Fprintf(&b, "    Release SHA: %s MISMATCH (current: %s)\n",
					util.ShortSHA(av.ReleaseSHA), util.ShortSHA(av.CurrentSHA))
			}
		}

		if av.GPGSigned != nil {
			if *av.GPGSigned {
				fmt.Fprintf(&b, "    GPG signed: ✓\n")
			} else if av.GPGDiscontinuity {
				fmt.Fprintf(&b, "    GPG signed: ✗ (prior releases were signed)\n")
			} else {
				fmt.Fprintf(&b, "    Not GPG signed (no prior signed releases to compare)\n")
			}
		}

		if av.ChronologyValid != nil {
			if *av.ChronologyValid {
				fmt.Fprintf(&b, "    Chronology: ✓\n")
			} else {
				fmt.Fprintf(&b, "    Chronology: ✗ (authored %s, parent %s)\n",
					av.AuthoredDate, av.ParentDate)
			}
		}

		if len(av.Advisories) > 0 {
			fmt.Fprintf(&b, "    Advisories: %s\n", strings.Join(av.Advisories, ", "))
		} else {
			fmt.Fprintf(&b, "    Advisories: none\n")
		}

		for _, note := range av.Notes {
			if strings.HasPrefix(note, "MULTIPLE") {
				fmt.Fprintf(&b, "    ⚠ %s\n", note)
			}
		}
	}

	fmt.Fprintf(&b, "\nVerification complete: %d clean, %d limited, %d FAILED\n",
		result.Clean, result.Limited, result.Failed)
	return b.String()
}

// FormatJSON produces JSON output for verify results.
func FormatJSON(result *VerifyResult) (string, error) {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshaling json: %w", err)
	}
	return string(data), nil
}

