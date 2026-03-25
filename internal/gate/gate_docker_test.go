// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only

package gate

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGateDockerDigestVerification(t *testing.T) {
	const goodDigest = "sha256:9e3a184f680d5f4e1007348f04b020e7e34f205124e5fb2e7eae3ca2fd919e00"
	const badDigest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

	tests := []struct {
		name           string
		manifestDigest string
		liveDigest     string
		wantViolations int
	}{
		{
			name:           "digest matches",
			manifestDigest: goodDigest,
			liveDigest:     goodDigest,
			wantViolations: 0,
		},
		{
			name:           "digest mismatch — image repointed",
			manifestDigest: goodDigest,
			liveDigest:     badDigest,
			wantViolations: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			silenceOutput(t)

			registryTS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case strings.Contains(r.URL.Path, "/token"):
					fmt.Fprintf(w, `{"token":"test"}`)
				case r.Method == "HEAD" && strings.Contains(r.URL.Path, "/manifests/"):
					w.Header().Set("Docker-Content-Digest", tt.liveDigest)
					w.WriteHeader(http.StatusOK)
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer registryTS.Close()

			lockfile := Manifest{
				Version: 2,
				Actions: map[string]map[string]ManifestEntry{
					"aquasecurity/trivy-action": {
						"v0.28.0": {
							SHA:       "abc123def456abc123def456abc123def456abc1",
							Integrity: "sha256-AAAA",
							Type:      "docker",
							Docker: &DockerInfo{
								Image:  "ghcr.io/aquasecurity/trivy",
								Tag:    "0.58.1",
								Digest: tt.manifestDigest,
								Source: "action.yml",
							},
						},
					},
				},
			}
			lockJSON, _ := json.Marshal(lockfile)

			workflow := "on: push\njobs:\n  scan:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: aquasecurity/trivy-action@v0.28.0\n"

			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case strings.Contains(r.URL.Path, "/graphql"):
					resp := buildGraphQLResponse(map[string]map[string]string{
						"aquasecurity/trivy-action": {"v0.28.0": "abc123def456abc123def456abc123def456abc1"},
					})
					fmt.Fprint(w, resp)
				case strings.Contains(r.URL.Path, "ci.yml"):
					fmt.Fprint(w, buildContentResponse(workflow))
				case strings.Contains(r.URL.Path, "actions-lock.json"):
					fmt.Fprint(w, buildContentResponse(string(lockJSON)))
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer ts.Close()

			result, err := RunGate(context.Background(), GateOptions{
				Repo:         "owner/repo",
				SHA:          "abc123",
				WorkflowRef:  "owner/repo/.github/workflows/ci.yml@refs/heads/main",
				ManifestPath: ".github/actions-lock.json",
				APIURL:       ts.URL,
				GraphQLURL:   ts.URL + "/graphql",
				Integrity:    true,
				RegistryURL:  registryTS.URL,
			})

			if err != nil {
				t.Fatalf("RunGate: %v", err)
			}

			dockerViolations := 0
			for _, v := range result.Violations {
				if strings.Contains(v.ExpectedSHA, "sha256:") || strings.Contains(v.ActualSHA, "sha256:") {
					dockerViolations++
				}
			}

			if dockerViolations != tt.wantViolations {
				t.Errorf("docker violations = %d, want %d. All violations: %+v", dockerViolations, tt.wantViolations, result.Violations)
			}
		})
	}
}

func TestGateDockerScenarioC_ImageRefChanged(t *testing.T) {
	silenceOutput(t)

	lockfile := Manifest{
		Version: 2,
		Actions: map[string]map[string]ManifestEntry{
			"custom-org/scanner": {
				"v1": {
					SHA:       "abc123def456abc123def456abc123def456abc1",
					Integrity: "sha256-OriginalHash",
					Type:      "docker",
					Docker: &DockerInfo{
						Image:  "ghcr.io/safe-image",
						Tag:    "v1",
						Digest: "sha256:safe",
						Source: "action.yml",
					},
				},
			},
		},
	}
	lockJSON, _ := json.Marshal(lockfile)

	workflow := "on: push\njobs:\n  scan:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: custom-org/scanner@v1\n"

	attackerSHA := "bad456abc123bad456abc123bad456abc123bad4"

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/graphql"):
			resp := buildGraphQLResponse(map[string]map[string]string{
				"custom-org/scanner": {"v1": attackerSHA},
			})
			fmt.Fprint(w, resp)
		case strings.Contains(r.URL.Path, "ci.yml"):
			fmt.Fprint(w, buildContentResponse(workflow))
		case strings.Contains(r.URL.Path, "actions-lock.json"):
			fmt.Fprint(w, buildContentResponse(string(lockJSON)))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	result, err := RunGate(context.Background(), GateOptions{
		Repo:         "owner/repo",
		SHA:          "abc123",
		WorkflowRef:  "owner/repo/.github/workflows/ci.yml@refs/heads/main",
		ManifestPath: ".github/actions-lock.json",
		APIURL:       ts.URL,
		GraphQLURL:   ts.URL + "/graphql",
		Integrity:    true,
	})

	if err != nil {
		t.Fatalf("RunGate: %v", err)
	}

	if len(result.Violations) == 0 {
		t.Fatal("expected violation for tag repoint (Scenario C), got none")
	}

	found := false
	for _, v := range result.Violations {
		if v.Action == "custom-org/scanner" && v.ExpectedSHA != v.ActualSHA {
			found = true
		}
	}
	if !found {
		t.Errorf("no SHA mismatch violation for custom-org/scanner; violations: %+v", result.Violations)
	}
}

func TestGateDockerBaseImageVerification(t *testing.T) {
	const goodDigest = "sha256:aaa"
	const badDigest = "sha256:bbb"

	silenceOutput(t)

	registryTS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/token"):
			fmt.Fprintf(w, `{"token":"test"}`)
		case r.Method == "HEAD" && strings.Contains(r.URL.Path, "/manifests/"):
			// Return a different digest than what's recorded
			w.Header().Set("Docker-Content-Digest", badDigest)
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer registryTS.Close()

	lockfile := Manifest{
		Version: 2,
		Actions: map[string]map[string]ManifestEntry{
			"custom-org/builder": {
				"v1": {
					SHA:  "abc123def456abc123def456abc123def456abc1",
					Type: "docker",
					Docker: &DockerInfo{
						Image: "Dockerfile",
						BaseImages: []DockerBaseImage{
							{Image: "alpine", Tag: "3.19", Digest: goodDigest},
						},
						Source: "Dockerfile",
					},
				},
			},
		},
	}
	lockJSON, _ := json.Marshal(lockfile)

	workflow := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: custom-org/builder@v1\n"

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/graphql"):
			resp := buildGraphQLResponse(map[string]map[string]string{
				"custom-org/builder": {"v1": "abc123def456abc123def456abc123def456abc1"},
			})
			fmt.Fprint(w, resp)
		case strings.Contains(r.URL.Path, "ci.yml"):
			fmt.Fprint(w, buildContentResponse(workflow))
		case strings.Contains(r.URL.Path, "actions-lock.json"):
			fmt.Fprint(w, buildContentResponse(string(lockJSON)))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	result, err := RunGate(context.Background(), GateOptions{
		Repo:         "owner/repo",
		SHA:          "abc123",
		WorkflowRef:  "owner/repo/.github/workflows/ci.yml@refs/heads/main",
		ManifestPath: ".github/actions-lock.json",
		APIURL:       ts.URL,
		GraphQLURL:   ts.URL + "/graphql",
		Integrity:    true,
		RegistryURL:  registryTS.URL,
	})

	if err != nil {
		t.Fatalf("RunGate: %v", err)
	}

	// Should catch base image digest mismatch
	found := false
	for _, v := range result.Violations {
		if v.ExpectedSHA == goodDigest && v.ActualSHA == badDigest {
			found = true
		}
	}
	if !found {
		t.Errorf("expected base image digest violation, got: %+v", result.Violations)
	}
}
