// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only

package manifest

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseDockerRef(t *testing.T) {
	tests := []struct {
		name     string
		ref      string
		wantReg  string
		wantRepo string
		wantTag  string
		wantErr  bool
	}{
		{
			name:     "ghcr.io with tag",
			ref:      "docker://ghcr.io/aquasecurity/trivy:0.58.1",
			wantReg:  "ghcr.io",
			wantRepo: "aquasecurity/trivy",
			wantTag:  "0.58.1",
		},
		{
			name:     "ghcr.io with latest (no tag)",
			ref:      "docker://ghcr.io/owner/image",
			wantReg:  "ghcr.io",
			wantRepo: "owner/image",
			wantTag:  "latest",
		},
		{
			name:     "docker hub library image",
			ref:      "docker://alpine:3.19",
			wantReg:  "docker.io",
			wantRepo: "library/alpine",
			wantTag:  "3.19",
		},
		{
			name:     "docker hub user image",
			ref:      "docker://myuser/myimage:v1",
			wantReg:  "docker.io",
			wantRepo: "myuser/myimage",
			wantTag:  "v1",
		},
		{
			name:     "quay.io",
			ref:      "docker://quay.io/org/image:latest",
			wantReg:  "quay.io",
			wantRepo: "org/image",
			wantTag:  "latest",
		},
		{
			name:     "docker.io explicit",
			ref:      "docker://docker.io/library/ubuntu:22.04",
			wantReg:  "docker.io",
			wantRepo: "library/ubuntu",
			wantTag:  "22.04",
		},
		{
			name:     "digest reference (already pinned)",
			ref:      "docker://ghcr.io/owner/image@sha256:abc123",
			wantReg:  "ghcr.io",
			wantRepo: "owner/image",
			wantTag:  "sha256:abc123",
		},
		{name: "missing docker:// prefix", ref: "ghcr.io/owner/image:v1", wantErr: true},
		{name: "empty ref", ref: "", wantErr: true},
		{name: "just docker://", ref: "docker://", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reg, repo, tag, err := ParseDockerRef(tt.ref)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr = %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if reg != tt.wantReg {
				t.Errorf("registry = %q, want %q", reg, tt.wantReg)
			}
			if repo != tt.wantRepo {
				t.Errorf("repo = %q, want %q", repo, tt.wantRepo)
			}
			if tag != tt.wantTag {
				t.Errorf("tag = %q, want %q", tag, tt.wantTag)
			}
		})
	}
}

func TestParseDockerfile(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    []DockerBaseImage
	}{
		{
			name:    "simple FROM",
			content: "FROM alpine:3.19\nRUN echo hello\n",
			want:    []DockerBaseImage{{Image: "alpine", Tag: "3.19"}},
		},
		{
			name:    "FROM with AS",
			content: "FROM golang:1.24 AS builder\nRUN go build\nFROM alpine:3.19\nCOPY --from=builder /app /app\n",
			want: []DockerBaseImage{
				{Image: "golang", Tag: "1.24"},
				{Image: "alpine", Tag: "3.19"},
			},
		},
		{
			name:    "FROM with registry",
			content: "FROM ghcr.io/owner/image:v1.2.3\n",
			want:    []DockerBaseImage{{Image: "ghcr.io/owner/image", Tag: "v1.2.3"}},
		},
		{
			name:    "FROM with digest",
			content: "FROM alpine@sha256:abc123\n",
			want:    []DockerBaseImage{{Image: "alpine", Tag: "sha256:abc123"}},
		},
		{
			name:    "FROM latest (no tag)",
			content: "FROM ubuntu\n",
			want:    []DockerBaseImage{{Image: "ubuntu", Tag: "latest"}},
		},
		{
			name:    "ARG before FROM",
			content: "ARG BASE=alpine\nARG VERSION=3.19\nFROM ${BASE}:${VERSION}\n",
			want:    nil,
		},
		{
			name:    "FROM scratch",
			content: "FROM scratch\nCOPY binary /\n",
			want:    nil,
		},
		{name: "empty", content: "", want: nil},
		{
			name:    "comments and whitespace",
			content: "# Comment\n  FROM  alpine:3.19  \n",
			want:    []DockerBaseImage{{Image: "alpine", Tag: "3.19"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseDockerfile([]byte(tt.content))
			if len(got) != len(tt.want) {
				t.Fatalf("got %d base images, want %d: %+v", len(got), len(tt.want), got)
			}
			for i := range got {
				if got[i].Image != tt.want[i].Image {
					t.Errorf("[%d] Image = %q, want %q", i, got[i].Image, tt.want[i].Image)
				}
				if got[i].Tag != tt.want[i].Tag {
					t.Errorf("[%d] Tag = %q, want %q", i, got[i].Tag, tt.want[i].Tag)
				}
			}
		})
	}
}

func TestResolveDigest(t *testing.T) {
	const wantDigest = "sha256:9e3a184f680d5f4e1007348f04b020e7e34f205124e5fb2e7eae3ca2fd919e00"

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/token" || r.URL.Path == "/v2/token":
			fmt.Fprintf(w, `{"token":"test-token"}`)
		case r.Method == "HEAD" && strings.Contains(r.URL.Path, "/manifests/"):
			if r.Header.Get("Authorization") != "Bearer test-token" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			accept := r.Header.Get("Accept")
			if !strings.Contains(accept, "application/vnd.docker.distribution.manifest") &&
				!strings.Contains(accept, "application/vnd.oci.image") {
				t.Error("missing manifest accept header")
			}
			w.Header().Set("Docker-Content-Digest", wantDigest)
			w.WriteHeader(http.StatusOK)
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	rc := &RegistryClient{
		HTTP:             &http.Client{},
		registryOverride: ts.URL,
	}

	digest, err := rc.ResolveDigest(context.Background(), "ghcr.io", "aquasecurity/trivy", "0.58.1")
	if err != nil {
		t.Fatalf("ResolveDigest: %v", err)
	}
	if digest != wantDigest {
		t.Errorf("digest = %q, want %q", digest, wantDigest)
	}
}

func TestResolveDigestUnauthorized(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/token" || r.URL.Path == "/v2/token":
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprintf(w, `{"errors":[{"code":"DENIED"}]}`)
		default:
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	defer ts.Close()

	rc := &RegistryClient{
		HTTP:             &http.Client{},
		registryOverride: ts.URL,
	}

	_, err := rc.ResolveDigest(context.Background(), "ghcr.io", "owner/private", "v1")
	if err == nil {
		t.Fatal("expected error for unauthorized registry")
	}
}

func TestResolveDigestDockerHub(t *testing.T) {
	const wantDigest = "sha256:aabbcc"

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/token" || r.URL.Path == "/v2/token":
			fmt.Fprintf(w, `{"token":"hub-token"}`)
		case r.Method == "HEAD" && strings.Contains(r.URL.Path, "/v2/library/alpine/manifests/3.19"):
			w.Header().Set("Docker-Content-Digest", wantDigest)
			w.WriteHeader(http.StatusOK)
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	rc := &RegistryClient{
		HTTP:             &http.Client{},
		registryOverride: ts.URL,
	}

	digest, err := rc.ResolveDigest(context.Background(), "docker.io", "library/alpine", "3.19")
	if err != nil {
		t.Fatalf("ResolveDigest: %v", err)
	}
	if digest != wantDigest {
		t.Errorf("digest = %q, want %q", digest, wantDigest)
	}
}
