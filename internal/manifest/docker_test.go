// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only

package manifest

import (
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
