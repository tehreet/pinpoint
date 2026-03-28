// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only

package util

import "testing"

func TestShortSHA(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		sha  string
		want string
	}{
		{"long sha", "abcdef1234567890", "abcdef1..."},
		{"exactly 7", "abcdef1", "abcdef1"},
		{"short sha", "abc", "abc"},
		{"empty", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := ShortSHA(tt.sha); got != tt.want {
				t.Errorf("ShortSHA(%q) = %q, want %q", tt.sha, got, tt.want)
			}
		})
	}
}

func TestLeadingSpaces(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		line string
		want int
	}{
		{"no indent", "hello", 0},
		{"two spaces", "  hello", 2},
		{"tab", "\thello", 2},
		{"mixed", " \t hello", 4},
		{"all spaces", "   ", 3},
		{"empty", "", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := LeadingSpaces(tt.line); got != tt.want {
				t.Errorf("LeadingSpaces(%q) = %d, want %d", tt.line, got, tt.want)
			}
		})
	}
}
