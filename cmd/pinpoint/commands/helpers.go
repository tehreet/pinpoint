// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only

package commands

import (
	"sort"
	"strings"
	"time"
)

// Version, Commit, and Date are set from main.go at startup.
var (
	Version = "dev"
	Commit  = "unknown"
	Date    = "unknown"
)

// GetFlag returns the value of a --name flag from the given args slice.
func GetFlag(args []string, name string) string {
	for i, arg := range args {
		if arg == "--"+name && i+1 < len(args) {
			return args[i+1]
		}
		if strings.HasPrefix(arg, "--"+name+"=") {
			return strings.TrimPrefix(arg, "--"+name+"=")
		}
	}
	return ""
}

// HasFlag returns true if --name appears in the given args slice.
func HasFlag(args []string, name string) bool {
	for _, arg := range args {
		if arg == "--"+name {
			return true
		}
	}
	return false
}

// Truncate shortens a string to max characters, appending "..." if truncated.
func Truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

// ComputeMeanInterval calculates the average time between release timestamps.
func ComputeMeanInterval(history []string) time.Duration {
	if len(history) < 2 {
		return 0
	}
	var times []time.Time
	for _, ts := range history {
		if t, err := time.Parse(time.RFC3339, ts); err == nil {
			times = append(times, t)
		}
	}
	if len(times) < 2 {
		return 0
	}
	sort.Slice(times, func(i, j int) bool { return times[i].Before(times[j]) })
	total := times[len(times)-1].Sub(times[0])
	return total / time.Duration(len(times)-1)
}
