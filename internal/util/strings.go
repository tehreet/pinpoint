// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only

package util

// ShortSHA truncates a SHA to 7 characters with an ellipsis.
func ShortSHA(sha string) string {
	if len(sha) > 7 {
		return sha[:7] + "..."
	}
	return sha
}

// LeadingSpaces counts the number of leading whitespace characters in a line.
// Tabs count as 2 spaces.
func LeadingSpaces(line string) int {
	count := 0
	for _, ch := range line {
		if ch == ' ' {
			count++
		} else if ch == '\t' {
			count += 2
		} else {
			break
		}
	}
	return count
}
