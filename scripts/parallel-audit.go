// Copyright (C) 2026 CoreWeave, Inc.
// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

const (
	workers   = 8
	outputDir = "/home/joshf/pinpoint/audits"
	binary    = "/tmp/pp"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "usage: parallel-audit <orgs-file>\n")
		os.Exit(1)
	}

	// Read org list
	f, err := os.Open(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "open %s: %v\n", os.Args[1], err)
		os.Exit(1)
	}
	defer f.Close()

	var orgs []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if t := sc.Text(); t != "" {
			orgs = append(orgs, t)
		}
	}

	total := len(orgs)
	fmt.Printf("=== Parallel audit: %d orgs, %d workers ===\n", total, workers)

	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		out, err := exec.Command("gh", "auth", "token").Output()
		if err != nil {
			fmt.Fprintf(os.Stderr, "no GITHUB_TOKEN and gh auth token failed: %v\n", err)
			os.Exit(1)
		}
		token = string(out[:len(out)-1])
		os.Setenv("GITHUB_TOKEN", token)
	}

	os.MkdirAll(outputDir, 0755)

	var (
		done    atomic.Int64
		success atomic.Int64
		failed  atomic.Int64
		skipped atomic.Int64
	)

	work := make(chan string, total)
	for _, org := range orgs {
		work <- org
	}
	close(work)

	start := time.Now()
	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for org := range work {
				outfile := filepath.Join(outputDir, org+".json")
				logfile := filepath.Join(outputDir, org+".log")

				// Skip if already done
				if info, err := os.Stat(outfile); err == nil && info.Size() > 1000 {
					n := done.Add(1)
					skipped.Add(1)
					success.Add(1)
					fmt.Printf("[%d/%d] w%d %s: CACHED (%d bytes)\n", n, total, id, org, info.Size())
					continue
				}

				// Run audit
				cmd := exec.Command(binary, "audit", "--org", org, "--output", "json")
				out, err := cmd.Output()
				n := done.Add(1)

				if err != nil {
					failed.Add(1)
					// Save error log
					if exitErr, ok := err.(*exec.ExitError); ok {
						os.WriteFile(logfile, exitErr.Stderr, 0644)
					}
					fmt.Printf("[%d/%d] w%d %s: FAIL (%v)\n", n, total, id, org, err)
					continue
				}

				os.WriteFile(outfile, out, 0644)
				success.Add(1)
				fmt.Printf("[%d/%d] w%d %s: OK (%d bytes)\n", n, total, id, org, len(out))

				// Rate limit check every 20 completions
				if n%20 == 0 {
					checkRateLimit(token)
				}
			}
		}(i)
	}

	wg.Wait()
	elapsed := time.Since(start)

	fmt.Printf("\n============================================\n")
	fmt.Printf("  PARALLEL AUDIT COMPLETE in %s\n", elapsed.Round(time.Second))
	fmt.Printf("  %d succeeded (%d cached), %d failed\n", success.Load(), skipped.Load(), failed.Load())
	fmt.Printf("  %.1f orgs/minute\n", float64(done.Load())/elapsed.Minutes())
	fmt.Printf("============================================\n")
}

func checkRateLimit(token string) {
	req, _ := http.NewRequest("GET", "https://api.github.com/rate_limit", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	var data struct {
		Resources struct {
			GraphQL struct {
				Remaining int `json:"remaining"`
				Limit     int `json:"limit"`
			} `json:"graphql"`
		} `json:"resources"`
	}
	json.NewDecoder(resp.Body).Decode(&data)
	fmt.Printf("  [rate limit: %d/%d GraphQL points remaining]\n",
		data.Resources.GraphQL.Remaining, data.Resources.GraphQL.Limit)
}
