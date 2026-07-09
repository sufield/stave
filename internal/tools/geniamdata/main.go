// Command geniamdata fetches IAM authorization reference data from the
// AWS service reference API and writes per-service JSON files to a
// local directory.
//
// Usage:
//
//	go run ./internal/tools/geniamdata -out data/iamauth
//	go run ./internal/tools/geniamdata -out data/iamauth -service s3
//	go run ./internal/tools/geniamdata -out data/iamauth -diff
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"time"
)

const indexURL = "https://servicereference.us-east-1.amazonaws.com/"

type indexEntry struct {
	Service  string `json:"service"`
	URL      string `json:"url"`
	Modified int64  `json:"modified"`
}

func main() {
	outDir := flag.String("out", "data/iamauth", "output directory for per-service JSON")
	service := flag.String("service", "", "fetch a single service (default: all)")
	diff := flag.Bool("diff", false, "show services modified since last fetch")
	flag.Parse()

	index, err := fetchIndex()
	if err != nil {
		fmt.Fprintf(os.Stderr, "fetch index: %v\n", err)
		os.Exit(1)
	}

	if *diff {
		showDiff(index, *outDir)
		return
	}

	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "mkdir %s: %v\n", *outDir, err)
		os.Exit(1)
	}

	indexData, err := json.Marshal(index)
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal index: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(filepath.Join(*outDir, "index.json"), indexData, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write index: %v\n", err)
		os.Exit(1)
	}

	var targets []indexEntry
	if *service != "" {
		for _, e := range index {
			if e.Service == *service {
				targets = append(targets, e)
				break
			}
		}
		if len(targets) == 0 {
			fmt.Fprintf(os.Stderr, "service %q not found in index\n", *service)
			os.Exit(2)
		}
	} else {
		targets = index
	}

	var fetched, failed int
	for i, entry := range targets {
		if i > 0 && i%50 == 0 {
			fmt.Fprintf(os.Stderr, "progress: %d/%d\n", i, len(targets))
		}

		data, err := fetchJSON(entry.URL)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  FAIL %s: %v\n", entry.Service, err)
			failed++
			continue
		}

		path := filepath.Join(*outDir, entry.Service+".json")
		if err := os.WriteFile(path, data, 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "  FAIL write %s: %v\n", entry.Service, err)
			failed++
			continue
		}
		fetched++
	}

	fmt.Fprintf(os.Stderr, "done: %d fetched, %d failed, %d total in index\n", fetched, failed, len(index))
}

func fetchIndex() ([]indexEntry, error) {
	data, err := fetchJSON(indexURL)
	if err != nil {
		return nil, err
	}
	var index []indexEntry
	if err := json.Unmarshal(data, &index); err != nil {
		return nil, fmt.Errorf("parse index: %w", err)
	}
	sort.Slice(index, func(i, j int) bool {
		return index[i].Service < index[j].Service
	})
	return index, nil
}

func fetchJSON(url string) ([]byte, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url) //nolint:gosec,noctx // fixed AWS URLs, short-lived tool
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d for %s", resp.StatusCode, url)
	}
	return io.ReadAll(resp.Body)
}

func showDiff(index []indexEntry, dir string) {
	oldIndex, err := loadOldIndex(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "no previous index at %s: %v\n", dir, err)
		fmt.Printf("all %d services are new\n", len(index))
		return
	}

	oldMap := make(map[string]int64, len(oldIndex))
	for _, e := range oldIndex {
		oldMap[e.Service] = e.Modified
	}

	var added, modified, removed int
	for _, e := range index {
		old, exists := oldMap[e.Service]
		if !exists {
			fmt.Printf("  ADDED    %s\n", e.Service)
			added++
		} else if e.Modified > old {
			fmt.Printf("  MODIFIED %s (delta %s)\n", e.Service,
				time.Unix(e.Modified, 0).Sub(time.Unix(old, 0)).Round(time.Hour))
			modified++
		}
	}

	newMap := make(map[string]bool, len(index))
	for _, e := range index {
		newMap[e.Service] = true
	}
	for _, e := range oldIndex {
		if !newMap[e.Service] {
			fmt.Printf("  REMOVED  %s\n", e.Service)
			removed++
		}
	}

	fmt.Printf("\nsummary: %d added, %d modified, %d removed, %d unchanged\n",
		added, modified, removed, len(index)-added-modified)
}

func loadOldIndex(dir string) ([]indexEntry, error) {
	data, err := os.ReadFile(filepath.Join(dir, "index.json"))
	if err != nil {
		return nil, err
	}
	var index []indexEntry
	if err := json.Unmarshal(data, &index); err != nil {
		return nil, err
	}
	return index, nil
}
