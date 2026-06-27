package apply

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
)

// all_staged.go renders `apply --all`: the same findings a full evaluation
// produces, grouped per service (per-group findings) and then compound
// (cross-service) findings, followed by a summary. It is a presentation over
// out.v0.1 JSON — service is derived from the control ID (CTL.<DOMAIN>.*), so no
// facade crossing is needed.

type stagedFinding struct {
	ControlID   string `json:"control_id"`
	Severity    string `json:"control_severity"`
	AssetID     string `json:"asset_id"`
	ControlName string `json:"control_name"`
}

type stagedDoc struct {
	Findings []stagedFinding `json:"findings"`
}

func serviceOf(controlID string) string {
	parts := strings.SplitN(controlID, ".", 3)
	if len(parts) >= 2 && parts[0] == "CTL" {
		return strings.ToLower(parts[1])
	}
	return "other"
}

// A finding is "compound" (cross-service) when its control ID carries a
// multi-resource marker. These are reported in their own stage.
func isCompound(f stagedFinding) bool {
	up := strings.ToUpper(f.ControlID)
	for _, m := range []string{"COMPOUND", "FOOTHOLD", "CHAIN"} {
		if strings.Contains(up, m) {
			return true
		}
	}
	return false
}

type sevTally struct{ critical, high, medium, low, info, total int }

func (s *sevTally) add(sev string) {
	switch strings.ToLower(sev) {
	case "critical":
		s.critical++
	case "high":
		s.high++
	case "medium":
		s.medium++
	case "low":
		s.low++
	default:
		s.info++
	}
	s.total++
}

func (s *sevTally) breakdown() string {
	return fmt.Sprintf("%d critical, %d high, %d medium, %d low", s.critical, s.high, s.medium, s.low)
}

func renderAllStaged(findingsJSON []byte, w io.Writer) error {
	var doc stagedDoc
	if err := json.Unmarshal(findingsJSON, &doc); err != nil {
		return fmt.Errorf("parse findings for --all: %w", err)
	}

	byService := map[string][]stagedFinding{}
	var compound []stagedFinding
	var grand sevTally
	for _, f := range doc.Findings {
		grand.add(f.Severity)
		if isCompound(f) {
			compound = append(compound, f)
			continue
		}
		svc := serviceOf(f.ControlID)
		byService[svc] = append(byService[svc], f)
	}

	services := make([]string, 0, len(byService))
	for s := range byService {
		services = append(services, s)
	}
	sort.Strings(services)

	for _, svc := range services {
		printStage(w, "["+svc+"]", byService[svc])
	}
	printStage(w, "[compound]", compound)

	fmt.Fprintf(w, "\nSummary: %d total finding(s) (%s)\n", grand.total, grand.breakdown())
	if grand.total == 0 {
		fmt.Fprintf(w, "All evaluated controls passed.\n")
	}
	return nil
}

func printStage(w io.Writer, label string, fs []stagedFinding) {
	var t sevTally
	for _, f := range fs {
		t.add(f.Severity)
	}
	word := "findings"
	if label == "[compound]" {
		word = "additional findings"
	}
	if len(fs) == 0 {
		fmt.Fprintf(w, "%s 0 %s\n", label, word)
		return
	}
	fmt.Fprintf(w, "%s %d %s (%s)\n", label, t.total, word, t.breakdown())
	// criticals first within the stage
	order := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
	sort.SliceStable(fs, func(i, j int) bool {
		return order[strings.ToLower(fs[i].Severity)] < order[strings.ToLower(fs[j].Severity)]
	})
	for _, f := range fs {
		fmt.Fprintf(w, "  [%s] %s — %s\n", strings.ToLower(f.Severity), f.ControlID, shortAsset(f.AssetID))
	}
}

func shortAsset(arn string) string {
	if strings.HasPrefix(arn, "arn:") {
		return arn[strings.LastIndex(arn, ":")+1:]
	}
	return arn
}
