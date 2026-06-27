package pack

import "strings"

// plan.go supports `stave plan`: a coverage preview of which controls would
// evaluate for a set of services/packs, broken down by service and severity.
// It is a view over pack resolution — it never evaluates anything.

// SeverityCounts is a per-severity control breakdown for one service.
type SeverityCounts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
	Total    int `json:"total"`
}

func (s *SeverityCounts) add(sev string) {
	switch strings.ToLower(sev) {
	case "critical":
		s.Critical++
	case "high":
		s.High++
	case "medium":
		s.Medium++
	case "low":
		s.Low++
	default:
		s.Info++
	}
	s.Total++
}

// CountByService groups controlIDs by AWS service with a severity breakdown.
// If services is non-empty, only those services are counted (controls for other
// services in the set are ignored — they won't evaluate without that data).
func CountByService(controlIDs []string, catalog []ControlMeta, services []string) map[string]SeverityCounts {
	sevOf := make(map[string]string, len(catalog))
	for _, c := range catalog {
		sevOf[c.ID] = c.Severity
	}
	want := map[string]bool{}
	for _, s := range services {
		want[strings.ToLower(strings.TrimSpace(s))] = true
	}
	out := map[string]SeverityCounts{}
	for _, id := range controlIDs {
		svc := ServiceForControlID(id)
		if svc == "" || (len(want) > 0 && !want[svc]) {
			continue
		}
		sc := out[svc]
		sc.add(sevOf[id])
		out[svc] = sc
	}
	return out
}
