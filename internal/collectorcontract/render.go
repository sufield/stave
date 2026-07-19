package collectorcontract

import (
	"encoding/json"
	"fmt"
	"io"
)

// WriteReport dispatches to text or JSON rendering based on format.
func WriteReport(w io.Writer, r *Report, format string, fixHints bool) error {
	if format == "json" {
		return WriteJSON(w, r)
	}
	return WriteText(w, r, fixHints)
}

// WriteText renders the contract check as human-readable text.
func WriteText(w io.Writer, r *Report, fixHints bool) error {
	fmt.Fprintf(w, "\nCollector Contract\n==================\n")
	fmt.Fprintf(w, "Fields checked:  %d\n", r.FieldsChecked)
	fmt.Fprintf(w, "  Pass:          %d\n", r.Pass)
	fmt.Fprintf(w, "  Not evaluated: %d\n", r.Null)
	fmt.Fprintf(w, "  Missing:       %d\n", r.Missing)
	fmt.Fprintf(w, "  Wrong type:    %d\n", r.WrongType)
	fmt.Fprintf(w, "  Coverage:      %d%%\n", r.CoveragePercent())

	if fixHints && len(r.Violations) > 0 {
		type fieldGroup struct {
			field     string
			status    Status
			count     int
			hint      string
			consumers []string
		}
		groups := make(map[string]*fieldGroup)
		var order []string
		for _, v := range r.Violations {
			key := v.Field + ":" + fmt.Sprint(v.Status)
			if g, ok := groups[key]; ok {
				g.count++
			} else {
				groups[key] = &fieldGroup{
					field:     v.Field,
					status:    v.Status,
					count:     1,
					hint:      v.FixHint,
					consumers: v.Consumers,
				}
				order = append(order, key)
			}
		}

		fmt.Fprintf(w, "\nTop issues (--fix-hints):\n")
		for _, key := range order {
			g := groups[key]
			statusLabel := "unknown"
			switch g.status {
			case StatusMissing:
				statusLabel = "missing"
			case StatusWrongType:
				statusLabel = "wrong type"
			case StatusNull:
				statusLabel = "null (not_evaluated)"
			}
			fmt.Fprintf(w, "  %s — %s on %d observation%s\n", g.field, statusLabel, g.count, plural(g.count))
			if len(g.consumers) > 0 {
				fmt.Fprintf(w, "    Affects: %s\n", joinMax(g.consumers, 3))
			}
			if g.hint != "" {
				hint := g.hint
				if len(hint) > 120 {
					hint = hint[:117] + "..."
				}
				fmt.Fprintf(w, "    Hint: %s\n", hint)
			}
		}
	}

	if r.HasViolations() {
		fmt.Fprintf(w, "\nResult: %d contract violation%s found (exit 2)\n",
			r.ViolationCount(), plural(r.ViolationCount()))
	} else if r.HasWarnings() {
		fmt.Fprintf(w, "\nResult: %d field%s not evaluated (warnings)\n",
			r.Null, plural(r.Null))
	} else {
		fmt.Fprintf(w, "\nResult: collector contract clean\n")
	}
	return nil
}

// WriteJSON renders the contract check as JSON.
func WriteJSON(w io.Writer, r *Report) error {
	type jsonViolation struct {
		Field     string   `json:"field"`
		Status    string   `json:"status"`
		AssetID   string   `json:"asset_id"`
		AssetType string   `json:"asset_type"`
		Hint      string   `json:"hint,omitempty"`
		Consumers []string `json:"consumers,omitempty"`
	}
	type jsonContract struct {
		FieldsChecked   int             `json:"fields_checked"`
		Pass            int             `json:"pass"`
		NotEvaluated    int             `json:"not_evaluated"`
		Missing         int             `json:"missing"`
		WrongType       int             `json:"wrong_type"`
		CoveragePercent int             `json:"coverage_percent"`
		Violations      []jsonViolation `json:"violations,omitempty"`
	}

	jc := jsonContract{
		FieldsChecked:   r.FieldsChecked,
		Pass:            r.Pass,
		NotEvaluated:    r.Null,
		Missing:         r.Missing,
		WrongType:       r.WrongType,
		CoveragePercent: r.CoveragePercent(),
	}
	for _, v := range r.Violations {
		statusStr := "unknown"
		switch v.Status {
		case StatusMissing:
			statusStr = "missing"
		case StatusWrongType:
			statusStr = "wrong_type"
		case StatusNull:
			statusStr = "not_evaluated"
		}
		jc.Violations = append(jc.Violations, jsonViolation{
			Field:     v.Field,
			Status:    statusStr,
			AssetID:   v.AssetID,
			AssetType: v.AssetType,
			Hint:      v.FixHint,
			Consumers: v.Consumers,
		})
	}

	data, err := json.MarshalIndent(jc, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal contract JSON: %w", err)
	}
	fmt.Fprintf(w, "\n")
	_, err = w.Write(data)
	return err
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func joinMax(ss []string, n int) string {
	if len(ss) <= n {
		return fmt.Sprintf("%v", ss)
	}
	return fmt.Sprintf("%v ...", ss[:n])
}
