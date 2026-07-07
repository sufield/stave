package main

import (
	"fmt"
	"strings"
)

func writeReport(r TriageReport) {
	fmt.Printf("SERVICE: %s\n", r.ServiceName)
	fmt.Printf("SDK STATUS: %s\n\n", boolStr(r.Available, "available", "not available"))

	totalFields := 0
	for _, op := range r.Operations {
		totalFields += len(op.Fields)
	}
	fmt.Printf("SECURITY-RELEVANT FIELDS (%d):\n", totalFields)
	for _, op := range r.Operations {
		fmt.Printf("  %s:\n", op.Name)
		for _, f := range op.Fields {
			fmt.Printf("    %-50s [%s]\n", f.Path, f.Kind)
		}
	}
	fmt.Println()

	if len(r.ExistingControls) > 0 {
		fmt.Printf("EXISTING CONTROLS (%d):\n", len(r.ExistingControls))
		for _, c := range r.ExistingControls {
			cats := ""
			if len(c.Categories) > 0 {
				cats = " — " + strings.Join(c.Categories, ", ")
			}
			fmt.Printf("  %-50s%s\n", c.ID, cats)
		}
		fmt.Println()
	}

	fmt.Printf("COVERAGE: %d/%d (%.0f%%)\n\n", len(r.CoveredFields), r.TotalSecFields, r.CoveragePct)

	if len(r.UncoveredFields) > 0 {
		fmt.Printf("UNCOVERED FIELDS (%d):\n", len(r.UncoveredFields))
		for i, f := range r.UncoveredFields {
			cats := ""
			if len(f.Categories) > 0 {
				cats = " → " + strings.Join(f.Categories, ", ")
			}
			fmt.Printf("  %d. %-50s [%s]%s\n", i+1, f.Field.Path, f.Field.Kind, cats)
		}
		fmt.Println()
	}

	if len(r.CoveredFields) > 0 {
		fmt.Printf("COVERED FIELDS (%d):\n", len(r.CoveredFields))
		for i, f := range r.CoveredFields {
			fmt.Printf("  %d. %s.%s\n", i+1, f.Operation, f.Field.Path)
		}
		fmt.Println()
	}
}

func writeFieldsOnly(service string, ops []SecurityOp) {
	fmt.Printf("SERVICE: %s\n\n", service)
	total := 0
	for _, op := range ops {
		total += len(op.Fields)
	}
	fmt.Printf("SECURITY-RELEVANT FIELDS (%d):\n", total)
	for _, op := range ops {
		fmt.Printf("  %s:\n", op.Name)
		for _, f := range op.Fields {
			fmt.Printf("    %-50s [%s]\n", f.Path, f.Kind)
		}
	}
}

func boolStr(b bool, t, f string) string {
	if b {
		return t
	}
	return f
}
