package diagnose

import (
	"fmt"
	"io"

	"github.com/sufield/stave/internal/pkg/jsonutil"
)

func writeExplainText(w io.Writer, out ExplainResult) error {
	if err := writeExplainHeader(w, out); err != nil {
		return err
	}
	if err := writeExplainMatchedFields(w, out.MatchedFields); err != nil {
		return err
	}
	if err := writeExplainRules(w, out.Rules); err != nil {
		return err
	}
	if err := writeExplainMinimalObservation(w, out.MinimalObservation); err != nil {
		return err
	}
	_, err := fmt.Fprintln(w, "Next: save this JSON under ./observations/<timestamp>.json, then run `stave validate --controls ./controls --observations ./observations`")
	return err
}

func writeExplainHeader(w io.Writer, out ExplainResult) error {
	lines := []string{
		fmt.Sprintf("Control: %s", out.ControlID),
		fmt.Sprintf("Name: %s", out.Name),
		fmt.Sprintf("Description: %s", out.Description),
		fmt.Sprintf("Type: %s", out.Type),
		"",
	}
	for _, line := range lines {
		if _, err := fmt.Fprintln(w, line); err != nil {
			return err
		}
	}
	return nil
}

func writeExplainMatchedFields(w io.Writer, fields []string) error {
	if _, err := fmt.Fprintln(w, "Matched fields:"); err != nil {
		return err
	}
	for _, field := range fields {
		if _, err := fmt.Fprintf(w, "  - %s\n", field); err != nil {
			return err
		}
	}
	return nil
}

func writeExplainRules(w io.Writer, rules []ExplainRule) error {
	if _, err := fmt.Fprintln(w, "\nRules:"); err != nil {
		return err
	}
	for _, rule := range rules {
		if _, err := fmt.Fprintf(w, "  - %s %s %v (%s)\n", rule.Path, rule.Op, rule.Value, rule.From); err != nil {
			return err
		}
	}
	return nil
}

func writeExplainMinimalObservation(w io.Writer, observation any) error {
	if _, err := fmt.Fprintln(w, "\nMinimal observation snippet:"); err != nil {
		return err
	}
	return jsonutil.WriteIndented(w, observation)
}
