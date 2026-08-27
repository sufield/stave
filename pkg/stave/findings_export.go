package stave

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/sufield/stave/internal/app/exportchanges"
	appocsf "github.com/sufield/stave/internal/app/ocsf"
	apposcal "github.com/sufield/stave/internal/app/oscal"
	"github.com/sufield/stave/internal/app/oscalpoam"
	"github.com/sufield/stave/internal/app/teams"
	"github.com/sufield/stave/internal/app/ticketexport"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/util/jsonutil"
)

// parseExportFindings extracts the findings array from a `stave apply`
// assessment (JSON). A parse failure wraps [ErrInvalidInput] (exit 2).
func parseExportFindings(data []byte) ([]remediation.Finding, error) {
	var assessment struct {
		Findings []remediation.Finding `json:"findings"`
	}
	if err := json.Unmarshal(data, &assessment); err != nil {
		return nil, fmt.Errorf("parse assessment: %w: %w", err, ErrInvalidInput)
	}
	return assessment.Findings, nil
}

// ExportOCSF converts assessment findings to OCSF 1.1 Compliance Finding
// events (class_uid 2003) rendered as NDJSON — one event per line. It is
// the library entry point behind `stave export ocsf`.
func ExportOCSF(assessmentData []byte) ([]byte, error) {
	findings, err := parseExportFindings(assessmentData)
	if err != nil {
		return nil, err
	}
	events := appocsf.Export(findings)
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for i := range events {
		if err := enc.Encode(&events[i]); err != nil {
			return nil, fmt.Errorf("encode event: %w", err)
		}
	}
	return buf.Bytes(), nil
}

// ExportOSCAL converts assessment findings to an OSCAL 1.1.2 document —
// Assessment Results (default), POA&M (docType "poam"), or a not-yet-
// implemented SSP stub — rendered as indented JSON. now stamps the
// document. The SSP stub wraps [ErrInvalidInput] (exit 2). It is the
// library entry point behind `stave export oscal`.
func ExportOSCAL(assessmentData []byte, docType, systemUUID string, now time.Time) ([]byte, error) {
	findings, err := parseExportFindings(assessmentData)
	if err != nil {
		return nil, err
	}

	var result any
	switch docType {
	case "poam":
		result = oscalpoam.Generate(oscalpoam.Input{
			Findings:   findings,
			SystemUUID: systemUUID,
			EvalTime:   now,
		})
	case "ssp":
		return nil, fmt.Errorf("OSCAL SSP export is not yet implemented: %w", ErrInvalidInput)
	default:
		result = apposcal.Export(findings, now)
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(result); err != nil {
		return nil, fmt.Errorf("encode OSCAL: %w", err)
	}
	return buf.Bytes(), nil
}

// ExportChanges extracts remediation property changes from assessment
// findings into a structured document (indented JSON, HTML-escape off),
// filtered to MinConfidence. now stamps the document. It is the library
// entry point behind `stave export changes`.
func ExportChanges(assessmentData []byte, minConfidence float64, now time.Time) ([]byte, error) {
	findings, err := parseExportFindings(assessmentData)
	if err != nil {
		return nil, err
	}
	report := exportchanges.Export(exportchanges.Input{
		Findings:      findings,
		MinConfidence: minConfidence,
		GeneratedAt:   now.Format(time.RFC3339),
	})
	var buf bytes.Buffer
	if err := jsonutil.WriteIndented(&buf, report); err != nil {
		return nil, fmt.Errorf("encode changes: %w", err)
	}
	return buf.Bytes(), nil
}

// ExportTickets generates canonical ticket records from assessment
// findings (stable IDs, severity→priority mapping, optional team-manifest
// enrichment and team filter) and renders them as "json"/"" or "csv".
// Parse and unknown-format failures wrap [ErrInvalidInput] (exit 2). It is
// the library entry point behind `stave export tickets`.
func ExportTickets(assessmentData []byte, teamManifest, team, format string) ([]byte, error) {
	switch format {
	case "json", "", "csv":
	default:
		return nil, fmt.Errorf("unknown format %q (valid: json, csv): %w", format, ErrInvalidInput)
	}

	findings, err := parseExportFindings(assessmentData)
	if err != nil {
		return nil, err
	}
	tickets := ticketexport.Generate(findings)

	// Team-manifest enrichment.
	if teamManifest != "" {
		manifest, manifestErr := teams.LoadManifest(teamManifest)
		if manifestErr != nil {
			return nil, fmt.Errorf("load team manifest: %w", manifestErr)
		}
		for i := range tickets {
			t := &tickets[i]
			if t.Team == "" {
				owner := manifest.ResolveOwner(nil, string(t.AssetID), string(t.ControlID))
				t.Team = owner.TeamName
			}
		}
	}

	// Filter by team.
	if team != "" {
		var filtered []ticketexport.Ticket
		for i := range tickets {
			if tickets[i].Team == team {
				filtered = append(filtered, tickets[i])
			}
		}
		tickets = filtered
	}

	var buf bytes.Buffer
	if format == "csv" {
		if err := writeTicketsExportCSV(&buf, tickets); err != nil {
			return nil, fmt.Errorf("encode tickets csv: %w", err)
		}
	} else {
		enc := json.NewEncoder(&buf)
		enc.SetIndent("", "  ")
		if err := enc.Encode(tickets); err != nil {
			return nil, fmt.Errorf("encode tickets json: %w", err)
		}
	}
	return buf.Bytes(), nil
}

func writeTicketsExportCSV(w io.Writer, tickets []ticketexport.Ticket) (err error) {
	cw := csv.NewWriter(w)
	defer func() {
		cw.Flush()
		if flushErr := cw.Error(); flushErr != nil && err == nil {
			err = fmt.Errorf("flush tickets CSV: %w", flushErr)
		}
	}()

	if err = cw.Write([]string{
		"ticket_id", "title", "severity", "priority", "status",
		"control_id", "asset_id", "team", "dwell_days", "description",
	}); err != nil {
		return err
	}

	for i := range tickets {
		t := &tickets[i]
		if err = cw.Write([]string{
			t.TicketID,
			t.Title,
			t.Severity.String(),
			string(t.Priority),
			t.Status,
			string(t.ControlID),
			string(t.AssetID),
			t.Team,
			fmt.Sprintf("%.1f", t.DwellDays),
			t.Description,
		}); err != nil {
			return err
		}
	}
	return nil
}
