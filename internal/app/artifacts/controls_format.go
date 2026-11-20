package artifacts

import (
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/sufield/stave/internal/app/catalog"
	appcontracts "github.com/sufield/stave/internal/core/contracts"
	"github.com/sufield/stave/internal/util/jsonutil"
)

// FormatControlOutput writes control rows in the requested format.
func FormatControlOutput(w io.Writer, cfg catalog.DiscoveryRequest, rows []catalog.PolicyEntry) error {
	if w == nil {
		return errors.New("writer is nil")
	}
	format := parseOutputFormat(cfg.OutputFormat)

	if format == appcontracts.FormatJSON {
		if err := jsonutil.WriteIndented(w, rows); err != nil {
			return fmt.Errorf("write control JSON: %w", err)
		}
		return nil
	}

	cols, err := catalog.SelectFields(cfg.Fields)
	if err != nil {
		return fmt.Errorf("select control fields: %w", err)
	}

	switch format {
	case "csv":
		return WriteCSV(w, rows, cols, !cfg.HideHeaders)
	case appcontracts.FormatText:
		return WriteTable(w, rows, cols, !cfg.HideHeaders)
	default:
		return fmt.Errorf("unsupported --format %q (use: text, json, csv)", cfg.OutputFormat)
	}
}

func parseOutputFormat(raw string) appcontracts.OutputFormat {
	raw = strings.TrimSpace(raw)
	if strings.EqualFold(raw, "json") {
		return appcontracts.FormatJSON
	}
	if strings.EqualFold(raw, "csv") {
		return "csv"
	}
	if strings.EqualFold(raw, "text") || raw == "" {
		return appcontracts.FormatText
	}
	needsLower := false
	for i := 0; i < len(raw); i++ {
		if raw[i] >= 'A' && raw[i] <= 'Z' {
			needsLower = true
			break
		}
	}
	if needsLower {
		return appcontracts.OutputFormat(strings.ToLower(raw))
	}
	return appcontracts.OutputFormat(raw)
}

// WriteCSV writes control rows as CSV.
func WriteCSV(w io.Writer, rows []catalog.PolicyEntry, cols []string, header bool) error {
	cw := csv.NewWriter(w)
	if header {
		if err := cw.Write(cols); err != nil {
			return fmt.Errorf("write CSV header: %w", err)
		}
	}
	for _, row := range rows {
		record := make([]string, len(cols))
		for i, c := range cols {
			record[i] = catalog.GetAttribute(row, c)
		}
		if err := cw.Write(record); err != nil {
			return fmt.Errorf("write CSV row: %w", err)
		}
	}
	cw.Flush()
	if err := cw.Error(); err != nil {
		return fmt.Errorf("flush CSV: %w", err)
	}
	return nil
}

// WriteTable writes control rows as a formatted table.
func WriteTable(w io.Writer, rows []catalog.PolicyEntry, cols []string, header bool) error {
	if len(rows) == 0 {
		if _, err := fmt.Fprintln(w, "No controls found."); err != nil {
			return fmt.Errorf("write empty table message: %w", err)
		}
		return nil
	}

	tw := tabwriter.NewWriter(w, 0, 8, 2, ' ', 0)

	if header {
		fmt.Fprintln(tw, strings.Join(cols, "\t"))
	}

	for _, row := range rows {
		vals := make([]string, len(cols))
		for i, c := range cols {
			vals[i] = catalog.GetAttribute(row, c)
		}
		fmt.Fprintln(tw, strings.Join(vals, "\t"))
	}

	if err := tw.Flush(); err != nil {
		return fmt.Errorf("flush control table: %w", err)
	}
	return nil
}
