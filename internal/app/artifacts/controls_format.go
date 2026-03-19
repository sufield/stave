package artifacts

import (
	"encoding/csv"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/sufield/stave/internal/app/catalog"
	"github.com/sufield/stave/internal/pkg/jsonutil"
)

// FormatControlOutput writes control rows in the requested format.
func FormatControlOutput(w io.Writer, cfg catalog.ListConfig, rows []catalog.ControlRow) error {
	format := strings.ToLower(strings.TrimSpace(cfg.Format))

	if format == "json" {
		return jsonutil.WriteIndented(w, rows)
	}

	cols, err := catalog.ParseColumns(cfg.Columns)
	if err != nil {
		return err
	}

	switch format {
	case "csv":
		return WriteCSV(w, rows, cols, !cfg.NoHeaders)
	case "text":
		return WriteTable(w, rows, cols, !cfg.NoHeaders)
	default:
		return fmt.Errorf("unsupported --format %q (use: text, json, csv)", cfg.Format)
	}
}

// WriteCSV writes control rows as CSV.
func WriteCSV(w io.Writer, rows []catalog.ControlRow, cols []string, header bool) error {
	cw := csv.NewWriter(w)
	if header {
		if err := cw.Write(cols); err != nil {
			return err
		}
	}
	for _, row := range rows {
		record := make([]string, len(cols))
		for i, c := range cols {
			record[i] = catalog.FieldValue(row, c)
		}
		if err := cw.Write(record); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

// WriteTable writes control rows as a formatted table.
func WriteTable(w io.Writer, rows []catalog.ControlRow, cols []string, header bool) error {
	if len(rows) == 0 {
		_, err := fmt.Fprintln(w, "No controls found.")
		return err
	}

	tw := tabwriter.NewWriter(w, 0, 8, 2, ' ', 0)

	if header {
		fmt.Fprintln(tw, strings.Join(cols, "\t"))
	}

	for _, row := range rows {
		vals := make([]string, len(cols))
		for i, c := range cols {
			vals[i] = catalog.FieldValue(row, c)
		}
		fmt.Fprintln(tw, strings.Join(vals, "\t"))
	}

	return tw.Flush()
}
