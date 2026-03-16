package artifacts

import (
	"encoding/csv"
	"fmt"
	"io"
	"strings"

	"github.com/sufield/stave/internal/app/catalog"
	"github.com/sufield/stave/internal/pkg/jsonutil"
)

func formatOutput(w io.Writer, cfg catalog.ListConfig, rows []catalog.ControlRow) error {
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
		return writeCSV(w, rows, cols, !cfg.NoHeaders)
	case "text":
		return writeTable(w, rows, cols, !cfg.NoHeaders)
	default:
		return fmt.Errorf("unsupported --format %q (use: text, json, csv)", cfg.Format)
	}
}

func writeCSV(w io.Writer, rows []catalog.ControlRow, cols []string, header bool) error {
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

func writeTable(w io.Writer, rows []catalog.ControlRow, cols []string, header bool) error {
	if len(rows) == 0 {
		_, err := fmt.Fprintln(w, "No controls found.")
		return err
	}

	widths := make([]int, len(cols))
	for i, c := range cols {
		widths[i] = len(c)
	}
	for _, row := range rows {
		for i, c := range cols {
			if l := len(catalog.FieldValue(row, c)); l > widths[i] {
				widths[i] = l
			}
		}
	}

	printLine := func(vals []string) error {
		for i, v := range vals {
			if i > 0 {
				if _, err := fmt.Fprint(w, "  "); err != nil {
					return err
				}
			}
			if _, err := fmt.Fprintf(w, "%-*s", widths[i], v); err != nil {
				return err
			}
		}
		_, err := fmt.Fprintln(w)
		return err
	}

	if header {
		if err := printLine(cols); err != nil {
			return err
		}
	}

	for _, row := range rows {
		vals := make([]string, len(cols))
		for i, c := range cols {
			vals[i] = catalog.FieldValue(row, c)
		}
		if err := printLine(vals); err != nil {
			return err
		}
	}
	return nil
}
