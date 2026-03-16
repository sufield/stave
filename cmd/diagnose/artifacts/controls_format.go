package artifacts

import (
	"encoding/csv"
	"fmt"
	"io"
	"strings"

	"github.com/sufield/stave/internal/pkg/jsonutil"
)

func (r *ListRunner) formatOutput(cfg ListConfig, rows []ControlRow) error {
	format := strings.ToLower(strings.TrimSpace(cfg.Format))

	if format == "json" {
		return jsonutil.WriteIndented(cfg.Stdout, rows)
	}

	cols, err := parseColumns(cfg.Columns)
	if err != nil {
		return err
	}

	switch format {
	case "csv":
		return r.writeCSV(cfg.Stdout, rows, cols, !cfg.NoHeaders)
	case "text":
		return r.writeTable(cfg.Stdout, rows, cols, !cfg.NoHeaders)
	default:
		return fmt.Errorf("unsupported --format %q (use: text, json, csv)", cfg.Format)
	}
}

func (r *ListRunner) writeCSV(w io.Writer, rows []ControlRow, cols []string, header bool) error {
	cw := csv.NewWriter(w)
	if header {
		if err := cw.Write(cols); err != nil {
			return err
		}
	}
	for _, row := range rows {
		record := make([]string, len(cols))
		for i, c := range cols {
			record[i] = fieldValue(row, c)
		}
		if err := cw.Write(record); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

func (r *ListRunner) writeTable(w io.Writer, rows []ControlRow, cols []string, header bool) error {
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
			if l := len(fieldValue(row, c)); l > widths[i] {
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
			vals[i] = fieldValue(row, c)
		}
		if err := printLine(vals); err != nil {
			return err
		}
	}
	return nil
}
