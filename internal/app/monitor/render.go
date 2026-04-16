package monitor

import (
	"fmt"
	"io"
	"strings"
)

const (
	colorRed    = "\033[31m"
	colorYellow = "\033[33m"
	colorGreen  = "\033[32m"
	colorBold   = "\033[1m"
	colorReset  = "\033[0m"
	clearScreen = "\033[2J\033[H"
	blockChars  = "▁▂▃▄▅▆▇█"
)

// RenderLive writes the full ANSI monitor screen.
func RenderLive(w io.Writer, s *State, noColor bool) {
	if !noColor {
		_, _ = fmt.Fprint(w, clearScreen)
	}
	RenderPlain(w, s, !noColor)
}

// RenderPlain writes the monitor state as plain or colored text.
func RenderPlain(w io.Writer, s *State, color bool) {
	c := colorFuncs(color)

	fmt.Fprintf(w, "%sSTAVE MONITOR%s — %s\n", c.bold, c.reset, s.GeneratedAt)
	fmt.Fprintln(w, strings.Repeat("=", 60))

	// Posture score.
	scoreColor := c.green
	if s.Score < 60 {
		scoreColor = c.red
	} else if s.Score < 80 {
		scoreColor = c.yellow
	}
	delta := fmt.Sprintf("%+.1f", s.ScoreDelta)
	fmt.Fprintf(w, "Posture Score:  %s%.1f%s (%s, %s)\n\n", scoreColor, s.Score, c.reset, delta, s.ScoreTrend)

	// Sparkline.
	if len(s.ScoreHist) > 1 {
		fmt.Fprintf(w, "Trend: %s\n\n", Sparkline(s.ScoreHist))
	}

	// Findings.
	fmt.Fprintf(w, "Findings: %d total", s.Findings.Total)
	if s.Findings.Total > 0 {
		fmt.Fprintf(w, " (%s%d critical%s, %d high, %d medium, %d low)",
			critColor(s.Findings.Critical, c), s.Findings.Critical, c.reset,
			s.Findings.High, s.Findings.Medium, s.Findings.Low)
	}
	fmt.Fprintln(w)

	// Severity bars.
	if s.Findings.Total > 0 {
		maxCount := max(s.Findings.Critical, max(s.Findings.High, max(s.Findings.Medium, s.Findings.Low)))
		if maxCount == 0 {
			maxCount = 1
		}
		fmt.Fprintf(w, "  CRITICAL  %s %3d\n", bar(s.Findings.Critical, maxCount, c.red, c), s.Findings.Critical)
		fmt.Fprintf(w, "  HIGH      %s %3d\n", bar(s.Findings.High, maxCount, c.yellow, c), s.Findings.High)
		fmt.Fprintf(w, "  MEDIUM    %s %3d\n", bar(s.Findings.Medium, maxCount, c.green, c), s.Findings.Medium)
		fmt.Fprintf(w, "  LOW       %s %3d\n", bar(s.Findings.Low, maxCount, c.green, c), s.Findings.Low)
		fmt.Fprintln(w)
	}

	// SLA burn rate.
	if len(s.SLABurn) > 0 {
		fmt.Fprintln(w, "SLA Burn Rate:")
		for _, sev := range []string{"critical", "high", "medium", "low"} {
			rate, ok := s.SLABurn[sev]
			if !ok {
				continue
			}
			pct := rate * 100
			burnColor := c.green
			if pct >= 80 {
				burnColor = c.red
			} else if pct >= 50 {
				burnColor = c.yellow
			}
			fmt.Fprintf(w, "  %-10s %s[%s]%s %3.0f%%\n", sev, burnColor, gauge(rate, 10), c.reset, pct)
		}
		fmt.Fprintln(w)
	} else {
		fmt.Fprintln(w, "SLA: No policy configured. Run: stave sla init")
		fmt.Fprintln(w)
	}

	// Top findings.
	if len(s.TopFindings) > 0 {
		fmt.Fprintln(w, "Top Findings:")
		for _, tf := range s.TopFindings {
			status := ""
			if tf.SLABreached {
				status = fmt.Sprintf(" %sBREACHED%s", c.red, c.reset)
			}
			fmt.Fprintf(w, "  %-28s %-8s %5.0fh  burn:%4.0f%%%s\n",
				truncate(tf.ControlID, 28), strings.ToUpper(tf.Severity),
				tf.DwellHours, tf.SLABurnRate*100, status)
		}
		fmt.Fprintln(w)
	}

	// ATT&CK coverage.
	if len(s.ATTCKTactics) > 0 {
		fmt.Fprintln(w, "ATT&CK Coverage:")
		for _, t := range s.ATTCKTactics {
			fmt.Fprintf(w, "  %-6s %-20s %3d controls\n", t.ID, t.Name, t.Controls)
		}
		fmt.Fprintln(w)
	}

	// Summary.
	fmt.Fprintf(w, "Chains: %d  Findings: %d  Critical: %d\n",
		s.Catalog.Chains, s.Findings.Total, s.Findings.Critical)
}

// Sparkline generates a sparkline string from values using block characters.
func Sparkline(values []float64) string {
	if len(values) == 0 {
		return ""
	}
	minVal, maxVal := values[0], values[0]
	for _, v := range values[1:] {
		if v < minVal {
			minVal = v
		}
		if v > maxVal {
			maxVal = v
		}
	}
	rng := maxVal - minVal
	if rng == 0 {
		rng = 1
	}
	runes := []rune(blockChars)
	var b strings.Builder
	for _, v := range values {
		idx := int((v - minVal) / rng * float64(len(runes)-1))
		if idx >= len(runes) {
			idx = len(runes) - 1
		}
		b.WriteRune(runes[idx])
	}
	return b.String()
}

const barWidth = 20

func bar(val, maxVal int, clr string, c colors) string {
	filled := 0
	if maxVal > 0 {
		filled = val * barWidth / maxVal
	}
	filled = min(filled, barWidth)
	return clr + strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled) + c.reset
}

func gauge(rate float64, width int) string {
	filled := max(0, min(int(rate*float64(width)), width))
	return strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func critColor(count int, c colors) string {
	if count > 0 {
		return c.red
	}
	return ""
}

type colors struct {
	red, yellow, green, bold, reset string
}

func colorFuncs(enabled bool) colors {
	if !enabled {
		return colors{}
	}
	return colors{
		red:    colorRed,
		yellow: colorYellow,
		green:  colorGreen,
		bold:   colorBold,
		reset:  colorReset,
	}
}
