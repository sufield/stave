package stave

import (
	"bytes"
	"fmt"
	"strings"
	"time"

	ctlbuiltin "github.com/sufield/stave/internal/adapters/controls/builtin"
	"github.com/sufield/stave/internal/adapters/predicate"
	appexempt "github.com/sufield/stave/internal/app/exempt"
	"github.com/sufield/stave/internal/controldata"
	"github.com/sufield/stave/internal/core/ports"
)

// AcknowledgmentInput parameterizes [AddAcknowledgment]. Compensating is a
// comma-separated list of compensating control IDs (split internally).
type AcknowledgmentInput struct {
	ControlID     string
	AssetID       string
	Reason        string
	Approver      string
	Expires       string
	Compensating  string
	ReviewCadence string // e.g. "annual", "quarterly", "90d"
}

// ExceptionInput parameterizes [AddException].
type ExceptionInput struct {
	ControlID string
	AssetID   string
	Expires   string
	Reason    string
}

// AddAcknowledgment appends a formal risk acceptance to the acceptance file
// and saves it with an audit trail. It is the library entry point behind
// `stave exempt acknowledge`.
func AddAcknowledgment(file string, in AcknowledgmentInput) error {
	f, err := appexempt.Load(file)
	if err != nil {
		return fmt.Errorf("load acceptance file: %w", err)
	}
	var comps []string
	p := in.Compensating
	for p != "" {
		var seg string
		seg, p, _ = strings.Cut(p, ",")
		comps = append(comps, seg)
	}
	reviewBy := computeReviewBy(in.ReviewCadence, time.Now().UTC())
	if addErr := f.AddAcknowledgment(appexempt.AcknowledgmentEntry{
		ControlID:            in.ControlID,
		AssetID:              in.AssetID,
		Reason:               in.Reason,
		Approver:             in.Approver,
		ExpiryDate:           in.Expires,
		ReviewBy:             reviewBy,
		ReviewCadence:        in.ReviewCadence,
		CompensatingControls: comps,
	}, appexempt.NewTimestamp(ports.RealClock{})); addErr != nil {
		return fmt.Errorf("add acknowledgment: %w", addErr)
	}
	if saveErr := appexempt.Save(file, f, "stave exempt acknowledge", appexempt.NewTimestamp(ports.RealClock{})); saveErr != nil {
		return fmt.Errorf("save acceptance file: %w", saveErr)
	}
	return nil
}

// computeReviewBy derives the next review date from a cadence string.
// Returns "" if cadence is empty.
func computeReviewBy(cadence string, now time.Time) string {
	if cadence == "" {
		return ""
	}
	switch strings.ToLower(cadence) {
	case "annual", "yearly":
		return now.AddDate(1, 0, 0).Format("2006-01-02")
	case "semi-annual", "biannual":
		return now.AddDate(0, 6, 0).Format("2006-01-02")
	case "quarterly":
		return now.AddDate(0, 3, 0).Format("2006-01-02")
	case "monthly":
		return now.AddDate(0, 1, 0).Format("2006-01-02")
	default:
		if d, err := time.ParseDuration(cadence); err == nil {
			return now.Add(d).Format("2006-01-02")
		}
		return ""
	}
}

// AddException appends an operational suppression to the acceptance file. It
// is the library entry point behind `stave exempt except`.
func AddException(file string, in ExceptionInput) error {
	f, err := appexempt.Load(file)
	if err != nil {
		return fmt.Errorf("load acceptance file: %w", err)
	}
	ts := appexempt.NewTimestamp(ports.RealClock{})
	if addErr := f.AddException(appexempt.ExceptionEntry{
		ControlID:  in.ControlID,
		AssetID:    in.AssetID,
		ExpiryDate: in.Expires,
		Reason:     in.Reason,
	}, ts); addErr != nil {
		return fmt.Errorf("add exception: %w", addErr)
	}
	if saveErr := appexempt.Save(file, f, "stave exempt except", ts); saveErr != nil {
		return fmt.Errorf("save acceptance file: %w", saveErr)
	}
	return nil
}

// AddAssetExemption appends a scope exclusion (exempted asset pattern) to the
// acceptance file. It is the library entry point behind `stave exempt asset`.
func AddAssetExemption(file, pattern, reason string) error {
	f, err := appexempt.Load(file)
	if err != nil {
		return fmt.Errorf("load acceptance file: %w", err)
	}
	if addErr := f.AddExemption(appexempt.ExemptionEntry{
		AssetPattern: pattern,
		Reason:       reason,
	}); addErr != nil {
		return fmt.Errorf("add exemption: %w", addErr)
	}
	if saveErr := appexempt.Save(file, f, "stave exempt asset", appexempt.NewTimestamp(ports.RealClock{})); saveErr != nil {
		return fmt.Errorf("save acceptance file: %w", saveErr)
	}
	return nil
}

// RemoveAcceptance marks an acknowledgment (control_id@asset_id) as revoked,
// preserving it with an audit trail. It is the library entry point behind
// `stave exempt remove`.
func RemoveAcceptance(file, id string) error {
	f, err := appexempt.Load(file)
	if err != nil {
		return fmt.Errorf("load acceptance file: %w", err)
	}
	if rmErr := f.Remove(id, appexempt.NewTimestamp(ports.RealClock{})); rmErr != nil {
		return fmt.Errorf("revoke entry: %w", rmErr)
	}
	if saveErr := appexempt.Save(file, f, "stave exempt remove", appexempt.NewTimestamp(ports.RealClock{})); saveErr != nil {
		return fmt.Errorf("save acceptance file: %w", saveErr)
	}
	return nil
}

// ListAcceptances renders the active acceptances (filtered by listType and
// showExpired) in the requested format (table | json). It is the library
// entry point behind `stave exempt list`.
func ListAcceptances(file, format, listType string, showExpired bool) ([]byte, error) {
	f, err := appexempt.Load(file)
	if err != nil {
		return nil, fmt.Errorf("load acceptance file: %w", err)
	}
	var buf bytes.Buffer
	if err := appexempt.WriteList(&buf, f, format, listType, showExpired); err != nil {
		return nil, fmt.Errorf("write list: %w", err)
	}
	return buf.Bytes(), nil
}

// UpcomingAcceptances renders the acknowledgments expiring within `days` of
// `now`. It is the library entry point behind `stave exempt upcoming`.
func UpcomingAcceptances(file string, days int, now time.Time) ([]byte, error) {
	f, err := appexempt.Load(file)
	if err != nil {
		return nil, fmt.Errorf("load acceptance file: %w", err)
	}
	var buf bytes.Buffer
	if err := exemptRenderUpcoming(&buf, days, f.Upcoming(days, now)); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// AcceptanceHistory renders the full acknowledgment audit trail (including
// expired/revoked entries) in the requested format. It is the library entry
// point behind `stave exempt history`.
func AcceptanceHistory(file, format string) ([]byte, error) {
	f, err := appexempt.Load(file)
	if err != nil {
		return nil, fmt.Errorf("load acceptance file: %w", err)
	}
	entries := f.History()
	var buf bytes.Buffer
	if len(entries) == 0 {
		if _, werr := fmt.Fprintln(&buf, "No acknowledgment history."); werr != nil {
			return nil, fmt.Errorf("write output: %w", werr)
		}
		return buf.Bytes(), nil
	}
	renderer, err := exemptNewHistoryRenderer(format)
	if err != nil {
		return nil, err
	}
	if rerr := renderer.Render(&buf, entries); rerr != nil {
		return nil, fmt.Errorf("render output: %w", rerr)
	}
	return buf.Bytes(), nil
}

// ValidateAcceptances checks the acceptance file for required fields, date
// formats, and structural correctness, cross-referencing compensating
// controls against the built-in catalog. It returns the list of validation
// errors (empty when valid). It is the library entry point behind
// `stave exempt validate`.
func ValidateAcceptances(file string) ([]string, error) {
	f, err := appexempt.Load(file)
	if err != nil {
		return nil, fmt.Errorf("load acceptance file: %w", err)
	}
	// Load the built-in catalog for compensating-control validation. Catalog
	// load errors are tolerated: the field/date checks are still useful.
	knownIDs := make(map[string]struct{})
	store := ctlbuiltin.NewControlStore(controldata.FS, ".", ctlbuiltin.WithAliasResolver(predicate.ResolverFunc()))
	if controls, loadErr := store.All(); loadErr == nil {
		for i := range controls {
			knownIDs[string(controls[i].ID)] = struct{}{}
		}
	}
	return f.ValidateWithCatalog(knownIDs), nil
}

// exemptRenderUpcoming renders the upcoming-expiry report. Moved verbatim
// from the command so the output stays byte-identical.
func exemptRenderUpcoming(w *bytes.Buffer, days int, entries []appexempt.AcknowledgmentEntry) error {
	if len(entries) == 0 {
		if _, err := fmt.Fprintf(w, "No acceptances expiring within %d days.\n", days); err != nil {
			return fmt.Errorf("write output: %w", err)
		}
		return nil
	}
	if _, err := fmt.Fprintf(w, "ACCEPTANCES EXPIRING WITHIN %d DAYS\n", days); err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	if _, err := fmt.Fprintln(w, strings.Repeat("-", 70)); err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	for i := range entries {
		a := &entries[i]
		daysLeft := -1
		if expiry, parseErr := time.Parse("2006-01-02", a.ExpiryDate); parseErr == nil {
			daysLeft = int(time.Until(expiry).Hours() / 24)
		}
		if _, err := fmt.Fprintf(w, "  %-40s  %s  %d days  %s\n",
			a.ID, a.ExpiryDate, daysLeft, a.Approver); err != nil {
			return err
		}
	}
	return nil
}
