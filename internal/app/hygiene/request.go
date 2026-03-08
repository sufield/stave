package hygiene

import (
	"fmt"
	"strings"
	"time"

	"github.com/sufield/stave/internal/domain/evaluation/risk"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/pkg/timeutil"
)

// Request captures all inputs needed to generate a hygiene report.
// It is intentionally decoupled from CLI libraries to enable deterministic tests
// and reuse from other entrypoints (e.g. APIs).
type Request struct {
	ControlsDir     string
	ObservationsDir string
	ArchiveDir      string
	MaxUnsafe       string
	DueSoon         string
	Lookback        string
	DueWithin       string
	OlderThan       string
	RetentionTier   string
	KeepMin         int
	NowTime         string
	ControlIDs      []kernel.ControlID
	AssetTypes      []kernel.AssetType
	Statuses        []risk.Status
	NowFunc         func() time.Time // nil → time.Now().UTC()
}

// ParsedRequest holds the validated, typed values produced by Parse.
type ParsedRequest struct {
	MaxUnsafe time.Duration
	DueSoon   time.Duration
	Lookback  time.Duration
	DueWithin *time.Duration
	Now       time.Time
}

// Parse validates and converts raw request fields into typed values used by
// hygiene orchestration code.
func (r *Request) Parse() (ParsedRequest, error) {
	maxUnsafe, err := timeutil.ParseDuration(r.MaxUnsafe)
	if err != nil {
		return ParsedRequest{}, fmt.Errorf("invalid max-unsafe: %w", err)
	}
	dueSoon, err := timeutil.ParseDuration(r.DueSoon)
	if err != nil {
		return ParsedRequest{}, fmt.Errorf("invalid due-soon: %w", err)
	}
	lookback, err := timeutil.ParseDuration(r.Lookback)
	if err != nil {
		return ParsedRequest{}, fmt.Errorf("invalid lookback: %w", err)
	}
	if lookback <= 0 {
		return ParsedRequest{}, fmt.Errorf("invalid lookback %q: must be > 0", r.Lookback)
	}
	var dueWithin *time.Duration
	if strings.TrimSpace(r.DueWithin) != "" {
		dw, dwErr := timeutil.ParseDuration(r.DueWithin)
		if dwErr != nil {
			return ParsedRequest{}, fmt.Errorf("invalid due-within: %w", dwErr)
		}
		if dw < 0 {
			return ParsedRequest{}, fmt.Errorf("invalid due-within %q: must be >= 0", r.DueWithin)
		}
		dueWithin = &dw
	}
	if r.KeepMin < 0 {
		return ParsedRequest{}, fmt.Errorf("invalid keep-min %d: must be >= 0", r.KeepMin)
	}
	if err = validateStatuses(r.Statuses); err != nil {
		return ParsedRequest{}, err
	}
	nowFn := r.NowFunc
	if nowFn == nil {
		nowFn = func() time.Time { return time.Now().UTC() }
	}
	var now time.Time
	if strings.TrimSpace(r.NowTime) == "" {
		now = nowFn()
	} else {
		now, err = timeutil.ParseTimestamp(r.NowTime)
		if err != nil {
			return ParsedRequest{}, err
		}
	}
	return ParsedRequest{
		MaxUnsafe: maxUnsafe,
		DueSoon:   dueSoon,
		Lookback:  lookback,
		DueWithin: dueWithin,
		Now:       now,
	}, nil
}

func validateStatuses(statuses []risk.Status) error {
	raw := make([]string, len(statuses))
	for i, s := range statuses {
		raw[i] = string(s)
	}
	_, err := risk.ValidateStatuses(raw)
	return err
}
