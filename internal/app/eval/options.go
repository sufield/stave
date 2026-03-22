package eval

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/pkg/timeutil"
)

// ObservationSource represents the source of observation data.
// It is either a filesystem path or "-" for stdin.
type ObservationSource string

// IsStdin reports whether observations are read from stdin.
func (s ObservationSource) IsStdin() bool {
	return s == "-"
}

// Path returns the filesystem path, or "" if reading from stdin.
func (s ObservationSource) Path() string {
	if s.IsStdin() {
		return ""
	}
	return string(s)
}

// Options holds raw string flags for an evaluation run.
type Options struct {
	ContextName        string
	ProjectRoot        string
	ControlsDir        string
	ConfigPath         string
	UserConfigPath     string
	MaxUnsafeDuration  string
	NowTime            string
	ObservationsSource ObservationSource
	IntegrityManifest  string
	IntegrityPublicKey string
	Hasher             appcontracts.ContentHasher
}

// ParsedOptions holds validated, parsed values ready for use.
// Now is the parsed --now time; a zero value means "use real clock".
type ParsedOptions struct {
	ContextName       string
	MaxUnsafeDuration time.Duration
	Now               time.Time
	Source            ObservationSource
}

// Validate normalizes string fields, checks cross-flag constraints,
// validates file paths, and parses duration/time values.
func (o Options) Validate() (ParsedOptions, error) {
	o = o.normalize()

	if err := o.validateIntegrityFlags(); err != nil {
		return ParsedOptions{}, err
	}
	if err := validateFilePath(o.IntegrityManifest, "integrity-manifest"); err != nil {
		return ParsedOptions{}, err
	}
	if err := validateFilePath(o.IntegrityPublicKey, "integrity-public-key"); err != nil {
		return ParsedOptions{}, err
	}

	maxDuration, err := o.parseMaxUnsafeDuration()
	if err != nil {
		return ParsedOptions{}, err
	}

	now, err := o.parseNowTime()
	if err != nil {
		return ParsedOptions{}, err
	}

	return ParsedOptions{
		ContextName:       o.resolveContextName(),
		MaxUnsafeDuration: maxDuration,
		Now:               now,
		Source:            o.ObservationsSource,
	}, nil
}

// normalize trims whitespace from all string fields so downstream methods
// can trust the data without repeated TrimSpace calls.
func (o Options) normalize() Options {
	o.ContextName = strings.TrimSpace(o.ContextName)
	o.ProjectRoot = strings.TrimSpace(o.ProjectRoot)
	o.ControlsDir = strings.TrimSpace(o.ControlsDir)
	o.ConfigPath = strings.TrimSpace(o.ConfigPath)
	o.UserConfigPath = strings.TrimSpace(o.UserConfigPath)
	o.MaxUnsafeDuration = strings.TrimSpace(o.MaxUnsafeDuration)
	o.NowTime = strings.TrimSpace(o.NowTime)
	o.IntegrityManifest = strings.TrimSpace(o.IntegrityManifest)
	o.IntegrityPublicKey = strings.TrimSpace(o.IntegrityPublicKey)
	return o
}

func (o Options) validateIntegrityFlags() error {
	if o.IntegrityPublicKey != "" && o.IntegrityManifest == "" {
		return fmt.Errorf("integrity-public-key requires integrity-manifest")
	}
	if o.ObservationsSource.IsStdin() && o.IntegrityManifest != "" {
		return fmt.Errorf("integrity-manifest cannot be used with observations - (stdin mode)")
	}
	return nil
}

// validateFilePath checks that a flag value, when non-empty, references an
// existing regular file. It distinguishes not-exist from permission errors.
func validateFilePath(path, flag string) error {
	if path == "" {
		return nil
	}
	fi, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("%s not found: %s", flag, path)
		}
		if os.IsPermission(err) {
			return fmt.Errorf("%s not readable: %s (check file permissions)", flag, path)
		}
		return fmt.Errorf("cannot access %s %q: %w", flag, path, err)
	}
	if fi.IsDir() {
		return fmt.Errorf("%s must be a file, got directory: %s", flag, path)
	}
	return nil
}

func (o Options) parseMaxUnsafeDuration() (time.Duration, error) {
	d, err := timeutil.ParseDuration(o.MaxUnsafeDuration)
	if err != nil {
		return 0, fmt.Errorf("invalid --max-unsafe: %w", err)
	}
	return d, nil
}

// parseNowTime parses the --now flag into a time.Time. A zero value means
// the flag was not set; the caller decides which clock implementation to use.
func (o Options) parseNowTime() (time.Time, error) {
	if o.NowTime == "" {
		return time.Time{}, nil
	}
	return timeutil.ParseTimestamp(o.NowTime)
}

func (o Options) resolveContextName() string {
	if o.ContextName != "" {
		return o.ContextName
	}
	abs, err := filepath.Abs(o.ProjectRoot)
	if err != nil {
		return "default"
	}
	base := filepath.Base(abs)
	if base == "." || base == string(os.PathSeparator) {
		return "default"
	}
	return base
}

// FindConfigPath returns the project config path if set.
func (o Options) FindConfigPath() (string, bool) {
	path := strings.TrimSpace(o.ConfigPath)
	return path, path != ""
}

// FindUserConfigPath returns the user config path if set.
func (o Options) FindUserConfigPath() (string, bool) {
	path := strings.TrimSpace(o.UserConfigPath)
	return path, path != ""
}
