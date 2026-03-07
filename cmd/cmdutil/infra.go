package cmdutil

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/adapters/gitinfo"
	ctlyaml "github.com/sufield/stave/internal/adapters/input/controls/yaml"
	obsjson "github.com/sufield/stave/internal/adapters/input/observations/json"
	outjson "github.com/sufield/stave/internal/adapters/output/json"
	outsarif "github.com/sufield/stave/internal/adapters/output/sarif"
	outtext "github.com/sufield/stave/internal/adapters/output/text"
	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/policy"
	"github.com/sufield/stave/internal/domain/ports"
)

// ResolveNow parses a --now flag value. Returns wall clock UTC when raw is empty.
func ResolveNow(raw string) (time.Time, error) {
	if raw == "" {
		return time.Now().UTC(), nil
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid --now %q: expected RFC3339 timestamp", raw)
	}
	return t.UTC(), nil
}

// ResolveClock parses a --now flag value into a Clock. Returns RealClock when raw is empty.
func ResolveClock(raw string) (ports.Clock, error) {
	if raw == "" {
		return ports.RealClock{}, nil
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return nil, fmt.Errorf("invalid --now %q (use RFC3339: 2026-01-15T00:00:00Z)", raw)
	}
	return ports.FixedClock{Time: t}, nil
}

// ResolveFormatValue determines the effective output format from a flag value and
// global JSON mode. When the flag was not explicitly changed and global JSON mode
// is active, "json" is used instead.
func ResolveFormatValue(cmd *cobra.Command, raw string) (ui.OutputFormat, error) {
	formatRaw, err := ResolveFormat(cmd, raw)
	if err != nil {
		return "", err
	}
	return ui.ParseOutputFormat(strings.ToLower(formatRaw))
}

// LoadedAssets holds concurrently loaded observations and controls.
type LoadedAssets struct {
	Snapshots   []asset.Snapshot
	Controls    []policy.ControlDefinition
	ObsRepo     appcontracts.ObservationRepository
	ControlRepo appcontracts.ControlRepository
}

// Load concurrently fetches observations and controls using configured repositories.
func (r *LoadedAssets) Load(ctx context.Context, obsDir, ctlDir string) error {
	if r.ObsRepo == nil {
		return fmt.Errorf("observation repository is required")
	}
	if r.ControlRepo == nil {
		return fmt.Errorf("control repository is required")
	}

	var (
		wg     sync.WaitGroup
		obsErr error
		ctlErr error
	)

	wg.Add(2)
	go func() {
		defer wg.Done()
		var loadResult appcontracts.LoadResult
		loadResult, obsErr = r.ObsRepo.LoadSnapshots(ctx, obsDir)
		r.Snapshots = loadResult.Snapshots
	}()
	go func() {
		defer wg.Done()
		r.Controls, ctlErr = r.ControlRepo.LoadControls(ctx, ctlDir)
	}()
	wg.Wait()

	if obsErr != nil {
		return fmt.Errorf("load observations from %q: %w", obsDir, obsErr)
	}
	if ctlErr != nil {
		return fmt.Errorf("load controls from %q: %w", ctlDir, ctlErr)
	}
	return nil
}

// SnapshotObservationRepository extends ObservationRepository with reader loading.
type SnapshotObservationRepository interface {
	appcontracts.ObservationRepository
	LoadSnapshotFromReader(ctx context.Context, r io.Reader, sourceName string) (asset.Snapshot, error)
}

// Composition holds constructor wiring for adapters.
type Composition struct {
	NewObservationRepository func() (appcontracts.ObservationRepository, error)
	NewStdinObservationRepo  func(r io.Reader) (appcontracts.ObservationRepository, error)
	NewControlRepository     func() (appcontracts.ControlRepository, error)
	NewSnapshotObservation   func() (SnapshotObservationRepository, error)
	NewFindingWriter         func(format string, jsonMode bool) (appcontracts.FindingMarshaler, error)
}

// DefaultComposition is the standard adapter wiring.
var DefaultComposition = Composition{
	NewObservationRepository: func() (appcontracts.ObservationRepository, error) {
		return obsjson.NewObservationLoader(), nil
	},
	NewStdinObservationRepo: func(r io.Reader) (appcontracts.ObservationRepository, error) {
		return obsjson.NewStdinObservationLoader(obsjson.NewObservationLoader(), r), nil
	},
	NewControlRepository: func() (appcontracts.ControlRepository, error) {
		return ctlyaml.NewControlLoader()
	},
	NewSnapshotObservation: func() (SnapshotObservationRepository, error) {
		return obsjson.NewObservationLoader(), nil
	},
	NewFindingWriter: defaultNewFindingWriter,
}

// defaultNewFindingWriter creates a finding marshaler for the given output format.
func defaultNewFindingWriter(format string, jsonMode bool) (appcontracts.FindingMarshaler, error) {
	const indented = true

	switch strings.ToLower(strings.TrimSpace(format)) {
	case "text":
		return outtext.NewFindingWriter(), nil
	case "json":
		if jsonMode {
			return outjson.NewFindingWriterWithEnvelope(indented), nil
		}
		return outjson.NewFindingWriter(indented), nil
	case "sarif":
		return outsarif.NewFindingWriter(), nil
	default:
		return nil, fmt.Errorf("invalid --format %q (use text, json, or sarif)", format)
	}
}

// NewObservationRepository creates a new observation repository.
func NewObservationRepository() (appcontracts.ObservationRepository, error) {
	return DefaultComposition.NewObservationRepository()
}

// NewControlRepository creates a new control repository.
func NewControlRepository() (appcontracts.ControlRepository, error) {
	return DefaultComposition.NewControlRepository()
}

// NewStdinObservationRepository creates an observation repository that reads from stdin.
func NewStdinObservationRepository(r io.Reader) (appcontracts.ObservationRepository, error) {
	return DefaultComposition.NewStdinObservationRepo(r)
}

// NewSnapshotObservationRepository creates a snapshot observation repository.
func NewSnapshotObservationRepository() (SnapshotObservationRepository, error) {
	return DefaultComposition.NewSnapshotObservation()
}

// NewFindingWriter creates a finding marshaler for the given output format.
func NewFindingWriter(format string, jsonMode bool) (appcontracts.FindingMarshaler, error) {
	return DefaultComposition.NewFindingWriter(format, jsonMode)
}

// LoadObsAndInv creates loaders and loads both concurrently.
func LoadObsAndInv(ctx context.Context, obsDir, ctlDir string) (LoadedAssets, error) {
	obsRepo, err := NewObservationRepository()
	if err != nil {
		return LoadedAssets{}, fmt.Errorf("create observation loader: %w", err)
	}
	ctlRepo, err := NewControlRepository()
	if err != nil {
		return LoadedAssets{}, fmt.Errorf("create control loader: %w", err)
	}

	res := LoadedAssets{
		ObsRepo:     obsRepo,
		ControlRepo: ctlRepo,
	}
	if err := res.Load(ctx, obsDir, ctlDir); err != nil {
		return LoadedAssets{}, err
	}
	return res, nil
}

// CollectGitAudit gathers git status for the given paths.
// Returns nil when git is not available or the directory is not a repository.
func CollectGitAudit(baseDir string, watchPaths []string) *evaluation.GitInfo {
	if strings.TrimSpace(baseDir) == "" {
		baseDir, _ = os.Getwd()
	}
	repoRoot, ok := gitinfo.DetectRepoRoot(baseDir)
	if !ok {
		return nil
	}
	head, _ := gitinfo.HeadCommit(repoRoot)
	cleaned := make([]string, 0, len(watchPaths))
	for _, p := range watchPaths {
		if strings.TrimSpace(p) == "" {
			continue
		}
		abs := p
		if !filepath.IsAbs(abs) {
			abs = filepath.Join(baseDir, p)
		}
		cleaned = append(cleaned, abs)
	}
	dirty, dirtyList, _ := gitinfo.IsDirty(repoRoot, cleaned)
	return &evaluation.GitInfo{RepoRoot: repoRoot, Head: head, Dirty: dirty, DirtyList: dirtyList}
}

// WarnIfGitDirty prints a warning if git is dirty and quiet is not set.
func WarnIfGitDirty(cmd *cobra.Command, git *evaluation.GitInfo, label string) {
	if git == nil || !git.Dirty {
		return
	}
	if QuietEnabled(cmd) {
		return
	}
	_, _ = fmt.Fprintf(os.Stderr, "WARN: Uncommitted changes detected in %s inputs (%s). This run may not reflect committed state.\n", label, strings.Join(git.DirtyList, ", "))
}

// EmptyDash returns "-" for empty strings.
func EmptyDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}
