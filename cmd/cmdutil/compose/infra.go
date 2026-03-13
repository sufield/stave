package compose

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sync/errgroup"

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
	"github.com/sufield/stave/internal/pkg/timeutil"
)

// Provider manages the instantiation of various adapters and repositories.
// It acts as a Service Locator/Factory registry.
type Provider struct {
	ObsRepoFunc       func() (appcontracts.ObservationRepository, error)
	StdinObsRepoFunc  func(io.Reader) (appcontracts.ObservationRepository, error)
	ControlRepoFunc   func() (appcontracts.ControlRepository, error)
	FindingWriterFunc func(format string, jsonMode bool) (appcontracts.FindingMarshaler, error)
}

// NewDefaultProvider returns a provider configured with standard adapters.
func NewDefaultProvider() *Provider {
	return &Provider{
		ObsRepoFunc: func() (appcontracts.ObservationRepository, error) {
			return obsjson.NewObservationLoader(), nil
		},
		StdinObsRepoFunc: func(r io.Reader) (appcontracts.ObservationRepository, error) {
			return obsjson.NewStdinObservationLoader(obsjson.NewObservationLoader(), r), nil
		},
		ControlRepoFunc: func() (appcontracts.ControlRepository, error) {
			return ctlyaml.NewControlLoader()
		},
		FindingWriterFunc: DefaultFindingWriter,
	}
}

// --- Active Provider ---

// activeProvider is the process-wide provider used by command handlers.
// Set via UseProvider during App bootstrap; tests use OverrideProviderForTest.
var activeProvider = NewDefaultProvider()

// ActiveProvider returns the current process-wide provider.
func ActiveProvider() *Provider { return activeProvider }

// UseProvider replaces the active provider. Called once from App.bootstrap.
func UseProvider(p *Provider) { activeProvider = p }

// OverrideProviderForTest replaces the active provider for the duration of a test.
func OverrideProviderForTest(t interface {
	Helper()
	Cleanup(func())
}, p *Provider) {
	t.Helper()
	orig := activeProvider
	activeProvider = p
	t.Cleanup(func() { activeProvider = orig })
}

// SnapshotObservationRepository extends ObservationRepository with single-snapshot reader loading.
type SnapshotObservationRepository interface {
	appcontracts.ObservationRepository
	appcontracts.SnapshotReader
}

// --- Provider Repository Methods ---

// NewObservationRepo creates a new observation repository.
func (p *Provider) NewObservationRepo() (appcontracts.ObservationRepository, error) {
	return p.ObsRepoFunc()
}

// NewControlRepo creates a new control repository.
func (p *Provider) NewControlRepo() (appcontracts.ControlRepository, error) {
	return p.ControlRepoFunc()
}

// NewStdinObsRepo creates an observation repository that reads from stdin.
func (p *Provider) NewStdinObsRepo(r io.Reader) (appcontracts.ObservationRepository, error) {
	return p.StdinObsRepoFunc(r)
}

// NewSnapshotRepo creates a snapshot observation repository.
func (p *Provider) NewSnapshotRepo() (SnapshotObservationRepository, error) {
	repo, err := p.ObsRepoFunc()
	if err != nil {
		return nil, err
	}
	sr, ok := repo.(SnapshotObservationRepository)
	if !ok {
		return nil, fmt.Errorf("observation repository does not implement SnapshotReader")
	}
	return sr, nil
}

// NewFindingWriter creates a finding marshaler for the given output format.
func (p *Provider) NewFindingWriter(format string, jsonMode bool) (appcontracts.FindingMarshaler, error) {
	return p.FindingWriterFunc(format, jsonMode)
}

// --- Asset Loading ---

// Assets represents the data loaded for an evaluation.
type Assets struct {
	Snapshots []asset.Snapshot
	Controls  []policy.ControlDefinition
}

// LoadAssets concurrently fetches observations and controls.
func (p *Provider) LoadAssets(ctx context.Context, obsDir, ctlDir string) (Assets, error) {
	obsRepo, err := p.ObsRepoFunc()
	if err != nil {
		return Assets{}, fmt.Errorf("create observation loader: %w", err)
	}
	ctlRepo, err := p.ControlRepoFunc()
	if err != nil {
		return Assets{}, fmt.Errorf("create control loader: %w", err)
	}

	var res Assets
	g, gCtx := errgroup.WithContext(ctx)

	g.Go(func() error {
		loadResult, loadErr := obsRepo.LoadSnapshots(gCtx, obsDir)
		if loadErr != nil {
			return fmt.Errorf("load observations from %q: %w", obsDir, loadErr)
		}
		res.Snapshots = loadResult.Snapshots
		return nil
	})

	g.Go(func() error {
		ctls, loadErr := ctlRepo.LoadControls(gCtx, ctlDir)
		if loadErr != nil {
			return fmt.Errorf("load controls from %q: %w", ctlDir, loadErr)
		}
		res.Controls = ctls
		return nil
	})

	if err := g.Wait(); err != nil {
		return Assets{}, err
	}
	return res, nil
}

// --- Output Resolution ---

// DefaultFindingWriter is the standard implementation for finding marshalers.
func DefaultFindingWriter(format string, jsonMode bool) (appcontracts.FindingMarshaler, error) {
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

// ResolveStdout returns a writer based on quiet settings and format.
func ResolveStdout(w io.Writer, quiet bool, format ui.OutputFormat) io.Writer {
	if quiet && !format.IsJSON() {
		return io.Discard
	}
	if w == nil {
		return os.Stdout
	}
	return w
}

// --- Time & Clock ---

// ResolveClock returns a FixedClock if a timestamp is provided, otherwise RealClock.
func ResolveClock(raw string) (ports.Clock, error) {
	if raw == "" {
		return ports.RealClock{}, nil
	}
	t, err := timeutil.ParseRFC3339(raw, "--now")
	if err != nil {
		return nil, err
	}
	return ports.FixedClock(t), nil
}

// --- Git Auditing ---

// AuditGitStatus gathers git metadata for specific paths.
func AuditGitStatus(baseDir string, watchPaths []string) *evaluation.GitInfo {
	if strings.TrimSpace(baseDir) == "" {
		baseDir, _ = os.Getwd()
	}
	repoRoot, ok := gitinfo.DetectRepoRoot(baseDir)
	if !ok {
		return nil
	}
	head, _ := gitinfo.HeadCommit(repoRoot)

	var cleaned []string
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
	return &evaluation.GitInfo{
		RepoRoot:  repoRoot,
		Head:      head,
		Dirty:     dirty,
		DirtyList: dirtyList,
	}
}

// WarnGitDirty prints a warning to stderr if the repository is dirty.
func WarnGitDirty(stderr io.Writer, git *evaluation.GitInfo, label string, quiet bool) {
	if git == nil || !git.Dirty || quiet {
		return
	}
	if stderr == nil {
		stderr = os.Stderr
	}
	fmt.Fprintf(stderr, "WARN: Uncommitted changes detected in %s inputs (%s). This run may not reflect committed state.\n",
		label, strings.Join(git.DirtyList, ", "))
}

// --- Helpers ---

// EmptyDash returns "-" if the string is whitespace-only.
func EmptyDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}
