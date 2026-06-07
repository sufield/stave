package cmdutil

import (
	"context"
	"io"

	"github.com/sufield/stave/internal/cli/ui"
)

// NewPager is a thin pass-through to ui.NewPager for command packages that may
// not import internal/* directly (the pkg/stave facade rule — see
// docs/architecture/pkg-stave-facade.md, enforced by their architecture_test).
// cmd/cmdutil is on those packages' allow-list, so they page their human output
// through here.
//
// It returns the writer to render into plus a close func that MUST be called.
// When w is not a terminal or paging is disabled, it returns w unchanged with a
// no-op close. Behavior and rationale live in internal/cli/ui/pager.go.
func NewPager(ctx context.Context, w io.Writer, enabled bool) (io.Writer, func() error) {
	return ui.NewPager(ctx, w, enabled)
}
