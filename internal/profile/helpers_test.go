package profile

import (
	"context"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/compliance"
)

// TestEvaluate is a context-free wrapper around Evaluate intended
// for use in test code only. Threading context.Background() through
// every assertion clutters tests without adding signal — TestEvaluate
// keeps the test focus on profile / report behaviour.
//
// Production code paths must call Evaluate directly so cancellation
// and deadlines propagate as designed.
func (p *Profile) TestEvaluate(snap asset.Snapshot, registries ...*compliance.ControlCatalog) (Report, error) {
	return p.Evaluate(context.Background(), snap, registries...)
}
