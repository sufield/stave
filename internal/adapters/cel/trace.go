package cel

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"text/tabwriter"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

// TraceResult holds a CEL-based predicate evaluation trace.
// It implements evaluation.TraceRenderer for integration with
// the existing finding enrichment pipeline.
type TraceResult struct {
	ControlID  kernel.ControlID `json:"control_id"`
	AssetID    asset.ID         `json:"asset_id"`
	Expression string           `json:"expression"`
	Result     bool             `json:"result"`
	Error      string           `json:"error,omitempty"`
}

// RenderText writes a human-readable trace to the writer.
//
// Wraps the writer in a sticky-error helper so any individual
// fmt.Fprintf failure is captured and returned. The previous shape
// discarded each Fprintf return — a broken pipe (operator pipes
// stave to head) silently dropped trailing lines and the function
// reported the final tw.Flush as successful.
func (r *TraceResult) RenderText(w io.Writer) error {
	sw := &stickyTraceWriter{w: w}
	tw := tabwriter.NewWriter(sw, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "Control:\t%s\n", r.ControlID)
	fmt.Fprintf(tw, "Asset:\t%s\n", r.AssetID)
	fmt.Fprintf(tw, "Result:\t%v\n", r.Result)
	if r.Error != "" {
		fmt.Fprintf(tw, "Error:\t%s\n", r.Error)
	}
	fmt.Fprintf(tw, "\nCEL Expression:\n%s\n", r.Expression)
	if flushErr := tw.Flush(); flushErr != nil {
		return fmt.Errorf("flush trace output: %w", flushErr)
	}
	return sw.err
}

// stickyTraceWriter captures the first write error so subsequent
// fmt.Fprintf calls become no-ops. Mirrors the stickyWriter pattern
// in internal/profile/reporter/text.go so trace rendering and
// profile rendering share the same error-handling shape.
type stickyTraceWriter struct {
	w   io.Writer
	err error
}

func (s *stickyTraceWriter) Write(p []byte) (int, error) {
	if s.err != nil {
		return 0, s.err
	}
	n, err := s.w.Write(p)
	if err != nil {
		s.err = fmt.Errorf("write trace: %w", err)
	}
	return n, err
}

// RenderJSON writes the trace as JSON to the writer.
func (r *TraceResult) RenderJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(r); err != nil {
		return fmt.Errorf("encode trace JSON: %w", err)
	}
	return nil
}

// sharedTraceCompiler is the package-level compiler used by
// BuildTrace. cel.Compiler holds a Compile cache that is only useful
// when the same compiler instance sees an expression more than once;
// constructing a fresh compiler on every BuildTrace would throw the
// cache away. A single shared compiler keeps the cache warm across
// the trace API, mirroring NewPredicateEval.
//
// Lazy init is guarded by sync.RWMutex with double-checked write
// rather than sync.Once so that a transient init failure (a
// platform-specific permission error during environment construction,
// for example) does not lock the package into a permanent error
// state. sync.Once would memoize the failure and every subsequent
// call would return the same error — even after the underlying
// condition cleared. The double-check pattern retries on each call
// until init succeeds, then takes the read-locked fast path.
var (
	sharedTraceCompiler   *Compiler
	sharedTraceCompilerMu sync.RWMutex
)

func getTraceCompiler() (*Compiler, error) {
	sharedTraceCompilerMu.RLock()
	c := sharedTraceCompiler
	sharedTraceCompilerMu.RUnlock()
	if c != nil {
		return c, nil
	}

	sharedTraceCompilerMu.Lock()
	defer sharedTraceCompilerMu.Unlock()
	// Re-check under the write lock: another goroutine may have
	// initialised between our RUnlock and Lock.
	if sharedTraceCompiler != nil {
		return sharedTraceCompiler, nil
	}
	compiler, err := NewCompiler()
	if err != nil {
		return nil, err
	}
	sharedTraceCompiler = compiler
	return compiler, nil
}

// BuildTrace compiles and evaluates a control's predicate against an
// asset, returning a TraceResult with the CEL expression and
// evaluation result. Returns (nil, error) for missing inputs (a nil
// control or asset is a programming defect, not data absence) or for
// compiler initialization failure. Compile and evaluate errors are
// captured in the returned TraceResult's Error field rather than
// surfaced as a Go error so callers can still render a partial trace.
func BuildTrace(
	ctl *policy.ControlDefinition,
	a *asset.Asset,
	snapshot *asset.Snapshot,
) (*TraceResult, error) {
	if ctl == nil {
		return nil, errors.New("BuildTrace: control is nil")
	}
	if a == nil {
		return nil, errors.New("BuildTrace: asset is nil")
	}

	compiler, err := getTraceCompiler()
	if err != nil {
		return nil, fmt.Errorf("BuildTrace: CEL compiler init: %w", err)
	}

	cp, err := compiler.Compile(ctl.UnsafePredicate)
	if err != nil {
		// Capture both the original compile error and any
		// predicate-to-expression conversion error so a malformed
		// predicate (e.g. unsupported literal type, missing
		// operator) doesn't disappear into a "compile" message
		// that names the wrong root cause. The earlier shape
		// silently dropped the conversion error, leaving operators
		// without the actual reason the trace is incomplete.
		expr, exprErr := PredicateToExpr(ctl.UnsafePredicate)
		errMsg := fmt.Sprintf("CEL compile: %v", err)
		if exprErr != nil {
			errMsg = fmt.Sprintf("%s; predicate-to-expression: %v", errMsg, exprErr)
		}
		return &TraceResult{
			ControlID:  ctl.ID,
			AssetID:    a.ID,
			Expression: expr,
			Error:      errMsg,
		}, nil
	}

	var identities []asset.CloudIdentity
	if snapshot != nil {
		identities = snapshot.Identities
	}

	result, evalErr := Evaluate(cp, *a, identities, ctl.Params.Raw())

	tr := &TraceResult{
		ControlID:  ctl.ID,
		AssetID:    a.ID,
		Expression: string(cp.Expression),
		Result:     result,
	}
	if evalErr != nil {
		// Evaluation failures get returned as the function's error
		// so callers can decide whether to abort their workflow,
		// while the readable form still lives on tr.Error for
		// rendering. The earlier shape only captured the message
		// on tr.Error, so a downstream caller that ignored the
		// (TraceResult, nil) pair processed an inconclusive trace
		// as if it were definitive.
		tr.Error = fmt.Sprintf("CEL eval: %v", evalErr)
		return tr, evalErr
	}
	return tr, nil
}
