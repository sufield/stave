# Plan: Refactor cmd/diagnose/output.go

## Problem

Three issues in the Presenter:

1. **Presenter resolves output writer**: `RenderReport` and `RenderDetail`
   call `compose.ResolveStdout` internally to handle quiet mode. The
   Presenter should be a dumb pipe — the CLI layer should pass the
   already-resolved writer.

2. **Swallowed trace error**: `writeFindingDetailJSON` ignores
   `RenderJSON` errors (`if err == nil`). A failed trace is silently
   dropped, losing diagnostic information.

3. **Intermediate buffer for trace**: `bytes.Buffer` + `buf.Bytes()`
   allocates for every trace. A `json.Marshaler` wrapper would let
   the encoder pull bytes directly.

## Changes

### 1. Remove quiet resolution from Presenter

Remove `Quiet` field from `Presenter`. Caller passes the
already-resolved writer (or `io.Discard` for quiet mode).

```go
// Before
type Presenter struct {
    Stdout   io.Writer
    Format   ui.OutputFormat
    Quiet    bool       // REMOVE
    Template string
}
func (p *Presenter) RenderReport(report) {
    out := compose.ResolveStdout(p.Stdout, p.Quiet, "text")  // REMOVE

// After
type Presenter struct {
    W        io.Writer  // Already resolved for quiet
    Format   ui.OutputFormat
    Template string
}
func (p *Presenter) RenderReport(report) {
    // Uses p.W directly — no resolution needed
```

### 2. Propagate trace render error

```go
// Before
if err := detail.Trace.Raw.RenderJSON(&buf); err == nil {
    out.Trace = buf.Bytes()
}

// After
if err := detail.Trace.Raw.RenderJSON(&buf); err != nil {
    return fmt.Errorf("rendering trace JSON: %w", err)
}
out.Trace = buf.Bytes()
```

### 3. Custom json.Marshaler for trace (optional)

Create `jsonTrace` wrapper that implements `json.Marshaler`. The
encoder calls `MarshalJSON` lazily — only when it reaches the field.

```go
type jsonTrace struct{ trace *evaluation.Trace }

func (jt jsonTrace) MarshalJSON() ([]byte, error) {
    if jt.trace == nil || jt.trace.Raw == nil {
        return []byte("null"), nil
    }
    var buf bytes.Buffer
    if err := jt.trace.Raw.RenderJSON(&buf); err != nil {
        return nil, err
    }
    return buf.Bytes(), nil
}
```

### 4. Stream JSON with json.NewEncoder

Replace `jsonutil.WriteIndented(w, out)` with
`json.NewEncoder(w).Encode(out)` to stream directly to the writer.

## Files Changed

| File | Change |
|------|--------|
| `cmd/diagnose/output.go` | Remove Quiet, resolve writer in caller, error propagation, jsonTrace |
| `cmd/diagnose/runner.go` | Pass resolved writer to Presenter |

## Acceptance

- `Presenter` has no `Quiet` field
- `compose.ResolveStdout` not called inside Presenter
- Trace render errors propagated (not swallowed)
- `go test ./...` zero failures
- `make script-test` passes
