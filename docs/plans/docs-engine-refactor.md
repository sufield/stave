# Plan: Refactor cmd/diagnose/docs/engine.go

## Problem

The docs search engine has performance and safety issues:

1. **Per-line string allocation**: `scanner.Text()` allocates a new
   string for every line. `strings.ToLower(line)` allocates another.
   For large doc sets this creates significant GC pressure.

2. **Integer subtraction in comparator**: `compareSearchHits` uses
   `b.Score - a.Score` which can overflow on extreme values. Should
   use `cmp.Compare`.

3. **Sequential file search**: Files are searched one at a time. With
   100+ doc files, this is unnecessarily slow.

4. **No context cancellation**: `searchReader` has no way to stop early
   on SIGINT or timeout.

## Changes

### 1. Byte-based scoring (zero-allocation hot path)

Convert `scoreLine` and `searchReader` to work with `[]byte` instead
of `string`. Use `scanner.Bytes()` (zero-alloc) instead of
`scanner.Text()` (alloc per line). Only convert to string when a
hit is found.

```go
// Before
line := scanner.Text()                    // alloc
lineCmp := strings.ToLower(line)          // alloc
score := scoreLine(line, phrase, tokens, caseSensitive)

// After
line := scanner.Bytes()                   // zero alloc
score := scoreLine(line, phrase, tokens, caseSensitive)
if score > 0 {
    snippet := trimSnippet(string(line))  // alloc only on hit
}
```

**Functions changed:**
- `tokenizeQuery` → `tokenizeQueryBytes` returns `([][]byte, []byte)`
- `scoreLine` takes `[]byte` params, uses `bytes.Contains`/`bytes.Count`
- `scorePath` takes `[]byte` tokens
- `searchReader` uses `scanner.Bytes()`

### 2. Fix comparator with `cmp.Compare`

```go
// Before
func compareSearchHits(a, b SearchHit) int {
    if a.Score != b.Score {
        return b.Score - a.Score  // potential overflow
    }

// After
func compareSearchHits(a, b SearchHit) int {
    if n := cmp.Compare(b.Score, a.Score); n != 0 {
        return n
    }
```

### 3. Add context parameter for cancellation

Add `context.Context` as first parameter to `searchDocsFiles`,
`searchSingleFile`, and `searchReader`. Check `ctx.Err()` every
line in the scanner loop.

```go
func searchReader(ctx context.Context, r io.Reader, ...) ([]SearchHit, error) {
    for scanner.Scan() {
        if err := ctx.Err(); err != nil {
            return nil, err
        }
        // ...
    }
}
```

**Caller update:** `open.go:59` passes `context.Background()` or
the command's context.

### 4. Concurrent file search (optional, phase 2)

NOT in this plan. The doc set is small (~60 files) and the byte-based
optimization will make sequential search fast enough. Concurrency
adds complexity (errgroup, mutex) for minimal gain on this workload.
Revisit if doc count exceeds 500.

## Files Changed

| File | Change |
|------|--------|
| `cmd/diagnose/docs/engine.go` | Byte-based scoring, context param, cmp.Compare |
| `cmd/diagnose/docs/open.go` | Pass context to searchDocsFiles |
| `cmd/diagnose/docs/search.go` | Pass context to searchDocsFiles (if called directly) |

## What NOT to Change

- **No errgroup concurrency**: Doc set is ~60 files. Sequential with
  byte-based scoring is fast enough. Avoids sync.Mutex complexity.
- **No `io.LimitReader`**: Doc files are trusted local files, not
  user-uploaded content.
- **No `bufio.Reader.ReadLine`**: Scanner with 2MB buffer is adequate
  for markdown files.

## Acceptance

- `scoreLine` takes `[]byte`, not `string`
- `scanner.Bytes()` used instead of `scanner.Text()`
- `compareSearchHits` uses `cmp.Compare`
- `searchReader` accepts `context.Context`
- `go build ./...` clean
- `go test ./...` zero failures
- `make script-test` passes (docs search testscript)
