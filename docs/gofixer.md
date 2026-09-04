# Go Modernization & Dead-Code Cleanup (`gofixer`)

Referenced by `CONTRIBUTING.md`. Run this before opening a PR so new code
ships in the project's current idioms and leaves no dead code behind.

The whole workflow is one target:

```bash
cd stave && make gofixer
```

It is also wired into `make check`-style hygiene; run it explicitly when
you've added or refactored Go code.

## What it does

`make gofixer` runs these steps in order (see the `gofixer` target in the
`Makefile`):

1. **Preview** — `go fix -diff ./...` prints the modernizations that would
   be applied. (See the note below: this step exits non-zero when there
   *are* diffs — that is expected, not a failure.)
2. **Apply default modernizers** — `go fix ./...`.
3. **Cross-platform passes** — `go fix ./...` under `GOOS=linux/amd64`,
   `darwin/arm64`, and `windows/amd64`, so build-tagged files for every
   target platform get modernized too, not just the host's.
4. **`new(expr)` modernizer** — `go fix -newexpr ./...`.
5. **Final pass** — `go fix ./...` to settle any follow-on rewrites.
6. **Dead-code detection** — `deadcode -test ./...` (install:
   `go install golang.org/x/tools/cmd/deadcode@latest`).
7. **Validation** — `goimports -w` over all non-vendored `*.go`, then
   `make lint` and `go test ./...`.

## Typical modernizations applied

These are tool-driven and behavior-preserving — review the diff, but they
are safe:

- `for i := 0; i < n; i++ {` → `for i := range n {`
- linear-search helper loops → `slices.Contains(...)`
- `sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })` → `slices.Sort(s)`
- `new(expr)` where Go 1.26+ allows it

## A gotcha: `make gofixer` "Error 1" is usually benign

Step 1 (`go fix -diff`) returns a **non-zero exit code whenever there are
diffs to show** — it behaves like a check/preview, not an applier. So a
fresh `make gofixer` on a tree with pending modernizations prints the
diff and then reports `make: *** [gofixer] Error 1`. That is the preview
step reporting "there is work to do," not a real failure. The apply steps
(2–5) then make the changes. Re-run `make gofixer` after they apply: once
the tree is modern, step 1 has nothing to show and the target is green.

If you want a clean exit in one shot, run the apply steps directly:

```bash
go fix ./... && go fix -newexpr ./... && go fix ./...
goimports -w $(find . -name '*.go' -not -path './vendor/*')
make lint && go test ./...
```

## Before you commit

- Review the diff — modernizations should be mechanical; anything that
  looks like a behavior change is a bug, not a modernization.
- `make lint` must be **0 issues** and the affected packages' tests must
  pass (the target runs both).
- Commit the modernizations as their own `chore:` change when they are
  unrelated to your feature, so the PR diff stays readable.
