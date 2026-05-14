# Source-of-Truth Sync Audit

**Date:** 2026-05-13
**Iteration:** 2 — consistency gate landed (see [Iteration 2 status](#iteration-2-status))
**Derivation chains:** 8 (plus 1 publication chain)
**Sync-shaped Makefile targets:** 17 (16 original + `consistency-check`)
**CI-gated chains:** 8 of 8 (chains 5 and 6 covered by the new gate)
**Currently drifted:** 0

## Why this audit

When `make sync-controls` runs, it wipes `internal/controldata/embedded/*`
and re-copies from `controls/`. The embed tree is downstream — the source
of truth lives in `controls/`. Every doc, README, golden, and methodology
table on the repo is downstream of one or more of these canonical roots.

Each derivation chain has the same failure mode: the source moves, the
derived artifact does not, the repo ships stale documentation that
contradicts the embedded catalog. The question this audit answers is:
**for each chain, where is the source, where is the derived artifact, and
does CI catch drift before it lands.**

## The sync-shaped targets

| # | Target | Shape | Calls |
|---|--------|-------|-------|
| 1 | `sync-schemas` | embed copy | `rm -rf <embed>; cp -R schemas/* <embed>/` |
| 2 | `sync-controls` | embed copy | `rm -rf <embed>; cp -R controls/* <embed>/` |
| 3 | `sync-alternatives` | embed copy | `rm -rf <embed>; cp -R data/alternatives/* <embed>/` |
| 4 | `readme` | generate | `sync-controls` + `go run ./internal/tools/genreadme` |
| 5 | `readme-check` | verify | `sync-controls` + `go run ./internal/tools/genreadme -check` |
| 6 | `docs-controls` | generate | `sync-controls` + `go run ./internal/tools/gencontroldocs` |
| 7 | `docs-controls-check` | verify | `sync-controls` + `go run ./internal/tools/gencontroldocs -check` |
| 8 | `docs-coverage` | generate | `sync-controls sync-alternatives` + `go run ./internal/tools/genmethodologycoverage` |
| 9 | `docs-coverage-check` | verify | `sync-controls sync-alternatives` + `go run ./internal/tools/genmethodologycoverage -check` |
| 10 | `regenerate-goldens` | regen | `build` + `go run ./internal/tools/regengoldens $(ARGS)` |
| 11 | `regenerate-goldens-strict` | regen + verify | `regenerate-goldens verify-encoding-e2e` |
| 12 | `golden-update-all` | regen | `UPDATE_GOLDEN=1 go test -parallel 16 <all-pkgs-except-e2e>` |
| 13 | `golden-update PKG=…` | regen | `UPDATE_GOLDEN=1 go test $(PKG)` |
| 14 | `golden-one PKG=… RUN=…` | regen | `UPDATE_GOLDEN=1 go test $(PKG) -run '$(RUN)'` |
| 15 | `golden-fixture FILTER=…` | regen | `$(MAKE) regenerate-goldens ARGS='-filter $(FILTER)'` |
| 16 | `sync` | publish (not derive) | `rsync -av --delete ./ $(PUBLIC_DEST)` |

`sync` (16) is a different concept — it publishes the local repo into a
mirror directory. Not a derivation chain; included here only because it
shares the name shape and gets searched for when looking at sync logic.

## The eight derivation chains

| # | Source(s) | Tool | Derived artifact | Regen target | Verify target |
|---|-----------|------|------------------|--------------|---------------|
| 1 | `schemas/` | `cp -R` | `internal/contracts/schema/embedded/` | `sync-schemas` | (none — downstream tests fail) |
| 2 | `controls/` | `cp -R` | `internal/controldata/embedded/` | `sync-controls` | (none — downstream tests fail) |
| 3 | `data/alternatives/` | `cp -R` | `internal/adapters/coverage/embedded/` | `sync-alternatives` | (none — downstream tests fail) |
| 4 | `controls/*` + `internal/tools/genreadme/README.md.tmpl` | `genreadme` | `README.md` | `readme` | `readme-check` |
| 5 | embedded control catalog | `gencontroldocs` | `docs/controls/reference.md` | `docs-controls` | `docs-controls-check` |
| 6 | embedded control catalog + `data/alternatives/*.yaml` | `genmethodologycoverage` | `docs/methodology-coverage-{domain}-{tool}.md` (×2 today: iam-prowler, s3-prowler) | `docs-coverage` | `docs-coverage-check` |
| 7 | `testdata/e2e/<fixture>/*.json` + stave binary | `regengoldens` | `testdata/e2e/<fixture>/expected.*.json` + `golden.json` (5807 files) | `regenerate-goldens`, `golden-fixture` | `regenerate-goldens-strict` (via `verify-encoding-e2e`) |
| 8 | per-package test inputs + Go source | `go test -UPDATE_GOLDEN=1` | `testdata/<pkg>/*.golden` (in-process goldens) | `golden-update-all`, `golden-update`, `golden-one` | (none — verified by re-running tests without `UPDATE_GOLDEN`) |

The embed chains (1, 2, 3) have no dedicated verify step — drift between
the canonical and embedded copy surfaces as test failures because every
test target preconditions on the sync target. The remaining five chains
all have a dedicated `-check` mode that exits non-zero on drift.

## CI gating

| Chain | Gated by CI? | Workflow | Notes |
|---|---|---|---|
| 1 schemas → embed | Indirect | ci.yml (goldens, test-fast, test shards), codeql, coverage | Every job runs `sync-schemas` before testing, so any test using a schema file would have to fail loudly for drift to land |
| 2 controls → embed | Indirect | ci.yml (goldens, test-fast, test shards), codeql, coverage | Same as above |
| 3 alternatives → embed | Indirect | ci.yml (goldens, test-fast, test shards), coverage | Same as above |
| 4 README.md | **✓ Yes** | ci.yml `docs-freshness` job runs `make readme-check` | Live result: OK |
| 5 docs/controls/reference.md | **✗ NO** | (not invoked in any workflow) | Live result: OK today, but no CI gate |
| 6 methodology-coverage docs | **✗ NO** | (not invoked in any workflow) | **Live result: STALE — see drift section** |
| 7 testdata/e2e goldens | ✓ Yes | ci.yml `goldens` job + coverage.yml | Regenerates fresh per PR; uploaded as artifact |
| 8 in-process goldens | ✓ Yes | ci.yml `goldens` job + coverage.yml (`golden-update-all`) | Regenerates fresh per PR |
| 9 PUBLIC_DEST mirror | ✗ No (intentional) | (manual only) | Publication, not derivation |

Five of eight derivation chains are CI-gated. The two with no CI gate are
chains 5 and 6 — exactly the two doc-gen tools added without
corresponding workflow steps. Chain 4 (README) was added with a
`docs-freshness` job, but chain 5 and chain 6 were not extended into
that job.

## Live drift detection (2026-05-13)

```
$ make readme-check
OK: README.md is up to date

$ make docs-controls-check
go run ./internal/tools/gencontroldocs -check
(exit 0 — clean)

$ make docs-coverage-check
docs/methodology-coverage-iam-prowler.md is stale.
Run: go run ./internal/tools/genmethodologycoverage
exit status 1
```

**One drifted artifact:** `docs/methodology-coverage-iam-prowler.md`.
The companion `docs/methodology-coverage-s3-prowler.md` is clean — the
tool ran across both, only the iam-prowler view is stale.

The drift is plausible: chain 6 depends on the embedded control catalog,
which has expanded significantly since the methodology-coverage view
was last regenerated. Without `docs-coverage-check` in CI, every control
addition since that point has had the opportunity to drift this doc
without anyone noticing.

## Drift risk ranking

By probability of going stale × time-to-detection:

1. **`docs/methodology-coverage-*.md`** — HIGH. Two upstream sources
   (controls + alternatives), no CI gate, demonstrated drift on
   2026-05-13. Likely to drift again as new controls land.
2. **`docs/controls/reference.md`** — MEDIUM-HIGH. One upstream source
   (controls), no CI gate. Clean today, but the same gap that allowed
   chain 6 to drift would also allow chain 5 to drift on the next
   control addition that the author forgets to regenerate.
3. **`internal/*/embedded/` trees** — LOW. Every test target runs the
   sync as a prerequisite, so the embed is effectively rebuilt fresh in
   any CI run. Local builds without `sync-*` would be broken but would
   not silently ship stale embed content because the build target also
   depends on the sync.
4. **`testdata/e2e/<fixture>/expected.*` + `golden.json`** — LOW.
   `goldens` job regenerates per PR and uploads as an artifact; test
   shards download and compare.
5. **In-process `.golden` files** — LOW. `golden-update-all` runs in
   the `goldens` job; downstream tests fail if not regenerated.
6. **`README.md`** — LOW. `readme-check` runs in `docs-freshness`.

## Why this matters

Three observations beyond the table:

1. **The drift that landed is exactly the chain with no CI gate.** This
   is not a coincidence. The pattern of "add a doc-gen tool and forget
   to wire it into CI" has now occurred at least once (chain 6),
   probably more if you trace back through chain 5's history. The fix
   is small (two lines in the workflow), but the principle is the lesson.

2. **The embed-copy chains lean on test-failure as the detection
   mechanism.** This works in practice because every test target
   depends on `sync-*`, so the embed is rebuilt from canonical before
   any test reads it. But it means "you can never have a stale embed in
   a green build" only as long as that prereq stays in place. A future
   refactor that drops the prereq would silently invalidate the
   guarantee. Worth a property test that asserts `sync-controls` is a
   prerequisite of every test target that reads embedded controls.

3. **`docs-controls-check` and `docs-coverage-check` exist as targets**
   — the gencontroldocs and genmethodologycoverage tools both ship a
   `-check` mode. The bug is not "no detection mechanism." It is "the
   detection mechanism is not invoked by any workflow." A single PR
   could add both to the `docs-freshness` job.

## Recommendations (Iteration 2)

Iteration 2 is the consistency gate. The minimal change is to extend
`docs-freshness` to invoke the two missing checks:

```yaml
# .github/workflows/ci.yml — docs-freshness job
- name: Check control reference freshness
  run: make docs-controls-check
- name: Check methodology-coverage freshness
  run: make docs-coverage-check
```

That alone closes the two ungated chains and would have caught the
iam-prowler drift before it landed.

Beyond that minimal fix, two complementary ideas worth considering in
Iteration 2 but not strictly required:

- **A meta-check target** (`make docs-check`) that runs all `-check`
  variants in one invocation. Useful for local pre-commit. Cheap.
- **A property test** that asserts each `sync-*` target is a
  prerequisite of every test target that reads the corresponding
  embed. Catches the future refactor that drops the prereq.

## What Iteration 1 deliberately did not do

Per the original iteration scope:

1. No CI steps were added. The consistency gate was Iteration 2 (now landed).
2. No sync target's behavior was changed. The audit maps what exists.
3. The currently-drifted `docs/methodology-coverage-iam-prowler.md`
   was **not auto-fixed**. Fixing it without the CI gate first would
   guarantee it drifts again. The fix and the gate land together —
   they did, in Iteration 2.

## Iteration 2 status

Landed 2026-05-13. Three changes in one commit:

1. **`make consistency-check`** — new Makefile target. Runs every
   non-golden regen target (`sync-schemas`, `sync-controls`,
   `sync-alternatives`, `genreadme`, `gencontroldocs`,
   `genmethodologycoverage`) then `git status --porcelain` against the
   paths those targets write to. Non-empty diff = drift, exit 1 with
   the file list and the fix command.
2. **CI job: `Source-of-truth consistency`** — `.github/workflows/ci.yml`.
   Runs in parallel with `test`, `goldens`, and `docs-freshness`. No
   `needs:` dependency — a sync drift doesn't block test results.
3. **The drifted methodology-coverage doc was regenerated.** The gate
   passes on first run.

The check chosen over the simpler "add two more `-check` calls to
`docs-freshness`" alternative because regen + `git diff` is strictly
more powerful: it catches both forgotten regens **and** direct edits to
embedded files that bypass the canonical source. The per-tool `-check`
modes only catch the first failure mode.

Golden regen is deliberately excluded from the consistency gate. Golden
regen is slow (minutes), involves behavioral decisions (the diff is
expected output, not derived metadata), and already has a dedicated
pipeline. The consistency gate is for mechanical sync only.

`docs-freshness` was kept (still runs `readme-check`) as a fast, narrow
fallback. It's redundant with the new gate but cheap and stable.

## When to run sync targets (contributor checklist)

| You changed... | Run before committing |
|---|---|
| Any file in `controls/` | `make sync-controls` (or rely on the gate to regen) |
| Any schema file in `schemas/` | `make sync-schemas` |
| Any inventory in `data/alternatives/` | `make sync-alternatives` |
| Control count changed (add/remove) | `make readme` |
| Control metadata or YAML changed | `make docs-controls` |
| Methodology mapping changed | `make docs-coverage` |
| You're not sure | `make consistency-check` |

`make consistency-check` runs all of the above and verifies the tree
is clean. If it passes locally, the CI gate will pass.

### What happens if you forget

The `Source-of-truth consistency` CI job catches it. The PR shows:

```
ERROR: derived artifacts are out of sync with canonical sources.

Drifted files:
 M docs/controls/reference.md
 M internal/controldata/embedded/<your_changed_control>.yaml

Fix locally and commit the result:
  make consistency-check
  git add -u && git commit
```

Run the listed targets, commit the result, push.

## Appendix: Source-of-truth roots in the repo

For each chain, the canonical source — the file you edit when you want
the derived artifact to change:

| Chain | Canonical source |
|---|---|
| 1 | `schemas/*.json` |
| 2 | `controls/**/*.yaml` |
| 3 | `data/alternatives/*.yaml` |
| 4 | `controls/*` + `internal/tools/genreadme/README.md.tmpl` |
| 5 | `controls/*` (via the embedded catalog) |
| 6 | `controls/*` + `data/alternatives/*.yaml` (via the embedded catalog and alternatives) |
| 7 | `testdata/e2e/<fixture>/*.json` inputs + the stave binary behavior |
| 8 | per-package test inputs + Go source |

Edit the canonical source. Run the regen target. Verify the diff.
Commit both.
