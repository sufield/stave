.PHONY: all build build-dev test test-fast test-integration test-e2e test-ci test-coverage test-compliance cover-report clean-cover lint lint-fix lint-debt fmt vet tidy clean install run run-now check ci e2e determinism reproduce-release release-local release-check release help sync-schemas sync-controls sync-alternatives sync-skills gofixer imports imports-check sync-public fuzz bench docker-demo demo-check verify-encoding-demos verify-encoding-controls verify-encoding-e2e regenerate-goldens-strict regenerate-goldens docs-controls docs-controls-check docs-commands docs-commands-check docs-commands-catalog docs-commands-catalog-check docs-site docs-site-check sync-guide docs-coverage docs-coverage-check metrics docs-datalog docs-datalog-check golden-update-all golden-update golden-one golden-fixture attack-stage-check domain-check mcp mcp-test deadcode-check refactor-scan refactor-scan-check refactor-scan-update triage quarterly-audit quarterly-save compliance-diff
# Binary name
BINARY=stave

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOTEST=$(GOCMD) test
GOFMT=$(GOCMD) fmt
GOVET=$(GOCMD) vet
GOMOD=$(GOCMD) mod
GOLINT_LOCAL=$(shell $(GOCMD) env GOPATH)/bin/golangci-lint
GOLINT=$(if $(wildcard $(GOLINT_LOCAL)),$(GOLINT_LOCAL),golangci-lint)

# Schema sync (contracts source → embedded runtime copy)
SCHEMA_SRC=schemas
SCHEMA_DST=internal/contracts/schema/embedded

# Control sync (canonical controls → embedded runtime copy)
CONTROL_SRC=controls
CONTROL_DST=internal/controldata/embedded

# Alternatives inventory sync (canonical inventories → embedded runtime copy)
ALTERNATIVES_SRC=data/alternatives
ALTERNATIVES_DST=internal/adapters/coverage/embedded

# Version from VERSION file
VERSION=$(shell cat VERSION)

# Go version from go.mod (single source of truth for CI, Dockerfile, etc.)
GO_VERSION=$(shell grep '^toolchain' go.mod | sed 's/toolchain go//')

# Build flags
LDFLAGS=-ldflags "-s -w -X github.com/sufield/stave/internal/version.String=$(VERSION)"

# Default target
all: lint test build

## Sync targets are content-hash-gated for the local dev loop: each
## hashes its source tree and skips the rm/cp when the hash matches a
## cached value AND the destination still exists. CI's clean checkouts
## have no cache file, so they re-sync every time — correctness is
## unchanged; only the no-op work on repeated local runs is removed.
## The hash files (.sync-*-hash) are gitignored — local cache only.
##
## The hash covers file content AND tree structure: every file in the
## source is hashed under its path-sorted order, then those lines are
## hashed once more. A rename or a one-byte content change invalidates
## the cache and triggers a re-sync.

SCHEMA_HASH_FILE       := .sync-schemas-hash
CONTROL_HASH_FILE      := .sync-controls-hash
ALTERNATIVES_HASH_FILE := .sync-alternatives-hash

## sync_tree: single source for the three identical embed-copy targets.
##
## $(call sync_tree,<target>,<label>,<src>,<dst>,<hashfile>) defines a
## hash-gated copy target: hash the source tree; skip the rm/cp when the
## hash matches the cached value and the destination still exists;
## otherwise wipe and re-copy. The embedded trees are committed copies of
## canonical sources that live ABOVE the embedding package — go:embed
## cannot reach a parent directory (`..`), so the copy is structural, not
## accidental. See docs/audits/sync-audit.md ("Why a copy, not a direct
## embed"). Drift is caught by `make consistency-check` in CI.
define sync_tree
$(1):
	@new_hash=$$$$(find $(3) -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum | sha256sum | cut -d' ' -f1); \
	if [ -f $(5) ] && [ "$$$$(cat $(5))" = "$$$$new_hash" ] && [ -d $(4) ]; then \
	  echo "$(2) unchanged ($$$$new_hash) — skipping sync"; \
	else \
	  mkdir -p $(4); \
	  rm -rf $(4)/*; \
	  cp -R $(3)/* $(4)/; \
	  echo "$$$$new_hash" > $(5); \
	  echo "$(2) synced ($$$$new_hash)"; \
	fi
endef

## sync-schemas: Copy canonical schemas into embed directory (hash-gated)
$(eval $(call sync_tree,sync-schemas,schemas,$(SCHEMA_SRC),$(SCHEMA_DST),$(SCHEMA_HASH_FILE)))
## sync-controls: Copy canonical controls into embed directory (hash-gated)
$(eval $(call sync_tree,sync-controls,controls,$(CONTROL_SRC),$(CONTROL_DST),$(CONTROL_HASH_FILE)))
## sync-alternatives: Copy canonical alternative-tool inventories into embed directory (hash-gated)
$(eval $(call sync_tree,sync-alternatives,alternatives,$(ALTERNATIVES_SRC),$(ALTERNATIVES_DST),$(ALTERNATIVES_HASH_FILE)))

## build: Build the production binary
build: sync-schemas sync-controls sync-alternatives
	$(GOBUILD) $(LDFLAGS) -o $(BINARY) ./cmd/stave

## build-dev: Build the dev binary with all commands
build-dev: sync-schemas sync-controls sync-alternatives
	$(GOBUILD) $(LDFLAGS) -tags stavedev -o stave-dev ./cmd/stave-dev

## mcp: Build the MCP server binary (stave-mcp)
mcp: sync-schemas sync-controls sync-alternatives
	$(GOBUILD) $(LDFLAGS) -o stave-mcp ./cmd/mcp

## mcp-test: Run the MCP server's protocol validation tests
mcp-test: sync-schemas sync-controls sync-alternatives
	$(GOTEST) ./cmd/mcp/ -count=1

## Testing pyramid:
##
##   test-fast        sub-minute dev iteration (`-short`, no binary spawn).
##   test-integration internal/ tests that load fixtures but do not spawn
##                    the stave binary; targets the middle tier.
##   test-e2e         binary-driven E2E (./e2e and testscript). Slowest.
##   test             everything, including E2E and golden suites.
##   test-ci          regenerate goldens then run the full `test` target.
##
## Reach for `make test-fast` while iterating on a single change. Promote
## to `make test-integration` before opening a PR. CI runs the full
## `test-ci` target as a final gate.
##
## test: Run all tests with race detector (includes dev-only packages via build tag)
##
## Assumes goldens are current. Use `make test-ci` for CI runs that
## regenerate goldens fresh, or `make test-fast` for the fast dev loop.
##
## -timeout 30m mirrors what the prior CI workflow used. The default 10m
## is not enough once -race plus the binary-driven ./e2e suite are in scope.
##
## -parallel 16 caps in-package t.Parallel() concurrency. Golden / e2e
## tests are I/O-bound (forking the stave binary, reading observation
## fixtures, comparing JSON), so over-subscribing GOMAXPROCS hides
## per-test latency rather than CPU work. Race-enabled binaries do extra
## bookkeeping per goroutine but the I/O wait dominates.
test: sync-schemas sync-controls sync-alternatives
	$(GOTEST) -tags stavedev -race -v -timeout 30m -parallel 16 ./...

## test-fast: Sub-minute dev feedback loop.
##
## Passes -short so any test that gates on testing.Short() (e2e,
## profile, fixture-binary determinism) self-skips. Designed to
## finish under 30 seconds so adding a control does not pay a
## 2000+ golden-regeneration tax on the dev machine.
test-fast: sync-schemas sync-controls sync-alternatives
	$(GOTEST) -short -timeout 5m ./...

## test-pkg PKG=...: Path-aware fast-test for the package(s) currently
## being changed. Skips sync-schemas / sync-controls / sync-alternatives
## because those only affect the embedded catalog packages — every
## other package can run without re-syncing. Pass the package selector
## verbatim:
##
##   make test-pkg PKG=./cmd/apply/...
##   make test-pkg PKG=./internal/core/evaluation/...
##   make test-pkg PKG=./cmd/gaps/...
##
## Use this in the pre-PR loop after a focused change. If the change
## touches controls/ or schemas/, fall back to `make test-unit`.
test-pkg:
	@if [ -z "$(PKG)" ]; then \
		echo "Usage: make test-pkg PKG=./path/to/pkg/..."; exit 2; \
	fi
	@case "$(PKG)" in \
		*controldata*|*contracts/schema*|*adapters/coverage*) \
			for h in .sync-controls-hash .sync-schemas-hash .sync-alternatives-hash; do \
				if [ ! -f "$$h" ]; then \
					echo "WARNING: $$h missing — embedded data may be stale. Run 'make sync-controls sync-schemas sync-alternatives' first." >&2; \
					break; \
				fi; \
			done ;; \
	esac
	$(GOTEST) -short -timeout 5m $(PKG)

## test-shard SHARD=N: Run the same package set as CI shard N (0-3).
## Reproduces a CI shard failure locally without copy-pasting filters
## from .github/workflows/ci.yml.
##
##   make test-shard SHARD=0   # enginetest (heaviest, ~383s)
##   make test-shard SHARD=1   # cmd/stave + graph + cel (~351s)
##   make test-shard SHARD=2   # controls/builtin + pack + pkg/stave + cmd/apply (~255s)
##   make test-shard SHARD=3   # everything else (~150 packages)
SHARD_FILTER_0 = internal/core/enginetest$$
SHARD_FILTER_1 = (cmd/stave|internal/graph|internal/cel)$$
SHARD_FILTER_2 = (internal/adapters/controls/builtin|internal/builtin/pack|pkg/stave)$$|cmd/apply
test-shard: sync-schemas sync-controls sync-alternatives
	@if [ -z "$(SHARD)" ]; then \
		echo "Usage: make test-shard SHARD=0|1|2|3"; exit 2; \
	fi
	@all_pkgs=$$($(GOCMD) list ./... | grep -vE '/e2e$$'); \
	case "$(SHARD)" in \
		0) pkgs=$$(echo "$$all_pkgs" | grep -E '$(SHARD_FILTER_0)') ;; \
		1) pkgs=$$(echo "$$all_pkgs" | grep -E '$(SHARD_FILTER_1)') ;; \
		2) pkgs=$$(echo "$$all_pkgs" | grep -E '$(SHARD_FILTER_2)') ;; \
		3) pkgs=$$(echo "$$all_pkgs" | grep -vE '$(SHARD_FILTER_0)|$(SHARD_FILTER_1)|$(SHARD_FILTER_2)') ;; \
		*) echo "Invalid SHARD=$(SHARD); use 0-3"; exit 2 ;; \
	esac; \
	echo "Shard $(SHARD): $$(echo "$$pkgs" | wc -l) packages"; \
	$(GOTEST) -timeout 30m $$pkgs

## test-integration: Fixture-loading tests that don't spawn the binary.
##
## ./internal/... covers fixture-loaders, evaluation engine,
## adapters, and graph builders. Does NOT pass -short, so heavier
## table-driven tests run, but does not include ./e2e or
## ./cmd/stave (testscript fixtures spawn the binary).
test-integration: sync-schemas sync-controls sync-alternatives
	$(GOTEST) -timeout 15m ./internal/... ./cmd/apply/... ./cmd/evaluate/...

## test-e2e: Binary-driven E2E tests only.
##
## Builds the stave binary and runs it against fixture inputs.
## ./e2e holds the cross-cutting golden suite; cmd/stave hosts
## testscript fixtures. Slowest tier; expect minutes, not seconds.
test-e2e: build sync-schemas sync-controls sync-alternatives
	$(GOTEST) -timeout 30m ./e2e/... ./cmd/stave/... ./cmd/apply/...

## test-ci: CI entry point — regenerate goldens fresh, then run the full suite
##
## Goldens are regenerated in the CI workspace and discarded when the job
## ends; nothing is committed back. Catalog growth that only churns
## fingerprints is therefore invisible to PR diffs and never blocks a dev
## machine. Two regen passes cover both golden families: regenerate-goldens
## handles the testdata/e2e fixture goldens, and golden-update-all handles
## the in-process goldens driven by UPDATE_GOLDEN=1. The downstream `test`
## target adds -parallel 16 so in-package t.Parallel() golden subtests
## actually overlap on CI runners (default GOMAXPROCS on small runners
## is 2–4, which is too low for I/O-bound golden tests).
test-ci: regenerate-goldens golden-update-all test

## test-coverage: Run tests with coverage
test-coverage:
	$(GOTEST) -v -cover -coverprofile=coverage.out ./...
	$(GOCMD) tool cover -html=coverage.out -o coverage.html

## test-compliance: Run metadata linter + testscript with global coverage
test-compliance: sync-schemas sync-controls sync-alternatives
	@echo "==> Running Compliance & Integration Tests..."
	$(GOTEST) -coverprofile=compliance-coverage.out -coverpkg=./... ./cmd/ ./cmd/stave/
	@echo ""
	@echo "==> Coverage Summary:"
	@$(GOCMD) tool cover -func=compliance-coverage.out | grep total | awk '{print "Compliance Test Coverage: " $$3}'

## cover-report: Generate HTML coverage report from compliance tests
cover-report: test-compliance
	@echo "==> Generating HTML report..."
	$(GOCMD) tool cover -html=compliance-coverage.out -o compliance-coverage.html
	@echo "Done: compliance-coverage.html"

## clean-cover: Remove coverage files
clean-cover:
	rm -f coverage.out coverage.html compliance-coverage.out compliance-coverage.html

## script-test: Run testscript behavioral CLI tests
script-test: sync-schemas sync-controls sync-alternatives
	$(GOTEST) ./cmd/stave/ -run TestScripts -count=1

## clig-check: Verify CLI commands follow clig.dev guidelines
clig-check:
	$(GOTEST) ./cmd/ -run "TestCligCompliance|TestCligGlobalFlags" -count=1

## parallelize: Insert t.Parallel() into every Test* in PKG=<dir>
## (skips files that touch t.Setenv / os.Setenv / os.Chdir).
## Used to roll out parallelism to a new hot package; see commit
## 4c7170cf0 for the original 6-package rollout (10.6× speedup
## on enginetest).
parallelize:
	@if [ -z "$(PKG)" ]; then \
		echo "usage: make parallelize PKG=<directory>"; \
		exit 2; \
	fi
	bash scripts/add-parallel.sh $(PKG)

## lint: Run golangci-lint (v2.8.0)
lint:
	$(GOLINT) run ./...

## lint-fix: Auto-format code (gofmt only — most lint issues require manual fixes)
lint-fix:
	$(GOFMT) ./...

## lint-debt: Burn-down metric for grandfathered wrapcheck violations.
##
## Background: wrapcheck is enforced only in internal/core/evaluation/engine/
## today (see .golangci.yml + docs/audits/lint-wrapcheck-rollout.md). The rest
## of the codebase carries grandfathered violations. This target MEASURES that
## debt and ratchets it: the count may only go down, never up.
##
## It derives the measurement config from the canonical .golangci.yml at
## runtime (dropping the wrapcheck path-except rule) so there is no committed
## duplicate config to drift. The committed baseline is docs/audits/lint-debt-baseline.
##
## CI fails if debt grew (new boundary error left unwrapped). When debt drops,
## it prints the command to lower the baseline so the ratchet tightens.
LINT_DEBT_BASELINE := docs/audits/lint-debt-baseline
lint-debt:
	@cfg=$$(mktemp --suffix=.yml); \
	awk '/- linters: \[wrapcheck\]/{skip=2} skip>0{skip--;next} {print}' .golangci.yml > "$$cfg"; \
	count=$$($(GOLINT) run -c "$$cfg" --enable-only=wrapcheck ./... 2>/dev/null | grep -c '(wrapcheck)'); \
	rm -f "$$cfg"; \
	baseline=$$(cat $(LINT_DEBT_BASELINE)); \
	echo "wrapcheck debt: $$count  (baseline ceiling: $$baseline)"; \
	if [ "$$count" -gt "$$baseline" ]; then \
		echo "ERROR: wrapcheck debt grew ($$baseline -> $$count)."; \
		echo "  Wrap the new boundary error(s) with fmt.Errorf(\"...: %w\", err),"; \
		echo "  or if you fixed a package, widen the .golangci.yml path-except allow-list."; \
		exit 1; \
	elif [ "$$count" -lt "$$baseline" ]; then \
		echo "Debt decreased — ratchet it down by committing the new floor:"; \
		echo "  echo $$count > $(LINT_DEBT_BASELINE)"; \
	else \
		echo "No change. Debt holds at the baseline ceiling."; \
	fi

## refactor-scan: list remaining Go modernization candidates per category.
## Ratcheted categories (genuine targets) show full file:line lists; wide nets
## show counts only. See scripts/refactor-scan.sh + docs/audits/refactor-scan-plan.md.
refactor-scan:
	@bash scripts/refactor-scan.sh list

## refactor-scan-check: burn-down gate — fail if any ratcheted candidate count
## grew above docs/audits/refactor-scan-baseline. Pairs with refactor-scan-update.
refactor-scan-check:
	@bash scripts/refactor-scan.sh check

## refactor-scan-update: rewrite the ratcheted baseline to current counts; commit
## it to tighten the ratchet when candidates drop (mirrors the lint-debt floor).
refactor-scan-update:
	@bash scripts/refactor-scan.sh update-baseline

## audit: Generate the report-only Go best-practices baseline (docs/audits/go-best-practices-baseline.{md,json}).
## audit-check: Verify the committed baseline matches current source (manual; NOT in CI — churn is per-commit volatile).
##
## Report-only and advisory — gates nothing. Detectors: .golangci.audit.yml
## (interfacebloat / gochecknoglobals / gochecknoinits / forbidigo) +
## internal/tools/goroutinescan; aggregated by internal/tools/auditreport.
# Design: docs/superpowers/specs/2026-06-13-go-best-practices-audit-design.md.
.PHONY: audit audit-check
audit: AUDIT_CHECK :=
audit-check: AUDIT_CHECK := -check
audit audit-check:
	@set -e; tmp=$$(mktemp -d); trap 'rm -rf "$$tmp"' EXIT; \
	$(GOLINT) config verify -c .golangci.audit.yml; \
	$(GOLINT) run -c .golangci.audit.yml --output.json.path stdout --show-stats=false --issues-exit-code 0 ./... > "$$tmp/lint.json"; \
	$(GOCMD) run ./internal/tools/goroutinescan -root . > "$$tmp/goroutines.json"; \
	git log --format= --name-only --relative -- '*.go' | grep -v _test.go | sort | uniq -c | sort -rn > "$$tmp/churn.txt"; \
	$(GOCMD) run ./internal/tools/auditreport \
		-lint "$$tmp/lint.json" -goroutines "$$tmp/goroutines.json" -churn "$$tmp/churn.txt" \
		-out docs/audits/go-best-practices-baseline.md \
		-json docs/audits/go-best-practices-baseline.json \
		-now "$$(git log -1 --format=%cI)" -commit "$$(git rev-parse --short HEAD)" $(AUDIT_CHECK) $(ARGS)

## fmt: Format code
fmt:
	$(GOFMT) ./...

## vet: Run go vet
vet:
	$(GOVET) ./...

## tidy: Tidy dependencies
tidy:
	$(GOMOD) tidy

## clean: Remove build artifacts
clean:
	rm -f $(BINARY) stave-dev
	rm -rf bin/
	rm -f coverage.out coverage.html
	rm -rf $(SCHEMA_DST)/*

## install: Install binary to GOPATH/bin
install:
	$(GOCMD) install ./cmd/stave

## run: Run with default fixtures
run: build
	./$(BINARY) apply --controls examples/public-bucket/controls --observations examples/public-bucket/observations --max-unsafe 168h

## run-now: Run with fixed time for deterministic output
run-now: build
	./$(BINARY) apply --controls examples/public-bucket/controls --observations examples/public-bucket/observations --max-unsafe 168h --now 2026-01-11T00:00:00Z

## stale-terminology-check: Fail if active source/doc files reference
## architectural terms that have been renamed. Cheap drift gate.
##
## The package map moved from `internal/domain/...` to
## `internal/core/...` long ago, but stale references keep reappearing
## in docs and test comments. This target greps for the old name in
## files that ship to users / contributors (docs, root markdown, Go
## source). It excludes:
##   - MEMORY.md (Claude's auto-memory, may carry historical context)
##   - testdata/ (e2e justify.md files are point-in-time evidence)
##   - vendor/, node_modules/, .git/
## A clean run means no stale terminology in any file a contributor
## would read while onboarding.
stale-terminology-check:
	@bad=$$(grep -rln "internal/domain" \
		--include='*.go' --include='*.md' \
		--exclude-dir=vendor --exclude-dir=node_modules \
		--exclude-dir=.git --exclude-dir=testdata \
		--exclude=MEMORY.md \
		. 2>/dev/null); \
	if [ -n "$$bad" ]; then \
		echo "Stale 'internal/domain' references (renamed to 'internal/core'):"; \
		echo "$$bad" | sed 's/^/  /'; \
		exit 1; \
	fi

## deadcode-check: Fail on unreachable exported functions (whole-program analysis)
##
## Known false positive: byteReader.Read in cel/persist.go implements io.Reader
## via interface satisfaction (var _ io.Reader = (*byteReader)(nil)); deadcode
## can't trace implicit interface dispatch.
deadcode-check:
	@echo "==> Dead code check..."
	@out=$$(deadcode -test ./... 2>&1 | grep -v "byteReader.Read"); \
	if [ -n "$$out" ]; then \
		echo "deadcode found unreachable functions:"; \
		echo "$$out"; \
		exit 1; \
	fi

## check-unsafe-writes: Forbid raw os.Create/os.WriteFile on user-controlled
## output paths in cmd/ and internal/app/. These must use the symlink-safe
## fsutil.SafeCreateFile / fsutil.SafeWriteFile wrappers (internal/platform/fsutil)
## to close the symlink/hardlink/TOCTOU redirect window. Scoped by grep because
## forbidigo cannot express "forbid in these dirs only" (RE2 has no negative
## lookahead) without flagging legitimate writes elsewhere in the tree.
## Excludes _test.go (test fixtures) and cmd/mcp (writes self-generated
## os.TempDir() files, not user paths, and is pkg/stave-only by design).
.PHONY: check-unsafe-writes
check-unsafe-writes:
	@hits=$$(grep -rnE 'os\.(Create|WriteFile)\(' cmd/ internal/app/ --include='*.go' \
		| grep -v '_test\.go' \
		| grep -v 'cmd/mcp/'); \
	if [ -n "$$hits" ]; then \
		echo "ERROR: use fsutil.SafeWriteFile/SafeCreateFile (symlink-safe) instead of os.Create/os.WriteFile:"; \
		echo "$$hits"; \
		exit 1; \
	fi; \
	echo "OK: no unsafe os.Create/os.WriteFile on user paths in cmd/ or internal/app/"

## check: Run all checks (fmt, vet, lint, terminology, deadcode, test)
check: fmt vet lint stale-terminology-check check-unsafe-writes deadcode-check test

## semantic-diff: Run CEL vs reference differential on S3 controls + iam_condition_bypass chain
## Use ARGS for additional flags: make semantic-diff ARGS="-symbolic -v"
semantic-diff: sync-controls
	$(GOCMD) run ./internal/tools/semantic-diff $(ARGS)

## chain-discover: Datalog reachability + Z3 chain discovery
## Discovers attack chains not covered by existing chain YAMLs.
## Use ARGS for flags: make chain-discover ARGS="-snapshot observations/ -query escalation"
chain-discover: build
	$(GOCMD) run ./reasoning/souffle/discovery/main.go ./reasoning/souffle/discovery/dedup.go ./reasoning/souffle/discovery/report.go $(ARGS)

## ci: CI pipeline (tidy, check, build)
ci: tidy check build

## regenerate-goldens: Batch-regenerate all fixture goldens and report a categorized diff
##
## After changes that affect control YAML (metadata edits, predicate edits,
## new/removed controls), run this target once. The tool writes updated
## goldens across every fixture shape (expected.out.json, expected.summary.json,
## expected.findings.count, expected.exit, profile golden.json, etc.) and
## emits a report bucketed as CLEAN / FINGERPRINT-ONLY / METADATA-ONLY /
## BEHAVIORAL / MIXED so you can tell metadata churn apart from detection
## changes before committing.
##
## Safe-to-commit categories: CLEAN, FINGERPRINT-ONLY, METADATA-ONLY.
## Investigate before committing: BEHAVIORAL, MIXED.
##
## Flags (pass via ARGS):
##   ARGS="-dry-run"             preview diffs without writing
##   ARGS="-filter pattern"      limit to fixture names matching regex
##   ARGS="-fail-on-behavioral"  exit non-zero on BEHAVIORAL/MIXED/ERROR
##                               (CI gate; CLEAN/FINGERPRINT-ONLY/METADATA-ONLY
##                                still flow through silently)
regenerate-goldens: build
	$(GOCMD) run ./internal/tools/regengoldens $(ARGS)

## regenerate-goldens-ci: Regenerate and fail loudly on behavioral diffs
##
## What CI uses: rewrites all benign goldens (CLEAN / FINGERPRINT-ONLY /
## METADATA-ONLY) silently, exits non-zero (3) if any fixture lands in
## BEHAVIORAL / MIXED / ERROR. PRs see noise only when there's a real
## detection-behavior change to review — the categorized-diff that's
## already running just got an exit code that gates CI on it.
##
## Local equivalent: `make regenerate-goldens ARGS="-fail-on-behavioral"`
.PHONY: regenerate-goldens-ci
regenerate-goldens-ci: build
	$(GOCMD) run ./internal/tools/regengoldens -fail-on-behavioral $(ARGS)

## --- Targeted golden regeneration ---------------------------------------
##
## Two mechanisms, picked by which kind of golden you are updating:
##
## 1. In-process goldens (a small set of files under internal/.../testdata/)
##    are regenerated by setting UPDATE_GOLDEN=1 on `go test`. Use
##    `golden-update`, `golden-update-all`, or `golden-one` below.
##
## 2. The 5807 testdata/e2e fixture goldens (expected.* + golden.json) are
##    regenerated by the regengoldens tool. Use `golden-fixture FILTER=...`
##    for a friendlier name on top of `regenerate-goldens ARGS='-filter ...'`.

## golden-update-all: Regenerate every in-process golden in the repo
##
## Equivalent to `UPDATE_GOLDEN=1 go test ./...` but writes only changed files
## (writeGoldenIfChanged in internal/testutil keeps mtimes stable on no-ops).
##
## Excludes ./e2e because that package's testdata/e2e fixture goldens are
## regenerated by the regengoldens tool (see `regenerate-goldens`), not by
## UPDATE_GOLDEN. Including ./e2e here re-runs the full binary-driven E2E
## suite under the default 10-minute go test timeout and reliably trips it.
## Each in-process golden test writes to its own unique path
## (testdata/<package>/<fixture>.golden), so parallel writes don't
## collide. -parallel 16 lets subtests overlap during regeneration.
.PHONY: golden-update-all
golden-update-all:
	UPDATE_GOLDEN=1 $(GOCMD) test -parallel 16 $(shell $(GOCMD) list ./... | grep -vE '^github\.com/sufield/stave/e2e$$')

## golden-update: Regenerate in-process goldens for one package
##
## Usage: make golden-update PKG=./internal/profile/reporter/...
.PHONY: golden-update
golden-update:
	@test -n "$(PKG)" || (echo "Usage: make golden-update PKG=./path/to/pkg/..." && exit 1)
	UPDATE_GOLDEN=1 $(GOCMD) test $(PKG)

## golden-one: Regenerate a single in-process golden test
##
## Usage: make golden-one PKG=./internal/profile/reporter RUN=TestTextReporter_Golden
.PHONY: golden-one
golden-one:
	@test -n "$(PKG)" || (echo "Usage: make golden-one PKG=./path/to/pkg RUN=TestName" && exit 1)
	@test -n "$(RUN)" || (echo "Usage: make golden-one PKG=./path/to/pkg RUN=TestName" && exit 1)
	UPDATE_GOLDEN=1 $(GOCMD) test $(PKG) -run '$(RUN)'

## golden-fixture: Regenerate testdata/e2e fixture goldens matching a regex
##
## Friendlier wrapper around `regenerate-goldens ARGS='-filter <regex>'` for
## the 5807 fixture goldens that are produced by running the stave binary
## per fixture (not by go test).
##
## Usage: make golden-fixture FILTER=hipaa
##        make golden-fixture FILTER='ec2-keypair'
.PHONY: golden-fixture
golden-fixture:
	@test -n "$(FILTER)" || (echo "Usage: make golden-fixture FILTER=<regex>" && exit 1)
	$(MAKE) regenerate-goldens ARGS='-filter $(FILTER)'

## e2e: Run end-to-end tests
##
## -timeout 30m: the full TestE2E fixture loop spawns the stave binary
## per fixture across thousands of fixtures and reliably trips the
## default 10-minute go test timeout. Matches test / test-e2e.
e2e: build
	go test ./e2e/ -run E2E -count=1 -timeout 30m

## determinism: Verify apply --profile aws-s3 output is deterministic (run twice, diff)
determinism: build
	@echo "Determinism check: running apply --profile aws-s3 twice on golden-path fixture..."
	@./$(BINARY) apply --profile aws-s3 \
		--input testdata/e2e/e2e-s3-golden-path/observations.json \
		--include-all \
		--now 2026-01-11T00:00:00Z \
		> /tmp/stave-determinism-run1.json 2>/dev/null || true
	@./$(BINARY) apply --profile aws-s3 \
		--input testdata/e2e/e2e-s3-golden-path/observations.json \
		--include-all \
		--now 2026-01-11T00:00:00Z \
		> /tmp/stave-determinism-run2.json 2>/dev/null || true
	@diff -u /tmp/stave-determinism-run1.json /tmp/stave-determinism-run2.json \
		|| (echo "FAIL: outputs differ between runs" && exit 1)
	@echo "OK: outputs are identical"
	@rm -f /tmp/stave-determinism-run1.json /tmp/stave-determinism-run2.json

## reproduce-release: Reproduce release binaries locally and print checksums for comparison
reproduce-release: sync-schemas
	@echo "Reproducing release binaries with deterministic build flags..."
	@echo "Go version: $$($(GOCMD) version)"
	@echo "VERSION: $(VERSION)"
	@mkdir -p dist-local
	@for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64; do \
		os="$${target%/*}"; \
		arch="$${target#*/}"; \
		bin="stave_v$(VERSION)_$${os}_$${arch}"; \
		if [ "$$os" = "windows" ]; then bin="$${bin}.exe"; fi; \
		echo "Building $$bin"; \
		CGO_ENABLED=0 GOOS="$$os" GOARCH="$$arch" \
			$(GOBUILD) -trimpath \
			-ldflags "-s -w -buildid= -X github.com/sufield/stave/internal/version.String=v$(VERSION)" \
			-o "dist-local/$$bin" \
			./cmd/stave; \
	done
	@echo ""
	@echo "Binary checksums (compare with release SHA256SUMS):"
	@cd dist-local && sha256sum stave_*
	@echo ""
	@echo "Note: Release archives (tar.gz/zip) include metadata that may"
	@echo "differ across builds. Compare binary checksums, not archive checksums."

## release-local: Build a local snapshot release with GoReleaser (no publish)
release-local:
	goreleaser release --snapshot --clean

## release-check: Validate GoReleaser configuration
release-check:
	goreleaser check

## release: Prepare and push a release (usage: make release V=0.0.3)
release:
ifndef V
	$(error Usage: make release V=0.0.3)
endif
	@echo "==> Preparing release v$(V)..."
	@echo "$(V)" > VERSION
	@echo "==> VERSION file: $$(cat VERSION)"
	@echo "==> Running tests..."
	$(MAKE) test
	@echo "==> Running e2e..."
	$(MAKE) e2e
	@echo "==> Validating goreleaser config..."
	$(MAKE) release-check
	@echo "==> All checks passed. Committing..."
	git add VERSION README.md
	git commit -m "Prepare release v$(V)"
	git tag v$(V)
	@echo ""
	@echo "Release v$(V) is ready. Push with:"
	@echo "  git push origin main"
	@echo "  git push git@github.com-sufield:sufield/stave.git v$(V)"

## gofixer: Run full Go modernization workflow from gofixer.md
gofixer:
	@echo "1) Preview modernization changes"
	$(GOCMD) fix -diff ./...
	@echo "2) Apply default modernizers"
	$(GOCMD) fix ./...
	@echo "3) Cross-platform modernization passes"
	GOOS=linux GOARCH=amd64 $(GOCMD) fix ./...
	GOOS=darwin GOARCH=arm64 $(GOCMD) fix ./...
	GOOS=windows GOARCH=amd64 $(GOCMD) fix ./...
	@echo "4) Run Go 1.26 new(expr) modernizer explicitly"
	$(GOCMD) fix -newexpr ./...
	@echo "5) Final go fix pass"
	$(GOCMD) fix ./...
	@echo "6) Dead code detection"
	@out=$$(deadcode -test ./... 2>&1 | grep -v "byteReader.Read"); \
	if [ -n "$$out" ]; then echo "$$out"; exit 1; fi
	@echo "7) Validation"
	find . -name '*.go' -not -path './vendor/*' | xargs goimports -w
	$(MAKE) lint
	$(GOTEST) ./...

## imports: Auto-fix import grouping and remove unused imports
imports:
	find . -name '*.go' -not -path './vendor/*' | xargs goimports -w

## imports-check: Check import grouping without modifying files
imports-check:
	@bad=$$(find . -name '*.go' -not -path './vendor/*' | xargs goimports -l); \
	if [ -n "$$bad" ]; then \
		echo "goimports would reformat:"; echo "$$bad"; exit 1; \
	fi

## bench: Run performance benchmarks (engine evaluation at 10k assets)
bench:
	$(GOTEST) -bench=BenchmarkEvaluate -benchmem -count=1 ./internal/core/evaluation/engine/
	$(GOTEST) -bench=BenchmarkEvaluateLargeSnapshot -benchmem -count=1 ./internal/app/

## fuzz: Run Go native fuzz tests (30s per target)
fuzz: sync-schemas sync-controls sync-alternatives
	$(GOTEST) -fuzz=Fuzz -fuzztime=30s ./internal/core/s3/policy/
	$(GOTEST) -fuzz=Fuzz -fuzztime=30s ./internal/adapters/observations/
	$(GOTEST) -fuzz=Fuzz -fuzztime=30s ./internal/contracts/validator/
	$(GOTEST) -fuzz=Fuzz -fuzztime=30s ./internal/core/predicate/
	$(GOTEST) -fuzz=Fuzz -fuzztime=30s -run=FuzzNewControlID ./internal/core/kernel/
	$(GOTEST) -fuzz=FuzzParseByteSize -fuzztime=30s ./internal/core/kernel/
	$(GOTEST) -fuzz=FuzzParseDuration -fuzztime=30s ./internal/core/kernel/
	$(GOTEST) -fuzz=FuzzCompile -fuzztime=30s ./internal/adapters/cel/
	$(GOTEST) -fuzz=FuzzParsePolicyDocument -fuzztime=30s ./internal/platform/providers/aws/iam/

# Gosentry fuzzing (Trail of Bits' security-oriented Go toolchain fork:
# LibAFL engine, grammar mode, race/leak/overflow detection). Same testing.F
# harnesses as `make fuzz`. Requires gosentry built at GOSENTRY_PATH; not
# vendored. See docs/fuzzing.md.
GOSENTRY_PATH ?= /tmp/gosentry
GOSENTRY_GO := $(GOSENTRY_PATH)/bin/go
FUZZ_TIME ?= 30m

.PHONY: fuzz-install fuzz-cel fuzz-snapshot fuzz-iam fuzz-all fuzz-coverage

## fuzz-install: Build gosentry at GOSENTRY_PATH (one-time)
# gosentry is a Go-toolchain fork: build it with src/make.bash (produces
# ../bin/go), NOT `make`. Requires a Rust toolchain on PATH.
fuzz-install:
	@if [ ! -f $(GOSENTRY_GO) ]; then \
		echo "Installing gosentry into $(GOSENTRY_PATH)..."; \
		[ -d $(GOSENTRY_PATH)/.git ] || git clone https://github.com/trailofbits/gosentry.git $(GOSENTRY_PATH); \
		cd $(GOSENTRY_PATH)/src && ./make.bash; \
	fi
	@echo "gosentry ready at $(GOSENTRY_GO)"

## fuzz-cel: Fuzz the CEL predicate compiler with gosentry (FuzzCompile)
fuzz-cel: fuzz-install
	$(GOSENTRY_GO) test -fuzz=FuzzCompile \
		--focus-on-new-code=false --catch-races=true --catch-leaks=true \
		--panic-on=log.Fatal -fuzztime=$(FUZZ_TIME) \
		./internal/adapters/cel/

## fuzz-snapshot: Fuzz the obs.v0.1 snapshot parser with gosentry
fuzz-snapshot: fuzz-install
	$(GOSENTRY_GO) test -fuzz=FuzzLoadSnapshotFromReader \
		--focus-on-new-code=false --catch-races=true --catch-leaks=true \
		--panic-on=log.Fatal -fuzztime=$(FUZZ_TIME) \
		./internal/adapters/observations/

## fuzz-iam: Fuzz the IAM policy resolver with gosentry (grammar mode)
fuzz-iam: fuzz-install
	$(GOSENTRY_GO) test -fuzz=FuzzParsePolicyDocument \
		--focus-on-new-code=false \
		--use-grammar --grammar=fuzz/grammars/iam-policy-grammar.json \
		--catch-races=true --catch-leaks=true \
		--panic-on=log.Fatal -fuzztime=$(FUZZ_TIME) \
		./internal/platform/providers/aws/iam/

## fuzz-all: Run all gosentry fuzz targets
fuzz-all: fuzz-cel fuzz-snapshot fuzz-iam

## fuzz-coverage: Generate gosentry coverage reports for each target
fuzz-coverage: fuzz-install
	$(GOSENTRY_GO) test -fuzz=FuzzCompile --generate-coverage ./internal/adapters/cel/
	$(GOSENTRY_GO) test -fuzz=FuzzLoadSnapshotFromReader --generate-coverage ./internal/adapters/observations/
	$(GOSENTRY_GO) test -fuzz=FuzzParsePolicyDocument --generate-coverage ./internal/platform/providers/aws/iam/

## help: Show this help
help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@grep -E '^## [a-zA-Z0-9_-]+:' Makefile | sed 's/## /  /'

e2e-s3: build
	go test ./e2e/ -run E2E/e2e-s3 -count=1 -timeout 5m


## gencontrol: Scaffold a new control with E2E test fixtures (usage: make gencontrol ID=CTL.S3.NEW.001 NAME="..." FIELD=... REMEDIATION="...")
gencontrol:
ifndef ID
	$(error Usage: make gencontrol ID=CTL.S3.NEW.001 NAME="Control Name" FIELD=properties.storage.access.public_read REMEDIATION="Fix action text")
endif
	$(GOCMD) run ./internal/tools/gencontrol --id "$(ID)" --name "$(NAME)" --field "$(FIELD)" --remediation "$(REMEDIATION)" $(if $(DOMAIN),--domain "$(DOMAIN)") $(if $(SEVERITY),--severity "$(SEVERITY)") $(if $(SCOPE_TAGS),--scope-tags "$(SCOPE_TAGS)") $(if $(ASSET_TYPE),--asset-type "$(ASSET_TYPE)") $(if $(OP),--op "$(OP)") $(if $(VALUE),--value "$(VALUE)") $(if $(COMPLIANCE),--compliance "$(COMPLIANCE)") $(if $(OUT),--out "$(OUT)")

## triage: Triage a new AWS feature for control coverage gaps (usage: make triage ARGS="--service acm")
triage:
	@$(MAKE) sync-controls >&2
	@$(GOCMD) run ./internal/tools/triage $(ARGS)

## quarterly-audit: Run all gap discovery engines and produce a consolidated report
quarterly-audit:
	@$(MAKE) sync-controls >&2
	@$(GOCMD) run ./internal/tools/quarterly $(ARGS)

## quarterly-save: Run quarterly audit and save results as this quarter's baseline
quarterly-save:
	@$(MAKE) sync-controls >&2
	@$(GOCMD) run ./internal/tools/quarterly --save $(ARGS)

## compliance-diff: Diff a compliance framework checklist against the control catalog
compliance-diff:
	@$(MAKE) sync-controls >&2
	@$(GOCMD) run ./internal/tools/compliance-diff $(ARGS)

## gen-steampipe-mappings: Generate contracts/steampipe/*.yaml from the cached column catalog
##                          Skips existing files; new files carry _auto_generated: true and
##                          _review_required: N markers for human review.
gen-steampipe-mappings:
	@echo "Generating Steampipe -> Stave mapping YAMLs..."
	@python3 scripts/gen-steampipe-mappings.py \
		--columns scripts/steampipe-columns.json \
		--output contracts/steampipe/ \
		--skip-existing
	@echo "Total mappings: $$(ls contracts/steampipe/*.yaml 2>/dev/null | wc -l)"

## gen-steampipe-mappings-validate: Measure auto-generator accuracy against hand-authored ground truth.
gen-steampipe-mappings-validate:
	@python3 scripts/gen-steampipe-mappings.py \
		--columns scripts/steampipe-columns.json \
		--validate-against contracts/steampipe/

## docs-controls: Generate control reference from built-in catalog
docs-controls: sync-controls
	$(GOCMD) run ./internal/tools/gencontroldocs

## docs-controls-check: Verify control reference is up to date
docs-controls-check: sync-controls
	$(GOCMD) run ./internal/tools/gencontroldocs -check

## docs-commands: Generate the CLI command reference from the cobra tree
docs-commands:
	$(GOCMD) run ./internal/tools/gencommanddocs

## docs-commands-check: Verify the command reference matches the binary
docs-commands-check:
	$(GOCMD) run ./internal/tools/gencommanddocs -check

## docs-datalog: Generate Datalog relations reference from .dl source files
docs-datalog:
	$(GOCMD) run ./internal/tools/gendatalogdocs

## docs-datalog-check: Verify Datalog reference is up to date
docs-datalog-check:
	$(GOCMD) run ./internal/tools/gendatalogdocs -check

SITE_CLI_REF ?= ../projects/stave-guide/reference/cli-reference

## docs-site: Generate Docusaurus CLI reference pages from the cobra tree
docs-site:
	$(GOCMD) run ./internal/tools/gencommanddocs -site $(SITE_CLI_REF)

## docs-site-check: Verify the site CLI reference pages match the binary
docs-site-check:
	@if [ -d $(SITE_CLI_REF) ]; then \
	  $(GOCMD) run ./internal/tools/gencommanddocs -site-check $(SITE_CLI_REF); \
	else \
	  echo "skip: $(SITE_CLI_REF) not present in this checkout"; \
	fi

## sync-guide: Refresh projects/stave-guide/ real-file copies of generated + sub-repo docs.
## projects/stave-guide/ is the Docusaurus SSG source (real files, not symlinks — SSG can't
## render symlinked content). Regenerates the generated docs, then copies per
## projects/stave-guide/.sync-manifest.tsv. Commit the result.
.PHONY: sync-guide
sync-guide: docs-controls docs-commands
	@cd .. && bash scripts/sync-guide.sh

## docs-commands-catalog: Generate the curated root commands-catalog.md
## from catalog_meta.go annotations + the live cobra tree. Edit the
## when-to-use text / grouping in catalog_meta.go, not the markdown.
## The catalog lives at the repo root (outside this module).
COMMANDS_CATALOG ?= ../commands-catalog.md
docs-commands-catalog:
	$(GOCMD) run ./internal/tools/gencommanddocs -catalog $(COMMANDS_CATALOG)

## docs-commands-catalog-check: Verify the curated catalog matches the
## annotations + binary (fails on phantom/missing-leaf or stale prose).
## Skips cleanly when the root doc isn't present in the checkout.
docs-commands-catalog-check:
	@if [ -f $(COMMANDS_CATALOG) ]; then \
	  $(GOCMD) run ./internal/tools/gencommanddocs -catalog-check $(COMMANDS_CATALOG); \
	else \
	  echo "skip: $(COMMANDS_CATALOG) not present in this checkout"; \
	fi

## attack-stage-check: Reject deprecated attack_stage values in control YAMLs
##
## The canonical 12-stage taxonomy is enforced by the JSON Schema enum
## under params.attack_stage. This guard catches deprecated literals
## before the schema validation kicks in, so the failure message is
## obvious rather than buried in a validator backtrace.
attack-stage-check:
	@bad=$$(grep -rEln '^[[:space:]]*attack_stage:[[:space:]]*(defense_evasion|credential_theft|data_access|reconnaissance|data_in_transit_exposure|command_and_control|none)[[:space:]]*$$' controls/ || true); \
	if [ -n "$$bad" ]; then \
		echo "ERROR: deprecated attack_stage values found in:"; echo "$$bad"; \
		echo "Migration map: defense_evasion->detection_evasion, credential_theft->credential_access, data_access->collection, reconnaissance->discovery, data_in_transit_exposure->exfiltration, command_and_control->REMOVED, none->REMOVE the params block"; \
		exit 2; \
	fi

## domain-check: Soft-enum check on `domain:` values in control YAMLs
##
## domain is intentionally an open string field — local extensions are
## allowed — but values outside docs/ontology/domains.json indicate
## potential drift. This target prints WARN lines for non-canonical
## values and reports any deprecated spellings (e.g. detect, encrypt,
## cryptography, compliance, availability) as ERROR. It exits 0 on
## warnings, 2 on deprecated values.
domain-check:
	@deprecated=$$(grep -rEln '^[[:space:]]*domain:[[:space:]]*(detect|encrypt|cryptography|compliance|availability)[[:space:]]*$$' controls/ || true); \
	if [ -n "$$deprecated" ]; then \
		echo "ERROR: deprecated domain values found in:"; echo "$$deprecated"; \
		echo "Migration map (see docs/ontology/domains.json): detect->detection, encrypt->encryption, cryptography->encryption, compliance->governance, availability->resilience"; \
		exit 2; \
	fi
	@canonical='exposure governance identity detection encryption audit network resilience lifecycle storage access hygiene secrets capacity'; \
	values=$$(grep -rh --include='*.yaml' "^[[:space:]]*domain:" controls/ | awk -F: '{gsub(/^[[:space:]]*/,"",$$2); gsub(/[[:space:]]*$$/,"",$$2); print $$2}' | sort -u); \
	for v in $$values; do \
		case " $$canonical " in *" $$v "*) ;; *) echo "WARN: non-canonical domain '$$v' (see docs/ontology/domains.json)" ;; esac; \
	done

## docs-coverage: Regenerate methodology-coverage docs from control + inventory data
docs-coverage: sync-controls sync-alternatives
	$(GOCMD) run ./internal/tools/genmethodologycoverage

## docs-coverage-check: Verify methodology-coverage docs are up to date
docs-coverage-check: sync-controls sync-alternatives
	$(GOCMD) run ./internal/tools/genmethodologycoverage -check

## docker-demo: Build demo Docker image using Go version from go.mod
docker-demo: build
	docker build \
		--build-arg GO_VERSION=$(GO_VERSION) \
		-f ../docs-content/demo/Dockerfile \
		-t stave-demo ..

## demo-check: Verify demo scenarios produce expected finding counts AND
##             encoding correctness (no projector emits a fact that drifts
##             from the underlying observation).
demo-check: build
	@echo "Checking demo scenarios..."
	@fail=0; \
	for scenario in ../docs-content/demo/scenarios/*/; do \
		name="$$(basename "$$scenario")"; \
		expected="$$(cat "$$scenario/expected.findings.count" 2>/dev/null)"; \
		if [ -z "$$expected" ]; then continue; fi; \
		actual="$$(./stave apply \
			--observations "$$scenario/observations" \
			--now 2026-01-15T00:00:00Z \
			--max-unsafe 12h \
			--format json 2>/dev/null \
			| jq '.findings | length' || echo "ERROR")"; \
		if [ "$$actual" != "$$expected" ]; then \
			echo "FAIL: $$name: expected $$expected findings, got $$actual"; \
			fail=1; \
		else \
			echo "  OK: $$name ($$actual findings)"; \
		fi; \
	done; \
	if [ "$$fail" -eq 1 ]; then exit 1; fi; \
	echo "All demo scenarios match expected counts"
	@$(MAKE) --no-print-directory verify-encoding-demos

## verify-encoding-demos: Run examples/explain/verify_encoding.py --strict
##                       against every demo scenario. Catches projector
##                       regressions (wrong path, wrong value, type
##                       coercion drift) at demo-check time so a faulty
##                       projector fails the build on every developer
##                       machine — no manual step required.
##
##                       Discovers fixtures via glob in two roots:
##                         - ../docs-content/demo/scenarios/*/observations
##                         - examples/*/fixtures/*/observations
##                       New demos under examples/ are picked up
##                       automatically without Makefile edits.
##
##                       Three outcome categories:
##                         OK    — n/n verifiable facts match
##                         SKIP  — 0/0 facts (SIR projector has no path
##                                 for the fixture's properties yet —
##                                 not an encoding bug)
##                         FAIL  — verifier reports a mismatch — exit 1
verify-encoding-demos: build
	@echo "Verifying encoding correctness for demo scenarios..."
	@fail=0; ok=0; skip=0; tmp=$$(mktemp); \
	for obs_dir in $$(find ../docs-content/demo/scenarios -mindepth 2 -maxdepth 2 \
	                       -type d -name observations 2>/dev/null | sort) \
	               $$(find examples -path '*/fixtures/*/observations' \
	                       -type d 2>/dev/null | sort); do \
		label=$$(echo "$$obs_dir" \
			| sed -E 's|^\.\./docs-content/demo/scenarios/([^/]+)/observations$$|docs-content:\1|; \
			          s|^examples/([^/]+)/fixtures/([^/]+)/observations$$|\1/\2|'); \
		./stave export-sir --format jsonl \
			--observations "$$obs_dir" \
			--now 2027-01-01T00:00:00Z > "$$tmp" 2>/dev/null; \
		rc=$$?; \
		if [ "$$rc" -ne 0 ]; then \
			echo "  SKIP: $$label — export-sir rc=$$rc"; \
			skip=$$((skip+1)); \
			continue; \
		fi; \
		out=$$(NO_COLOR=1 python3 examples/explain/verify_encoding.py --strict \
			"$$tmp" "$$obs_dir" 2>&1); \
		vrc=$$?; \
		if [ "$$vrc" -ne 0 ]; then \
			echo "  FAIL: $$label encoding verification:"; \
			echo "$$out" | sed 's/^/    /'; \
			fail=1; \
		elif echo "$$out" | grep -q '0/0 verifiable'; then \
			echo "  SKIP: $$label — 0/0 verifiable facts (SIR projector gap)"; \
			skip=$$((skip+1)); \
		else \
			summary=$$(echo "$$out" | head -1 | sed 's/Encoding verified: //'); \
			echo "  OK: $$label — $$summary"; \
			ok=$$((ok+1)); \
		fi; \
	done; \
	rm -f "$$tmp"; \
	echo "Summary: $$ok OK, $$skip SKIP, $$( [ "$$fail" -eq 1 ] && echo 1 || echo 0 ) FAIL"; \
	if [ "$$fail" -eq 1 ]; then exit 1; fi; \
	echo "All demo scenario encodings verified (or skipped due to projector gap)"

## verify-encoding-controls: Run verify_encoding.py --strict against every
##                          internal/controldata/testdata/*/*/observations
##                          directory. Same OK / SKIP / FAIL semantics as
##                          verify-encoding-demos but covers per-control
##                          taxonomy fixtures (Shadow Admin role scenarios,
##                          S3 delegation scenarios) instead of demos.
verify-encoding-controls: build
	@echo "Verifying encoding correctness for control testdata..."
	@fail=0; ok=0; skip=0; tmp=$$(mktemp); \
	for obs_dir in $$(find internal/controldata -path '*/testdata/*/observations' \
	                       -type d 2>/dev/null | sort); do \
		label=$$(echo "$$obs_dir" \
			| sed -E 's|^internal/controldata/testdata/||; s|/observations$$||'); \
		./stave export-sir --format jsonl \
			--observations "$$obs_dir" \
			--now 2027-01-01T00:00:00Z > "$$tmp" 2>/dev/null; \
		rc=$$?; \
		if [ "$$rc" -ne 0 ]; then \
			echo "  SKIP: $$label — export-sir rc=$$rc"; \
			skip=$$((skip+1)); \
			continue; \
		fi; \
		out=$$(NO_COLOR=1 python3 examples/explain/verify_encoding.py --strict \
			"$$tmp" "$$obs_dir" 2>&1); \
		vrc=$$?; \
		if [ "$$vrc" -ne 0 ]; then \
			echo "  FAIL: $$label encoding verification:"; \
			echo "$$out" | sed 's/^/    /'; \
			fail=1; \
		elif echo "$$out" | grep -q '0/0 verifiable'; then \
			echo "  SKIP: $$label — 0/0 verifiable facts (SIR projector gap)"; \
			skip=$$((skip+1)); \
		else \
			summary=$$(echo "$$out" | head -1 | sed 's/Encoding verified: //'); \
			echo "  OK: $$label — $$summary"; \
			ok=$$((ok+1)); \
		fi; \
	done; \
	rm -f "$$tmp"; \
	echo "Summary: $$ok OK, $$skip SKIP, $$( [ "$$fail" -eq 1 ] && echo 1 || echo 0 ) FAIL"; \
	if [ "$$fail" -eq 1 ]; then exit 1; fi; \
	echo "All control testdata encodings verified (or skipped due to projector gap)"

## verify-encoding-e2e: Run verify_encoding.py --strict against every
##                     testdata/e2e/<fixture>/observations directory.
##                     Hooked from regenerate-goldens-strict so a regen
##                     that produces drifted encoding fails fast.
verify-encoding-e2e: build
	@echo "Verifying encoding correctness for e2e fixtures..."
	@fail=0; tmp=$$(mktemp); checked=0; \
	for obs in testdata/e2e/*/observations; do \
		name="$$(basename "$$(dirname "$$obs")")"; \
		[ -d "$$obs" ] || continue; \
		if ! ls "$$obs"/*.json >/dev/null 2>&1; then continue; fi; \
		./stave export-sir --format jsonl \
			--observations "$$obs" \
			--now 2026-01-15T00:00:00Z > "$$tmp" 2>/dev/null || continue; \
		[ -s "$$tmp" ] || continue; \
		out="$$(NO_COLOR=1 python3 examples/explain/verify_encoding.py --strict \
			"$$tmp" "$$obs" 2>&1)"; \
		if [ $$? -ne 0 ]; then \
			echo "FAIL: $$name encoding verification:"; \
			echo "$$out" | sed 's/^/    /'; \
			fail=1; \
		fi; \
		checked=$$((checked + 1)); \
	done; \
	rm -f "$$tmp"; \
	if [ "$$fail" -eq 1 ]; then exit 1; fi; \
	echo "$$checked e2e fixture(s) — encoding verified"

## regenerate-goldens-strict: Wrap regenerate-goldens with encoding
##                           verification. Use this in CI so a regen
##                           that produces drifted encoding fails.
##                           regenerate-goldens itself stays
##                           unchanged so day-to-day local regen
##                           is unaffected.
regenerate-goldens-strict: regenerate-goldens verify-encoding-e2e
	@echo "Goldens regenerated AND encoding verified."

## metrics: Generate docs/metrics.yaml from live codebase counts
metrics:
	@echo "# Stave Metrics — GENERATED, do not edit" > docs/metrics.yaml
	@echo "# Run: make metrics" >> docs/metrics.yaml
	@echo "" >> docs/metrics.yaml
	@echo "catalog:" >> docs/metrics.yaml
	@echo "  controls: $$(find controls/ -name '*.yaml' -not -path '*/_triage/*' | wc -l | tr -d ' ')" >> docs/metrics.yaml
	@echo "  services: $$(find controls/ -mindepth 1 -maxdepth 1 -type d -not -name '_triage' | wc -l | tr -d ' ')" >> docs/metrics.yaml
	@echo "" >> docs/metrics.yaml
	@echo "chains:" >> docs/metrics.yaml
	@echo "  authored: $$(find chains/ -name '*.yaml' 2>/dev/null | wc -l | tr -d ' ')" >> docs/metrics.yaml
	@echo "" >> docs/metrics.yaml
	@echo "frameworks:" >> docs/metrics.yaml
	@echo "  count: $$(find data/frameworks/ -name '*.yaml' 2>/dev/null | wc -l | tr -d ' ')" >> docs/metrics.yaml
	@echo "" >> docs/metrics.yaml
	@echo "updated: $$(date +%Y-%m-%d)" >> docs/metrics.yaml
	@echo "Generated docs/metrics.yaml"

## consistency-check: Verify every derived artifact matches its canonical source
##
## Runs each non-golden regen target then asserts the working tree is clean.
## Detects two failure modes the per-tool -check targets miss:
##   1. Contributor regenerated some derived artifacts but forgot others.
##   2. Contributor edited an embedded/ file directly instead of the
##      canonical controls/ or schemas/ source.
##
## Golden regen is excluded — it has its own pipeline (regenerate-goldens)
## and is too slow to gate every PR. See docs/audits/sync-audit.md for the full
## chain map.
.PHONY: consistency-check
consistency-check: sync-schemas sync-controls sync-alternatives
	@$(GOCMD) run ./internal/tools/gencontroldocs
	@$(GOCMD) run ./internal/tools/genmethodologycoverage
	@$(GOCMD) run ./internal/tools/gencommanddocs
	@$(GOCMD) run ./internal/tools/gendatalogdocs
	@# Verify the curated root catalog matches its annotations + the binary
	@# (phantom / missing-leaf / stale prose). Skips cleanly if the root
	@# doc isn't in this checkout. Runs before the git-clean drift check.
	@if [ -f ../commands-catalog.md ]; then \
	  $(GOCMD) run ./internal/tools/gencommanddocs -catalog-check ../commands-catalog.md; \
	fi
	@# Scope the drift check to paths the gate's targets actually write to.
	@# Globally `git status` would also surface unrelated working-tree state
	@# (e.g. when stave/ is checked out inside a monorepo), which is noise
	@# for this gate.
	@drift=$$(git status --porcelain -- \
		internal/contracts/schema/embedded \
		internal/controldata/embedded \
		internal/adapters/coverage/embedded \
		docs/controls/reference.md \
		docs/command-reference.md \
		docs/reference/datalog-relations.md \
		'docs/methodology-coverage-*.md' \
	); \
	if [ -n "$$drift" ]; then \
		echo "ERROR: derived artifacts are out of sync with canonical sources."; \
		echo ""; \
		echo "Drifted files:"; \
		echo "$$drift"; \
		echo ""; \
		echo "Fix locally and commit the result:"; \
		echo "  make consistency-check"; \
		echo "  git add -u && git commit"; \
		echo ""; \
		echo "Or run individual targets — see docs/audits/sync-audit.md for the chain map:"; \
		echo "  make sync-controls sync-schemas sync-alternatives"; \
		echo "  make docs-controls docs-coverage"; \
		exit 1; \
	else \
		echo "OK: all derived artifacts in sync"; \
	fi

# ── Public repo sync ──────────────────────────────────────────────
# Syncs the stave project to a separate public repository, excluding
# internal-only directories. The public repo lives at PUBLIC_DEST.
#
# Usage:
#   make sync              # sync and show summary

PUBLIC_DEST ?= $(HOME)/work/stave/
# Excludes for the public-repo mirror. The contract: anything internal
# (audit reports, design plans, project tracking, contributor process,
# point-in-time cleanup notes) stays in the private monorepo and is
# NOT shipped to adopters. The classification mirrors the docs-drift
# CI gate's exclude list so the two stay aligned — a file that's
# internal for drift purposes is also internal for sync.
#
# skills/ is excluded because sync-skills writes that subtree from a
# different source (../skills/superpowers/ at the monorepo root, NOT
# under stave/). Without the exclude, the main rsync's --delete walks
# the dest, sees skills/ has no counterpart under ./, and deletes the
# work sync-skills just did.
SYNC_EXCLUDES = \
	--exclude='.git/' \
	--exclude='dev/' \
	--exclude='.tmp/' \
	--exclude='/stave' \
	--exclude='.lychee.toml' \
	--exclude='dist/' \
	--exclude='dist-local/' \
	--exclude='skills/' \
	--exclude='__pycache__/' \
	--exclude='*.pyc' \
	--exclude='.tools-venv/' \
	--exclude='.venv/' \
	--exclude='venv/' \
	--exclude='docs/audits/' \
	--exclude='docs/superpowers/' \
	--exclude='docs/plans/' \
	--exclude='docs/ontology/' \
	--exclude='docs/design/' \
	--exclude='docs/design-notes/' \
	--exclude='docs/project/' \
	--exclude='docs/contrib/' \
	--exclude='docs/*-audit.md' \
	--exclude='docs/*-backlog.md' \
	--exclude='docs/aggregation_decisions.md' \
	--exclude='docs/bisect-timeline.md' \
	--exclude='docs/bug-template.md' \
	--exclude='docs/cli-style-guide.md' \
	--exclude='docs/developer-workflow.md' \
	--exclude='docs/examples-experiments.md' \
	--exclude='docs/fixture-drift-cleanup-*.md' \
	--exclude='docs/go-idioms.md' \
	--exclude='docs/graph-experiments.md' \
	--exclude='docs/pending-items.md' \
	--exclude='docs/sir-pending-discussion.md' \
	--exclude='/gofixer.md' \
	--exclude='.stave-backlog/'

## sync: Sync to public repo (calls sync-skills automatically so the
##       monorepo's external-but-published assets ride along)
sync: sync-skills
	@if [ ! -d "$(PUBLIC_DEST)/.git" ]; then \
		echo "Error: $(PUBLIC_DEST) is not a git repository."; \
		echo "Initialize it first:"; \
		echo "  mkdir -p $(PUBLIC_DEST) && cd $(PUBLIC_DEST) && git init"; \
		exit 1; \
	fi
	rsync -av --delete $(SYNC_EXCLUDES) ./ $(PUBLIC_DEST)
	@echo ""
	@echo "Synced to $(PUBLIC_DEST)"
	@echo "Review changes:  cd $(PUBLIC_DEST) && git status"
ifdef MSG
	cd $(PUBLIC_DEST) && git add -A && git commit -m "$(MSG)"
	@echo "Committed: $(MSG)"
endif

## sync-skills: Push the Superpowers skills (../skills/superpowers/) to
## the public repo. The skills tree lives at the monorepo root — OUTSIDE
## the stave/ subdirectory the main `sync` target walks — so they would
## otherwise be left behind. Same PUBLIC_DEST variable so a single
## override flows through to both targets.
##
## Source: ../skills/superpowers/   (canonical, in this private monorepo)
## Dest:   $(PUBLIC_DEST)/skills/superpowers/
##
## --delete keeps the public copy a pure mirror; a skill removed here
## is removed there. Run `make sync-skills` standalone, or let `make
## sync` invoke it automatically.
SKILLS_SRC = ../skills/superpowers/
SKILLS_DST = $(PUBLIC_DEST)/skills/superpowers/

sync-skills:
	@if [ ! -d "$(SKILLS_SRC)" ]; then \
		echo "Error: $(SKILLS_SRC) does not exist relative to the stave/ Makefile."; \
		echo "The Superpowers skills tree should be at the monorepo root."; \
		exit 1; \
	fi
	@if [ ! -d "$(PUBLIC_DEST)" ]; then \
		echo "Error: $(PUBLIC_DEST) does not exist."; \
		echo "Set PUBLIC_DEST or initialise the public repo first:"; \
		echo "  mkdir -p $(PUBLIC_DEST) && cd $(PUBLIC_DEST) && git init"; \
		exit 1; \
	fi
	@echo "Syncing Superpowers skills..."
	@mkdir -p $(SKILLS_DST)
	@rsync -a --delete $(SKILLS_SRC) $(SKILLS_DST)
	@echo "Synced $$(find $(SKILLS_DST) -type f \( -name '*.md' -o -name '*.yaml' \) | wc -l | tr -d ' ') files to $(SKILLS_DST)"
