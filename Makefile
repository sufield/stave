.PHONY: all build build-dev test test-unit test-fast test-integration test-e2e test-ci test-coverage test-compliance cover-report clean-cover lint lint-fix fmt vet tidy clean install run run-now check ci e2e determinism reproduce-release release-local release-check release help sync-schemas sync-controls sync-alternatives gofixer imports imports-check sync-public fuzz bench docker-demo demo-check readme readme-check golden regenerate-goldens docs-controls docs-controls-check docs-coverage docs-coverage-check golden-update-all golden-update golden-one golden-fixture attack-stage-check domain-check
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

## sync-schemas: Copy canonical schemas into embed directory
sync-schemas:
	@mkdir -p $(SCHEMA_DST)
	rm -rf $(SCHEMA_DST)/*
	cp -R $(SCHEMA_SRC)/* $(SCHEMA_DST)/

## sync-controls: Copy canonical controls into embed directory
sync-controls:
	@mkdir -p $(CONTROL_DST)
	rm -rf $(CONTROL_DST)/*
	cp -R $(CONTROL_SRC)/* $(CONTROL_DST)/

## sync-alternatives: Copy canonical alternative-tool inventories into embed directory
sync-alternatives:
	@mkdir -p $(ALTERNATIVES_DST)
	rm -rf $(ALTERNATIVES_DST)/*
	cp -R $(ALTERNATIVES_SRC)/* $(ALTERNATIVES_DST)/

## build: Build the production binary
build: sync-schemas sync-controls sync-alternatives
	$(GOBUILD) $(LDFLAGS) -o $(BINARY) ./cmd/stave

## build-dev: Build the dev binary with all commands
build-dev: sync-schemas sync-controls sync-alternatives
	$(GOBUILD) $(LDFLAGS) -tags stavedev -o stave-dev ./cmd/stave-dev

## Testing pyramid:
##
##   test-fast        sub-minute dev iteration (`-short`, no binary spawn).
##   test-unit        same as test-fast plus race detector / coverage off.
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

## test-unit: Fast dev loop — unit tests only, skips e2e / golden / profile suites
##
## Targets only ./internal/... and ./cmd/... and passes -short so any test
## that gates on testing.Short() (e2e, profile, fixture-binary
## determinism) self-skips. The ./e2e/ tree is excluded outright. Designed
## to finish under 30 seconds so adding a control does not pay a 2000+
## golden-regeneration tax on the dev machine.
test-unit: sync-schemas sync-controls sync-alternatives
	$(GOTEST) -short ./internal/... ./cmd/...

## test-fast: Sub-minute dev feedback loop.
##
## Identical to test-unit at present (same -short scope, same
## packages) but kept as a separate target so the documented
## intent ("targeted at sub-minute") is stable even if test-unit
## later grows extra concerns (race detector, vet, etc.). Use this
## while iterating on a single change.
test-fast: sync-schemas sync-controls sync-alternatives
	$(GOTEST) -short -timeout 5m ./...

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
	./$(BINARY) apply --controls examples/public-bucket/controls --observations examples/public-bucket/observations --max-unsafe 168h --allow-unknown-input

## run-now: Run with fixed time for deterministic output
run-now: build
	./$(BINARY) apply --controls examples/public-bucket/controls --observations examples/public-bucket/observations --max-unsafe 168h --now 2026-01-11T00:00:00Z --allow-unknown-input

## check: Run all checks (fmt, vet, lint, test)
check: fmt vet lint test

## ci: CI pipeline (tidy, check, build)
ci: tidy check build

## golden: Update e2e expected outputs from current behavior (legacy narrow target)
##
## This target predates regenerate-goldens and only updates expected.summary.json
## + expected.findings.count for fixtures without command.txt. Prefer
## `make regenerate-goldens` for full coverage (expected.out.json, profile
## goldens, command.txt fixtures) and a categorized diff report.
golden: build
	@echo "Updating golden files (narrow legacy target — consider regenerate-goldens instead)..."
	@for case in testdata/e2e/e2e-*; do \
		if [ -f "$$case/command.txt" ]; then continue; fi; \
		extra=""; \
		if [ -f "$$case/args.txt" ]; then \
			extra="$$(sed "s|\$$CASE_DIR|$$case|g" "$$case/args.txt" | tr '\n' ' ')"; \
		fi; \
		./stave apply \
			--controls "$$case/controls" \
			--observations "$$case/observations" \
			--max-unsafe 168h \
			--now 2026-01-11T00:00:00Z \
			$$extra \
			> "$$case/output.json" 2> "$$case/err.txt" || true; \
		if [ -f "$$case/output.json" ] && jq -e '.summary' "$$case/output.json" > /dev/null 2>&1; then \
			jq -S '.summary' "$$case/output.json" > "$$case/expected.summary.json"; \
			jq '.findings | length' "$$case/output.json" | tr -d '\n' > "$$case/expected.findings.count"; \
		fi; \
	done
	@echo "Golden files updated"

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
##   ARGS="-dry-run"           preview diffs without writing
##   ARGS="-filter pattern"    limit to fixture names matching regex
regenerate-goldens: build
	$(GOCMD) run ./internal/tools/regengoldens $(ARGS)

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
e2e: build
	go test ./e2e/ -run E2E -count=1 -timeout 5m

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
	$(MAKE) readme
	@echo "==> VERSION file: $$(cat VERSION)"
	@echo "==> README version: $$(grep -o 'v[0-9]*\.[0-9]*\.[0-9]*' README.md | head -1)"
	@echo "==> Running tests..."
	$(MAKE) test
	@echo "==> Running e2e..."
	$(MAKE) e2e
	@echo "==> Checking README freshness..."
	$(MAKE) readme-check
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
	deadcode -test ./...
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
	$(GOTEST) -fuzz=Fuzz -fuzztime=30s ./internal/cel/

## help: Show this help
help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@grep -E '^## [a-zA-Z0-9_-]+:' Makefile | sed 's/## /  /'

e2e-s3: build
	go test ./e2e/ -run E2E/e2e-s3 -count=1 -timeout 5m

## readme: Render README.md from README.md.tmpl (fills in control counts, version)
readme: sync-controls
	$(GOCMD) run ./internal/tools/genreadme

## readme-check: Verify README.md matches template output
readme-check: sync-controls
	$(GOCMD) run ./internal/tools/genreadme -check

## forge: Scaffold a new control with E2E test fixtures (usage: make forge ID=CTL.S3.NEW.001 NAME="..." FIELD=... REMEDIATION="...")
forge:
ifndef ID
	$(error Usage: make forge ID=CTL.S3.NEW.001 NAME="Control Name" FIELD=properties.storage.access.public_read REMEDIATION="Fix action text")
endif
	$(GOCMD) run ./internal/tools/gencontrol --id "$(ID)" --name "$(NAME)" --field "$(FIELD)" --remediation "$(REMEDIATION)" $(if $(DOMAIN),--domain "$(DOMAIN)") $(if $(SEVERITY),--severity "$(SEVERITY)") $(if $(SCOPE_TAGS),--scope-tags "$(SCOPE_TAGS)") $(if $(ASSET_TYPE),--asset-type "$(ASSET_TYPE)") $(if $(OP),--op "$(OP)") $(if $(VALUE),--value "$(VALUE)") $(if $(COMPLIANCE),--compliance "$(COMPLIANCE)") $(if $(OUT),--out "$(OUT)")

## docs-controls: Generate control reference from built-in catalog
docs-controls: sync-controls
	$(GOCMD) run ./internal/tools/gencontroldocs

## docs-controls-check: Verify control reference is up to date
docs-controls-check: sync-controls
	$(GOCMD) run ./internal/tools/gencontroldocs -check

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

## demo-check: Verify demo scenarios produce expected finding counts
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

# ── Public repo sync ──────────────────────────────────────────────
# Syncs the stave project to a separate public repository, excluding
# internal-only directories. The public repo lives at PUBLIC_DEST.
#
# Usage:
#   make sync              # sync and show summary

PUBLIC_DEST ?= $(HOME)/work/stave/
SYNC_EXCLUDES = \
	--exclude='.git/' \
	--exclude='dev/' \
	--exclude='.tmp/' \
	--exclude='/stave' \
	--exclude='.lychee.toml' \
	--exclude='dist/' \
	--exclude='dist-local/'

## sync: Sync to public repo
sync:
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
