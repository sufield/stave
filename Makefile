.PHONY: all build build-dev test test-coverage lint lint-fix fmt vet tidy clean install run run-now check ci e2e determinism reproduce-release release-local release-check release help sync-schemas sync-controls gofixer imports imports-check sync-public sync-public-dry fuzz docker-demo demo-check readme readme-check

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

## build: Build the production binary
build: sync-schemas sync-controls
	$(GOBUILD) $(LDFLAGS) -o $(BINARY) ./cmd/stave

## build-dev: Build the dev binary with all commands
build-dev: sync-schemas sync-controls
	$(GOBUILD) $(LDFLAGS) -tags stavedev -o stave-dev ./cmd/stave-dev

## test: Run all tests (includes dev-only packages via build tag)
test: sync-schemas sync-controls
	$(GOTEST) -tags stavedev -v ./...

## test-coverage: Run tests with coverage
test-coverage:
	$(GOTEST) -v -cover -coverprofile=coverage.out ./...
	$(GOCMD) tool cover -html=coverage.out -o coverage.html

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

## golden: Update e2e expected outputs from current behavior
golden: build
	@echo "Updating golden files..."
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

## e2e: Run end-to-end tests
e2e: build
	./scripts/e2e.sh

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

## fuzz: Run Go native fuzz tests (30s per target)
fuzz: sync-schemas sync-controls
	$(GOTEST) -fuzz=Fuzz -fuzztime=30s ./pkg/alpha/domain/s3/policy/
	$(GOTEST) -fuzz=Fuzz -fuzztime=30s ./internal/adapters/observations/
	$(GOTEST) -fuzz=Fuzz -fuzztime=30s ./internal/contracts/validator/
	$(GOTEST) -fuzz=Fuzz -fuzztime=30s ./pkg/alpha/domain/predicate/
	$(GOTEST) -fuzz=Fuzz -fuzztime=30s ./pkg/alpha/domain/kernel/

## help: Show this help
help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@grep -E '^## [a-zA-Z0-9_-]+:' Makefile | sed 's/## /  /'

e2e-s3: build
	./scripts/e2e-s3.sh

## readme: Render README.md from README.md.tmpl (fills in control counts, version)
readme: sync-controls
	$(GOCMD) run ./internal/tools/genreadme

## readme-check: Verify README.md matches template output
readme-check: sync-controls
	$(GOCMD) run ./internal/tools/genreadme -check

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
#   make sync-public-dry          # preview what would be copied/deleted
#   make sync-public              # sync and show summary
#   make sync-public MSG="v0.1.0 release"  # sync, commit, push

PUBLIC_DEST ?= $(HOME)/work/stave/
SYNC_EXCLUDES = \
	--exclude='.git/' \
	--exclude='dev/' \
	--exclude='.tmp/' \
	--exclude='/stave' \
	--exclude='.lychee.toml' \
	--exclude='dist/' \
	--exclude='dist-local/'

## sync-public-dry: Preview sync to public repo (no changes)
sync-public-dry:
	rsync -avn --delete $(SYNC_EXCLUDES) ./ $(PUBLIC_DEST)

## sync-public: Sync to public repo
sync-public:
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
