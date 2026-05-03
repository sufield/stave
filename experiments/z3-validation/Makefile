.PHONY: setup build experiment-s3 experiment-iam experiment-kms experiment-network experiment-cognito experiment-cross experiment-all clean

# Verify Z3 is reachable on PATH. The CGO binding finds headers /
# libs through pkg-config; we only check the CLI here so the
# failure mode is "z3 not installed" rather than a CGO compile
# error five files deep.
setup:
	@z3 --version >/dev/null 2>&1 || \
		(echo "Z3 not installed. brew install z3 / apt install z3 libz3-dev" && exit 1)
	go build ./...
	@echo "Setup complete."

build: setup
	go build -o z3-validation ./cmd/

# Per-service runs. Each target builds the binary and invokes it
# with the matching --service flag. The fixture root points at
# the repo's testdata tree by default; override with
# `make experiment-s3 FIXTURES=other/path` if you want to scope
# the experiment to a smaller corpus.
REPO_ROOT := $(shell cd ../.. && pwd)
FIXTURES  ?= $(REPO_ROOT)/testdata
STAVE     ?= $(shell which stave 2>/dev/null || echo $(REPO_ROOT)/stave)
CONTROLS  ?= $(REPO_ROOT)/controls

experiment-s3: build
	./z3-validation \
		--service s3 \
		--fixture-root $(FIXTURES) \
		--stave-binary $(STAVE) \
		--controls $(CONTROLS)/s3 \
		--output results/s3/

experiment-iam: build
	./z3-validation \
		--service iam \
		--fixture-root $(FIXTURES) \
		--stave-binary $(STAVE) \
		--controls $(CONTROLS) \
		--output results/iam/

experiment-kms: build
	./z3-validation \
		--service kms \
		--fixture-root $(FIXTURES) \
		--stave-binary $(STAVE) \
		--controls $(CONTROLS) \
		--output results/kms/

experiment-network: build
	./z3-validation \
		--service network \
		--fixture-root $(FIXTURES) \
		--stave-binary $(STAVE) \
		--controls $(CONTROLS) \
		--output results/network/

experiment-cognito: build
	./z3-validation \
		--service cognito \
		--fixture-root $(FIXTURES) \
		--stave-binary $(STAVE) \
		--controls $(CONTROLS) \
		--output results/cognito/

experiment-cross: build
	./z3-validation \
		--service crossservice \
		--fixture-root $(FIXTURES) \
		--stave-binary $(STAVE) \
		--controls $(CONTROLS) \
		--output results/crossservice/

# Run all individual services in dependency order. Cross-service
# composition is intentionally omitted; per the experiment plan
# it runs only after every individual service clears the >95%
# agreement gate.
experiment-all: experiment-s3 experiment-iam experiment-kms experiment-network experiment-cognito

clean:
	rm -rf results/ z3-validation
