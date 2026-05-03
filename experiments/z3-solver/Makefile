.PHONY: check-z3 build test run-compatibility run-conflict run-shadow run-invariant clean

# Verify the Z3 binary is reachable. The CGO binding discovers
# headers / libs via pkg-config; we only check the CLI here so
# the failure mode is "z3 not installed" rather than a CGO
# compile error five files deep.
check-z3:
	@z3 --version >/dev/null 2>&1 || \
		(echo "Z3 not installed. Install with: brew install z3 / apt install libz3-dev z3" && exit 1)

build: check-z3
	go build -o stave-z3 ./cmd/stave-z3

test: check-z3
	go test ./... -count=1

# Run a compatibility query against the iam_deny_overrides_allow
# fixture. The expected verdict is unsatisfiable: AWS Deny wins.
run-compatibility: build
	./stave-z3 \
		--observations testdata/known_answers/iam_deny_overrides_allow/observations \
		--query compatibility \
		--principal "arn:aws:iam::111122223333:role/ServiceB" \
		--action s3:GetObject \
		--resource "arn:aws:s3:::deny-test-bucket/*" | jq .

# Run conflict detection. Looks for any (P, A, R) where one Allow
# matches and one Deny matches. The fixture above contains exactly
# that — the expected verdict is satisfiable with a witness.
run-conflict: build
	./stave-z3 \
		--observations testdata/known_answers/iam_deny_overrides_allow/observations \
		--query conflict | jq .

# Verify a single invariant against an open universe. Pick any
# control ID from `stave controls list` for the catalog.
run-invariant: build
	./stave-z3 \
		--observations testdata/known_answers/iam_deny_overrides_allow/observations \
		--query invariant \
		--invariant CTL.S3.POLICY.EXISTS.001 | jq .

# Shadow mode: compare Z3 with Stave CEL across the loaded
# catalog. Use a real e2e fixture with diverse findings.
run-shadow: build
	./stave-z3 \
		--observations ../../testdata/e2e/aws-s3-obs-public/observations \
		--query shadow | jq .

clean:
	rm -f stave-z3
