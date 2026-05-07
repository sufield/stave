// z3prove is a sibling Go module to keep its CGO dependency on
// libz3 isolated from the parent stave module's vendored tree.
// Stave's main binary stays CGO_ENABLED=0; only this prover
// links libz3.
module local/iter13-z3prove

go 1.21

require github.com/aclements/go-z3 v0.0.0-20220809013456-4675d5f90ca5
