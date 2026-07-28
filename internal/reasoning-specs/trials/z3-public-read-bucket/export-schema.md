# Stave SMT-LIB Export Schema

Produced by `stave export-sir --format smt2`.

The output is SMT-LIB v2 with three layers:

1. **Logic header** — `(set-logic ALL)`. The fact base uses
   uninterpreted predicates over `String` sort, so any logic that
   includes `UF` (uninterpreted functions) suffices; `ALL` is the
   conservative default.

2. **Predicate declarations** — one `(declare-fun <name> (String
   String) Bool)` per predicate the catalog projects. Every
   predicate is binary; the first argument is the asset id
   (typically an ARN), the second is the value (a string — even
   booleans are projected as `"true"` / `"false"` for solver
   compatibility).

3. **Ground assertions and closed-world axioms** — one
   `(assert (has_x "subject" "object"))` per fact, plus one
   universal axiom per predicate stating the predicate is true
   ONLY for the explicitly-asserted pairs:
   ```
   (assert (forall ((x String) (y String))
     (=> (has_public_read x y)
         (or (and (= x "arn:...") (= y "true"))
             ...))))
   ```

   The closed-world axioms make the fact base a true reflection of
   the observation snapshot: a predicate value that wasn't observed
   is provably false, not just absent.

The file is **facts only** by design. A reasoning consumer appends
its own `(check-sat)`, `(get-value …)`, or `(get-model)` queries
before invoking the solver.

## Common predicates

| Predicate | Meaning |
|---|---|
| `has_type(arn, type)` | Asset type (`"aws_s3_bucket"`, `"aws_iam_role"`, …) |
| `has_public_read(arn, "true"|"false")` | Bucket policy / ACL admits anonymous read |
| `has_public_access_blocked(arn, "true"|"false")` | All four PAB flags enabled |
| `has_severity(controlID, severity)` | Control severity for control facts |
| `contributed_by(arn, controlID)` | Asset failed control |
| `trusts_service(role, service)` | IAM role trusts a service principal |

The full predicate set is determined by the catalog at export time;
new controls that read new property paths add new predicates.

## Witness extraction

When `(check-sat)` returns `sat`, the consumer can ask for the
binding of any free variable in the query via
`(get-value (<var>))`. The solver returns the bound value as a
ground term — typically the asset ARN that satisfied the query's
conjunction.
