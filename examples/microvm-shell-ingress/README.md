# MICROVM-021 — Production MicroVM SHELL_INGRESS Connector

Reasoning spec for `CTL.LAMBDA.MICROVM.SHELLINGRESS.001`. Shell access is
structurally impossible unless the MicroVM was launched with the SHELL_INGRESS
connector — so a production MicroVM that *has* it has shell access enabled at
the infrastructure layer. **MICROVM-021 (infrastructure) > the SHELLAUTH IAM
control in assurance**: IAM restricts who may mint a shell token; the connector
decides whether a shell is possible at all.

Proves the production-identification join (env tag OR production account/OU) two
ways. `PATH "$HOME/.local/bin:$PATH" bash run.sh`:
```
vuln  souffle=FINDING  z3=sat      prod tag + SHELL_INGRESS                 (FAIL)
fp    souffle=NONE     z3=unsat    prod tag, no SHELL_INGRESS               (PASS)
fn    souffle=FINDING  z3=sat      no tag, prod ACCOUNT + SHELL_INGRESS     (FAIL)
```
The `fn` row is the false-negative trap: a tagless MicroVM is still production
by account/OU.
