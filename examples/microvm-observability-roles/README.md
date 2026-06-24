# MICROVM-022 — Production MicroVM Observability Roles

Reasoning spec for `CTL.LAMBDA.MICROVM.OBSERVABILITY.ROLES.001`. A production
MicroVM must have an execution role (runtime logs + AWS-service access) and its
source image a build role (build logs). Both are AWS-optional; in production
their absence is an audit blind spot.

`PATH "$HOME/.local/bin:$PATH" bash run.sh`:
```
vuln  souffle=no_exec_role   z3=sat      prod, no execution role         (FAIL)
fp    souffle=NONE           z3=unsat    prod, exec + build present      (PASS)
fn    souffle=no_build_role  z3=sat      prod, image has no build role   (FAIL)
```
The `fn` row catches the image-level build-role gap at the MicroVM that runs
from it.
