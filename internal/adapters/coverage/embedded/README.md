data/alternatives/prowler-iam.yaml   — declarative list of Prowler's IAM checks
data/alternatives/prowler-s3.yaml    — declarative list of Prowler's S3 checks                                            
                                                                                                                            
Each is a flat YAML with tool: prowler, domain: iam|s3, and a list of check IDs (e.g., iam_avoid_root_usage, s3_bucket_acl_prohibited) — the exact identifiers Prowler emits.                                                          
                                                                                         
Why they're required:                
                                          
  1. Per-domain coverage math. Each Stave control YAML carries an alternatives: annotation declaring which external tool    
  checks it overlaps with (prowler:iam_avoid_root_usage, etc.). The coverage aggregator at                                  
  internal/core/evaluation/coverage/coverage.go joins those annotations against these inventory files to compute "Stave
  covers N of M Prowler IAM checks" per domain.                                                                             
  2. "Not covered" gap reports. With the inventory present, the aggregator can list the specific Prowler checks no Stave
  control claims — that's the actionable gap list for the catalog roadmap. Without the inventory, the aggregator can compute
   coverage counts but not what's missing (it has the numerator from control annotations; the inventory is the denominator).
  3. _unmatched integrity check. When a control's alternatives: block references a (tool, check_id) pair the inventory
  doesn't know about, the aggregator routes it to a _unmatched domain bucket. That surfaces typos and outdated check names
  without silently dropping them.
  4. Build-time embed. The Makefile copies data/alternatives/* into internal/adapters/coverage/embedded/ before go build
  (you can see it in every make build output: cp -R data/alternatives/* internal/adapters/coverage/embedded/). The values
  are baked into the binary so coverage works without a side-channel data file at runtime.
  5. Doc generation. internal/tools/genmethodologycoverage/main.go writes the per-tool methodology coverage docs from these
  inventories — markdown tables under docs/coverage/ showing the join of Stave annotations against the upstream check list.
  The tool emits Inventory: data/alternatives/<tool>-<domain>.yaml as a citation in the output so the source is traceable.

When to update them: the file headers say it explicitly — "Update this list when Prowler adds, removes, or renames an IAM check." Source for both files is prowler-cloud/prowler/prowler/providers/aws/services/{iam,s3}/ on the upstream master branch. Adding more tools (Trivy, Checkov, cloudsploit) or more domains is a "add a new YAML following the same shape" exercise — the aggregator picks up new files automatically.

The orthogonal stave-coverage repo (separate Go project at stave-coverage/, per the CLAUDE.md note) is what consumes the embedded inventory at runtime — stave-coverage check --report report.json --format table produces the "X of Y Prowler checks covered" view per domain.
