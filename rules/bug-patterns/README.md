# Bug Pattern Rules

ast-grep rules that encode known Stave bug classes. Each rule was mined
from a real bug in the git history. When a code change matches a known
bug shape, CI fails before tests even run.

## Adding a new rule
1. Find the bug-fixing commit: `git show <hash>`
2. Extract the structural pattern that was wrong
3. Write a YAML rule that matches the wrong pattern
4. Test: `ast-grep scan --rule rules/bug-patterns/<rule>.yml <file-with-known-bug>`
5. Verify clean code does NOT match: `ast-grep scan --rule rules/bug-patterns/<rule>.yml <fixed-file>`
6. Verify zero matches on the current codebase: `make lint-patterns`

## Bug classes

| Rule | Class | Origin |
|------|-------|--------|
| unchecked-type-assertion | Unchecked `x.(Type)` panics | Jul 17 2026 bughunt |
| duplicated-arn-parser | Duplicate parseARN outside arn.go | Recurring across sessions |
| case-sensitive-extension | `HasSuffix(name, ".json")` skips `.JSON` | Jun 28-29 2026 bughunt |
| case-sensitive-action-match | IAM action `==` instead of EqualFold | Jun 24 2026 bughunt |
| map-iteration-to-output | Map range → append without sort | Jun 30, Jul 14-18 2026 bughunt |
| bare-findings-access | `.Findings` without `--include-atomic` | CLAUDE.md policy |
| severity-string-comparison | Alphabetical severity sort | Jul 16 2026 bughunt |
| early-return-dead-code | Code after unconditional return | HAZOP + Jun 29 2026 bughunt |
| substring-contains-for-type | `strings.Contains` on raw JSON for type detection | Jul 17 2026 bughunt |
| nil-map-write | Write to `var m map[K]V` without make() | Standard Go bug class |
| missing-scope-filter | AppliesToVendor without AppliesToAssetType | Jun 2 2026 CloudGoat |
| pointer-stringify | fmt.Sprintf on pointer value | Jun 27 2026 bughunt |
| expiry-date-unchecked | ExpiryDate without format validation | Jun 26, Jul 19 2026 bughunt |
| worsening-ratio-bug | Negative/negative division = false positive | Jul 4 2026 bughunt |
| bare-time-now | `time.Now()` in app layer bypasses Clock interface | 013c9e89f5, 49680ca22b |
| shallow-glob | `filepath.Glob` misses subdirectories | 49680ca22b |
| os-exit-in-library | `os.Exit` in library code prevents error handling | Architecture policy |
