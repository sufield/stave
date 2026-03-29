# Adding Stave to awesome-go

Step-by-step instructions for submitting stave to
[awesome-go](https://github.com/avelino/awesome-go).

Public repo: https://github.com/sufield/stave

---

## Prerequisites Checklist

The CI bot runs automated checks on every PR. All blocking checks must
pass before a maintainer reviews.

### Blocking (must pass)

| Requirement | Stave Status | Action Needed |
|---|---|---|
| Repository is public and not archived | OK | None |
| `go.mod` at repo root | OK | None |
| At least one semver tag (vX.Y.Z) | OK — v0.0.1, v0.0.2, v0.0.3 | None |
| pkg.go.dev loads | OK | None |
| Go Report Card grade A- or higher | OK — A+ (0 issues across 700 files) | None |
| PR body includes forge, pkg.go.dev, goreportcard links | N/A | Fill in at PR time |
| Single package per PR | N/A | Standard |
| Description ends with period | N/A | Write carefully |
| Alphabetical ordering maintained | N/A | Place correctly |
| Format: `- [name](url) - Description.` | N/A | Follow exactly |

### Non-Blocking (warnings, but maintainers notice)

| Requirement | Stave Status | Action Needed |
|---|---|---|
| Recognized open source license | OK — Apache 2.0 | None |
| First commit 5+ months old | FAIL — repo created 2026-03-06 (< 1 month) | **Wait until August 2026** |
| GitHub Actions CI configured | Check if present | Add CI workflow if missing |
| README present | OK | None |
| Coverage link (Codecov/Coveralls) | Not configured | Set up Codecov |
| Test coverage ≥80% | Needs improvement | Increase coverage |
| Link text matches repo name | N/A | Use "stave" |
| No superlatives in description | N/A | Write factually |

---

## Blockers to Resolve

### 1. Repository Age (earliest submission: August 2026)

The repo was created 2026-03-06. awesome-go requires "at least 5 months
of history since the first commit." This is a non-blocking CI warning
but maintainers routinely reject young repos.

**Earliest eligible date: approximately 2026-08-06.**

Use the waiting period to address items 2 and 3 below.

### 2. Set Up Coverage Reporting

Set up Codecov or Coveralls with a GitHub Actions workflow. Add a
coverage badge to README.md. awesome-go's CI checks that the coverage
link is reachable.

```yaml
# .github/workflows/ci.yml (coverage step)
- name: Upload coverage
  uses: codecov/codecov-action@v4
  with:
    file: coverage.out
```

### 3. Increase Test Coverage

awesome-go expects ≥80% for standard packages, ≥90% for data-focused
packages. Priority areas to improve:

- `cmd/` packages — add integration tests
- `internal/tools/` packages — add basic tests
- `internal/ui/` — add basic tests

### 4. Go Report Card

Already A+ with 0 issues. No action needed. Recheck before submission:
```
https://goreportcard.com/report/github.com/sufield/stave
```

---

## Submission Steps

### Step 1: Choose the Category

Stave evaluates cloud configuration safety using declarative controls.
The best fit in awesome-go is **Security**. It sits alongside tools
like `age`, `lego`, and `sops` — security-focused CLI tools.

### Step 2: Write the Description

Must be concise, factual, no marketing language, end with period.

```
- [stave](https://github.com/sufield/stave) - Configuration safety engine that detects insecure cloud configurations using declarative controls and local snapshots.
```

Avoid superlatives ("best", "fastest", "powerful") — the bot warns
and maintainers reject.

### Step 3: Fork and Edit

```bash
git clone https://github.com/<your-username>/awesome-go.git
cd awesome-go
git checkout -b add-stave
```

Edit `README.md`:
- Find the **Security** category
- Add the entry in **alphabetical order** (s → between "securego" and "simple-scrypt" or wherever "stave" falls)
- Use exact format: `- [stave](https://github.com/sufield/stave) - Description.`

### Step 4: Prepare PR Body

The PR description **must** include these links:

```
Forge link: https://github.com/sufield/stave
pkg.go.dev: https://pkg.go.dev/github.com/sufield/stave
goreportcard.com: https://goreportcard.com/report/github.com/sufield/stave
Coverage: https://codecov.io/gh/sufield/stave
```

### Step 5: Submit PR

```bash
git add README.md
git commit -m "Add stave to Security"
git push origin add-stave
```

Open a PR from your fork to `avelino/awesome-go:main`.

### Step 6: Wait for CI

The bot runs within minutes. Fix any failures and force-push. Common
failure causes:
- Alphabetical order wrong
- Description doesn't end with period
- Links in PR body don't match README entry
- Link text doesn't match repo name

### Step 7: Maintainer Review

After CI passes, a maintainer reviews manually. They check:
- Does the project actually work?
- Is it useful to the Go community?
- Does it fit the category?
- Is documentation adequate?

Response time varies from days to weeks.

---

## Timeline

| When | Action |
|---|---|
| Now | Set up GitHub Actions CI with coverage |
| Now | Increase test coverage toward 80% |
| Now | Add Codecov badge to README |
| August 2026 | Repo reaches 5-month age threshold |
| August 2026 | Recheck Go Report Card grade |
| August 2026 | Submit PR to awesome-go |
