---
name: stave-write-your-first-control
description: Author, test, and verify a custom Stave control YAML for an organization-specific security policy, using an existing control as a template
triggers:
  - write a control
  - author a control
  - custom detection
  - add a security policy to Stave
  - new control YAML
requires:
  - a built stave binary (run stave-setup first)
---

# stave-write-your-first-control

## What this skill does
Walks you through authoring a new control YAML, then proves it fires on the
positive case and stays quiet on the negative case. Always start from the
closest existing control — do NOT invent a new field-naming convention.

**Time:** ~20 minutes. **No AWS needed.**

## Steps

### 1. State the property to detect
e.g. "An IAM user must not have admin access" (you'll generalize from here).

### 2. Find the closest existing control and read it
```
./stave search "<keywords for your property>"
find controls -name '*<ID-fragment>*'
cat controls/.../<that-control>.yaml
```
Note the shape: `id`, `name`, `domain`, `severity`, `type`,
`unsafe_predicate` (the field + op + value that triggers), `observation_fields`
(every field it reads), `remediation`, and embedded `tests:`.

### 3. Copy and adapt into your own controls dir
```
mkdir -p ~/my-controls
cp controls/.../<template>.yaml ~/my-controls/CTL.MYORG.EXAMPLE.001.yaml
```
Edit: `id`, `name`, the `unsafe_predicate` field path, `observation_fields`, and
`remediation`. Keep field naming consistent with the template family — reuse the
existing `properties.identity.…` / `properties.storage.…` paths; don't invent new ones.

### 4. Add embedded tests (a VIOLATION and a PASS case)
In the YAML, add a `tests:` block with one asset that should fire (`present: true`)
and one that should not (`present: false`). Then:
```
./stave test --controls ~/my-controls
```
Expect your control's tests to pass (it fires on the VIOLATION asset, not the PASS asset).

### 5. Test against a standalone observation
Positive (must fire):
```
mkdir -p ~/ctl-test/pos
# write an obs.v0.1 file (source: deployed) with your trigger field == true
./stave apply --controls ~/my-controls --observations ~/ctl-test/pos/ --now 2026-01-02T00:00:00Z
```
Negative (must NOT fire): same but with the trigger field == false → 0 violations.

## Success
You authored a control, gave it pass/fail tests, and watched it fire on the
positive case only. You can now encode org-specific policy in Stave.

(To add it to the built-in catalog rather than a side dir, drop the YAML under
`controls/<domain>/` and run `make build` to sync it into the embedded catalog.)
