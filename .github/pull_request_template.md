## Summary

<!-- What does this PR do and why? -->

## Control changes

<!-- Remove this section if the PR does not touch controls/ -->

- [ ] This PR adds or modifies Stave controls
- [ ] I ran `differential-review` on the control diff — security-focused review
      for false negatives and edge-case coverage (see CONTRIBUTING.md)
- [ ] I ran `fp-check` on any new control's false-positive trap

> The **Control Security Review** check is required when `controls/**` changes.
> It passes once the `differential-review` box above is checked.

## Checklist

- [ ] `make consistency-check` passes
- [ ] Goldens regenerated if control YAML changed (`make regenerate-goldens`)
