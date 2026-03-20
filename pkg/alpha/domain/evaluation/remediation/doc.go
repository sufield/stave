// Package remediation generates machine-readable remediation plans from
// evaluation findings.
//
// [Planner] delegates to specialist handlers per control class to produce
// step-by-step remediation guidance. [Mapper] translates findings into
// remediation structures, [Baseline] computes current vs. target state, and
// grouping logic clusters similar plans for batch presentation.
package remediation
