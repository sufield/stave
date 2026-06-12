package stave

import (
	"github.com/sufield/stave/pkg/stave/internal/nepcmd"
)

// NepPrincipalConfig parameterizes [ResolvePrincipal]. Mirrors the
// `stave permissions principal` flags.
type NepPrincipalConfig = nepcmd.PrincipalConfig

// NepResourceConfig parameterizes [ResolveResourceAccess]. Mirrors the
// `stave permissions resource` flags.
type NepResourceConfig = nepcmd.ResourceConfig

// NepSummaryConfig parameterizes [NepSummary]. Mirrors the
// `stave permissions summary` flags.
type NepSummaryConfig = nepcmd.SummaryConfig

// ResolvePrincipal resolves the net effective permissions for a single IAM
// principal (all six AWS policy layers) and renders them (table | json),
// returning the rendered bytes. Bad format / load failure / missing principal
// stay plain (exit 4). It is the library entry point behind
// `stave permissions principal`.
func ResolvePrincipal(cfg NepPrincipalConfig) ([]byte, error) {
	return nepcmd.ResolvePrincipal(cfg) //nolint:wrapcheck // engine already wrapped; preserve exit 4.
}

// ResolveResourceAccess shows which principals have resolved effective access
// to a resource ARN, rendering the view (table | json | dot). It returns the
// rendered bytes, operator warnings (for stderr), and whether any
// non-designated principal has access (the caller maps that to exit 1 via
// ui.ErrSecurityAuditFindings). Load/render failures stay plain (exit 4). It
// is the library entry point behind `stave permissions resource`.
func ResolveResourceAccess(cfg NepResourceConfig) (output []byte, warnings []string, hasFindings bool, err error) {
	return nepcmd.ResolveResourceAccess(cfg) //nolint:wrapcheck // engine already wrapped; preserve exit codes.
}

// NepSummary aggregates net-effective-permission metrics across all
// principals in the snapshot and renders them (table | json), returning the
// rendered bytes. Load/render failures stay plain (exit 4). It is the library
// entry point behind `stave permissions summary`.
func NepSummary(cfg NepSummaryConfig) ([]byte, error) {
	return nepcmd.NepSummary(cfg) //nolint:wrapcheck // engine already wrapped; preserve exit 4.
}
