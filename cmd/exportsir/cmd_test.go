package exportsir

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

// stubCtlRepo / stubObsRepo are minimal in-memory implementations
// of the compose factory targets. The tests drive run() without
// hitting the filesystem or the real CLI bootstrap.
type stubCtlRepo struct {
	ctls []controldef.ControlDefinition
}

func (r *stubCtlRepo) LoadControls(_ context.Context, _ string) ([]controldef.ControlDefinition, error) {
	return r.ctls, nil
}

type stubObsRepo struct{ snaps []asset.Snapshot }

func (r *stubObsRepo) LoadSnapshots(_ context.Context, _ string) (appcontracts.LoadResult, error) {
	return appcontracts.LoadResult{Snapshots: r.snaps}, nil
}

func ctlFactory(ctls []controldef.ControlDefinition) func() (appcontracts.ControlRepository, error) {
	return func() (appcontracts.ControlRepository, error) {
		return &stubCtlRepo{ctls: ctls}, nil
	}
}

func obsFactory(snaps []asset.Snapshot) func() (appcontracts.ObservationRepository, error) {
	return func() (appcontracts.ObservationRepository, error) {
		return &stubObsRepo{snaps: snaps}, nil
	}
}

// celFactory returns a stub PredicateEval that always reports
// "secure". export-sir's happy path doesn't depend on per-asset
// evaluation outcomes; the lifecycle source still exercises the
// engine pipeline.
func celFactory() func() (controldef.PredicateEval, error) {
	return func() (controldef.PredicateEval, error) {
		return func(_ controldef.ControlDefinition, _ asset.Asset, _ []asset.CloudIdentity) (bool, error) {
			return false, nil
		}, nil
	}
}

func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatalf("parse time %q: %v", s, err)
	}
	return parsed
}

func TestRun_EmitsSIRJSONWithCrossAccountRoleHops(t *testing.T) {
	// Cross-account fixture: AppRole grants AssumeRole on
	// CrossAdmin (different account). The output must contain
	// the final-role ARN and "cross_account":true — the
	// success criterion phrased as "stave export-sir for a
	// cross-account fixture now shows the transitive role hops
	// in the JSON".
	appRolePolicies := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Resource":"arn:aws:iam::444455556666:role/Admin"}]}`
	adminPolicies := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`
	adminTrust := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Resource":"arn:aws:iam::111122223333:role/AppRole"}]}`
	permissiveSCP := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`

	snap := asset.Snapshot{
		Source:     asset.SourceDeployed,
		CapturedAt: mustTime(t, "2026-05-01T11:00:00Z"),
		Identities: []asset.CloudIdentity{
			{
				ID:     asset.ID("arn:aws:iam::111122223333:role/AppRole"),
				Type:   kernel.AssetType("aws_iam_role"),
				Vendor: kernel.Vendor("aws"),
				Properties: map[string]any{
					"identity": map[string]any{
						"policies_json": appRolePolicies,
						"scp_json":      permissiveSCP,
					},
				},
			},
			{
				ID:     asset.ID("arn:aws:iam::444455556666:role/Admin"),
				Type:   kernel.AssetType("aws_iam_role"),
				Vendor: kernel.Vendor("aws"),
				Properties: map[string]any{
					"identity": map[string]any{
						"policies_json":     adminPolicies,
						"trust_policy_json": adminTrust,
						"scp_json":          permissiveSCP,
					},
				},
			},
		},
	}

	var buf bytes.Buffer
	err := run(t.Context(), &buf, &options{
		ControlsDir:     "controls",
		ObservationsDir: "observations",
		Format:          "json",
		Now:             "2026-05-01T12:00:00Z",
	}, ctlFactory(nil), obsFactory([]asset.Snapshot{snap}), celFactory())
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	body := buf.String()
	if !strings.Contains(body, `"arn:aws:iam::444455556666:role/Admin"`) {
		t.Errorf("missing cross-account final role: %s", body)
	}
	if !strings.Contains(body, `"cross_account": true`) {
		t.Errorf("missing cross_account=true: %s", body)
	}
	if !strings.Contains(body, `"evaluated_at": "2026-05-01T12:00:00Z"`) {
		t.Errorf("evaluated_at not pinned to --now: %s", body)
	}
}

func TestRun_RejectsNonJSONFormat(t *testing.T) {
	var buf bytes.Buffer
	err := run(t.Context(), &buf, &options{Format: "yaml"},
		ctlFactory(nil), obsFactory(nil), celFactory())
	if err == nil {
		t.Fatalf("expected error for non-json format")
	}
	if !strings.Contains(err.Error(), "--format must be json") {
		t.Errorf("error should explain format: got %q", err.Error())
	}
}

func TestRun_RejectsMalformedNow(t *testing.T) {
	var buf bytes.Buffer
	err := run(t.Context(), &buf, &options{Format: "json", Now: "not-a-time"},
		ctlFactory(nil), obsFactory(nil), celFactory())
	if err == nil {
		t.Fatalf("expected error for malformed --now")
	}
	if !strings.Contains(err.Error(), "RFC3339") {
		t.Errorf("error should mention RFC3339: got %q", err.Error())
	}
}

func TestRun_ProducesByteIdenticalOutputAcrossRuns(t *testing.T) {
	// Determinism gate: identical inputs + identical --now →
	// byte-identical JSON. A regression here would catch
	// non-stable map iteration or a wall-clock leak.
	snap := asset.Snapshot{
		Source:     asset.SourceDeployed,
		CapturedAt: mustTime(t, "2026-05-01T10:00:00Z"),
		Assets: []asset.Asset{
			{
				ID:     asset.ID("arn:aws:s3:::stable"),
				Type:   kernel.AssetType("aws_s3_bucket"),
				Vendor: kernel.Vendor("aws"),
				Properties: map[string]any{
					"policy_json": `{"Version":"2012-10-17","Statement":[{"Sid":"R","Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::stable/*"}]}`,
					"storage":     map[string]any{"ownership_controls": "ObjectWriter"},
				},
			},
		},
	}

	var first, second bytes.Buffer
	for _, w := range []*bytes.Buffer{&first, &second} {
		if err := run(t.Context(), w, &options{
			Format: "json",
			Now:    "2026-05-01T12:00:00Z",
		}, ctlFactory(nil), obsFactory([]asset.Snapshot{snap}), celFactory()); err != nil {
			t.Fatalf("run: %v", err)
		}
	}
	if first.String() != second.String() {
		t.Fatalf("non-deterministic output:\n#1: %s\n#2: %s", first.String(), second.String())
	}

	// Decoded shape must be well-formed JSON.
	var doc map[string]any
	if err := json.Unmarshal(first.Bytes(), &doc); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}
}
