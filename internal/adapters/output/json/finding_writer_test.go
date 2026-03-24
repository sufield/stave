package json

import (
	"strings"
	"testing"
	"time"

	appeval "github.com/sufield/stave/internal/app/eval"
	contractvalidator "github.com/sufield/stave/internal/contracts/validator"
	"github.com/sufield/stave/internal/env"
	"github.com/sufield/stave/internal/platform/crypto"
	"github.com/sufield/stave/pkg/alpha/domain/evaluation"
	"github.com/sufield/stave/pkg/alpha/domain/evaluation/remediation"
	"github.com/sufield/stave/pkg/alpha/domain/kernel"
)

func TestWriteFindings_BareJSON(t *testing.T) {
	w := NewFindingWriter(false)
	enricher := remediation.NewMapper(crypto.NewHasher())
	result := evaluation.Result{
		Run: evaluation.RunInfo{
			StaveVersion:      "test",
			Offline:           true,
			Now:               time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC),
			MaxUnsafeDuration: kernel.Duration(24 * time.Hour),
			Snapshots:         0,
		},
		Summary: evaluation.Summary{
			AssetsEvaluated: 0,
			AttackSurface:   0,
			Violations:      0,
		},
		Findings: nil,
	}

	enriched, err := appeval.Enrich(enricher, nil, result)
	if err != nil {
		t.Fatal(err)
	}
	data, err := w.MarshalFindings(enriched)
	if err != nil {
		t.Fatalf("MarshalFindings() error = %v", err)
	}
	out := string(data)

	if strings.Contains(out, `"ok":`) {
		t.Fatalf("unexpected envelope in output: %s", out)
	}
	if !strings.Contains(out, `"kind":"evaluation"`) {
		t.Fatalf("missing evaluation kind: %s", out)
	}
	if !strings.Contains(out, `"findings":[]`) {
		t.Fatalf("expected normalized empty findings array: %s", out)
	}
}

func TestShouldValidateFindingContract_EnvSwitches(t *testing.T) {
	t.Setenv(env.DevValidateFindings.Name, "")
	t.Setenv(env.Debug.Name, "")
	if shouldValidateFindingContract() {
		t.Fatal("expected validation toggle to be false by default")
	}

	t.Setenv(env.DevValidateFindings.Name, "1")
	if !shouldValidateFindingContract() {
		t.Fatal("expected validation toggle to be true for STAVE_DEV_VALIDATE_FINDINGS=1")
	}

	t.Setenv(env.DevValidateFindings.Name, "")
	t.Setenv(env.Debug.Name, "1")
	if !shouldValidateFindingContract() {
		t.Fatal("expected validation toggle to be true for STAVE_DEBUG=1")
	}
}

func TestValidateFindings_InvalidFinding(t *testing.T) {
	err := validateFindings(contractvalidator.New(), []remediation.Finding{{}})
	if err == nil {
		t.Fatal("expected contract validation error for empty finding payload")
	}
}
