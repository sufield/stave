package external

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/sir"
)

func TestParseCommand(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want []string
	}{
		{"simple", "python3 -m stave_solver.main", []string{"python3", "-m", "stave_solver.main"}},
		{"docker", "docker run --rm -i stave-solver:latest", []string{"docker", "run", "--rm", "-i", "stave-solver:latest"}},
		{"empty", "", nil},
		{"whitespace", "   \t\n  ", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			inv, err := ParseCommand(tc.raw)
			if err != nil {
				t.Fatalf("ParseCommand: %v", err)
			}
			if len(inv.Argv) != len(tc.want) {
				t.Fatalf("argv length: want %d, got %d (%v)", len(tc.want), len(inv.Argv), inv.Argv)
			}
			for i := range tc.want {
				if inv.Argv[i] != tc.want[i] {
					t.Errorf("argv[%d]: want %q, got %q", i, tc.want[i], inv.Argv[i])
				}
			}
		})
	}
}

func TestPythonSolverSource_EmptyArgvErrors(t *testing.T) {
	src := NewPythonSolverSource(SolverInvocation{}, sir.NewBuilder(), time.Second, nil)
	_, err := src.ProduceFindings(context.Background(), evaluation.FindingRequest{})
	if err == nil {
		t.Fatalf("expected error for empty argv")
	}
}

func TestPythonSolverSource_NilBuilderErrors(t *testing.T) {
	src := NewPythonSolverSource(SolverInvocation{Argv: []string{"true"}}, nil, time.Second, nil)
	_, err := src.ProduceFindings(context.Background(), evaluation.FindingRequest{})
	if err == nil {
		t.Fatalf("expected error for nil builder")
	}
}

// TestPythonSolverSource_EchoSolverReturnsEmptyFindings verifies
// the subprocess pipeline end-to-end using a tiny shell script
// that ignores stdin and prints "[]". This is enough to prove
// stdin-stdout-unmarshal works without depending on a real
// Python solver being installed.
func TestPythonSolverSource_EchoSolverReturnsEmptyFindings(t *testing.T) {
	src := NewPythonSolverSource(
		SolverInvocation{Argv: []string{"/bin/sh", "-c", "cat>/dev/null;printf '[]'"}},
		sir.NewBuilder(),
		2*time.Second,
		nil,
	)
	out, err := src.ProduceFindings(context.Background(), evaluation.FindingRequest{
		Now: time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("ProduceFindings: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("echo solver must return empty findings, got %d", len(out))
	}
}

func TestPythonSolverSource_NonZeroExitErrors(t *testing.T) {
	src := NewPythonSolverSource(
		SolverInvocation{Argv: []string{"/bin/sh", "-c", "cat>/dev/null;exit 2"}},
		sir.NewBuilder(),
		2*time.Second,
		nil,
	)
	_, err := src.ProduceFindings(context.Background(), evaluation.FindingRequest{})
	if err == nil {
		t.Fatalf("expected error on non-zero exit")
	}
	if !errors.Is(err, ErrSolverFailed) {
		t.Errorf("expected ErrSolverFailed sentinel, got %v", err)
	}
}

func TestPythonSolverSource_MalformedOutputErrors(t *testing.T) {
	src := NewPythonSolverSource(
		SolverInvocation{Argv: []string{"/bin/sh", "-c", "cat>/dev/null;printf 'not json'"}},
		sir.NewBuilder(),
		2*time.Second,
		nil,
	)
	_, err := src.ProduceFindings(context.Background(), evaluation.FindingRequest{})
	if err == nil {
		t.Fatalf("expected error on malformed output")
	}
	if !errors.Is(err, ErrSolverOutput) {
		t.Errorf("expected ErrSolverOutput sentinel, got %v", err)
	}
}
