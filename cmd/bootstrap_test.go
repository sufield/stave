package cmd

import (
	"errors"
	"testing"

	"github.com/spf13/cobra"
	"github.com/sufield/stave/cmd/cmdutil"
)

func TestBootstrapPipeline_OrderAndCount(t *testing.T) {
	app := &App{}
	phases := app.bootstrapPipeline()
	if len(phases) != 5 {
		t.Fatalf("expected 5 phases, got %d", len(phases))
	}
	expected := []string{"context", "config", "validate", "logging", "enrich"}
	for i, p := range phases {
		if p.Name != expected[i] {
			t.Errorf("phase %d: got %q, want %q", i, p.Name, expected[i])
		}
	}
}

func TestCheckConfigHealth_AnnotatedCommand(t *testing.T) {
	app := &App{}
	cfgErr := errors.New("bad config")

	// Non-annotated command should fail.
	cmd := &cobra.Command{Use: "apply"}
	if err := app.checkConfigHealth(cmd, cfgErr); err == nil {
		t.Fatal("expected error for non-tolerant command")
	}

	// Annotated command should pass.
	cmd2 := &cobra.Command{
		Use:         "init",
		Annotations: map[string]string{cmdutil.AnnotationConfigOptional: "true"},
	}
	if err := app.checkConfigHealth(cmd2, cfgErr); err != nil {
		t.Fatalf("expected nil for annotated command, got: %v", err)
	}
}

func TestCheckConfigHealth_HelpCommand(t *testing.T) {
	app := &App{}
	cmd := &cobra.Command{Use: "help"}
	if err := app.checkConfigHealth(cmd, errors.New("bad config")); err != nil {
		t.Fatalf("help command should be tolerant, got: %v", err)
	}
}

func TestCheckConfigHealth_NilError(t *testing.T) {
	app := &App{}
	cmd := &cobra.Command{Use: "apply"}
	if err := app.checkConfigHealth(cmd, nil); err != nil {
		t.Fatalf("nil config error should return nil, got: %v", err)
	}
}

func TestHasAnnotation_InheritsFromParent(t *testing.T) {
	parent := &cobra.Command{
		Use:         "parent",
		Annotations: map[string]string{cmdutil.AnnotationConfigOptional: "true"},
	}
	child := &cobra.Command{Use: "child"}
	parent.AddCommand(child)
	if !hasAnnotation(child, cmdutil.AnnotationConfigOptional) {
		t.Fatal("child should inherit parent annotation")
	}
}

func TestHasAnnotation_NotSet(t *testing.T) {
	cmd := &cobra.Command{Use: "apply"}
	if hasAnnotation(cmd, cmdutil.AnnotationConfigOptional) {
		t.Fatal("unannotated command should return false")
	}
}
