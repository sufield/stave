package docsverify

import (
	"testing"
)

func TestExtractCommands_BasicBash(t *testing.T) {
	md := []byte("# Example\n\n```bash\nstave apply --observations ./obs\n```\n")
	cmds, err := ExtractCommands(md, "test.md", []string{"bash", "shell", "sh"})
	if err != nil {
		t.Fatal(err)
	}
	if len(cmds) != 1 {
		t.Fatalf("got %d commands, want 1", len(cmds))
	}
	if cmds[0].Command != "stave apply --observations ./obs" {
		t.Errorf("got %q", cmds[0].Command)
	}
	if cmds[0].File != "test.md" {
		t.Errorf("file = %q", cmds[0].File)
	}
}

func TestExtractCommands_StripsDollarPrompt(t *testing.T) {
	md := []byte("```bash\n$ stave catalog --kind chain\n```\n")
	cmds, err := ExtractCommands(md, "test.md", []string{"bash"})
	if err != nil {
		t.Fatal(err)
	}
	if len(cmds) != 1 {
		t.Fatalf("got %d commands, want 1", len(cmds))
	}
	if cmds[0].Command != "stave catalog --kind chain" {
		t.Errorf("got %q", cmds[0].Command)
	}
}

func TestExtractCommands_SkipsComments(t *testing.T) {
	md := []byte("```bash\n# this is a comment\nstave apply -o ./obs\n```\n")
	cmds, err := ExtractCommands(md, "test.md", []string{"bash"})
	if err != nil {
		t.Fatal(err)
	}
	if len(cmds) != 1 {
		t.Fatalf("got %d commands, want 1", len(cmds))
	}
}

func TestExtractCommands_LineContinuation(t *testing.T) {
	md := []byte("```bash\nstave apply \\\n  --observations ./obs \\\n  --format json\n```\n")
	cmds, err := ExtractCommands(md, "test.md", []string{"bash"})
	if err != nil {
		t.Fatal(err)
	}
	if len(cmds) != 1 {
		t.Fatalf("got %d commands, want 1", len(cmds))
	}
	want := "stave apply --observations ./obs --format json"
	if cmds[0].Command != want {
		t.Errorf("got %q, want %q", cmds[0].Command, want)
	}
}

func TestExtractCommands_IgnoresNonStaveCommands(t *testing.T) {
	md := []byte("```bash\necho hello\ngrep foo bar\nstave version\n```\n")
	cmds, err := ExtractCommands(md, "test.md", []string{"bash"})
	if err != nil {
		t.Fatal(err)
	}
	if len(cmds) != 1 {
		t.Fatalf("got %d commands, want 1", len(cmds))
	}
	if cmds[0].Command != "stave version" {
		t.Errorf("got %q", cmds[0].Command)
	}
}

func TestExtractCommands_IgnoresUnmatchedLang(t *testing.T) {
	md := []byte("```go\nstave.Run()\n```\n```yaml\nstave: true\n```\n")
	cmds, err := ExtractCommands(md, "test.md", []string{"bash", "shell"})
	if err != nil {
		t.Fatal(err)
	}
	if len(cmds) != 0 {
		t.Fatalf("got %d commands, want 0", len(cmds))
	}
}

func TestExtractCommands_DoctestSkip(t *testing.T) {
	md := []byte("```bash\n# doctest:skip — requires AWS\nstave apply -o ./obs\n```\n")
	cmds, err := ExtractCommands(md, "test.md", []string{"bash"})
	if err != nil {
		t.Fatal(err)
	}
	if len(cmds) != 1 {
		t.Fatalf("got %d commands, want 1", len(cmds))
	}
	if !cmds[0].Skip {
		t.Error("expected Skip=true")
	}
	if cmds[0].SkipReason == "" {
		t.Error("expected SkipReason")
	}
}

func TestExtractCommands_DoctestExpectError(t *testing.T) {
	md := []byte("```bash\n# doctest:expect-error — demonstrates error handling\nstave validate --in nonexistent.yaml\n```\n")
	cmds, err := ExtractCommands(md, "test.md", []string{"bash"})
	if err != nil {
		t.Fatal(err)
	}
	if len(cmds) != 1 {
		t.Fatalf("got %d commands, want 1", len(cmds))
	}
	if !cmds[0].ExpectError {
		t.Error("expected ExpectError=true")
	}
}

func TestExtractCommands_MultipleCommandsInOneBlock(t *testing.T) {
	md := []byte("```bash\nstave catalog --kind chain\nstave catalog --kind chain --verbose\n```\n")
	cmds, err := ExtractCommands(md, "test.md", []string{"bash"})
	if err != nil {
		t.Fatal(err)
	}
	if len(cmds) != 2 {
		t.Fatalf("got %d commands, want 2", len(cmds))
	}
}

func TestExtractCommands_MultipleBlocks(t *testing.T) {
	md := []byte("# One\n\n```bash\nstave version\n```\n\n# Two\n\n```shell\nstave catalog --kind chain\n```\n")
	cmds, err := ExtractCommands(md, "test.md", []string{"bash", "shell"})
	if err != nil {
		t.Fatal(err)
	}
	if len(cmds) != 2 {
		t.Fatalf("got %d commands, want 2", len(cmds))
	}
}

func TestExtractCommands_PipeIgnored(t *testing.T) {
	// Piped commands are too complex to run as-is
	md := []byte("```bash\nstave apply -o ./obs | jq '.findings'\n```\n")
	cmds, err := ExtractCommands(md, "test.md", []string{"bash"})
	if err != nil {
		t.Fatal(err)
	}
	if len(cmds) != 1 {
		t.Fatalf("got %d commands, want 1", len(cmds))
	}
	// The extractor should mark piped commands for skip
	if !cmds[0].Skip {
		t.Error("piped command should be auto-skipped")
	}
}

func TestExtractCommands_RedirectIgnored(t *testing.T) {
	md := []byte("```bash\nstave apply -o ./obs > output.json\n```\n")
	cmds, err := ExtractCommands(md, "test.md", []string{"bash"})
	if err != nil {
		t.Fatal(err)
	}
	if len(cmds) != 1 {
		t.Fatalf("got %d commands, want 1", len(cmds))
	}
	if !cmds[0].Skip {
		t.Error("redirected command should be auto-skipped")
	}
}

func TestExtractCommands_VariableAssignment(t *testing.T) {
	// stave := envOr(...) is Go code, not a CLI invocation
	md := []byte("```bash\nstave := envOr(\"STAVE_BIN\", \"stave\")\n```\n")
	cmds, err := ExtractCommands(md, "test.md", []string{"bash"})
	if err != nil {
		t.Fatal(err)
	}
	if len(cmds) != 0 {
		t.Fatalf("got %d commands, want 0 (variable assignment)", len(cmds))
	}
}

func TestExtractCommands_InlineComment(t *testing.T) {
	md := []byte("```bash\nstave catalog --kind chain              # all chains, grouped by family\n```\n")
	cmds, err := ExtractCommands(md, "test.md", []string{"bash"})
	if err != nil {
		t.Fatal(err)
	}
	if len(cmds) != 1 {
		t.Fatalf("got %d commands, want 1", len(cmds))
	}
	if cmds[0].Command != "stave catalog --kind chain" {
		t.Errorf("got %q, want inline comment stripped", cmds[0].Command)
	}
}

func TestExtractCommands_EmptyFile(t *testing.T) {
	cmds, err := ExtractCommands([]byte(""), "empty.md", []string{"bash"})
	if err != nil {
		t.Fatal(err)
	}
	if len(cmds) != 0 {
		t.Fatalf("got %d commands from empty file", len(cmds))
	}
}

func TestExtractCommands_NoCodeBlocks(t *testing.T) {
	md := []byte("# Title\n\nSome text about stave apply.\n")
	cmds, err := ExtractCommands(md, "test.md", []string{"bash"})
	if err != nil {
		t.Fatal(err)
	}
	if len(cmds) != 0 {
		t.Fatalf("got %d commands, want 0", len(cmds))
	}
}
