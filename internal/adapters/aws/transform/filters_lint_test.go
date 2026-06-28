package transform

import "testing"

// TestFiltersLint is the filter gate: every embedded .jq must compile and the
// detect map must stay in sync with the filter files. A new filter that doesn't
// compile, or a detect-map entry with no .jq file, fails the build here — the
// contributor sees it before review. Advisory (non-fatal) issues are logged.
func TestFiltersLint(t *testing.T) {
	issues, err := LintFilters()
	if err != nil {
		t.Fatal(err)
	}
	for _, is := range issues {
		if is.Fatal {
			t.Errorf("filter %q: %s", is.Filter, is.Message)
		} else {
			t.Logf("advisory — filter %q: %s", is.Filter, is.Message)
		}
	}
}

// ScaffoldContent must itself produce a filter that compiles, so the starter a
// contributor gets is a valid jq program from the first edit.
func TestScaffoldContentCompiles(t *testing.T) {
	for _, is := range lintProgram("scaffold", ScaffoldContent("kms-keys", "Keys")) {
		if is.Fatal {
			t.Errorf("scaffold output does not compile: %s", is.Message)
		}
	}
}
