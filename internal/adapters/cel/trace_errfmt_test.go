package cel

import (
	"strings"
	"testing"
	"unicode"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
)

func TestBuildTrace_ErrorStringsAreLowercase(t *testing.T) {
	t.Parallel()

	t.Run("nil control", func(t *testing.T) {
		_, err := BuildTrace(nil, &asset.Asset{ID: "x"}, nil)
		if err == nil {
			t.Fatal("expected error for nil control")
		}
		assertLowercaseError(t, err)
	})

	t.Run("nil asset", func(t *testing.T) {
		_, err := BuildTrace(&policy.ControlDefinition{}, nil, nil)
		if err == nil {
			t.Fatal("expected error for nil asset")
		}
		assertLowercaseError(t, err)
	})
}

func assertLowercaseError(t *testing.T, err error) {
	t.Helper()
	msg := err.Error()
	if r := []rune(msg); unicode.IsUpper(r[0]) {
		t.Errorf("error starts with uppercase: %q", msg)
	}
	if strings.Contains(msg, "BuildTrace:") {
		t.Errorf("error contains function name prefix: %q", msg)
	}
}
