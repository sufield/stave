package stave

import (
	"testing"

	domainexposure "github.com/sufield/stave/internal/core/evaluation/exposure"
)

func TestToExposureCaps(t *testing.T) {
	c := toExposureCaps(exposureCapInput{Read: true, Write: true, List: false, Delete: true, Admin: false})
	if !c.Read || !c.Write || c.List || !c.Delete || c.Admin {
		t.Fatalf("toExposureCaps mismatch: %+v", c)
	}
}

func TestExposureResourceInput_ToDomain(t *testing.T) {
	input := exposureResourceInput{
		Name:              "my-bucket",
		Exists:            true,
		WebsiteEnabled:    true,
		WriteSourceHasGet: true,
	}
	d := input.toDomain()
	if d.Name != "my-bucket" || !d.Exists || !d.WebsiteEnabled || !d.WriteSourceHasGet {
		t.Fatalf("toDomain mismatch: %+v", d)
	}
}

// Verify the conversion produces the domain type at compile time.
var _ domainexposure.NormalizedResourceInput = exposureResourceInput{}.toDomain()
