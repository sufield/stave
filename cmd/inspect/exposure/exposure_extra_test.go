package exposure

import (
	"strings"
	"testing"

	domainexposure "github.com/sufield/stave/internal/core/evaluation/exposure"
	"github.com/sufield/stave/internal/platform/fsutil"
)

func TestToCaps(t *testing.T) {
	c := toCaps(CapInput{Read: true, Write: true, List: false, Delete: true, Admin: false})
	if !c.Read {
		t.Fatal("Read should be true")
	}
	if !c.Write {
		t.Fatal("Write should be true")
	}
	if c.List {
		t.Fatal("List should be false")
	}
	if !c.Delete {
		t.Fatal("Delete should be true")
	}
	if c.Admin {
		t.Fatal("Admin should be false")
	}
}

func TestResourceInput_ToDomain(t *testing.T) {
	input := ResourceInput{
		Name:               "my-bucket",
		Exists:             true,
		ExternalReference:  false,
		WebsiteEnabled:     true,
		IsAuthOnly:         false,
		IdentityPerms:      0,
		ResourcePerms:      0,
		WriteSourceHasGet:  true,
		WriteSourceHasList: false,
	}
	d := input.ToDomain()
	if d.Name != "my-bucket" {
		t.Fatalf("Name = %q", d.Name)
	}
	if !d.Exists {
		t.Fatal("Exists should be true")
	}
	if !d.WebsiteEnabled {
		t.Fatal("WebsiteEnabled should be true")
	}
	if !d.WriteSourceHasGet {
		t.Fatal("WriteSourceHasGet should be true")
	}
}

func TestReadInput_Stdin(t *testing.T) {
	r := strings.NewReader(`{"resources":[]}`)
	data, err := fsutil.ReadFileOrStdin("", r)
	if err != nil {
		t.Fatalf("readInput error: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("expected non-empty data")
	}
}

func TestReadInput_MissingFile(t *testing.T) {
	_, err := fsutil.ReadFileOrStdin("/nonexistent/file.json", nil)
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

// Verify type implements interface at compile time.
var _ domainexposure.NormalizedResourceInput = ResourceInput{}.ToDomain()
