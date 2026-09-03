package stave

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/sufield/stave/internal/adapters/controls/archetype"
	"github.com/sufield/stave/internal/app/expand"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

// These exercise the expand render/resolve helpers that moved here from
// cmd/expand. End-to-end coverage that loads from disk lives in the txtar
// suite (cmd/stave/testdata/scripts).

func expandSampleControls() []policy.ControlDefinition {
	return []policy.ControlDefinition{
		{
			ID:        "CTL.ROUTE53.DANGLING.S3.001",
			Name:      "DNS → deleted S3",
			Severity:  policy.SeverityCritical,
			Defect:    "DNS record points to a deleted S3 bucket.",
			Archetype: "ghost-reference",
		},
		{
			ID:        "CTL.SQS.GHOST.DLQ.001",
			Name:      "Queue → deleted DLQ",
			Severity:  policy.SeverityCritical,
			Defect:    "Source queue references a deleted DLQ.",
			Archetype: "ghost-reference",
		},
		{
			ID:        "CTL.SQS.POLICY.S3.NOSOURCE.001",
			Name:      "S3 service principal unguarded",
			Severity:  policy.SeverityHigh,
			Defect:    "S3 service principal authorized without aws:SourceArn.",
			Archetype: "confused-deputy",
		},
		{
			ID:       "CTL.UNTAGGED.ENCRYPT.001",
			Name:     "control without an archetype",
			Severity: policy.SeverityMedium,
		},
	}
}

func TestRenderExpandJSON_IncludesArchetypeAndControls(t *testing.T) {
	arch, _ := archetype.Lookup("ghost-reference")
	matched := expand.FilterByArchetype(expandSampleControls(), kernel.ArchetypeID("ghost-reference"))

	var buf bytes.Buffer
	if err := renderExpandJSON(&buf, arch, matched, nil, nil); err != nil {
		t.Fatalf("renderExpandJSON: %v", err)
	}

	var got struct {
		Archetype struct {
			ID string `json:"id"`
		} `json:"archetype"`
		Controls []struct {
			ID      string `json:"id"`
			Service string `json:"service"`
		} `json:"controls"`
		ServicesAffected []string `json:"services_affected"`
	}
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal output: %v\noutput: %s", err, buf.String())
	}
	if got.Archetype.ID != "ghost-reference" {
		t.Errorf("archetype.id = %q", got.Archetype.ID)
	}
	if len(got.Controls) != 2 {
		t.Errorf("controls len = %d, want 2", len(got.Controls))
	}
	wantServices := map[string]struct{}{"route53": {}, "sqs": {}}
	for _, svc := range got.ServicesAffected {
		if _, ok := wantServices[svc]; !ok {
			t.Errorf("unexpected service in services_affected: %q", svc)
		}
	}
}

func TestRenderExpandList_TextLightsAllArchetypes(t *testing.T) {
	out, err := renderExpandList(expandSampleControls(), "text")
	if err != nil {
		t.Fatalf("renderExpandList text: %v", err)
	}
	s := string(out)
	for _, a := range archetype.Catalog {
		if !strings.Contains(s, a.ID.String()) {
			t.Errorf("--list output missing archetype %q", a.ID)
		}
	}
}

func TestRenderExpandList_JSONIncludesCounts(t *testing.T) {
	out, err := renderExpandList(expandSampleControls(), "json")
	if err != nil {
		t.Fatalf("renderExpandList json: %v", err)
	}
	var got struct {
		Archetypes []struct {
			ID           string `json:"id"`
			ControlCount int    `json:"control_count"`
		} `json:"archetypes"`
	}
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("unmarshal: %v\noutput: %s", err, out)
	}
	counts := map[string]int{}
	for _, a := range got.Archetypes {
		counts[a.ID] = a.ControlCount
	}
	if counts["ghost-reference"] != 2 {
		t.Errorf("ghost-reference count = %d, want 2", counts["ghost-reference"])
	}
	if counts["confused-deputy"] != 1 {
		t.Errorf("confused-deputy count = %d, want 1", counts["confused-deputy"])
	}
	if counts["transport-cleartext"] != 0 {
		t.Errorf("transport-cleartext count = %d, want 0", counts["transport-cleartext"])
	}
}

func TestExpandArchetypeFromControls_UnknownArchetype(t *testing.T) {
	_, err := expandArchetypeFromControls(nil, "controls", "not-real", "", "", "text")
	if err == nil || !strings.Contains(err.Error(), "unknown archetype") {
		t.Fatalf("error = %v, want 'unknown archetype'", err)
	}
}

func TestExpandArchetypeFromControls_FindingResolves(t *testing.T) {
	_, err := expandArchetypeFromControls(expandSampleControls(), "controls", "", "CTL.ROUTE53.DANGLING.S3.001", "", "text")
	if err != nil {
		t.Fatalf("expected nil error for known finding, got %v", err)
	}
}

func TestExpandArchetypeFromControls_FindingUnknown(t *testing.T) {
	_, err := expandArchetypeFromControls(expandSampleControls(), "controls", "", "CTL.NOPE.001", "", "text")
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Errorf("error = %v, want 'not found'", err)
	}
}

func TestExpandArchetypeFromControls_FindingNoArchetype(t *testing.T) {
	_, err := expandArchetypeFromControls(expandSampleControls(), "controls", "", "CTL.UNTAGGED.ENCRYPT.001", "", "text")
	if err == nil || !strings.Contains(err.Error(), "no archetype") {
		t.Errorf("error = %v, want 'no archetype'", err)
	}
}
