package graph

import (
	"bytes"
	"encoding/xml"
	"strings"
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/kernel"
)

// fixtureFinding builds a minimal Finding the graph builder accepts.
// The contents matter to the export test because the URI scheme,
// shortcut edges, and severity weights all derive from finding
// fields.
func fixtureFinding(severity policy.Severity, controlID, assetID, assetType string, vendor kernel.Vendor) remediation.Finding {
	return remediation.Finding{
		Finding: evaluation.Finding{
			FindingID:       "finding-" + assetID,
			ControlID:       kernel.ControlID(controlID),
			ControlName:     "Test Control",
			ControlSeverity: severity,
			AssetID:         asset.ID(assetID),
			AssetType:       kernel.AssetType(assetType),
			AssetVendor:     vendor,
			Evidence:        evaluation.Evidence{TemporalRisk: "exposed"},
		},
	}
}

func buildFixtureGraph(t *testing.T) *GraphData {
	t.Helper()
	now := time.Date(2026, 1, 11, 0, 0, 0, 0, time.UTC)
	g := Build(BuildInput{
		Findings: []remediation.Finding{
			fixtureFinding(policy.SeverityCritical, "CTL.S3.PUBLIC.001",
				"arn:aws:s3:::123456789012-bucket", "aws_s3_bucket", "aws"),
			fixtureFinding(policy.SeverityHigh, "CTL.S3.ACL.FULLCONTROL.001",
				"arn:aws:s3:::123456789012-bucket", "aws_s3_bucket", "aws"),
		},
		Now:        now,
		SourcePath: "test/assessment.json",
	})
	return g
}

func TestMarshalJSONLD_DocumentShape(t *testing.T) {
	g := buildFixtureGraph(t)
	var buf bytes.Buffer
	if err := MarshalJSONLD(&buf, g); err != nil {
		t.Fatalf("MarshalJSONLD: %v", err)
	}
	out := buf.String()

	// Document must declare @context and @graph at the top level.
	if !strings.Contains(out, `"@context"`) {
		t.Error("output missing @context")
	}
	if !strings.Contains(out, `"@graph"`) {
		t.Error("output missing @graph")
	}
	// URI scheme: bucket IRIs follow stave:bucket/{account}/{name}.
	if !strings.Contains(out, "urn:stave:bucket/") {
		t.Error("expected urn:stave:bucket/ IRIs in output")
	}
	// Materialized shortcut edge: stave:violates with isAlgorithmShortcut.
	if !strings.Contains(out, `"isAlgorithmShortcut": true`) {
		t.Error("output missing isAlgorithmShortcut annotation on shortcut edges")
	}
	// Severity weight is numeric and present on Finding nodes.
	if !strings.Contains(out, `"severity_weight": 10`) {
		t.Errorf("expected severity_weight 10 on critical finding; output:\n%s", out)
	}
}

func TestMarshalJSONLD_DeterministicOrdering(t *testing.T) {
	g := buildFixtureGraph(t)
	var buf1, buf2 bytes.Buffer
	if err := MarshalJSONLD(&buf1, g); err != nil {
		t.Fatal(err)
	}
	if err := MarshalJSONLD(&buf2, g); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf1.Bytes(), buf2.Bytes()) {
		t.Error("MarshalJSONLD output is not byte-deterministic across runs")
	}
}

func TestMarshalGraphML_ValidXML(t *testing.T) {
	g := buildFixtureGraph(t)
	var buf bytes.Buffer
	if err := MarshalGraphML(&buf, g); err != nil {
		t.Fatalf("MarshalGraphML: %v", err)
	}

	// Parse the output to confirm well-formedness — fail-loud
	// catch for the hand-rolled escape path.
	dec := xml.NewDecoder(bytes.NewReader(buf.Bytes()))
	for {
		_, err := dec.Token()
		if err != nil {
			break
		}
	}

	out := buf.String()
	if !strings.Contains(out, `<graphml`) {
		t.Error("missing <graphml> root")
	}
	if !strings.Contains(out, `<key id="n_type"`) {
		t.Error("missing <key> declaration for node type")
	}
	// Severity weight must be declared as numeric so consumers know
	// to read it as a double, not a string.
	if !strings.Contains(out, `attr.type="double"`) {
		t.Error("expected at least one double-typed key declaration")
	}
	// Shortcut edges carry the isAlgorithmShortcut data flag.
	if !strings.Contains(out, `<data key="e_isAlgorithmShortcut">true`) {
		t.Errorf("missing isAlgorithmShortcut annotation on a shortcut edge\n%s", out)
	}
}

func TestExporters_InterfaceSatisfied(t *testing.T) {
	g := buildFixtureGraph(t)

	var ex GraphExporter = NewJSONLDExporter()
	out, err := ex.Export(g)
	if err != nil || len(out) == 0 {
		t.Fatalf("JSONLDExporter.Export: out=%d err=%v", len(out), err)
	}

	ex = NewGraphMLExporter()
	out, err = ex.Export(g)
	if err != nil || len(out) == 0 {
		t.Fatalf("GraphMLExporter.Export: out=%d err=%v", len(out), err)
	}
}

func TestSeverityWeight_Mapping(t *testing.T) {
	cases := []struct {
		in   string
		want float64
	}{
		{"critical", 10},
		{"high", 7},
		{"medium", 4},
		{"low", 1},
		{"none", 0},
		{"unknown", 0},
		{"CRITICAL", 10}, // case-insensitive
	}
	for _, tc := range cases {
		if got := SeverityWeight(tc.in); got != tc.want {
			t.Errorf("SeverityWeight(%q) = %g, want %g", tc.in, got, tc.want)
		}
	}
}

func TestBucketIRI_URIShape(t *testing.T) {
	got := BucketIRI("123456789012", "my-bucket")
	want := "urn:stave:bucket/123456789012/my-bucket"
	if got != want {
		t.Errorf("BucketIRI = %q, want %q", got, want)
	}
}

func TestInvariantIRI_SplitsControlID(t *testing.T) {
	cat, num := splitControlID("CTL.S3.PUBLIC.001")
	if cat != "CTL.S3.PUBLIC" || num != "001" {
		t.Errorf("splitControlID = (%q, %q), want (CTL.S3.PUBLIC, 001)", cat, num)
	}
	got := InvariantIRI(cat, num)
	want := "urn:stave:invariant/CTL.S3.PUBLIC.001"
	if got != want {
		t.Errorf("InvariantIRI = %q, want %q", got, want)
	}
}

func TestOntology_Embedded(t *testing.T) {
	ttl := Ontology()
	if len(ttl) == 0 {
		t.Fatal("Ontology() returned empty bytes")
	}
	s := string(ttl)
	if !strings.Contains(s, "@prefix stave:") {
		t.Error("ontology.ttl missing stave: prefix declaration")
	}
	if !strings.Contains(s, "stave:isAlgorithmShortcut") {
		t.Error("ontology.ttl missing isAlgorithmShortcut annotation property")
	}
	if !strings.Contains(s, "stave:Bucket") {
		t.Error("ontology.ttl missing stave:Bucket class")
	}
}

func TestMapToRDFGraph_MaterializesShortcutEdge(t *testing.T) {
	g := buildFixtureGraph(t)
	rdf := mapToRDFGraph(g)

	var found bool
	for _, e := range rdf.Edges {
		if e.Predicate == predViolates && e.Shortcut {
			found = true
			if w, ok := e.Properties["weight"].(float64); !ok || w == 0 {
				t.Errorf("shortcut edge missing numeric weight: %+v", e.Properties)
			}
			break
		}
	}
	if !found {
		t.Error("expected at least one materialized stave:violates shortcut edge")
	}
}
