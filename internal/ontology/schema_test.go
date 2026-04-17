// Package ontology holds tests that assert the ontology schemas
// under docs/ontology/v0.1/ are valid JSON Schemas and that conformant
// and non-conformant documents validate as expected. The ontology
// schemas are the developer contract for Stave Apps; downstream app
// developers rely on these tests as evidence the contract is enforced.
package ontology_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

const conflictReportSchemaRelPath = "../../docs/ontology/v0.1/conflict-report.schema.json"

// loadConflictReportSchema reads and compiles the ConflictReport schema.
// Compilation exercises the JSON Schema 2020-12 meta-schema; a schema
// authoring mistake (unknown keyword combinations, malformed $ref,
// illegal type) fails here.
func loadConflictReportSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()

	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed — cannot locate schema file")
	}
	schemaPath := filepath.Join(filepath.Dir(thisFile), conflictReportSchemaRelPath)

	raw, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatalf("read %s: %v", schemaPath, err)
	}

	var doc any
	if unmarshalErr := json.Unmarshal(raw, &doc); unmarshalErr != nil {
		t.Fatalf("parse schema JSON: %v", unmarshalErr)
	}

	c := jsonschema.NewCompiler()
	const id = "https://stave.dev/ontology/v0.1/conflict-report"
	if addErr := c.AddResource(id, doc); addErr != nil {
		t.Fatalf("add schema resource: %v", addErr)
	}
	schema, err := c.Compile(id)
	if err != nil {
		t.Fatalf("compile ConflictReport schema (meta-validation failure): %v", err)
	}
	return schema
}

// unmarshalJSON parses a test fixture string into a JSON document the
// validator can consume.
func unmarshalJSON(t *testing.T, s string) any {
	t.Helper()
	var doc any
	if err := json.Unmarshal([]byte(s), &doc); err != nil {
		t.Fatalf("fixture is not valid JSON: %v\n\nfixture:\n%s", err, s)
	}
	return doc
}

// TestConflictReportSchema_CompilesAsJSONSchema2020 confirms the schema
// is itself a valid JSON Schema 2020-12 document. If this test fails,
// the schema has an authoring defect that must be fixed before any
// downstream validation tests are meaningful.
func TestConflictReportSchema_CompilesAsJSONSchema2020(t *testing.T) {
	_ = loadConflictReportSchema(t)
}

// TestConflictReportSchema_ValidExamples asserts a well-formed report
// for each of the four categories validates without errors.
// Each category's payload shape is exercised; if the discriminator
// wiring drifts, a category's test fails with a pointer to the
// specific payload field.
func TestConflictReportSchema_ValidExamples(t *testing.T) {
	schema := loadConflictReportSchema(t)

	cases := map[string]string{
		"contradiction":         fixtureContradictionValid,
		"redundancy":            fixtureRedundancyValid,
		"empirical_subsumption": fixtureEmpiricalSubsumptionValid,
		"divergence":            fixtureDivergenceValid,
	}

	for name, fixture := range cases {
		t.Run(name, func(t *testing.T) {
			doc := unmarshalJSON(t, fixture)
			if err := schema.Validate(doc); err != nil {
				t.Fatalf("expected %s fixture to validate; got error:\n%v", name, err)
			}
		})
	}
}

// TestConflictReportSchema_DiscriminatorRejectsMismatchedPayload is the
// discriminator test: when category is REDUNDANCY but payload carries
// CONTRADICTION-shaped fields, validation must fail AND the error path
// must point at the payload — not just "failed oneOf." The quality of
// that error message is what makes the contract debuggable for
// downstream app developers.
func TestConflictReportSchema_DiscriminatorRejectsMismatchedPayload(t *testing.T) {
	schema := loadConflictReportSchema(t)

	doc := unmarshalJSON(t, fixtureMismatchedPayload)
	err := schema.Validate(doc)
	if err == nil {
		t.Fatal("expected validation error for mismatched payload; got nil")
	}

	msg := err.Error()
	if !strings.Contains(msg, "payload") {
		t.Errorf("expected error to reference 'payload' field; got:\n%s", msg)
	}
}

// TestConflictReportSchema_RejectsUnknownCategory guards the closed
// enum on category. An unknown value must be rejected outright rather
// than matching some default payload branch.
func TestConflictReportSchema_RejectsUnknownCategory(t *testing.T) {
	schema := loadConflictReportSchema(t)

	doc := unmarshalJSON(t, fixtureUnknownCategory)
	if err := schema.Validate(doc); err == nil {
		t.Fatal("expected validation error for unknown category; got nil")
	}
}

// TestConflictReportSchema_RequiresReasoningFields guards top-level
// required fields. Missing report_id must fail — this is the stable
// identifier downstream apps correlate on; its absence is a defect,
// not a "nice to have."
func TestConflictReportSchema_RequiresReportID(t *testing.T) {
	schema := loadConflictReportSchema(t)

	doc := unmarshalJSON(t, fixtureMissingReportID)
	if err := schema.Validate(doc); err == nil {
		t.Fatal("expected validation error for missing report_id; got nil")
	}
}

// TestConflictReportSchema_RejectsAdditionalTopLevelProperties guards
// additionalProperties: false on the report root. Schema drift where
// new top-level fields are added silently is exactly the kind of
// contract erosion downstream apps cannot detect without this check.
func TestConflictReportSchema_RejectsAdditionalTopLevelProperties(t *testing.T) {
	schema := loadConflictReportSchema(t)

	doc := unmarshalJSON(t, fixtureWithUnknownTopLevelField)
	if err := schema.Validate(doc); err == nil {
		t.Fatal("expected validation error for unknown top-level field; got nil")
	}
}

// --- Fixtures -------------------------------------------------------
//
// Fixtures are inlined rather than placed under testdata/ so a reader
// reviewing the contract claims can see the fixture and the assertion
// together. If the fixture set grows beyond a screen or two, move to
// testdata/conflict-report/ and load via os.ReadFile.

const fixtureReportEnvelope = `
  "report_id": "sha256:abc0123456789def",
  "catalog_version": "abc1234",
  "fixture_corpus_version": "def5678",
  "generated_at": "2026-04-17T14:03:22Z",
  "stave_version": "0.1.3"
`

const fixtureCorpusCoverage = `
    "corpus_coverage": {
      "fixtures_evaluated": 142,
      "fixtures_matched": 7,
      "corpus_version": "def5678",
      "low_coverage": false
    }
`

const fixtureEmptyGaps = `"analysis_gaps": []`

const fixtureContradictionValid = `{` + fixtureReportEnvelope + `,
  "pairs": [
    {
      "category": "CONTRADICTION",
      "control_a": "CTL.S3.PUBLIC.001",
      "control_b": "CTL.S3.PUBLIC.042",
      ` + fixtureCorpusCoverage + `,
      "payload": {
        "subcategory": "MISSING_ASSET_CLASS_GUARD",
        "shared_dependencies": ["properties.storage.access.public_read"],
        "disagreement_witnesses": [
          {
            "fixture_path": "aws-lab/fixtures/s3-static-site.json",
            "asset_id": "arn:aws:s3:::example-site",
            "verdict_a": "VIOLATION",
            "verdict_b": "PASS",
            "observed_values": {"properties.storage.access.public_read": true}
          }
        ],
        "witnesses_truncated": false
      }
    }
  ],
  ` + fixtureEmptyGaps + `
}`

const fixtureRedundancyValid = `{` + fixtureReportEnvelope + `,
  "pairs": [
    {
      "category": "REDUNDANCY",
      "control_a": "CTL.IAM.POLICY.007",
      "control_b": "CTL.IAM.POLICY.019",
      ` + fixtureCorpusCoverage + `,
      "payload": {
        "shared_dependencies": ["properties.identity.policies.attached[*].arn"],
        "shared_compliance_hash": "sha256:9c1e0000000000000000000000000000",
        "shared_attack_stage": "privilege_escalation",
        "shared_remediation_hash": "sha256:aaaa1111000000000000000000000000"
      }
    }
  ],
  ` + fixtureEmptyGaps + `
}`

const fixtureEmpiricalSubsumptionValid = `{` + fixtureReportEnvelope + `,
  "pairs": [
    {
      "category": "EMPIRICAL_SUBSUMPTION",
      "control_a": "CTL.S3.PUBLIC.001",
      "control_b": "CTL.S3.PUBLIC.014",
      ` + fixtureCorpusCoverage + `,
      "payload": {
        "narrower": "CTL.S3.PUBLIC.001",
        "broader":  "CTL.S3.PUBLIC.014",
        "dependency_delta": ["properties.storage.access.public_list"]
      }
    }
  ],
  ` + fixtureEmptyGaps + `
}`

const fixtureDivergenceValid = `{` + fixtureReportEnvelope + `,
  "pairs": [
    {
      "category": "DIVERGENCE",
      "control_a": "CTL.IAM.POLICY.007",
      "control_b": "CTL.IAM.POLICY.022",
      ` + fixtureCorpusCoverage + `,
      "payload": {
        "shared_dependencies": ["properties.identity.trust.external_ids"],
        "agreement_rate": 0.89,
        "minimal_disagreement_fixtures": [
          {
            "fixture_path": "aws-lab/fixtures/iam-cross-account.json",
            "asset_id": "arn:aws:iam::111122223333:role/DataIngest",
            "verdict_a": "VIOLATION",
            "verdict_b": "PASS",
            "differing_values": {
              "properties.identity.trust.external_ids": ["shared-external-id"]
            }
          }
        ],
        "witnesses_truncated": false
      }
    }
  ],
  ` + fixtureEmptyGaps + `
}`

// fixtureMismatchedPayload: category=REDUNDANCY but payload shape is
// CONTRADICTION. The discriminator's if/then branches must direct
// validation to RedundancyPayload, which requires fields the
// CONTRADICTION payload lacks.
const fixtureMismatchedPayload = `{` + fixtureReportEnvelope + `,
  "pairs": [
    {
      "category": "REDUNDANCY",
      "control_a": "CTL.S3.PUBLIC.001",
      "control_b": "CTL.S3.PUBLIC.042",
      ` + fixtureCorpusCoverage + `,
      "payload": {
        "subcategory": "LOGIC_BUG",
        "shared_dependencies": ["properties.storage.access.public_read"],
        "disagreement_witnesses": [],
        "witnesses_truncated": false
      }
    }
  ],
  ` + fixtureEmptyGaps + `
}`

// fixtureUnknownCategory uses a category value outside the closed enum.
const fixtureUnknownCategory = `{` + fixtureReportEnvelope + `,
  "pairs": [
    {
      "category": "TENSION",
      "control_a": "CTL.A",
      "control_b": "CTL.B",
      ` + fixtureCorpusCoverage + `,
      "payload": {}
    }
  ],
  ` + fixtureEmptyGaps + `
}`

// fixtureMissingReportID omits the required report_id field.
const fixtureMissingReportID = `{
  "catalog_version": "abc1234",
  "fixture_corpus_version": "def5678",
  "generated_at": "2026-04-17T14:03:22Z",
  "stave_version": "0.1.3",
  "pairs": []
}`

// fixtureWithUnknownTopLevelField adds an unknown top-level property.
// additionalProperties: false on the report root must reject it.
const fixtureWithUnknownTopLevelField = `{` + fixtureReportEnvelope + `,
  "pairs": [],
  "unexpected_field": "should be rejected"
}`
