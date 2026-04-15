package graph_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	tcneo4j "github.com/testcontainers/testcontainers-go/modules/neo4j"
)

// TestExperiment06_Neo4jRoundTrip starts a Neo4j container, loads
// Cypher output from stave graph export, and runs Cypher assertions.
func TestExperiment06_Neo4jRoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping Neo4j container test in short mode")
	}

	// Check Docker availability.
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("skipping: docker not available")
	}

	ctx := context.Background()

	// Start Neo4j container.
	neo4jContainer, err := tcneo4j.Run(ctx,
		"neo4j:5",
		tcneo4j.WithAdminPassword("stavetest"),
		tcneo4j.WithoutAuthentication(),
	)
	if err != nil {
		t.Fatalf("start neo4j container: %v", err)
	}
	defer func() {
		if termErr := neo4jContainer.Terminate(ctx); termErr != nil {
			t.Logf("terminate neo4j: %v", termErr)
		}
	}()

	boltURL, err := neo4jContainer.BoltUrl(ctx)
	if err != nil {
		t.Fatalf("get bolt URL: %v", err)
	}

	// Connect with neo4j driver (no auth since WithoutAuthentication).
	driver, err := neo4j.NewDriverWithContext(boltURL, neo4j.NoAuth())
	if err != nil {
		t.Fatalf("create neo4j driver: %v", err)
	}
	defer driver.Close(ctx)

	if err := driver.VerifyConnectivity(ctx); err != nil {
		t.Fatalf("neo4j connectivity check: %v", err)
	}

	// Build stave binary and generate Cypher.
	_, thisFile, _, _ := runtime.Caller(0)
	repoRoot := filepath.Join(filepath.Dir(thisFile), "..", "..")

	bin := filepath.Join(t.TempDir(), "stave-neo4j-test")
	build := exec.Command("go", "build", "-o", bin, "./cmd/stave")
	build.Dir = repoRoot
	if out, buildErr := build.CombinedOutput(); buildErr != nil {
		t.Fatalf("build: %v\n%s", buildErr, out)
	}

	assessment := filepath.Join(repoRoot, "testdata", "e2e",
		"graph-ontology", "experiment-02-active-chain", "assessment.json")
	if _, statErr := os.Stat(assessment); statErr != nil {
		t.Skipf("fixture not found: %s", assessment)
	}

	// Apply schema.
	schemaPath := filepath.Join(repoRoot, "docs", "integrations", "neo4j", "schema.cypher")
	applySchema(t, ctx, driver, schemaPath)

	// Generate Cypher and load into Neo4j.
	cypherOutput := runGraphExportCypher(t, bin, repoRoot, assessment)
	loadCypher(t, ctx, driver, cypherOutput)

	session := driver.NewSession(ctx, neo4j.SessionConfig{})
	defer session.Close(ctx)

	// Assertion 1: Active chain exists.
	assertCypherCount(t, ctx, session,
		"MATCH (c:ThreatChain {active: true}) RETURN count(c) AS n",
		1, "active ThreatChain")

	// Assertion 2: All 3 findings are chain members.
	assertCypherCount(t, ctx, session,
		"MATCH (f:Finding)-[:MEMBER_OF]->(c:ThreatChain) RETURN count(f) AS n",
		3, "findings with MEMBER_OF chain")

	// Assertion 3: Findings have severity set.
	assertCypherCount(t, ctx, session,
		"MATCH (f:Finding) WHERE f.severity IS NOT NULL RETURN count(f) AS n",
		3, "findings with severity")

	// Assertion 4: Resources have resource_class set.
	assertCypherCount(t, ctx, session,
		"MATCH (r:Resource) WHERE r.resource_class IS NOT NULL RETURN count(r) AS n",
		3, "resources with resource_class")

	// Assertion 5: Idempotency — load the same Cypher again.
	countBefore := querySingleInt(t, ctx, session,
		"MATCH (n) RETURN count(n) AS n")
	loadCypher(t, ctx, driver, cypherOutput)
	countAfter := querySingleInt(t, ctx, session,
		"MATCH (n) RETURN count(n) AS n")
	if countBefore != countAfter {
		t.Errorf("idempotency failed: before=%d, after=%d", countBefore, countAfter)
	}
}

// applySchema reads a .cypher file and executes each statement.
func applySchema(t *testing.T, ctx context.Context, driver neo4j.DriverWithContext, path string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Logf("schema file not found: %s (skipping schema setup)", path)
		return
	}
	session := driver.NewSession(ctx, neo4j.SessionConfig{})
	defer session.Close(ctx)

	for _, stmt := range splitCypherStatements(string(data)) {
		if _, err := session.Run(ctx, stmt, nil); err != nil {
			// Schema statements may fail if constraint already exists.
			t.Logf("schema statement warning: %v", err)
		}
	}
}

// loadCypher executes Cypher MERGE statements in Neo4j.
// Constraint validation errors are logged but not fatal — they
// occur when MERGE + SET touches a uniqueness constraint on a
// property that differs from the MERGE key.
func loadCypher(t *testing.T, ctx context.Context, driver neo4j.DriverWithContext, cypher string) {
	t.Helper()
	session := driver.NewSession(ctx, neo4j.SessionConfig{})
	defer session.Close(ctx)

	for _, stmt := range splitCypherStatements(cypher) {
		if _, err := session.Run(ctx, stmt, nil); err != nil {
			if strings.Contains(err.Error(), "ConstraintValidation") {
				t.Logf("constraint warning (expected for MERGE idempotency): %.120s", err)
				continue
			}
			t.Fatalf("execute cypher: %v\nstatement: %.200s", err, stmt)
		}
	}
}

// splitCypherStatements splits Cypher text into individual statements.
func splitCypherStatements(text string) []string {
	var stmts []string
	for raw := range strings.SplitSeq(text, ";") {
		stmt := strings.TrimSpace(raw)
		if stmt == "" {
			continue
		}
		// Skip pure comment blocks.
		lines := strings.Split(stmt, "\n")
		hasCode := false
		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			if trimmed != "" && !strings.HasPrefix(trimmed, "//") {
				hasCode = true
				break
			}
		}
		if hasCode {
			stmts = append(stmts, stmt)
		}
	}
	return stmts
}

func assertCypherCount(t *testing.T, ctx context.Context, session neo4j.SessionWithContext, query string, want int, label string) {
	t.Helper()
	got := querySingleInt(t, ctx, session, query)
	if got != int64(want) {
		t.Errorf("%s: count = %d, want %d", label, got, want)
	}
}

func querySingleInt(t *testing.T, ctx context.Context, session neo4j.SessionWithContext, query string) int64 {
	t.Helper()
	result, err := session.Run(ctx, query, nil)
	if err != nil {
		t.Fatalf("query failed: %v\nquery: %s", err, query)
	}
	record, err := result.Single(ctx)
	if err != nil {
		t.Fatalf("single result failed: %v\nquery: %s", err, query)
	}
	val, ok := record.Values[0].(int64)
	if !ok {
		t.Fatalf("expected int64, got %T (%v)", record.Values[0], record.Values[0])
	}
	return val
}
