package taxonomy

import (
	"testing"

	"github.com/sufield/stave/internal/core/kernel"
)

func TestBuildMatrix_Basic(t *testing.T) {
	entries := []ControlEntry{
		{Service: "s3", Taxonomy: []kernel.CategoryID{NetworkPerimeter, EncryptionAtRest}},
		{Service: "s3", Taxonomy: []kernel.CategoryID{NetworkPerimeter}},
		{Service: "iam", Taxonomy: []kernel.CategoryID{LeastPrivilege}},
		{Service: "ec2", Taxonomy: []kernel.CategoryID{NetworkPerimeter, ComputeHardening}},
	}
	m := BuildMatrix(entries)

	if len(m.Services) != 3 {
		t.Errorf("expected 3 services, got %d", len(m.Services))
	}
	if len(m.Categories) < 3 {
		t.Errorf("expected >= 3 categories, got %d", len(m.Categories))
	}

	// network-perimeter should appear for s3 (count=2) and ec2 (count=1)
	var s3Net, ec2Net int
	for _, c := range m.Cells {
		if c.Category == NetworkPerimeter && c.Service == "s3" {
			s3Net = c.ControlCount
		}
		if c.Category == NetworkPerimeter && c.Service == "ec2" {
			ec2Net = c.ControlCount
		}
	}
	if s3Net != 2 {
		t.Errorf("s3 network-perimeter: got %d, want 2", s3Net)
	}
	if ec2Net != 1 {
		t.Errorf("ec2 network-perimeter: got %d, want 1", ec2Net)
	}
}

func TestGapCells_FindsMissing(t *testing.T) {
	entries := []ControlEntry{
		{Service: "s3", Taxonomy: []kernel.CategoryID{Logging}},
		{Service: "iam", Taxonomy: []kernel.CategoryID{Logging}},
		{Service: "ec2", Taxonomy: []kernel.CategoryID{Logging}},
		{Service: "lambda", Taxonomy: []kernel.CategoryID{Logging}},
		// rds has NO logging controls
		{Service: "rds", Taxonomy: []kernel.CategoryID{EncryptionAtRest}},
	}
	m := BuildMatrix(entries)
	gaps := m.GapCells()

	found := false
	for _, g := range gaps {
		if g.Category == Logging && g.Service == "rds" {
			found = true
		}
	}
	if !found {
		t.Error("expected gap: logging × rds")
	}
}

func TestGapCells_IgnoresNicheCategories(t *testing.T) {
	// Category present in only 2 services — should NOT produce gaps
	entries := []ControlEntry{
		{Service: "s3", Taxonomy: []kernel.CategoryID{DataPerimeter}},
		{Service: "iam", Taxonomy: []kernel.CategoryID{DataPerimeter}},
		{Service: "ec2", Taxonomy: []kernel.CategoryID{ComputeHardening}},
	}
	m := BuildMatrix(entries)
	gaps := m.GapCells()

	for _, g := range gaps {
		if g.Category == DataPerimeter {
			t.Errorf("data-perimeter in only 2 services should not produce gaps, got gap for %s", g.Service)
		}
	}
}

func TestCategoryTotals(t *testing.T) {
	entries := []ControlEntry{
		{Service: "s3", Taxonomy: []kernel.CategoryID{Logging}},
		{Service: "iam", Taxonomy: []kernel.CategoryID{Logging, LeastPrivilege}},
		{Service: "ec2", Taxonomy: []kernel.CategoryID{Logging}},
	}
	m := BuildMatrix(entries)
	totals := m.CategoryTotals()

	if len(totals) != 2 {
		t.Fatalf("expected 2 category totals, got %d", len(totals))
	}
	// Logging should be first (count=3), least-privilege second (count=1)
	if totals[0].Category != Logging || totals[0].ControlCount != 3 {
		t.Errorf("first total: got %s=%d, want logging=3", totals[0].Category, totals[0].ControlCount)
	}
}
