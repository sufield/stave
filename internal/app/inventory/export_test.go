package inventory

import (
	"strings"
	"testing"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/kernel"
)

func TestExtract_EKSVersion(t *testing.T) {
	snapshots := []asset.Snapshot{
		{Assets: []asset.Asset{
			{ID: "eks-prod", Type: kernel.AssetType("eks_cluster"), Vendor: "aws",
				Properties: map[string]any{
					"k8s": map[string]any{"cluster": map[string]any{"version": "1.27.4"}},
				}},
		}},
	}
	versions := Extract(snapshots)
	if len(versions) != 1 {
		t.Fatalf("versions = %d, want 1", len(versions))
	}
	if versions[0].Version != "1.27.4" {
		t.Errorf("version = %q, want 1.27.4", versions[0].Version)
	}
	if !strings.Contains(versions[0].CPE, "kubernetes:1.27.4") {
		t.Errorf("CPE = %q, should contain kubernetes:1.27.4", versions[0].CPE)
	}
	if versions[0].PackageEcosystem != "kubernetes" {
		t.Errorf("ecosystem = %q, want kubernetes", versions[0].PackageEcosystem)
	}
}

func TestExtract_RDSEngine(t *testing.T) {
	snapshots := []asset.Snapshot{
		{Assets: []asset.Asset{
			{ID: "rds-prod", Type: kernel.AssetType("rds_instance"), Vendor: "aws",
				Properties: map[string]any{
					"database": map[string]any{"engine": "mysql", "engine_version": "8.0.32"},
				}},
		}},
	}
	versions := Extract(snapshots)
	if len(versions) != 1 {
		t.Fatalf("versions = %d, want 1", len(versions))
	}
	if !strings.Contains(versions[0].CPE, "mysql:8.0.32") {
		t.Errorf("CPE = %q, should contain mysql:8.0.32", versions[0].CPE)
	}
}

func TestExtract_LambdaRuntime(t *testing.T) {
	snapshots := []asset.Snapshot{
		{Assets: []asset.Asset{
			{ID: "lambda-api", Type: kernel.AssetType("lambda_function"), Vendor: "aws",
				Properties: map[string]any{
					"compute": map[string]any{"runtime": map[string]any{"name": "python3.9"}},
				}},
		}},
	}
	versions := Extract(snapshots)
	if len(versions) != 1 {
		t.Fatalf("versions = %d, want 1", len(versions))
	}
	if versions[0].PackageEcosystem != "pypi" {
		t.Errorf("ecosystem = %q, want pypi", versions[0].PackageEcosystem)
	}
}
