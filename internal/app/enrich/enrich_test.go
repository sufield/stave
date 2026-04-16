package enrich

import (
	"testing"

	"github.com/sufield/stave/internal/app/inventory"
)

func TestEnrich_CPEMatchOnAffectedVersion(t *testing.T) {
	inv := []inventory.AssetVersion{
		{
			AssetID:   "cluster-1",
			AssetType: "eks_cluster",
			Version:   "1.27.4",
			CPE:       "cpe:2.3:a:kubernetes:kubernetes:1.27.4:*:*:*:*:*:*:*",
		},
	}

	feed := NVDFeed{
		Entries: []CVEEntry{
			{
				CVEID:        "CVE-2024-1234",
				CVSSScore:    9.1,
				Description:  "Critical K8s vuln",
				AffectedCPEs: []string{"cpe:2.3:a:kubernetes:kubernetes:1.27:*:*:*:*:*:*:*"},
			},
		},
	}

	result := Enrich(Input{Inventory: inv, Feed: feed})

	if len(result.Assets) != 1 {
		t.Fatalf("assets = %d, want 1", len(result.Assets))
	}
	if len(result.Assets[0].CVEs) != 1 {
		t.Fatalf("CVEs = %d, want 1", len(result.Assets[0].CVEs))
	}
	if result.Assets[0].CVEs[0].CVEID != "CVE-2024-1234" {
		t.Errorf("CVE = %s, want CVE-2024-1234", result.Assets[0].CVEs[0].CVEID)
	}
}

func TestEnrich_NoMatchOnPatchedVersion(t *testing.T) {
	inv := []inventory.AssetVersion{
		{
			AssetID: "cluster-2",
			Version: "1.28.1",
			CPE:     "cpe:2.3:a:kubernetes:kubernetes:1.28.1:*:*:*:*:*:*:*",
		},
	}

	feed := NVDFeed{
		Entries: []CVEEntry{
			{
				CVEID:        "CVE-2024-1234",
				CVSSScore:    9.1,
				AffectedCPEs: []string{"cpe:2.3:a:kubernetes:kubernetes:1.27:*:*:*:*:*:*:*"},
			},
		},
	}

	result := Enrich(Input{Inventory: inv, Feed: feed})

	if len(result.Assets) != 1 {
		t.Fatalf("assets = %d, want 1", len(result.Assets))
	}
	if len(result.Assets[0].CVEs) != 0 {
		t.Errorf("CVEs = %d, want 0 (patched version)", len(result.Assets[0].CVEs))
	}
}

func TestEnrich_MinCVSSFilterApplied(t *testing.T) {
	inv := []inventory.AssetVersion{
		{
			AssetID: "cluster-1",
			Version: "1.27.4",
			CPE:     "cpe:2.3:a:kubernetes:kubernetes:1.27.4:*:*:*:*:*:*:*",
		},
	}

	feed := NVDFeed{
		Entries: []CVEEntry{
			{
				CVEID:        "CVE-2024-LOW",
				CVSSScore:    3.5,
				AffectedCPEs: []string{"cpe:2.3:a:kubernetes:kubernetes:1.27:*:*:*:*:*:*:*"},
			},
			{
				CVEID:        "CVE-2024-HIGH",
				CVSSScore:    9.1,
				AffectedCPEs: []string{"cpe:2.3:a:kubernetes:kubernetes:1.27:*:*:*:*:*:*:*"},
			},
		},
	}

	result := Enrich(Input{Inventory: inv, Feed: feed, MinCVSS: 7.0})

	if len(result.Assets) != 1 {
		t.Fatalf("assets = %d, want 1", len(result.Assets))
	}
	if len(result.Assets[0].CVEs) != 1 {
		t.Fatalf("CVEs = %d, want 1 (filtered by min-cvss)", len(result.Assets[0].CVEs))
	}
	if result.Assets[0].CVEs[0].CVEID != "CVE-2024-HIGH" {
		t.Errorf("CVE = %s, want CVE-2024-HIGH", result.Assets[0].CVEs[0].CVEID)
	}
}
