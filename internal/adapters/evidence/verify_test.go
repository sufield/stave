package evidence

import (
	"testing"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/report"
	platformcrypto "github.com/sufield/stave/internal/platform/crypto"
)

func TestVerify_UnsignedBundle(t *testing.T) {
	bundle := buildTestBundle(t, nil)

	result, err := Verify(bundle, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.ManifestValid {
		t.Fatal("expected manifest valid")
	}
	if result.Signed {
		t.Fatal("expected unsigned")
	}
}

func TestVerify_SignedBundle(t *testing.T) {
	privPEM, pubPEM, err := platformcrypto.GenerateSigningKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	bundle := buildTestBundle(t, privPEM)

	result, err := Verify(bundle, pubPEM)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.ManifestValid {
		t.Fatal("expected manifest valid")
	}
	if !result.Signed {
		t.Fatal("expected signed")
	}
	if !result.SignatureValid {
		t.Fatal("expected signature valid")
	}
}

func TestVerify_SignedBundle_WrongKey(t *testing.T) {
	privPEM, _, err := platformcrypto.GenerateSigningKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	_, otherPubPEM, err := platformcrypto.GenerateSigningKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	bundle := buildTestBundle(t, privPEM)

	result, err := Verify(bundle, otherPubPEM)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.ManifestValid {
		t.Fatal("expected manifest valid")
	}
	if !result.Signed {
		t.Fatal("expected signed")
	}
	if result.SignatureValid {
		t.Fatal("expected signature invalid with wrong key")
	}
}

func buildTestBundle(t *testing.T, privateKeyPEM []byte) []byte {
	t.Helper()

	assessment := &report.Assessment{
		Summary: evaluation.ComplianceSummary{
			TotalAssets: 1,
			Violations:  1,
		},
		Status: "NON_COMPLIANT",
		Findings: []remediation.Finding{
			{AssetID: "arn:aws:s3:::test-bucket"},
		},
	}

	snapshots := []asset.Snapshot{
		{
			Assets: []asset.Asset{
				{ID: "arn:aws:s3:::test-bucket", Type: "aws_s3_bucket"},
			},
		},
	}

	data, err := Build(BundleInput{
		Assessment:    assessment,
		Snapshots:     snapshots,
		PrivateKeyPEM: privateKeyPEM,
		StaveVersion:  "test",
	})
	if err != nil {
		t.Fatalf("build bundle: %v", err)
	}
	return data
}
