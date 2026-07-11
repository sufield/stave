package template

import (
	"testing"

	"github.com/sufield/stave/pkg/stave/snapshot"
)

type mockCatalog struct {
	ids  []string
	deps map[string][]string
}

func (m mockCatalog) ControlIDs() []string                   { return m.ids }
func (m mockCatalog) ChainDependencies() map[string][]string { return m.deps }

func TestResolveAutoScope_MatchesServices(t *testing.T) {
	catalog := mockCatalog{
		ids: []string{
			"CTL.IAM.POLICY.WILDCARD.001",
			"CTL.IAM.ROLE.TRUST.001",
			"CTL.S3.BUCKET.PUBLIC.READ.001",
			"CTL.EC2.SG.OPEN.001",
		},
		deps: map[string][]string{
			"iam_s3_chain": {"iam", "s3"},
			"ec2_chain":    {"ec2"},
		},
	}

	summary := snapshot.Summary{
		Services: []string{"iam", "s3"},
	}

	scope, err := ResolveAutoScope(summary, catalog)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(scope.MatchedServices) != 2 {
		t.Errorf("expected 2 matched services, got %d", len(scope.MatchedServices))
	}
	if len(scope.ControlPatterns) != 2 {
		t.Errorf("expected 2 control patterns, got %d: %v", len(scope.ControlPatterns), scope.ControlPatterns)
	}
	if len(scope.ChainIDs) != 1 || scope.ChainIDs[0] != "iam_s3_chain" {
		t.Errorf("expected iam_s3_chain included, got %v", scope.ChainIDs)
	}
	if len(scope.SkippedChains) != 1 || scope.SkippedChains[0] != "ec2_chain" {
		t.Errorf("expected ec2_chain skipped, got %v", scope.SkippedChains)
	}
}

func TestResolveAutoScope_NoMatch(t *testing.T) {
	catalog := mockCatalog{
		ids:  []string{"CTL.IAM.POLICY.WILDCARD.001"},
		deps: nil,
	}

	summary := snapshot.Summary{
		Services: []string{"serverlessrepo"},
	}

	_, err := ResolveAutoScope(summary, catalog)
	if err == nil {
		t.Fatal("expected error for no matching services")
	}
}
