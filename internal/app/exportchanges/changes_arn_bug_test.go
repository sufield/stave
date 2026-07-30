package exportchanges

import (
	"testing"
)

func TestParseAssetID_7ComponentARNPreservesResourceType(t *testing.T) {
	arn := "arn:aws:ecs:us-east-1:123456789012:task:my-task-id"
	vendor, service, resourceID := parseAssetID(arn)

	if vendor != "aws" {
		t.Errorf("expected vendor 'aws', got %q", vendor)
	}
	if service != "ecs" {
		t.Errorf("expected service 'ecs', got %q", service)
	}
	// Expected resourceID should preserve type prefix "task:my-task-id", matching slash-separated "role/my-role"
	expected := "task:my-task-id"
	if resourceID != expected {
		t.Errorf("expected resourceID %q, got %q", expected, resourceID)
	}
}
