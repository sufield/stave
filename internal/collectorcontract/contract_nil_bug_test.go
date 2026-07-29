package collectorcontract

import (
	"testing"
)

func TestContract_FieldIndex_NilReceiver(t *testing.T) {
	var c *Contract
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("FieldIndex() panicked on nil receiver: %v", r)
		}
	}()

	idx := c.FieldIndex()
	if idx != nil {
		t.Errorf("expected nil map for nil receiver, got %v", idx)
	}
}
