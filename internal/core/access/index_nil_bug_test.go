package access

import (
	"testing"
)

func TestResourceAccessIndex_NilReceiver(t *testing.T) {
	var idx *ResourceAccessIndex

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("ResourceAccessIndex method panicked on nil receiver: %v", r)
		}
	}()

	entries := idx.EntriesFor("arn:aws:s3:::my-bucket")
	if len(entries) != 0 {
		t.Errorf("expected empty entries, got %v", entries)
	}

	idx.AddEntry("arn:aws:s3:::my-bucket", ResourceAccessEntry{PrincipalARN: "arn:aws:iam::123:root"})

	count := 0
	idx.Range(func(res string, e ResourceAccessEntry) {
		count++
	})
	if count != 0 {
		t.Errorf("expected count 0 from Range, got %d", count)
	}

	hasNonDesig := idx.HasNonDesignatedPHIAccess("arn:aws:s3:::my-bucket", map[string]struct{}{})
	if hasNonDesig {
		t.Errorf("expected false for HasNonDesignatedPHIAccess on nil receiver, got true")
	}
}
