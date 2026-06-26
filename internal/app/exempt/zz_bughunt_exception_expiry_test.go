package exempt

import (
	"testing"
)

func TestBugHunt_ExceptionExpiryValidation(t *testing.T) {
	f := &AcceptanceFile{SchemaVersion: "1"}

	// 1. AddException with invalid expiry date format should return an error
	err := f.AddException(ExceptionEntry{
		ControlID:  "CTL.A",
		AssetID:    "arn:aws:s3:::my-bucket",
		ExpiryDate: "invalid-date",
		Reason:     "legacy",
	})
	if err == nil {
		t.Errorf("expected error when adding exception with invalid expiry date format, got nil")
	}

	// 2. AddException with valid expiry date format should succeed
	err = f.AddException(ExceptionEntry{
		ControlID:  "CTL.A",
		AssetID:    "arn:aws:s3:::my-bucket",
		ExpiryDate: "2027-01-15",
		Reason:     "legacy",
	})
	if err != nil {
		t.Errorf("unexpected error adding valid exception: %v", err)
	}

	// 3. Validate() should flag invalid expiry dates
	f.Exceptions = append(f.Exceptions, ExceptionEntry{
		ControlID:  "CTL.B",
		AssetID:    "arn:aws:s3:::another-bucket",
		ExpiryDate: "2027-13-45", // invalid month/day
		Reason:     "testing",
	})

	errs := f.Validate()
	found := false
	for _, e := range errs {
		if e == `exception[1]: invalid expiry_date "2027-13-45"` {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected Validate to return error for invalid expiry date '2027-13-45', got: %v", errs)
	}
}
