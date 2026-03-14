package kernel

import (
	"reflect"
	"testing"
)

func TestSourceIDString(t *testing.T) {
	if got := SourceID("abc").String(); got != "abc" {
		t.Errorf("SourceID.String() = %q, want %q", got, "abc")
	}
}

func TestStatementIDString(t *testing.T) {
	if got := StatementID("AllowPublic").String(); got != "AllowPublic" {
		t.Errorf("StatementID.String() = %q, want %q", got, "AllowPublic")
	}
}

func TestGranteeIDString(t *testing.T) {
	uri := GranteeID("http://acs.amazonaws.com/groups/global/AllUsers")
	if got := uri.String(); got != "http://acs.amazonaws.com/groups/global/AllUsers" {
		t.Errorf("GranteeID.String() = %q", got)
	}
}

func TestStringsFrom(t *testing.T) {
	ids := []StatementID{"A", "B", "C"}
	got := StringsFrom(ids)
	want := []string{"A", "B", "C"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("StringsFrom() = %v, want %v", got, want)
	}
}

func TestStringsFromNil(t *testing.T) {
	var ids []StatementID
	if got := StringsFrom(ids); got != nil {
		t.Errorf("StringsFrom(nil) = %v, want nil", got)
	}
}

func TestStringsFromSourceID(t *testing.T) {
	ids := []SourceID{"x", "y"}
	got := StringsFrom(ids)
	want := []string{"x", "y"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("StringsFrom(SourceID) = %v, want %v", got, want)
	}
}
