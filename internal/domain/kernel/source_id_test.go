package kernel

import (
	"reflect"
	"testing"
)

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

func TestStringsFromGranteeID(t *testing.T) {
	ids := []GranteeID{"x", "y"}
	got := StringsFrom(ids)
	want := []string{"x", "y"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("StringsFrom(GranteeID) = %v, want %v", got, want)
	}
}
