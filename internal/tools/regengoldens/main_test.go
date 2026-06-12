package main

import (
	"math"
	"reflect"
	"testing"
)

func TestDiffPaths_MarshalError(t *testing.T) {
	// Under the bug, both math.NaN() and math.Inf(1) fail to marshal,
	// resulting in aj=nil and bj=nil. bytes.Equal(nil, nil) evaluates
	// to true, so no diff is reported even though the values differ.
	got := diffPaths(math.NaN(), math.Inf(1), "testpath")
	want := []string{"testpath"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("diffPaths(NaN, Inf) = %v, want %v", got, want)
	}
}
