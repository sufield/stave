package ui

import "testing"

func TestShouldSkipFirstRunHint(t *testing.T) {
	tests := []struct {
		args []string
		skip bool
	}{
		{args: []string{"help"}, skip: true},
		{args: []string{"--help"}, skip: true},
		{args: []string{"-h"}, skip: true},
		{args: []string{"completion"}, skip: true},
		{args: []string{"--version"}, skip: true},
		{args: []string{"version"}, skip: true},
		{args: []string{"evaluate", "--controls", "./ctl"}, skip: false},
		{args: nil, skip: false},
	}

	for _, tt := range tests {
		got := ShouldSkipFirstRunHint(tt.args)
		if got != tt.skip {
			t.Fatalf("ShouldSkipFirstRunHint(%v) = %v, want %v", tt.args, got, tt.skip)
		}
	}
}
