package ui

import "testing"

func TestSanitizePaths(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "absolute path",
			input: "cannot read /home/user/data/observations/snap1.json: no such file",
			want:  "cannot read snap1.json: no such file",
		},
		{
			name:  "multiple paths",
			input: "--controls not accessible: /home/user/ctl/s3/public.yaml and /home/user/obs/snap.json",
			want:  "--controls not accessible: public.yaml and snap.json",
		},
		{
			name:  "no path",
			input: "invalid --max-unsafe \"abc\"",
			want:  "invalid --max-unsafe \"abc\"",
		},
		{
			name:  "relative path preserved",
			input: "file not found: observations/snap1.json",
			want:  "file not found: observations/snap1.json",
		},
		{
			name:  "path with colon",
			input: "error in /home/user/file.yaml:10: bad syntax",
			want:  "error in file.yaml:10: bad syntax",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SanitizePaths(tt.input)
			if got != tt.want {
				t.Errorf("SanitizePaths(%q)\n  got:  %q\n  want: %q", tt.input, got, tt.want)
			}
		})
	}
}
