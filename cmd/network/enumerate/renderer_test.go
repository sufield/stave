package enumerate

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/sufield/stave/internal/core/network"
)

func TestIsValidFormat(t *testing.T) {
	tests := []struct {
		format string
		want   bool
	}{
		{"json", true},
		{"text", true},
		{"", true},
		{"xml", false},
		{"yaml", false},
		{"csv", false},
	}

	for _, tt := range tests {
		t.Run(tt.format, func(t *testing.T) {
			if got := IsValidFormat(tt.format); got != tt.want {
				t.Errorf("IsValidFormat(%q) = %v, want %v", tt.format, got, tt.want)
			}
		})
	}
}

func TestNewRenderer(t *testing.T) {
	tests := []struct {
		format  string
		wantErr bool
	}{
		{"json", false},
		{"text", false},
		{"", false},
		{"xml", true},
		{"yaml", true},
	}

	for _, tt := range tests {
		t.Run(tt.format, func(t *testing.T) {
			r, err := NewRenderer(tt.format)
			if (err != nil) != tt.wantErr {
				t.Fatalf("NewRenderer(%q) err = %v, wantErr %v", tt.format, err, tt.wantErr)
			}
			if !tt.wantErr && r == nil {
				t.Fatal("expected non-nil renderer")
			}
		})
	}
}

func TestJSONRenderer_Render(t *testing.T) {
	r, err := NewRenderer("json")
	if err != nil {
		t.Fatalf("NewRenderer(json) failed: %v", err)
	}

	res := &network.EnumerateResult{
		Port:            22,
		ProductionHosts: 2,
		Paths: []network.SSHPath{
			{
				Source:      "src-1",
				Destination: "dst-1",
				Port:        22,
				PathType:    "ingress",
			},
		},
	}

	var buf bytes.Buffer
	if err := r.Render(&buf, res); err != nil {
		t.Fatalf("Render() error: %v", err)
	}

	var decoded network.EnumerateResult
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("Unmarshal() error: %v", err)
	}

	if decoded.Port != res.Port || decoded.ProductionHosts != res.ProductionHosts || len(decoded.Paths) != 1 {
		t.Errorf("decoded result mismatch: %+v", decoded)
	}
}

func TestTextRenderer_Render(t *testing.T) {
	r, err := NewRenderer("text")
	if err != nil {
		t.Fatalf("NewRenderer(text) failed: %v", err)
	}

	res := &network.EnumerateResult{
		Port:            22,
		ProductionHosts: 1,
		Paths: []network.SSHPath{
			{
				Source:      "internet",
				Destination: "i-prod1",
				Port:        22,
				PathType:    "direct",
			},
		},
	}

	var buf bytes.Buffer
	if err := r.Render(&buf, res); err != nil {
		t.Fatalf("Render() error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "SSH Entry Points to Production (port 22)") {
		t.Errorf("missing header in text output: %s", out)
	}
	if !strings.Contains(out, "i-prod1") {
		t.Errorf("missing destination in text output: %s", out)
	}
}

func TestTextRenderer_RenderEmpty(t *testing.T) {
	r, err := NewRenderer("text")
	if err != nil {
		t.Fatalf("NewRenderer(text) failed: %v", err)
	}

	res := &network.EnumerateResult{
		Port:            22,
		ProductionHosts: 1,
	}

	var buf bytes.Buffer
	if err := r.Render(&buf, res); err != nil {
		t.Fatalf("Render() error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "No SSH paths to production hosts found.") {
		t.Errorf("missing empty notice in text output: %s", out)
	}
}
