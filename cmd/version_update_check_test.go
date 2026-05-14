package cmd

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSameVersion(t *testing.T) {
	cases := []struct {
		current, latest string
		want            bool
	}{
		{"0.0.4", "0.0.4", true},
		{"v0.0.4", "0.0.4", true},
		{"0.0.4", "v0.0.4", true},
		{"v0.0.4", "v0.0.4", true},
		{"0.0.3", "0.0.4", false},
		{"v0.0.3", "v0.0.4", false},
		{"edge", "v0.0.4", false},
		{"", "v0.0.4", false},
		{" v0.0.4 ", "v0.0.4", true}, // whitespace tolerance
	}
	for _, c := range cases {
		if got := sameVersion(c.current, c.latest); got != c.want {
			t.Errorf("sameVersion(%q, %q) = %v, want %v", c.current, c.latest, got, c.want)
		}
	}
}

func TestFetchLatestRelease_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"tag_name":"v1.2.3","name":"Release 1.2.3"}`))
	}))
	defer srv.Close()

	tag, err := fetchLatestRelease(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("fetchLatestRelease error: %v", err)
	}
	if tag != "v1.2.3" {
		t.Errorf("tag_name = %q, want %q", tag, "v1.2.3")
	}
}

func TestFetchLatestRelease_Non200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
	}))
	defer srv.Close()

	if _, err := fetchLatestRelease(context.Background(), srv.URL); err == nil {
		t.Fatal("expected error on non-200 response, got nil")
	}
}

func TestFetchLatestRelease_EmptyTag(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"name":"no tag here"}`))
	}))
	defer srv.Close()

	if _, err := fetchLatestRelease(context.Background(), srv.URL); err == nil {
		t.Fatal("expected error on empty tag_name, got nil")
	}
}

func TestRunUpdateCheck_NoNetworkEnvShortCircuits(t *testing.T) {
	t.Setenv("STAVE_NO_NETWORK", "1")
	var buf bytes.Buffer
	runUpdateCheck(context.Background(), &buf, "v0.0.4")
	got := buf.String()
	if !bytes.Contains(buf.Bytes(), []byte("Update check skipped")) {
		t.Errorf("expected skip message, got: %s", got)
	}
}
