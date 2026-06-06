package ui

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"syscall"
	"testing"
)

// A bytes.Buffer is never a *os.File, so it is never a TTY — NewPager must
// return it untouched and a no-op close, regardless of the enabled flag.
func TestNewPager_NonTTY_PassesThrough(t *testing.T) {
	for _, enabled := range []bool{true, false} {
		var buf bytes.Buffer
		w, closeFn := NewPager(context.Background(), &buf, enabled)
		if _, err := w.Write([]byte("hello")); err != nil {
			t.Fatalf("write: %v", err)
		}
		if err := closeFn(); err != nil {
			t.Fatalf("close: %v", err)
		}
		if buf.String() != "hello" {
			t.Errorf("enabled=%v: output went somewhere other than the passed writer: %q", enabled, buf.String())
		}
	}
}

func TestResolvePager_HonorsPAGER(t *testing.T) {
	t.Setenv("PAGER", "cat")
	name, args := resolvePager()
	if !strings.HasSuffix(name, "cat") {
		t.Errorf("PAGER=cat should resolve to a cat binary, got %q", name)
	}
	if len(args) != 0 {
		t.Errorf("PAGER=cat carries no args, got %v", args)
	}
}

func TestResolvePager_PAGERWithArgsSplit(t *testing.T) {
	t.Setenv("PAGER", "cat -n")
	name, args := resolvePager()
	if !strings.HasSuffix(name, "cat") {
		t.Errorf("expected cat, got %q", name)
	}
	if len(args) != 1 || args[0] != "-n" {
		t.Errorf("expected args [-n], got %v", args)
	}
}

// An unresolvable $PAGER must not be used; resolvePager falls back (to less/
// more if present, else "" meaning "do not page").
func TestResolvePager_UnresolvableFallsBack(t *testing.T) {
	t.Setenv("PAGER", "/no/such/pager-binary-xyz")
	name, _ := resolvePager()
	if strings.Contains(name, "pager-binary-xyz") {
		t.Errorf("must not return a nonexistent PAGER, got %q", name)
	}
}

func TestEpipeSwallowWriter(t *testing.T) {
	// EPIPE (user quit the pager) is swallowed: Write reports the full length
	// written and no error, so a renderer's tw.Flush does not bubble it up.
	ep := epipeSwallowWriter{w: errWriter{err: syscall.EPIPE}}
	n, err := ep.Write([]byte("abc"))
	if err != nil || n != 3 {
		t.Errorf("EPIPE should be swallowed as (len, nil), got (%d, %v)", n, err)
	}
	// A non-EPIPE error still propagates.
	other := errors.New("disk full")
	ep2 := epipeSwallowWriter{w: errWriter{err: other}}
	if _, err := ep2.Write([]byte("abc")); !errors.Is(err, other) {
		t.Errorf("non-EPIPE error must propagate, got %v", err)
	}
}

type errWriter struct{ err error }

func (e errWriter) Write(p []byte) (int, error) { return 0, e.err }

// Guard: NewPager only ever pages a real terminal. os.Stdout under `go test`
// is a pipe, so enabled=true must still pass it through unchanged.
func TestNewPager_TestStdoutNotPaged(t *testing.T) {
	if IsTerminal(os.Stdout) {
		t.Skip("stdout is a real terminal in this environment; pass-through guard N/A")
	}
	w, closeFn := NewPager(context.Background(), os.Stdout, true)
	defer func() { _ = closeFn() }()
	if w != os.Stdout {
		t.Errorf("non-terminal stdout must pass through unchanged, got %T", w)
	}
}
