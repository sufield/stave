package crypto

import (
	"errors"
	"strings"
	"testing"
)

func TestHashBytesAndHashReader_Match(t *testing.T) {
	payload := []byte("stave-hash-payload")

	fromBytes := HashBytes(payload)
	fromReader, err := HashReader(strings.NewReader(string(payload)))
	if err != nil {
		t.Fatalf("HashReader() error = %v", err)
	}

	if fromReader != fromBytes {
		t.Fatalf("HashReader() = %s, want %s", fromReader, fromBytes)
	}
}

func TestHashReader_Error(t *testing.T) {
	expected := errors.New("boom")
	_, err := HashReader(errorReader{err: expected})
	if err == nil {
		t.Fatal("expected HashReader() to return error")
	}
	if !errors.Is(err, expected) {
		t.Fatalf("expected wrapped error %v, got %v", expected, err)
	}
}

type errorReader struct {
	err error
}

func (e errorReader) Read(_ []byte) (int, error) {
	return 0, e.err
}
