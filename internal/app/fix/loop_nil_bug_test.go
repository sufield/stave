package fix

import (
	"context"
	"os"
	"testing"
)

func TestService_LoopNilReceiverHandledSafely(t *testing.T) {
	var s *Service

	defer func() {
		if rec := recover(); rec != nil {
			t.Fatalf("Service.Loop panicked on nil receiver: %v", rec)
		}
	}()

	dir1 := t.TempDir()
	dir2 := t.TempDir()
	dir3 := t.TempDir()
	outDir := t.TempDir()

	_ = os.WriteFile(dir1+"/a.json", []byte("{}"), 0644)
	_ = os.WriteFile(dir2+"/a.json", []byte("{}"), 0644)
	_ = os.WriteFile(dir3+"/a.yaml", []byte("{}"), 0644)

	req := LoopRequest{
		BeforeDir:   dir1,
		AfterDir:    dir2,
		ControlsDir: dir3,
		OutDir:      outDir,
	}

	err := s.Loop(context.Background(), req, LoopDeps{}, nil, nil)
	if err == nil {
		t.Errorf("expected error from Service.Loop on nil receiver")
	}
}
