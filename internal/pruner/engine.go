package pruner

import (
	"fmt"
	"os"
)

// DeleteFile represents a filesystem path selected for deletion.
type DeleteFile struct {
	Path string
}

// DeleteInput defines deletion execution dependencies.
type DeleteInput struct {
	Files  []DeleteFile
	Remove func(string) error
}

// DeleteResult captures deletion execution totals.
type DeleteResult struct {
	Deleted int
}

// ApplyDelete executes the prune inner loop over selected files.
// It is intentionally CLI-agnostic so command handlers can stay thin.
func ApplyDelete(in DeleteInput) (DeleteResult, error) {
	remove := in.Remove
	if remove == nil {
		remove = os.Remove
	}

	out := DeleteResult{}
	for _, file := range in.Files {
		if err := remove(file.Path); err != nil {
			return out, fmt.Errorf("remove %s: %w", file.Path, err)
		}
		out.Deleted++
	}
	return out, nil
}
