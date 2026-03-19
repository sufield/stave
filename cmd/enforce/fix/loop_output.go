package fix

import appfix "github.com/sufield/stave/internal/app/fix"

// Re-export types from internal/app/fix so existing tests and command.go
// can reference them without import changes.

type LoopReport = appfix.LoopReport
type LoopArtifacts = appfix.LoopArtifacts
