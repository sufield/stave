package template

import (
	"io/fs"

	"github.com/sufield/stave/internal/templates"
)

// BuiltinFS returns the embedded filesystem containing built-in report templates.
func BuiltinFS() fs.FS {
	return templates.BuiltinTemplateFS
}
