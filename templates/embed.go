package templates

import "embed"

//go:embed all:bucket-hijacking-assessment all:m-and-a-diligence all:breach-reconstruction all:independent-audit all:critical-findings
var BuiltinTemplateFS embed.FS
