package transform

import (
	"path/filepath"
	"regexp"
)

// filenamekey.go lets raw per-call enrichment files work without manual
// annotation. A call like `aws s3api get-public-access-block` returns no bucket
// name, so the merge id normally has to be added by hand
// (`{"Bucket":"<name>", ...}`). Instead, if the file is NAMED with the resource
// key (`s3-pab-<bucket>.json`), the key is derived from the filename and
// injected into the parsed JSON under the field the filter expects — so the
// existing filter reads it as if it were annotated.
//
// Only resources whose id is fully determined by the captured key are eligible.
// S3 qualifies (bucket name → arn:aws:s3:::<name>). IAM roles do NOT: the asset
// id is the full role ARN, which a role NAME alone can't reconstruct (account +
// path), so role enrichment still requires an explicit RoleArn annotation.

type filenameKeyPattern struct {
	re    *regexp.Regexp // exactly one capture group = the key
	field string         // JSON field to inject (the filter's join key)
}

var filenameKeyPatterns = []filenameKeyPattern{
	{regexp.MustCompile(`^s3-pab-(.+)\.json$`), "Bucket"},
	{regexp.MustCompile(`^s3-encryption-(.+)\.json$`), "Bucket"},
	{regexp.MustCompile(`^s3-tags-(.+)\.json$`), "Bucket"},
}

// injectFilenameKey sets parsed[field] = <key from filename> when name matches a
// pattern and parsed doesn't already carry the field. Returns true if it
// injected a key. Content-supplied keys win — an annotated file is never
// overridden by its filename.
func injectFilenameKey(name string, parsed map[string]any) bool {
	base := filepath.Base(name)
	for _, p := range filenameKeyPatterns {
		m := p.re.FindStringSubmatch(base)
		if m == nil {
			continue
		}
		if _, exists := parsed[p.field]; exists {
			return false
		}
		parsed[p.field] = m[1]
		return true
	}
	return false
}
