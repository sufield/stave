package risk

import "strings"

// S3ActionMap maps S3 policy action strings to domain permissions.
var S3ActionMap = map[string]Permission{
	"*":                      PermFullControl,
	"s3:*":                   PermFullControl,
	"s3:getobject":           PermRead,
	"s3:putobject":           PermWrite,
	"s3:listbucket":          PermList,
	"s3:getbucketacl":        PermAdminRead,
	"s3:getobjectacl":        PermAdminRead,
	"s3:putbucketacl":        PermAdminWrite,
	"s3:putobjectacl":        PermAdminWrite,
	"s3:deleteobject":        PermDelete,
	"s3:deletebucket":        PermDelete,
	"s3:listbucketversions":  PermList,
}

// S3PrefixRules maps S3 action prefixes to domain permissions.
var S3PrefixRules = []PrefixRule{
	{Prefix: "s3:put", Perm: PermWrite},
	{Prefix: "s3:delete", Perm: PermDelete},
}

// NormalizeActions lowercases and trims all action strings.
func NormalizeActions(actions []string) []string {
	out := make([]string, len(actions))
	for i, a := range actions {
		out[i] = strings.ToLower(strings.TrimSpace(a))
	}
	return out
}
