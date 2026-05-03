package policy

// Policy constants.
const (
	wildcard         = "*"
	s3Wildcard       = "s3:*"
	s3GlobalResource = "arn:aws:s3:::*"
)

// isWildcardPrincipal reports whether s is the universal IAM wildcard ("*").
func isWildcardPrincipal(s string) bool { return s == wildcard }

// isWildcardAction reports whether s grants all actions ("*" or "s3:*").
func isWildcardAction(s string) bool { return s == wildcard || s == s3Wildcard }

// isWildcardResource reports whether s matches all S3 resources ("*" or "arn:aws:s3:::*").
func isWildcardResource(s string) bool { return s == wildcard || s == s3GlobalResource }

// S3 action constants (lowercase for case-insensitive matching).
const (
	actionGetObject          = "s3:getobject"
	actionListBucket         = "s3:listbucket"
	actionListBucketVersions = "s3:listbucketversions"
	actionPutObject          = "s3:putobject"
	actionPutObjectACL       = "s3:putobjectacl"
	actionPutBucketPolicy    = "s3:putbucketpolicy"
	actionDeleteObject       = "s3:deleteobject"
	actionDeleteBucket       = "s3:deletebucket"
	actionPutBucketACL       = "s3:putbucketacl"
	actionGetBucketACL       = "s3:getbucketacl"
	actionGetObjectACL       = "s3:getobjectacl"
	actionPrefixGet          = "s3:get"
	actionPrefixList         = "s3:list"
	actionPrefixPut          = "s3:put"
	actionPrefixDelete       = "s3:delete"
)

// Condition keys and values.
const (
	condBool            = "Bool"
	condSecureTransport = "aws:SecureTransport"
	condValueFalse      = "false"
	principalAWS        = "AWS"
)

// Condition operator prefixes and suffixes.
const (
	condPrefixForAnyValue  = "foranyvalue:"
	condPrefixForAllValues = "forallvalues:"
	condSuffixIfExists     = "ifexists"
)
