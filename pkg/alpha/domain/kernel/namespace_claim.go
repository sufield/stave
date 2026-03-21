package kernel

// NamespaceClaim records whether an S3 bucket namespace is registered and owned.
// Used by CTL.S3.BUCKET.TAKEOVER.001 to detect dangling bucket references.
type NamespaceClaim struct {
	Exists bool // bucket exists in S3 namespace
	Owned  bool // bucket is owned by the expected account
}
