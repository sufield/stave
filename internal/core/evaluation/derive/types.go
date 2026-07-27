package derive

// VPCCIDRTypes holds the asset type strings for the VPC CIDR
// coverage enricher. Populated by the provider's Register function
// at startup; empty strings disable the corresponding enricher.
var VPCCIDRTypes struct {
	Subnet        string
	SecurityGroup string
	NetworkACL    string
}

// BucketAPTypes holds the asset type strings for the bucket access
// point exposure enricher. Populated by the provider's Register
// function at startup; empty strings disable the corresponding
// enricher.
var BucketAPTypes struct {
	Bucket      string
	AccessPoint string
}
