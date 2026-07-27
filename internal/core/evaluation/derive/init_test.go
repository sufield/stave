package derive

func init() {
	VPCCIDRTypes.Subnet = "aws_subnet"
	VPCCIDRTypes.SecurityGroup = "aws_ec2_security_group"
	VPCCIDRTypes.NetworkACL = "aws_vpc_network_acl"
	BucketAPTypes.Bucket = "aws_s3_bucket"
	BucketAPTypes.AccessPoint = "aws_s3_access_point"
}
