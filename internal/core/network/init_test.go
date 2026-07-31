package network

func init() {
	GraphTypes.Instance = "aws_ec2_instance"
	GraphTypes.SecurityGroup = "aws_ec2_security_group"
	GraphTypes.PeeringConnection = "aws_vpc_peering_connection"
}
