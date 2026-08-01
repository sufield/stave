package network

func init() {
	GraphTypes.Instance = "aws_ec2_instance"
	GraphTypes.SecurityGroup = "aws_ec2_security_group"
	GraphTypes.PeeringConnection = "aws_vpc_peering_connection"
	GraphTypes.Subnet = "aws_ec2_subnet"
	GraphTypes.RouteTable = "aws_ec2_route_table"
	GraphTypes.Firewall = "aws_networkfirewall_firewall"
}
