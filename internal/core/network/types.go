package network

// GraphTypes holds the asset type strings for the network graph
// builder. Populated by the provider's Register function at startup;
// empty strings cause the corresponding extractor to be skipped.
var GraphTypes struct {
	Instance          string
	SecurityGroup     string
	PeeringConnection string
	Subnet            string
	RouteTable        string
	Firewall          string
	TransitGateway    string
}
