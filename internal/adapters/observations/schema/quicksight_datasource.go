package schema

import "github.com/sufield/stave/internal/core/kernel"

var quicksightDatasourceSchema = Schema{
	AssetType: kernel.AssetType("aws_quicksight_datasource"),
	Fields: []FieldRequirement{
		{Path: "properties.analytics.kind", Required: true,
			Doc: "type discriminator; every quicksight-datasource control gates on this"},
		{Path: "properties.analytics.network.has_vpc_connection", Required: true,
			Doc: "VPC connection present — network isolation family"},
		{Path: "properties.analytics.encryption.ssl_disabled", Required: true,
			Doc: "SSL disabled on data source connection — encryption-in-transit family"},
	},
}

func init() { Register(quicksightDatasourceSchema) }
