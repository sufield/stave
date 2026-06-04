package schema

import "github.com/sufield/stave/internal/core/kernel"

// aws_eventbridge_pipe — 11 controls. governance.kind is the type
// discriminator; source/target DLQ presence, source filtering, and the
// enrichment/source IAM-wildcard signals drive the pipe resilience and
// least-privilege families.
var eventbridgePipeSchema = Schema{
	AssetType: kernel.AssetType("aws_eventbridge_pipe"),
	Fields: []FieldRequirement{
		{Path: "properties.governance.kind", Required: true,
			Doc: "type discriminator; every EventBridge-pipe control gates on this"},
		{Path: "properties.governance.events.source_type", Required: true,
			Doc: "pipe source taxonomy; controls branch on source class"},
		{Path: "properties.governance.events.has_source_filter", Required: true,
			Doc: "source-filter presence — core over-fanout detection signal"},
		{Path: "properties.governance.events.source_has_dlq", Required: true,
			Doc: "source dead-letter-queue presence — core resilience signal"},
		{Path: "properties.governance.events.target_has_dlq", Required: true,
			Doc: "target dead-letter-queue presence — core resilience signal"},
		{Path: "properties.governance.events.source_role_has_wildcard", Required: true,
			Doc: "source-role wildcard detection — least-privilege signal"},
		{Path: "properties.governance.events.enrichment_role_has_wildcard", Required: false,
			Doc: "enrichment-role wildcard; sparse when no enrichment configured"},
		{Path: "properties.governance.events.kafka_credentials_plaintext", Required: false,
			Doc: "plaintext-credential signal; sparse, Kafka/MSK sources only"},
		{Path: "properties.governance.events.alarm_failed_configured", Required: false,
			Doc: "failed-invocation alarm coverage; sparse when no alarm wired"},
	},
}

func init() { Register(eventbridgePipeSchema) }
