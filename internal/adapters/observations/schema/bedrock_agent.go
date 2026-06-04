package schema

import "github.com/sufield/stave/internal/core/kernel"

// aws_bedrock_agent — 12 controls. Detection is driven by ghost-resource and
// broad-scope signals on the agent; absence silently false-PASSes those controls.
var bedrockAgentSchema = Schema{
	AssetType: kernel.AssetType("aws_bedrock_agent"),
	Fields: []FieldRequirement{
		{Path: "properties.ai.kind", Required: true,
			Doc: "type discriminator; every bedrock-agent control gates on this"},
		{Path: "properties.ai.agent.has_ghost_action_group_lambda", Required: true,
			Doc: "ghost action-group Lambda detection — foundational for orphaned-resource controls"},
		{Path: "properties.ai.agent.model_invoke_scope_broad", Required: true,
			Doc: "broad model-invoke scope detection — overpermission family"},
		{Path: "properties.ai.agent.guardrail_associated", Required: true,
			Doc: "guardrail-association signal; controls gate on its absence"},
		{Path: "properties.ai.agent.lambda_invoke_scope_broad", Required: false,
			Doc: "broad Lambda-invoke scope; populated only when action groups exist"},
		{Path: "properties.ai.agent.public_invocation_endpoint", Required: false,
			Doc: "public-endpoint exposure; sparse, feature-gated signal"},
		{Path: "properties.ai.agent.invocation_logging_enabled", Required: false,
			Doc: "invocation-logging audit; only meaningful when logging is configured"},
	},
}

func init() { Register(bedrockAgentSchema) }
