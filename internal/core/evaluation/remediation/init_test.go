package remediation

func init() {
	TypeTokens["aws_s3_bucket"] = []TokenDef{
		{Placeholder: "<bucket>"},
		{Placeholder: "<bucket-name>"},
	}
	TypeTokens["aws_iam_role"] = []TokenDef{
		{Placeholder: "<role>"},
		{Placeholder: "<role-name>"},
		{Placeholder: "<role-arn>", UseFullID: true},
	}
	TypeTokens["aws_iam_user"] = []TokenDef{
		{Placeholder: "<user>"},
		{Placeholder: "<user-name>"},
		{Placeholder: "<user-arn>", UseFullID: true},
	}
	TypeTokens["aws_iam_policy"] = []TokenDef{
		{Placeholder: "<policy>"},
		{Placeholder: "<policy-name>"},
		{Placeholder: "<policy-arn>", UseFullID: true},
	}
	TypeTokens["aws_eks_cluster"] = []TokenDef{
		{Placeholder: "<cluster>"},
		{Placeholder: "<cluster-name>"},
	}
	TypeTokens["aws_kms_key"] = []TokenDef{
		{Placeholder: "<key-id>"},
		{Placeholder: "<key-arn>", UseFullID: true},
	}
	TypeTokens["aws_cloudtrail_trail"] = []TokenDef{
		{Placeholder: "<trail-name>"},
	}
	TypeTokens["aws_s3_access_point"] = []TokenDef{
		{Placeholder: "<access-point-name>"},
	}
	TypeTokens["aws_lambda_function"] = []TokenDef{
		{Placeholder: "<function>"},
		{Placeholder: "<function-name>"},
	}
	TypeTokens["aws_ecs_service"] = []TokenDef{
		{Placeholder: "<service>"},
		{Placeholder: "<service-name>"},
	}
	TypeTokens["aws_vpc"] = []TokenDef{
		{Placeholder: "<vpc-id>"},
	}
	TypeTokens["aws_sqs_queue"] = []TokenDef{
		{Placeholder: "<queue>"},
		{Placeholder: "<queue-name>"},
	}
}
