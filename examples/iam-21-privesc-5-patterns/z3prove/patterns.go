package main

// method represents one named privilege-escalation method.
// Rhino-numbered methods carry their original method number;
// methods Rhino didn't enumerate carry rhino=0.
type method struct {
	rhino       int      // Rhino method number (1..21), or 0 if not in Rhino's list
	label       string   // human-readable name
	actions     []string // every required action must be effectively allowed
	target      string   // semantic target: "self", "another_principal", "compute_role", "trust"
	serviceTrust string  // for compute methods: the service principal the target role must trust
}

// pattern1Methods — Policy Self-Mutation
//
// Principal can modify its own effective permission set,
// either by changing a policy it's subject to, attaching a
// new policy, or joining a group with more permissions.
var pattern1Methods = []method{
	{rhino: 1, label: "iam:CreatePolicyVersion → activate admin version on a policy the principal uses",
		actions: []string{"iam:CreatePolicyVersion"}, target: "self"},
	{rhino: 2, label: "iam:SetDefaultPolicyVersion → activate dormant admin version",
		actions: []string{"iam:SetDefaultPolicyVersion"}, target: "self"},
	{rhino: 7, label: "iam:AttachUserPolicy → attach AdministratorAccess to self",
		actions: []string{"iam:AttachUserPolicy"}, target: "self"},
	{rhino: 8, label: "iam:AttachGroupPolicy → attach admin to own group",
		actions: []string{"iam:AttachGroupPolicy"}, target: "self"},
	{rhino: 9, label: "iam:AttachRolePolicy → attach admin to assumable role",
		actions: []string{"iam:AttachRolePolicy"}, target: "self"},
	{rhino: 10, label: "iam:PutUserPolicy → create admin inline on self",
		actions: []string{"iam:PutUserPolicy"}, target: "self"},
	{rhino: 11, label: "iam:PutGroupPolicy → create admin inline on own group",
		actions: []string{"iam:PutGroupPolicy"}, target: "self"},
	{rhino: 12, label: "iam:PutRolePolicy → create admin inline on own role",
		actions: []string{"iam:PutRolePolicy"}, target: "self"},
	{rhino: 13, label: "iam:AddUserToGroup → join admin group",
		actions: []string{"iam:AddUserToGroup"}, target: "self"},

	// Beyond Rhino's enumeration — same structural pattern.
	{label: "iam:CreatePolicy + iam:AttachUserPolicy → create admin policy and attach",
		actions: []string{"iam:CreatePolicy", "iam:AttachUserPolicy"}, target: "self"},
	{label: "iam:DeleteUserPolicy + iam:PutUserPolicy → drop restrictive inline, replace",
		actions: []string{"iam:DeleteUserPolicy", "iam:PutUserPolicy"}, target: "self"},
	{label: "iam:DetachUserPolicy + iam:AttachUserPolicy → swap boundary for admin",
		actions: []string{"iam:DetachUserPolicy", "iam:AttachUserPolicy"}, target: "self"},
	{label: "iam:DeleteRolePermissionsBoundary → remove permissions boundary on assumable role",
		actions: []string{"iam:DeleteRolePermissionsBoundary"}, target: "self"},
}

// pattern2Methods — Credential Creation/Theft
//
// Principal creates credentials for, or hijacks access to, a
// more privileged principal — without modifying any policy.
var pattern2Methods = []method{
	{rhino: 4, label: "iam:CreateAccessKey → create API keys for an admin user",
		actions: []string{"iam:CreateAccessKey"}, target: "another_principal"},
	{rhino: 5, label: "iam:CreateLoginProfile → create console password for admin user",
		actions: []string{"iam:CreateLoginProfile"}, target: "another_principal"},
	{rhino: 6, label: "iam:UpdateLoginProfile → reset admin user's password",
		actions: []string{"iam:UpdateLoginProfile"}, target: "another_principal"},
	{rhino: 14, label: "iam:UpdateAssumeRolePolicy → add self to admin role's trust policy",
		actions: []string{"iam:UpdateAssumeRolePolicy"}, target: "trust"},

	// Beyond Rhino's enumeration.
	{label: "iam:CreateVirtualMFADevice + iam:EnableMFADevice → register attacker MFA on admin account",
		actions: []string{"iam:CreateVirtualMFADevice", "iam:EnableMFADevice"}, target: "another_principal"},
	{label: "iam:DeactivateMFADevice → disable MFA on admin user, weaken auth",
		actions: []string{"iam:DeactivateMFADevice"}, target: "another_principal"},
	{label: "sts:GetFederationToken → mint federated session for persistence",
		actions: []string{"sts:GetFederationToken"}, target: "another_principal"},
}

// pattern3Methods — Compute + PassRole
//
// Principal launches or modifies compute that runs with a
// more privileged role. Requires iam:PassRole plus a
// compute-launch action.
var pattern3Methods = []method{
	{rhino: 3, label: "ec2:RunInstances + iam:PassRole → EC2 with admin instance profile",
		actions: []string{"ec2:RunInstances", "iam:PassRole"}, target: "compute_role", serviceTrust: "ec2.amazonaws.com"},
	{rhino: 15, label: "lambda:CreateFunction + lambda:InvokeFunction + iam:PassRole",
		actions: []string{"lambda:CreateFunction", "lambda:InvokeFunction", "iam:PassRole"}, target: "compute_role", serviceTrust: "lambda.amazonaws.com"},
	{rhino: 16, label: "lambda:CreateFunction + lambda:CreateEventSourceMapping + iam:PassRole",
		actions: []string{"lambda:CreateFunction", "lambda:CreateEventSourceMapping", "iam:PassRole"}, target: "compute_role", serviceTrust: "lambda.amazonaws.com"},
	{rhino: 17, label: "lambda:UpdateFunctionCode → hijack existing Lambda's role",
		actions: []string{"lambda:UpdateFunctionCode"}, target: "compute_role", serviceTrust: "lambda.amazonaws.com"},
	{rhino: 18, label: "glue:CreateDevEndpoint + iam:PassRole → SageMaker-style notebook with admin role",
		actions: []string{"glue:CreateDevEndpoint", "iam:PassRole"}, target: "compute_role", serviceTrust: "glue.amazonaws.com"},
	{rhino: 19, label: "glue:UpdateDevEndpoint → hijack existing Glue endpoint",
		actions: []string{"glue:UpdateDevEndpoint"}, target: "compute_role", serviceTrust: "glue.amazonaws.com"},
	{rhino: 20, label: "cloudformation:CreateStack + iam:PassRole",
		actions: []string{"cloudformation:CreateStack", "iam:PassRole"}, target: "compute_role", serviceTrust: "cloudformation.amazonaws.com"},
	{rhino: 21, label: "datapipeline:CreatePipeline + datapipeline:PutPipelineDefinition + iam:PassRole",
		actions: []string{"datapipeline:CreatePipeline", "datapipeline:PutPipelineDefinition", "iam:PassRole"}, target: "compute_role", serviceTrust: "datapipeline.amazonaws.com"},

	// Beyond Rhino's enumeration — same structural pattern.
	{label: "autoscaling:CreateLaunchConfiguration + autoscaling:CreateAutoScalingGroup + iam:PassRole",
		actions: []string{"autoscaling:CreateLaunchConfiguration", "autoscaling:CreateAutoScalingGroup", "iam:PassRole"}, target: "compute_role", serviceTrust: "ec2.amazonaws.com"},
	{label: "ecs:RunTask + iam:PassRole",
		actions: []string{"ecs:RunTask", "iam:PassRole"}, target: "compute_role", serviceTrust: "ecs-tasks.amazonaws.com"},
	{label: "ecs:CreateService + iam:PassRole",
		actions: []string{"ecs:CreateService", "iam:PassRole"}, target: "compute_role", serviceTrust: "ecs-tasks.amazonaws.com"},
	{label: "codebuild:CreateProject + codebuild:StartBuild + iam:PassRole",
		actions: []string{"codebuild:CreateProject", "codebuild:StartBuild", "iam:PassRole"}, target: "compute_role", serviceTrust: "codebuild.amazonaws.com"},
	{label: "sagemaker:CreateNotebookInstance + iam:PassRole",
		actions: []string{"sagemaker:CreateNotebookInstance", "iam:PassRole"}, target: "compute_role", serviceTrust: "sagemaker.amazonaws.com"},
	{label: "sagemaker:CreateTrainingJob + iam:PassRole",
		actions: []string{"sagemaker:CreateTrainingJob", "iam:PassRole"}, target: "compute_role", serviceTrust: "sagemaker.amazonaws.com"},
	{label: "batch:SubmitJob + iam:PassRole",
		actions: []string{"batch:SubmitJob", "iam:PassRole"}, target: "compute_role", serviceTrust: "batch.amazonaws.com"},
	{label: "states:CreateStateMachine + iam:PassRole",
		actions: []string{"states:CreateStateMachine", "iam:PassRole"}, target: "compute_role", serviceTrust: "states.amazonaws.com"},
	{label: "apprunner:CreateService + iam:PassRole",
		actions: []string{"apprunner:CreateService", "iam:PassRole"}, target: "compute_role", serviceTrust: "apprunner.amazonaws.com"},
}

// pattern4Methods — Indirect Compute Invocation
//
// Principal triggers compute execution without direct
// invoke permission, by manipulating the event source that
// triggers the compute.
var pattern4Methods = []method{
	{rhino: 16, label: "dynamodb:PutItem → trigger DynamoDB stream → Lambda with privileged role",
		actions: []string{"dynamodb:PutItem"}, target: "compute_role"},

	// Beyond Rhino's enumeration.
	{label: "sqs:SendMessage → trigger SQS → Lambda subscriber",
		actions: []string{"sqs:SendMessage"}, target: "compute_role"},
	{label: "kinesis:PutRecord → trigger Kinesis → Lambda consumer",
		actions: []string{"kinesis:PutRecord"}, target: "compute_role"},
	{label: "sns:Publish → trigger SNS → Lambda subscription",
		actions: []string{"sns:Publish"}, target: "compute_role"},
	{label: "s3:PutObject → trigger S3 event notification → Lambda",
		actions: []string{"s3:PutObject"}, target: "compute_role"},
	{label: "events:PutRule + events:PutTargets → EventBridge rule with Lambda target",
		actions: []string{"events:PutRule", "events:PutTargets"}, target: "compute_role"},
	{label: "iot:CreateTopicRule → IoT rule → Lambda action",
		actions: []string{"iot:CreateTopicRule"}, target: "compute_role"},
	{label: "ses:CreateReceiptRule → SES receipt rule → Lambda action",
		actions: []string{"ses:CreateReceiptRule"}, target: "compute_role"},
	{label: "cognito-idp:UpdateUserPool → Cognito trigger → Lambda",
		actions: []string{"cognito-idp:UpdateUserPool"}, target: "compute_role"},
	{label: "cloudwatch:PutMetricAlarm → alarm action → Lambda",
		actions: []string{"cloudwatch:PutMetricAlarm"}, target: "compute_role"},
}

// pattern5Methods — Role Trust Modification
//
// Principal modifies a role's trust policy to allow
// self-assumption, or creates a new role whose trust the
// principal controls.
var pattern5Methods = []method{
	{rhino: 14, label: "iam:UpdateAssumeRolePolicy → modify admin role trust to add self",
		actions: []string{"iam:UpdateAssumeRolePolicy"}, target: "trust"},

	// Beyond Rhino's enumeration.
	{label: "iam:CreateRole + iam:AttachRolePolicy → mint new admin role with controlled trust",
		actions: []string{"iam:CreateRole", "iam:AttachRolePolicy"}, target: "trust"},
	{label: "iam:DeleteRolePolicy → strip restrictive inline policy, widen permissions, then assume",
		actions: []string{"iam:DeleteRolePolicy", "sts:AssumeRole"}, target: "trust"},
}
