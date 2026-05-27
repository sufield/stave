package main

// computeLaunchVector represents one known way to launch
// compute with a specified IAM role. Each vector requires
// the listed actions to all be effectively permitted (in
// Allow, not in Deny) plus iam:PassRole eligibility for
// PassedToService.
type computeLaunchVector struct {
	Service         string
	Description     string
	RequiredActions []string
	PassedToService string
}

// computeLaunchVectors enumerates the AWS services through
// which a principal with iam:PassRole can launch compute
// running with a specified IAM role. The set is the
// foundation for the Z3 deny-coverage proof: each vector
// the principal can effectively reach (allowed and not
// denied) is a privilege-escalation path.
//
// Source: AWS service authorization references; PMapper
// research; Rhino Security Labs IAM privesc methods. The
// list is bounded by what we know AWS supports today;
// new compute services AWS introduces become new vectors
// the deny list must learn about.
var computeLaunchVectors = []computeLaunchVector{
	{
		Service:         "ec2",
		Description:     "Direct EC2 launch with instance profile",
		RequiredActions: []string{"ec2:RunInstances"},
		PassedToService: "ec2.amazonaws.com",
	},
	{
		Service:         "lambda",
		Description:     "Create Lambda with execution role",
		RequiredActions: []string{"lambda:CreateFunction"},
		PassedToService: "lambda.amazonaws.com",
	},
	{
		Service:         "lambda",
		Description:     "Update existing Lambda to use different execution role",
		RequiredActions: []string{"lambda:UpdateFunctionConfiguration"},
		PassedToService: "lambda.amazonaws.com",
	},
	{
		Service:         "cloudformation",
		Description:     "Create CloudFormation stack with execution role",
		RequiredActions: []string{"cloudformation:CreateStack"},
		PassedToService: "cloudformation.amazonaws.com",
	},
	{
		Service:         "autoscaling",
		Description:     "Auto Scaling launch config + group with instance profile",
		RequiredActions: []string{"autoscaling:CreateLaunchConfiguration", "autoscaling:CreateAutoScalingGroup"},
		PassedToService: "ec2.amazonaws.com",
	},
	{
		Service:         "ecs",
		Description:     "Run ECS task with task role",
		RequiredActions: []string{"ecs:RunTask"},
		PassedToService: "ecs-tasks.amazonaws.com",
	},
	{
		Service:         "codebuild",
		Description:     "Create and start CodeBuild project with service role",
		RequiredActions: []string{"codebuild:CreateProject", "codebuild:StartBuild"},
		PassedToService: "codebuild.amazonaws.com",
	},
	{
		Service:         "glue",
		Description:     "Create Glue job with execution role",
		RequiredActions: []string{"glue:CreateJob"},
		PassedToService: "glue.amazonaws.com",
	},
	{
		Service:         "sagemaker",
		Description:     "Create SageMaker notebook with execution role",
		RequiredActions: []string{"sagemaker:CreateNotebookInstance"},
		PassedToService: "sagemaker.amazonaws.com",
	},
}
