# aws lambda list-functions  ->  one aws_lambda_function asset per function.
# Single-call source; id = the FunctionArn AWS returns. execution_role_arn is the
# function's Role (the IAM role it assumes), which lets controls correlate a
# function to its role's permissions.
.Functions[] | {
  id: .FunctionArn,
  type: "aws_lambda_function",
  vendor: "aws",
  properties: { function: {
    name: .FunctionName,
    arn: .FunctionArn,
    runtime: .Runtime,
    execution_role_arn: .Role
  } }
}
