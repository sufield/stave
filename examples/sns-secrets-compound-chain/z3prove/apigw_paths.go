package main

// apigwManagementPaths enumerates a representative subset
// of the API Gateway management-plane resource paths that
// the `apigateway:GET` action operates on. Source:
// https://docs.aws.amazon.com/apigateway/latest/api/API_Operations.html
//
// Each path here is a resource the action could target. A
// principal with `apigateway:GET` on `Resource: "*"` can
// reach all of them by default; a Deny scoped to specific
// paths only blocks the listed ones, leaving the rest
// reachable. The deny-coverage table in the Z3 prover
// quotes this list directly.
var apigwManagementPaths = []string{
	"/restapis",
	"/restapis/{id}",
	"/restapis/{id}/resources",
	"/restapis/{id}/resources/{resource_id}",
	"/restapis/{id}/resources/{resource_id}/methods/{method}",
	"/restapis/{id}/resources/{resource_id}/methods/{method}/integration",
	"/restapis/{id}/stages",
	"/restapis/{id}/stages/{stage}",
	"/restapis/{id}/deployments",
	"/restapis/{id}/deployments/{deployment_id}",
	"/restapis/{id}/models",
	"/restapis/{id}/authorizers",
	"/restapis/{id}/gatewayresponses",
	"/restapis/{id}/requestvalidators",
	"/restapis/{id}/documentation",
	"/apikeys",
	"/apikeys/{key_id}",
	"/usageplans",
	"/usageplans/{plan_id}",
	"/usageplans/{plan_id}/keys",
	"/domainnames",
	"/vpclinks",
	"/clientcertificates",
	"/account",
}
