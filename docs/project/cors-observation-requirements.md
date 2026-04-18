# Requirements: CORS Observation Capture for Stave

## Purpose

Define the observation schema requirements for capturing CORS configurations across AWS services, such that Stave can evaluate CORS-related security controls against local JSON snapshots without needing cloud credentials at evaluation time. Extractor implementation is out of scope; this document specifies what the observation must contain, not how to produce it.

## Scope

Five AWS services expose CORS configuration through public API responses and are in scope for observation capture:

1. S3 bucket CORS
2. API Gateway v1 (REST APIs) method-level CORS
3. API Gateway v2 (HTTP APIs) API-level CORS
4. CloudFront response headers policy CORS
5. Lambda Function URL CORS

AppSync, AWS SAM-generated CORS, and third-party CDN CORS configurations are out of scope for this iteration.

## General Requirements

**R1. Source fidelity.** The observation must preserve the exact field names, value types, and structural shape returned by the corresponding AWS CLI command. Predicates will reference these fields directly, so deviation from AWS's JSON shape creates predicate ambiguity.

**R2. Absence is observable.** For each service, the absence of CORS configuration is a distinct state from the presence of a permissive-but-empty configuration. The observation schema must represent three states unambiguously: not configured, configured with specific values, configured with wildcard.

**R3. Per-resource capture.** Each observable resource (bucket, API, policy, function URL) carries its own CORS observation. The schema must support CORS as a property of each resource type, not as a global or account-level concept.

**R4. Raw field preservation.** Every field returned by the AWS CLI command must be captured even if no current predicate consumes it. Predicates evolve; observations are expensive to re-capture.

**R5. Empty arrays are distinct from missing fields.** `AllowedOrigins: []` and an absent `AllowedOrigins` field are different states. The schema must distinguish them.

**R6. Credential-coupled CORS is a distinct signal.** Wildcard origin (`"*"`) combined with credentialed requests allowed is a structurally different configuration from wildcard origin alone. The observation must capture both fields so predicates can evaluate the compound.

## Service-Specific Requirements

### S3 Bucket CORS

**Source command:** `aws s3api get-bucket-cors --bucket <name>`

**Observation location:** Under each S3 bucket resource, as a `cors` property.

**Required fields:**
- `configured` (boolean): true if the bucket has any CORS configuration, false if the API returned `NoSuchCORSConfiguration`.
- `rules` (array, present only if `configured` is true): one object per `CORSRules` entry, preserving all fields:
  - `allowed_headers` (array of strings)
  - `allowed_methods` (array of strings)
  - `allowed_origins` (array of strings)
  - `expose_headers` (array of strings)
  - `max_age_seconds` (integer, may be absent)
  - `id` (string, may be absent — present when rule was named)

**Example snapshot fragment:**
```json
{
  "resource_type": "aws_s3_bucket",
  "arn": "arn:aws:s3:::example-bucket",
  "cors": {
    "configured": true,
    "rules": [
      {
        "allowed_headers": ["*"],
        "allowed_methods": ["GET", "PUT", "POST"],
        "allowed_origins": ["*"],
        "expose_headers": [],
        "max_age_seconds": 3000
      }
    ]
  }
}
```

**Absence example:**
```json
{
  "resource_type": "aws_s3_bucket",
  "arn": "arn:aws:s3:::example-bucket",
  "cors": {
    "configured": false
  }
}
```

### API Gateway v2 (HTTP APIs) CORS

**Source command:** `aws apigatewayv2 get-api --api-id <id>`

**Observation location:** Under each API Gateway v2 API resource, as a `cors_configuration` property.

**Required fields:**
- `configured` (boolean): true if the API has a `CorsConfiguration` object in its response, false otherwise.
- `allow_credentials` (boolean, present if configured): directly from `AllowCredentials` field.
- `allow_headers` (array of strings, present if configured): from `AllowHeaders`.
- `allow_methods` (array of strings, present if configured): from `AllowMethods`.
- `allow_origins` (array of strings, present if configured): from `AllowOrigins`.
- `expose_headers` (array of strings, present if configured): from `ExposeHeaders`.
- `max_age` (integer, present if configured): from `MaxAge`.

**Rationale for inclusion:** API Gateway v2's CORS configuration is the cleanest to capture because it's a top-level object on the API resource. One observation per API covers the entire API's CORS behavior.

### API Gateway v1 (REST APIs) CORS

**Source command:** A REST API's CORS behavior is defined per method, via OPTIONS integrations and method response headers. The capture requires `aws apigateway get-resources --rest-api-id <id>` followed by `aws apigateway get-method --rest-api-id <id> --resource-id <id> --http-method OPTIONS` for each resource.

**Observation location:** Under each REST API resource, as a `cors_by_method` property.

**Required fields:**
- `configured` (boolean): true if any method on the API has CORS-related integration response parameters set.
- `methods` (array of objects, present if configured): one per method with CORS configuration:
  - `resource_path` (string): path of the resource.
  - `http_method` (string): the method with CORS (typically `OPTIONS`).
  - `allowed_origins` (array of strings): parsed from the `Access-Control-Allow-Origin` integration response parameter value. Single-string AWS values are wrapped in a one-element array for schema consistency with v2.
  - `allowed_methods` (array of strings): parsed from `Access-Control-Allow-Methods`.
  - `allowed_headers` (array of strings): parsed from `Access-Control-Allow-Headers`.
  - `allow_credentials` (boolean): parsed from `Access-Control-Allow-Credentials` (`"true"` → true).
  - `raw_integration_response` (object): the full integration response object as returned by the API, for predicates that need detail the structured fields don't carry.

**Rationale for complexity:** REST APIs don't have a unified CORS surface. The observation normalizes it into the same shape as v2 where possible, with `raw_integration_response` as an escape hatch.

### CloudFront Response Headers Policy CORS

**Source command:** `aws cloudfront get-response-headers-policy --id <id>` for each policy, plus `aws cloudfront list-response-headers-policies` to enumerate.

**Observation location:** CloudFront response headers policies are a distinct resource type. Capture as `aws_cloudfront_response_headers_policy` resources, each with a `cors_config` property.

**Required fields on the policy resource:**
- `resource_type` (string): `"aws_cloudfront_response_headers_policy"`
- `id` (string): the policy ID.
- `name` (string): the policy name.
- `cors_config` (object):
  - `configured` (boolean): true if the policy has a `CorsConfig` block.
  - `access_control_allow_credentials` (boolean, if configured).
  - `access_control_allow_headers` (array of strings, if configured): from `AccessControlAllowHeaders.Items`.
  - `access_control_allow_methods` (array of strings, if configured): from `AccessControlAllowMethods.Items`.
  - `access_control_allow_origins` (array of strings, if configured): from `AccessControlAllowOrigins.Items`.
  - `access_control_expose_headers` (array of strings, if configured): from `AccessControlExposeHeaders.Items`.
  - `access_control_max_age_sec` (integer, if configured).
  - `origin_override` (boolean, if configured).

**Additional requirement:** CloudFront distributions reference response headers policies by ID. The observation must separately capture, on each `aws_cloudfront_distribution` resource, the `response_headers_policy_id` associated with each cache behavior so predicates can cross-reference which distributions use which CORS-carrying policies.

### Lambda Function URL CORS

**Source command:** `aws lambda get-function-url-config --function-name <name>`

**Observation location:** Under each Lambda function resource that has a function URL configured, as a `function_url_cors` property.

**Required fields:**
- `configured` (boolean): true if the function has a URL config with a `Cors` block.
- `allow_credentials` (boolean, if configured).
- `allow_headers` (array of strings, if configured).
- `allow_methods` (array of strings, if configured).
- `allow_origins` (array of strings, if configured).
- `expose_headers` (array of strings, if configured).
- `max_age` (integer, if configured).

**Additional requirement:** The function URL itself has an `AuthType` field (`AWS_IAM` or `NONE`). The observation must capture `auth_type` on the function resource, because unauthenticated function URLs with permissive CORS are a structurally different risk than IAM-authenticated ones.

## Cross-Service Requirements

**R7. Schema uniformity.** Predicates that reason about CORS across services should be able to use consistent field names where AWS's own APIs diverge. The observation schema normalizes to snake_case and uses consistent field names (`allow_origins`, `allow_credentials`, etc.) across all five services except where the source API's structure is genuinely different (REST API methods, CloudFront policy references).

**R8. Wildcard representation.** The string `"*"` is the wildcard value across all five services. The schema preserves it as a literal string; predicates check membership. Do not normalize wildcards to a separate boolean field — the array form preserves the distinction between `["*"]` (wildcard) and `["*", "https://example.com"]` (wildcard plus specific origin, which is still wildcard-effective but indicates an author who may not have understood that).

**R9. Compound-predicate support.** The schema must allow predicates to express the compound "wildcard origin AND credentials allowed" as a single rule. This requires that `allow_credentials` and `allow_origins` are always co-located on the same observation object, never split across unrelated properties.

**R10. Versioning.** Each observation carrying CORS data must include an observation schema version field (`observation_version: "v1"` or similar) so future schema changes can be detected and handled without breaking existing snapshots.

## Out of Scope

- Extractor implementation details: how the JSON is actually fetched, whether via boto3, AWS CLI invocation, or SDK calls.
- Runtime CORS behavior testing (actually sending OPTIONS requests to endpoints).
- CORS configurations on non-AWS resources (third-party CDNs, reverse proxies, application-level CORS middleware).
- Predicate authoring: which specific security controls are written against these observations. That's a separate iteration, gated on having disclosed-incident grounding per principle 3.
- Historical CORS state: the observation captures current state only. Change detection across snapshots is a separate concern handled by Stave's existing diff machinery.

## Acceptance Criteria

The observation schema meets requirements when:

1. A snapshot captured from an AWS account contains, for every resource of the five named types, either a populated CORS observation or an explicit `configured: false` marker.
2. The three states — not configured, configured without wildcard, configured with wildcard — are distinguishable by a predicate examining only the CORS observation fields.
3. A predicate can express "wildcard origin AND credentials allowed" for any of the five services using a single rule per service.
4. Raw source JSON can be reconstructed from the observation for every captured field (modulo snake_case conversion).
5. Absence of CORS configuration does not cause predicate evaluation errors — the schema guarantees the `configured` boolean is always present on any CORS-capable resource.

## Notes on Use

These requirements define the input side of the loop. Once the schema is extended and a sample snapshot exists, predicate authoring against disclosed CORS incidents becomes a separate iteration with its own grounding requirement.

The requirements deliberately don't name specific predicates or control IDs. That's predicate work, which depends on which CORS misconfigurations show up in disclosed incidents. This document makes those predicates possible, not inevitable.
