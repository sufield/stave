# Cross-service CORS Namespace

CORS configuration appears under four namespace prefixes depending on
which AWS service hosts it: `storage.cors.*` (S3), `api.cors.*` (API
Gateway v2), `cdn.response_headers_policy.cors.*` (CloudFront), and
`compute.function_url.cors.*` (Lambda Function URLs). This file
documents the complete cross-service surface as one unit so controls
that span multiple services have a single reference.

Part of the [observation contract](README.md).

## Cross-origin resource sharing namespace

CORS configurations are captured per service from AWS CLI JSON responses
and normalized into precomputed boolean signals plus raw rule arrays.
Predicates evaluate the precomputed booleans; raw rules remain available
for custom predicates. The compound signal **wildcard origin combined
with credentialed access** is the primary unsafe state — naked wildcard
origins on public assets are expected.

### S3 bucket (`aws_s3_bucket`)

Source: `aws s3api get-bucket-cors --bucket <name>`. The API returns
`NoSuchCORSConfiguration` when no CORS is set; that maps to
`storage.cors.configured = false`.

| Field | Type | Description |
|-------|------|-------------|
| `storage.cors.configured` | bool | Bucket has any CORS configuration |
| `storage.cors.allows_wildcard_origin` | bool | Any rule has `"*"` in `AllowedOrigins` |

### API Gateway v2 HTTP API (`aws_apigatewayv2_api`)

Source: `aws apigatewayv2 get-api --api-id <id>`. The top-level
`CorsConfiguration` object contains `AllowOrigins` and
`AllowCredentials` directly.

| Field | Type | Description |
|-------|------|-------------|
| `api.kind` | string | `"http_api"` for API Gateway v2 HTTP APIs |
| `api.cors.configured` | bool | API has a `CorsConfiguration` object |
| `api.cors.allows_wildcard_origin` | bool | `AllowOrigins` contains `"*"` |
| `api.cors.credentials_allowed` | bool | `AllowCredentials` is `true` |
| `api.cors.allow_methods` | array | Raw `AllowMethods` list |
| `api.cors.allow_headers` | array | Raw `AllowHeaders` list |
| `api.cors.expose_headers` | array | Raw `ExposeHeaders` list |
| `api.cors.max_age` | integer | `MaxAge` seconds |

### CloudFront response headers policy (`aws_cloudfront_response_headers_policy`)

Source: `aws cloudfront get-response-headers-policy --id <id>`. The
`CorsConfig` block lives under
`ResponseHeadersPolicyConfig.CorsConfig`.

| Field | Type | Description |
|-------|------|-------------|
| `cdn.kind` | string | `"response_headers_policy"` |
| `cdn.response_headers_policy.cors.configured` | bool | Policy has a `CorsConfig` block |
| `cdn.response_headers_policy.cors.allows_wildcard_origin` | bool | `AccessControlAllowOrigins.Items` contains `"*"` |
| `cdn.response_headers_policy.cors.credentials_allowed` | bool | `AccessControlAllowCredentials` is `true` |
| `cdn.response_headers_policy.cors.origin_override` | bool | Policy overrides origin response headers |
| `cdn.response_headers_policy.cors.max_age_sec` | integer | `AccessControlMaxAgeSec` |

Distributions reference policies by id: `cdn.response_headers_policy_id`
on each distribution's cache behavior captures the association so
predicates can cross-reference which distributions use which
CORS-carrying policies.

### Lambda function URL (`aws_lambda_function`)

Source: `aws lambda get-function-url-config --function-name <name>`.
CORS lives under `Cors`; the surrounding `AuthType` field determines
whether the URL is publicly invocable.

| Field | Type | Description |
|-------|------|-------------|
| `compute.function_url.configured` | bool | Function has a URL configuration |
| `compute.function_url.auth_type_none` | bool | `AuthType` is `NONE` (unauthenticated) |
| `compute.function_url.cors.configured` | bool | Function URL has a `Cors` block |
| `compute.function_url.cors.allows_wildcard_origin` | bool | `AllowOrigins` contains `"*"` |
| `compute.function_url.cors.credentials_allowed` | bool | `AllowCredentials` is `true` |
| `compute.function_url.cors.allow_methods` | array | Raw `AllowMethods` list |
| `compute.function_url.cors.allow_headers` | array | Raw `AllowHeaders` list |
| `compute.function_url.cors.expose_headers` | array | Raw `ExposeHeaders` list |
| `compute.function_url.cors.max_age` | integer | `MaxAge` seconds |

### Wildcard representation

The string `"*"` is the wildcard value across all four services. Raw
arrays preserve `["*"]` vs `["*", "https://example.com"]` so custom
predicates can distinguish naive wildcard from mixed-wildcard (which is
still wildcard-effective at the browser). The precomputed
`allows_wildcard_origin` boolean is true in both cases.

### Absence vs empty

`configured: false` is a distinct state from `configured: true,
allows_wildcard_origin: false`. Predicates that should only fire on
misconfigured CORS must gate on `configured: true` to avoid firing on
resources that have no CORS at all.

---

