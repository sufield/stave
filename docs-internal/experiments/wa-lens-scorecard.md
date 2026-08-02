# Well-Architected Lens Coverage Scorecard

**Date:** 2026-08-02
**Method:** Automated monthly check — parse WA custom lens JSONs,
run Stave against committed inverted fixtures, compare violation
counts against baseline.

**Lenses with Security pillar:** 17
**Total Security best practices:** 354
**Invertible (CONFIG + ARCHITECTURAL):** 318
**Procedural (skipped):** 36

**Stave eval results:** 0 risk signals from 0 unique controls

## Violations by Fixture

| Fixture | Violations | Unique Controls |
|---|---|---|

## Lens Practice Counts

| Lens | Best Practices | Invertible | Procedural | Fixture |
|---|---|---|---|---|
| Amazon-Cognito-Lens | 30 | 30 | 0 | cognito |
| Amazon-ECS-Lens | 42 | 41 | 1 | ecs |
| Amazon-MSK-Lens | 27 | 23 | 4 | msk |
| Amazon-S3-Lens | 52 | 43 | 9 | s3 |
| ApiGwLambda | 19 | 14 | 5 | lambda-apigw |
| DocumentDB | 18 | 17 | 1 | documentdb |
| DynamoDB | 34 | 28 | 6 | dynamodb |
| EMR-spark-lens | 14 | 13 | 1 | emr |
| ElastiCache | 21 | 20 | 1 | elasticache |
| Glue | 9 | 8 | 1 | glue |
| IDP-custom-lens | 16 | 14 | 2 | sagemaker |
| OpenSearch | 19 | 16 | 3 | opensearch |
| Personalize | 8 | 8 | 0 | sagemaker |
| SaaS-Anywhere-Lens | 13 | 12 | 1 | sagemaker |
| SageMaker-AutoGluon-lens | 12 | 12 | 0 | sagemaker |
| SageMaker-Flower-Lens | 7 | 6 | 1 | sagemaker |
| Streaming-Media-Lens | 13 | 13 | 0 | streaming-media |

## Lenses Without Fixtures

All lenses have fixture coverage.

<!-- BASELINE (machine-readable — do not edit manually)
-->
