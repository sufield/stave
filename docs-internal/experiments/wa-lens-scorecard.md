# Well-Architected Lens Coverage Scorecard

**Date:** 2026-09-01
**Method:** Automated monthly check — parse WA custom lens JSONs,
run Stave against committed inverted fixtures, compare violation
counts against baseline.

**Lenses with Security pillar:** 18
**Total Security best practices:** 360
**Invertible (CONFIG + ARCHITECTURAL):** 324
**Procedural (skipped):** 36

**Stave eval results:** 88 risk signals from 121 unique controls

## Violations by Fixture

| Fixture | Violations | Unique Controls |
|---|---|---|
| cognito | 4 | 28 |
| documentdb | 7 | 9 |
| dynamodb | 5 | 6 |
| ecs | 9 | 10 |
| elasticache | 6 | 9 |
| emr | 3 | 5 |
| glue | 3 | 3 |
| lambda-apigw | 15 | 15 |
| msk | 5 | 7 |
| opensearch | 7 | 7 |
| s3 | 14 | 12 |
| sagemaker | 3 | 3 |
| streaming-media | 7 | 7 |

## Lens Practice Counts

| Lens | Best Practices | Invertible | Procedural | Fixture |
|---|---|---|---|---|
| Amazon-Cognito-Lens | 30 | 30 | 0 | cognito |
| Amazon-ECS-Lens | 42 | 41 | 1 | ecs |
| Amazon-MSK-Lens | 27 | 23 | 4 | msk |
| Amazon-S3-Lens | 52 | 43 | 9 | s3 |
| ApiGwLambda | 19 | 14 | 5 | lambda-apigw |
| Athena-SQL-Lens | 6 | 6 | 0 | — |
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

- **Athena-SQL-Lens** (6 invertible practices) — needs fixture generation

<!-- BASELINE (machine-readable — do not edit manually)
cognito: 4
documentdb: 7
dynamodb: 5
ecs: 9
elasticache: 6
emr: 3
glue: 3
lambda-apigw: 15
msk: 5
opensearch: 7
s3: 14
sagemaker: 3
streaming-media: 7
-->
