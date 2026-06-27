# aws s3api list-buckets  ->  one base aws_s3_bucket asset per bucket.
# list-buckets carries only Name/CreationDate; the public-access-block,
# encryption, and tag fields come from per-bucket calls and are merged in by id
# (arn:aws:s3:::<name>) via their own enrichment filters.
.Buckets[] | {
  id: ("arn:aws:s3:::" + .Name),
  type: "aws_s3_bucket",
  vendor: "aws",
  properties: { storage: {
    kind: "bucket",
    name: .Name
  } }
}
