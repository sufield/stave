# Per-role tags, merged into the base role asset by id.
#
# INPUT CONTRACT: aws iam list-role-tags returns only {"Tags":[{Key,Value}]} with
# no role identity, so the collector annotates it with the role ARN (the merge id):
#   {"RoleArn":"arn:aws:iam::…:role/<name>","Tags":[{"Key":…,"Value":…}]}
# A file without "RoleArn" is skipped (no id to merge onto).
#
# Mapping matches scripts/aws-snapshot.sh: tags is the Key/Value list folded into
# an object. Tag VALUES are hashed by the Go scrubber when the key looks secret;
# this filter just reshapes.
{
  id: .RoleArn,
  type: "aws_iam_role",
  vendor: "aws",
  properties: { identity: {
    tags: ((.Tags // []) | map({(.Key): .Value}) | add // {})
  } }
}
