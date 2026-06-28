# Per-group inline policy list -> has_inline_policies, merged onto the base group.
#
# INPUT CONTRACT: aws iam list-group-policies returns {"PolicyNames":[...]} with
# no group identity. Supply the group via the filename (group-inline-<group>.json,
# which injects GroupName) or annotate {"GroupName":"<name>", ...}. The group ARN
# is rebuilt from $account + GroupName (default IAM path). has_inline_policies is
# true when the list is non-empty.
{
  id: ("arn:aws:iam::" + $account + ":group/" + .GroupName),
  type: "aws_iam_group",
  vendor: "aws",
  properties: { identity: { group: {
    has_inline_policies: (((.PolicyNames) // []) | length > 0)
  } } }
}
