# Per-user inline policy list -> has_inline_policies, merged onto the base user.
#
# INPUT CONTRACT: aws iam list-user-policies returns {"PolicyNames":[...]} with
# no user identity. Supply the user via the filename (user-inline-<user>.json,
# which injects UserName) or annotate {"UserName":"<name>", ...}. The user ARN is
# rebuilt from $account + UserName (default IAM path); a non-default path needs an
# explicit content annotation. has_inline_policies is true when the list is
# non-empty.
{
  id: ("arn:aws:iam::" + $account + ":user/" + .UserName),
  type: "aws_iam_user",
  vendor: "aws",
  properties: { identity: { policies: {
    has_inline_policies: (((.PolicyNames) // []) | length > 0)
  } } }
}
