# Inline policy document (user/group/role) -> one aws_iam_policy asset with the
# computed "shadow logic" signal (a NotAction statement, which grants everything
# EXCEPT the listed actions — an easy-to-miss over-grant).
#
# SELF-DESCRIBING INPUT: aws iam get-user-policy / get-group-policy / get-role-policy
# return {PrincipalName, PolicyName, PolicyDocument:{Statement:[...]}}. The
# principal + PolicyName form the inline-policy id; no annotation needed.
# $account supplies the ARN account segment.
#
# shadow_logic is computed (not a reshape): scan statements for NotAction and
# report the first one's values/effect/resource. No NotAction -> has_not_action:false.
((.PolicyDocument.Statement // []) | if type == "array" then . else [.] end) as $stmts
| ($stmts | map(select(.NotAction != null)) | .[0]) as $na
| (.UserName // .GroupName // .RoleName) as $principal
| {
  id: ("arn:aws:iam::" + $account + ":inline-policy/" + $principal + "/" + .PolicyName),
  type: "aws_iam_policy",
  vendor: "aws",
  properties: { identity: {
    kind: "policy",
    policy: {
      shadow_logic: (
        if $na then {
          has_not_action: true,
          not_action_values: ($na.NotAction | if type == "array" then . else [.] end),
          effect: $na.Effect,
          resource: $na.Resource
        } else {
          has_not_action: false
        } end
      )
    }
  } }
}
