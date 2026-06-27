# aws iam get-account-password-policy  ->  one aws_iam_password_policy asset.
# $account is supplied at transform time (the raw output carries no ARN).
# Absent fields default to 0: AWS omits PasswordReusePrevention / MaxPasswordAge
# when password reuse / expiry is unset.
.PasswordPolicy | {
  id: ("arn:aws:iam::" + $account + ":password-policy"),
  type: "aws_iam_password_policy",
  vendor: "aws",
  properties: { identity: {
    kind: "password_policy",
    password_policy: {
      minimum_length: .MinimumPasswordLength,
      require_uppercase: .RequireUppercaseCharacters,
      require_lowercase: .RequireLowercaseCharacters,
      require_numbers: .RequireNumbers,
      require_symbols: .RequireSymbols,
      reuse_prevention_count: (.PasswordReusePrevention // 0),
      max_password_age: (.MaxPasswordAge // 0)
    }
  } }
}
