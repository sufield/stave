# aws kms get-key-policy  ->  policy.has_wildcard_principal, merged onto the base
# key by id.
#
# INPUT CONTRACT: get-key-policy returns {"Policy":"<json string>","PolicyName"}
# with no key identity, so the collector annotates it with the key ARN:
#   {"KeyArn":"arn:aws:kms:…:key/<id>", "Policy":"…"}
# A file without "KeyArn" is skipped (no id to merge onto). Policy is a JSON
# string and is parsed; a statement granting a "*" principal sets the signal.
(.Policy | fromjson) as $p
| {
  id: .KeyArn,
  type: "aws_kms_key",
  vendor: "aws",
  properties: { cryptography: { policy: {
    has_wildcard_principal: (
      (($p.Statement) // [])
      | (if type == "object" then [.] else . end)
      | any(
          (.Principal == "*")
          or ((.Principal.AWS?) == "*")
          or ((.Principal.AWS?) | (if type == "array" then any(. == "*") else false end))
        )
    )
  } } }
}
