# aws kms list-keys  ->  one base aws_kms_key asset per key.
# list-keys carries only KeyId/KeyArn; key_rotation_enabled and the key-policy
# wildcard signal come from per-key calls and merge in by id (the KeyArn).
.Keys[] | {
  id: .KeyArn,
  type: "aws_kms_key",
  vendor: "aws",
  properties: { cryptography: {
    kind: "key"
  } }
}
