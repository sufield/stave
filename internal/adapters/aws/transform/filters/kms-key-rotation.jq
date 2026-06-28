# aws kms get-key-rotation-status  ->  key_rotation_enabled, merged onto the base
# key by id. Self-describing: the response carries KeyId as the full key ARN, so
# no annotation is needed.
{
  id: .KeyId,
  type: "aws_kms_key",
  vendor: "aws",
  properties: { cryptography: {
    key_rotation_enabled: .KeyRotationEnabled
  } }
}
