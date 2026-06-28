# aws ec2 describe-volumes  ->  one aws_ebs_volume asset per volume.
# Single-call source: describe-volumes returns every field needed, so this is a
# light reshape (no enrichment). The id is the volume ARN, rebuilt from the
# region (derived from the AvailabilityZone by dropping the trailing AZ letter),
# $account, and VolumeId.
.Volumes[] | {
  id: ("arn:aws:ec2:" + (.AvailabilityZone | .[:-1]) + ":" + $account + ":volume/" + .VolumeId),
  type: "aws_ebs_volume",
  vendor: "aws",
  properties: { compute: {
    kind: "volume",
    ebs: {
      attached: (((.Attachments) // []) | length > 0),
      is_error_state: (.State == "error"),
      is_gp2: (.VolumeType == "gp2"),
      encrypted: ((.Encrypted) // false)
    }
  } }
}
