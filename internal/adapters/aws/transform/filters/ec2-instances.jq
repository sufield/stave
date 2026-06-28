# aws ec2 describe-instances  ->  one aws_ec2_instance asset per instance.
# Reservations[].Instances[] are flattened. The id is the instance ARN, with the
# region derived from Placement.AvailabilityZone (drop the trailing AZ letter).
#
# Emitted (faithfully derivable from describe-instances):
#   network.has_public_ip      a public IPv4 is assigned
#   network.imdsv2_required    MetadataOptions.HttpTokens == "required"
#
# NOT emitted (documented in ctf/stave-transform/pending-items.md):
#   encryption.ebs_encrypted   describe-instances BlockDeviceMappings carry no
#                              Encrypted flag; it needs a describe-volumes join
#   user_data.has_secrets      needs describe-instance-attribute --attribute
#                              userData (a separate call) plus secret analysis
.Reservations[].Instances[] | {
  id: ("arn:aws:ec2:" + (.Placement.AvailabilityZone | .[:-1]) + ":" + $account + ":instance/" + .InstanceId),
  type: "aws_ec2_instance",
  vendor: "aws",
  properties: { compute: {
    kind: "instance",
    network: {
      has_public_ip: ((.PublicIpAddress) != null),
      imdsv2_required: (((.MetadataOptions.HttpTokens)) == "required")
    }
  } }
}
