# aws ec2 describe-security-groups  ->  one aws_ec2_security_group asset per SG.
# Single-call source; the id is the SecurityGroupArn AWS already returns. These
# are computed internet-exposure signals over the ingress rules (IpPermissions),
# definitions calibrated against the committed nccgroup security groups:
#   has_broad_port_range     a tcp/udp rule open to 0.0.0.0/0 spanning a port range
#   high_risk_ports_exposed  a single high-risk admin/db port open to 0.0.0.0/0
#   icmp_all_types_from_internet  any icmp rule open to 0.0.0.0/0
#   has_broad_cidr           an all-protocols (-1) rule with a non-/32 CIDR
#
# NOT emitted (documented in ctf/stave-transform/pending-items.md):
#   is_unused              needs describe-network-interfaces (not in a SG's own data)
#   has_broad_eastwest_rules  no positive example to calibrate a faithful definition
def internet($r): (((($r.IpRanges) // [])) | any(.CidrIp == "0.0.0.0/0"));
.SecurityGroups[]
| (.IpPermissions // []) as $perms
| {
  id: .SecurityGroupArn,
  type: "aws_ec2_security_group",
  vendor: "aws",
  properties: { network: {
    kind: "security_group",
    security_group: {
      has_broad_port_range: ($perms | any(. as $r
        | (($r.IpProtocol == "tcp") or ($r.IpProtocol == "udp"))
        and ($r.FromPort != $r.ToPort) and internet($r))),
      high_risk_ports_exposed: ($perms | any(. as $r
        | ($r.FromPort == $r.ToPort) and internet($r)
        and (([22, 3389, 3306, 5432, 1433, 1521, 27017, 2049] | index($r.FromPort)) != null))),
      icmp_all_types_from_internet: ($perms | any(. as $r
        | ($r.IpProtocol == "icmp") and internet($r))),
      has_broad_cidr: ($perms | any(. as $r
        | ($r.IpProtocol == "-1")
        and ((($r.IpRanges) // []) | any((.CidrIp | split("/")[1] | tonumber) < 32))))
    }
  } }
}
