# Observation Contract: Cisco IOS Network Devices

## Asset Type

```
vendor: "cisco"
type: "cisco_ios_device"
```

## Properties

| Property | Type | Description |
|---|---|---|
| `device.ios_version` | string | IOS version |
| `device.hostname` | string | Hostname |
| `authentication.enable_secret_configured` | bool | Enable secret |
| `authentication.aaa_new_model_enabled` | bool | AAA new-model |
| `authentication.aaa_authentication_login` | string | Login method |
| `authentication.aaa_accounting_exec` | string | Exec accounting |
| `authentication.service_password_encryption` | bool | Password encryption |
| `management.telnet_enabled` | bool | Telnet enabled |
| `management.ssh_version` | int | SSH version |
| `management.http_server_enabled` | bool | HTTP server |
| `management.access_class_applied` | bool | VTY ACL |
| `management.snmp_version` | int | SNMP version |
| `management.has_default_community` | bool | Default SNMP community |
| `management.cdp_enabled` | bool | CDP globally enabled |
| `management.tcp_small_servers_enabled` | bool | TCP small servers |
| `management.udp_small_servers_enabled` | bool | UDP small servers |
| `management.finger_enabled` | bool | Finger service |
| `management.ip_source_route_enabled` | bool | IP source routing |
| `management.gratuitous_arps_enabled` | bool | Gratuitous ARPs |
| `management.ntp_configured` | bool | NTP servers configured |
| `management.ntp_authentication_enabled` | bool | NTP authenticated |
| `logging.logging_configured` | bool | Syslog configured |
| `logging.timestamps_enabled` | bool | Log timestamps |
| `interfaces.has_proxy_arp` | bool | Proxy ARP on any interface |
| `interfaces.has_ip_redirects` | bool | IP redirects on any interface |
| `interfaces.has_directed_broadcast` | bool | Directed broadcast |
| `interfaces.unused_ports_shutdown` | bool | Unused ports down |
| `acl.vty_acl_applied` | bool | VTY ACL applied |
| `acl.has_missing_egress` | bool | Interface without egress ACL |
| `routing.has_unauthenticated_bgp` | bool | BGP peer without auth |
| `routing.has_unfiltered_bgp_in` | bool | BGP without inbound filter |
| `routing.has_unfiltered_bgp_out` | bool | BGP without outbound filter |
| `routing.has_unauthenticated_ospf` | bool | OSPF without auth |
| `routing.has_unauthenticated_hsrp` | bool | HSRP without MD5 |
