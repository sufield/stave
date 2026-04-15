# Observation Contract: Cisco IOS Network Devices

## Asset Type

```
vendor: "cisco"
type: "cisco_ios_device"
```

## Properties Schema

### device

| Property | Type | Description |
|---|---|---|
| `device.ios_version` | string | IOS version string |
| `device.hostname` | string | Device hostname |

### authentication

| Property | Type | Description |
|---|---|---|
| `authentication.enable_secret_configured` | bool | Enable secret (not enable password) |
| `authentication.aaa_new_model_enabled` | bool | AAA new-model enabled |
| `authentication.service_password_encryption` | bool | service password-encryption |

### management

| Property | Type | Description |
|---|---|---|
| `management.telnet_enabled` | bool | Telnet VTY access (must be false) |
| `management.ssh_version` | int | SSH version (must be 2) |
| `management.http_server_enabled` | bool | HTTP server (must be false) |
| `management.access_class_applied` | bool | Management ACL on VTY lines |
| `management.snmp_version` | int | SNMP version (must be 3) |
| `management.has_default_community` | bool | Default SNMP community strings |

### logging

| Property | Type | Description |
|---|---|---|
| `logging.logging_configured` | bool | Syslog target configured |
| `logging.timestamps_enabled` | bool | Log timestamps |
| `logging.source_interface` | string | Logging source interface |

### interfaces

| Property | Type | Description |
|---|---|---|
| `interfaces.has_proxy_arp` | bool | Any interface with ip proxy-arp |
| `interfaces.has_ip_redirects` | bool | Any interface with ip redirects |
| `interfaces.unused_ports_shutdown` | bool | Unused ports administratively down |

## Sample Extractor

A Cisco IOS extractor parses `show running-config` output:
- Enable secret: presence of `enable secret` vs `enable password`
- SSH version: `ip ssh version 2`
- SNMP: `snmp-server community` entries
- Interfaces: per-interface `no ip proxy-arp` checks

Output: obs.v0.1 JSON with `vendor: "cisco"`.
