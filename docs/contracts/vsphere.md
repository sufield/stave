# Observation Contract: VMware vSphere

## Asset Types

```
vendor: "vmware"
type: "vsphere_esxi_host"
type: "vsphere_vm"
```

## ESXi Host Properties

| Property | Type | Description |
|---|---|---|
| `esxi.version` | string | ESXi version |
| `esxi.ssh_enabled` | bool | SSH daemon running |
| `esxi.shell_enabled` | bool | ESXi shell enabled |
| `esxi.lockdown_mode` | string | disabled/normal/strict |
| `esxi.ntp_configured` | bool | NTP configured |
| `esxi.syslog_configured` | bool | Remote syslog configured |
| `esxi.host_firewall_enabled` | bool | ESXi firewall active |
| `esxi.acceptance_level` | string | VIB acceptance level |
| `esxi.coredump_configured` | bool | Coredump configured |
| `esxi.persistent_log_configured` | bool | Logs persist across reboot |
| `esxi.sfcbd_enabled` | bool | CIM server (should be false) |
| `esxi.slpd_enabled` | bool | SLP daemon (should be false) |
| `host_firewall.enabled` | bool | ESXi firewall active |
| `distributed_switch.has_promiscuous` | bool | Promiscuous mode on any portgroup |
| `distributed_switch.has_mac_changes` | bool | MAC changes allowed |
| `distributed_switch.has_forged_transmits` | bool | Forged transmits allowed |
| `vsan.enabled` | bool | vSAN enabled |
| `vsan.encryption_enabled` | bool | vSAN data at rest encrypted |
| `vsan.data_in_transit_encrypted` | bool | vSAN inter-host encrypted |
| `storage.has_unauthenticated_nfs` | bool | NFS without Kerberos |
| `storage.has_unauthenticated_iscsi` | bool | iSCSI without CHAP |

## VM Properties

| Property | Type | Description |
|---|---|---|
| `vm.name` | string | VM display name |
| `vm.encryption_enabled` | bool | VM encrypted |
| `vm.snapshot_count` | int | Snapshot count |
| `vm.oldest_snapshot_days` | int | Oldest snapshot age |
| `vm.copy_paste_enabled` | bool | Copy/paste enabled |
| `vm.hgfs_enabled` | bool | Host-guest FS |
| `vm.log_size_limit_enabled` | bool | Log size limited |
| `vm.remote_display_enabled` | bool | VNC/VMRC enabled |
| `vm.disk_shrinking_enabled` | bool | Disk shrinking |
| `vm.independent_non_persistent` | bool | Non-persistent disk |
