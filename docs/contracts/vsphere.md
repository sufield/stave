# Observation Contract: VMware vSphere

## Asset Types

```
vendor: "vmware"
type: "vsphere_esxi_host"  # ESXi hypervisor host
type: "vsphere_vm"          # Virtual machine
```

## ESXi Host Properties

| Property | Type | Description |
|---|---|---|
| `esxi.version` | string | ESXi version |
| `esxi.ssh_enabled` | bool | SSH daemon running (should be false) |
| `esxi.shell_enabled` | bool | ESXi shell enabled (should be false) |
| `esxi.lockdown_mode` | string | "disabled", "normal", "strict" |
| `esxi.ntp_configured` | bool | NTP time synchronization configured |
| `esxi.syslog_configured` | bool | Remote syslog target configured |
| `esxi.host_firewall_enabled` | bool | ESXi firewall active |
| `management_network.dedicated_interface` | bool | Management on dedicated NIC |
| `management_network.vlan_id` | int | Management VLAN ID |

## VM Properties

| Property | Type | Description |
|---|---|---|
| `vm.name` | string | VM display name |
| `vm.power_state` | string | "poweredOn", "poweredOff", "suspended" |
| `vm.encryption_enabled` | bool | VM encrypted at rest |
| `vm.snapshot_count` | int | Number of snapshots (> 3 is hygiene issue) |
| `vm.oldest_snapshot_days` | int | Age of oldest snapshot |
| `vm.tools_up_to_date` | bool | VMware Tools current |
| `vm.copy_paste_enabled` | bool | Copy/paste between VM and host |
| `vm.hgfs_enabled` | bool | Host-guest filesystem sharing |
| `vm.log_size_limit_enabled` | bool | VM log file size limited |

## Sample Extractor

A vSphere extractor uses the vSphere SDK (pyVmomi or govmomi):
- ESXi hosts: `vim.HostSystem` properties
- VMs: `vim.VirtualMachine` config/runtime properties

Output: obs.v0.1 JSON with `vendor: "vmware"`.
