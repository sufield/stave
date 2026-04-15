# Observation Contract: Active Directory / LDAP

## Asset Type

```
vendor: "microsoft"
type: "active_directory_domain"
```

## Properties Schema

### domain

| Property | Type | Description |
|---|---|---|
| `domain.functional_level` | string | Domain functional level: "2016", "2019", "2022" |
| `domain.tombstone_lifetime_days` | int | Tombstone lifetime in days |

### password_policy

| Property | Type | Description |
|---|---|---|
| `password_policy.min_length` | int | Minimum password length |
| `password_policy.complexity_enabled` | bool | Password complexity requirement |
| `password_policy.max_age_days` | int | Maximum password age in days |
| `password_policy.lockout_threshold` | int | Account lockout threshold |
| `password_policy.lockout_duration_minutes` | int | Lockout duration |
| `password_policy.reversible_encryption` | bool | Reversible encryption enabled (must be false) |

### kerberos_policy

| Property | Type | Description |
|---|---|---|
| `kerberos_policy.max_ticket_age_hours` | int | Maximum Kerberos ticket lifetime |
| `kerberos_policy.max_service_ticket_age_minutes` | int | Maximum service ticket lifetime |

### privileged_groups

| Property | Type | Description |
|---|---|---|
| `privileged_groups.domain_admins_count` | int | Number of Domain Admins members |
| `privileged_groups.has_stale_admins` | bool | Members with no logon > 90 days |
| `privileged_groups.has_kerberoastable_spn` | bool | Members with SPNs (Kerberoasting risk) |

### security_settings

| Property | Type | Description |
|---|---|---|
| `security_settings.smb_signing_required` | bool | SMB signing enforced |
| `security_settings.ntlm_restriction_level` | int | NTLM restriction level (0-5, >= 3 for NTLMv2) |
| `security_settings.laps_enabled` | bool | LAPS enabled |
| `security_settings.credential_guard_enabled` | bool | Credential Guard on DCs |
| `security_settings.krbtgt_password_age_days` | int | Days since KRBTGT password change |

### trusts

| Property | Type | Description |
|---|---|---|
| `trusts.has_unsecured_external_trust` | bool | External trust without SID filtering |

## Sample Extractor

An AD extractor queries the domain controller via LDAP/PowerShell:
- Password policy: `Get-ADDefaultDomainPasswordPolicy`
- Privileged groups: `Get-ADGroupMember "Domain Admins"`
- Kerberos policy: GPO query
- Trusts: `Get-ADTrust -Filter *`

Output: obs.v0.1 JSON with `vendor: "microsoft"`, `type: "active_directory_domain"`.
