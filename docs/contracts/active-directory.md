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
| `password_policy.min_age_days` | int | Minimum password age in days |
| `password_policy.lockout_threshold` | int | Account lockout threshold |
| `password_policy.lockout_duration_minutes` | int | Lockout duration |
| `password_policy.lockout_observation_window` | int | Lockout observation window in minutes |
| `password_policy.reversible_encryption` | bool | Reversible encryption enabled (must be false) |
| `password_policy.history_count` | int | Password history depth |

### kerberos_policy

| Property | Type | Description |
|---|---|---|
| `kerberos_policy.max_ticket_age_hours` | int | Maximum Kerberos ticket lifetime |
| `kerberos_policy.max_service_ticket_age_minutes` | int | Maximum service ticket lifetime |
| `kerberos_policy.max_clock_skew_minutes` | int | Maximum Kerberos clock skew tolerance |
| `kerberos_policy.max_renewal_days` | int | Maximum ticket renewal period |

### privileged_groups

| Property | Type | Description |
|---|---|---|
| `privileged_groups.domain_admins_count` | int | Number of Domain Admins members |
| `privileged_groups.enterprise_admins_count` | int | Number of Enterprise Admins members |
| `privileged_groups.schema_admins_count` | int | Number of Schema Admins members |
| `privileged_groups.has_stale_admins` | bool | Members with no logon > 90 days |
| `privileged_groups.has_kerberoastable_spn` | bool | Members with SPNs (Kerberoasting risk) |
| `privileged_groups.builtin_admin_enabled` | bool | Built-in Administrator account enabled |
| `privileged_groups.has_nested_groups` | bool | Privileged groups contain nested groups |

### accounts

| Property | Type | Description |
|---|---|---|
| `accounts.krbtgt_password_age_days` | int | Days since KRBTGT password last changed |
| `accounts.admin_with_no_expiry` | bool | Admin accounts with non-expiring passwords |
| `accounts.password_not_required_count` | int | Accounts with password-not-required flag |
| `accounts.inactive_admin_count` | int | Admin accounts with no logon > 90 days |
| `accounts.guest_enabled` | bool | Guest account enabled |
| `accounts.des_only_count` | int | Accounts using DES-only Kerberos encryption |
| `accounts.unconstrained_delegation_count` | int | Accounts with unconstrained delegation |
| `accounts.reversible_encryption_count` | int | Accounts with reversible encryption flag |

### security_settings

| Property | Type | Description |
|---|---|---|
| `security_settings.smb_signing_required` | bool | SMB signing enforced |
| `security_settings.ntlm_restriction_level` | int | NTLM restriction level (0-5, >= 3 for NTLMv2) |
| `security_settings.laps_enabled` | bool | LAPS enabled |
| `security_settings.credential_guard_enabled` | bool | Credential Guard on DCs |
| `security_settings.krbtgt_password_age_days` | int | Days since KRBTGT password change |
| `security_settings.ldap_signing_required` | bool | LDAP signing enforced |
| `security_settings.ldap_channel_binding` | bool | LDAP channel binding token required |
| `security_settings.audit_logon_events` | bool | Logon event auditing enabled |
| `security_settings.audit_privilege_use` | bool | Privilege use auditing enabled |
| `security_settings.audit_account_management` | bool | Account management auditing enabled |
| `security_settings.protected_users_populated` | bool | Protected Users group has members |
| `security_settings.admin_sd_holder_clean` | bool | AdminSDHolder ACL is default (not backdoored) |
| `security_settings.recycle_bin_enabled` | bool | AD Recycle Bin enabled |

### trusts

| Property | Type | Description |
|---|---|---|
| `trusts.has_unsecured_external_trust` | bool | External trust without SID filtering |
| `trusts.has_unfiltered_selective_auth` | bool | External trust without selective authentication |
| `trusts.external_trust_count` | int | Number of external (non-forest) trusts |

## Sample Extractor

An AD extractor queries the domain controller via LDAP/PowerShell:
- Password policy: `Get-ADDefaultDomainPasswordPolicy`
- Privileged groups: `Get-ADGroupMember "Domain Admins"`
- Kerberos policy: GPO query
- Trusts: `Get-ADTrust -Filter *`
- Accounts: `Get-ADUser -Filter * -Properties ...`

Output: obs.v0.1 JSON with `vendor: "microsoft"`, `type: "active_directory_domain"`.
