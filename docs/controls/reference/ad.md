# Control Reference — AD

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.AD.ACCOUNT.DELEGATION.001

**No Accounts Must Have Unconstrained Delegation**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_ad: 5.6;

No accounts should be configured with unconstrained Kerberos delegation. Unconstrained delegation allows a service to impersonate any user to any service in the domain. An attacker who compromises a host with unconstrained delegation can harvest TGTs from connecting users, including domain administrators, enabling full domain compromise.

**Remediation:** Replace unconstrained delegation with constrained delegation or resource-based constrained delegation. Run: Get-ADUser -Filter {TrustedForDelegation -eq $true} to find affected accounts, then reconfigure each with specific SPNs.

---

### CTL.AD.ACCOUNT.DESONLY.001

**No Accounts Must Use DES-Only Kerberos Encryption**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_ad: 5.7;

No accounts should have the "Use DES encryption types for this account" flag set. DES is a deprecated and broken encryption algorithm. Kerberos tickets encrypted with DES can be cracked quickly, exposing account credentials. Any account configured for DES-only encryption is trivially compromised.

**Remediation:** Remove the DES-only flag from all accounts. Run: Get-ADUser -Filter {UseDESKeyOnly -eq $true} | Set-ADUser -KerberosEncryptionType AES128,AES256

---

### CTL.AD.ACCOUNT.GUEST.001

**Guest Account Must Be Disabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_ad: 1.1.1;

The built-in Guest account must be disabled in Active Directory. An enabled Guest account allows unauthenticated or weakly authenticated users to access domain resources. Attackers use the Guest account as an initial access vector to enumerate domain objects and escalate privileges.

**Remediation:** Disable the Guest account. Run: Disable-ADAccount -Identity Guest

---

### CTL.AD.ACCOUNT.NOEXPIRY.001

**Admin Accounts Must Not Have Non-Expiring Passwords**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_ad: 5.4; owasp_nhi: NHI7;

Privileged accounts must not have the password-never-expires flag set. Non-expiring passwords on admin accounts create persistent credential risks.

**Remediation:** Remove the password-never-expires flag from admin accounts. Use Fine-Grained Password Policies if different expiry is needed.

---

### CTL.AD.ACCOUNT.NOPASSWD.001

**No Accounts May Have Password-Not-Required Flag**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_ad: 5.5;

No account should have the PASSWD_NOTREQD flag set. Accounts with this flag can authenticate with an empty password.

**Remediation:** Clear the PASSWD_NOTREQD flag on all accounts. Get-ADUser -Filter {PasswordNotRequired -eq $true} | Set-ADUser -PasswordNotRequired $false

---

### CTL.AD.ACCOUNT.REVENC.001

**No Accounts Must Have Reversible Encryption Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_ad: 1.1.5; nist_800_53_r5: IA-5;

No accounts should have the "Store password using reversible encryption" flag set. Reversible encryption stores passwords in a form equivalent to plaintext. An attacker who gains access to the AD database can recover these passwords directly without cracking, compromising every affected account instantly.

**Remediation:** Remove the reversible encryption flag from all accounts. Run: Get-ADUser -Filter {AllowReversiblePasswordEncryption -eq $true} | Set-ADUser -AllowReversiblePasswordEncryption $false Users must change their passwords after this change.

---

### CTL.AD.ACCOUNT.STALE.001

**No Inactive Admin Accounts Must Exist**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_ad: 5.1; owasp_nhi: NHI1;

There must be no inactive admin accounts in Active Directory. Admin accounts that have not logged in for an extended period are dormant backdoors. Attackers target stale privileged accounts because they are less likely to be monitored and their compromise may go unnoticed indefinitely.

**Remediation:** Review and disable or remove inactive admin accounts. Run: Search-ADAccount -AccountInactive -UsersOnly -TimeSpan 90.00:00:00 | Where-Object {$_.MemberOf -match "Domain Admins"}

---

### CTL.AD.ADMINSDHOLDER.001

**AdminSDHolder ACL Must Be Clean**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_ad: 5.3;

The AdminSDHolder object ACL must contain only default entries. AdminSDHolder permissions are stamped onto all protected accounts and groups every 60 minutes by the SDProp process. If an attacker adds a custom ACE to AdminSDHolder, that ACE propagates to every privileged account, creating a persistent backdoor that survives individual permission resets.

**Remediation:** Review the AdminSDHolder object ACL and remove any non-default entries. Use: Get-ACL "AD:\CN=AdminSDHolder,CN=System,DC=domain,DC=com" to audit. Compare against a known-good baseline.

---

### CTL.AD.AUDIT.ACCTMGMT.001

**Account Management Auditing Must Be Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_ad: 17.1.1;

Active Directory must audit account management events. Without this auditing, creation, deletion, and modification of user and group accounts go unrecorded. Attackers who create backdoor accounts or add themselves to privileged groups will leave no audit trail.

**Remediation:** Enable account management auditing via Group Policy: Computer Configuration > Windows Settings > Security Settings > Advanced Audit Policy Configuration > Account Management > Audit User Account Management. Set to Success and Failure.

---

### CTL.AD.AUDIT.LOGON.001

**Logon Event Auditing Must Be Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_ad: 17.5.1;

Active Directory must audit logon events. Without logon auditing, successful and failed authentication attempts go unrecorded, preventing detection of brute-force attacks, credential stuffing, and unauthorized access. CIS benchmarks require logon event auditing on all domain controllers.

**Remediation:** Enable logon event auditing via Group Policy: Computer Configuration > Windows Settings > Security Settings > Advanced Audit Policy Configuration > Logon/Logoff > Audit Logon. Set to Success and Failure.

---

### CTL.AD.AUDIT.OBJACCESS.001

**Object Access Auditing Must Be Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_ad: 17.6.1;

Active Directory must audit object access events. Without this auditing, access to sensitive AD objects such as GPOs, OUs, and critical containers goes unrecorded. Attackers modifying Group Policy or sensitive directory objects will leave no trace.

**Remediation:** Enable object access auditing via Group Policy: Computer Configuration > Windows Settings > Security Settings > Advanced Audit Policy Configuration > Object Access > Audit Other Object Access Events. Set to Success and Failure.

---

### CTL.AD.AUDIT.PRIVUSE.001

**Privilege Use Auditing Must Be Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_ad: 17.8.1;

Active Directory must audit privilege use events. Without this auditing, escalation of privileges and sensitive privilege invocations go unlogged, making it impossible to detect abuse of administrative rights or identify accounts performing privileged operations they should not.

**Remediation:** Enable privilege use auditing via Group Policy: Computer Configuration > Windows Settings > Security Settings > Advanced Audit Policy Configuration > Privilege Use > Audit Sensitive Privilege Use. Set to Success and Failure.

---

### CTL.AD.BUILTIN.LIMIT.001

**Built-in Administrator Account Must Be Disabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_ad: 2.1;

The built-in Administrator account (RID 500) must be disabled or renamed. It is a well-known target for brute-force attacks.

**Remediation:** Disable or rename the built-in Administrator account. Use dedicated named admin accounts with audit trails.

---

### CTL.AD.CRED.GUARD.001

**Credential Guard Must Be Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6;

Windows Credential Guard must be enabled to protect LSASS from memory dumping attacks (Mimikatz). Without it, domain credentials cached in memory can be extracted by any local administrator.

**Remediation:** Enable Credential Guard via GPO or Intune. Requires UEFI Secure Boot and virtualization-based security.

---

### CTL.AD.DOMAIN.ADMIN.COUNT.001

**Domain Admins Group Must Have 5 or Fewer Members**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_ad: 5.2;

The Domain Admins group should be minimized. Each member is a high-value target for attackers. More than 5 members indicates over-provisioned administrative access.

**Remediation:** Review Domain Admins membership and remove unnecessary members. Use dedicated admin accounts with just-in-time access.

---

### CTL.AD.KERB.CLOCKSKEW.001

**Kerberos Clock Skew Tolerance Must Not Exceed 5 Minutes**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_ad: 1.3.3;

Maximum clock skew tolerance must not exceed 5 minutes. Large skew enables replay attacks on Kerberos tickets.

**Remediation:** Set maximum clock skew to 5 minutes in Kerberos Policy.

---

### CTL.AD.KERB.SERVICE.001

**Kerberos Service Ticket Lifetime Must Not Exceed 600 Minutes**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_ad: 1.3.2;

Maximum Kerberos service ticket lifetime must not exceed 600 minutes (10 hours). Long service ticket lifetimes extend the window for ticket reuse after compromise.

**Remediation:** Set maximum service ticket age to 600 minutes in Kerberos Policy.

---

### CTL.AD.KERB.TICKET.AGE.001

**Kerberos TGT Lifetime Must Not Exceed 10 Hours**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_ad: 1.3.1;

Maximum Kerberos ticket-granting ticket lifetime must not exceed 10 hours. Longer lifetimes extend the window for stolen ticket reuse.

**Remediation:** Set maximum ticket age to 10 hours in the Kerberos Policy GPO.

---

### CTL.AD.KERBEROAST.001

**Privileged Accounts Must Not Have Kerberoastable SPNs**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_ad: 5.3; nist_800_53_r5: AC-6;

Service accounts that are members of privileged groups (Domain Admins, Enterprise Admins, etc.) must not have Service Principal Names (SPNs) registered. Any domain user can request a Kerberos service ticket for an SPN and crack the ticket offline to recover the service account password. When the account is privileged, a successful Kerberoasting attack grants immediate domain-level access.

**Remediation:** Remove SPNs from privileged accounts or move the service to a Group Managed Service Account (gMSA) with automatic password rotation. Run: setspn -D <spn> <account> or migrate to gMSA.

---

### CTL.AD.KRBTGT.ROTATION.001

**KRBTGT Password Must Be Rotated Within 180 Days**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: IA-5; owasp_nhi: NHI7;

The KRBTGT account password must be changed at least every 180 days. A stale KRBTGT enables Golden Ticket attacks indefinitely — any attacker who once obtained the KRBTGT hash can forge tickets forever.

**Remediation:** Reset the KRBTGT password twice (with replication between resets) using Reset-KrbtgtAccountPassword or manual reset. Schedule regular rotation every 90-180 days.

---

### CTL.AD.LAPS.001

**Local Administrator Password Solution Must Be Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6;

LAPS (Local Administrator Password Solution) must be deployed to manage local administrator passwords on domain-joined machines. Without LAPS, local admin passwords are often identical across all workstations, allowing an attacker who compromises one machine to move laterally to every machine in the domain using the same credential.

**Remediation:** Deploy Windows LAPS or legacy Microsoft LAPS. Install the LAPS CSE on all domain-joined machines, extend the AD schema, configure the GPO, and set password rotation policy. Run: Update-LapsADSchema; Set-LapsADComputerSelfPermission -Identity "OU=Workstations,DC=corp,DC=local"

---

### CTL.AD.LDAP.CHANNELBIND.001

**LDAP Channel Binding Must Be Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_ad: 2.3.11.9; nist_800_53_r5: SC-8;

LDAP channel binding must be enabled on domain controllers. Without channel binding, LDAP connections are vulnerable to relay attacks where an attacker forwards authentication tokens from one session to another. Channel binding ties the LDAP session to the underlying TLS channel, preventing token relay.

**Remediation:** Enable LDAP channel binding via registry: Set HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\LdapEnforceChannelBinding to 2 (Always) on all domain controllers.

---

### CTL.AD.LDAP.SIGNING.001

**LDAP Signing Must Be Required**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_ad: 2.3.11.8; nist_800_53_r5: SC-8;

LDAP signing must be required on all domain controllers. Without mandatory LDAP signing, LDAP traffic can be intercepted and modified via man-in-the-middle attacks. Attackers can capture and replay LDAP bind credentials or modify directory queries in transit.

**Remediation:** Enable mandatory LDAP signing via Group Policy: Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options > "Domain controller: LDAP server signing requirements" set to "Require signing".

---

### CTL.AD.LOCK.DURATION.001

**Account Lockout Duration Must Be At Least 15 Minutes**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_ad: 1.2.2;

Account lockout duration must be at least 15 minutes to slow brute-force attacks and give defenders time to respond.

**Remediation:** Set lockout duration to 15 minutes or more in Default Domain Policy.

---

### CTL.AD.LOCK.THRESHOLD.001

**Account Lockout Threshold Must Be Set**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_ad: 1.2.1;

Account lockout threshold must be configured (1-5 attempts) to prevent unlimited brute-force login attempts.

**Remediation:** Set account lockout threshold to 5 or fewer in Default Domain Policy.

---

### CTL.AD.LOCK.WINDOW.001

**Account Lockout Observation Window Must Be At Least 15 Minutes**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_ad: 1.2.3;

The lockout observation window must be at least 15 minutes. A shorter window allows attackers to spread attempts over time without triggering lockout.

**Remediation:** Set lockout observation window to 15 minutes or more.

---

### CTL.AD.NTLM.LEVEL.001

**NTLM Authentication Must Be Restricted to NTLMv2**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_ad: 2.3.11.7; nist_800_53_r5: IA-2;

The domain must enforce NTLMv2 authentication by setting the LAN Manager authentication level to 3 or higher (Send NTLMv2 response only / refuse LM & NTLM). NTLMv1 and LM responses use weak cryptography that can be cracked in seconds. NTLM relay and pass- the-hash attacks are significantly harder when NTLMv2 is enforced and legacy protocols are refused.

**Remediation:** Set the LAN Manager authentication level to 3 or higher via Group Policy: Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options > "Network security: LAN Manager authentication level" to "Send NTLMv2 response only. Refuse LM & NTLM."

---

### CTL.AD.PASS.COMPLEXITY.001

**Password Complexity Requirements Must Be Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_ad: 1.1.2;

Active Directory domain password policy must enforce complexity requirements (uppercase, lowercase, digit, special character).

**Remediation:** Enable password complexity in Default Domain Policy GPO.

---

### CTL.AD.PASS.HISTORY.001

**Password History Must Enforce At Least 24 Remembered Passwords**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_ad: 1.1.2; nist_800_53_r5: IA-5;

Active Directory domain password policy must remember at least 24 previous passwords. A short history count allows users to cycle through a small set of passwords and reuse compromised credentials. Enforcing 24 remembered passwords ensures that even with regular rotation, previously compromised passwords cannot be reused for approximately two years.

**Remediation:** Set password history to 24 or greater in the Default Domain Policy GPO. Run: Set-ADDefaultDomainPasswordPolicy -PasswordHistoryCount 24

---

### CTL.AD.PASS.MAXAGE.001

**Password Maximum Age Must Be 90 Days or Less**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_ad: 1.1.3; owasp_nhi: NHI7;

Password maximum age must not exceed 90 days to limit the window of exposure for compromised credentials.

**Remediation:** Set maximum password age to 90 days or less in Default Domain Policy.

---

### CTL.AD.PASS.MINAGE.001

**Password Minimum Age Must Be At Least 1 Day**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_ad: 1.1.4;

Minimum password age must be at least 1 day to prevent rapid password cycling that allows users to reuse old passwords by changing through the history depth in one session.

**Remediation:** Set minimum password age to 1 day in Default Domain Policy.

---

### CTL.AD.PASS.MINLEN.001

**Password Minimum Length Must Be At Least 14 Characters**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_ad: 1.1.1; nist_800_53_r5: IA-5;

Active Directory domain password policy must enforce a minimum length of 14 characters. Shorter passwords are vulnerable to offline brute-force and credential-stuffing attacks. A 14-character minimum aligns with current NIST and CIS guidance and significantly increases the search space an attacker must exhaust.

**Remediation:** Set the minimum password length to 14 or greater in the Default Domain Policy GPO. Run: Set-ADDefaultDomainPasswordPolicy -MinPasswordLength 14

---

### CTL.AD.PASS.REVENC.001

**Reversible Encryption Must Be Disabled**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_ad: 1.1.6; nist_800_53_r5: IA-5;

Active Directory must not store passwords using reversible encryption. When enabled, password hashes can be decrypted back to plaintext, effectively storing passwords in cleartext. An attacker who gains access to the AD database (ntds.dit) can recover every user password without cracking. This setting is required only by legacy protocols such as CHAP and digest authentication, which should be eliminated.

**Remediation:** Disable reversible encryption in the Default Domain Policy GPO. Run: Set-ADDefaultDomainPasswordPolicy -ReversibleEncryptionEnabled $false Then force all users to change their passwords so new hashes are stored without reversible encryption.

---

### CTL.AD.PRIV.NESTED.001

**Privileged Groups Must Not Contain Nested Groups**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_ad: 5.2;

Privileged groups such as Domain Admins, Enterprise Admins, and Schema Admins must not contain nested groups. Nested group membership obscures who actually has privileged access, makes access reviews unreliable, and can create unintended privilege escalation paths when users are added to seemingly unprivileged groups that are nested into admin groups.

**Remediation:** Remove nested groups from Domain Admins, Enterprise Admins, and Schema Admins. Add individual accounts directly instead. Use: Get-ADGroupMember "Domain Admins" | Where-Object {$_.objectClass -eq "group"} to find nested groups.

---

### CTL.AD.PROTUSERS.001

**Protected Users Group Must Be Populated**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_ad: 5.5;

The Protected Users security group must contain privileged accounts. Members of this group receive hardened credential protections including no NTLM authentication, no DES or RC4 in Kerberos pre-authentication, no delegation, and no credential caching. Leaving it empty means privileged accounts lack these defenses.

**Remediation:** Add all privileged accounts (Domain Admins, Enterprise Admins, Schema Admins) to the Protected Users group. Test application compatibility before adding service accounts.

---

### CTL.AD.RECYCLEBIN.001

**AD Recycle Bin Must Be Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_ad: 7.3;

The Active Directory Recycle Bin feature must be enabled. Without it, deleted objects lose most attributes immediately, making recovery difficult and forensic investigation of malicious deletions nearly impossible. The Recycle Bin preserves all attributes of deleted objects for a configurable tombstone period.

**Remediation:** Enable the AD Recycle Bin feature. This requires forest functional level 2008 R2 or higher. Run: Enable-ADOptionalFeature "Recycle Bin Feature" -Scope ForestOrConfigurationSet -Target "domain.com"

---

### CTL.AD.SMB.SIGNING.001

**SMB Signing Must Be Required**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_ad: 2.3.8.1; nist_800_53_r5: SC-8;

SMB signing must be required on all domain controllers and member servers. Without mandatory signing, SMB traffic can be intercepted and modified via man-in-the-middle attacks. Attackers use SMB relay to forward captured NTLM authentication to other hosts, gaining unauthorized access without cracking passwords.

**Remediation:** Enable mandatory SMB signing via Group Policy: Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options > "Microsoft network server: Digitally sign communications (always)" set to Enabled. Apply to all domain controllers and member servers.

---

### CTL.AD.STALE.ADMIN.001

**Privileged Groups Must Not Have Stale Members**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_ad: 5.1; owasp_nhi: NHI1;

Privileged groups must not contain members with no logon in over 90 days. Stale admin accounts are dormant backdoors.

**Remediation:** Review and remove stale accounts from Domain Admins, Enterprise Admins, and Schema Admins groups.

---

### CTL.AD.TRUST.SELECTIVE.001

**External Trusts Must Use Selective Authentication**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-4;

External trusts must use selective authentication to restrict which users from the trusted domain can authenticate. Without it, all trusted domain users can access resources.

**Remediation:** Configure selective authentication on external trusts via AD Domains and Trusts or PowerShell.

---

### CTL.AD.TRUST.SIDFILTER.001

**External Trusts Must Have SID Filtering Enabled**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-4;

External trusts must have SID filtering enabled to prevent SID history injection attacks from trusted domains.

**Remediation:** Enable SID filtering on all external trusts. netdom trust <TrustingDomain> /domain:<TrustedDomain> /quarantine:yes

---

