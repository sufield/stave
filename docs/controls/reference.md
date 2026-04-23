# Control Reference

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`

**Total controls:** 903
**Pack hash:** `db8bf6deed09b082471b50ab9a9bf9b1a592a26d170ac53d7c4201b4547ff136`

## Summary

| Severity | Count |
|----------|-------|
| critical | 137 |
| high | 400 |
| info | 16 |
| low | 77 |
| medium | 273 |

| Domain | Count |
|--------|-------|
| audit | 20 |
| detection | 6 |
| encryption | 35 |
| exposure | 601 |
| governance | 21 |
| identity | 177 |
| network | 21 |
| resilience | 14 |
| storage | 8 |

## Controls

### CTL.ACM.CERT.EXPIRY.001

**ACM Imported Certificates Must Not Be Near Expiry**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-12; hipaa: 164.312(e)(2)(ii); nist_800_53_r5: SC-12; pci_dss_v4.0: 4.2.1; soc2: CC6.7;

SSL/TLS certificates imported into ACM must not be within 30 days of expiry or already expired. ACM automatically renews certificates it provisions (AMAZON_ISSUED) but does not renew imported certificates. Imported certificates expire silently on their expiry date with no enforcement mechanism — services continue serving traffic on an expired certificate until clients reject it. An expired certificate on a production load balancer or CloudFront distribution causes TLS negotiation failures for all clients that enforce certificate validity. For HIPAA and PCI-DSS environments, serving traffic on an expired certificate is a direct compliance violation. This control evaluates only IMPORTED certificates — AMAZON_ISSUED certificates are auto-renewed and out of scope.

**Remediation:** Renew or replace the imported certificate. Import the new certificate into ACM via aws acm import-certificate. If the certificate was originally from a private CA, re-issue from the CA and re-import. Consider migrating to an ACM-managed certificate (AMAZON_ISSUED) for automatic renewal — ACM provisions free public certificates for domains validated via DNS or email. After importing the new certificate, verify the associated services (load balancers, CloudFront distributions, API Gateway domains) are serving the updated certificate.

---

### CTL.ACM.KEY.ALGORITHM.001

**ACM Certificates Must Use Strong Key Algorithms**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** nist_800_53_r5: SC-13; soc2: CC6.7;

ACM certificates must use RSA-2048+ or ECDSA P-256+ key algorithms. Weak algorithms (RSA-1024, ECDSA P-192) are vulnerable to factoring or discrete logarithm attacks.

**Remediation:** Request a new certificate with RSA-2048 or ECDSA P-256.

---

### CTL.ACM.TRANSPARENCY.001

**ACM Certificates Must Enable Certificate Transparency Logging**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AU-2; soc2: CC7.1;

ACM-issued certificates must have Certificate Transparency (CT) logging enabled. CT logging publishes certificates to public logs, enabling detection of unauthorized certificate issuance for the domain.

**Remediation:** Enable CT logging when requesting or renewing the certificate.

---

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
- **Compliance:** cis_ad: 5.4;

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
- **Compliance:** cis_ad: 5.1;

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
- **Compliance:** nist_800_53_r5: IA-5;

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
- **Compliance:** cis_ad: 1.1.3;

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
- **Compliance:** cis_ad: 5.1;

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

### CTL.APIGATEWAY.AUTH.001

**API Routes Must Have Authorization Configured**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-3; nist_800_53_r5: AC-3; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

API Gateway routes and methods must have an authorizer configured (Cognito, Lambda, IAM, or JWT). Routes with authorization set to NONE are publicly accessible without any identity verification. The Trello breach (2024) exposed 15 million accounts through an unauthenticated API endpoint. The Spoutible breach (2024) leaked user data through an API without proper auth checks.

**Remediation:** Configure an authorizer on all non-health-check routes. Use Cognito user pools, Lambda authorizers, IAM authorization, or JWT authorizers depending on the client type.

---

### CTL.APIGATEWAY.CACHE.ENCRYPT.001

**REST API Cache Must Be Encrypted**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** nist_800_53_r5: SC-28; soc2: CC6.7;

API Gateway REST API stages with caching enabled must encrypt cached responses at rest. Unencrypted cache can expose response payloads, tokens, and PII.

**Remediation:** Enable cache encryption on the stage.

---

### CTL.APIGATEWAY.CORS.001

**HTTP APIs Must Not Combine Wildcard Origin With Credentials**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-4; nist_800_53_r5: AC-4; pci_dss_v4.0: 6.4.1; soc2: CC6.1;

API Gateway v2 HTTP APIs expose CORS configuration at the API level. Setting AllowOrigins to "*" together with AllowCredentials=true is the canonical CORS misconfiguration: browsers reject the combination at request time, so the configuration never succeeds for real clients, but the intent encoded in the resource is credentialed cross-origin access from any origin. This typically indicates the API owner intended to allow a broad set of web clients to make credentialed calls and did not understand that wildcard-plus-credentials is rejected. Real attackers do not need this misconfiguration to be functional — its presence signals that the origin allowlist and credentials policy have not been reasoned about together. The observation shape mirrors the CorsConfiguration object returned by "aws apigatewayv2 get-api".

**Remediation:** Either set AllowCredentials to false and keep the wildcard (if the API is genuinely open and cookies/auth headers are not required), or replace the wildcard in AllowOrigins with the explicit set of origins that need credentialed access. Update via "aws apigatewayv2 update-api --api-id <id> --cors-configuration ...".

---

### CTL.APIGATEWAY.DOMAIN.TLS.001

**API Gateway Custom Domains Must Enforce TLS 1.2+**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-8;

API Gateway custom domain names must enforce a minimum TLS version of 1.2. TLS 1.0 and 1.1 have known protocol-level vulnerabilities including BEAST, POODLE, and weak cipher suites that enable man-in-the-middle attacks. When a custom domain allows TLS below 1.2, an attacker on the network path can downgrade the connection and intercept API credentials, session tokens, or request payloads in transit. AWS API Gateway supports TLS 1.2 as the minimum security policy. Custom domains configured with older TLS versions expose every API behind that domain to protocol downgrade attacks regardless of the application-layer security controls in place.

**Remediation:** Update the custom domain security policy to TLS_1_2. In the API Gateway console or via the AWS CLI, set the security policy on the domain name to TLS_1_2. Verify that all API clients support TLS 1.2 before applying the change. Monitor CloudWatch access logs for connection failures after the update to identify clients that need upgrading.

---

### CTL.APIGATEWAY.INCOMPLETE.001

**Complete Data Required for API Gateway Assessment**

- **Severity:** info
- **Type:** unsafe_state
- **Domain:** exposure

The observation snapshot is missing required API Gateway properties.

**Remediation:** Ensure the extractor calls aws apigateway get-rest-apis and aws apigateway get-domain-names and maps security policy to the api observation properties.

---

### CTL.APIGATEWAY.LOG.001

**REST API Stages Must Have Logging Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AU-2; soc2: CC7.1;

API Gateway REST API stages must have execution or access logging enabled to CloudWatch. Without logging, API activity lacks visibility for detecting abuse and supporting incident response.

**Remediation:** Enable execution logging or access logging on the stage.

---

### CTL.APIGATEWAY.MTLS.001

**REST API Stages Must Use Client Certificates**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: IA-5; soc2: CC6.1;

API Gateway REST API stages should configure a client certificate for mutual TLS with backend integrations. Without client authentication, backends cannot verify requests originate from API Gateway.

**Remediation:** Generate and attach a client certificate to the stage.

---

### CTL.APIGATEWAY.PUBLIC.001

**REST APIs Should Use Private Endpoints When Possible**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.6;

REST APIs using EDGE or REGIONAL endpoint types are internet-accessible. APIs that serve only internal consumers should use PRIVATE endpoint type (VPC-only via PrivateLink) to reduce attack surface.

**Remediation:** Convert to PRIVATE endpoint type if the API serves only VPC consumers. If public access is required, ensure WAF and authorizers are configured.

---

### CTL.APIGATEWAY.STAGE.LIFECYCLE.001

**API Gateway Stages Must Not Have Orphaned or Deprecated Versions Accessible**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: CM-7; hipaa: 164.312(a)(1); nist_800_53_r5: CM-7; pci_dss_v4.0: 6.3.2; soc2: CC7.1;

API Gateway REST APIs must not have orphaned stages accessible with weaker security controls than the production stage. Orphaned stages from previous deployments, testing, and migrations accumulate without security controls applied to the current stage — no WAF association, no throttling, potentially no authorization. OWASP API9:2023 (Improper Inventory Management) identifies this as a primary API security gap. Older stages may retain endpoints that were fixed or removed in current versions. The security delta between orphaned and production stages defines the attack surface an attacker gains by discovering the old endpoint. A stage with no invocations in 30 days and missing controls present on the production stage is considered orphaned.

**Remediation:** Decommission orphaned stages by deleting the deployment from the API Gateway console or DeleteStage API. If the stage must remain for legacy integration, apply equivalent security controls — WAF association, throttling, and authorization — matching the production stage. Document intentional multi-stage deployments with a stave/api-stage-lookback-days tag.

---

### CTL.APIGATEWAY.THROTTLE.001

**API Gateway Stages Must Have Throttling Limits Configured**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-5; hipaa: 164.308(a)(1)(ii)(B); nist_800_53_r5: SC-5; pci_dss_v4.0: 6.4.1; soc2: A1.1;

API Gateway stages must have default throttling limits configured with non-zero burst and rate values. Without throttling, a single client can send unlimited requests — exhausting backend resources, generating unbounded AWS costs (Denial of Wallet on Lambda), enabling credential brute force, and abusing sensitive business flows at machine speed. OWASP API4:2023 (Unrestricted Resource Consumption) and API6:2023 (Unrestricted Access to Sensitive Business Flows) both share this infrastructure gap. WAF rate-based rules limit requests per IP at the WAF layer; API Gateway throttling limits requests per stage or per API key at the application layer. Both are needed — WAF addresses anonymous volume attacks, API Gateway throttling addresses authenticated API abuse and distributed attacks that evade per-IP limits.

**Remediation:** Configure stage-level throttling via the API Gateway console or UpdateStage API. Set a burst limit and rate limit appropriate for the API's expected traffic. For REST APIs handling sensitive operations, create a usage plan with per-consumer throttle limits and associate API keys with it.

---

### CTL.APIGATEWAY.TLS.001

**API Gateway Must Enforce TLS 1.2**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-8; gdpr: Art.32; hipaa: 164.312(e)(2)(ii); nist_800_53_r5: SC-8; pci_dss_v4.0: 4.2.1; soc2: CC6.6;

API Gateway stages must enforce TLS 1.2 or higher. Allowing older TLS versions exposes API traffic to known cryptographic attacks (BEAST, POODLE, etc).

**Remediation:** Set the minimum TLS version on the custom domain or API stage. For REST APIs, configure a security policy of TLS_1_2 on the custom domain name.

---

### CTL.APIGATEWAY.TRACING.001

**REST API Stages Should Enable X-Ray Tracing**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AU-12;

API Gateway REST API stages should enable X-Ray active tracing for distributed request tracing across connected services.

**Remediation:** Enable active tracing on the stage.

---

### CTL.APIGATEWAY.VALIDATION.001

**API Gateway Must Have Request Validation Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SI-10; hipaa: 164.312(c)(1); nist_800_53_r5: SI-10; pci_dss_v4.0: 6.2.4; soc2: CC6.6;

API Gateway REST APIs must have request validation configured. API Gateway can validate incoming requests against a defined schema — checking required parameters, parameter types and formats, and request body conformance to a JSON schema — before the request reaches the backend. Without validation, malformed and malicious inputs are forwarded to the backend uninspected. This is complementary to WAF protection: WAF managed rules detect known-malicious patterns (SQLi, XSS, known exploits), while request validation detects structural violations (missing fields, wrong types, malformed bodies). A backend that receives only structurally valid requests is harder to attack through injection because type confusion, null pointer paths, and unexpected field exploitation are blocked at the API boundary. Request validation is particularly valuable for APIs handling PHI or financial data where the backend may make trust assumptions about well-formed input.

**Remediation:** Configure a request validator on the REST API via the API Gateway console or PutRestApi/UpdateMethod API. Define request models (JSON schemas) for endpoints that accept request bodies. Enable parameter validation for all methods. For REST APIs handling PHI or sensitive data, enable both parameter and body validation against defined model schemas.

---

### CTL.APIGATEWAY.WAF.001

**REST API Stages Must Have WAF ACL Attached**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.6;

API Gateway REST API stages must have an AWS WAF web ACL associated for application-layer filtering. Without WAF, APIs are exposed to injection attacks, parameter tampering, L7 floods, and bot abuse.

**Remediation:** Associate a WAFv2 web ACL with the API stage.

---

### CTL.APIGW2.AUTH.001

**HTTP APIs Must Have Authorizers Configured**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3; soc2: CC6.1;

API Gateway v2 HTTP APIs must have an authorizer (JWT, Cognito, or Lambda) configured to authenticate requests. Without an authorizer, any client can invoke API routes without authentication.

**Remediation:** Configure a JWT, Cognito, or Lambda authorizer on the API routes.

---

### CTL.APIGW2.LOG.001

**HTTP API Stages Must Have Access Logging Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AU-2; soc2: CC7.1;

API Gateway v2 HTTP API stages must configure access logging to capture request details. Without logging, API calls lack traceability for detecting abuse and supporting incident response.

**Remediation:** Configure access logging with a CloudWatch Logs destination.

---

### CTL.APPSTREAM.INTERNET.001

**AppStream Fleets Must Disable Default Internet Access**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.6;

AppStream fleets must disable default internet access. Fleets with default internet connectivity allow streaming sessions to reach the internet directly, bypassing network controls.

**Remediation:** Disable EnableDefaultInternetAccess and use VPC with NAT.

---

### CTL.ATHENA.ENCRYPT.001

**Athena Workgroups Must Encrypt Query Results**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** nist_800_53_r5: SC-28; soc2: CC6.7;

Athena workgroups must encrypt query results at rest. Unencrypted query results in S3 expose data extracted by SQL queries.

**Remediation:** Enable encryption in the workgroup result configuration.

---

### CTL.AUTOSCALING.ELB.HEALTH.001

**Auto Scaling Groups Must Use ELB Health Checks**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** resilience
- **Compliance:** nist_800_53_r5: CP-7; soc2: CC7.1;

ASGs with load balancers must use ELB health checks.

**Remediation:** Switch to ELB health checks.

---

### CTL.AUTOSCALING.INCOMPLETE.001

**Complete Data Required for Auto Scaling Assessment**

- **Severity:** info
- **Type:** unsafe_state
- **Domain:** exposure

The observation snapshot is missing required Auto Scaling properties.

**Remediation:** Ensure the extractor calls aws autoscaling describe-auto-scaling-groups.

---

### CTL.AUTOSCALING.MULTIAZ.001

**Auto Scaling Groups Must Span Multiple Availability Zones**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** soc2: A1.1;

Auto Scaling groups must be configured across multiple AZs. A single-AZ ASG has a single point of failure during AZ outages.

**Remediation:** Update the ASG: aws autoscaling update-auto-scaling-group --auto-scaling-group-name <name> --availability-zones us-east-1a us-east-1b

---

### CTL.BACKUP.ENCRYPT.001

**Backups Must Be Encrypted**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-28; ffiec: BCP; gdpr: Art.32; hipaa: 164.312(a)(2)(iv); nist_800_53_r5: SC-28; pci_dss_v4.0: 3.4.1; soc2: CC6.7;

All backups must be encrypted at rest. Unencrypted backups expose data if the backup storage is compromised or the backup is shared across accounts.

**Remediation:** Enable encryption on the backup vault or copy the backup with encryption enabled. For AWS Backup, set the vault encryption key to a customer-managed KMS key.

---

### CTL.BACKUP.EXISTS.001

**Critical Resources Must Have Backups**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.308(a)(7); soc2: A1.1;

Resources tagged as critical or containing PHI must have at least one backup configured. Without backups, data loss from accidental deletion, corruption, or ransomware is permanent and unrecoverable.

**Remediation:** Configure automated backups via AWS Backup, RDS automated snapshots, or S3 cross-region replication depending on the resource type.

---

### CTL.BACKUP.INCOMPLETE.001

**Complete Data Required for Backup Assessment**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure

Backup safety cannot be assessed when backup status is missing from the snapshot. The extractor must populate backup.has_backup.

**Remediation:** Re-run the extractor with backup permissions: backup:ListBackupJobs, backup:DescribeBackupVault, rds:DescribeDBSnapshots, s3:GetBucketReplication.

---

### CTL.BACKUP.MULTIAZ.001

**Critical Resources Must Be Multi-AZ**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.308(a)(7); soc2: A1.1;

Resources tagged as critical must be deployed across multiple Availability Zones. Single-AZ deployment has a single point of failure that causes unavailability during AZ outages.

**Remediation:** Enable Multi-AZ deployment or configure cross-AZ replication depending on the resource type (RDS Multi-AZ, S3 cross-region replication, ELB multi-AZ targets).

---

### CTL.BACKUP.PLAN.EXISTS.001

**AWS Backup Plan Must Exist and Cover Critical Resources**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.308(a)(7)(ii)(A); mitre_attack: T1490; nist_800_53_r5: CP-9;

An AWS Backup plan must exist and protect critical resources. Without centralized backup, ransomware or accidental deletion can permanently destroy production data across EC2, RDS, EFS, DynamoDB, and S3.

**Remediation:** Create an AWS Backup plan covering all critical resources with daily backups and 35-day retention. Enable vault lock for write-once-read-many protection.

---

### CTL.BACKUP.RECENT.001

**Backups Must Be Recent**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** ffiec: BCP; hipaa: 164.308(a)(7); soc2: A1.1;

The most recent backup must be within the defined recovery point objective (RPO). Stale backups indicate a broken backup process and increase data loss exposure.

**Remediation:** Verify the backup schedule is active and producing successful backups. Check AWS Backup job history or RDS automated snapshot timestamps.

---

### CTL.BACKUP.RECOVERY.ISOLATION.001

**Backup KMS Key Must Be in Different Account Than Source Data**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** storage
- **Compliance:** fedramp_moderate: CP-9; nist_800_53_r5: CP-9; soc2: A1.1;

The KMS key used to encrypt backups must reside in a different AWS account than the source data. If both the data and the decryption key are in the same account, a single account compromise destroys both — the attacker can delete the data AND schedule the KMS key for deletion, rendering backups permanently unrecoverable.

**Remediation:** Create a dedicated backup recovery account. Generate a KMS key in the recovery account and use it for backup encryption. Use aws backup start-copy-job to replicate backups to the recovery account.

---

### CTL.BACKUP.RECOVERY.ISOLATION.002

**Data Admin Must Not Have KMS Key Deletion Permission**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** storage
- **Compliance:** fedramp_moderate: CP-9(1); nist_800_53_r5: CP-9(1); soc2: CC6.1;

The principal that administers the source data must have separate permissions from the principal that manages the backup encryption key. If the same admin can delete both the data and schedule the KMS key for deletion, a compromised credential enables complete and irreversible data destruction — the ransomware path.

**Remediation:** Separate data administration from key management. Use a dedicated backup admin role in a separate account. Apply SCP policies that deny kms:ScheduleKeyDeletion from data admin roles.

---

### CTL.BACKUP.REPLICATION.001

**Critical Data Must Have Cross-Region Replication**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.308(a)(7); soc2: A1.1;

Data classified as critical or PHI must have cross-region replication configured for disaster recovery. Single-region data is vulnerable to regional outages and cannot meet recovery time objectives (RTO) for multi-region failover.

**Remediation:** Configure cross-region replication: S3 CRR, RDS cross-region read replica, or AWS Backup cross-region copy rule.

---

### CTL.BACKUP.VAULT.LOCK.001

**Backup Vaults Must Have Vault Lock Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: CP-9; soc2: A1.1;

AWS Backup vaults must have vault lock enabled to prevent deletion of recovery points. Without vault lock, an attacker with vault access can delete all backups before conducting a destructive attack — the ransomware pattern eliminates the recovery path before encrypting production data.

**Remediation:** Enable vault lock with a retention policy.

---

### CTL.BEANSTALK.LOG.001

**Elastic Beanstalk Environments Must Stream Logs to CloudWatch**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AU-2; soc2: CC7.1;

Elastic Beanstalk environments must stream instance and proxy logs to CloudWatch Logs for centralized monitoring.

**Remediation:** Enable CloudWatch Logs streaming in the environment configuration.

---

### CTL.BEANSTALK.UPDATES.001

**Elastic Beanstalk Must Enable Managed Platform Updates**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SI-2; soc2: CC7.1;

Elastic Beanstalk environments must enable managed platform updates to automatically apply security patches and minor updates.

**Remediation:** Enable managed platform updates in the environment.

---

### CTL.BEDROCK.ACCESS.ADMIN.001

**Bedrock API Keys Must Not Have Administrative Privileges**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6; soc2: CC6.1;

IAM users with Bedrock API keys must not have policies granting bedrock:* or full administrative access. A compromised overprivileged key can invoke models at scale, modify guardrails and logging, and escalate IAM privileges.

**Remediation:** Scope the IAM user's policies to only the Bedrock actions required (e.g., bedrock:InvokeModel on specific models).

---

### CTL.BEDROCK.ACCESS.FULLACCESS.001

**IAM Roles Must Not Use AmazonBedrockFullAccess Policy**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6; soc2: CC6.1;

IAM roles (excluding service-linked roles) must not have the AWS-managed AmazonBedrockFullAccess policy attached. This policy grants unrestricted access to all Bedrock actions and resources. If the role is compromised, an attacker can invoke any model, modify guardrails and logging, and incur significant costs.

**Remediation:** Replace AmazonBedrockFullAccess with a scoped policy granting only required Bedrock actions on specific model ARNs.

---

### CTL.BEDROCK.ACCESS.LONGTERM.001

**Bedrock API Keys Must Not Be Long-Lived**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: IA-5; soc2: CC6.1;

Bedrock API keys must have appropriate expiration dates. Long-lived or non-expiring keys enable persistent access if compromised — unauthorized inference, exposure of prompts/outputs, uncontrolled cost, and inability to timely revoke credentials.

**Remediation:** Set an appropriate expiration on the API key. Rotate keys regularly and use short-lived credentials where possible.

---

### CTL.BEDROCK.AGENT.GUARDRAIL.001

**Bedrock Agents Must Have an Associated Guardrail**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SI-10; soc2: CC6.1;

Bedrock agents must have a guardrail associated with their sessions. Without guardrails, agent exchanges may expose PII or internal data, accept prompt injections that manipulate tool calls, and produce unsafe or out-of-scope responses. Agents can invoke tools and APIs — an unguarded agent is an unguarded API caller.

**Remediation:** Associate a guardrail with the agent via the guardrailConfiguration setting in the agent definition.

---

### CTL.BEDROCK.GUARDRAIL.PII.001

**Bedrock Guardrails Must Enable Sensitive Information Filter**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.312(a)(1); nist_800_53_r5: SI-10; soc2: CC6.1;

Bedrock guardrails must configure sensitive information filters to block or mask PII and custom patterns in prompts and responses. Without filtering, prompts or outputs can reveal PII, credentials, financial records, or other sensitive data. LLMs may echo sensitive data from prompts or training data in responses.

**Remediation:** Configure sensitive information filters in the guardrail to block or mask PII types (SSN, credit card, email, etc.) and custom regex patterns.

---

### CTL.BEDROCK.GUARDRAIL.PROMPTATTACK.001

**Bedrock Guardrails Must Enable High-Strength Prompt Attack Filter**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SI-10; soc2: CC6.1;

Bedrock guardrails must configure the prompt attack filter at HIGH strength. Without high-strength filtering, models are exposed to prompt injection and jailbreak attacks that can coerce disclosure of sensitive data, evade content policies, and trigger unintended tool execution.

**Remediation:** Update the guardrail to set the prompt attack filter strength to HIGH via aws bedrock update-guardrail.

---

### CTL.BEDROCK.LOG.ENCRYPT.001

**Bedrock Invocation Logs Must Be Encrypted**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** hipaa: 164.312(a)(2)(iv); nist_800_53_r5: SC-28; soc2: CC6.7;

Bedrock model invocation logs must be stored in encrypted destinations — S3 with bucket encryption and CloudWatch Logs with KMS. Invocation logs contain prompts and responses which frequently include sensitive business data, PII, and confidential queries.

**Remediation:** Enable KMS encryption on the CloudWatch Logs group and/or S3 bucket used for invocation log delivery.

---

### CTL.BEDROCK.LOG.INVOCATION.001

**Bedrock Model Invocation Logging Must Be Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AU-2; soc2: CC7.1;

Bedrock model invocation logging must be enabled to capture request/response data for Converse, InvokeModel, and streaming calls. Without invocation logs, there is no audit trail for what prompts were sent or what the model responded — credential misuse, prompt injection, and data exfiltration go undetected.

**Remediation:** Enable model invocation logging via aws bedrock put-model-invocation-logging-configuration with S3 and/or CloudWatch Logs destinations.

---

### CTL.BEDROCK.VPC.ENDPOINTS.001

**VPC Must Have Bedrock Interface Endpoints Configured**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.6;

VPCs using Bedrock must have interface endpoints for all Bedrock services (bedrock, bedrock-runtime, bedrock-agent, bedrock-agent-runtime). Without private endpoints, API traffic exits the VPC via internet gateway, exposing it to network-path threats and adding an internet dependency.

**Remediation:** Create interface VPC endpoints for bedrock, bedrock-runtime, bedrock-agent, and bedrock-agent-runtime services.

---

### CTL.CFN.PARAM.NOECHO.001

**CloudFormation Parameters for Sensitive Values Must Have NoEcho Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-28; hipaa: 164.312(a)(2)(iv); nist_800_53_r5: SC-28; pci_dss_v4.0: 3.4.1; soc2: CC6.1;

CloudFormation template parameters that are likely to contain sensitive values must have NoEcho set to true. Without NoEcho, parameter values are visible in stack events, stack details, and change set descriptions. Any IAM principal with cloudformation:DescribeStacks can read them in plaintext. This control checks the NoEcho property — not the parameter value or default.

**Remediation:** Add NoEcho: true to the parameter definition in the CloudFormation template. Redeploy the stack. Note that existing stack events may still contain the plaintext value — rotate the credential after enabling NoEcho.

---

### CTL.CISCO.ACL.EGRESS.001

**Egress Filtering Must Be Applied**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_cisco_ios_17: 4.2.1; nist_800_53_r5: SC-7;

Cisco IOS devices must have egress filtering applied on external interfaces. Without egress filtering, the device forwards traffic with any source address including spoofed and RFC 1918 addresses. An attacker on the internal network can send packets with forged source addresses to participate in reflected DDoS attacks, evade source-based logging and tracing, or exfiltrate data in a way that cannot be traced back to the originating host.

**Remediation:** Apply egress ACLs to external interfaces permitting only legitimate source address ranges. Run: interface <external-interface> ip access-group <egress-acl> out Verify with: show ip access-lists

---

### CTL.CISCO.ACL.VTY.001

**VTY Lines Must Have ACL Applied**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_cisco_ios_17: 4.1.1; nist_800_53_r5: AC-3;

All VTY lines on Cisco IOS devices must have an access-class ACL applied to restrict remote management access. Without an ACL on VTY lines, any IP address that can reach the device can attempt SSH or Telnet connections. An attacker from any network position can attempt credential brute-force attacks against the management interface. VTY access should be restricted to authorized management networks only.

**Remediation:** Apply an access-class ACL to all VTY lines. Run: line vty 0 15 access-class <acl-name> in Verify with: show running-config | section line vty

---

### CTL.CISCO.AUTH.AAA.001

**AAA New-Model Must Be Enabled**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_cisco_ios_17: 1.2.1; nist_800_53_r5: IA-2;

Cisco IOS devices must have AAA new-model enabled. Without AAA new-model, the device falls back to line-based authentication which cannot enforce centralized authentication, authorization, or accounting policies. An attacker who compromises a local line password gains full access with no audit trail and no ability to enforce per-user access controls.

**Remediation:** Enable AAA new-model. Run: aaa new-model Verify with: show running-config | include aaa new-model

---

### CTL.CISCO.AUTH.ACCOUNTING.001

**AAA Accounting Exec Must Be Configured**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_cisco_ios_17: 1.2.5; nist_800_53_r5: AU-2;

Cisco IOS devices must have AAA accounting for exec sessions configured. Without exec accounting, there is no record of who accessed the device, when sessions started and stopped, or what privilege level was used. An attacker can access the device and perform reconnaissance or configuration changes with no audit trail for incident response or forensic analysis.

**Remediation:** Configure AAA accounting for exec sessions. Run: aaa accounting exec default start-stop group tacacs+ Verify with: show running-config | include aaa accounting exec

---

### CTL.CISCO.AUTH.ENABLE.001

**Enable Secret Must Be Configured**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_cisco_ios_17: 1.1.1; nist_800_53_r5: IA-5;

Cisco IOS devices must use enable secret instead of enable password. The enable password command stores the password using a weak reversible cipher (Type 7) that is trivially decoded. Enable secret uses a one-way hash (MD5 or scrypt) that cannot be reversed. An attacker with read access to the running configuration can decode Type 7 passwords instantly using publicly available tools.

**Remediation:** Configure enable secret and remove enable password. Run: enable secret <strong-password> no enable password Verify with: show running-config | include enable

---

### CTL.CISCO.AUTH.LOGIN.001

**AAA Authentication Login Must Be Configured**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_cisco_ios_17: 1.2.2; nist_800_53_r5: IA-2;

Cisco IOS devices must have AAA authentication login configured. Without an explicit authentication login method list, the device uses default line authentication which typically accepts a single shared password. This prevents per-user accountability and allows any user with the shared password to access the device without individual identification.

**Remediation:** Configure AAA authentication login. Run: aaa authentication login default group tacacs+ local Verify with: show running-config | include aaa authentication login

---

### CTL.CISCO.AUTH.SVCENC.001

**Service Password-Encryption Must Be Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_cisco_ios_17: 1.1.2; nist_800_53_r5: IA-5;

Cisco IOS devices must have service password-encryption enabled. Without this service, passwords in the running and startup configuration are stored in cleartext. Anyone with read access to the configuration file — through SNMP, TFTP backup, or shoulder surfing — can immediately read all passwords including line passwords and username passwords.

**Remediation:** Enable service password-encryption. Run: service password-encryption Verify with: show running-config | include service password

---

### CTL.CISCO.BGP.AUTH.001

**BGP Neighbors Must Use Authentication**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_cisco_ios_17: 3.1.1; nist_800_53_r5: SC-8;

All BGP neighbor sessions on Cisco IOS devices must be configured with MD5 authentication. Without authentication, an attacker who can reach the BGP TCP port (179) can establish a peer session and inject arbitrary routes. This enables traffic hijacking, black-hole attacks, and man-in-the-middle interception of traffic destined for any prefix the attacker advertises. BGP route injection can redirect traffic at internet scale.

**Remediation:** Configure MD5 authentication for all BGP neighbors. Run: router bgp <asn> neighbor <ip> password <secret> Verify with: show ip bgp neighbors | include password

---

### CTL.CISCO.BGP.FILTERIN.001

**BGP Inbound Route Filtering Must Be Applied**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_cisco_ios_17: 3.1.2; nist_800_53_r5: SC-7;

All BGP neighbors on Cisco IOS devices must have inbound route filtering configured. Without inbound filters, the device accepts any route advertised by a peer including routes for prefixes the peer has no authority to announce. An attacker who compromises a peer or establishes an unauthorized session can inject routes for any prefix, redirecting traffic through attacker-controlled infrastructure for interception or denial of service.

**Remediation:** Apply inbound prefix-list or route-map filters to all BGP neighbors. Run: router bgp <asn> neighbor <ip> prefix-list <name> in Verify with: show ip bgp neighbors | include filter

---

### CTL.CISCO.BGP.FILTEROUT.001

**BGP Outbound Route Filtering Must Be Applied**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_cisco_ios_17: 3.1.3; nist_800_53_r5: SC-7;

All BGP neighbors on Cisco IOS devices must have outbound route filtering configured. Without outbound filters, the device may advertise routes for prefixes it should not announce, including internal network prefixes, default routes, or prefixes learned from other peers. This can cause route leaks that redirect traffic through unintended paths, expose internal network topology, or create routing loops that cause denial of service.

**Remediation:** Apply outbound prefix-list or route-map filters to all BGP neighbors. Run: router bgp <asn> neighbor <ip> prefix-list <name> out Verify with: show ip bgp neighbors | include filter

---

### CTL.CISCO.HSRP.AUTH.001

**HSRP Must Use Authentication**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_cisco_ios_17: 3.3.1; nist_800_53_r5: SC-8;

All HSRP groups on Cisco IOS devices must be configured with authentication. Without HSRP authentication, an attacker on the local network segment can send crafted HSRP hello packets with a higher priority to become the active gateway. This redirects all default gateway traffic through the attacker's machine, enabling man-in-the-middle interception of all traffic leaving the subnet including credentials, session tokens, and sensitive data.

**Remediation:** Configure HSRP authentication for all groups. Run: interface <interface> standby <group> authentication md5 key-string <secret> Verify with: show standby | include authentication

---

### CTL.CISCO.INTF.DIRBROADCAST.001

**Directed Broadcast Must Be Disabled on Interfaces**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_cisco_ios_17: 4.3.1; nist_800_53_r5: SC-7;

Cisco IOS devices must have IP directed broadcast disabled on all interfaces. Directed broadcasts allow a remote host to send a packet to the broadcast address of a subnet, which the router then converts to a layer 2 broadcast. This is the basis of the Smurf attack where an attacker sends ICMP echo requests to a directed broadcast address with a spoofed source, causing all hosts on the subnet to respond to the victim, creating massive amplification.

**Remediation:** Disable directed broadcast on all interfaces. Run: interface <interface> no ip directed-broadcast Verify with: show running-config | include directed-broadcast

---

### CTL.CISCO.MGMT.BANNER.001

**Login Banner Must Be Configured**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_cisco_ios_17: 1.1.1; nist_800_53_r5: AC-8;

A login banner must be configured on Cisco IOS devices. A login banner provides legal notice to anyone attempting to access the device. Without a banner, unauthorized access attempts may not be prosecutable in some jurisdictions because the attacker can claim there was no indication the system was private or that access was restricted. The banner should warn that unauthorized access is prohibited and that activity may be monitored.

**Remediation:** Configure a login banner on the device. Run: banner login ^ Unauthorized access is prohibited. All activity is monitored. ^ Verify with: show banner login

---

### CTL.CISCO.MGMT.HTTP.001

**HTTP Server Must Be Disabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_cisco_ios_17: 1.2.1; nist_800_53_r5: CM-7;

The HTTP server must be disabled on Cisco IOS devices. The IOS HTTP server provides a web-based management interface that transmits credentials and configuration data in cleartext. An attacker on the network path can intercept administrator credentials, session tokens, and device configuration. The HTTP server has also been the target of multiple IOS vulnerabilities including remote code execution. If web-based management is required, HTTPS must be used instead.

**Remediation:** Disable the HTTP server on the device. Run: no ip http server Verify with: show ip http server status If web management is required, enable HTTPS instead with ip http secure-server.

---

### CTL.CISCO.MGMT.SNMP.001

**SNMP Version Must Be 3**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_cisco_ios_17: 2.2.1; nist_800_53_r5: SC-8;

Cisco IOS devices must use SNMP version 3. SNMP v1 and v2c transmit community strings in cleartext and provide no authentication or encryption. An attacker with network access can capture community strings and gain read or read-write access to the device MIB. SNMP v3 provides authentication (AuthNoPriv) and encryption (AuthPriv) protecting both credentials and management data in transit.

**Remediation:** Configure SNMP v3 with authentication and privacy. Run: snmp-server group <group> v3 priv snmp-server user <user> <group> v3 auth sha <auth-pass> priv aes 256 <priv-pass> Remove SNMP v1/v2c community strings: no snmp-server community <string>

---

### CTL.CISCO.MGMT.SNMPCOMM.001

**No Default SNMP Community Strings**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_cisco_ios_17: 2.2.2; nist_800_53_r5: IA-5;

Cisco IOS devices must not use default SNMP community strings. Default community strings such as "public" and "private" are universally known and are the first values attempted in any SNMP enumeration scan. A device with default community strings allows unauthenticated read or read-write access to its entire MIB, exposing configuration details, routing tables, interface statistics, and enabling configuration changes.

**Remediation:** Remove default SNMP community strings and replace with unique values or migrate to SNMP v3. Run: no snmp-server community public no snmp-server community private Verify with: show snmp community

---

### CTL.CISCO.MGMT.SSH.001

**SSH Version Must Be 2**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_cisco_ios_17: 2.1.2; nist_800_53_r5: SC-8;

Cisco IOS devices must use SSH version 2. SSH version 1 has known cryptographic weaknesses including vulnerability to man-in-the-middle attacks and session hijacking. SSH v1 uses CRC-32 for integrity checking which is not cryptographically secure. An attacker on the network path can exploit these weaknesses to intercept or modify management sessions.

**Remediation:** Configure SSH version 2 explicitly. Run: ip ssh version 2 Verify with: show ip ssh

---

### CTL.CISCO.MGMT.TELNET.001

**Telnet Must Be Disabled**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_cisco_ios_17: 2.1.1; nist_800_53_r5: SC-8;

Telnet must be disabled on Cisco IOS devices. Telnet transmits all data including credentials in cleartext. An attacker with network access can capture management session traffic and extract authentication credentials using passive packet capture. All management access must use SSH which provides encrypted transport.

**Remediation:** Disable Telnet on all VTY lines and require SSH. Run: line vty 0 15 transport input ssh Verify with: show line vty 0 15 | include input

---

### CTL.CISCO.NTP.AUTH.001

**NTP Authentication Must Be Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_cisco_ios_17: 2.2.2; nist_800_53_r5: AU-8;

Cisco IOS devices must have NTP authentication enabled. Without NTP authentication, the device accepts time updates from any source claiming to be an NTP server. An attacker can inject false time data to manipulate log timestamps, cause certificate validation failures, invalidate time-based access controls, or create gaps in audit records by shifting the device clock forward or backward.

**Remediation:** Enable NTP authentication. Run: ntp authenticate ntp authentication-key 1 md5 <key> ntp trusted-key 1 Verify with: show ntp status

---

### CTL.CISCO.NTP.SERVERS.001

**NTP Must Be Configured**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_cisco_ios_17: 2.2.1; nist_800_53_r5: AU-8;

Cisco IOS devices must have NTP configured with at least one time source. Without NTP, device clocks drift and log timestamps become unreliable. Inaccurate timestamps make incident response and forensic analysis extremely difficult because events cannot be correlated across devices. An attacker benefits from unreliable timestamps because their activity cannot be precisely timed or correlated with other network events.

**Remediation:** Configure NTP with a trusted time source. Run: ntp server <ntp-server-ip> Verify with: show ntp status

---

### CTL.CISCO.OSPF.AUTH.001

**OSPF Areas Must Use Authentication**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_cisco_ios_17: 3.2.1; nist_800_53_r5: SC-8;

All OSPF areas on Cisco IOS devices must be configured with authentication. Without OSPF authentication, an attacker connected to an OSPF-enabled network segment can inject false routing information by sending crafted OSPF hello and LSA packets. This enables traffic redirection through attacker-controlled hosts, black-hole attacks that drop traffic silently, and network topology manipulation that can isolate network segments.

**Remediation:** Enable OSPF authentication for all areas. Run: router ospf <process-id> area <area-id> authentication message-digest Verify with: show ip ospf | include authentication

---

### CTL.CISCO.SVC.BOOTP.001

**BOOTP Server Must Be Disabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_cisco_ios_17: 2.1.1; nist_800_53_r5: CM-7;

The BOOTP server must be disabled on Cisco IOS devices. BOOTP is a legacy protocol used to assign IP addresses and boot images to network clients. The IOS BOOTP server listens on UDP port 67 and can serve IOS images to any client that requests them. An attacker can use BOOTP to obtain a copy of the IOS image, which enables offline vulnerability analysis and credential extraction. BOOTP also enables network-based attacks by allowing the attacker to serve malicious boot images to clients.

**Remediation:** Disable the BOOTP server on the device. Run: no ip bootp server Verify with: show ip bootp server

---

### CTL.CISCO.SVC.CDP.001

**CDP Must Be Disabled Globally**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_cisco_ios_17: 2.1.3; nist_800_53_r5: CM-7;

Cisco Discovery Protocol must be disabled on Cisco IOS devices. CDP broadcasts device information including hostname, IOS version, platform, IP addresses, and VLAN information in cleartext to all directly connected devices. An attacker with layer 2 access can passively collect this information to map the network topology and identify vulnerable software versions without generating any traffic that would trigger detection.

**Remediation:** Disable CDP globally. Run: no cdp run Verify with: show cdp

---

### CTL.CISCO.SVC.FINGER.001

**Finger Service Must Be Disabled**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_cisco_ios_17: 2.1.4; nist_800_53_r5: CM-7;

Cisco IOS devices must have the finger service disabled. The finger service exposes user session information including which users are logged in, their terminal lines, idle times, and connection sources. An attacker can use this information to enumerate active management sessions, identify administrator activity patterns, and time attacks for periods of low monitoring activity.

**Remediation:** Disable the finger service. Run: no ip finger no service finger Verify with: show running-config | include finger

---

### CTL.CISCO.SVC.GRATARP.001

**Gratuitous ARP Must Be Disabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_cisco_ios_17: 2.1.6; nist_800_53_r5: SC-7;

Cisco IOS devices must have gratuitous ARP disabled. Gratuitous ARP allows a device to announce its IP-to-MAC mapping without being asked. An attacker can send forged gratuitous ARP packets to poison the ARP cache of other devices on the network segment, redirecting traffic through the attacker's machine for man-in-the-middle attacks. This enables credential interception, session hijacking, and data exfiltration on the local network segment.

**Remediation:** Disable gratuitous ARP on interfaces. Run: no ip gratuitous-arps Verify with: show running-config | include gratuitous

---

### CTL.CISCO.SVC.HTTPD.001

**HTTPS Must Be Used Instead of HTTP for Management**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_cisco_ios_17: 1.2.2; nist_800_53_r5: SC-8;

HTTPS must be enabled for web-based management of Cisco IOS devices. Without HTTPS, any web management traffic falls back to cleartext HTTP, exposing administrator credentials, session tokens, and configuration data to network interception. TLS encryption provided by HTTPS protects the confidentiality and integrity of management sessions. Even when the HTTP server is disabled, HTTPS should be explicitly enabled to ensure that any future web management configuration defaults to encrypted transport.

**Remediation:** Enable the HTTPS server on the device. Run: ip http secure-server Verify with: show ip http server status Ensure the HTTP server is disabled with: no ip http server

---

### CTL.CISCO.SVC.SRCROUTE.001

**IP Source Routing Must Be Disabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_cisco_ios_17: 2.1.5; nist_800_53_r5: SC-7;

Cisco IOS devices must have IP source routing disabled. Source routing allows a packet sender to specify the route the packet takes through the network, bypassing normal routing decisions. An attacker can use source routing to direct traffic through specific hosts for eavesdropping, bypass firewall rules by routing around security devices, or reach internal hosts that would otherwise be unreachable from the attacker's network position.

**Remediation:** Disable IP source routing. Run: no ip source-route Verify with: show running-config | include ip source-route

---

### CTL.CISCO.SVC.TCPSMALL.001

**TCP Small Servers Must Be Disabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_cisco_ios_17: 2.1.1; nist_800_53_r5: CM-7;

Cisco IOS devices must have TCP small servers disabled. TCP small servers include echo, chargen, discard, and daytime services that provide no operational value on network infrastructure. These services can be used for amplification attacks and denial of service. The chargen service in particular is commonly exploited for reflected DDoS attacks by spoofing the source address.

**Remediation:** Disable TCP small servers. Run: no service tcp-small-servers Verify with: show running-config | include tcp-small-servers

---

### CTL.CISCO.SVC.UDPSMALL.001

**UDP Small Servers Must Be Disabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_cisco_ios_17: 2.1.2; nist_800_53_r5: CM-7;

Cisco IOS devices must have UDP small servers disabled. UDP small servers include echo, chargen, and discard services that provide no operational value on network infrastructure. These services are particularly dangerous because UDP is connectionless and source addresses are easily spoofed, making them ideal for reflected amplification attacks that can overwhelm target networks.

**Remediation:** Disable UDP small servers. Run: no service udp-small-servers Verify with: show running-config | include udp-small-servers

---

### CTL.CISCO.URPF.001

**Unicast Reverse Path Forwarding Must Be Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_cisco_ios_17: 4.3.1; nist_800_53_r5: SC-7;

Unicast Reverse Path Forwarding must be enabled on Cisco IOS devices. Without uRPF, the device accepts packets with spoofed source IP addresses. IP spoofing enables denial-of-service amplification attacks, TCP session hijacking, and evasion of IP-based access controls. uRPF verifies that the source address of each incoming packet is reachable via the interface it arrived on, dropping packets that fail this check. This is a fundamental anti-spoofing control recommended by BCP 38 (RFC 2827).

**Remediation:** Enable uRPF on all external-facing interfaces. Run: interface <interface> ip verify unicast source reachable-via rx Use "rx" (strict mode) on interfaces with a single path, or "any" (loose mode) on interfaces with asymmetric routing. Verify with: show ip verify unicast source

---

### CTL.CLOUDFORMATION.DRIFT.001

**CloudFormation Stack Drift Detection Must Be Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: CM-3; nist_800_53_r5: CM-3; pci_dss_v4.0: 6.3.2; soc2: CC8.1;

CloudFormation stacks managing production infrastructure must have drift detection enabled. Drift indicates out-of-band changes bypassing IaC.

**Remediation:** Detect drift: aws cloudformation detect-stack-drift --stack-name <name>. Configure periodic detection via EventBridge.

---

### CTL.CLOUDFORMATION.INCOMPLETE.001

**Complete Data Required for CloudFormation Assessment**

- **Severity:** info
- **Type:** unsafe_state
- **Domain:** exposure

The observation snapshot is missing required CloudFormation properties.

**Remediation:** Ensure the extractor calls aws cloudformation describe-stacks.

---

### CTL.CLOUDFORMATION.ROLLBACK.001

**CloudFormation Stacks Must Have Rollback Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: CM-3; nist_800_53_r5: CM-3; soc2: CC8.1;

CloudFormation stacks must not have DisableRollback set to true. With rollback disabled, a failed deployment leaves resources in a partially created state that may be insecure. Rollback ensures failed changes are reverted to the last known-good state.

**Remediation:** Remove DisableRollback from stack creation/update parameters. Ensure all stacks use the default rollback behavior.

---

### CTL.CLOUDFORMATION.SECRETS.001

**CloudFormation Stack Outputs Must Not Contain Secrets**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: IA-5(7); soc2: CC6.1;

CloudFormation stack outputs must not contain hardcoded secrets. Stack outputs are readable by anyone with cloudformation:DescribeStacks access, visible in the console, and logged in CloudTrail.

**Remediation:** Remove secrets from outputs. Use Secrets Manager or Parameter Store with dynamic references.

---

### CTL.CLOUDFORMATION.STACKSETS.RESTRICT.001

**CloudFormation StackSets Must Require Administrator Approval**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** mitre_attack: T1578; nist_800_53_r5: CM-3;

CloudFormation StackSets deploy infrastructure across multiple AWS accounts and regions simultaneously. An attacker with cloudformation:CreateStackSet and cloudformation:CreateStackInstances can execute arbitrary CloudFormation templates across an entire AWS Organization — creating IAM roles, modifying security groups, or deploying compute resources in hundreds of accounts. StackSet operations should require explicit approval and be restricted to trusted automation accounts or principals.

**Remediation:** Restrict cloudformation:CreateStackInstances to designated automation principals via SCP. Deny unless aws:PrincipalArn matches approved automation roles.

---

### CTL.CLOUDFORMATION.STATE.001

**Terraform State Must Be Versioned**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: CM-3; nist_800_53_r5: CM-3; soc2: CC8.1;

Terraform state files must be stored in a versioned backend (S3 with versioning, Terraform Cloud, or equivalent). Unversioned state means a corrupted or accidentally deleted state file cannot be recovered, leaving infrastructure in an unmanaged state with no rollback path.

**Remediation:** Configure an S3 backend with versioning enabled and DynamoDB state locking. Alternatively, use Terraform Cloud or an equivalent managed backend with built-in versioning.

---

### CTL.CLOUDFORMATION.TERMINATION.001

**CloudFormation Stacks Must Have Termination Protection Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: CP-10; soc2: A1.1;

CloudFormation root stacks must enable termination protection to prevent accidental or unauthorized deletion of infrastructure.

**Remediation:** Enable termination protection on the stack.

---

### CTL.CLOUDFRONT.CORS.001

**Response Headers Policy Must Not Combine Wildcard Origin With Credentials**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-4; nist_800_53_r5: AC-4; pci_dss_v4.0: 6.4.1; soc2: CC6.1;

CloudFront response headers policies can attach a CorsConfig block whose AccessControlAllowOrigins and AccessControlAllowCredentials values are propagated to every distribution that references the policy. A policy that sets AccessControlAllowOrigins to "*" and AccessControlAllowCredentials to true encodes the intent that any origin may make credentialed requests against every distribution using this policy. Browsers refuse wildcard-plus-credentials, but the configuration signals that the origin allowlist and credentials policy have not been reasoned about together. Because response headers policies are shared across distributions, a single misconfigured policy can propagate the misconfiguration to unrelated workloads. Observation fields mirror the CorsConfig block returned by "aws cloudfront get-response-headers-policy".

**Remediation:** Update the policy so AccessControlAllowCredentials is false or the AccessControlAllowOrigins list does not contain "*". Use "aws cloudfront update-response-headers-policy" with a patched ResponseHeadersPolicyConfig.CorsConfig block. Audit which distributions reference this policy via "aws cloudfront list-distributions" — every referencing distribution inherits the change.

---

### CTL.CLOUDFRONT.GEO.001

**CloudFront Distributions Requiring Geo Restriction Must Configure It**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3;

CloudFront distributions that are required to enforce geographic restrictions must have geo restriction configured. Geo restriction limits content delivery to approved countries and blocks requests from sanctioned or high-risk regions. When geo restriction is required by compliance policy but not configured on the distribution, content is served globally without geographic controls. This creates regulatory exposure for organizations subject to export controls, data sovereignty requirements, or sanctions compliance. CloudFront geo restriction operates at the edge location level and is the primary mechanism for enforcing geographic access boundaries on CDN-delivered content.

**Remediation:** Configure geo restriction on the CloudFront distribution. Use either an allow list to restrict delivery to approved countries or a deny list to block specific regions. Set the restriction type and country codes in the distribution configuration. Verify the geo restriction configuration aligns with the organization's compliance requirements for geographic content delivery boundaries.

---

### CTL.CLOUDFRONT.HEADERS.001

**CloudFront Distributions Must Enforce Security Response Headers**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-8; nist_800_53_r5: SC-8; pci_dss_v4.0: 6.4.1; soc2: CC6.6;

CloudFront distributions must have a response headers policy attached that includes Strict-Transport-Security (HSTS) with max-age >= 31536000, X-Frame-Options set to DENY or SAMEORIGIN, X-Content-Type-Options set to nosniff, and Referrer-Policy set to a restrictive value. Without these headers, browsers do not enforce transport security, framing protection, MIME type enforcement, or referrer leakage prevention. Content-Security-Policy (CSP) is not required — it requires application-specific source definitions outside Stave's scope. This pairs with CTL.CLOUDFRONT.TLS.001: TLS enforces encrypted transport, response headers enforce browser-layer security.

**Remediation:** Create or update a response headers policy with the four required headers: Strict-Transport-Security (max-age=31536000; includeSubDomains), X-Frame-Options (DENY or SAMEORIGIN), X-Content-Type-Options (nosniff), and Referrer-Policy (strict-origin-when-cross-origin or no-referrer). Attach the policy to the distribution via the CloudFront console or UpdateDistribution API.

---

### CTL.CLOUDFRONT.HTTPS.ONLY.001

**CloudFront Distributions Must Enforce HTTPS-Only Viewer Protocol**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** aws_security_hub: CloudFront.3; mitre_attack: TA0006; nist_800_53_r5: SC-8;

CloudFront distributions that allow HTTP (allow-all viewer protocol policy) serve content over plaintext connections. Session cookies, authentication tokens, and sensitive data transmitted over HTTP are visible to network-level attackers. Both the default cache behavior and all custom cache behaviors must enforce HTTPS. A single HTTP-permitting behavior is sufficient for session hijacking.

**Remediation:** Update viewer protocol policy to redirect-to-https or https-only for all cache behaviors (default and custom) in the distribution configuration.

---

### CTL.CLOUDFRONT.LOGGING.001

**CloudFront Distributions Must Have Access Logging Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** aws_security_hub: CloudFront.5; mitre_attack: TA0005; nist_800_53_r5: AU-12;

CloudFront access logs record every request served by the distribution — viewer IP, request URI, response code, bytes transferred, and cache hit/miss status. Without access logs, there is no record of attempted exploitation, data exfiltration via large response payloads, reconnaissance scanning, or suspicious geographic access patterns. A distribution without logging is a blind spot in the organization's visibility.

**Remediation:** Enable access logging in the distribution configuration, specifying an S3 bucket as destination. The S3 bucket must grant CloudFront write access via bucket ACL or bucket policy.

---

### CTL.CLOUDFRONT.ORIGIN.FAILOVER.001

**CloudFront Distributions Must Have Origin Failover Configured**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** resilience
- **Compliance:** aws_security_hub: CloudFront.4; mitre_attack: TA0040; nist_800_53_r5: CP-7;

CloudFront origin failover automatically routes requests to a secondary origin when the primary returns specific HTTP error codes (502, 503, 504). Without failover, a primary origin outage causes all requests to fail — a DoS condition on the distribution. A secondary origin (cross-region S3 bucket, secondary ALB, or backup API endpoint) ensures availability during primary origin failures.

**Remediation:** Configure an origin group with primary and secondary origins. Specify failover criteria (HTTP status codes that trigger failover to the secondary origin).

---

### CTL.CLOUDFRONT.ORIGIN.NOACCESS.001

**CloudFront S3 Origin Must Have Origin Access Control**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-3; nist_800_53_r5: AC-3; pci_dss_v4.0: 1.3.4; soc2: CC6.6;

CloudFront distributions with S3 origins must have Origin Access Control (OAC) or at minimum Origin Access Identity (OAI) configured. Without either, CloudFront accesses the bucket via its public endpoint, requiring the bucket to have a public or permissive policy. This makes CloudFront's authentication, WAF, and geo-restriction bypassable by hitting the S3 endpoint directly.

**Remediation:** Configure Origin Access Control (OAC) on the distribution. Update the S3 bucket policy to grant access only to the CloudFront distribution via the OAC principal. Remove any public access from the bucket policy.

---

### CTL.CLOUDFRONT.ORIGIN.SHIELD.001

**High-Traffic CloudFront Distributions Should Have Origin Shield Enabled**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** resilience
- **Compliance:** mitre_attack: TA0040; nist_800_53_r5: SC-5;

Origin Shield adds an additional caching layer between CloudFront edge locations and the origin, reducing the number of requests that reach the origin server. Without it, high-traffic distributions can overwhelm origins with cache-miss requests — a potential vector for cache-busting DoS attacks where attackers force cache misses by varying request parameters.

**Remediation:** Enable Origin Shield in each origin configuration, selecting the region closest to the origin.

---

### CTL.CLOUDFRONT.TLS.001

**CloudFront Distributions Must Enforce TLS 1.2 or Higher**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-8; hipaa: 164.312(e)(2)(ii); nist_800_53_r5: SC-8; pci_dss_v4.0: 4.2.1; soc2: CC6.6;

CloudFront distributions must use a security policy that enforces TLS 1.2 or higher for all viewer connections. TLS 1.0 and TLS 1.1 have known cryptographic weaknesses (BEAST, POODLE, SWEET32) that are structural properties of the protocol, not implementation bugs. The default CloudFront security policy permits TLS 1.0 for backwards compatibility with older clients. Organizations that accept this default are unknowingly accepting protocol-downgrade attacks. TLS 1.2 enforcement exists for ALB (CTL.ELB.TLS.001), API Gateway (CTL.APIGATEWAY.TLS.001), RDS (CTL.RDS.SSL.001), and OpenSearch (CTL.OPENSEARCH.HTTPS.001) — this control closes the CloudFront gap. PCI-DSS explicitly prohibits TLS 1.0 for cardholder data. NIST SP 800-52r2 requires TLS 1.2 minimum for federal systems. Acceptable policies: TLSv1.2_2021, TLSv1.2_2019, TLSv1.2_2018.

**Remediation:** Update the CloudFront distribution viewer certificate configuration to use TLSv1.2_2021 security policy. This requires a custom SSL certificate (not the default CloudFront certificate). Use ACM to provision a certificate in us-east-1, attach it to the distribution, and select TLSv1.2_2021 as the minimum protocol version. All modern browsers and clients released after 2015 support TLS 1.2.

---

### CTL.CLOUDFRONT.TLS.MINIMUM.001

**CloudFront Distributions Must Enforce TLS 1.2 Minimum Security Policy**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** aws_security_hub: CloudFront.10; hipaa: 164.312(e)(2)(ii); mitre_attack: TA0006; nist_800_53_r5: SC-8;

CloudFront distributions using TLSv1 or TLSv1.1 security policies accept connections over deprecated TLS versions vulnerable to BEAST, POODLE, and other protocol attacks. The security policy controls the minimum TLS version and cipher suites accepted from viewers. TLSv1.2_2021 or TLSv1.3_2022 are recommended — they exclude all vulnerable cipher suites and protocol versions.

**Remediation:** Update the distribution viewer certificate configuration to use TLSv1.2_2021 or TLSv1.3_2022 as the minimum protocol version. Requires a custom SSL certificate from ACM in us-east-1.

---

### CTL.CLOUDFRONT.WAF.001

**CloudFront Distributions Must Have a WAF Web ACL Associated**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SI-3; hipaa: 164.312(e)(1); nist_800_53_r5: SC-7;

CloudFront distributions must have an AWS WAF Web ACL associated for layer-7 protection against web application attacks. Without WAF, requests reach the origin without inspection for SQL injection, XSS, known exploit signatures, rate limiting, or IP reputation blocking.

**Remediation:** Create a WAF Web ACL in us-east-1 (required for CloudFront) with AWSManagedRulesCommonRuleSet and associate it with the distribution via UpdateDistribution API.

---

### CTL.CLOUDTRAIL.CWLOGS.001

**CloudTrail Trails Must Be Integrated with CloudWatch Logs**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 3.4; fedramp_moderate: AU-6; hipaa: 164.312(b); nist_800_53_r5: AU-6; pci_dss_v4.0: 10.5.1; soc2: CC7.1;

CloudTrail trails must be configured to deliver events to a CloudWatch Logs log group with active delivery. CloudTrail delivers events to S3 by default. CloudWatch Logs integration is a separate configuration that enables real-time metric filtering and alerting. Without it, all 17 CIS-required CloudWatch metric filter controls (CTL.CLOUDWATCH.MONITOR.*) evaluate an empty event stream — the filters exist, the alarms are configured, but nothing fires. This is a silent gap: all monitoring controls appear to pass individually while the event pipeline is broken. CTL.CLOUDTRAIL.ENABLED.001 verifies the trail is active. This control verifies the trail is delivering to CloudWatch Logs — the prerequisite for real-time monitoring.

**Remediation:** Configure the trail to deliver to a CloudWatch Logs log group via the CloudTrail console or update-trail API. Create or specify a log group and grant CloudTrail the cloudwatch:PutLogEvents permission via an IAM role. Verify delivery is active after configuration.

---

### CTL.CLOUDTRAIL.DATA.DYNAMODB.001

**CloudTrail Must Log DynamoDB Data Events**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** nist_800_53_r5: AU-12; soc2: CC7.1;

CloudTrail trails must include DynamoDB data events to log table-level operations (GetItem, PutItem, Query, Scan). Without this, data exfiltration from DynamoDB is invisible.

**Remediation:** Add DynamoDB data event selector to the trail: event category Data, resource type AWS::DynamoDB::Table, read/write type All.

---

### CTL.CLOUDTRAIL.DATA.LAMBDA.001

**CloudTrail Must Log Lambda Invocation Data Events**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** nist_800_53_r5: AU-12; soc2: CC7.1;

CloudTrail trails must include Lambda data events to log function invocations. Without this, attacker execution via Lambda is invisible.

**Remediation:** Add Lambda data event selector to the trail: event category Data, resource type AWS::Lambda::Function, read/write type All.

---

### CTL.CLOUDTRAIL.DATAREAD.001

**S3 Object Read Logging Must Be Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 3.9; fedramp_moderate: AU-3; gdpr: Art.30; nist_800_53_r5: AU-3; pci_dss_v4.0: 10.2.1.7; soc2: CC6.2;

CloudTrail must log S3 data read events (GetObject). Read logging provides evidence of data access for PHI audit trails and breach investigation.

**Remediation:** Add S3 data read event selectors to the trail using advanced event selectors with readOnly=true.

---

### CTL.CLOUDTRAIL.DATAWRITE.001

**S3 Object Write Logging Must Be Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 3.8; fedramp_moderate: AU-3; gdpr: Art.30; nist_800_53_r5: AU-3; pci_dss_v4.0: 10.2.1.7; soc2: CC6.2;

CloudTrail must log S3 data write events (PutObject, DeleteObject). Without object-level write logging, individual object mutations are invisible to the audit trail.

**Remediation:** Add S3 data write event selectors to the trail using advanced event selectors with readOnly=false.

---

### CTL.CLOUDTRAIL.DISABLE.RECUR.001

**CloudTrail Must Not Be Stopped and Restarted Repeatedly**

- **Severity:** critical
- **Type:** unsafe_recurrence
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 3.1; fedramp_moderate: AU-9; hipaa: 164.312(b); nist_800_53_r5: AU-9; pci_dss_v4.0: 10.5.1; soc2: CC7.1;

CloudTrail trail has been stopped and restarted more than once in 30 days. Stopping CloudTrail creates gaps in the audit record. Repeated stop/start cycles are the forensic signature of deliberate audit evasion across multiple attacker sessions — the attacker stops the trail, takes actions, restarts it, and repeats.

**Remediation:** Investigate the root cause of the repeated oscillation. Determine whether the pattern indicates a broken process, operational workaround, or active compromise. Review CloudTrail for the API calls that triggered each transition.

---

### CTL.CLOUDTRAIL.ENABLED.001

**CloudTrail Must Be Enabled in All Regions**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v1.4.0: 3.1; cis_aws_v3.0: 3.1; fedramp_moderate: AU-2; ffiec: ISH-4; gdpr: Art.30; hipaa: 164.312(b); iso_27001_2022: A.8.15; nist_800_53_r5: AU-2; nist_csf_2.0: DE.CM; pci_dss_v4.0: 10.2.1; soc2: CC7.1;

CloudTrail must be configured as a multi-region trail. A single-region trail misses API activity in other regions, leaving gaps in the audit record that prevent forensic investigation of unauthorized access.

**Remediation:** Update the trail to enable multi-region logging. Run: aws cloudtrail update-trail --name xxx --is-multi-region-trail

---

### CTL.CLOUDTRAIL.ENCRYPT.001

**CloudTrail Logs Must Be Encrypted with KMS**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v1.4.0: 3.7; cis_aws_v3.0: 3.5; fedramp_moderate: AU-9; hipaa: 164.312(a)(2)(iv); nist_800_53_r5: AU-9; pci_dss_v4.0: 10.5.1; soc2: CC6.7;

CloudTrail logs must be encrypted at rest using a KMS customer-managed key. Default S3 encryption (SSE-S3) does not provide key revocation capability needed for breach response.

**Remediation:** Configure the trail to use a KMS key for log encryption. Run: aws cloudtrail update-trail --name xxx --kms-key-id arn:aws:kms:...

---

### CTL.CLOUDTRAIL.INCOMPLETE.001

**Complete Data Required for CloudTrail Assessment**

- **Severity:** info
- **Type:** unsafe_state
- **Domain:** exposure

The observation snapshot is missing required CloudTrail properties. A safety assessment cannot be completed without trail configuration data.

**Remediation:** Ensure the extractor calls aws cloudtrail describe-trails and aws cloudtrail get-trail-status and maps the response to the audit_trail observation properties.

---

### CTL.CLOUDTRAIL.INSIGHTS.001

**CloudTrail Insights Must Be Enabled for Anomaly Detection**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** nist_800_53_r5: SI-4; soc2: CC7.1;

CloudTrail Insights must be enabled to detect anomalous API activity patterns — unusual call volumes or error rates that indicate automated reconnaissance or attack.

**Remediation:** Enable CloudTrail Insights (ApiCallRateInsight and ApiErrorRateInsight) on the trail via the CloudTrail console or PutInsightSelectors API.

---

### CTL.CLOUDTRAIL.LOG.VALIDATION.001

**CloudTrail Log File Validation Must Be Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws: 3.2; mitre_attack: T1562.008; nist_800_53_r5: AU-9;

CloudTrail log file validation must be enabled to detect whether log files have been modified or deleted after delivery to S3. Without validation, forensic investigators cannot determine if logs were tampered with.

**Remediation:** aws cloudtrail update-trail --name <trail-name> --enable-log-file-validation

---

### CTL.CLOUDTRAIL.LOOKUP.RESTRICT.001

**CloudTrail LookupEvents Must Be Restricted**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** mitre_attack: T1526; nist_800_53_r5: AU-9;

CloudTrail LookupEvents access must be restricted to security and administrative roles. Unrestricted LookupEvents access exposes 90 days of API activity patterns including which principals performed which actions, resource names, source IP addresses, and timestamps. Attackers use this to identify active service accounts, map API usage patterns, and time their actions to blend with normal activity.

**Remediation:** Restrict cloudtrail:LookupEvents to security and administrative roles only. Apply conditions such as aws:PrincipalTag to limit access. Consider using CloudTrail Lake with fine-grained query permissions instead of LookupEvents for audit workflows.

---

### CTL.CLOUDTRAIL.NETWORK.ACTIVITY.001

**CloudTrail Must Log Network Activity Events for VPC Endpoints**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** fedramp_moderate: AU-12; nist_800_53_r5: AU-12; soc2: CC7.1;

CloudTrail Network Activity event logging must be enabled to capture VPC endpoint data-plane events including anonymous S3 requests. AWS's April 2026 patch logs anonymous requests as Network Activity events, but only if this event type is enabled.

**Remediation:** Enable Network Activity events on the CloudTrail trail via PutEventSelectors with the networkActivity event category.

---

### CTL.CLOUDTRAIL.ORG.001

**CloudTrail Must Be Configured as Organization Trail**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** cis_aws_v3.0: 3.1; fedramp_moderate: AU-12; nist_800_53_r5: AU-12; soc2: CC7.1;

CloudTrail trails must be configured as AWS Organizations trails covering all member accounts. Account-level trails leave member accounts without centralized logging.

**Remediation:** Convert to an organization trail via the management account.

---

### CTL.CLOUDTRAIL.REPLICATION.001

**CloudTrail Logs Must Be Replicated to a Separate Account**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** fedramp_moderate: AU-9; nist_800_53_r5: AU-9; soc2: CC7.1;

CloudTrail log destination must have cross-account replication configured to a separate logging account. Without replication, compromising the trail-hosting account enables complete evidence destruction.

**Remediation:** Configure S3 replication on the trail bucket targeting a bucket in a separate logging account.

---

### CTL.CLOUDTRAIL.RETENTION.001

**CloudTrail Logs Must Be Retained Beyond 90 Days**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 3.3; fedramp_moderate: AU-11; gdpr: Art.30; hipaa: 164.312(b); iso_27001_2022: A.8.15; nist_800_53_r5: AU-11; nist_csf_2.0: DE.AE; pci_dss_v4.0: 10.7.1; soc2: CC7.1;

CloudTrail trail must deliver logs to an S3 bucket or CloudWatch Logs group with a retention policy that preserves logs beyond the 90-day CloudTrail Events History window. Without long-term retention, forensic investigation of incidents older than 90 days is impossible.

**Remediation:** Configure the trail to deliver logs to an S3 bucket with a lifecycle policy that retains objects for at least 365 days. Alternatively, deliver logs to a CloudWatch Logs group with a retention policy of 365 days or more.

---

### CTL.CLOUDTRAIL.S3LOG.001

**CloudTrail S3 Bucket Must Have Access Logging**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 3.4; fedramp_moderate: AU-9; nist_800_53_r5: AU-9; pci_dss_v4.0: 10.5.1; soc2: CC7.1;

The S3 bucket receiving CloudTrail logs must have server access logging enabled. Without it, access to the audit logs themselves is not auditable.

**Remediation:** Enable access logging on the trail S3 bucket: aws s3api put-bucket-logging --bucket <trail-bucket> --bucket-logging-status '{"LoggingEnabled":{"TargetBucket":"<log-bucket>"}}'

---

### CTL.CLOUDTRAIL.STOP.DETECT.001

**CloudTrail Trails Must Be Actively Logging in All Regions**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.312(b); mitre_attack: T1562.008; nist_800_53_r5: AU-12;

CloudTrail must be actively logging and configured as a multi-region trail. Stopping CloudTrail is the first action attackers take after gaining access — it eliminates the audit trail of subsequent actions.

**Remediation:** aws cloudtrail start-logging --name <trail-name> aws cloudtrail update-trail --name <trail-name> --is-multi-region-trail

---

### CTL.CLOUDTRAIL.VALIDATION.001

**CloudTrail Log File Validation Must Be Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v1.4.0: 3.2; cis_aws_v3.0: 3.2; fedramp_moderate: AU-9; ffiec: ISH-4; gdpr: Art.32; hipaa: 164.312(b); iso_27001_2022: A.8.15; nist_800_53_r5: AU-9; pci_dss_v4.0: 10.2.1; soc2: CC7.1;

CloudTrail must have log file integrity validation enabled. Without validation, an attacker who gains access to the log bucket can modify or delete log entries to cover their tracks.

**Remediation:** Enable log file validation on the trail. Run: aws cloudtrail update-trail --name xxx --enable-log-file-validation

---

### CTL.CLOUDWATCH.ALARM.GHOST.001

**CloudWatch Alarm Actions Must Not Target Deleted SNS Topics**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** fedramp_moderate: AU-5; hipaa: 164.312(b); nist_800_53_r5: AU-5; soc2: CC7.1;

CloudWatch alarm notification actions must not reference deleted SNS topics. When the alarm fires, the notification goes nowhere. The security team is not alerted. The alarm appears configured and active in the console while notifications are silently broken.

**Remediation:** Update the alarm action to reference an existing SNS topic.

---

### CTL.CLOUDWATCH.INCOMPLETE.001

**Complete Data Required for CloudWatch Assessment**

- **Severity:** info
- **Type:** unsafe_state
- **Domain:** exposure

The observation snapshot is missing required CloudWatch log group properties.

**Remediation:** Ensure the extractor calls aws logs describe-log-groups and maps the retentionInDays to the log_group observation properties.

---

### CTL.CLOUDWATCH.LOG.EXPORT.001

**CloudWatch Log Group Exports Must Be Restricted to Authorized Buckets**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** mitre_attack: T1530; nist_800_53_r5: AU-9;

CloudWatch log group export tasks copy all log data to an S3 bucket. An attacker with logs:CreateExportTask permission can export CloudTrail logs, application logs, and security tool outputs to an attacker-controlled bucket. This is particularly dangerous for CloudTrail log groups — exporting them gives the attacker a complete copy of all API activity before they cover their tracks.

**Remediation:** Restrict logs:CreateExportTask to approved S3 destinations via IAM resource conditions. Monitor for export tasks to unexpected destinations via CloudTrail alerting.

---

### CTL.CLOUDWATCH.LOG.RETENTION.001

**CloudWatch Log Groups Must Have Retention Policies Set**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** mitre_attack: T1530; nist_800_53_r5: AU-11;

CloudWatch log groups without retention policies retain logs indefinitely — creating an ever-growing collection of potentially sensitive data (application logs, access patterns, error messages containing credentials). An attacker with logs:GetLogEvents access can search through years of accumulated logs to harvest credentials, API keys, and internal system details. Retention policies limit the data collection window.

**Remediation:** Set a retention policy appropriate for the log type: aws logs put-retention-policy --log-group-name <name> --retention-in-days 90

---

### CTL.CLOUDWATCH.LOG.RETENTION365.001

**CloudWatch Log Retention Must Be At Least 365 Days**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AU-11; gdpr: Art.30; nist_800_53_r5: AU-11; pci_dss_v4.0: 10.7;

CloudWatch log groups for cardholder data environment audit logs must retain logs for at least 365 days. PCI-DSS v4.0 requires 12 months of audit trail with at least 3 months immediately available.

**Remediation:** Set retention to at least 365 days: aws logs put-retention-policy --log-group-name <name> --retention-in-days 365

---

### CTL.CLOUDWATCH.MONITOR.ANON.VPC.001

**Anonymous S3 Requests via VPC Endpoints Must Be Monitored**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AU-12; soc2: CC7.1;

CloudWatch alarms must detect anonymous S3 requests transiting VPC endpoints. Even with Network Activity logging enabled, events must be actively monitored to surface anonymous access.

**Remediation:** Create a CloudWatch metric filter on Network Activity events matching anonymous (unsigned) S3 requests through VPC endpoints. Create an alarm with SNS notification.

---

### CTL.CLOUDWATCH.MONITOR.AUTHFAIL.001

**Console Authentication Failures Must Be Monitored**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 4.6; soc2: CC7.1;

A CloudWatch metric filter and alarm must monitor console authentication failures. Failed console authentication attempts indicate brute force attacks against IAM user passwords.

**Remediation:** Create a CloudWatch log metric filter on the CloudTrail log group matching the CIS-specified pattern for console authentication failures, then create an alarm with an SNS notification action.

---

### CTL.CLOUDWATCH.MONITOR.CMK.001

**CMK Disable or Deletion Must Be Monitored**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 4.7; soc2: CC7.1;

A CloudWatch metric filter and alarm must monitor cmk disable or deletion. KMS key disabling or scheduled deletion renders encrypted data permanently inaccessible — a ransomware vector.

**Remediation:** Create a CloudWatch log metric filter on the CloudTrail log group matching the CIS-specified pattern for cmk disable or deletion, then create an alarm with an SNS notification action.

---

### CTL.CLOUDWATCH.MONITOR.CONFIG.001

**AWS Config Changes Must Be Monitored**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 4.9; soc2: CC7.1;

A CloudWatch metric filter and alarm must monitor aws config changes. Changes to AWS Config (StopConfigurationRecorder) remove drift detection.

**Remediation:** Create a CloudWatch log metric filter on the CloudTrail log group matching the CIS-specified pattern for aws config changes, then create an alarm with an SNS notification action.

---

### CTL.CLOUDWATCH.MONITOR.CROSSACCOUNT.001

**Cross-Account AssumeRole Events Must Be Monitored**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AU-12; nist_800_53_r5: AU-12; soc2: CC7.1;

A CloudWatch metric filter and alarm must monitor sts:AssumeRole events from external accounts. Cross-account assumption is a normal operation for partner integrations and CI/CD pipelines, but unexpected external assumptions indicate compromised trust relationships or credential theft. The metric filter should match AssumeRole events where the source account is not in the organization's known account list.

**Remediation:** Create a CloudWatch log metric filter on the CloudTrail log group matching sts:AssumeRole events where the source account differs from the target account. Create an alarm with SNS notification.

---

### CTL.CLOUDWATCH.MONITOR.ESCALATION.001

**IAM Privilege Escalation Events Must Be Monitored**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 4.4; fedramp_moderate: AU-12; nist_800_53_r5: AU-12; soc2: CC7.1;

A CloudWatch metric filter and alarm must monitor IAM privilege escalation API calls. These are the specific API actions that enable an attacker to elevate permissions after initial access: CreatePolicyVersion, SetDefaultPolicyVersion, AttachUserPolicy, AttachRolePolicy, AttachGroupPolicy, PutUserPolicy, PutRolePolicy, PutGroupPolicy, CreateAccessKey, CreateLoginProfile, UpdateLoginProfile, UpdateAssumeRolePolicy, and PassRole (as a parameter in RunInstances, CreateFunction, CreateStack, etc.). The existing iam_policy_changes metric filter (CIS 4.4) covers general policy modifications but does not specifically surface the escalation-enabling subset. This control verifies that a dedicated escalation-focused filter and alarm exist.

**Remediation:** Create a CloudWatch log metric filter on the CloudTrail log group matching escalation-relevant API calls: { ($.eventName = CreatePolicyVersion) ||
  ($.eventName = SetDefaultPolicyVersion) ||
  ($.eventName = AttachUserPolicy) ||
  ($.eventName = AttachRolePolicy) ||
  ($.eventName = PutUserPolicy) ||
  ($.eventName = PutRolePolicy) ||
  ($.eventName = CreateAccessKey) ||
  ($.eventName = CreateLoginProfile) ||
  ($.eventName = UpdateAssumeRolePolicy) }.
Then create a CloudWatch alarm with an SNS notification action.

---

### CTL.CLOUDWATCH.MONITOR.GW.001

**Network Gateway Changes Must Be Monitored**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 4.12; soc2: CC7.1;

A CloudWatch metric filter and alarm must monitor network gateway changes. Gateway attachment is the boundary between a VPC and the internet.

**Remediation:** Create a CloudWatch log metric filter on the CloudTrail log group matching the CIS-specified pattern for network gateway changes, then create an alarm with an SNS notification action.

---

### CTL.CLOUDWATCH.MONITOR.IAMPOLICY.001

**IAM Policy Changes Must Be Monitored**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 4.4; soc2: CC7.1;

A CloudWatch metric filter and alarm must monitor iam policy changes. IAM policy modifications (CreatePolicy, DeletePolicy, AttachRolePolicy) are a primary persistence mechanism for attackers.

**Remediation:** Create a CloudWatch log metric filter on the CloudTrail log group matching the CIS-specified pattern for iam policy changes, then create an alarm with an SNS notification action.

---

### CTL.CLOUDWATCH.MONITOR.IMDS.001

**IMDS Configuration Changes Must Be Monitored**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AU-12; soc2: CC7.1;

CloudWatch alarms must detect changes to EC2 instance metadata options (ModifyInstanceMetadataOptions). Without monitoring, an attacker can downgrade IMDSv2 to IMDSv1 silently.

**Remediation:** Create a CloudWatch metric filter on CloudTrail events matching ModifyInstanceMetadataOptions. Create an alarm with SNS notification for any match.

---

### CTL.CLOUDWATCH.MONITOR.LAMBDA.ERRORS.001

**Lambda Error and Permission Failure Events Must Be Monitored**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AU-12; nist_800_53_r5: AU-12; soc2: CC7.1;

CloudWatch alarms must be configured to detect Lambda function error spikes, throttling events, and permission failure patterns. Without monitoring, a compromised function probing IAM permissions generates AccessDenied events nobody sees, and application errors indicating exploitation accumulate without alerting.

**Remediation:** Create CloudWatch alarms for: AWS/Lambda Errors metric exceeding threshold, AWS/Lambda Throttles > 0, and CloudTrail AccessDenied/UnauthorizedAccess events filtered to Lambda- sourced principals. Configure SNS notification for each alarm.

---

### CTL.CLOUDWATCH.MONITOR.MFADEVICE.001

**MFA Device Changes Must Be Monitored**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SI-4; nist_800_53_r5: SI-4; soc2: CC7.1;

A CloudWatch metric filter and alarm must monitor MFA device enrollment and deactivation events. MFA device changes (CreateVirtualMFADevice, EnableMFADevice, DeactivateMFADevice, DeleteVirtualMFADevice) are a persistence mechanism — an attacker who gains temporary access can enroll their own MFA device to maintain access after the victim resets their password.

**Remediation:** Create a CloudWatch log metric filter on the CloudTrail log group matching CreateVirtualMFADevice, EnableMFADevice, DeactivateMFADevice, and DeleteVirtualMFADevice events. Create an alarm with an SNS notification action to alert on any MFA device change.

---

### CTL.CLOUDWATCH.MONITOR.NACL.001

**NACL Changes Must Be Monitored**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 4.11; soc2: CC7.1;

A CloudWatch metric filter and alarm must monitor nacl changes. Network ACL changes can open or close network paths.

**Remediation:** Create a CloudWatch log metric filter on the CloudTrail log group matching the CIS-specified pattern for nacl changes, then create an alarm with an SNS notification action.

---

### CTL.CLOUDWATCH.MONITOR.NOMFA.001

**Console Sign-In Without MFA Must Be Monitored**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 4.2; soc2: CC7.1;

A CloudWatch metric filter and alarm must monitor console sign-in without mfa. Console sign-ins without MFA indicate either MFA is not enforced or credentials were used from a context that bypassed MFA.

**Remediation:** Create a CloudWatch log metric filter on the CloudTrail log group matching the CIS-specified pattern for console sign-in without mfa, then create an alarm with an SNS notification action.

---

### CTL.CLOUDWATCH.MONITOR.ORG.001

**AWS Organizations Changes Must Be Monitored**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 4.15; soc2: CC7.1;

A CloudWatch metric filter and alarm must monitor aws organizations changes. Organizations changes affect account-level governance and SCP enforcement.

**Remediation:** Create a CloudWatch log metric filter on the CloudTrail log group matching the CIS-specified pattern for aws organizations changes, then create an alarm with an SNS notification action.

---

### CTL.CLOUDWATCH.MONITOR.ROOT.001

**Root Account Usage Must Be Monitored**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 4.3; soc2: CC7.1;

A CloudWatch metric filter and alarm must monitor root account usage. Root account API activity should be near-zero. Any activity may indicate compromise or unauthorized administrative action.

**Remediation:** Create a CloudWatch log metric filter on the CloudTrail log group matching the CIS-specified pattern for root account usage, then create an alarm with an SNS notification action.

---

### CTL.CLOUDWATCH.MONITOR.ROUTE.001

**Route Table Changes Must Be Monitored**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 4.13; soc2: CC7.1;

A CloudWatch metric filter and alarm must monitor route table changes. Route table modifications can redirect traffic through attacker-controlled paths.

**Remediation:** Create a CloudWatch log metric filter on the CloudTrail log group matching the CIS-specified pattern for route table changes, then create an alarm with an SNS notification action.

---

### CTL.CLOUDWATCH.MONITOR.S3POLICY.001

**S3 Bucket Policy Changes Must Be Monitored**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 4.8; soc2: CC7.1;

A CloudWatch metric filter and alarm must monitor s3 bucket policy changes. S3 bucket policy changes (PutBucketPolicy, PutBucketAcl) can make private buckets public.

**Remediation:** Create a CloudWatch log metric filter on the CloudTrail log group matching the CIS-specified pattern for s3 bucket policy changes, then create an alarm with an SNS notification action.

---

### CTL.CLOUDWATCH.MONITOR.SG.001

**Security Group Changes Must Be Monitored**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 4.10; soc2: CC7.1;

A CloudWatch metric filter and alarm must monitor security group changes. Security group changes directly affect network access to resources.

**Remediation:** Create a CloudWatch log metric filter on the CloudTrail log group matching the CIS-specified pattern for security group changes, then create an alarm with an SNS notification action.

---

### CTL.CLOUDWATCH.MONITOR.STS.ANOMALOUS.001

**Anomalous STS Credential Usage Must Be Monitored**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AU-12; soc2: CC7.1;

CloudWatch alarms must detect STS credential usage from unexpected IP addresses or regions — indicating stolen instance role credentials being used externally.

**Remediation:** Create a CloudWatch metric filter matching STS API calls where the source IP is outside the expected VPC CIDR range or from unexpected regions. Alert on any match.

---

### CTL.CLOUDWATCH.MONITOR.TRAIL.001

**CloudTrail Configuration Changes Must Be Monitored**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 4.5; soc2: CC7.1;

A CloudWatch metric filter and alarm must monitor cloudtrail configuration changes. Changes to CloudTrail (CreateTrail, UpdateTrail, DeleteTrail, StopLogging) are the first action in covering tracks after compromise.

**Remediation:** Create a CloudWatch log metric filter on the CloudTrail log group matching the CIS-specified pattern for cloudtrail configuration changes, then create an alarm with an SNS notification action.

---

### CTL.CLOUDWATCH.MONITOR.TRAIL.ACCESS.001

**Unauthorized Access to CloudTrail Log Bucket Must Be Monitored**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AU-9; soc2: CC7.1;

CloudWatch alarms must detect access to the CloudTrail log bucket by principals other than the CloudTrail service. An attacker who reads log files can learn what's logged and plan evasion.

**Remediation:** Create a CloudWatch metric filter on the CloudTrail log group matching S3 GetObject/ListBucket events on the trail bucket where the principal is not cloudtrail.amazonaws.com. Create an alarm with SNS notification.

---

### CTL.CLOUDWATCH.MONITOR.UNAUTH.001

**Unauthorized API Calls Must Be Monitored**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 4.1; soc2: CC7.1;

A CloudWatch metric filter and alarm must monitor unauthorized api calls. Unauthorized API calls (AccessDenied, UnauthorizedAccess) indicate credential probing or misconfigured IAM policies.

**Remediation:** Create a CloudWatch log metric filter on the CloudTrail log group matching the CIS-specified pattern for unauthorized api calls, then create an alarm with an SNS notification action.

---

### CTL.CLOUDWATCH.MONITOR.VPC.001

**VPC Changes Must Be Monitored**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 4.14; soc2: CC7.1;

A CloudWatch metric filter and alarm must monitor vpc changes. VPC lifecycle changes affect the entire network boundary.

**Remediation:** Create a CloudWatch log metric filter on the CloudTrail log group matching the CIS-specified pattern for vpc changes, then create an alarm with an SNS notification action.

---

### CTL.CLOUDWATCH.RETENTION.001

**CloudWatch Log Groups Must Have Retention Policy**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.312(b); soc2: CC7.1;

CloudWatch Logs log groups must have a retention policy configured. Without a retention policy, logs are kept indefinitely (incurring cost) or may be deleted manually without audit trail.

**Remediation:** Set a retention policy on the log group. Run: aws logs put-retention-policy --log-group-name xxx --retention-in-days 365

---

### CTL.CODEBUILD.BUILDSPEC.USERCONTROLLED.001

**CodeBuild Projects Must Not Use User-Controlled Buildspecs**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SA-12; soc2: CC8.1;

CodeBuild projects should use centrally managed buildspec definitions, not user-controlled buildspec files from the source repository. Repository-controlled buildspecs allow unreviewed pull request changes to execute arbitrary commands in the CI environment under the project's IAM role.

**Remediation:** Use an inline buildspec or a buildspec stored in a separate, access-controlled location. If repository buildspecs are required, enforce branch protection and require approvals before builds execute on PR changes.

---

### CTL.CODEBUILD.ENCRYPT.REPORTS.001

**CodeBuild Report Group Exports Must Be Encrypted**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** nist_800_53_r5: SC-28; pci_dss_v4.0: 3.4.1; soc2: CC6.7;

CodeBuild report groups exporting to S3 must encrypt exported test results at rest with a KMS key. Unencrypted reports may contain test data, code coverage metrics, and build artifacts.

**Remediation:** Enable KMS encryption on the report group S3 export configuration.

---

### CTL.CODEBUILD.ENCRYPT.S3LOGS.001

**CodeBuild S3 Build Logs Must Be Encrypted**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** nist_800_53_r5: SC-28;

CodeBuild projects delivering logs to S3 must encrypt log objects at rest. Unencrypted build logs can expose source structure, dependency versions, test results, and secrets leaked during build.

**Remediation:** Enable encryption on S3 log delivery in the build project configuration.

---

### CTL.CODEBUILD.INACTIVE.001

**CodeBuild Projects Must Not Be Inactive for Over 90 Days**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: CM-8; soc2: CC6.1;

CodeBuild projects not invoked in over 90 days should be reviewed and decommissioned. Inactive projects retain webhooks, source credentials, and IAM roles — dormant attack surface with stale permissions.

**Remediation:** Review the project. If no longer needed, delete it and its associated IAM role and webhooks. If still needed, document the justification.

---

### CTL.CODEBUILD.LOG.001

**CodeBuild Projects Must Have Logging Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AU-2; soc2: CC7.1;

CodeBuild projects must have at least one log destination enabled (CloudWatch Logs or S3). Without logging, build execution details, errors, and security events are invisible — a compromised build leaves no forensic trail.

**Remediation:** Enable CloudWatch Logs or S3 log delivery in the project configuration.

---

### CTL.CODEBUILD.PRIVILEGED.001

**CodeBuild Projects Must Not Use Docker Privileged Mode**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-6(5); soc2: CC6.1;

CodeBuild projects must not enable Docker privileged mode unless building Docker images is required. Privileged mode grants the build container full access to the host, enabling container escape. A compromised build with privileged mode gains the build role's permissions on the underlying host.

**Remediation:** Disable privileged mode unless building Docker images. If Docker-in-Docker is required, use a dedicated project with a narrowly scoped IAM role.

---

### CTL.CODEBUILD.PUBLIC.001

**CodeBuild Projects Must Not Be Publicly Accessible**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3; soc2: CC6.1;

CodeBuild project visibility must be PRIVATE. Projects with PUBLIC_READ visibility allow anyone to access build results, logs, and artifacts — exposing source code structure, dependency versions, deployment targets, and potentially secrets leaked in build output.

**Remediation:** Set project visibility to PRIVATE via aws codebuild update-project-visibility.

---

### CTL.CODEBUILD.ROLE.001

**CodeBuild Project Role Must Follow Least Privilege**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

CodeBuild project service roles must be scoped to the minimum permissions required for the build. Overprivileged build roles allow a compromised build to access resources beyond what the build needs — reading secrets, deploying to production, or modifying IAM policies.

**Remediation:** Scope the service role to the minimum permissions: source pull, artifact push, log write. Remove permissions for services the build does not interact with.

---

### CTL.CODEBUILD.SECRETS.001

**CodeBuild Projects Must Not Store Secrets in Plaintext Environment Variables**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: IA-5(7); pci_dss_v4.0: 3.4.1; soc2: CC6.1;

CodeBuild project environment variables of type PLAINTEXT must not contain secrets (API keys, tokens, passwords). Plaintext env vars are visible in the AWS console, CLI output, and CloudTrail logs. Use SECRETS_MANAGER or PARAMETER_STORE environment variable types instead.

**Remediation:** Change environment variable types from PLAINTEXT to SECRETS_MANAGER or PARAMETER_STORE. Store secrets in AWS Secrets Manager or SSM Parameter Store and reference them by name in the environment variable configuration.

---

### CTL.CODEBUILD.SOURCE.CREDS.001

**CodeBuild Source Repository URLs Must Not Embed Credentials**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: IA-5(7); soc2: CC6.1;

CodeBuild project source repository URLs must not contain embedded authentication tokens or username:password patterns. Embedded credentials in URLs are logged in CloudTrail, visible in the console, and persist in project configuration.

**Remediation:** Remove credentials from the URL. Use CodeBuild source credentials (OAuth, personal access token, or CodeConnections) configured separately from the repository URL.

---

### CTL.CODEBUILD.SOURCE.ORG.001

**CodeBuild GitHub Source Must Use Allowed Organizations**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SA-12; soc2: CC6.1;

CodeBuild projects sourcing from GitHub must reference repositories in approved organizations. Repos from untrusted organizations can let external contributors trigger builds that execute under the project's IAM role.

**Remediation:** Restrict source repositories to approved organizations. Configure an organization allowlist and validate source URLs against it.

---

### CTL.CODEBUILD.WEBHOOK.ANCHORED.001

**CodeBuild Webhook Filters Must Use Anchored Regex Patterns**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3; soc2: CC6.1;

CodeBuild webhook filters using ACTOR_ACCOUNT_ID, HEAD_REF, or BASE_REF must anchor regex patterns with ^ and $ for exact matching. Unanchored patterns allow substring bypass — an attacker creates a GitHub account whose ID contains the trusted value as a substring. This is the "CodeBreach" vulnerability disclosed by Wiz Research.

**Remediation:** Update all ACTOR_ACCOUNT_ID, HEAD_REF, and BASE_REF filter patterns to use ^ (start anchor) and $ (end anchor) for exact matching. Example: change "12345" to "^12345$".

---

### CTL.CODECOMMIT.ACCESS.001

**CodeCommit Repositories Must Have Restrictive Resource Policies**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-3; gdpr: Art.32; hipaa: 164.312(a)(1); nist_800_53_r5: AC-3; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

CodeCommit repositories must not allow overly broad access through wildcard principal resource policies or unrestricted IAM read permissions. Repositories contain source code, configuration files, infrastructure definitions, and frequently embedded secrets. MITRE ATT&CK T1213.003 documents code repository access as a collection technique — attackers use repository access to gather credentials and understand internal architecture before moving to higher-value targets. A compromised IAM role with broad CodeCommit read permissions can exfiltrate the entire codebase including hardcoded credentials, IaC files, and CI/CD pipeline configurations.

**Remediation:** Restrict repository resource policies to named principals. Scope IAM policies granting codecommit:GitPull and read actions to specific repository ARNs rather than Resource *. Enable CloudTrail data events for CodeCommit to audit repository access.

---

### CTL.CODECOMMIT.APPROVAL.001

**CodeCommit Repositories Must Have Branch Protection and Approval Rules**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SI-7; hipaa: 164.312(c)(1); iso_27001_2022: A.8.4; nist_800_53_r5: SI-7; pci_dss_v4.0: 6.3.2; soc2: CC8.1;

CodeCommit repositories must have approval rule templates configured on protected branches requiring at least one reviewer. Without branch protection, any principal with push permissions can commit directly to the main branch — bypassing code review, inserting malicious code into the deployment pipeline, and establishing persistence through the CI/CD chain. This is a supply chain persistence technique: the attacker uses the legitimate deployment pipeline to deliver their payload. Lambda code signing and ECR image signing enforce integrity at the artifact level; this control enforces integrity at the source level before the artifact is built.

**Remediation:** Create an approval rule template requiring at least one reviewer from a designated reviewer group. Apply the template to the default branch (main/master). Prevent force-push on the default branch. Use aws codecommit create-approval-rule-template to create the template and associate-approval-rule-template-with-repository to apply it.

---

### CTL.COGNITO.ADAPTIVE.AUTH.001

**Cognito Must Block Malicious Sign-In Attempts at All Risk Levels**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: IA-5; soc2: CC6.1;

Cognito user pools with advanced security must block risky sign-in attempts at low, medium, and high risk levels. Adaptive authentication detects anomalous sign-in patterns (new device, new location, impossible travel) and blocks them.

**Remediation:** Set adaptive authentication to BLOCK for low, medium, and high risk levels in the account-takeover risk configuration.

---

### CTL.COGNITO.ADVANCED.SECURITY.001

**Cognito User Pools Must Have Advanced Security Features Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** aws_security_hub: Cognito.2; mitre_attack: TA0006; nist_800_53_r5: SI-4;

Cognito Advanced Security Features detects and responds to compromised credentials, account takeover attempts, and unusual sign-in activity using adaptive authentication. It detects sign-ins from new devices, blocks credentials found in breach databases, and generates risk scores for authentication events. Without ASF, Cognito cannot detect credential stuffing using breached passwords.

**Remediation:** aws cognito-idp update-user-pool --user-pool-id <id> --user-pool-add-ons AdvancedSecurityMode=ENFORCED

---

### CTL.COGNITO.CLIENT.ENUMERATION.001

**Cognito App Clients Must Prevent User Existence Disclosure**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3; soc2: CC6.1;

Cognito app clients must enable PreventUserExistenceErrors to suppress user-existence disclosures. Without this, authentication error messages reveal whether a username exists, enabling account enumeration attacks.

**Remediation:** Set PreventUserExistenceErrors to ENABLED on the app client.

---

### CTL.COGNITO.CLIENT.TOKEN.REVOCATION.001

**Cognito App Clients Must Enable Token Revocation**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: IA-5; soc2: CC6.1;

Cognito app clients must enable token revocation so revoked refresh tokens and their derived access/ID tokens are immediately invalidated. Without revocation, compromised tokens remain valid until expiry.

**Remediation:** Set EnableTokenRevocation to true on the app client.

---

### CTL.COGNITO.COMPROMISED.CREDS.001

**Cognito Must Block Sign-In with Compromised Credentials**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: IA-5; soc2: CC6.1;

Cognito user pools with advanced security must block sign-in attempts using credentials detected in known breaches. Requires advanced security ENFORCED mode with compromised-credentials policy set to BLOCK on sign-in events.

**Remediation:** Enable advanced security in ENFORCED mode and set the compromised-credentials policy to BLOCK for sign-in events.

---

### CTL.COGNITO.DELETEPROT.001

**Cognito User Pools Must Have Deletion Protection Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: CP-10; soc2: A1.1;

Cognito user pools must have deletion protection set to ACTIVE. Without protection, accidental or malicious deletion destroys the user directory and all authentication state.

**Remediation:** Set deletion protection to ACTIVE on the user pool.

---

### CTL.COGNITO.IDENTITY.GUEST.001

**Cognito Identity Pools Must Not Allow Guest Access**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3; soc2: CC6.1;

Cognito identity pools must disable unauthenticated (guest) identities. When enabled, any client can obtain temporary AWS credentials without signing in. The unauthenticated IAM role's permissions become effectively public.

**Remediation:** Disable unauthenticated identities on the identity pool. If guest access is required, scope the unauthenticated role to minimal permissions.

---

### CTL.COGNITO.INCOMPLETE.001

**Complete Data Required for Cognito Assessment**

- **Severity:** info
- **Type:** unsafe_state
- **Domain:** identity

The observation snapshot is missing required Cognito user pool properties.

**Remediation:** Ensure the extractor calls aws cognito-idp describe-user-pool and maps MfaConfiguration to the identity observation properties.

---

### CTL.COGNITO.MFA.001

**Cognito User Pool Must Enforce MFA**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: IA-2(1); hipaa: 164.312(d); nist_800_53_r5: IA-2(1); pci_dss_v4.0: 8.3.1; soc2: CC6.1;

Cognito user pools handling PHI must enforce multi-factor authentication. Without MFA, a compromised password grants full access to the application and any PHI it serves.

**Remediation:** Set MfaConfiguration to ON (required) on the user pool. Run: aws cognito-idp set-user-pool-mfa-config --user-pool-id xxx --mfa-configuration ON --software-token-mfa-configuration Enabled=true

---

### CTL.COGNITO.MFA.ENFORCE.001

**Cognito User Pools Must Enforce MFA for All Users**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** aws_security_hub: Cognito.1; hipaa: 164.312(d); mitre_attack: TA0006; nist_800_53_r5: IA-2;

Cognito user pools without MFA enforcement are vulnerable to credential stuffing and brute force attacks. A user pool managing authentication for a customer-facing application without MFA means a single leaked password leads to full account compromise. MFA configuration ON requires all users to set up MFA.

**Remediation:** aws cognito-idp set-user-pool-mfa-config --user-pool-id <id> --software-token-mfa-configuration Enabled=true --mfa-configuration ON

---

### CTL.COGNITO.PASSWORD.001

**Cognito User Pools Must Enforce a Strong Password Policy**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: IA-5(1); hipaa: 164.312(d); nist_800_53_r5: IA-5(1); pci_dss_v4.0: 8.3.6; soc2: CC6.1;

Cognito user pools must enforce a minimum password length of 12 characters and require at least three of four character classes (uppercase, lowercase, numbers, special characters). Cognito password policy is independent of the IAM account password policy — a strong IAM policy does not protect application users authenticated through Cognito. A user pool with weak defaults allows end users to set trivially guessable passwords. Temporary password validity must not exceed 7 days — temporary passwords issued during account creation or password reset that remain valid for extended periods are a credential exposure risk if the invitation email is intercepted. For user pools handling PHI (patient portals, healthcare applications), weak application passwords are a direct credential compromise risk that IAM password controls cannot address.

**Remediation:** Update the user pool password policy via the Cognito console or UpdateUserPool API. Set minimum password length to 12 or higher. Require at least three of: uppercase, lowercase, numbers, special characters. Set temporary password validity to 7 days or less. Consider enabling Cognito advanced security features for compromised credential detection as a complementary control.

---

### CTL.COGNITO.PASSWORD.POLICY.001

**Cognito User Pools Must Enforce a Strong Password Policy**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** aws_security_hub: Cognito.3; mitre_attack: TA0006; nist_800_53_r5: IA-5;

Weak Cognito password policies enable brute force and dictionary attacks against user accounts. A minimum length of 12 characters with complexity requirements significantly increases the effort required for credential attacks. Temporary passwords with long validity windows allow attackers to reuse intercepted temporary passwords for extended periods.

**Remediation:** aws cognito-idp update-user-pool --user-pool-id <id> --policies PasswordPolicy='{MinimumLength=12, RequireUppercase=true,RequireLowercase=true, RequireNumbers=true,RequireSymbols=true, TemporaryPasswordValidityDays=3}'

---

### CTL.COGNITO.SELFREG.001

**Cognito User Pools Must Disable Unrestricted Self-Registration**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-2; soc2: CC6.1;

Cognito user pools should require administrator-created accounts (AllowAdminCreateUserOnly=true). Unrestricted self-registration lets anyone create an account and potentially access resources mapped through identity pools.

**Remediation:** Set AllowAdminCreateUserOnly to true in AdminCreateUserConfig.

---

### CTL.COGNITO.TEMPPASSWORD.001

**Cognito Temporary Passwords Must Expire Within 7 Days**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: IA-5;

Cognito user pool temporary password validity must not exceed 7 days. Long-lived temporary passwords increase the window for credential interception or misuse.

**Remediation:** Set TemporaryPasswordValidityDays to 7 or less.

---

### CTL.COGNITO.WAF.001

**Cognito User Pools Must Have WAF ACL Attached**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.6;

Cognito user pools must be associated with an AWS WAFv2 web ACL for rate limiting, bot protection, and IP filtering on the hosted UI and public API endpoints. Without WAF, the authentication endpoint is unprotected against credential stuffing and brute force attacks.

**Remediation:** Associate a WAFv2 web ACL with the user pool. Configure rate limiting and bot protection rules.

---

### CTL.CONFIG.ENABLED.001

**AWS Config Must Be Recording All Resource Types**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v1.4.0: 3.5; cis_aws_v3.0: 3.3; fedramp_moderate: CM-2; ffiec: CAT-D3; gdpr: Art.30; hipaa: 164.312(b); iso_27001_2022: A.8.9; nist_800_53_r5: CM-2; nist_csf_2.0: PR.PS; pci_dss_v4.0: 6.3.2; soc2: CC7.1;

AWS Config must be enabled and recording all supported resource types. Without Config, configuration changes are not tracked and drift from the desired security baseline cannot be detected.

**Remediation:** Enable the Config recorder with all resource types. Run: aws configservice put-configuration-recorder --configuration-recorder name=default,roleARN=arn:...,recordingGroup={allSupported=true}

---

### CTL.CONFIG.INCOMPLETE.001

**Complete Data Required for AWS Config Assessment**

- **Severity:** info
- **Type:** unsafe_state
- **Domain:** exposure

The observation snapshot is missing required AWS Config properties.

**Remediation:** Ensure the extractor calls aws configservice describe-configuration-recorders and aws configservice describe-config-rules.

---

### CTL.CONFIG.REMEDIATION.001

**Critical Config Rules Must Have Automatic Remediation**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-6; nist_800_53_r5: CM-6; pci_dss_v4.0: 6.3.2; soc2: CC7.1;

Safety mechanism integrity control. Checks that security guardrails are actively enforcing, not just present.

**Remediation:** Review the specific guardrail identified in this finding and restore it to an enforcing state.

---

### CTL.CONFIG.RULE.STATUS.001

**Config Rules Must Not Be in ERROR State**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-3; nist_800_53_r5: CM-3; soc2: CC7.1;

Safety mechanism integrity control. Checks that security guardrails are actively enforcing, not just present.

**Remediation:** Review the specific guardrail identified in this finding and restore it to an enforcing state.

---

### CTL.CONFIG.RULES.001

**AWS Config Must Have Active Rules**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: CM-3; hipaa: 164.312(c)(1); nist_800_53_r5: CM-3; pci_dss_v4.0: 6.3.2; soc2: CC6.3;

AWS Config must have active Config Rules to evaluate resource compliance. Recording without rules provides change history but no automated drift detection.

**Remediation:** Deploy Config Rules for your compliance requirements. Start with AWS managed rules for common checks (encrypted-volumes, restricted-common-ports, etc).

---

### CTL.CONFIG.SERVICEROLE.001

**AWS Config Must Use the Service-Linked Role**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: AC-6; soc2: CC6.1;

AWS Config recorders must use the AWS-managed service-linked role AWSServiceRoleForConfig rather than a custom IAM role. Custom roles may have excessive or insufficient permissions and are not automatically updated when Config adds support for new resources.

**Remediation:** Switch to the AWSServiceRoleForConfig service-linked role.

---

### CTL.DMS.LOG.SOURCE.001

**DMS Replication Tasks Must Enable Source Logging**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AU-2; soc2: CC7.1;

DMS replication tasks must enable source logging (SOURCE_CAPTURE and SOURCE_UNLOAD) for auditability of data extraction from source databases.

**Remediation:** Enable SOURCE_CAPTURE and SOURCE_UNLOAD logging.

---

### CTL.DMS.LOG.TARGET.001

**DMS Replication Tasks Must Enable Target Logging**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AU-2; soc2: CC7.1;

DMS replication tasks must enable target logging (TARGET_APPLY and TARGET_LOAD) for auditability of data loading to target databases.

**Remediation:** Enable TARGET_APPLY and TARGET_LOAD logging.

---

### CTL.DMS.MULTIAZ.001

**DMS Replication Instances Must Use Multi-AZ**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: CP-10; soc2: A1.1;

DMS replication instances must enable Multi-AZ for cross-AZ standby redundancy during database migration and ongoing replication.

**Remediation:** Enable Multi-AZ on the replication instance.

---

### CTL.DMS.PUBLIC.001

**DMS Replication Instances Must Not Be Publicly Accessible**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.6;

DMS replication instances must not be publicly accessible. Public instances expose the migration pipeline to internet attacks, allowing data interception during database replication.

**Remediation:** Set PubliclyAccessible to false on the replication instance.

---

### CTL.DMS.SSL.001

**DMS Endpoints Must Enforce SSL/TLS**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** nist_800_53_r5: SC-8; soc2: CC6.7;

DMS endpoints must use SSL/TLS (require, verify-ca, or verify-full) rather than none. Without SSL, data in transit between the replication instance and source/target databases is unencrypted.

**Remediation:** Set SslMode to require, verify-ca, or verify-full.

---

### CTL.DMS.UPGRADE.001

**DMS Replication Instances Must Enable Auto Minor Version Upgrade**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SI-2;

DMS replication instances must enable automatic minor version upgrades to receive security patches during maintenance windows.

**Remediation:** Enable auto_minor_version_upgrade.

---

### CTL.DNS.DANGLING.001

**DNS Records Must Not Point to Unclaimed Resources**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure

DNS records (CNAME, ALIAS, A) that reference external cloud resources must resolve to resources that exist and are owned by the organization. A dangling DNS record pointing to a deleted or unclaimed resource enables subdomain takeover — the attacker claims the resource and serves content under the organization's domain.

**Remediation:** Either claim the target resource in your cloud account to block takeover, or delete the DNS record that points to the unclaimed resource. Audit all DNS zones for records pointing to decommissioned infrastructure.

---

### CTL.DNS.DANGLING.002

**DNS Records to Cloud Storage Must Resolve to Owned Buckets**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure

DNS records that reference cloud storage endpoints (S3, GCS, Azure Blob) must resolve to buckets that exist and are owned by the organization. Storage bucket names are globally unique — a deleted bucket's name can be claimed by any account, enabling content injection under a trusted domain.

**Remediation:** Create the bucket in your cloud account to claim the name, or remove the DNS record. For software distribution URLs, update documentation to point to the current distribution endpoint.

---

### CTL.DNS.DANGLING.003

**DNS Records to Software Distribution Must Resolve to Owned Endpoints**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure

DNS records or URLs that reference software distribution endpoints (package repositories, binary downloads, update servers) must resolve to resources owned by the organization. Supply chain takeover through dangling distribution references delivers executable code to systems that trust the source.

**Remediation:** Claim the resource to block takeover. Update all documentation, install guides, and CI pipelines to reference the current distribution URL. Search community forums and cached tutorials for outdated references.

---

### CTL.DOCUMENTDB.BACKUP.001

**DocumentDB Automated Backups Must Be Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** resilience
- **Compliance:** nist_800_53_r5: CP-9; soc2: CC7.1;

DocumentDB clusters must have automated backups.

**Remediation:** Set backup retention period to at least 7 days.

---

### CTL.DOCUMENTDB.DELETEPROT.001

**DocumentDB Must Have Deletion Protection**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** resilience
- **Compliance:** nist_800_53_r5: CP-10; soc2: CC6.1;

DocumentDB clusters must have deletion protection enabled.

**Remediation:** Enable deletion protection.

---

### CTL.DOCUMENTDB.ENCRYPT.REST.001

**DocumentDB Clusters Must Have Encryption at Rest**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-28; pci_dss_v4.0: 3.4.1; soc2: CC6.7;

DocumentDB clusters must encrypt data at rest.

**Remediation:** Enable encryption. Requires creating a new encrypted cluster.

---

### CTL.DOCUMENTDB.LOG.AUDIT.001

**DocumentDB Must Export Logs to CloudWatch**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** nist_800_53_r5: AU-12; soc2: CC7.1;

DocumentDB clusters must export audit logs to CloudWatch.

**Remediation:** Enable CloudWatch log export.

---

### CTL.DOCUMENTDB.MULTIAZ.001

**DocumentDB Must Use Multi-AZ**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** resilience
- **Compliance:** nist_800_53_r5: CP-7; soc2: CC7.1;

DocumentDB clusters must deploy across multiple availability zones.

**Remediation:** Add read replicas in additional AZs.

---

### CTL.DOCUMENTDB.SNAPSHOT.PUBLIC.001

**DocumentDB Snapshots Must Not Be Public**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3; soc2: CC6.6;

DocumentDB snapshots must not be publicly accessible.

**Remediation:** Remove public access from the snapshot.

---

### CTL.DYNAMODB.BACKUP.001

**DynamoDB Tables Must Have Backup Plan**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** resilience
- **Compliance:** nist_800_53_r5: CP-9; soc2: CC7.1;

DynamoDB tables must be included in a backup plan.

**Remediation:** Add table to AWS Backup plan or enable PITR.

---

### CTL.DYNAMODB.ENCRYPT.001

**DynamoDB Must Use Customer-Managed KMS Encryption**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-28; gdpr: Art.32; hipaa: 164.312(a)(2)(iv); nist_800_53_r5: SC-28; pci_dss_v4.0: 3.4.1; soc2: CC6.7;

DynamoDB tables must use a customer-managed KMS key for encryption at rest. The default AWS-owned key does not support key revocation, audit of key usage, or cross-account key policies.

**Remediation:** Update the table encryption to use a customer-managed KMS key. Run: aws dynamodb update-table --table-name xxx --sse-specification Enabled=true,SSEType=KMS,KMSMasterKeyId=arn:...

---

### CTL.DYNAMODB.INCOMPLETE.001

**Complete Data Required for DynamoDB Assessment**

- **Severity:** info
- **Type:** unsafe_state
- **Domain:** exposure

The observation snapshot is missing required DynamoDB properties.

**Remediation:** Ensure the extractor calls aws dynamodb describe-table and maps the SSEDescription to the database.encryption observation properties.

---

### CTL.DYNAMODB.PITR.001

**Point-in-Time Recovery Must Be Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: CP-9; hipaa: 164.308(a)(7); nist_800_53_r5: CP-9; soc2: A1.1;

DynamoDB tables must have point-in-time recovery (PITR) enabled. Without PITR, accidental deletes, application bugs, or ransomware that corrupts table data cannot be recovered. PITR provides continuous backups with per-second granularity for the last 35 days.

**Remediation:** Enable PITR using aws dynamodb update-continuous-backups --table-name TABLE --point-in-time-recovery-specification PointInTimeRecoveryEnabled=true.

---

### CTL.DYNAMODB.VPC.ENDPOINT.001

**VPC Must Have DynamoDB Gateway Endpoint**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** network
- **Compliance:** nist_800_53_r5: SC-7;

VPCs accessing DynamoDB should have a gateway endpoint.

**Remediation:** Create a DynamoDB gateway endpoint.

---

### CTL.EC2.AMI.CURRENCY.001

**EC2 Instances Must Not Run Deprecated or End-of-Life AMIs**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SI-2; nist_800_53_r5: SI-2; pci_dss_v4.0: 6.3.3; soc2: CC7.1;

EC2 instances must not run on AMIs that are deprecated by AWS or the AMI owner, or that exceed the maximum AMI age threshold (default 180 days). Deprecated AMIs represent an OS-level version currency gap — the underlying operating system, kernel, and pre-installed packages are not receiving security patches. Unlike Lambda runtimes and RDS engine versions where AWS manages the execution environment, EC2 AMIs are operator-selected and operator-maintained. SSM Patch Manager patches running instances but does not update the underlying AMI — when instances are replaced through auto-scaling or redeployment, they launch from the same aged AMI with accumulated patches missing. The 180-day default threshold represents two quarterly patching cycles with buffer. Organizations can override per-instance via a stave/ami-max-age-days tag.

**Remediation:** Replace the instance with one launched from a current, non-deprecated AMI. For auto-scaling groups, update the launch template to reference a current AMI and perform a rolling replacement. For standalone instances, launch a replacement from a current AMI and migrate the workload. Establish an AMI refresh pipeline that builds updated AMIs on a regular cadence and deprecates old ones.

---

### CTL.EC2.AMI.GHOST.001

**Launch Templates Must Not Reference Deregistered AMIs**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: CP-2; soc2: A1.2;

EC2 launch templates must not reference AMIs that have been deregistered. Instance launches using the template fail. Auto Scaling groups using the template cannot scale out during incidents.

**Remediation:** Update the launch template to reference an available AMI.

---

### CTL.EC2.AMI.PUBLIC.001

**Custom AMIs Must Not Be Publicly Shared**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** aws_security_hub: EC2.25; mitre_attack: T1525; nist_800_53_r5: AC-3;

A publicly shared AMI exposes the complete disk contents of the base image — including installed software, configuration files, hard-coded credentials, and application code. Custom AMIs frequently contain SSH authorized_keys, internal PKI certificates, application source code, and secrets. Unlike EBS snapshots, public AMIs appear in AWS Marketplace searches and are trivially discoverable.

**Remediation:** Remove public sharing from the AMI: aws ec2 modify-image-attribute --image-id <ami-id> --launch-permission '{"Remove":[{"Group":"all"}]}'. Audit all custom AMIs: aws ec2 describe-images --owners self --filters Name=is-public,Values=true

---

### CTL.EC2.ASG.HEALTHCHECK.001

**EC2 Auto Scaling Groups Must Use ELB Health Checks**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** resilience
- **Compliance:** aws_security_hub: AutoScaling.1; mitre_attack: TA0040; nist_800_53_r5: CP-7;

Auto Scaling Groups with EC2 health checks only replace instances when the underlying EC2 instance fails — they do not detect unhealthy application state. ELB health checks detect when an instance is running but serving errors, allowing ASG to replace unhealthy instances automatically. Without ELB health checks, a compromised or malfunctioning instance can remain in the ASG.

**Remediation:** aws autoscaling update-auto-scaling-group --auto-scaling-group-name <n> --health-check-type ELB --health-check-grace-period 300

---

### CTL.EC2.DEFAULT.VPC.001

**EC2 Instances Must Not Run in the Default VPC**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws: 4.9; nist_800_53_r5: SC-7;

EC2 instances must not be deployed in the default VPC. The default VPC has a flat network topology with no segmentation, making lateral movement trivial after a single instance compromise.

**Remediation:** Migrate the instance to a purpose-built VPC with proper subnet segmentation. Delete the default VPC from regions where it is not needed.

---

### CTL.EC2.DETAILED.MONITORING.001

**Production EC2 Instances Must Have Detailed Monitoring Enabled**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** aws_security_hub: EC2.7; nist_800_53_r5: AU-12;

Basic EC2 monitoring provides metrics at 5-minute intervals. Detailed monitoring provides 1-minute intervals — critical for detecting short-duration attacks (CPU spike from crypto-mining, burst network traffic during exfiltration). Without detailed monitoring, an attacker can exfiltrate data in a short burst that is averaged away in 5-minute metrics.

**Remediation:** Enable detailed monitoring: aws ec2 monitor-instances --instance-ids <id>

---

### CTL.EC2.EBS.DEFAULT.001

**EBS Default Encryption Must Be Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws: 2.2.1; nist_800_53_r5: SC-28;

EBS default encryption must be enabled at the account level to ensure all new EBS volumes are automatically encrypted. Without it, volumes created by auto-scaling or manual launches may be unencrypted.

**Remediation:** aws ec2 enable-ebs-encryption-by-default --region <region> Enable in all regions where EC2 workloads run.

---

### CTL.EC2.EBS.ENCRYPT.001

**EBS Volumes Must Be Encrypted**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v1.4.0: 2.2.1; cis_aws_v3.0: 2.2.1; fedramp_moderate: SC-28; ffiec: ISH-4; gdpr: Art.32; hipaa: 164.312(a)(2)(iv); iso_27001_2022: A.8.24; nist_800_53_r5: SC-28; nist_csf_2.0: PR.DS; pci_dss_v4.0: 3.4.1; soc2: CC6.7;

EBS volumes attached to EC2 instances must have encryption enabled. Unencrypted volumes storing PHI or sensitive data violate encryption at rest requirements.

**Remediation:** Enable EBS encryption by default for the account. For existing volumes, create an encrypted snapshot and restore to a new encrypted volume. Run: aws ec2 enable-ebs-encryption-by-default

---

### CTL.EC2.EBS.SNAPSHOT.ENCRYPT.001

**EBS Snapshots Must Be Encrypted**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** aws_security_hub: EC2.32; mitre_attack: TA0010; nist_800_53_r5: SC-28;

Unencrypted EBS snapshots expose full disk contents if shared or made public. Even in a private state, unencrypted snapshots can be copied to another account. Encrypted EBS snapshots require access to the KMS key to restore — snapshots shared across accounts cannot be used without the source account sharing the KMS key.

**Remediation:** Copy the snapshot with encryption enabled: aws ec2 copy-snapshot --source-snapshot-id <id> --source-region <region> --encrypted --kms-key-id <key-arn>. Enable encryption by default: aws ec2 enable-ebs-encryption-by-default

---

### CTL.EC2.EIP.UNASSIGNED.001

**Elastic IPs Must Be Associated with Resources**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance

Unassigned Elastic IP addresses incur cost and represent unused public IP allocations that should be released.

**Remediation:** Associate the EIP with an instance or release it.

---

### CTL.EC2.IAMROLE.001

**EC2 Instances Must Use IAM Instance Roles**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v3.0: 1.18; soc2: CC6.8;

EC2 instances that access AWS services must use IAM instance profiles (roles) instead of embedded access keys. Instance roles provide temporary credentials that are automatically rotated.

**Remediation:** Create an IAM role and attach it to the instance: aws ec2 associate-iam-instance-profile --iam-instance-profile Name=<role> --instance-id <id>

---

### CTL.EC2.IMDSV2.001

**EC2 Instances Must Require IMDSv2**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v1.4.0: 5.6; cis_aws_v3.0: 5.6; fedramp_moderate: CM-6; nist_800_53_r5: CM-6; pci_dss_v4.0: 2.2.1; soc2: CC6.6;

EC2 instances must enforce Instance Metadata Service Version 2 (IMDSv2). IMDSv1 is vulnerable to SSRF attacks that can steal instance credentials from the metadata endpoint.

**Remediation:** Set HttpTokens to required on the instance metadata options. Run: aws ec2 modify-instance-metadata-options --instance-id i-xxx --http-tokens required --http-endpoint enabled

---

### CTL.EC2.IMDSV2.002

**EC2 Container Hosts Must Not Permit IMDSv2 Bypass**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v1.4.0: 5.6; cis_aws_v3.0: 5.6; fedramp_moderate: CM-6; nist_800_53_r5: CM-6; pci_dss_v4.0: 2.2.1; soc2: CC6.6;

EC2 instances running containerized workloads must not expose the instance metadata service to containers. IMDSv2's HttpTokens=required requirement is defeated from inside a container because the container can complete the IMDSv2 PUT-for-token handshake just like the host. AWS provides two closures: HttpPutResponseHopLimit=1 (rejects requests from bridge-networked containers, which add a hop) and avoiding host-network containers (which share the host's network namespace and bypass the hop limit entirely). This control fires when IMDSv2 is enforced on the instance (so CTL.EC2.IMDSV2.001 is silent) but the compound is still bypassable: containers are present AND either the hop limit is > 1 with bridge-networked containers, or any container uses host networking. Pentest practice confirms this as the realistic exposure posture for EKS, ECS, and Docker-on-EC2 workloads — basic IMDSv2 enforcement alone is theater on containerized hosts.

**Remediation:** Set HttpPutResponseHopLimit to 1 on the instance metadata options and audit every container workload for host-network usage. Run: aws ec2 modify-instance-metadata-options --instance-id i-xxx --http-put-response-hop-limit 1 --http-tokens required --http-endpoint enabled. For EKS, pin hop limit via the launch template's metadata_options block. For ECS, prefer awsvpc network mode over host. For Docker, move workloads off --network=host.

---

### CTL.EC2.INCOMPLETE.001

**Complete Data Required for EC2 Assessment**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure

EC2 instance safety cannot be assessed when encryption status is missing from the snapshot. The extractor must populate compute.encryption.ebs_encrypted.

**Remediation:** Re-run the extractor with EC2 permissions: ec2:DescribeInstances, ec2:DescribeVolumes, ec2:DescribeSnapshots.

---

### CTL.EC2.INSTANCE.AGE.001

**EC2 Instances Must Not Exceed Maximum Age**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SI-2; soc2: CC7.1;

EC2 instances running longer than the maximum age threshold (default 180 days) accumulate unpatched vulnerabilities and configuration drift.

**Remediation:** Replace with a new instance launched from a current AMI.

---

### CTL.EC2.INSTANCE.PROFILE.001

**EC2 Instances Must Use Instance Profiles Instead of Access Keys**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** aws_security_hub: EC2.29; cis_aws_v3.0: 1.18; nist_800_53_r5: IA-5;

EC2 instances that need AWS API access should use IAM instance profiles (role-based, temporary, automatically rotated credentials) rather than embedding long-term access keys. Long-term access keys stored on EC2 instances are frequently discovered via metadata SSRF, file system access after compromise, or accidental git commits. Instance profile credentials auto-rotate every hour via the metadata service.

**Remediation:** Attach an IAM instance profile with minimum required permissions: aws ec2 associate-iam-instance-profile --instance-id <id> --iam-instance-profile Name=<profile-name>. Remove any hard-coded access keys from the instance.

---

### CTL.EC2.LAUNCH.TEMPLATE.001

**EC2 Auto Scaling Groups Must Use Launch Templates**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** aws_security_hub: AutoScaling.9; mitre_attack: TA0003; nist_800_53_r5: CM-6;

Launch configurations are a legacy mechanism superseded by launch templates. Launch templates support IMDSv2 enforcement, instance metadata tags, Nitro Enclave support, EBS volume encryption by default, and multiple instance types per ASG. AWS has deprecated launch configurations. New ASG features and security improvements are only available via launch templates.

**Remediation:** Create a launch template from the existing launch configuration, then update the ASG: aws autoscaling update-auto-scaling-group --auto-scaling-group-name <n> --launch-template LaunchTemplateId=<id>,Version='$Latest'

---

### CTL.EC2.NETWORK.DIRECT.001

**Public Instances Must Be Behind a Load Balancer**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** network
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.6;

EC2 instances with public IPs receiving internet traffic must be behind an ALB or NLB. Direct internet-to-instance traffic bypasses DDoS absorption, WAF evaluation, connection rate limiting, and TLS termination that load balancers provide.

**Remediation:** Place the instance behind an ALB or NLB. Remove the public IP and route inbound traffic through the load balancer. Use private subnets for the instance.

---

### CTL.EC2.NITRO.ENCLAVE.001

**Sensitive Workloads Must Use Nitro Enclaves for Cryptographic Isolation**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** mitre_attack: TA0006; nist_800_53_r5: SC-28;

Nitro Enclaves provide an isolated execution environment with no persistent storage, no interactive access, and no external networking. Cryptographic operations performed inside an enclave are protected even if the parent instance is compromised. Applies only to instances tagged requires-enclave=true.

**Remediation:** aws ec2 modify-instance-attribute --instance-id <id> --enclave-options Enabled=true. Requires an enclave-capable instance type (m5, c5, r5 or newer).

---

### CTL.EC2.PROFILE.OVERBROAD.001

**EC2 Instance Profile Must Follow Least Privilege**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v3.0: 1.18; nist_800_53_r5: AC-6; soc2: CC6.1;

EC2 instance profiles must not have AdministratorAccess or overly broad permissions. Instance profile credentials are accessible via the metadata service — overprivileged profiles increase the blast radius of credential theft.

**Remediation:** Replace the instance profile's role with a scoped policy granting only the permissions the workload needs. Use IAM Access Analyzer to generate a least-privilege policy from observed API activity.

---

### CTL.EC2.PROFILE.SHARED.001

**EC2 Instances Must Use Per-Instance Instance Profiles**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

Each EC2 instance should use a dedicated instance profile not shared with other instances. Shared instance profiles grant every instance using the profile the union of all instances' required permissions, expanding blast radius. A compromise of one instance gives the attacker credentials for every other instance sharing the same profile. ECS (CTL.ECS.TASKROLE.SHARED.001) and Lambda (CTL.LAMBDA.ROLE.SHARED.001) enforce the same principle.

**Remediation:** Create a dedicated IAM instance profile per instance (or per instance group with identical permission needs) scoped to only the permissions that specific workload requires.

---

### CTL.EC2.PUBLIC.001

**EC2 Instances Must Not Have Public IP Addresses**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v1.4.0: 5.1; fedramp_moderate: AC-3; gdpr: Art.32; hipaa: 164.312(e)(1); nist_800_53_r5: AC-3; pci_dss_v4.0: 1.3.4; soc2: CC6.6;

EC2 instances should not have public IP addresses unless explicitly required. Public IP assignment exposes the instance to direct internet access, bypassing network perimeter controls.

**Remediation:** Launch instances in private subnets without public IP assignment. Use NAT Gateway or VPC endpoints for outbound internet access. Use ALB or NLB for inbound traffic that requires internet access.

---

### CTL.EC2.SG.DEFAULT.RESTRICT.001

**Default Security Group Must Restrict All Inbound and Outbound Traffic**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** network
- **Compliance:** aws_security_hub: EC2.2; cis_aws_v3.0: 4.4; nist_800_53_r5: SC-7;

The default security group in every VPC allows all inbound traffic from other members of the same security group and all outbound traffic. Any EC2 instance launched without an explicit security group uses the default — inheriting this permissive posture. Restricting the default to no rules means accidental use results in a non-functional but safe instance.

**Remediation:** Remove all inbound and outbound rules from the default SG in every VPC. Get the default SG ID: aws ec2 describe-security-groups --filters Name=group-name,Values=default Name=vpc-id,Values=<vpc-id>. Revoke all ingress and egress rules.

---

### CTL.EC2.SG.DESCRIBE.RESTRICT.001

**ec2:Describe* Must Be Restricted to Administrative Roles**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** mitre_attack: T1580; nist_800_53_r5: AC-6;

ec2:Describe* permissions must be restricted to administrative roles. Unrestricted ec2:Describe* access exposes the full network topology including VPCs, subnets, security groups, route tables, and network interfaces. Attackers use this information to map the network architecture, identify reachable instances, and plan lateral movement paths.

**Remediation:** Restrict ec2:Describe* to administrative roles only. Replace wildcard ec2:Describe* with the specific describe actions needed by the workload. Apply resource-level conditions or tag-based access control to limit enumeration scope.

---

### CTL.EC2.SG.INGRESS.CIDR.001

**Security Group Inbound Rules Must Not Use Overly Broad CIDR Ranges**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** network
- **Compliance:** aws_security_hub: EC2.19; mitre_attack: TA0001; nist_800_53_r5: SC-7;

Security groups with 0.0.0.0/0 inbound rules on ports other than 80/443 expose internal services to the internet. This includes common misconfigurations like opening port 8080, 8443, or custom application ports. HTTP (80) and HTTPS (443) are excluded as legitimate internet-facing ports. All other ports exposed to 0.0.0.0/0 should use specific CIDR ranges.

**Remediation:** Replace 0.0.0.0/0 rules on non-HTTP/S ports with specific corporate IP ranges, security group references, or VPN gateway IPs.

---

### CTL.EC2.SG.RESTRICTED.PORTS.001

**Security Groups Must Not Allow Unrestricted Access on High-Risk Ports**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** network
- **Compliance:** aws_security_hub: EC2.14; cis_aws_v3.0: 4.1; mitre_attack: TA0001; nist_800_53_r5: SC-7;

Security groups must not allow unrestricted inbound access on high-risk ports: RDP (3389), Telnet (23), FTP (20/21), VNC (5900), database ports (3306/5432/1433/27017), Redis (6379), and Memcached (11211). Each of these has been the source of high-profile breaches when accidentally exposed to 0.0.0.0/0.

**Remediation:** Remove or restrict rules opening these ports to the internet. Replace 0.0.0.0/0 with specific CIDR ranges (VPN exit IPs, bastion host SG references, or corporate NAT IPs). For database ports, use security group references. For RDP/VNC, use Systems Manager Session Manager instead of direct port exposure.

---

### CTL.EC2.SG.UNUSED.001

**Unused Security Groups Must Be Removed**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** network
- **Compliance:** nist_800_53_r5: CM-7; soc2: CC6.1;

Security groups with no attached resources should be removed. Unused SGs with broad rules are latent risks — when accidentally attached, the broad rules take effect immediately.

**Remediation:** Delete the unused security group, or if retention is needed, remove all ingress and egress rules to eliminate latent risk.

---

### CTL.EC2.SNAPSHOT.CROSSACCOUNT.001

**EBS Snapshots Must Not Be Shared with External Accounts**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

EBS snapshots must not be shared with external AWS accounts unless the snapshot is encrypted and sharing is to a specific authorized account. Unencrypted cross-account snapshot sharing enables data exfiltration — an attacker with ec2:ModifySnapshotAttribute shares a snapshot to their account, then restores it in their environment. ATT&CK technique T1578.001 (Create Snapshot) uses this vector.

**Remediation:** Remove cross-account sharing from the snapshot. If sharing is required, ensure the snapshot is encrypted with a KMS key and share only with specific authorized account IDs.

---

### CTL.EC2.SNAPSHOT.ENCRYPT.001

**EBS Snapshots Must Be Encrypted**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v1.4.0: 2.2.1; fedramp_moderate: SC-28; gdpr: Art.32; hipaa: 164.312(a)(2)(iv); nist_800_53_r5: SC-28; pci_dss_v4.0: 3.4.1; soc2: CC6.7;

EBS snapshots must be encrypted. Unencrypted snapshots can be shared across accounts or made public, exposing data at rest.

**Remediation:** Copy the snapshot with encryption enabled. Delete the unencrypted snapshot. Enable EBS encryption by default for future snapshots.

---

### CTL.EC2.SNAPSHOT.PUBLIC.001

**EBS Snapshots Must Not Be Publicly Restorable**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** aws_security_hub: EC2.32; mitre_attack: T1537; nist_800_53_r5: AC-3;

A public EBS snapshot can be copied to any AWS account and mounted as a volume — exposing all data on the volume including OS files, application data, database files, and credentials stored on disk. Unlike S3, public snapshots do not require knowing a URL or bucket name — they appear in public snapshot searches.

**Remediation:** Remove public access from the snapshot: aws ec2 modify-snapshot-attribute --snapshot-id <id> --attribute createVolumePermission --operation-type remove --group-names all. Use an SCP to prevent future public snapshots.

---

### CTL.EC2.SSM.MANAGED.001

**EC2 Instances Must Be Managed by AWS Systems Manager**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: CM-7;

EC2 instances must be managed by SSM to enable patching, session management, and compliance checking without SSH. Unmanaged instances require bastion hosts or open SSH ports.

**Remediation:** Attach AmazonSSMManagedInstanceCore IAM policy to the instance profile and ensure the SSM agent is installed.

---

### CTL.EC2.SSM.SESSION.LOGGING.001

**SSM Session Manager Must Log All Sessions to S3 or CloudWatch**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** mitre_attack: T1059.009; nist_800_53_r5: AU-12;

SSM Session Manager provides interactive shell access to EC2 instances without SSH keys or open inbound ports. Without session logging, all commands executed through Session Manager leave no audit trail. An attacker who gains ssm:StartSession access can execute arbitrary commands on managed instances without any record of the session content — only the session start/stop is logged in CloudTrail.

**Remediation:** Configure Session Manager preferences to log sessions to S3 or CloudWatch Logs. Enable encryption for session logs. aws ssm update-document --name SSM-SessionManagerRunShell --content file://session-prefs.json --document-version '$LATEST'

---

### CTL.EC2.SUBNET.PUBLIC.IP.001

**Subnets Must Not Automatically Assign Public IP Addresses**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** network
- **Compliance:** aws_security_hub: EC2.15; mitre_attack: TA0001; nist_800_53_r5: SC-7;

Subnets configured to automatically assign public IP addresses make every instance launched into them directly internet-reachable. An operator who launches an instance without specifying a private IP gets an unexpected public IP — creating unintended internet exposure. Private subnets require explicit intent to assign a public IP.

**Remediation:** aws ec2 modify-subnet-attribute --subnet-id <id> --no-map-public-ip-on-launch

---

### CTL.EC2.TERMINATION.PROTECT.001

**Production EC2 Instances Must Have Termination Protection**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** mitre_attack: T1490; nist_800_53_r5: CP-10;

Production EC2 instances must have termination protection enabled to prevent accidental or malicious instance termination via API, console, or CLI.

**Remediation:** aws ec2 modify-instance-attribute --instance-id <id> --disable-api-termination

---

### CTL.EC2.USERDATA.CREDS.001

**EC2 Launch Configurations Must Not Embed Credentials in User Data**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** mitre_attack: T1552.005; nist_800_53_r5: IA-5;

EC2 user data scripts are executed at instance launch with root privileges. User data is stored in plaintext and is accessible via the metadata service to any process on the instance — including attacker code via SSRF. Credentials embedded in user data (AWS access keys, passwords, API tokens) are trivially extracted from the metadata service at /latest/user-data, CloudFormation template parameters, and EC2 instance configuration APIs. This pattern has been the root cause of multiple credential exposure incidents.

**Remediation:** Remove all credentials from user data scripts. Use IAM instance profiles for AWS API access. Use Secrets Manager or Parameter Store for other secrets, retrieved at runtime by the application.

---

### CTL.EC2.USERDATA.SECRETS.001

**EC2 User Data Must Not Contain Secrets or Credentials**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** mitre_attack: T1059.009; nist_800_53_r5: IA-5;

EC2 instance user data is stored in plaintext in the instance metadata and is visible to any process on the instance via the metadata endpoint. Secrets embedded in user data (API keys, database passwords, tokens) are exposed to any compromised process and persist in the instance metadata after launch. User data is also visible in the EC2 console and via ec2:DescribeInstanceAttribute API calls.

**Remediation:** Move secrets to AWS Secrets Manager or SSM Parameter Store (SecureString type). Retrieve secrets at runtime via IAM role credentials rather than embedding in user data scripts.

---

### CTL.EC2.VPC.ENDPOINT.ACCESS.001

**VPC Interface Endpoints Must Have Restrictive Endpoint Policies**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** network
- **Compliance:** mitre_attack: TA0010; nist_800_53_r5: AC-4;

VPC interface endpoints without custom policies use the default full-access policy — any principal in the VPC can use the endpoint to reach any resource in the target service. A custom endpoint policy restricts which principals and resources are accessible. For S3 endpoints, restricting access to specific buckets prevents data exfiltration to attacker-controlled buckets via the endpoint.

**Remediation:** Apply a restrictive endpoint policy: aws ec2 modify-vpc-endpoint --vpc-endpoint-id <id> --policy-document file://endpoint-policy.json

---

### CTL.ECR.INCOMPLETE.001

**Complete Data Required for ECR Assessment**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure

ECR repository safety cannot be proven when access control data is missing from the snapshot. The extractor must populate container_registry.access.public to evaluate exposure controls.

**Remediation:** Re-run the extractor with ECR permissions: ecr:DescribeRepositories, ecr:GetRepositoryPolicy.

---

### CTL.ECR.LIFECYCLE.001

**ECR Repositories Must Have a Lifecycle Policy**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: CM-7;

ECR repositories must have a lifecycle policy to expire untagged and old images. Without it, images with known CVEs remain pullable and deployable indefinitely.

**Remediation:** aws ecr put-lifecycle-policy --repository-name <name> --lifecycle-policy-text '<policy JSON>'

---

### CTL.ECR.POLICY.BROAD.001

**ECR Repository Policy Must Not Grant Broad Cross-Account Access**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

ECR repository policies must not grant ecr:GetDownloadUrlForLayer, ecr:BatchGetImage, or ecr:PutImage to external accounts without restricting to specific account IDs or aws:PrincipalOrgID. Broad cross-account access allows image theft (pull) or supply chain compromise (push) from any granted account.

**Remediation:** Restrict the repository policy to specific account IDs or add an aws:PrincipalOrgID condition. For push access, restrict to CI/CD pipeline roles only.

---

### CTL.ECR.PUBLIC.001

**ECR Repository Must Not Be Public**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-3; nist_800_53_r5: AC-3; soc2: CC6.1;

ECR repositories must not be publicly accessible. A public ECR repository allows anyone to pull container images, potentially exposing proprietary code, embedded credentials, internal architecture details, and software supply chain artifacts. Public repositories should use ECR Public Gallery only for intentionally open-source images.

**Remediation:** Set the repository policy to restrict access to specific IAM principals. If the repository was created as ECR Public, migrate images to a private ECR repository and update deployment configs.

---

### CTL.ECR.SCAN.001

**Image Scanning Must Be Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: RA-5; nist_800_53_r5: RA-5; soc2: CC7.1;

ECR repositories must have image scanning enabled (basic or enhanced). Without scanning, container images with known vulnerabilities are deployed to production undetected.

**Remediation:** Enable scan-on-push in the repository configuration. For enhanced scanning, enable Amazon Inspector ECR integration.

---

### CTL.ECR.SIGNING.001

**ECR Repositories Must Have Image Signing Verification Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SI-7; hipaa: 164.312(c)(1); nist_800_53_r5: SI-7; pci_dss_v4.0: 6.3.2; soc2: CC7.1;

ECR repositories must have container image signing verification configured in enforce mode. Image signing cryptographically verifies that container images were built by a trusted source and have not been tampered with. Without signing verification, any image pushed to the repository — including one from a compromised CI/CD pipeline or supply chain attack — can be deployed without proof of origin or integrity. AWS ECR supports signing through AWS Signer with Notation and Sigstore Cosign. Verification must be in enforce mode — audit mode detects unsigned images but still allows deployment, providing observability without protection. This mirrors the WAF COUNT vs BLOCK and Lambda code signing Warn vs Enforce distinction.

**Remediation:** Configure image signing using AWS Signer with Notation or Sigstore Cosign. Set the ECR registry policy or repository policy to enforce signature verification — unsigned or invalidly signed images must be rejected at pull time. For Kubernetes workloads, configure an admission controller (Kyverno, OPA Gatekeeper) to verify signatures. For ECS, configure the ECR registry signing policy in enforce mode.

---

### CTL.ECR.TAG.IMMUTABLE.001

**ECR Repositories Must Enforce Image Tag Immutability**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws: 5.4; nist_800_53_r5: SI-7;

ECR repositories must enforce image tag immutability to prevent supply chain attacks where a compromised pipeline overwrites a trusted image tag with malicious content.

**Remediation:** aws ecr put-image-tag-mutability --repository-name <name> --image-tag-mutability IMMUTABLE

---

### CTL.ECS.EXEC.001

**ECS Exec Must Be Disabled on Production Services**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-17; hipaa: 164.312(a)(1); nist_800_53_r5: AC-17; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

ECS services in production environments must not have enableExecuteCommand: true. ECS Exec provides interactive shell access to running containers — an always-available persistence and lateral movement primitive for any IAM principal with ecs:ExecuteCommand permission. Intended for debugging, it creates a direct access path to production container runtime, filesystem, secrets, and execution role credentials.

**Remediation:** Disable ECS Exec on production services via aws ecs update-service --enable-execute-command false.

---

### CTL.ECS.EXEC.AUDIT.001

**ECS Exec Must Have Audit Logging Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AU-2; soc2: CC7.1;

When ECS Exec is enabled, audit logging must be configured to capture all Exec sessions. ECS Exec provides interactive shell access to running containers, including access to the task metadata credential endpoint. Without audit logging, an operator or attacker using Exec leaves no trace of commands executed or credentials accessed.

**Remediation:** Configure ECS Exec audit logging to CloudWatch Logs or S3. Enable session logging in the cluster Execute Command configuration.

---

### CTL.ECS.EXEC.RESTRICT.001

**ECS Exec Must Be Disabled on Production Services**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** mitre_attack: T1059; nist_800_53_r5: AC-3;

ECS Exec allows running interactive shell commands in running ECS containers via aws ecs execute-command. When enabled, any principal with ecs:ExecuteCommand permission can run arbitrary commands in production containers — equivalent to SSH access. ECS Exec has legitimate debugging use in development, but in production it represents an unnecessary execution vector. Attackers with IAM access can use it to establish persistence, exfiltrate data, or pivot to other services accessible from the container's network.

**Remediation:** Disable ECS Exec on production services: aws ecs update-service --cluster <cluster> --service <service> --no-enable-execute-command --force-new-deployment. Restrict ecs:ExecuteCommand via IAM policy to break-glass roles with MFA enforcement.

---

### CTL.ECS.EXECROLE.OVERBROAD.001

**ECS Execution Role Must Not Have Admin or Overly Broad Permissions**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6(5); pci_dss_v4.0: 7.2.1; soc2: CC6.1;

The ECS execution role (used by the ECS agent for image pulls, log writes, and secret retrieval) must not have AdministratorAccess or overly broad policies. The execution role is distinct from the task role — it operates at the infrastructure level, not the application level.

**Remediation:** Replace with a scoped execution role using the AmazonECSTaskExecutionRolePolicy managed policy. Add only the specific ECR, CloudWatch Logs, and Secrets Manager permissions the task requires.

---

### CTL.ECS.FARGATE.VERSION.001

**ECS Fargate Tasks Must Use Latest Platform Version**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SI-2;

ECS Fargate tasks must use the latest platform version. Fargate platform versions determine the runtime environment including the kernel version, container runtime, and networking stack. Older platform versions do not receive security patches — AWS applies fixes only to the latest platform version. A task pinned to an older platform version runs on an environment with known unpatched kernel and runtime vulnerabilities. Unlike EC2 where operators can patch independently, Fargate platform versions are AWS-managed and the only remediation is upgrading to the latest version. Tasks using LATEST resolve to the current platform version automatically but tasks pinned to specific versions accumulate security debt silently.

**Remediation:** Update the task definition to use the latest Fargate platform version. Set the platform version to LATEST in the ECS service or task definition. For services, update the service to force a new deployment with the latest platform version. Verify workload compatibility with the new platform version in a staging environment before updating production services.

---

### CTL.ECS.IMAGE.001

**ECS Container Images Must Not Use the latest Tag**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SI-7; nist_800_53_r5: SI-7; pci_dss_v4.0: 6.3.2; soc2: CC8.1;

ECS container images must use specific tags or digest references, not the latest tag. The latest tag is mutable — a compromised pipeline can push a malicious image that automatically deploys on next task restart. Pinned tags or digests provide immutable references for forensic reproducibility.

**Remediation:** Pin container images to specific version tags or use digest references (@sha256:...) for immutability.

---

### CTL.ECS.IMAGE.DIGEST.001

**ECS Container Images Must Be Referenced by Digest**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SI-7; soc2: CC6.1;

ECS task definitions must reference container images by digest (repo@sha256:...) instead of mutable tags (repo:v1.2). Tags are mutable — the same tag can point to different images over time. Digest pinning ensures the exact image deployed is the one that was tested and approved.

**Remediation:** Replace the tag reference with a digest reference. Example: 123456789012.dkr.ecr.us-east-1.amazonaws.com/app@sha256:abc123... Update CI/CD pipelines to output digest references after image push.

---

### CTL.ECS.IMAGE.GHOST.001

**ECS Task Definitions Must Not Reference Deleted Container Images**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SI-7; pci_dss_v4.0: 6.3.2; soc2: CC6.1;

ECS task definitions must not reference container images that don't exist in the ECR inventory. A deleted image with a tag-based reference is reclaimable — an attacker who pushes an image with the matching tag controls what code runs in the container with the task role's full IAM permissions.

**Remediation:** Update the task definition to reference an existing image. Use digest-pinned references for immutable images.

---

### CTL.ECS.IMAGE.UNTRUSTED.001

**ECS Task Definitions Must Reference Images from Trusted Registries**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SI-7; pci_dss_v4.0: 6.3.2; soc2: CC6.1;

ECS task definitions must reference container images from the organization's trusted registry set (typically the account's own ECR or a curated approved list). Images from Docker Hub, third- party registries, or unknown sources may contain vulnerabilities, backdoors, or cryptocurrency miners.

**Remediation:** Mirror the required image into the organization's ECR and reference the ECR copy in the task definition. Enable image scanning on the ECR repository to detect vulnerabilities in mirrored images.

---

### CTL.ECS.INCOMPLETE.001

**Complete Data Required for ECS Assessment**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure

ECS task definition or service configuration is missing required properties for security assessment. Re-run the extractor with ecs:DescribeTaskDefinition, ecs:DescribeServices, ecs:ListTaskDefinitions, and ecs:ListServices permissions.

**Remediation:** Re-run extractor with full ECS permissions.

---

### CTL.ECS.LOG.001

**ECS Task Definitions Must Have CloudWatch Logging Configured**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AU-2; hipaa: 164.312(b); nist_800_53_r5: AU-2; pci_dss_v4.0: 10.2.1; soc2: CC7.1;

ECS essential containers must have a log driver configured. Without logging, container stdout and stderr are discarded — invocations, errors, and execution output leave no audit trail. A compromised container generating no logs is forensically invisible.

**Remediation:** Configure the awslogs log driver for all essential containers in the task definition.

---

### CTL.ECS.METADATA.CREDENTIAL.001

**ECS Tasks Must Restrict Credential Endpoint Access to Required Containers**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-6(5); hipaa: 164.312(a)(1); nist_800_53_r5: AC-6(5); pci_dss_v4.0: 7.2.1; soc2: CC6.1;

ECS task definitions must restrict task metadata credential endpoint access (169.254.170.2) to only the containers that require AWS API access. Sidecar containers, init containers, and utility containers that do not call AWS APIs should not have credential endpoint access. Without scoping, every container in the task — including those vulnerable to SSRF — can retrieve the task role's IAM credentials from the metadata endpoint. This is the same attack class as EC2 IMDSv1 credential theft (Capital One) but on containers. Unlike EC2 IMDS which has IMDSv2 token requirements, ECS task metadata has no equivalent token mechanism — the mitigation is restricting which containers can reach the endpoint.

**Remediation:** Configure container-level credential scoping in the task definition. Set credentialSpecs or use task role credential isolation to restrict which containers can access the credential endpoint. Sidecar and utility containers that do not require AWS API access should not have credential endpoint access.

---

### CTL.ECS.NETWORK.001

**ECS Task Definitions Must Not Use Host Network Mode**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-7; hipaa: 164.312(e)(1); nist_800_53_r5: SC-7; pci_dss_v4.0: 1.3.2; soc2: CC6.6;

ECS task definitions must not use host network mode. Host networking removes network isolation between the container and the EC2 host — the container shares the host network namespace, can bind to any host port, and can access services on localhost including the ECS agent and metadata endpoint. Use awsvpc mode for per-task network isolation.

**Remediation:** Switch to awsvpc network mode for per-task ENI with dedicated security group.

---

### CTL.ECS.NETWORK.PUBLIC.001

**ECS Tasks Must Not Run in Public Subnets with Public IPs**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** network
- **Compliance:** nist_800_53_r5: SC-7; pci_dss_v4.0: 1.3.4; soc2: CC6.6;

ECS tasks must not be placed in public subnets with public IP assignment. Public subnet placement makes the container directly reachable from the internet without traversing a load balancer.

**Remediation:** Move the task to a private subnet. Use an ALB or API Gateway for inbound traffic and a NAT gateway for outbound.

---

### CTL.ECS.PRIV.001

**ECS Containers Must Not Run in Privileged Mode**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: CM-7; hipaa: 164.312(a)(1); nist_800_53_r5: CM-7; pci_dss_v4.0: 2.2.1; soc2: CC6.6;

ECS container definitions must not enable privileged mode. A privileged container has full host device access and kernel capabilities — effectively root on the underlying host. Container escape gives access to EC2 instance role, host networking, and all other containers.

**Remediation:** Remove privileged: true from container definitions. If host device access is required, use specific Linux capabilities instead.

---

### CTL.ECS.ROOT.001

**ECS Containers Must Not Run as Root User**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: CM-7; nist_800_53_r5: CM-7; pci_dss_v4.0: 2.2.1; soc2: CC6.6;

ECS containers must set the user field to a non-root UID. An empty user field means the container runs as whatever user the image defines — frequently root. Running as root inside a container means a process breakout gives root access to the host.

**Remediation:** Set the user field to a non-root UID in the container definition. Build images with a non-root USER directive.

---

### CTL.ECS.SECRET.GHOST.001

**ECS Task Definitions Must Not Reference Deleted Secrets**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.312(d); nist_800_53_r5: IA-5; soc2: CC6.1;

ECS task definitions must not inject secrets from Secrets Manager that have been deleted. A missing secret causes either container startup failure or silent fallback to insecure defaults — hardcoded credentials, unauthenticated connections, or disabled TLS.

**Remediation:** Recreate the secret or update the task definition to reference an active secret.

---

### CTL.ECS.SECRETS.001

**ECS Task Definitions Must Not Pass Secrets as Plaintext Environment Variables**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: IA-5; hipaa: 164.312(a)(2)(iv); nist_800_53_r5: IA-5; pci_dss_v4.0: 3.4.1; soc2: CC6.1;

ECS container definitions must not pass credentials as plaintext environment variables. Plaintext env vars are stored in the task definition, visible in the ECS console, logged in CloudTrail, and accessible to any process in the container. Use Secrets Manager or SSM Parameter Store references via the secrets field instead.

**Remediation:** Move secrets to Secrets Manager or SSM Parameter Store. Reference them via the secrets field in the container definition.

---

### CTL.ECS.SECURITY.CAPABILITIES.001

**ECS Containers Must Not Have Dangerous Linux Capabilities**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: CM-7; soc2: CC6.1;

ECS task definitions must not add dangerous Linux capabilities (SYS_ADMIN, NET_ADMIN, SYS_PTRACE, SYS_RAWIO, DAC_OVERRIDE, NET_RAW) and should drop all unnecessary capabilities. Dangerous capabilities grant kernel-level access enabling container escape.

**Remediation:** Remove added capabilities from the task definition. Use linuxParameters.capabilities.drop = ["ALL"] and only add the specific capabilities the application requires.

---

### CTL.ECS.TASK.NOEXEC.001

**ECS Task Definitions Must Not Use Privileged Mode with Host Network**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** mitre_attack: T1610; nist_800_53_r5: AC-6;

ECS task definitions with both privileged mode and host networking allow container escape to the host instance with full network access. A compromised container with these settings can access the instance metadata service, other containers' network traffic, and the host filesystem — providing arbitrary code execution on the host. This combination is equivalent to running untrusted code directly on the EC2 instance.

**Remediation:** Remove privileged mode from the container definition. Use awsvpc network mode instead of host mode. If root capabilities are required, use specific Linux capabilities instead of full privileged mode.

---

### CTL.ECS.TASKMETADATA.001

**ECS Task Role Must Follow Least Privilege**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-6; hipaa: 164.312(a)(1); nist_800_53_r5: AC-6; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

ECS task definitions must not have over-privileged task IAM roles. The task metadata endpoint (TMDEv4) exposes the task role credentials to every container in the task via a link-local HTTP endpoint with no session-based protection. An SSRF vulnerability in any container can retrieve valid short-lived AWS credentials in a single HTTP request. The blast radius of a credential theft is defined entirely by the task role's permissions — wildcard actions or wildcard resources on data-plane services (S3, DynamoDB, RDS, Secrets Manager, KMS) make the credential theft equivalent to account-wide lateral movement. This is the container equivalent of the EC2 IMDS vulnerability that CTL.EC2.IMDSV2.001 addresses, but structurally more exposed because the ECS metadata endpoint has no IMDSv2-style session token protection.

**Remediation:** Scope the task role to only the specific actions and resource ARNs the task requires. Replace managed policies like AmazonS3FullAccess with inline policies scoped to specific resources. Use IAM Access Analyzer to generate a least-privilege policy from actual task activity. If the task does not need AWS API access, remove the task role entirely.

---

### CTL.ECS.TASKMETADATA.002

**PHI ECS Tasks Must Have Scoped Task Roles**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-6; hipaa: 164.312(a)(1); nist_800_53_r5: AC-6; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

ECS task definitions tagged with data-classification phi or pii must have task roles scoped exclusively to the services required for the task's declared function. For PHI workloads, the task role defines the blast radius of any SSRF exploit — a task processing PHI with a role granting broad S3 access is one SSRF vulnerability away from a HIPAA breach. The task metadata endpoint exposes credentials to every container in the task with no session-based protection. Cross-service access beyond the PHI data path increases the regulatory exposure from a credential theft without providing functional value.

**Remediation:** Scope the task role to only the services in the PHI data path. Remove access to services the task does not require. For PHI tasks accessing S3, restrict to specific bucket ARNs. For tasks accessing DynamoDB, restrict to specific table ARNs. Ensure no wildcard resource ARNs exist on data-plane actions.

---

### CTL.ECS.TASKROLE.SHARED.001

**ECS Task Definitions Must Use Per-Service Task Roles**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

Each ECS task definition should have its own dedicated IAM task role. Shared task roles grant every service using the role the union of all services' permissions, expanding blast radius.

**Remediation:** Create a dedicated IAM role per task definition scoped to only the permissions that specific service needs.

---

### CTL.EFS.AP.POSIX.001

**EFS Access Points Must Enforce POSIX Identity**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-6;

EFS access points without a POSIX user identity allow clients to connect with any UID/GID, enabling privilege escalation across tenants sharing the file system. Every access point must enforce a fixed POSIX user to constrain file ownership and permissions.

**Remediation:** Update the access point to enforce a POSIX user. Run: aws efs create-access-point --file-system-id fs-xxx --posix-user Uid=1000,Gid=1000

---

### CTL.EFS.AP.ROOT.001

**EFS Access Points Must Not Expose Root Directory**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-6;

EFS access points with a root directory grant clients visibility into the entire file system tree. Each access point should scope access to a specific subdirectory to enforce least-privilege and prevent data exfiltration across application boundaries.

**Remediation:** Recreate the access point with a scoped root directory path. Run: aws efs create-access-point --file-system-id fs-xxx --root-directory Path=/app/data,CreationInfo={OwnerUid=1000,OwnerGid=1000,Permissions=755}

---

### CTL.EFS.BACKUP.001

**EFS File System Must Have Backup Policy Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.308(a)(7)(ii)(A); nist_800_53_r5: CP-9;

EFS file systems must have automatic backups enabled via AWS Backup. Without a backup policy, data loss from accidental deletion, ransomware, or corruption cannot be recovered, violating disaster recovery and business continuity requirements.

**Remediation:** Enable automatic backups for the EFS file system. Run: aws efs put-backup-policy --file-system-id fs-xxx --backup-policy Status=ENABLED

---

### CTL.EFS.ENCRYPT.001

**EFS File System Must Be Encrypted at Rest**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 2.4.1; fedramp_moderate: SC-28; gdpr: Art.32; hipaa: 164.312(a)(2)(iv); nist_800_53_r5: SC-28; pci_dss_v4.0: 3.5.1; soc2: CC6.1;

EFS file systems must have encryption at rest enabled. Data stored on unencrypted file systems is readable if the underlying storage is compromised. EFS encryption uses AWS KMS and must be enabled at creation time — it cannot be enabled on existing file systems.

**Remediation:** Create a new encrypted EFS file system and migrate data. Encryption cannot be enabled on existing file systems. Run: aws efs create-file-system --encrypted --kms-key-id alias/aws/elasticfilesystem

---

### CTL.EFS.ENCRYPT.TRANSIT.001

**EFS File System Must Enforce Encryption in Transit**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 2.4.1; fedramp_moderate: SC-8; hipaa: 164.312(e)(1); nist_800_53_r5: SC-8; pci_dss_v4.0: 4.2.1; soc2: CC6.1;

EFS file systems must enforce encryption in transit via a file system policy that denies unencrypted connections. Without this policy, NFS clients can mount the file system without TLS, exposing data to network-level interception.

**Remediation:** Apply a file system policy that denies unencrypted transport. Run: aws efs put-file-system-policy --file-system-id fs-xxx --policy '{"Statement":[{"Effect":"Deny","Principal":{"AWS":"*"}, "Action":"*","Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}'

---

### CTL.EFS.INCOMPLETE.001

**Complete Data Required for EFS Assessment**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure

EFS file system safety cannot be assessed when encryption status is missing from the snapshot. The extractor must populate filesystem.encryption.at_rest_enabled.

**Remediation:** Re-run the extractor with EFS permissions: elasticfilesystem:DescribeFileSystems, elasticfilesystem:DescribeFileSystemPolicy.

---

### CTL.EFS.KMS.CMK.001

**EFS File System Must Use Customer-Managed KMS Key**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.312(a)(2)(iv); nist_800_53_r5: SC-28; pci_dss_v4.0: 3.6.1;

EFS file systems encrypted with the AWS-managed key (aws/elasticfilesystem) cannot enforce key policies, rotation schedules, or cross-account access restrictions. A customer-managed KMS key is required for full control over the encryption lifecycle and to meet compliance frameworks that mandate key management separation.

**Remediation:** Create a new EFS file system with a customer-managed KMS key and migrate data. The KMS key type cannot be changed after creation. Run: aws efs create-file-system --encrypted --kms-key-id arn:aws:kms:REGION:ACCOUNT:key/KEY-ID

---

### CTL.EFS.LIFECYCLE.001

**EFS File System Should Have Lifecycle Policy Configured**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: CP-9;

EFS file systems should have a lifecycle policy that transitions infrequently accessed files to the Infrequent Access (IA) storage class. Without a lifecycle policy, all files remain in the Standard storage class regardless of access patterns, increasing storage costs and reducing operational resilience through budget inefficiency.

**Remediation:** Configure a lifecycle policy to transition infrequently accessed files. Run: aws efs put-lifecycle-configuration --file-system-id fs-xxx --lifecycle-policies TransitionToIA=AFTER_30_DAYS

---

### CTL.EFS.MT.SG.001

**EFS Mount Targets Must Have Security Groups Attached**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7;

EFS mount targets must have security groups attached to control network access. Mount targets without security groups accept connections from any source within the VPC, enabling unauthorized NFS access from compromised workloads.

**Remediation:** Attach a security group to the mount target that restricts NFS (port 2049) to authorized sources. Run: aws efs modify-mount-target-security-groups --mount-target-id fsmt-xxx --security-groups sg-xxx

---

### CTL.EFS.MULTIAZ.001

**EFS File System Must Use Multi-AZ Deployment**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: CP-10; soc2: A1.1;

EFS file systems must be Regional type (not One Zone) with mount targets in multiple Availability Zones. Single-AZ concentration means an AZ outage severs all client connectivity.

**Remediation:** Use Regional storage class and create mount targets in multiple AZs.

---

### CTL.EFS.POLICY.ANONYMOUS.001

**EFS File System Policy Must Prevent Anonymous Access**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3;

EFS file system policies must prevent anonymous (unauthenticated) access. Without this policy, any principal that can reach the mount target can access the file system without IAM authentication, enabling unauthorized data access from within the VPC.

**Remediation:** Apply a file system policy that prevents anonymous access. Run: aws efs put-file-system-policy --file-system-id fs-xxx --policy '{"Statement":[{"Effect":"Deny","Principal":{"AWS":"*"}, "Action":"*","Condition":{"Bool":{"elasticfilesystem:AccessedViaMountTarget":"true"}}, "Resource":"*"}]}'

---

### CTL.EFS.POLICY.DENYROOT.001

**EFS File System Policy Must Deny Root Access**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.312(a)(1); nist_800_53_r5: AC-6;

EFS file system policies must include a statement denying root access. Without this policy, NFS clients mounting the file system can operate as root (UID 0), bypassing POSIX permission boundaries and enabling full read/write access to all files.

**Remediation:** Apply a file system policy that denies root access. Run: aws efs put-file-system-policy --file-system-id fs-xxx --policy '{"Statement":[{"Effect":"Deny","Principal":{"AWS":"*"}, "Action":"elasticfilesystem:ClientRootAccess","Resource":"*"}]}'

---

### CTL.EFS.POLICY.TRANSIT.001

**EFS File System Policy Must Enforce In-Transit Encryption**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.312(e)(1); nist_800_53_r5: SC-8;

EFS file system policies must enforce encryption in transit by denying connections that do not use TLS. Without this policy, NFS clients can mount the file system over plaintext, exposing data to network-level interception and credential sniffing.

**Remediation:** Apply a file system policy that enforces in-transit encryption. Run: aws efs put-file-system-policy --file-system-id fs-xxx --policy '{"Statement":[{"Effect":"Deny","Principal":{"AWS":"*"}, "Action":"*","Condition":{"Bool":{"aws:SecureTransport":"false"}}, "Resource":"*"}]}'

---

### CTL.EKS.ADDON.VERSION.001

**EKS Managed Addons Must Use the Latest Compatible Version**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** aws_security_hub: EKS.7; mitre_attack: TA0003; nist_800_53_r5: SI-2;

EKS managed addons (VPC CNI, CoreDNS, kube-proxy, EBS CSI driver) contain the container runtime components that handle pod networking, DNS, and storage. Outdated addon versions may contain known CVEs exploitable for container escape or privilege escalation. The EKS VPC CNI stale NetworkPolicy IP reuse vulnerability demonstrates that addon bugs can silently bypass security controls. Staying current on addon versions is the only mitigation for addon-layer vulnerabilities.

**Remediation:** List available updates: aws eks describe-addon-versions --kubernetes-version <version>. Update each addon: aws eks update-addon --cluster-name <cluster> --addon-name <addon> --addon-version <latest> --resolve-conflicts OVERWRITE

---

### CTL.EKS.CLUSTER.VERSION.001

**EKS Cluster Kubernetes Version Must Be Within Support Window**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** aws_security_hub: EKS.6; mitre_attack: TA0003; nist_800_53_r5: SI-2;

AWS supports each EKS Kubernetes minor version for approximately 14 months. Clusters on end-of-life versions receive no security patches — known CVEs in the Kubernetes control plane remain unpatched indefinitely. Kubernetes releases security patches only for the current and two previous minor versions. A cluster more than 2 minor versions behind cannot receive patches for newly disclosed CVEs. EKS auto-upgrades unsupported versions — often causing unexpected breaking changes.

**Remediation:** Check current version: aws eks describe-cluster --name <cluster> --query 'cluster.version'. Upgrade: aws eks update-cluster-version --name <cluster> --kubernetes-version <target>. Then upgrade node groups.

---

### CTL.EKS.CONTROL.PLANE.AUDIT.001

**EKS Cluster Must Have Audit Logs Enabled and Delivered to CloudWatch**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** cis_eks: 2.1; mitre_attack: TA0005; nist_800_53_r5: AU-2;

EKS audit logs record all Kubernetes API server requests — who called which API, with what arguments, and the result. Without audit logs delivered to CloudWatch, there is no record of kubectl exec sessions, Secret reads and writes, RBAC policy modifications, or ServiceAccount token creations. This control verifies audit log delivery to CloudWatch — logs enabled but not delivered are useless for incident response.

**Remediation:** Enable audit logging: aws eks update-cluster-config --name <cluster> --logging '{"clusterLogging":[{"types":["audit"],"enabled":true}]}'. Verify the log group exists in CloudWatch.

---

### CTL.EKS.DELETEPROT.001

**EKS Clusters Must Have Deletion Protection Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: CP-10; soc2: A1.1;

EKS clusters must enable deletion protection to prevent accidental or unauthorized cluster removal. Without protection, automation errors or a compromised administrator can delete the cluster control plane, causing immediate availability loss, orphaned node groups, and data in etcd becoming permanently inaccessible.

**Remediation:** Enable deletion protection via aws eks update-cluster-config --name <cluster> --deletion-protection.

---

### CTL.EKS.ENDPOINT.PRIVATE.001

**EKS Clusters Must Enable Private Endpoint Access**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.6;

EKS clusters must enable private endpoint access so kubectl and API traffic can use a VPC-resolved private endpoint. Without private access, all control plane traffic traverses the public internet, expanding the attack surface and adding an internet dependency for cluster management.

**Remediation:** Enable private endpoint access via aws eks update-cluster-config --name <cluster> --resources-vpc-config endpointPrivateAccess=true.

---

### CTL.EKS.IRSA.ENFORCE.001

**EKS Clusters Must Have OIDC Provider for IRSA**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** aws_security_hub: EKS.9; mitre_attack: TA0006; nist_800_53_r5: AC-6;

Without IRSA (IAM Roles for Service Accounts), pods needing AWS API access must use the node's EC2 instance profile — granting all pods on the node the same IAM permissions. A compromised pod can use the node's credentials to access any AWS service the node role permits. IRSA binds IAM roles to Kubernetes service accounts via OIDC federation. Each pod gets only the permissions its service account requires. IRSA requires the EKS OIDC provider to be configured. This control verifies the OIDC provider exists.

**Remediation:** Associate an OIDC provider: eksctl utils associate-iam-oidc-provider --cluster <cluster> --approve. Then create service account-specific IAM roles.

---

### CTL.EKS.LOGGING.001

**EKS Control Plane Logging Must Be Enabled for All Log Types**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_eks: 2.1; fedramp_moderate: AU-12; hipaa: 164.312(b); nist_800_53_r5: AU-2;

EKS clusters must have all five control plane log types enabled (api, audit, authenticator, controllerManager, scheduler). Without full logging, an attacker who compromises the cluster can escalate privileges and exfiltrate data without any audit trail.

**Remediation:** Enable all five control plane log types via AWS CLI: aws eks update-cluster-config --name <cluster> --logging '{"clusterLogging":[{"types":["api","audit","authenticator", "controllerManager","scheduler"],"enabled":true}]}'

---

### CTL.EKS.NETPOL.ENFORCE.001

**EKS Clusters Must Have Network Policy Enforcement Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** network
- **Compliance:** mitre_attack: TA0008; nist_800_53_r5: AC-4;

Without network policy enforcement, all pods in an EKS cluster can communicate freely regardless of namespace or label. A compromised pod can reach any other pod, service, or node in the cluster on any port. NetworkPolicy objects exist but have no effect unless a network policy controller enforces them. The VPC CNI network policy controller (enableNetworkPolicy) enforces Kubernetes NetworkPolicy objects using eBPF rules.

**Remediation:** Enable network policy enforcement via VPC CNI: aws eks update-addon --cluster-name <cluster> --addon-name vpc-cni --configuration-values '{"enableNetworkPolicy": "true"}'. Then apply default-deny NetworkPolicy in each namespace.

---

### CTL.EKS.NODEGROUP.AMI.001

**EKS Node Groups Must Use Current AMIs**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SI-2;

EKS managed node groups must use current Amazon Machine Images. AWS publishes updated EKS-optimized AMIs that include kernel patches, container runtime updates, and kubelet security fixes. Node groups running outdated AMIs are missing security patches for the underlying operating system and Kubernetes node components. Unlike the EKS control plane which AWS manages, node group AMIs must be updated by the operator. Outdated node AMIs create a persistent attack surface at the node level — container escapes, kernel exploits, and privilege escalation vulnerabilities in the kubelet or containerd remain exploitable until the AMI is updated. The gap between the current AMI and the running AMI directly correlates with the number of unpatched CVEs on every node in the group.

**Remediation:** Update the node group to use the latest EKS-optimized AMI. For managed node groups, trigger an AMI update through the EKS console or AWS CLI using update-nodegroup-version. Use the rolling update strategy to replace nodes without downtime. Verify pod disruption budgets are configured to protect workload availability during the node rotation.

---

### CTL.EKS.NODEGROUP.SG.001

**EKS Node Groups Must Not Use the Cluster Default Security Group**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** network
- **Compliance:** mitre_attack: TA0008; nist_800_53_r5: SC-7;

EKS clusters create a default cluster security group that allows all traffic between nodes and the control plane. Node groups without dedicated security groups rely on this permissive default — all nodes can communicate with all other nodes on all ports. Dedicated node group security groups with minimal required rules reduce the blast radius of a compromised node.

**Remediation:** Create a dedicated security group for each node group with only required rules: port 10250 (kubelet) from control plane SG, port 443 to control plane SG, and application-specific ports. Assign via launch template.

---

### CTL.EKS.PUBLIC.ENDPOINT.001

**EKS Public API Endpoint Must Restrict Access with CIDR Allowlists**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_eks: 2.2; fedramp_moderate: SC-7; nist_800_53_r5: AC-17;

EKS clusters with public API endpoints must restrict access to specific CIDR ranges. An unrestricted public endpoint (0.0.0.0/0) allows any internet IP to reach the API server, enabling credential-based attacks from anywhere.

**Remediation:** Option 1 (preferred): Disable public endpoint entirely. Option 2: Restrict to specific CIDRs (corporate NAT, VPN, CI/CD). aws eks update-cluster-config --name <cluster> --resources-vpc-config endpointPublicAccess=true, publicAccessCidrs="10.0.0.0/8,203.0.113.0/24"

---

### CTL.EKS.RBAC.AUDIT.001

**EKS Cluster Must Not Grant cluster-admin to Service Accounts**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 5.1.1; nist_800_53_r5: AC-6;

EKS clusters must not bind the cluster-admin ClusterRole to service accounts. The cluster-admin role grants unrestricted access to every resource in every namespace. When a service account holds this binding, any pod running under that service account inherits full cluster control. An attacker who compromises a single workload can escalate to cluster-admin privileges by reading the mounted service account token. Legitimate automation rarely needs cluster-wide admin access — most controllers operate within a bounded set of API groups. A cluster-admin binding to a service account turns a container escape into a full cluster compromise with no additional exploit required.

**Remediation:** Remove the cluster-admin binding from the service account. Create a scoped ClusterRole or Role with only the API groups and verbs the workload actually needs. Bind that scoped role to the service account instead. Audit all ClusterRoleBindings with kubectl get clusterrolebindings -o json and filter for subjects of kind ServiceAccount bound to cluster-admin.

---

### CTL.EKS.SECRETS.ENCRYPT.001

**EKS Kubernetes Secrets Must Be Encrypted with KMS CMK**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_eks: 2.3; fedramp_moderate: SC-28; hipaa: 164.312(a)(2)(iv); nist_800_53_r5: SC-28;

EKS clusters must encrypt Kubernetes secrets at rest using a customer-managed KMS key. Without envelope encryption, anyone with access to the etcd backup or underlying EBS volume can read all cluster secrets (API tokens, database passwords, TLS certificates) in plaintext.

**Remediation:** Enable secrets encryption: aws eks associate-encryption-config --cluster-name <cluster> --encryption-config '[{"resources":["secrets"],"provider": {"keyArn":"arn:aws:kms:<region>:<account>:key/<key-id>"}}]'

---

### CTL.EKS.SECRETS.ROTATION.001

**KMS Key for EKS Secrets Encryption Must Have Rotation Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** mitre_attack: TA0006; nist_800_53_r5: SC-12;

EKS envelope encryption uses a KMS CMK to encrypt the data encryption key protecting Kubernetes secrets. A compromised KMS key grants permanent access to all secrets encrypted with it — without rotation, a leaked or compromised key remains valid indefinitely. Annual KMS key rotation limits the window of exposure. Each rotation generates a new key version — previous versions remain available for decryption but new encryptions use the current version.

**Remediation:** Enable automatic rotation on the KMS key: aws kms enable-key-rotation --key-id <key-id>

---

### CTL.EKS.VERSION.001

**EKS Clusters Must Not Run Deprecated Kubernetes Versions**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: CM-6; hipaa: 164.312(a)(2)(i); nist_800_53_r5: CM-6; pci_dss_v4.0: 2.2.1; soc2: CC7.1;

EKS clusters must not run Kubernetes versions that have reached end-of-support. AWS publishes a Kubernetes version support lifecycle for EKS — each minor version is supported for approximately 14 months after release. After end-of-support, the cluster no longer receives security patches for the Kubernetes control plane or EKS-managed components. Kubernetes has a high rate of critical CVEs affecting the API server, kubelet, and container runtime. An EKS cluster on a deprecated version is running an unpatched control plane against which known exploits exist. EKS version upgrades require a defined upgrade path and may involve breaking API changes, causing clusters to accumulate version debt due to upgrade friction rather than deliberate choice. For organizations that have invested in Kubernetes network policies, RBAC, and secrets encryption, running a deprecated control plane version undermines every other security control in the cluster.

**Remediation:** Upgrade the EKS cluster to a supported Kubernetes version. Review the AWS EKS Kubernetes version support lifecycle for the current end-of-support dates. Follow the EKS upgrade guide — upgrade one minor version at a time. Test workloads against the new version in a staging cluster before upgrading production. Check for deprecated API usage with kubectl deprecations or the Kubernetes API deprecation guide for your target version.

---

### CTL.EKS.VPC.CNI.NETPOL.TTL.001

**EKS VPC CNI NetworkPolicy Must Have Completed Pod Firewall Cleanup**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** mitre_attack: TA0008; nist_800_53_r5: AC-4;

EKS clusters with VPC CNI NetworkPolicy enforcement must have completed pod firewall rule cleanup configured. VPC CNI creates per-IP firewall rules on nodes. Pod completion does not trigger rule removal — only pod deletion does. Without TTL controller or explicit flush, completed pod IPs are recycled with stale rules.

**Remediation:** Option 1: Enable the TTLAfterFinished feature gate at cluster level. Option 2: Set ttlSecondsAfterFinished on all Job specs. Option 3: Update VPC CNI to a version with pod completion handling. Verify VPC CNI version:
  kubectl describe daemonset aws-node -n kube-system | grep Image

---

### CTL.ELASTICACHE.AUTH.001

**Redis AUTH Token Must Be Set**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-3; nist_800_53_r5: AC-3; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

ElastiCache Redis clusters must have an AUTH token configured. Without AUTH, any client with network access can read and write data. Combined with a missing VPC or open security group, this creates an unauthenticated database exposure — the same pattern as the Darkbeam Elasticsearch breach.

**Remediation:** Set an AUTH token using aws elasticache modify-replication-group --auth-token. Ensure transit encryption is also enabled (required for AUTH). Rotate the token periodically.

---

### CTL.ELASTICACHE.ENCRYPT.REST.001

**ElastiCache Redis Must Have At-Rest Encryption Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-28; pci_dss_v4.0: 3.4.1; soc2: CC6.7;

ElastiCache Redis clusters must have at-rest encryption enabled to protect cached data (sessions, credentials, application state) stored on disk.

**Remediation:** Create a new cluster with at-rest encryption enabled (cannot be changed on existing clusters).

---

### CTL.ELASTICACHE.INCOMPLETE.001

**Complete Data Required for ElastiCache Assessment**

- **Severity:** info
- **Type:** unsafe_state
- **Domain:** exposure

The observation snapshot is missing required ElastiCache properties.

**Remediation:** Ensure the extractor calls aws elasticache describe-replication-groups and maps TransitEncryptionEnabled to the cache observation properties.

---

### CTL.ELASTICACHE.TRANSIT.001

**ElastiCache Must Have In-Transit Encryption Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-8; gdpr: Art.32; hipaa: 164.312(e)(2)(ii); nist_800_53_r5: SC-8; pci_dss_v4.0: 4.2.1; soc2: CC6.6;

ElastiCache clusters must have in-transit encryption enabled. Without TLS, cache traffic travels in plaintext between the application and the cache nodes, exposing cached PHI data.

**Remediation:** In-transit encryption can only be enabled at cluster creation. Create a new replication group with TransitEncryptionEnabled=true and migrate data from the existing cluster.

---

### CTL.ELB.CROSSZONE.001

**Load Balancer Must Have Cross-Zone Load Balancing Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** ffiec: BCP; hipaa: 164.308(a)(7); soc2: A1.1;

Load balancers must distribute traffic across all registered targets in all enabled Availability Zones. Without cross-zone balancing, uneven distribution can cause availability issues during AZ failures.

**Remediation:** Enable cross-zone load balancing. Run: aws elbv2 modify-load-balancer-attributes --load-balancer-arn xxx --attributes Key=load_balancing.cross_zone.enabled,Value=true

---

### CTL.ELB.DELETION.PROTECT.001

**Load Balancer Must Have Deletion Protection Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** resilience
- **Compliance:** nist_800_53_r5: CP-10; soc2: CC6.1;

Production load balancers must have deletion protection enabled.

**Remediation:** Enable deletion protection.

---

### CTL.ELB.HTTPS.001

**Load Balancer Must Redirect HTTP to HTTPS**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-8; gdpr: Art.32; hipaa: 164.312(e)(2)(ii); nist_800_53_r5: SC-8; pci_dss_v4.0: 4.2.1; soc2: CC6.6;

Load balancers serving PHI must redirect all HTTP traffic to HTTPS. Allowing plaintext HTTP exposes data in transit to interception.

**Remediation:** Add a listener rule on port 80 that redirects to HTTPS (443) with status code 301.

---

### CTL.ELB.INCOMPLETE.001

**Complete Data Required for ELB Assessment**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure

Load balancer safety cannot be assessed when TLS configuration is missing from the snapshot. The extractor must populate loadbalancer.encryption.tls_1_2_or_higher.

**Remediation:** Re-run the extractor with ELB permissions: elasticloadbalancing:DescribeLoadBalancers, elasticloadbalancing:DescribeLoadBalancerAttributes, elasticloadbalancing:DescribeListeners.

---

### CTL.ELB.LOG.001

**Load Balancer Access Logging Must Be Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.312(b); soc2: CC7.1;

Load balancer access logging must be enabled for audit and forensic analysis. Without access logs, request patterns and potential unauthorized access cannot be investigated after an incident.

**Remediation:** Enable access logging to an S3 bucket. Run: aws elbv2 modify-load-balancer-attributes --load-balancer-arn xxx --attributes Key=access_logs.s3.enabled,Value=true Key=access_logs.s3.bucket,Value=my-elb-logs

---

### CTL.ELB.TLS.001

**Load Balancer Must Use TLS 1.2 or Higher**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-8; ffiec: ISH-4; gdpr: Art.32; hipaa: 164.312(e)(2)(ii); nist_800_53_r5: SC-8; pci_dss_v4.0: 4.2.1; soc2: CC6.6;

Application and Network Load Balancers must use TLS 1.2 or higher for HTTPS listeners. Older TLS versions have known vulnerabilities.

**Remediation:** Update the HTTPS listener to use an ELBSecurityPolicy that enforces TLS 1.2 minimum (e.g., ELBSecurityPolicy-TLS-1-2-2017-01).

---

### CTL.ELB.WAF.001

**Application Load Balancer Must Have WAF Web ACL Associated**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** network
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.6;

Internet-facing ALBs must have an AWS WAF web ACL associated.

**Remediation:** Associate a WAF web ACL with the ALB.

---

### CTL.EMR.ENCRYPT.001

**EMR Clusters Must Use a Security Configuration for Encryption**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** nist_800_53_r5: SC-28; soc2: CC6.7;

EMR clusters must have a security configuration enabling encryption at rest (EMRFS S3, local disk) and in transit (TLS). Without a security configuration, data processed by Spark and Hadoop jobs is stored and transmitted in plaintext.

**Remediation:** Create an EMR security configuration with encryption enabled for at-rest (S3 via EMRFS, local disk via LUKS) and in-transit (TLS) and attach it to the cluster.

---

### CTL.EMR.LOG.001

**EMR Clusters Must Have Logging Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AU-2; soc2: CC7.1;

EMR clusters must enable logging to S3 for cluster events, step execution, and application logs. Without logging, job failures, security events, and data access patterns are invisible.

**Remediation:** Enable logging with an S3 log URI when creating or updating the cluster.

---

### CTL.EMR.PUBLIC.BLOCK.001

**EMR Account Must Enable Block Public Access**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.6;

The EMR account-level Block Public Access setting must be enabled. When enabled, clusters cannot use security groups with inbound rules allowing public sources (0.0.0.0/0, ::/0) except on explicitly permitted ports.

**Remediation:** Enable Block Public Access in the EMR console or via aws emr put-block-public-access-configuration.

---

### CTL.EMR.PUBLIC.IP.001

**EMR Cluster Nodes Must Not Have Public IP Addresses**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.6;

EMR cluster nodes (master and worker) must not have public IP addresses assigned. Public IPs make cluster nodes directly reachable from the internet, exposing Hadoop, Spark, and YARN management interfaces.

**Remediation:** Launch clusters in private subnets without public IP assignment. Use a bastion host or VPN for administrative access.

---

### CTL.EMR.PUBLIC.SG.001

**EMR Cluster Security Groups Must Not Allow Public Inbound**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.6;

Security groups attached to EMR cluster nodes must not have inbound rules allowing traffic from 0.0.0.0/0 or ::/0. Open security groups expose Hadoop, Spark, and YARN interfaces to the internet.

**Remediation:** Restrict security group inbound rules to specific CIDR ranges or security group IDs. Remove 0.0.0.0/0 and ::/0 rules.

---

### CTL.EVENTBRIDGE.BUS.CROSSACCOUNT.001

**EventBridge Event Bus Must Not Allow Unrestricted Cross-Account Access**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3; soc2: CC6.1;

EventBridge event bus resource policies must not grant event delivery to external accounts without conditions. Cross-account event injection allows external principals to trigger downstream service actions.

**Remediation:** Restrict cross-account access with conditions or specific account IDs.

---

### CTL.EVENTBRIDGE.BUS.PUBLIC.001

**EventBridge Event Bus Must Not Allow Public Access**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3; soc2: CC6.1;

EventBridge event bus resource policies must not grant public access (Principal "*"). Public access allows anyone to publish events that trigger downstream Lambda, Step Functions, or other targets.

**Remediation:** Restrict the resource policy to specific accounts or principals.

---

### CTL.EVENTBRIDGE.REPLICATION.001

**EventBridge Global Endpoints Must Enable Event Replication**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: CP-10; soc2: A1.1;

EventBridge global endpoints must have event replication enabled to replicate events to both primary and secondary regions for cross-region resilience.

**Remediation:** Enable event replication on the global endpoint.

---

### CTL.EVENTBRIDGE.SCHEMA.PUBLIC.001

**EventBridge Schema Registry Must Not Allow Public or Cross-Account Access**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3; soc2: CC6.1;

EventBridge schema registry resource policies must not grant public or unrestricted cross-account access. Schema registries describe event structure — public access reveals internal API contracts.

**Remediation:** Restrict the registry resource policy.

---

### CTL.EVENTBRIDGE.TARGET.GHOST.001

**EventBridge Rule Must Not Target Deleted Resources**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** fedramp_moderate: SI-4; nist_800_53_r5: SI-4; soc2: CC7.1;

EventBridge rules must not target Lambda functions, SQS queues, or other resources that no longer exist. Events matching the rule are silently dropped. If the rule triggers security automation, that automation stops functioning while appearing active.

**Remediation:** Update the rule target to an existing resource or disable the rule.

---

### CTL.EXPOSURE.ANON.001

**Sensitive Resources Must Not Be Reachable from Anonymous**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-3; gdpr: Art.32; hipaa: 164.312(a)(1); nist_800_53_r5: AC-3; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

Resources tagged with sensitive data classifications (PHI, PII, confidential) must not be reachable from anonymous or unauthenticated principals through any composition of access grants. The extractor traces paths from anonymous through API Gateway routes, Lambda integrations, IAM role assumptions, bucket policies, VPC endpoint policies, and security group rules. This catches the API Gateway → Lambda → IAM Role → S3 Bucket pattern where every resource passes individual inspection but the composition creates an unauthenticated path to sensitive data.

**Remediation:** Add an authorization layer to the path. Configure an API Gateway authorizer (Cognito, Lambda, or IAM), attach a WAF with managed rule groups, or remove the Lambda function's permission to access the sensitive resource. Review the full path and break the chain at the most appropriate point.

---

### CTL.EXPOSURE.ANON.002

**Unauthenticated Access Path Must Not Exceed Depth Threshold**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-6; nist_800_53_r5: AC-6; soc2: CC6.1;

Unauthenticated access paths to any resource must not exceed 3 hops. Deep chains (anonymous → API Gateway → Lambda → Role A → Role B → S3) indicate unintended transitive access. Each hop is an access grant — IAM policy, resource policy, role assumption, or network rule. Shorter paths are more likely intentional and auditable. Deep paths signal accidental composition where intermediate services were granted broader permissions than their design requires.

**Remediation:** Flatten the access chain. Remove unnecessary intermediate services. Scope Lambda execution role permissions to the minimum required resources. Replace broad IAM role assumption chains with direct service-linked roles.

---

### CTL.EXPOSURE.ANON.003

**Unauthenticated Access Path Must Have Authentication Boundary**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-7; nist_800_53_r5: SC-7; pci_dss_v4.0: 6.4.1; soc2: CC6.6;

Any resource reachable from anonymous principals must have at least one authentication boundary in the access path — a point where identity is verified (Cognito authorizer, Lambda authorizer, IAM authorization, mTLS). An inspection boundary (WAF, API Gateway threat protection) provides defense-in-depth but does NOT establish identity — a path with only WAF is still unauthenticated. This control flags paths where no identity verification exists between the public internet and the target resource.

**Remediation:** Add an authentication boundary to the access path. Configure a Cognito user pool authorizer or Lambda authorizer on API Gateway routes. Enable IAM authorization on the API Gateway stage. If service-to-service, enable mTLS.

---

### CTL.EXPOSURE.ANON.004

**Unauthenticated Access Path Should Have Inspection Boundary**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SI-3; pci_dss_v4.0: 6.4.2;

Any resource reachable from anonymous principals should have at least one inspection boundary in the access path — a point where requests are filtered for malicious content (WAF with managed rule groups, API Gateway request validation). An authentication boundary verifies identity; an inspection boundary verifies request safety. Both are needed for defense-in-depth. This control flags paths where no request inspection exists.

**Remediation:** Attach a WAF web ACL with managed rule groups (AWSManagedRulesCommonRuleSet, AWSManagedRulesKnownBadInputsRuleSet) to the API Gateway stage or ALB. Enable API Gateway request validation.

---

### CTL.EXPOSURE.ANON.INCOMPLETE.001

**Complete Data Required for Reachability Assessment**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure

Unauthenticated reachability cannot be assessed when the reachability kind discriminator is present but the reachable field is missing. The extractor encountered an error during graph traversal and could not determine whether the resource is reachable from anonymous principals.

**Remediation:** Re-run the reachability extractor with sufficient IAM permissions to read API Gateway configurations, Lambda function policies, IAM role trust policies, and resource-based policies for all resources in the account.

---

### CTL.EXPOSURE.ANON.PARTIAL.001

**Reachability Path Must Be Fully Resolved**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure

When the extractor finds a path from anonymous to a resource but cannot fully resolve all intermediate nodes (e.g., access denied on an IAM policy lookup, missing Lambda configuration), the path is marked as partially resolved. Safety cannot be proven because the unresolved segment may contain additional access grants that widen the blast radius. This is the "unknown" state — worse than a confirmed safe path, potentially better than a confirmed unsafe path.

**Remediation:** Grant the reachability extractor read access to the unresolved resources. Required permissions include iam:GetRolePolicy, lambda:GetFunction, apigateway:GetMethod, and resource-based policy read access for all services in the path.

---

### CTL.EXPOSURE.EXFIL.001

**Sensitive Data Must Not Be Readable by Compute with Internet Egress**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-7; hipaa: 164.312(a)(1); nist_800_53_r5: SC-7; pci_dss_v4.0: 3.4.1; soc2: CC6.7;

Resources containing sensitive data (PHI, PII, confidential) are readable by a compute instance that has an unmonitored path to the internet. The extractor traces from the sensitive resource to compute instances that can read it, then checks if those instances have outbound internet connectivity (NAT gateway, internet gateway, VPC peering to public subnet). This is the reverse of the unauthenticated reachability check — instead of "who can get in?" it answers "how can data get out?"

**Remediation:** Remove internet egress from the compute instance's subnet. Place sensitive-data-accessing instances in private subnets with VPC endpoints only. Scope the instance role to the minimum required resources. Enable VPC Flow Logs and CloudTrail data events for audit.

---

### CTL.EXPOSURE.EXFIL.002

**Compute with Internet Egress Must Not Have Wildcard Write**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-6; nist_800_53_r5: AC-6; soc2: CC6.1;

Compute instances with internet egress paths must have scoped write permissions. An instance with s3:PutObject on Resource "*" combined with outbound internet access can write data to any S3 bucket — including attacker-controlled external buckets. The extractor checks if the instance role grants wildcard write permissions to storage services.

**Remediation:** Scope the instance role's write permissions to specific resource ARNs. Replace s3:PutObject on Resource "*" with explicit bucket ARNs. Use VPC endpoints with bucket-scoped policies to restrict write targets.

---

### CTL.EXPOSURE.EXFIL.INCOMPLETE.001

**Complete Data Required for Exfiltration Assessment**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure

Data exfiltration path assessment requires the exfiltration kind discriminator and the path_to_internet_exists field. The extractor could not determine whether the compute instance has internet egress.

**Remediation:** Re-run the exfiltration extractor with sufficient permissions to read VPC route tables, NAT gateways, internet gateways, and security group egress rules.

---

### CTL.EXPOSURE.SOVEREIGNTY.001

**Sensitive Data Must Not Be Accessible from Outside Its Jurisdiction**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-4; gdpr: Art.44; nist_800_53_r5: AC-4;

Resources containing sensitive data (PHI, PII, confidential) in a specific jurisdiction must have access restricted to principals in the same jurisdiction. A bucket in eu-west-1 accessible by a US-based principal is a structural jurisdictional violation — the data is physically in the EU but logically reachable from outside the EU, defeating data residency controls.

**Remediation:** Restrict access to the resource using IAM condition keys that enforce source VPC or source IP ranges within the jurisdiction. Use SCPs to deny cross-jurisdiction access at the organization level. Review resource-based policies for cross-region grants.

---

### CTL.EXPOSURE.SOVEREIGNTY.INCOMPLETE.001

**Complete Data Required for Sovereignty Assessment**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure

Sovereignty assessment requires the cross_border_access_detected field. The extractor could not determine whether the resource is accessible from outside its jurisdiction.

**Remediation:** Re-run the sovereignty extractor with permissions to enumerate IAM principals, their account regions, and resource-based policies for all sensitive resources.

---

### CTL.GCS.ENCRYPT.001

**Customer-Managed Encryption Key Required**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_gcp_v1.3.0: 5.3;

GCS buckets containing sensitive data must use a customer-managed encryption key (CMEK) via Cloud KMS, not the default Google-managed key. CMEK provides key rotation control, access policies, and audit trails that Google-managed keys do not.

**Remediation:** Set a default CMEK on the bucket. Run: gcloud storage buckets update gs://BUCKET --default-encryption-key=projects/PROJECT/locations/LOCATION/keyRings/RING/cryptoKeys/KEY

---

### CTL.GCS.INCOMPLETE.001

**Complete Data Required for GCS Assessment**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** storage

GCS bucket safety cannot be proven when access control data is missing from the snapshot. The extractor must populate storage.access.public_read to evaluate public exposure controls.

**Remediation:** Re-run the extractor with storage permissions: storage.buckets.getIamPolicy, storage.buckets.get.

---

### CTL.GCS.LOG.001

**Access Logging Must Be Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_gcp_v1.3.0: 5.3;

GCS buckets must have access logging enabled. Without logging, access patterns cannot be audited and unauthorized access goes undetected.

**Remediation:** Enable access logging for the bucket. Run: gcloud storage buckets update gs://BUCKET --log-bucket=LOG_BUCKET --log-object-prefix=PREFIX

---

### CTL.GCS.PUBLIC.001

**No Public GCS Bucket Read**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_gcp_v1.3.0: 5.1;

GCS buckets must not allow public read access. Detects buckets where IAM bindings include allUsers or allAuthenticatedUsers with read permissions, or where uniform bucket-level access is disabled and object ACLs may grant public access.

**Remediation:** Remove allUsers and allAuthenticatedUsers from bucket IAM bindings. Run: gcloud storage buckets remove-iam-policy-binding gs://BUCKET --member=allUsers --role=roles/storage.objectViewer

---

### CTL.GCS.PUBLIC.002

**No Public GCS Bucket Listing**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_gcp_v1.3.0: 5.1;

GCS buckets must not allow public listing. Anonymous bucket listing exposes the full object inventory, enabling bulk data discovery.

**Remediation:** Remove allUsers from bucket IAM bindings for storage.objects.list. Enable uniform bucket-level access to prevent object ACL overrides.

---

### CTL.GCS.UNIFORM.001

**Uniform Bucket-Level Access Must Be Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_gcp_v1.3.0: 5.2;

GCS buckets must use uniform bucket-level access. When disabled, both IAM policies and object ACLs control access, creating a dual-path exposure risk that is harder to audit and more prone to misconfiguration.

**Remediation:** Enable uniform bucket-level access. Run: gcloud storage buckets update gs://BUCKET --uniform-bucket-level-access

---

### CTL.GCS.VERSION.001

**Object Versioning Must Be Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_gcp_v1.3.0: 5.3;

GCS buckets must have object versioning enabled. Without versioning, deleted or overwritten objects cannot be recovered, and ransomware attacks that encrypt objects are irreversible.

**Remediation:** Enable versioning. Run: gcloud storage buckets update gs://BUCKET --versioning

---

### CTL.GLUE.CATALOG.ENCRYPT.001

**Glue Data Catalog Metadata Must Be Encrypted At Rest**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** nist_800_53_r5: SC-28; soc2: CC6.7;

The Glue Data Catalog must use SSE-KMS encryption for metadata at rest. The catalog contains table schemas, partition information, S3 data locations, and database definitions — a complete map of the organization's data landscape. Unencrypted metadata enables reconnaissance and targeted data access.

**Remediation:** Enable SSE-KMS encryption for the Data Catalog in the Glue console or via aws glue put-data-catalog-encryption-settings.

---

### CTL.GLUE.CATALOG.ENCRYPT.PASSWORD.001

**Glue Data Catalog Must Encrypt Connection Passwords**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** nist_800_53_r5: SC-28; pci_dss_v4.0: 3.4.1; soc2: CC6.1;

The Glue Data Catalog must encrypt connection passwords at rest using KMS. Connection properties store JDBC passwords, Redshift credentials, and other data store authentication material. Unencrypted passwords are readable by any principal with glue:GetConnection access.

**Remediation:** Enable connection password encryption in the Data Catalog encryption settings with a KMS key.

---

### CTL.GLUE.CATALOG.POLICY.001

**Glue Data Catalog Must Not Be Publicly Accessible**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3; soc2: CC6.1;

The Glue Data Catalog resource policy must not grant access to Principal "*" or unauthenticated principals. Public catalog access allows unauthorized actors to enumerate table schemas, S3 data locations, partition metadata, and database definitions — the complete map of the organization's data architecture.

**Remediation:** Restrict the catalog resource policy to specific accounts or roles. Remove any statements with Principal "*".

---

### CTL.GLUE.CONNECTION.SSL.001

**Glue Database Connections Must Enforce SSL**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** nist_800_53_r5: SC-8; soc2: CC6.7;

Glue JDBC connections must enforce TLS/SSL via the JDBC_ENFORCE_SSL connection property. Without TLS, JDBC traffic between Glue jobs and data stores — including credentials, queries, and results — can be intercepted in transit.

**Remediation:** Set the JDBC_ENFORCE_SSL connection property to true in the Glue connection configuration.

---

### CTL.GLUE.ENDPOINT.ENCRYPT.BOOKMARKS.001

**Glue Dev Endpoint Must Encrypt Job Bookmarks**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** nist_800_53_r5: SC-28;

Glue development endpoints must use a security configuration with job bookmark encryption enabled (CSE-KMS). Note: AWS deprecated dev endpoints in favor of interactive sessions.

**Remediation:** Attach a security configuration with job bookmark encryption to the endpoint, or migrate to Glue interactive sessions.

---

### CTL.GLUE.ENDPOINT.ENCRYPT.LOG.001

**Glue Dev Endpoint CloudWatch Logs Must Be Encrypted**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** nist_800_53_r5: SC-28;

Glue development endpoints must use a security configuration with CloudWatch Logs encryption enabled. Note: AWS deprecated dev endpoints in favor of interactive sessions. Existing endpoints remain operational.

**Remediation:** Attach a security configuration with CloudWatch Logs encryption to the endpoint, or migrate to Glue interactive sessions.

---

### CTL.GLUE.ENDPOINT.ENCRYPT.S3.001

**Glue Dev Endpoint Must Encrypt S3 Data At Rest**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** nist_800_53_r5: SC-28;

Glue development endpoints must use a security configuration with S3 encryption enabled. Note: AWS deprecated dev endpoints in favor of interactive sessions.

**Remediation:** Attach a security configuration with S3 encryption to the endpoint, or migrate to Glue interactive sessions.

---

### CTL.GLUE.JOB.ENCRYPT.BOOKMARKS.001

**Glue ETL Jobs Must Encrypt Job Bookmarks**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** nist_800_53_r5: SC-28;

Glue ETL jobs must use a security configuration with job bookmark encryption enabled (CSE-KMS). Unencrypted bookmarks expose dataset paths, partitions, and processing state. Tampered bookmarks can trigger data reprocessing or skipping.

**Remediation:** Create a Glue security configuration with job bookmark encryption (CSE-KMS) and attach it to the job.

---

### CTL.GLUE.JOB.ENCRYPT.S3.001

**Glue ETL Jobs Must Encrypt S3 Data At Rest**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** nist_800_53_r5: SC-28; soc2: CC6.7;

Glue ETL jobs must use a security configuration with S3 encryption enabled (SSE-S3 or SSE-KMS). Without encryption, job outputs, temporary data, and scripts stored in S3 are readable by anyone with bucket access.

**Remediation:** Create a Glue security configuration with S3 encryption enabled (SSE-KMS recommended) and attach it to the job.

---

### CTL.GLUE.JOB.LOG.ENCRYPT.001

**Glue ETL Job CloudWatch Logs Must Be Encrypted**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** nist_800_53_r5: SC-28; soc2: CC6.7;

Glue ETL jobs must use a security configuration with CloudWatch Logs encryption enabled (SSE-KMS). Unencrypted log entries can expose credentials, PII, connection strings, and schema details.

**Remediation:** Create a Glue security configuration with CloudWatch Logs encryption (SSE-KMS) and attach it to the job.

---

### CTL.GLUE.JOB.SECRETS.001

**Glue ETL Jobs Must Not Store Secrets in Job Arguments**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: IA-5(7); pci_dss_v4.0: 3.4.1; soc2: CC6.1;

Glue ETL job DefaultArguments must not contain plaintext secrets (passwords, API keys, tokens). Job arguments are visible in the AWS console, CLI output, and CloudTrail logs. Use Secrets Manager or Parameter Store references instead.

**Remediation:** Move secrets to AWS Secrets Manager or SSM Parameter Store. Reference them in job scripts using boto3 at runtime instead of passing them as job arguments.

---

### CTL.GLUE.MLTRANSFORM.ENCRYPT.001

**Glue ML Transform Must Encrypt User Data At Rest**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** nist_800_53_r5: SC-28; soc2: CC6.7;

Glue ML transforms must encrypt user data at rest using SSE-KMS. Unencrypted transform artifacts, mappings, and sample datasets may reveal schemas and data relationships.

**Remediation:** Enable SSE-KMS encryption for the ML transform's user data via the MlUserDataEncryption setting.

---

### CTL.GUARDDUTY.ECS.RUNTIME.001

**GuardDuty ECS Runtime Monitoring Must Be Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SI-4; nist_800_53_r5: SI-4; soc2: CC7.1;

GuardDuty ECS Runtime Monitoring must be enabled to detect runtime threats in containers — crypto mining, malware, reverse shells, and credential access. Without runtime monitoring, container compromise proceeds undetected at the process and network level.

**Remediation:** Enable GuardDuty ECS Runtime Monitoring in the GuardDuty console or via API. Requires the GuardDuty agent deployed as a sidecar or managed add-on on ECS tasks.

---

### CTL.GUARDDUTY.ENABLED.001

**Amazon GuardDuty Must Be Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SI-3; ffiec: CAT-D3; gdpr: Art.32; iso_27001_2022: A.8.16; nist_800_53_r5: SI-3; nist_csf_2.0: DE.CM; pci_dss_v4.0: 5.2; soc2: CC7.1;

GuardDuty must be enabled to provide continuous threat detection. It analyzes CloudTrail, VPC Flow Logs, and DNS logs to detect reconnaissance, instance compromise, and account compromise.

**Remediation:** Enable GuardDuty: aws guardduty create-detector --enable

---

### CTL.GUARDDUTY.EXPORT.001

**GuardDuty Findings Must Be Exported to S3 for Long-Term Retention**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** aws_security_hub: GuardDuty.3; mitre_attack: TA0005; nist_800_53_r5: AU-11;

GuardDuty retains findings for 90 days by default. Without export to S3, findings older than 90 days are permanently deleted — making it impossible to review historical threat activity during long-running investigations or compliance audits. Exporting to S3 with Object Lock provides an immutable, long-term record of all GuardDuty findings.

**Remediation:** aws guardduty create-publishing-destination --detector-id <id> --destination-type S3 --destination-properties DestinationArn=arn:aws:s3:::<bucket>,KmsKeyArn=<key-arn>

---

### CTL.GUARDDUTY.INCOMPLETE.001

**Complete Data Required for GuardDuty Assessment**

- **Severity:** info
- **Type:** unsafe_state
- **Domain:** exposure

The observation snapshot is missing required GuardDuty properties.

**Remediation:** Ensure the extractor calls aws guardduty list-detectors and get-detector.

---

### CTL.GUARDDUTY.MALWARE.PROTECT.001

**GuardDuty Malware Protection Must Be Enabled for EC2**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** mitre_attack: TA0002; nist_800_53_r5: SI-3;

GuardDuty Malware Protection scans EBS volumes attached to EC2 instances and ECS containers when GuardDuty detects suspicious activity. It identifies crypto-mining malware, ransomware, spyware, and rootkits. Without Malware Protection, GuardDuty detects network-level and API-level threats but cannot detect malicious files already present on instance volumes.

**Remediation:** aws guardduty update-malware-scan-settings --detector-id <id> --scan-resource-criteria Include={ResourceTypes=[EC2]}

---

### CTL.GUARDDUTY.SUPPRESSION.001

**GuardDuty Must Not Have Broad Suppression Rules**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: SI-4; iso_27001_2022: A.8.16; nist_800_53_r5: SI-4; soc2: CC7.1;

Safety mechanism integrity control. Checks that security guardrails are actively enforcing, not just present.

**Remediation:** Review the specific guardrail identified in this finding and restore it to an enforcing state.

---

### CTL.GUARDRAIL.INCOMPLETE.001

**Complete Data Required for Safety Mechanism Integrity Assessment**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance

Safety mechanism integrity control. Checks that security guardrails are actively enforcing, not just present.

**Remediation:** Review the specific guardrail identified in this finding and restore it to an enforcing state.

---

### CTL.IAM.ACCOUNT.INACTIVE.001

**Inactive Accounts Must Be Disabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v3.0: 1.12; fedramp_moderate: AC-2; hipaa: 164.312(a)(2)(i); nist_800_53_r5: AC-2; pci_dss_v4.0: 8.1.4; soc2: CC6.2;

IAM accounts with no login or API activity for 90 days or more must be disabled. Dormant accounts are high-value targets — they have permissions but no active user monitoring their usage. Legacy accounts, test accounts, and accounts from departed employees accumulate over time and provide persistent, unmonitored access paths for attackers.

**Remediation:** Disable or delete the IAM user. If the account is still needed, review and renew its access with a documented justification and an updated expiry date.

---

### CTL.IAM.ADMIN.COUNT.001

**Admin User Count Must Not Exceed Threshold**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v3.0: 1.16; fedramp_moderate: AC-6(5); nist_800_53_r5: AC-6(5); pci_dss_v4.0: 7.2.2; soc2: CC6.1;

AWS accounts must have no more than 2 users with full administrator access. Excessive admin accounts expand the credential compromise surface and violate least privilege. Use IAM roles with temporary elevation (break-glass) instead of permanent admin access.

**Remediation:** Reduce admin users to 2 or fewer. Convert permanent admin access to IAM roles with temporary elevation via sts:AssumeRole. Use IAM Access Analyzer to identify unused admin permissions.

---

### CTL.IAM.ANALYZER.001

**IAM Access Analyzer Must Be Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v3.0: 1.20; fedramp_moderate: SI-4; nist_800_53_r5: SI-4; pci_dss_v4.0: 11.3.1; soc2: CC6.1;

IAM Access Analyzer must be enabled in every region. Access Analyzer identifies resources shared with external entities and generates findings for unintended exposure.

**Remediation:** Create an Access Analyzer in each region: aws accessanalyzer create-analyzer --analyzer-name default --type ACCOUNT --region <region>

---

### CTL.IAM.ANALYZER.MONITOR.001

**IAM Access Analyzer Must Be Configured for Continuous Monitoring**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v3.0: 1.21; fedramp_moderate: SI-4; nist_800_53_r5: SI-4; pci_dss_v4.0: 11.3.1; soc2: CC7.1;

IAM Access Analyzer must be in ACTIVE status and findings must be reviewed within 30 days. CIS 1.21 requires not just enablement (covered by CTL.IAM.ANALYZER.001) but active monitoring and finding review. An analyzer with unreviewed findings has detected external access paths — S3 buckets, IAM roles, KMS keys, Lambda functions accessible outside the account — that have not been evaluated for legitimacy. Active findings are confirmed external access paths waiting to be investigated, not theoretical risks. For PHI environments, any unreviewed external access path is a potential breach path.

**Remediation:** Verify the analyzer is in ACTIVE status in all regions. Review all active (unarchived) findings. For each finding, determine if the external access is intended — archive intended access, remediate unintended access. Establish an operational process to review new findings within 30 days of detection.

---

### CTL.IAM.BOUNDARY.001

**IAM Roles Must Have Permissions Boundary**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6; nist_800_53_r5: AC-6; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

IAM roles must have a permissions boundary attached. A permissions boundary sets a ceiling on the effective permissions of a role, regardless of what identity policies are attached. Without a boundary, a developer who can create or modify roles has no ceiling preventing the provisioned role from granting full admin access.

**Remediation:** Attach a permissions boundary policy to the role using aws iam put-role-permissions-boundary. Define a boundary that caps permissions to the services and actions required for the role's documented function.

---

### CTL.IAM.CERT.EXPIRED.001

**Remove Expired IAM Server Certificates**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v3.0: 1.19;

Expired SSL/TLS server certificates must be removed from IAM. Expired certificates cannot serve TLS but create confusion during audits and may mask missing certificate rotation.

**Remediation:** Delete expired certificates and migrate active ones to ACM: aws iam delete-server-certificate --server-certificate-name <name>

---

### CTL.IAM.CONSOLE.MFA.001

**Console Users Must Have MFA Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v1.4.0: 1.10; cis_aws_v3.0: 1.10; fedramp_moderate: IA-2(1); ffiec: CAT-D3; gdpr: Art.32; hipaa: 164.312(d); iso_27001_2022: A.8.5; nist_800_53_r5: IA-2(1); nist_csf_2.0: PR.AA; pci_dss_v3.2.1: 8.3; pci_dss_v4.0: 8.3.1; soc2: CC6.1;

IAM users with console access must have multi-factor authentication enabled. Console access without MFA allows credential-only login, making accounts vulnerable to password compromise.

**Remediation:** Enable MFA for the user via IAM > Users > Security credentials > MFA. Alternatively, disable console access if the user only needs programmatic access.

---

### CTL.IAM.CRED.EXPIRY.001

**Credentials Must Have Defined Expiry**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-2; iso_27001_2022: A.8.5; nist_800_53_r5: AC-2; pci_dss_v4.0: 8.1.4; soc2: CC6.1;

IAM credentials must have a defined maximum lifetime. Credentials without expiry — access keys created for QA, debugging, or temporary integrations — persist indefinitely and become permanent attack surfaces. Time transforms temporary mistakes into permanent breaches. Every credential must have a TTL enforced at creation time or through automated lifecycle policies.

**Remediation:** Replace long-lived access keys with STS temporary credentials that expire automatically. If access keys are required, enforce a maximum age policy and automate rotation via Secrets Manager. Tag credentials with creation date and intended expiry.

---

### CTL.IAM.CRED.RECUR.001

**IAM Console Password Must Not Be Disabled and Re-Enabled Repeatedly**

- **Severity:** high
- **Type:** unsafe_recurrence
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-2; hipaa: 164.312(a)(2)(i); nist_800_53_r5: AC-2; pci_dss_v4.0: 8.1.4; soc2: CC7.1;

IAM user console password has been disabled and re-enabled more than once in 30 days. Password lifecycle manipulation — disable, re-enable, repeat — is the pattern of an attacker maintaining persistence through credential lifecycle events that would otherwise revoke access.

**Remediation:** Investigate the root cause of the repeated oscillation. Determine whether the pattern indicates a broken process, operational workaround, or active compromise. Review CloudTrail for the API calls that triggered each transition.

---

### CTL.IAM.CRED.ROTATION.001

**Access Keys Must Be Rotated Within 90 Days**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v1.4.0: 1.14; cis_aws_v3.0: 1.14; fedramp_moderate: IA-5(1); hipaa: 164.312(a)(2)(i); nist_800_53_r5: IA-5(1); pci_dss_v3.2.1: 8.2.4; pci_dss_v4.0: 8.3.9; soc2: CC6.1;

IAM user access keys older than 90 days must be rotated. Long-lived access keys accumulate exposure risk and may have been leaked in code repositories, logs, or configuration files.

**Remediation:** Create a new access key, update all systems using the old key, then deactivate and delete the old key.

---

### CTL.IAM.CRED.SETUPKEY.001

**No Access Keys Created at User Setup**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v3.0: 1.11; soc2: CC6.2;

Access keys should not be created at user creation time. Keys created during setup are often distributed insecurely and may not be needed. Create keys only for specific programmatic access.

**Remediation:** Delete the setup-time access key and create a new one only if programmatic access is specifically required.

---

### CTL.IAM.CRED.SINGLEKEY.001

**Single Active Access Key per User**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v3.0: 1.13; fedramp_moderate: IA-5; nist_800_53_r5: IA-5; pci_dss_v4.0: 8.3.4; soc2: CC6.1;

Each IAM user must have at most one active access key. Multiple active keys increase the attack surface and complicate key rotation.

**Remediation:** Deactivate and delete the extra access key: aws iam update-access-key --status Inactive --access-key-id AKIA... aws iam delete-access-key --access-key-id AKIA...

---

### CTL.IAM.CRED.UNUSED.001

**Disable Unused Credentials**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v1.4.0: 1.12; cis_aws_v3.0: 1.12; fedramp_moderate: AC-2; hipaa: 164.312(a)(2)(i); nist_800_53_r5: AC-2; pci_dss_v4.0: 8.1.4; soc2: CC6.2;

IAM credentials unused for 90 days or more must be disabled. Dormant credentials are a persistent attack surface that provides access without triggering normal usage patterns.

**Remediation:** Disable or delete unused credentials. Review the user's need for access and remove the IAM user if no longer required.

---

### CTL.IAM.CRED.UNUSED45.001

**Disable Credentials Unused for 45 Days**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v3.0: 1.12;

IAM credentials (passwords and access keys) unused for 45 or more days must be disabled. CIS v3.0 requires a 45-day threshold, which is stricter than the 90-day HIPAA threshold.

**Remediation:** Disable inactive access keys and console passwords: aws iam update-access-key --status Inactive --access-key-id AKIA...

---

### CTL.IAM.CROSS.ENV.001

**Non-Production Must Not Access Production Resources**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-4; iso_27001_2022: A.8.22; nist_800_53_r5: AC-4; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

IAM roles in non-production environments (test, staging, QA) must not have access to production resources. Cross-environment access collapses security boundaries — a compromised test account becomes a path to production data. The Microsoft breach (2024) demonstrated this exact failure: a test tenant with production-scope grants enabled a nation-state actor to pivot from test to production.

**Remediation:** Remove production resource ARNs from non-production role policies. Use separate AWS accounts for prod and non-prod with no cross- account trust. Enforce environment boundaries via SCPs that deny non-prod accounts from accessing prod resources. Tag all accounts and roles with their environment classification.

---

### CTL.IAM.CROSS.ENV.PATH.001

**Production Must Not Be Reachable from Lower Environment via Transitive Trust**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-4; nist_800_53_r5: AC-4; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

Production resources must have no transitive access path from non-production environments. The extractor traces sts:AssumeRole chains and resource policy grants from non-production accounts to production resources. A direct cross-account role is one hop; a chain through an intermediate shared-services account is two or more. Each hop widens the attack surface — a compromised dev credential becomes a production breach when bridge roles exist.

**Remediation:** Remove cross-account trust relationships that bridge non-prod to prod. Use separate deployment pipelines per environment. Enforce environment isolation via SCPs that deny non-prod accounts from assuming prod roles.

---

### CTL.IAM.CROSSCLOUD.ADMIN.001

**No Full Admin Policies Across Any Cloud Provider**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6; soc2: CC6.1;

No IAM policy on any cloud provider should grant unrestricted administrative access (Action: *, Resource: * or equivalent). This control extends CTL.IAM.POLICY.ADMIN.001 beyond AWS to Azure (Contributor/Owner at subscription scope) and GCP (roles/owner, roles/editor at project scope). The same least-privilege principle applies regardless of cloud provider.

**Remediation:** Replace admin policies with scoped policies granting only required permissions. Use cloud-specific access analyzers to identify unused permissions.

---

### CTL.IAM.CROSSCLOUD.MFA.001

**MFA Must Be Enforced Across All Cloud Providers**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: IA-2(1); soc2: CC6.1;

All privileged accounts across all cloud providers must have MFA enforced. This control extends AWS MFA controls to Azure AD (Conditional Access requiring MFA) and GCP (2-Step Verification enforcement). A single cloud account without MFA is a breach vector regardless of how well other clouds are protected.

**Remediation:** Enforce MFA at the identity provider level. AWS: IAM MFA policy conditions. Azure: Conditional Access policies. GCP: 2-Step Verification enforcement in Workspace/Cloud Identity.

---

### CTL.IAM.ESCALATE.ADDUSERTOGROUP.001

**Principal Must Not Escalate via iam:AddUserToGroup To A Broader Group**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6(5); iso_27001_2022: A.8.3; nist_800_53_r5: AC-6(5); pci_dss_v4.0: 7.2.1; soc2: CC6.1;

A principal with `iam:AddUserToGroup` can add itself to any group whose Resource scope includes it. When a candidate target group grants permissions that exceed the principal's current set, joining that group is a single-call privilege escalation. This is Rhino Security Labs privilege-escalation technique #6 ("IAM — AddUserToGroup"). Unlike techniques #3 and #4, the escalating principal does not need to modify the group's policies at all; it only needs the group to exist with broader permissions and for `AddUserToGroup` to be scoped to reach that group.
Scope: gated on `identity.kind == "user"`. The `iam:AddUserToGroup` AWS action targets users specifically; IAM groups cannot contain roles. No role-side analogue exists.

**Remediation:** Scope `iam:AddUserToGroup` to groups whose permissions do not exceed the principal's, or remove the permission entirely from non-admin principals. If developer self-service group joins are needed, constrain the target group set with a Condition on `iam:ResourceTag` or a specific group-name prefix.

---

### CTL.IAM.ESCALATE.ASSUMEROLE.001

**Principal Must Not Escalate via sts:AssumeRole To A Broader Role**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6(5); iso_27001_2022: A.8.3; nist_800_53_r5: AC-6(5); pci_dss_v4.0: 7.2.1; soc2: CC6.1;

A principal with `sts:AssumeRole` reaching a role whose attached permissions exceed its own — and whose trust policy permits the principal to assume it — has a one-call path to those permissions. The principal does not grant itself anything; it pivots into a role that already carries the broader set. This is Rhino Security Labs' role-assumption escalation pattern, adjacent to the direct-policy cluster (CTL.IAM.ESCALATE.ATTACHUSERPOLICY.001 etc.) but distinct: the escalation vector here is the role's existing trust, not a self-modification of any policy. Remediation also differs — remove `sts:AssumeRole` from the principal or narrow the trust policy on the target role — so the control is separate from CTL.IAM.ESCALATE.UPDATETRUST.001 even though the two can chain.

**Remediation:** Either remove `sts:AssumeRole` from the principal, or narrow the target role's trust policy so the principal is no longer permitted. If cross-service pivots are intentional (CI/CD deploy roles, break-glass admin roles), gate the trust with `sts:ExternalId`, `aws:MultiFactorAuthPresent`, or `aws:PrincipalOrgID` and audit use via CloudTrail. For account-root trusts, add an explicit Condition on the calling principal's ARN or role.

---

### CTL.IAM.ESCALATE.ATTACHGROUPPOLICY.001

**Principal Must Not Escalate via iam:AttachGroupPolicy On A Belonging Group**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6(5); iso_27001_2022: A.8.3; nist_800_53_r5: AC-6(5); pci_dss_v4.0: 7.2.1; soc2: CC6.1;

A principal with `iam:AttachGroupPolicy` whose Resource field includes a group the principal belongs to can attach any managed policy to that group, elevating every member including itself. This is Rhino Security Labs privilege-escalation technique #3 ("IAM — Attach to group"). The group hop adds one indirection over `AttachUserPolicy` on self but is functionally equivalent: attach `AdministratorAccess` to a belonging group, and the principal is admin.
Scope: gated on `identity.kind == "user"`. IAM groups are a user-only concept — roles cannot belong to groups. The technique has no role-side analogue; there is no future control waiting in the queue for a role-side version because AWS IAM does not have role groups.

**Remediation:** Scope `iam:AttachGroupPolicy` to groups the principal does not belong to, or remove the permission entirely from non-admin principals. Use an SCP to deny `iam:AttachGroupPolicy` where the target group has the principal in its membership list.

---

### CTL.IAM.ESCALATE.ATTACHROLEPOLICY.001

**Role Must Not Escalate via iam:AttachRolePolicy On Self**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6(5); iso_27001_2022: A.8.3; nist_800_53_r5: AC-6(5); pci_dss_v4.0: 7.2.1; soc2: CC6.1;

A role with `iam:AttachRolePolicy` whose Resource field includes its own role ARN can attach any managed policy — including `arn:aws:iam::aws:policy/AdministratorAccess` — to itself and gain that policy's permissions with a single API call. This is the role-side analogue of `CTL.IAM.ESCALATE.ATTACHUSERPOLICY.001`: distinct AWS action (`iam:AttachRolePolicy` vs `iam:AttachUserPolicy`), distinct principal kind (role vs user), same one-step escalation outcome. Rhino Security Labs' iam__privesc_scan and Prowler's iam_policy_allows_privilege_escalation both enumerate this technique on roles as well as users. The companion Cluster 1 user-side control intentionally stays user-gated because its action is user-scoped; this control mirrors it for the role-action.

**Remediation:** Remove `iam:AttachRolePolicy` from the role, or scope its Resource to role ARNs that do not include the role itself (admin-only role-creation workflows, for example). Enforce at the organization level with an SCP that denies `iam:AttachRolePolicy` on `${aws:PrincipalArn}`. A permissions boundary on the role that prevents the attached policy from taking effect is an additional defensive layer.

---

### CTL.IAM.ESCALATE.ATTACHUSERPOLICY.001

**Principal Must Not Escalate via iam:AttachUserPolicy On Self**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6(5); iso_27001_2022: A.8.3; nist_800_53_r5: AC-6(5); pci_dss_v4.0: 7.2.1; soc2: CC6.1;

A principal with `iam:AttachUserPolicy` whose Resource field includes its own user ARN can attach any managed policy — including `arn:aws:iam::aws:policy/AdministratorAccess` — to itself and become admin with a single API call. This is Rhino Security Labs privilege-escalation technique #1 ("IAM — Attach to user") and is covered by Prowler's iam_policy_allows_privilege_escalation and Pacu's iam__privesc_scan. No other permission is required; self-scoped AttachUserPolicy is a one-step path to full admin.
Scope: gated on `identity.kind == "user"`. The `iam:AttachUserPolicy` AWS action targets users specifically — roles cannot be the self- target. The role-side analogue is `iam:AttachRolePolicy` on self, a separate technique that will require its own `CTL.IAM.ESCALATE.ATTACHROLEPOLICY.001` control in a future iteration.

**Remediation:** Remove `iam:AttachUserPolicy` from the principal, or scope its Resource field to user ARNs that do not include the principal itself (admin-only bootstrap roles, for example). Enforce at the organization level with an SCP that denies `iam:AttachUserPolicy` on `${aws:PrincipalArn}`. Also consider a permissions boundary on the principal that prevents the attached policy from taking effect.

---

### CTL.IAM.ESCALATE.CHAIN.001

**Principal Must Not Have Multi-Step Path to Admin**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6(5); nist_800_53_r5: AC-6(5); pci_dss_v4.0: 7.2.1; soc2: CC6.1;

IAM principals must have no multi-step permission chain that leads to administrative access. The extractor analyzes known escalation patterns (iam:PassRole + lambda:CreateFunction, iam:CreatePolicyVersion on self, sts:AssumeRole to admin role, etc.) and traces whether a low-privileged principal can chain permissions to reach admin. Each step is individually authorized but the composition creates a privilege escalation path that policy reviews miss.

**Remediation:** Remove the weakest link in the escalation chain. Common fixes: scope iam:PassRole to specific role ARNs, restrict lambda:CreateFunction to approved execution roles, add permissions boundaries that deny IAM self-modification.

---

### CTL.IAM.ESCALATE.CREATEACCESSKEY.001

**Principal Must Not Escalate via iam:CreateAccessKey On Another User**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6(5); iso_27001_2022: A.8.3; nist_800_53_r5: AC-6(5); pci_dss_v4.0: 7.2.1; soc2: CC6.1;

A principal with `iam:CreateAccessKey` whose Resource field reaches another IAM user — one whose attached permissions exceed the principal's own — can create a second access key for that user and authenticate as them immediately. The target user's password, console session, or MFA state is irrelevant; access keys are standalone long-lived credentials. This is Rhino Security Labs' credential-manipulation escalation technique and is covered by Prowler's iam_policy_allows_privilege_escalation and Pacu's iam__privesc_scan. The target user is limited to two access keys by AWS; when the victim already has two keys the attack requires an extra `DeleteAccessKey` call, which the `target_has_max_keys` diagnostic exposes.

**Remediation:** Scope `iam:CreateAccessKey` to the principal's own user ARN (or remove it entirely from non-admin principals). If a break-glass key-rotation workflow is needed, gate the permission through an assumed admin role rather than attaching it directly. Organization-level SCPs denying `iam:CreateAccessKey` on `${aws:PrincipalArn}` inversions are an effective perimeter control. Monitor `CreateAccessKey` calls in CloudTrail with an alert on any call where the subject user is not the caller.

---

### CTL.IAM.ESCALATE.CREATEINSTANCEPROFILE.001

**Principal Must Not Escalate via Instance Profile Creation and Association**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6(5); iso_27001_2022: A.8.3; nist_800_53_r5: AC-6(5); pci_dss_v4.0: 7.2.1; soc2: CC6.1;

Principals with iam:CreateInstanceProfile, iam:AddRoleToInstanceProfile, and ec2:AssociateIamInstanceProfile can escalate by creating a new instance profile, attaching a powerful role, and associating it with an EC2 instance they control. The instance then receives credentials for the powerful role via IMDS. This is distinct from the RunInstances vector (which creates a new instance with a profile) — this vector modifies an existing instance. No iam:PassRole is required for the iam:AddRoleToInstanceProfile step.

**Remediation:** Remove iam:CreateInstanceProfile or ec2:AssociateIamInstanceProfile from the principal. If instance profile management is required, restrict the roles that can be added via IAM policy conditions on iam:AddRoleToInstanceProfile.

---

### CTL.IAM.ESCALATE.CREATELOGINPROFILE.001

**Principal Must Not Escalate via iam:CreateLoginProfile On Another User**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6(5); iso_27001_2022: A.8.3; nist_800_53_r5: AC-6(5); pci_dss_v4.0: 7.2.1; soc2: CC6.1;

A principal with `iam:CreateLoginProfile` whose Resource field reaches another IAM user — one whose attached permissions exceed the principal's own AND who currently has no console login profile — can create a console password for that user and log in as them. Programmatic-only service accounts (no password set) are the specific target: the absence of a login profile is the precondition that makes `CreateLoginProfile` succeed. Once a profile exists, future takeover requires `UpdateLoginProfile` (covered by `CTL.IAM.ESCALATE.UPDATELOGINPROFILE.001`). Rhino Security Labs enumerates this as a distinct technique because the victim population — service accounts that "can't be logged into as" — is often overlooked during permission review.

**Remediation:** Scope `iam:CreateLoginProfile` to the principal's own user ARN (or remove it entirely from non-admin principals). As a defensive measure, apply a service-control policy that denies `iam:CreateLoginProfile` for any user tagged `type = service` or similar. Alert on CloudTrail `CreateLoginProfile` events on long-dormant service users.

---

### CTL.IAM.ESCALATE.CREATEPOLICYVERSION.001

**Principal Must Not Escalate via iam:CreatePolicyVersion + iam:SetDefaultPolicyVersion**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6(5); iso_27001_2022: A.8.3; nist_800_53_r5: AC-6(5); pci_dss_v4.0: 7.2.1; soc2: CC6.1;

A principal with both `iam:CreatePolicyVersion` and `iam:SetDefaultPolicyVersion` on a managed policy attached to itself — directly or via a group it belongs to — can create a new version of that policy granting broader permissions and mark the new version default. Every attached principal, including the one that authored the change, picks up the new effective policy immediately. This is Rhino Security Labs privilege-escalation technique #5 ("IAM — CreatePolicyVersion"). The version mechanism makes the escalation subtle: policy ARN and attachments are unchanged; only the default version pointer moves.

**Remediation:** Remove one of the two permissions from the principal — `CreatePolicyVersion` alone cannot activate a new version, and `SetDefaultPolicyVersion` alone cannot author one. Or scope the Resource of both grants to policies that are not attached to the principal or to groups it belongs to. AWS-managed policies (`arn:aws:iam::aws:policy/*`) cannot have versions created by customer principals; this control specifically targets customer-managed policies.

---

### CTL.IAM.ESCALATE.EDITLAMBDA.001

**Principal Must Not Escalate via Editing Existing Lambda Function**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6(5); iso_27001_2022: A.8.3; nist_800_53_r5: AC-6(5); pci_dss_v4.0: 7.2.1; soc2: CC6.1;

Principals with lambda:UpdateFunctionCode on a function whose execution role exceeds the principal's permissions can escalate by modifying the function's code. The modified code runs under the existing execution role on the next invocation. Unlike PassRole-based Lambda escalation, this technique does not require iam:PassRole — the powerful role is already attached. The attacker only changes what code the role executes. Rhino Security Labs documents this as "EditExistingLambdaFunctionWithRole" and Prowler's iam_policy_allows_privilege_escalation enumerates it.

**Remediation:** Restrict lambda:UpdateFunctionCode to functions whose execution roles do not exceed the principal's permissions, or scope the function's execution role to least privilege. If broader UpdateFunctionCode is required for deployment workflows, add a Lambda resource-based policy denying UpdateFunctionCode from non-deployment principals, or use code signing (CTL.LAMBDA.CODESIGN.ENFORCE.001) to prevent unauthorized code changes.

---

### CTL.IAM.ESCALATE.PASSROLE.CREATEDEVENDPOINT.001

**Principal Must Not Escalate via Glue CreateDevEndpoint Role**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6(5); iso_27001_2022: A.8.3; nist_800_53_r5: AC-6(5); pci_dss_v4.0: 7.2.1; soc2: CC6.1;

Principals with iam:PassRole on a role R plus glue:CreateDevEndpoint can escalate to R's permissions by creating a Glue development endpoint that runs under R and then connecting to its SSH interface. The principal executes arbitrary code on the endpoint under R's authority. When R's effective permissions exceed the principal's own, this is a privilege escalation path. Rhino Security Labs' iam__privesc_scan and Prowler's iam_policy_allows_privilege_escalation both enumerate this technique. SSH public-key registration on the endpoint is captured in the diagnostic fields so an operator can see how the principal would reach the running environment.

**Remediation:** Scope iam:PassRole to a role whose effective permissions do not exceed the principal's, or remove glue:CreateDevEndpoint. If broader endpoint creation is required, enforce a service allowlist on iam:PassRole (`iam:PassedToService == glue.amazonaws.com` plus narrow Resource ARN set) and disable SSH access to dev endpoints via the `PublicKeys` restriction.

---

### CTL.IAM.ESCALATE.PASSROLE.CREATEFUNCTION.001

**Principal Must Not Escalate via Lambda CreateFunction Execution Role**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6(5); iso_27001_2022: A.8.3; nist_800_53_r5: AC-6(5); pci_dss_v4.0: 7.2.1; soc2: CC6.1;

Principals with iam:PassRole on a role R, lambda:CreateFunction, and a path to invoke the function (lambda:InvokeFunction directly, creation of a function URL, or wiring to another trigger) can escalate to R's permissions. The created Lambda executes under R, so any code the principal uploads runs with R's authority. When R's effective permissions exceed the principal's own, this is a privilege escalation path. Rhino Security Labs' iam__privesc_scan and Prowler's iam_policy_allows_privilege_escalation both enumerate this technique. The invocation step is folded into the .present boolean upstream — a CreateFunction grant without any invocation path is not an escalation; the diagnostic fields expose which invocation vector was observed.

**Remediation:** Scope iam:PassRole to a role whose effective permissions do not exceed the principal's, or remove lambda:CreateFunction. If broader function-creation is required for deployment workflows, restrict iam:PassRole with a Condition (`iam:PassedToService == lambda.amazonaws.com` plus a narrowly- scoped Resource ARN set). Alternatively, deny lambda:InvokeFunction and lambda:CreateFunctionUrlConfig on non-admin principals so the created function cannot be triggered.

---

### CTL.IAM.ESCALATE.PASSROLE.CREATEPIPELINE.001

**Principal Must Not Escalate via DataPipeline CreatePipeline Role**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6(5); iso_27001_2022: A.8.3; nist_800_53_r5: AC-6(5); pci_dss_v4.0: 7.2.1; soc2: CC6.1;

Principals with iam:PassRole on a role R plus datapipeline:CreatePipeline and datapipeline:ActivatePipeline can escalate to R's permissions by defining pipeline actions that run under R. The activation step is what triggers execution; creation alone is not sufficient. Both permissions folded into the .present boolean upstream; the diagnostic fields expose which sub-conditions held. Rhino Security Labs' iam__privesc_scan and Prowler's iam_policy_allows_privilege_escalation both enumerate this technique.

**Remediation:** Scope iam:PassRole to a role whose effective permissions do not exceed the principal's, or remove datapipeline:CreatePipeline or datapipeline:ActivatePipeline. If the DataPipeline service is not used, deny the entire datapipeline:* namespace at the SCP level; AWS Data Pipeline is in maintenance mode and new workloads are expected to use Step Functions or Glue instead, so a blanket deny is commonly safe.

---

### CTL.IAM.ESCALATE.PASSROLE.CREATESTACK.001

**Principal Must Not Escalate via CloudFormation CreateStack**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6(5); iso_27001_2022: A.8.3; nist_800_53_r5: AC-6(5); pci_dss_v4.0: 7.2.1; soc2: CC6.1;

Principals with iam:PassRole on a role R plus cloudformation:CreateStack (without a condition that denies CAPABILITY_IAM / CAPABILITY_NAMED_IAM) can escalate to R's permissions by submitting a template that CloudFormation executes under R. When R's effective permissions exceed the principal's own, this is a privilege escalation path. The attacker submits a template that performs IAM mutations (attach user policy, put user policy, create access key), and CloudFormation executes those mutations under R. The principal never gains R directly — but gains R's authority through CloudFormation's template execution.

**Remediation:** Scope iam:PassRole to a role whose effective permissions do not exceed the principal's, or restrict cloudformation:CreateStack with a condition that denies CAPABILITY_IAM / CAPABILITY_NAMED_IAM. Alternatively, remove the escalation-enabling permissions from the target role (iam:PutUserPolicy, iam:AttachUserPolicy, iam:CreateAccessKey, iam:UpdateAssumeRolePolicy).

---

### CTL.IAM.ESCALATE.PASSROLE.RUNINSTANCES.001

**Principal Must Not Escalate via EC2 RunInstances Instance Profile**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6(5); iso_27001_2022: A.8.3; nist_800_53_r5: AC-6(5); pci_dss_v4.0: 7.2.1; soc2: CC6.1;

Principals with iam:PassRole on a role R plus ec2:RunInstances can escalate to R's permissions by launching an EC2 instance with R as its instance profile and executing code on the instance via user-data (first-boot) or direct shell access. When R's effective permissions exceed the principal's own, the running instance can call the IMDS for temporary credentials under R and perform actions the original principal lacks — including IAM mutations if R carries them.

**Remediation:** Scope iam:PassRole to a role whose effective permissions do not exceed the principal's, or remove ec2:RunInstances. If a broader instance-launch capability is required, enforce an instance-profile allowlist via a Condition on iam:PassRole (Condition.StringEquals: iam:PassedToService == ec2.amazonaws.com together with a narrowly-scoped Resource ARN).

---

### CTL.IAM.ESCALATE.PASSROLE.SENDCOMMAND.001

**Principal Must Not Escalate via SSM SendCommand On Privileged Instance**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6(5); iso_27001_2022: A.8.3; nist_800_53_r5: AC-6(5); pci_dss_v4.0: 7.2.1; soc2: CC6.1;

Principals with ssm:SendCommand or ssm:StartSession on an EC2 instance whose attached instance profile role R has broader effective permissions than the principal can escalate to R. The command or interactive session executes on the instance under R (the instance-profile role is the caller from the OS's perspective); IMDS reads from that session return R's temporary credentials. Rhino Security Labs' iam__privesc_scan lists this technique; the iam:PassRole check captured upstream corresponds to whether the principal can also attach alternate instance profiles, which widens the target-role set. Distinct from PASSROLE.RUNINSTANCES, which covers creating a fresh instance with an attacker-chosen profile; this covers exploiting an already-running one.

**Remediation:** Scope ssm:SendCommand and ssm:StartSession to instances whose instance-profile role does not exceed the principal's permissions. Use resource tags plus a Condition on ssm:resourceTag/<key> to bind the principal to a specific instance population. If the principal also has iam:PassRole reaching this or a broader role, also remove that grant — it enables replacing the instance profile entirely.

---

### CTL.IAM.ESCALATE.PUTGROUPPOLICY.001

**Principal Must Not Escalate via iam:PutGroupPolicy On A Belonging Group**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6(5); iso_27001_2022: A.8.3; nist_800_53_r5: AC-6(5); pci_dss_v4.0: 7.2.1; soc2: CC6.1;

A principal with `iam:PutGroupPolicy` whose Resource field includes a group the principal belongs to can write an arbitrary inline policy onto that group. Every member of the group — including the principal — inherits the inline policy immediately. This is Rhino Security Labs privilege-escalation technique #4 ("IAM — Put inline policy on group"). Mirrors PUTUSERPOLICY but via the group hop.
Scope: gated on `identity.kind == "user"`. IAM groups are a user-only concept — roles cannot belong to groups. No role-side analogue exists because AWS IAM does not have role groups.

**Remediation:** Scope `iam:PutGroupPolicy` to groups the principal does not belong to, or remove the permission from non-admin principals. SCP-level deny on `iam:PutGroupPolicy` where the target group contains the calling principal closes the path.

---

### CTL.IAM.ESCALATE.PUTROLEPOLICY.001

**Role Must Not Escalate via iam:PutRolePolicy On Self**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6(5); iso_27001_2022: A.8.3; nist_800_53_r5: AC-6(5); pci_dss_v4.0: 7.2.1; soc2: CC6.1;

A role with `iam:PutRolePolicy` whose Resource field includes its own role ARN can write an arbitrary inline policy onto itself — including one that grants `"Action": "*"` on `"Resource": "*"`. This is the role-side analogue of `CTL.IAM.ESCALATE.PUTUSERPOLICY.001`: distinct AWS action (`iam:PutRolePolicy` vs `iam:PutUserPolicy`), distinct principal kind (role vs user), same one-step escalation outcome. A single `PutRolePolicy` call produces full admin authority without touching any managed policy or other principal. Rhino Security Labs' iam__privesc_scan and Prowler's iam_policy_allows_privilege_escalation both enumerate this technique on roles.

**Remediation:** Remove `iam:PutRolePolicy` from the role, or scope its Resource to role ARNs that do not include the role itself. Organization SCPs denying `iam:PutRolePolicy` on `${aws:PrincipalArn}` close the path at the boundary. A permissions boundary on the role that forbids self-write of inline policies is an additional defensive layer.

---

### CTL.IAM.ESCALATE.PUTUSERPOLICY.001

**Principal Must Not Escalate via iam:PutUserPolicy On Self**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6(5); iso_27001_2022: A.8.3; nist_800_53_r5: AC-6(5); pci_dss_v4.0: 7.2.1; soc2: CC6.1;

A principal with `iam:PutUserPolicy` whose Resource field includes its own user ARN can write an arbitrary inline policy onto itself — including one that grants `"Action": "*"` on `"Resource": "*"`. This is Rhino Security Labs privilege-escalation technique #2 ("IAM — Put inline policy on user") and is covered by Prowler's iam_policy_allows_privilege_escalation and Pacu's iam__privesc_scan. A single PutUserPolicy call produces full admin access without touching any managed policy or group.
Scope: gated on `identity.kind == "user"`. The `iam:PutUserPolicy` AWS action targets users specifically — roles cannot be the self- target. The role-side analogue is `iam:PutRolePolicy` on self, a separate technique that will require its own `CTL.IAM.ESCALATE.PUTROLEPOLICY.001` control in a future iteration.

**Remediation:** Remove `iam:PutUserPolicy` from the principal, or scope the Resource field so the principal cannot include itself. Organization SCPs can deny `iam:PutUserPolicy` on `${aws:PrincipalArn}` to close the path at the boundary.

---

### CTL.IAM.ESCALATE.RESYNCMFADEVICE.001

**Principal Must Not Escalate via iam:ResyncMFADevice On Another User**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6(5); iso_27001_2022: A.8.3; nist_800_53_r5: AC-6(5); pci_dss_v4.0: 7.2.1; soc2: CC6.1;

A principal with `iam:ResyncMFADevice` whose Resource field reaches another IAM user — one whose attached permissions exceed the principal's own — can resynchronize or manipulate that user's MFA device. In combination with a password reset (`iam:UpdateLoginProfile`, covered separately) this clears the MFA barrier on console login; on its own it enables temporary MFA bypass by forcing the device into a resync window where a chosen code pair is accepted. This is one of Rhino Security Labs' credential-manipulation techniques and is covered by Prowler's iam_policy_allows_privilege_escalation and Pacu's iam__privesc_scan. The finding fires whenever the permission reaches a privileged user; whether the attack has already been chained with a password reset is a RiskEngine-level compounding concern, not something the single-resource control gates on.

**Remediation:** Scope `iam:ResyncMFADevice` to the principal's own user ARN (or remove it from non-admin principals). MFA-device management is an admin-role operation; direct user grants for it are rarely intentional. Alert on CloudTrail `ResyncMFADevice` events where the subject user differs from the caller.

---

### CTL.IAM.ESCALATE.STARTBUILD.001

**Principal Must Not Escalate via CodeBuild Source Injection**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6(5); iso_27001_2022: A.8.3; nist_800_53_r5: AC-6(5); pci_dss_v4.0: 7.2.1; soc2: CC6.1;

Principals with codebuild:StartBuild on project P, plus write access to P's source repository (CodeCommit push, S3 PutObject on source bucket, or external Git write) or the ability to override P's buildspec on invocation, can escalate to P's service role by injecting a malicious buildspec. The buildspec runs inside CodeBuild under P's service role and can perform any action the role is authorised for. This vector does not require iam:PassRole — the service role is already attached to the project; the attacker only needs to change what it executes.

**Remediation:** Remove the principal's write access to the source that feeds the project, or remove codebuild:StartBuild from the principal, or reduce the project's service role to permissions that do not exceed the principal's. If source-write is intentional (as in developer workflows), scope the project's service role narrowly and rely on source-approval controls (e.g., CodeCommit approval rules) before a build can run.

---

### CTL.IAM.ESCALATE.UPDATEDEVENDPOINT.001

**Principal Must Not Escalate via Updating Existing Glue Dev Endpoint**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6(5); iso_27001_2022: A.8.3; nist_800_53_r5: AC-6(5); pci_dss_v4.0: 7.2.1; soc2: CC6.1;

Principals with glue:UpdateDevEndpoint on an existing Glue development endpoint can replace the SSH public key and connect to the endpoint. The endpoint runs under its attached IAM role. If the role's permissions exceed the principal's, this is a privilege escalation path. Unlike PassRole-based Glue escalation (which creates a new endpoint), this technique modifies an existing one — no iam:PassRole required. Rhino Security Labs documents this as "UpdateExistingGlueDevEndpoint". Note: AWS deprecated Glue dev endpoints in favor of interactive sessions, but existing endpoints remain operational.

**Remediation:** Remove glue:UpdateDevEndpoint from the principal, or reduce the endpoint's IAM role to least privilege. If the endpoint is no longer needed, delete it — AWS deprecated Glue dev endpoints in favor of interactive sessions. For active endpoints, restrict glue:UpdateDevEndpoint via IAM policy conditions.

---

### CTL.IAM.ESCALATE.UPDATELOGINPROFILE.001

**Principal Must Not Escalate via iam:UpdateLoginProfile On Another User**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6(5); iso_27001_2022: A.8.3; nist_800_53_r5: AC-6(5); pci_dss_v4.0: 7.2.1; soc2: CC6.1;

A principal with `iam:UpdateLoginProfile` whose Resource field reaches another IAM user — one whose attached permissions exceed the principal's own — can reset that user's console password to a chosen value and log in as them. MFA enrollment on the target user is NOT a barrier: an attacker with `iam:ResyncMFADevice` (covered by `CTL.IAM.ESCALATE.RESYNCMFADEVICE.001`) or `iam:DeactivateMFADevice` on the same user can disarm MFA first. This is Rhino Security Labs' credential-manipulation escalation technique and is covered by Prowler's iam_policy_allows_privilege_escalation and Pacu's iam__privesc_scan. The control requires the target user to already have a console login profile; the `CREATELOGINPROFILE.001` control covers the case where the target has no profile and one must be created.

**Remediation:** Scope `iam:UpdateLoginProfile` to the principal's own user ARN (or remove it entirely from non-admin principals). Enforce MFA on all console logins at the account level so password reset alone does not yield a session. Alert on CloudTrail `UpdateLoginProfile` events where the subject user differs from the caller.

---

### CTL.IAM.ESCALATE.UPDATETRUST.001

**Principal Must Not Escalate via iam:UpdateAssumeRolePolicy On A Broader Role**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6(5); iso_27001_2022: A.8.3; nist_800_53_r5: AC-6(5); pci_dss_v4.0: 7.2.1; soc2: CC6.1;

A principal with `iam:UpdateAssumeRolePolicy` reaching a role whose attached permissions exceed its own can rewrite the role's trust policy to admit itself and then call `sts:AssumeRole` to pick up the broader permissions. The update is a single call and leaves the role's permissions unchanged — only the trust-policy pointer moves — which makes the escalation subtle in post-incident review. This is Rhino Security Labs' two-step role-assumption pattern. Listed as a distinct control from CTL.IAM.ESCALATE.ASSUMEROLE.001 because the remediations are different: this control is fixed by removing `iam:UpdateAssumeRolePolicy` from the principal or narrowing its Resource; ASSUMEROLE is fixed by removing `sts:AssumeRole` or narrowing target trust.

**Remediation:** Remove `iam:UpdateAssumeRolePolicy` from the principal, or scope its Resource field to roles whose permissions do not exceed the principal's (role-creation bootstrap roles, for example). At the organization level, deny `iam:UpdateAssumeRolePolicy` on privileged roles via SCP, or enforce a permissions boundary that forbids it. CloudTrail alerting on `UpdateAssumeRolePolicy` calls is an effective detective control while the preventive change lands.

---

### CTL.IAM.FEDERATION.001

**IAM Console Users Should Use Identity Federation**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws: 1.21; nist_800_53_r5: IA-2;

IAM users with console access should authenticate through identity federation rather than IAM-native passwords. Federated authentication centralizes identity management in the organization's identity provider and enforces consistent MFA, password policies, and session controls. IAM-native console users maintain a separate credential that bypasses the organization's identity governance — password resets, MFA enrollment, and access reviews must be managed independently in each AWS account. When console users authenticate directly through IAM, credential lifecycle management fragments across accounts and centralized access revocation requires visiting every account individually. Identity federation eliminates the IAM password as an attack surface and ensures that disabling a user in the identity provider immediately revokes AWS console access.

**Remediation:** Configure identity federation using AWS IAM Identity Center or a direct SAML/OIDC integration with the organization's identity provider. Migrate console users to federated access by creating corresponding identities in the identity provider. After verifying federated access works, remove the IAM console passwords from the migrated users. Retain IAM-native access only for break-glass emergency accounts.

---

### CTL.IAM.IDENTITY.BLASTRADIUS.001

**Role Blast Radius Must Not Exceed Resource Threshold**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6; nist_800_53_r5: AC-6; soc2: CC6.1;

IAM roles must not be able to reach more than 50 resources through direct permissions and transitive role assumption chains. A role with wide blast radius means a single credential compromise gives an attacker access to a large surface area. The extractor computes reachable resources by traversing sts:AssumeRole edges and collecting data access permissions per reachable role.

**Remediation:** Reduce the role's permissions to the minimum set of resources required. Split broad roles into per-service roles with scoped Resource ARNs. Use IAM Access Analyzer to identify unused permissions for removal.

---

### CTL.IAM.IDENTITY.BLASTRADIUS.002

**Cross-Account Role Must Require External ID**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-3; nist_800_53_r5: AC-3; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

IAM roles with cross-account blast radius (can reach resources in other AWS accounts) must require an external ID condition on the trust policy. Without an external ID, any principal in the trusted account can assume the role — including compromised service accounts and test tenants. Combined with cross-account reach, this is the maximum blast radius configuration.

**Remediation:** Add an sts:ExternalId condition to the role trust policy. Restrict the trust to specific role ARNs rather than account-wide principals. Review cross-account access grants for least privilege.

---

### CTL.IAM.IDENTITY.BLASTRADIUS.003

**Role Assume Chain Must Not Exceed Depth Threshold**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6; soc2: CC6.1;

IAM role assumption chains must not exceed 2 hops. Deep chains (Role A assumes Role B which assumes Role C) create hidden transitive access that is difficult to audit and often exceeds the intended permissions of the originating principal. Each hop in the chain potentially widens the blast radius.

**Remediation:** Flatten the role assumption chain. Grant permissions directly to the role that needs them rather than chaining through intermediate roles. Use service-linked roles where possible to avoid manual chain construction.

---

### CTL.IAM.IDENTITY.BLASTRADIUS.004

**Role Must Not Reach Excessive Sensitive Resources**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6(5); hipaa: 164.312(a)(1); nist_800_53_r5: AC-6(5); pci_dss_v4.0: 7.2.2; soc2: CC6.1;

IAM roles must have access to fewer than 20 resources classified as sensitive (PHI, PII, confidential). A role that can reach 85 sensitive resources is a qualitatively different risk than one that reaches 5 — credential compromise exposes a proportionally larger data surface. The extractor counts unique sensitive resources reachable through the role's attached and inline policies.

**Remediation:** Split broad roles into per-service roles scoped to specific resource ARNs. Use IAM Access Analyzer to identify unused permissions on sensitive resources. Apply permissions boundaries that restrict access to classified data.

---

### CTL.IAM.IDENTITY.BLASTRADIUS.005

**User Blast Radius Must Not Exceed Resource Threshold**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6; nist_800_53_r5: AC-6; soc2: CC6.1;

IAM users must not be able to reach more than 50 resources through their attached and inline policies. A user with wide blast radius means a single credential compromise — leaked access keys, phishing, stolen browser session — gives an attacker access to a large surface area. Iski's disclosure (April 2025) demonstrated this: an IAM user (dev-test) with long-term access keys and s3:GetObject / s3:ListBucket across multiple production buckets (vpc-logs-production, user-backups-staging, cdn-assets-public) was the precondition that turned a credential leak in a frontend CSS file into a full data breach. The user was not an admin; the leak was out-of-band from AWS configuration; but the breadth of AWS-side permissions made exploitation trivial. This is the user-kind equivalent of CTL.IAM.IDENTITY.BLASTRADIUS.001 for roles.

**Remediation:** Reduce the user's permissions to the minimum set of resources required. Split broad permissions into scoped Resource ARNs. Move programmatic workloads off long-term user access keys onto service-linked roles or IAM Roles Anywhere. Use IAM Access Analyzer to identify unused permissions for removal.

---

### CTL.IAM.IDENTITY.BLASTRADIUS.006

**User Must Not Reach Excessive Sensitive Resources**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6(5); hipaa: 164.312(a)(1); nist_800_53_r5: AC-6(5); pci_dss_v4.0: 7.2.2; soc2: CC6.1;

IAM users must have access to fewer than 20 resources classified as sensitive (PHI, PII, confidential). A user that can reach 85 sensitive resources is a qualitatively different risk than one that reaches 5 — credential compromise exposes a proportionally larger data surface. This is the user-kind equivalent of CTL.IAM.IDENTITY.BLASTRADIUS.004 for roles. Iski's disclosure (April 2025) showed the Iski pattern: a user with read access to user-backups-staging — which held production database backups and user PII — turned a leaked access key into a full PII breach. The extractor counts unique sensitive resources reachable through the user's attached and inline policies.

**Remediation:** Split broad user permissions into scoped Resource ARNs. Move programmatic access onto service-linked roles with tightly-scoped trust policies. Use IAM Access Analyzer to identify unused permissions on sensitive resources. Apply permissions boundaries that restrict access to classified data.

---

### CTL.IAM.INCOMPLETE.001

**Complete Data Required for IAM Assessment**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** identity

IAM account safety cannot be proven when root account MFA status or access key data is missing from the snapshot. The extractor must populate identity.root.mfa_enabled and identity.root.has_access_keys.

**Remediation:** Re-run the extractor with IAM permissions: iam:GetAccountSummary, iam:GenerateCredentialReport, iam:ListMFADevices.

---

### CTL.IAM.LIST.RESTRICT.001

**IAM Policies Must Not Grant Broad iam:List* Without Scope**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** mitre_attack: T1069.003; nist_800_53_r5: AC-6;

IAM policies must not grant broad iam:List* permissions without resource scope constraints. Unrestricted iam:List* access allows enumeration of all IAM users, roles, groups, and policies in the account. Attackers use this to map the identity surface and identify over-privileged roles or misconfigured trust policies for privilege escalation targeting.

**Remediation:** Scope iam:List* actions to specific resource ARNs. Replace wildcard iam:List* with the specific list actions required by the workload (e.g., iam:ListRolePolicies on a single role ARN). Apply conditions such as aws:ResourceTag to limit enumeration scope.

---

### CTL.IAM.MFA.HWKEY.001

**Privileged Accounts Must Use Hardware MFA**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v3.0: 1.6; fedramp_moderate: IA-2(1); gdpr: Art.32; hipaa: 164.312(d); iso_27001_2022: A.8.5; nist_800_53_r5: IA-2(1); nist_csf_2.0: PR.AA; pci_dss_v4.0: 8.3.1; soc2: CC6.1;

IAM users with admin access must use a hardware MFA device (FIDO2, YubiKey, Gemalto), not a virtual MFA app or SMS. Virtual MFA can be compromised through device theft, seed extraction, or SIM swap attacks. Hardware tokens cannot be cloned or phished via device compromise, providing stronger protection for the most privileged identities.

**Remediation:** Replace virtual MFA with a hardware FIDO2 or TOTP device. Remove the existing virtual MFA device and enroll a hardware token via IAM > Users > Security credentials > MFA.

---

### CTL.IAM.NEP.ADMIN.001

**Net Effective Permissions Must Not Include Admin-Equivalent Actions**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6; hipaa: 164.312(a)(1); nist_800_53_r5: AC-6; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

After resolving all policy layers (SCPs, permission boundaries, identity-based policies, explicit denies), a principal not designated as administrative must not have admin-equivalent effective permissions. This is distinct from CTL.IAM.POLICY.ADMIN.001 which checks policy content — this control checks the resolved effective permissions after organizational constraints are applied. A principal may have an AdminAccess policy attached but be effectively constrained by an SCP.

**Remediation:** Review the identity-based policies granting admin-equivalent actions. Apply an SCP or permission boundary to constrain the effective permissions. If the principal requires admin access, tag it with stave/role-type: administrative to document the intent.

---

### CTL.IAM.NEP.BOUNDARY.001

**Permission Boundaries Must Meaningfully Constrain Effective Permissions**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6; nist_800_53_r5: AC-6; soc2: CC6.1;

A principal with a permission boundary must have a boundary that meaningfully constrains its effective permissions. A boundary that allows iam:* or *:* on Resource: * is not a meaningful constraint. A boundary that is broader than the identity-based policy constrains nothing. Both conditions create a false sense of security — the boundary exists but provides no actual restriction.

**Remediation:** Review the permission boundary policy. Narrow it to exclude iam:* and *:* on Resource: *. Ensure the boundary is stricter than the identity-based policies — a boundary that is broader than the identity policy constrains nothing.

---

### CTL.IAM.NEP.ESCALATION.001

**No Principal May Have Net Effective Permissions to Escalate Privileges**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v3.0: 1.16; fedramp_moderate: AC-6; hipaa: 164.312(a)(1); nist_800_53_r5: AC-6; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

After resolving all policy layers including transitive role assumption chains, no non-administrative principal may have effective permissions to escalate beyond their intended privilege scope. Escalation is detected in two forms: direct escalation primitives (iam:CreatePolicyVersion, iam:AttachRolePolicy, etc.) in the resolved effective allow set, and transitive escalation through role chains that reach higher privilege levels than the principal's direct permissions. A developer role that can assume a pipeline role that can assume an admin role has effective admin access — neither individual role appears dangerous, but the chain is the finding.

**Remediation:** For direct primitives: remove or scope the escalation action to specific resource ARNs. For transitive chains: remove the sts:AssumeRole grant that enables the chain, or scope it to specific non-admin role ARNs.

---

### CTL.IAM.NEP.PHI.001

**Only Designated Principals May Have Net Effective Access to PHI Resources**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-3; gdpr: Art.32; hipaa: 164.312(a)(1); nist_800_53_r5: AC-3; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

For each resource tagged data-classification: phi, the complete set of principals with resolved effective access — via identity-based policies AND resource-based policies — must be limited to principals designated as PHI-authorized. A non-designated principal with effective read access to PHI data is a breach path regardless of how it was granted. This control resolves the complete multi-layer access picture including identity policies, SCPs, permission boundaries, and resource policies simultaneously. Cross-account resource policy grants on PHI are the highest-severity variant.

**Remediation:** Review the access path. For identity-based grants: restrict the principal's policies or add an SCP denying PHI resource access for non-designated principals. For resource policy grants: update the resource policy to restrict the Principal list to designated role ARNs. For public policies: remove the Principal: * statement.

---

### CTL.IAM.PASSWORD.COMPLEXITY.001

**Password Policy Must Require All Character Types**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v1.4.0: 1.8; fedramp_moderate: IA-5(1); hipaa: 164.312(a)(2)(i); nist_800_53_r5: IA-5(1); pci_dss_v3.2.1: 8.2.3; pci_dss_v4.0: 8.3.6; soc2: CC6.1;

The IAM account password policy must require uppercase, lowercase, numbers, and symbols. Missing any character type requirement reduces the keyspace and makes passwords easier to crack.

**Remediation:** Update the IAM password policy to require all four character types.

---

### CTL.IAM.PASSWORD.LENGTH.001

**Password Minimum Length Must Be At Least 14**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v1.4.0: 1.8; cis_aws_v3.0: 1.8; fedramp_moderate: IA-5(1); ffiec: CAT-D3; hipaa: 164.312(a)(2)(i); iso_27001_2022: A.8.5; nist_800_53_r5: IA-5(1); nist_csf_2.0: PR.AA; pci_dss_v3.2.1: 8.2.3; pci_dss_v4.0: 8.3.6; soc2: CC6.1;

The IAM account password policy must require a minimum password length of 14 characters. Shorter passwords are vulnerable to brute-force and dictionary attacks.

**Remediation:** Update the IAM account password policy to require at least 14 characters. Run: aws iam update-account-password-policy --minimum-password-length 14

---

### CTL.IAM.PASSWORD.REUSE.001

**Password Reuse Prevention Must Be At Least 24**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v1.4.0: 1.9; cis_aws_v3.0: 1.9; fedramp_moderate: IA-5(1); ffiec: ISH-4; hipaa: 164.312(a)(2)(i); iso_27001_2022: A.8.5; nist_800_53_r5: IA-5(1); nist_csf_2.0: PR.AA; pci_dss_v3.2.1: 8.2.5; pci_dss_v4.0: 8.3.7; soc2: CC6.1;

The IAM account password policy must prevent reuse of the last 24 passwords. Without reuse prevention, users cycle between a small set of passwords, negating the value of password rotation.

**Remediation:** Update the IAM password policy to prevent reuse of the last 24 passwords. Run: aws iam update-account-password-policy --password-reuse-prevention 24

---

### CTL.IAM.PASSWORD.ROTATION.001

**User Passwords Must Be Rotated Within Policy Period**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v3.0: 1.12; fedramp_moderate: IA-5(1); hipaa: 164.312(a)(2)(i); nist_800_53_r5: IA-5(1); pci_dss_v4.0: 8.3.9; soc2: CC6.1;

IAM user console passwords must be rotated per organizational policy (typically 90 days). The credential report tracks password_last_changed; passwords older than the policy period have accumulated exposure risk and may have been shared, phished, or brute-forced. This complements access key rotation (CTL.IAM.CRED.ROTATION.001) to cover the full credential lifecycle.

**Remediation:** Require the user to change their password. Enforce a maximum password age via the account password policy. Run: aws iam update-account-password-policy --max-password-age 90

---

### CTL.IAM.POLICY.ADMIN.001

**No Full Admin Policies Attached**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v3.0: 1.16; fedramp_moderate: AC-6; ffiec: CAT-D3; gdpr: Art.32; iso_27001_2022: A.8.3; nist_800_53_r5: AC-6; nist_csf_2.0: PR.AA; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

No IAM policy with Effect Allow on Action "*" and Resource "*" should be attached to any IAM entity. Full admin policies violate least privilege and grant unrestricted access to all services.

**Remediation:** Replace wildcard admin policies with scoped policies granting only the specific permissions required. Use AWS Access Analyzer to generate least-privilege policies from CloudTrail activity.

---

### CTL.IAM.POLICY.ASSUMEROLE.001

**AssumeRole Must Be Scoped to Specific Roles**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6; nist_800_53_r5: AC-6; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

sts:AssumeRole permissions must be scoped to specific role ARNs, not wildcard Resource *. With unrestricted AssumeRole, a compromised identity can assume any role in the account — including admin roles, cross-account trust roles, and service roles with elevated permissions. This is a direct privilege escalation path.

**Remediation:** Restrict sts:AssumeRole to specific role ARNs in the Resource field. Use IAM conditions like aws:PrincipalTag to further limit which roles can be assumed.

---

### CTL.IAM.POLICY.CLOUDSHELL.001

**Restrict AWSCloudShellFullAccess**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v3.0: 1.22; soc2: CC6.3;

The AWSCloudShellFullAccess managed policy should not be attached to any IAM entity unless specifically required. CloudShell provides a browser-based shell that can bypass network-level controls.

**Remediation:** Detach AWSCloudShellFullAccess from all IAM users, groups, and roles that do not require it.

---

### CTL.IAM.POLICY.COMPLEXITY.001

**IAM Policy Complexity Must Be Bounded**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6; nist_800_53_r5: AC-6; soc2: CC6.1;

IAM policies with more than 25 statements indicate excessive complexity that increases misconfiguration risk. Complex policies are harder to audit, more likely to contain shadowed statements or contradictory rules, and resist review. Policy complexity is itself a risk factor — it obscures the effective permissions and makes least-privilege verification impractical.

**Remediation:** Refactor complex policies into smaller, focused policies scoped to specific services. Use policy conditions and resource-scoped statements instead of many broad statements. Consider using AWS managed policies where appropriate.

---

### CTL.IAM.POLICY.DIRECT.001

**No Direct Policy Attachment on IAM Users**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v1.4.0: 1.15; cis_aws_v3.0: 1.15; fedramp_moderate: AC-6; ffiec: CAT-D3; gdpr: Art.32; hipaa: 164.312(a)(1); iso_27001_2022: A.8.2; nist_800_53_r5: AC-6; nist_csf_2.0: PR.AA; pci_dss_v4.0: 7.2.2; soc2: CC6.3;

IAM users must not have managed policies attached directly. Policies should be attached to groups or roles, not individual users. Direct attachment creates unmanageable per-user permission sprawl.

**Remediation:** Create IAM groups with the required policies and add the user to the appropriate groups. Remove directly attached policies from the user.

---

### CTL.IAM.POLICY.ESCALATION.001

**IAM Policies Must Not Grant Self-Modification**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6; iso_27001_2022: A.8.3; nist_800_53_r5: AC-6; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

IAM policies must not grant the ability to modify, create, or attach policies to the principal's own role or user. Permissions like iam:CreatePolicyVersion, iam:AttachRolePolicy, and iam:PutRolePolicy scoped to self enable privilege escalation — a compromised identity can grant itself full admin access without needing any other vulnerability.

**Remediation:** Remove iam:CreatePolicyVersion, iam:AttachRolePolicy, and iam:PutRolePolicy permissions from non-admin roles. Use SCPs to deny self-modification at the organization level.

---

### CTL.IAM.POLICY.GHOSTREF.001

**IAM Policies Must Not Reference Non-Existent Resources**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-3; nist_800_53_r5: AC-6; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

All fully-qualified non-wildcard ARNs in IAM policy Allow statements must resolve to resources present in the snapshot inventory. A dangling reference — an Allow statement granting permissions on a resource that no longer exists — is a persistence mechanism waiting to be exploited. An attacker who can create a resource with the same name inherits all permissions that reference it. For S3 buckets, which have globally unique names and no account-scoped protection, this is an active supply chain takeover vector. This control cross-references the IAM policy ARN inventory against the resource inventory and only fires when snapshot completeness for the relevant resource types is confirmed.

**Remediation:** Remove or update Allow statements referencing ARNs for resources that no longer exist. If the resource was intentionally deleted, remove the policy statement. If the resource was renamed, update the ARN.

---

### CTL.IAM.POLICY.GHOSTREF.002

**Write-Permission Dangling References Are Critical Severity**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-3; gdpr: Art.32; hipaa: 164.312(a)(1); nist_800_53_r5: AC-3; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

IAM policy Allow statements granting write permissions to non-existent reclaimable resource names are an active exfiltration path. The victim's systems attempt to write to the resource — if an attacker registers the name, data flows directly to attacker-controlled infrastructure. S3 bucket ARNs contain no account ID and are globally reclaimable. Write-class permissions (PutObject, SendMessage, Publish, PutRecord) on non-existent S3 buckets, SQS queues, SNS topics, and Kinesis streams are the highest-severity ghost reference findings. This control only evaluates ARN types with confirmed complete collection in the snapshot.

**Remediation:** Remove write-permission Allow statements referencing non-existent resources. For S3 buckets, re-create the bucket in the account before an attacker claims the name, or remove the policy statement entirely.

---

### CTL.IAM.POLICY.GHOSTREF.003

**Dangling KMS Key References Must Not Exist in Active Policies**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-12; hipaa: 164.312(a)(2)(iv); nist_800_53_r5: SC-12; pci_dss_v4.0: 3.6.1; soc2: CC6.7;

IAM policies granting KMS permissions must only reference KMS key ARNs in enabled status. A policy referencing a pending-deletion or deleted KMS key means systems depending on that policy for encrypt/decrypt operations will fail silently — data integrity violations for PHI workloads. KMS key ARNs include the account ID and a random key ID so they cannot be claimed cross-account, but the operational impact of referencing a non-functional key is a direct compliance failure.

**Remediation:** Cancel the key deletion if the key is still needed, or remove the KMS permissions from the policy. If a replacement key exists, update the policy to reference the new key ARN.

---

### CTL.IAM.POLICY.INLINE.001

**No Inline Policies on IAM Users**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v1.4.0: 1.15; cis_aws_v3.0: 1.15; fedramp_moderate: AC-6; ffiec: CAT-D3; gdpr: Art.32; hipaa: 164.312(a)(1); iso_27001_2022: A.8.2; nist_800_53_r5: AC-6; nist_csf_2.0: PR.AA; pci_dss_v4.0: 7.2.2; soc2: CC6.3;

IAM users must not have inline policies attached directly. Inline policies are harder to audit, cannot be reused, and create per-user policy sprawl that resists central governance.

**Remediation:** Convert inline policies to managed policies and attach via groups or roles. Delete the inline policies from the user.

---

### CTL.IAM.POLICY.INLINE.002

**No Inline Policies on IAM Roles**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 1.16; nist_800_53_r5: AC-2; soc2: CC6.1;

IAM roles must not have inline policies attached. Inline policies are embedded directly in the role and cannot be versioned, audited, or reused independently. They create shadow permission grants that are invisible to policy-listing tools that only enumerate managed policies. Use managed policies attached to the role instead. CTL.IAM.POLICY.INLINE.001 enforces this for users; this control enforces it for roles.

**Remediation:** Convert inline policies to managed policies. Use aws iam list-role-policies to enumerate inline policies, then aws iam create-policy to create equivalent managed policies, attach them, and delete the inline policies.

---

### CTL.IAM.POLICY.MFA.001

**Destructive Actions Must Require MFA**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v3.0: 1.4; fedramp_moderate: IA-2(1); hipaa: 164.312(d); nist_800_53_r5: IA-2(1); pci_dss_v4.0: 8.4.1; soc2: CC6.1;

IAM policies governing destructive operations (s3:DeleteBucket, iam:CreateUser, ec2:TerminateInstances, etc.) must include an aws:MultiFactorAuthPresent condition. Without policy-level MFA enforcement, a compromised access key alone is sufficient to execute destructive actions — the credential becomes the only barrier between an attacker and data loss.

**Remediation:** Add an aws:MultiFactorAuthPresent condition to IAM policies that permit destructive actions. Example condition block: "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}} Apply to policies covering s3:Delete*, iam:Create*, iam:Delete*, ec2:Terminate*, rds:Delete*, and similar destructive API calls.

---

### CTL.IAM.POLICY.PASSROLE.001

**PassRole Must Be Scoped to Specific Roles**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6; iso_27001_2022: A.8.3; nist_800_53_r5: AC-6; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

iam:PassRole permissions must be scoped to specific role ARNs, not wildcard resource *. PassRole allows a principal to assign an IAM role to an AWS service (Lambda, EC2, ECS). With a wildcard resource, an attacker can pass any role — including highly privileged ones — to a service they control, achieving privilege escalation without directly modifying IAM policies.

**Remediation:** Restrict iam:PassRole to specific role ARNs in the Resource field. Example: arn:aws:iam::123456789012:role/my-lambda-role. Use IAM conditions like iam:PassedToService to further limit which services can receive the role.

---

### CTL.IAM.POLICY.PASSROLE.CONDITION.001

**PassRole Must Have iam:PassedToService Condition**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6(5); iso_27001_2022: A.8.3; nist_800_53_r5: AC-6(5); pci_dss_v4.0: 7.2.1; soc2: CC6.1;

IAM policies granting iam:PassRole must include an iam:PassedToService condition restricting which AWS service can receive the passed role. Without this condition, a principal can pass a role to any compute service — Lambda, EC2, Glue, CodeBuild, CloudFormation, SSM — regardless of Resource scope. A role scoped to specific ARNs but passable to any service still enables lateral movement: the principal picks whichever service gives the most convenient execution environment.

**Remediation:** Add an iam:PassedToService condition to the PassRole statement. Example: "Condition": {"StringEquals": {"iam:PassedToService": "lambda.amazonaws.com"}}. Restrict to only the service(s) the principal legitimately uses.

---

### CTL.IAM.POLICY.RESOURCE.WILDCARD.001

**Sensitive Actions Must Not Use Resource Wildcard**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-6; nist_800_53_r5: AC-6; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

IAM policies granting sensitive actions (s3:*, kms:Decrypt, dynamodb:*, secretsmanager:GetSecretValue, rds:*, ec2:*, lambda:InvokeFunction, sts:AssumeRole) must scope the Resource element to specific ARNs. Resource "*" on sensitive actions grants the action on every resource in the account, vastly exceeding least privilege. CTL.IAM.POLICY.PASSROLE.001 and CTL.IAM.POLICY.ASSUMEROLE.001 enforce resource scoping for PassRole and AssumeRole specifically; this control generalizes the pattern to all sensitive actions.

**Remediation:** Scope the Resource element to specific ARNs or ARN patterns. For example, restrict s3:* to specific bucket ARNs, kms:Decrypt to specific key ARNs, and lambda:InvokeFunction to specific function ARNs.

---

### CTL.IAM.POLICY.SERVICEWILDCARD.001

**No Service-Wildcard Grants on Denied Services**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6(5); iso_27001_2022: A.8.3; nist_800_53_r5: AC-6(5); pci_dss_v4.0: 7.2.1; soc2: CC6.1;

IAM users and roles must not have any attached policy (inline or customer-managed) that grants `<service>:*` on `Resource: "*"` for services on the denied list. Service-wildcard grants are scoped to a single service but still exceed least-privilege for high-blast-radius services. The default denied list covers three Prowler-flagged services:

  - cloudtrail: enables trail tampering (StopLogging,
    DeleteTrail), log-tamper vector — upstream checks
    `iam_inline_policy_no_full_access_to_cloudtrail` and
    `iam_policy_no_full_access_to_cloudtrail`.
  - kms: enables full key management (ScheduleKeyDeletion,
    ReEncrypt, DisableKey), key-tamper vector — upstream checks
    `iam_inline_policy_no_full_access_to_kms` and
    `iam_policy_no_full_access_to_kms`.
  - aws-marketplace: enables unauthorized resource provisioning
    with direct billing impact — upstream checks
    `iam_inline_policy_no_wildcard_marketplace_subscribe` and
    `iam_policy_no_wildcard_marketplace_subscribe`.

Operators extend the denied list via `params.denied_service_wildcards` as new service-wildcard abuse patterns emerge. The control does not fire on principals with no attached policies — the field `identity.policies.service_wildcards_granted` is `null` in that case and the `present` gate keeps the check silent.

**Remediation:** Replace the `<service>:*` Action with the minimum specific actions the principal actually needs (e.g., `cloudtrail:LookupEvents` for read-only audit, `kms:Decrypt` + `kms:GenerateDataKey` for data access). If the principal legitimately needs broad service authority, narrow `Resource` to specific ARNs rather than `"*"`. For admin personas, use AWS-managed admin policies governed by `CTL.IAM.POLICY.ADMIN.001` instead of per-service wildcard grants.

---

### CTL.IAM.POLICY.SHADOW.001

**IAM Policy Must Not Use NotAction Construct**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6; nist_800_53_r5: AC-6; soc2: CC6.1;

IAM policies using NotAction or NotResource create negative logic that is prone to bypass. A NotAction policy says "allow everything EXCEPT these actions" — but the list of excepted actions rarely covers all dangerous permissions. New AWS services and actions are automatically allowed by the implicit "everything else" grant. Attackers exploit this shadow effect to find actions like iam:PutRolePolicy that fall through the negative logic gap.

**Remediation:** Replace NotAction with an explicit Allow list. Enumerate the specific actions needed and grant only those. Negative logic is prone to bypass as new AWS services and actions are added.

---

### CTL.IAM.POLICY.SHADOW.002

**Negative Logic Must Not Permit IAM Write Actions**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6(5); nist_800_53_r5: AC-6(5); soc2: CC6.1;

IAM policies using NotAction that allow IAM write actions (iam:PutRolePolicy, iam:CreateUser, iam:AttachRolePolicy) through the negative logic gap are a critical privilege escalation vector. The extractor resolves the effective permissions of NotAction policies and flags when dangerous IAM write actions fall through.

**Remediation:** Replace the NotAction policy with an explicit allow list. Ensure iam:PutRolePolicy, iam:CreateUser, iam:AttachRolePolicy, and iam:CreatePolicyVersion are explicitly denied or absent from the allowed actions.

---

### CTL.IAM.POLICY.SOD.001

**IAM Roles Must Not Combine Data Access and IAM Management**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-5; iso_27001_2022: A.8.3; nist_800_53_r5: AC-5; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

No single IAM role should have both data access permissions (s3:GetObject, dynamodb:GetItem, rds:*, secretsmanager:GetSecretValue) and IAM management permissions (iam:CreateRole, iam:AttachPolicy, iam:CreateUser, iam:PutRolePolicy). Combining these creates a privilege escalation path — a compromised role with data access can grant itself additional permissions. Separation of privileged access is required by IAM-09 in CCM v4.1.

**Remediation:** Split into two roles: one for data access (application role) and one for IAM management (admin role). Use separate assume-role policies for each. Apply the principle of least privilege — data-path roles should never modify IAM.

---

### CTL.IAM.ROLE.BREAKGLASS.001

**Break-Glass Elevated Roles Must Not Persist**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-2; nist_800_53_r5: AC-2; soc2: CC6.1;

IAM roles granted elevated permissions for incident response (break-glass access) must be revoked within 7 days. Elevated roles that persist beyond the incident become permanent backdoors — they carry admin-level permissions with no active justification. Debug rules, elevated roles, and emergency access must have mandatory time-bounding.

**Remediation:** Revoke the elevated role or revert its permissions to the pre-incident baseline. Implement automated expiry via STS session policies or Lambda-based role revocation. Tag elevated roles with grant timestamp and incident ID for tracking.

---

### CTL.IAM.ROLE.CATEGORYMIX.001

**Roles Must Not Span Incompatible Permission Categories**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-5; iso_27001_2022: A.8.3; nist_800_53_r5: AC-5; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

IAM roles must not combine permissions from structurally incompatible categories. A role with data_read + iam_write can access data AND modify who else can access it. A role with compute_control + iam_write can create compute AND grant it permissions (Shadow Admin escalation). A role with audit_control + data_read can access data AND cover tracks. No single permission is alarming. The combination is catastrophic. The extractor categorizes permissions against a defined taxonomy and flags roles that span incompatible pairs: data+iam_write, data+secrets, compute+iam_write, audit_control+sensitive, crypto_control+data.

**Remediation:** Split the role into separate roles with narrowly scoped permissions. Data access roles must not have IAM write permissions. Compute roles must not have IAM write permissions. Audit control roles must not have data access permissions. Use separate roles with separate trust policies for each function.

---

### CTL.IAM.ROLE.ENTROPY.INCOMPLETE.001

**Complete Data Required for Entitlement Entropy Assessment**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** identity

Access Advisor data, permission policy inventory, or tag inventory is absent from the snapshot. Without this data, permission drift, category mixing, and intent mismatch controls cannot evaluate. Re-run the extractor with iam:GenerateServiceLastAccessedDetails, iam:GetServiceLastAccessedDetails, iam:ListAttachedRolePolicies, iam:ListRolePolicies, and iam:ListRoleTags permissions.

**Remediation:** Re-run the extractor with permissions to collect Access Advisor data (iam:GenerateServiceLastAccessedDetails, iam:GetServiceLastAccessedDetails), policy inventory (iam:ListAttachedRolePolicies, iam:ListRolePolicies), and tags (iam:ListRoleTags).

---

### CTL.IAM.ROLE.INTENTMISMATCH.001

**Role Permissions Must Match Declared Purpose**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6; nist_800_53_r5: AC-6; pci_dss_v4.0: 7.2.1; soc2: CC6.3;

The permission categories present on a role must be consistent with its declared role-type tag. A role tagged readonly must not have iam_write or compute_control permissions. A role tagged application must not have iam_write or network_control permissions. The extractor computes intent_mismatch by comparing the role's actual permission categories against the compatibility matrix for its declared role-type. Requires CTL.IAM.ROLE.INTENTTAG.001 to pass first — if role-type is absent, this control cannot evaluate.

**Remediation:** Review the forbidden permission categories listed in this finding. Either remove the permissions that contradict the declared purpose, or update the role-type tag to accurately reflect the role's actual function. If the role legitimately needs cross-category permissions, consider splitting it into separate roles.

---

### CTL.IAM.ROLE.INTENTTAG.001

**Roles Must Have a Declared Purpose Tag**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: CM-8; nist_800_53_r5: CM-8; soc2: CC6.3;

All IAM roles must have a role-type tag with a value from the defined taxonomy (application, data-pipeline, readonly, admin, security, ci-cd, break-glass, service-account). Without a declared purpose, access reviews cannot systematically verify whether a role's permissions match its intent. A missing tag means no one has formally declared what this role is supposed to do. The role-type tag is the machine-readable anchor for intent-versus-permissions checking.

**Remediation:** Add a role-type tag with one of: application, data-pipeline, readonly, admin, security, ci-cd, break-glass, service-account. Choose the value that best describes the role's intended function.

---

### CTL.IAM.ROLE.PERMISSIONDRIFT.001

**Roles Must Not Accumulate Unused Permissions**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v3.0: 1.12; fedramp_moderate: AC-2; hipaa: 164.312(a)(2)(i); nist_800_53_r5: AC-2; pci_dss_v4.0: 8.1.4; soc2: CC6.3;

IAM roles must not retain access to services that have never been used or were last used more than 90 days ago, when the role itself has been active for more than 90 days. A role with 30 accessible services where 25 are never used has accumulated permissions far beyond its operational scope. An attacker who compromises this role has access to 30 services but the legitimate owner only uses 5. The unused 25 are the hidden blast radius. Access Advisor data from AWS provides exact timestamps of last permission use — this is an operational fact, not a security assertion.

**Remediation:** Review the unused service namespaces listed in this finding. Remove permissions for services that are no longer needed. For services that are intentionally retained for emergency use, set the stave/permission-drift-threshold tag on the role to document the justified exception (e.g., stave/permission-drift-threshold=0.40).

---

### CTL.IAM.ROOT.ACCESSKEY.001

**Root Account Must Not Have Access Keys**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v1.4.0: 1.4; cis_aws_v3.0: 1.4; fedramp_moderate: IA-2; hipaa: 164.312(a)(1); nist_800_53_r5: IA-2; pci_dss_v3.2.1: 2.1; pci_dss_v4.0: 8.3.4; soc2: CC6.1;

The AWS root account must not have active access keys. Root access keys provide unrestricted programmatic access. Use IAM users or roles for programmatic access instead.

**Remediation:** Delete the root access keys. Create IAM users or roles with least-privilege policies for programmatic access.

---

### CTL.IAM.ROOT.HWMFA.001

**Root Account Must Use Hardware MFA**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v3.0: 1.6; fedramp_moderate: IA-2(1); ffiec: CAT-D3; gdpr: Art.32; iso_27001_2022: A.8.5; nist_800_53_r5: IA-2(1); nist_csf_2.0: PR.AA; pci_dss_v4.0: 8.3.1; soc2: CC6.1;

The root account must use a hardware MFA device, not a virtual one. Hardware tokens cannot be cloned or phished via device compromise, providing stronger protection for the most privileged identity.

**Remediation:** Replace the virtual MFA with a hardware TOTP device (YubiKey, Gemalto) in the IAM console under Security Credentials.

---

### CTL.IAM.ROOT.MFA.001

**Root Account Must Have MFA Enabled**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v1.4.0: 1.5; cis_aws_v3.0: 1.5; fedramp_moderate: IA-2(1); ffiec: CAT-D3; gdpr: Art.32; hipaa: 164.312(d); iso_27001_2022: A.8.5; nist_800_53_r5: IA-2(1); nist_csf_2.0: PR.AA; pci_dss_v3.2.1: 8.3; pci_dss_v4.0: 8.3.1; soc2: CC6.1;

The AWS root account must have multi-factor authentication enabled. Root has unrestricted access to all resources. Compromise without MFA is the highest-severity identity risk.

**Remediation:** Enable MFA on the root account using a hardware MFA device or virtual MFA app. Navigate to IAM > Security credentials > MFA.

---

### CTL.IAM.ROOT.RECUR.001

**Root Account Must Not Be Used Repeatedly**

- **Severity:** critical
- **Type:** unsafe_recurrence
- **Domain:** identity
- **Compliance:** cis_aws_v3.0: 1.7; fedramp_moderate: AC-2; hipaa: 164.312(a)(2)(i); nist_800_53_r5: AC-2; pci_dss_v4.0: 8.1.1; soc2: CC7.1;

Root account API activity has occurred more than once in 30 days. A single root usage may be a legitimate break-glass event. Two or more usages within a month requires investigation — either the organization has not addressed the process that led to the first usage, or root credentials have been compromised and are being actively used.

**Remediation:** Investigate the root cause of the repeated oscillation. Determine whether the pattern indicates a broken process, operational workaround, or active compromise. Review CloudTrail for the API calls that triggered each transition.

---

### CTL.IAM.ROOT.USAGE.001

**Root Account Must Not Be Used for Daily Tasks**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v3.0: 1.7; fedramp_moderate: AC-2; nist_800_53_r5: AC-2; pci_dss_v4.0: 8.1.1; soc2: CC6.2;

The root account must not be used for day-to-day operations. Root activity should be limited to account setup tasks. Recent root usage indicates operational reliance on root credentials.

**Remediation:** Create IAM admin users or roles for daily operations. Lock root credentials and use them only for account-level tasks.

---

### CTL.IAM.SCP.CREATEACCOUNT.001

**SCPs Must Restrict Unauthorized IAM User and Account Creation**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-2; hipaa: 164.312(a)(2)(i); iso_27001_2022: A.8.2; nist_800_53_r5: AC-2; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

AWS Organizations must have an SCP restricting who can create IAM users (iam:CreateUser) and new AWS accounts (organizations:CreateAccount). Without this restriction, any principal with these permissions can create persistent identities that survive credential rotation and incident response. MITRE ATT&CK T1136/T1136.003 documents account creation as a primary persistence technique after initial compromise. An attacker-created IAM user has separate credentials unknown to the incident response team. An attacker-created AWS account starts with no monitoring infrastructure deployed — a fresh environment inside the organization's trust boundary but outside its detection field.

**Remediation:** Attach an SCP to the organization root with Deny statements on iam:CreateUser and organizations:CreateAccount. Use conditions to allow only authorized principals (e.g., a specific CI/CD role or identity management role) to perform these actions. Verify the conditions cannot be trivially satisfied by an attacker's existing permissions.

---

### CTL.IAM.SCP.DANGEROUS.ALLOWS.001

**SCPs Must Not Explicitly Allow Dangerous Administrative Actions**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6; iso_27001_2022: A.8.3; nist_800_53_r5: AC-6; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

SCPs must not contain Allow statements for actions that undermine the organization's security posture: audit evasion (DeleteTrail, StopLogging, DeleteDetector), data destruction (DeleteBucket, ScheduleKeyDeletion), boundary removal (DeletePolicy, DetachPolicy), or privilege escalation (CreatePolicyVersion, AttachRolePolicy). An Allow for these actions signals that someone has deliberately removed the organizational-level protection. To determine when the Allow was introduced, run stave bisect with this control against the snapshot archive.

**Remediation:** Remove the Allow statements for dangerous actions from the SCP. If the actions are legitimately needed, scope them to specific resources or conditions rather than blanket Allow. Use stave bisect to determine when the Allow statement was introduced.

---

### CTL.IAM.SCP.FULLACCESS.001

**Organizations Must Not Rely Solely on FullAWSAccess SCP**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6; iso_27001_2022: A.8.3; nist_800_53_r5: AC-6; nist_csf_2.0: PR.AA; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

AWS Organizations must have restrictive Service Control Policies beyond the default FullAWSAccess SCP. An organization that only has FullAWSAccess applied has no organizational guardrails — any IAM permission granted within a member account is allowed, including access to unused services that expand the attack surface.

**Remediation:** Create restrictive SCPs that deny unused services and dangerous actions. Apply them to organizational units. Keep FullAWSAccess on the root but add deny-based SCPs to OUs that restrict the effective permissions.

---

### CTL.IAM.SCP.OU.COVERAGE.001

**Production OUs Must Have Restrictive SCPs**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6; iso_27001_2022: A.8.22; nist_800_53_r5: AC-6; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

Safety mechanism integrity control. Checks that security guardrails are actively enforcing, not just present.

**Remediation:** Review the specific guardrail identified in this finding and restore it to an enforcing state.

---

### CTL.IAM.SCP.TRAIL.PROTECT.001

**SCPs Must Deny CloudTrail Disruption Actions**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AU-9; nist_800_53_r5: AU-9; soc2: CC7.1;

Service Control Policies must deny cloudtrail:StopLogging, cloudtrail:DeleteTrail, and cloudtrail:UpdateTrail to non- breakglass roles. Without these protective denies, any IAM principal with sufficient permissions can disrupt logging.

**Remediation:** Create an SCP with Effect Deny on cloudtrail:StopLogging, cloudtrail:DeleteTrail, and cloudtrail:UpdateTrail. Add a Condition excluding the breakglass role ARN.

---

### CTL.IAM.SUPPORT.001

**AWS Support Role Must Exist**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v3.0: 1.17;

At least one IAM entity must have the AWSSupportAccess managed policy attached. This ensures someone can open support cases during security incidents without using root.

**Remediation:** Create an IAM role with the AWSSupportAccess policy: aws iam attach-role-policy --role-name SupportRole --policy-arn arn:aws:iam::aws:policy/AWSSupportAccess

---

### CTL.IAM.TRUST.CONFUSEDDEPUTY.001

**Third-Party Role Trust Must Have Confused Deputy Protection**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-3; hipaa: 164.312(a)(1); iso_27001_2022: A.8.3; nist_800_53_r5: AC-3, AC-6; pci_dss_v4.0: 7.2.1; soc2: CC6.1, CC9.2;

IAM roles trusted by third-party AWS accounts (accounts outside your organization) must include sts:ExternalId or aws:SourceAccount conditions. Without these guardrails, the confused deputy problem allows any customer of the same third-party vendor to assume your role through the vendor's IAM system. The Microsoft Midnight Blizzard 2024 breach exploited a legacy cross-tenant trust without per-customer binding to pivot from a test tenant to production Exchange mailboxes. Coupa/Corecard-pattern SaaS integrations with shared IAM roles and no ExternalId allow cross-customer data access if the vendor's IAM system is compromised.

**Remediation:** Add an sts:ExternalId condition with a unique per-relationship value to the role trust policy. Alternatively, add aws:SourceAccount scoped to the specific account that should be permitted. Do not use wildcard values — ExternalId set to * provides no protection.

---

### CTL.IAM.TRUST.EXTERNALID.001

**Cross-Account Trust Must Require External ID**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-3; iso_27001_2022: A.8.3; nist_800_53_r5: AC-3; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

IAM roles with cross-account trust policies must include an sts:ExternalId condition. Without an external ID, any principal in the trusted account can assume the role — including compromised service accounts, OAuth applications, or test tenants. The Microsoft Midnight Blizzard 2024 breach exploited a legacy test OAuth app to assume a role with full_access_as_app permissions, pivoting from a test tenant to production Exchange mailboxes.

**Remediation:** Add an sts:ExternalId condition to the role trust policy. Generate a unique external ID per trust relationship. Verify the assuming application passes the correct external ID.

---

### CTL.IAM.TRUST.OIDC.001

**OIDC Federation Trust Must Be Scoped to Specific Repository**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-3; nist_800_53_r5: AC-3; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

IAM roles that trust OIDC identity providers (GitHub Actions, GitLab CI, Bitbucket Pipelines) must restrict the subject claim to a specific repository and branch. A trust policy that accepts any repository from the provider allows any project in the provider's namespace to assume the role — a compromised or malicious repository becomes a production ingress path.

**Remediation:** Add a StringEquals or StringLike condition on the sub claim to restrict to specific repositories and branches. Example for GitHub Actions: "token.actions.githubusercontent.com:sub": "repo:org/repo:ref:refs/heads/main"

---

### CTL.IAM.TRUST.OIDC.002

**OIDC Federation Must Not Use Wildcard Subject Claim**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6; nist_800_53_r5: AC-6; soc2: CC6.1;

IAM roles with OIDC federation must use exact or prefix-scoped subject claims. A wildcard sub condition ("*") defeats the purpose of OIDC federation — it accepts any identity from the provider, including pull request workflows from forks, ephemeral runners, and compromised pipelines. This is the supply chain equivalent of s3:* on Resource "*".

**Remediation:** Replace the wildcard with an exact subject match. For GitHub Actions: "repo:myorg/myrepo:ref:refs/heads/main". For GitLab CI: "project_path:mygroup/myproject:ref_type:branch:ref:main".

---

### CTL.IAM.TRUST.OIDC.003

**OIDC Federation Role Must Have Scoped Permissions**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6(5); soc2: CC6.1;

IAM roles assumed via OIDC federation (CI/CD pipelines) must have scoped permissions appropriate for their deployment task. A CI/CD role with AdministratorAccess or broad wildcard actions creates a supply chain blast radius — any compromise of the CI/CD pipeline grants full account access. The extractor checks if the role's effective permissions exceed a deployment-appropriate scope.

**Remediation:** Scope the role's permissions to the minimum required for the deployment task. Replace AdministratorAccess with task-specific policies (e.g., s3:PutObject on the deployment bucket, ecs:UpdateService on the target cluster).

---

### CTL.IAM.TRUST.ORGBOUNDARY.001

**Cross-Account Trust Must Restrict to Organization via PrincipalOrgID**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-3; iso_27001_2022: A.8.3; nist_800_53_r5: AC-3; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

IAM roles with cross-account trust policies must include an aws:PrincipalOrgID condition restricting assumption to principals within the AWS Organization. Without this condition, any external AWS account — including attacker-controlled accounts — can attempt role assumption. PrincipalOrgID is the broadest safe boundary for multi-account organizations: it permits all org members while denying all outsiders.

**Remediation:** Add an aws:PrincipalOrgID condition to the trust policy: "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-xxxxxxxxxxxx"}}. This restricts assumption to principals within the organization.

---

### CTL.IAM.TRUST.SESSION.001

**Cross-Account Trust Must Have Session-Limiting Conditions**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-3; nist_800_53_r5: AC-3; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

IAM roles with cross-account trust policies must include at least one session-limiting condition beyond principal identity binding. Without constraints on session duration, source network, or MFA, an assumed-role session is usable from any IP address, without MFA, for the maximum default duration (up to 12 hours). Existing controls verify principal binding (ExternalId, SourceArn, ConfusedDeputy). This control verifies that the trust policy also constrains the assumption context — how long, from where, and with what authentication strength.

**Remediation:** Add at least one of the following conditions to the trust policy: aws:MultiFactorAuthPresent (require MFA), aws:SourceIp or aws:SourceVpc (restrict network origin), or set MaxSessionDuration on the role to limit session lifetime. For cross-account CI/CD roles, combine OIDC subject scoping (covered by CTL.IAM.TRUST.OIDC.*) with a short MaxSessionDuration.

---

### CTL.IAM.TRUST.SOURCEARN.001

**AWS Service Principal Trust Must Have SourceArn or SourceAccount Condition**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-3; nist_800_53_r5: AC-3, AC-6; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

IAM roles trusted by AWS service principals (*.amazonaws.com) must include aws:SourceArn or aws:SourceAccount conditions. Without these conditions, the service can assume the role when acting on behalf of any resource in any account — including attacker-controlled resources. AWS Lambda execution roles without aws:SourceArn allow any Lambda function in any account to assume the role. SNS/S3 notification roles without SourceArn allow any bucket or topic in any account to trigger the role assumption.

**Remediation:** Add aws:SourceArn scoped to the specific resource ARN that should trigger the role assumption. If the resource ARN is not known at deploy time, add aws:SourceAccount scoped to your account ID.

---

### CTL.IAM.TRUST.WILDCARD.001

**Trust Policy Must Not Use Wildcard Principal**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-3; iso_27001_2022: A.8.3; nist_800_53_r5: AC-3; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

IAM role trust policies must not use Principal "*" or Principal: {AWS: "*"}. A wildcard principal allows any AWS principal in any account to attempt role assumption. This is the most dangerous trust configuration — the role is effectively public to the entire AWS ecosystem.

**Remediation:** Replace Principal "*" with specific account ARNs or role ARNs. Add aws:PrincipalOrgID to restrict to the organization. Add sts:ExternalId for third-party integrations.

---

### CTL.IAM.VENDOR.DORMANT.001

**Vendor Cross-Account Role Must Not Be Dormant**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-2; soc2: CC6.1;

Cross-account roles granted to external vendors (SaaS providers, auditors, consultants) must be actively used or decommissioned. A vendor role unused for more than 90 days is "ghost access" — the vendor may no longer need it, the contract may have ended, but the access persists. Each dormant vendor role is an unmonitored ingress path that can be exploited if the vendor is compromised.

**Remediation:** Review the vendor relationship. If the contract has ended or the vendor no longer needs access, delete the cross-account role. If access is still needed, re-verify the trust policy and scope permissions to current requirements.

---

### CTL.IAM.VENDOR.OVERPRIVILEGED.001

**Vendor Role Must Not Reach Excessive Sensitive Resources**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** hipaa: 164.312(a)(1); pci_dss_v4.0: 7.2.2; soc2: CC6.1;

External vendor roles must have scoped access to sensitive resources. A vendor that can reach more than 10 sensitive resources (PHI, PII, confidential) has a disproportionate blast radius — if the vendor is compromised, the attacker gains broad access to your most sensitive data through a third-party trust relationship.

**Remediation:** Scope the vendor role permissions to the minimum required resources. Create per-function roles for different vendor tasks. Use resource-based policies to restrict vendor access to specific non-sensitive resources.

---

### CTL.IAM.ZT.PERIMETER.001

**Sensitive Resources Must Use Identity-Based Access Not Network Perimeter**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-3; nist_800_53_r5: AC-3; nist_csf_2.0: PR.AA;

Access to sensitive resources must be governed by identity-based controls (IAM policies, conditions, session tags) rather than relying solely on network perimeter (VPC, security groups, NACLs). Network-only access control fails when the perimeter is bypassed — via VPN compromise, lateral movement, or insider threat. Zero Trust requires every access decision to verify identity, device, and context.

**Remediation:** Add IAM-based access controls (resource policies with principal constraints, IAM conditions for aws:PrincipalTag, VPC endpoint policies with principal scoping). Use AWS Verified Access or IAM Roles Anywhere for workload identity.

---

### CTL.IAM.ZT.SHORTLIVED.001

**Service Access Must Use Short-Lived Credentials**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: IA-5; nist_800_53_r5: IA-5; nist_csf_2.0: PR.AA;

Service-to-service access must use short-lived credentials (STS temporary tokens, IAM Roles Anywhere certificates, OIDC federation) rather than long-lived access keys. Short-lived credentials limit the blast radius of compromise — a stolen token expires automatically. This is a core Zero Trust principle: never trust a credential longer than necessary.

**Remediation:** Replace long-lived access keys with IAM roles (for EC2, ECS, Lambda), IAM Roles Anywhere (for on-premises), or OIDC federation (for CI/CD). Use STS AssumeRole with session duration limits.

---

### CTL.INSPECTOR.ENABLED.001

**Amazon Inspector Must Be Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: RA-5; soc2: CC7.1;

Amazon Inspector 2 must be enabled for vulnerability scanning of EC2, ECR, and Lambda resources. Without Inspector, known vulnerabilities in deployed software go undetected.

**Remediation:** Enable Inspector 2 for EC2, ECR, and Lambda scanning.

---

### CTL.K8S.APISERVER.ADM.CTRL.001

**API Server Must Enable AlwaysPullImages Admission Controller**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 1.2.11;

The API server must enable the AlwaysPullImages admission controller. This ensures every new pod always pulls the image, preventing nodes from using cached images that may have been tampered with.

**Remediation:** Add AlwaysPullImages to --enable-admission-plugins on the API server.

---

### CTL.K8S.APISERVER.ADM.CTRL.002

**API Server Must Enable Pod Security Admission**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 1.2.12;

The API server must enable PodSecurity or SecurityContextDeny admission controller to enforce pod security standards.

**Remediation:** Add PodSecurity to --enable-admission-plugins on the API server.

---

### CTL.K8S.APISERVER.ADM.CTRL.003

**API Server Must Enable ServiceAccount Admission Controller**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 1.2.13;

The API server must enable the ServiceAccount admission controller to automate service account management for pods.

**Remediation:** Add ServiceAccount to --enable-admission-plugins on the API server.

---

### CTL.K8S.APISERVER.ADM.CTRL.004

**API Server Must Enable NodeRestriction Admission Controller**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 1.2.16;

The API server must enable the NodeRestriction admission controller to limit what a kubelet can modify, preventing compromised nodes from escalating privileges.

**Remediation:** Add NodeRestriction to --enable-admission-plugins on the API server.

---

### CTL.K8S.APISERVER.ANON.001

**API Server Anonymous Authentication Must Be Disabled**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 1.2.1;

The Kubernetes API server must not allow anonymous authentication. Anonymous auth permits unauthenticated requests to the API, enabling reconnaissance and potential cluster compromise.

**Remediation:** Set --anonymous-auth=false on the API server. For managed clusters, verify the provider disables anonymous auth by default.

---

### CTL.K8S.APISERVER.AUDIT.001

**API Server Audit Logging Must Be Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 1.2.22;

The Kubernetes API server must have audit logging enabled. Without audit logs, security-relevant API calls are not recorded.

**Remediation:** Configure --audit-policy-file and --audit-log-path on the API server.

---

### CTL.K8S.APISERVER.AUDIT.MAXAGE.001

**API Server Audit Log Retention Must Be At Least 30 Days**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 1.2.23;

Audit log retention must be at least 30 days to support incident investigation and compliance evidence requirements.

**Remediation:** Set --audit-log-maxage=30 or higher on the API server.

---

### CTL.K8S.APISERVER.AUDIT.MAXBACKUP.001

**API Server Audit Log Max Backup Must Be At Least 10**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 1.2.24;

The API server must retain at least 10 old audit log files before rotation deletes them. Insufficient backup retention limits the availability of historical audit data for incident investigation.

**Remediation:** Set --audit-log-maxbackup=10 or higher on the API server.

---

### CTL.K8S.APISERVER.AUDIT.MAXSIZE.001

**API Server Audit Log Max Size Must Be At Least 100 MB**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 1.2.25;

Each audit log file must be allowed to grow to at least 100 MB before rotation. Smaller limits cause frequent rotation that may result in loss of audit records during high-activity periods.

**Remediation:** Set --audit-log-maxsize=100 or higher on the API server.

---

### CTL.K8S.APISERVER.AUTHZ.001

**API Server Must Use RBAC Authorization**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 1.2.7;

The API server authorization mode must include RBAC and must not include AlwaysAllow. RBAC enforces fine-grained access control; AlwaysAllow permits any authenticated user to perform any action.

**Remediation:** Set --authorization-mode=RBAC,Node on the API server. Remove AlwaysAllow from the mode list.

---

### CTL.K8S.APISERVER.CLIENT.CA.001

**API Server Client CA Must Be Configured**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 1.2.29;

The API server must be configured with a client certificate authority file to verify client certificates for mutual TLS authentication.

**Remediation:** Set --client-ca-file on the API server pointing to the cluster CA.

---

### CTL.K8S.APISERVER.ENCRYPT.PROV.001

**API Server Encryption Provider Must Be Configured**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 1.2.30;

The API server must have an encryption provider configuration set via --encryption-provider-config. Without this, Kubernetes secrets are stored unencrypted in etcd, exposing sensitive data to anyone with etcd access.

**Remediation:** Set --encryption-provider-config on the API server pointing to an EncryptionConfiguration resource that uses aescbc, secretbox, or a KMS provider.

---

### CTL.K8S.APISERVER.ETCD.CERT.001

**API Server Must Use TLS for etcd Communication**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 1.2.32;

The API server must present a client certificate when connecting to etcd. Without mutual TLS, API server to etcd traffic is unauthenticated and unencrypted.

**Remediation:** Set --etcd-certfile and --etcd-keyfile on the API server.

---

### CTL.K8S.APISERVER.INSECURE.PORT.001

**API Server Insecure Port Must Be Disabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 1.2.19;

The API server insecure port must be set to 0 (disabled). The insecure port serves requests without authentication or authorization, allowing unrestricted access to the Kubernetes API.

**Remediation:** Set --insecure-port=0 on the API server. This flag is deprecated in recent Kubernetes versions and will be removed.

---

### CTL.K8S.APISERVER.KUBELET.CERT.001

**API Server Kubelet Certificate Authority Must Be Set**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 1.2.5;

The API server must have --kubelet-certificate-authority configured to verify kubelet serving certificates. Without this, the API server cannot authenticate kubelet endpoints, enabling man-in-the-middle attacks on API-server-to-kubelet communication.

**Remediation:** Set --kubelet-certificate-authority on the API server pointing to the CA bundle used to sign kubelet serving certificates.

---

### CTL.K8S.APISERVER.PROFILING.001

**API Server Profiling Must Be Disabled**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 1.2.18;

The API server profiling endpoint must be disabled. Profiling exposes system and program details useful for attackers to identify vulnerabilities and plan exploitation.

**Remediation:** Set --profiling=false on the API server.

---

### CTL.K8S.APISERVER.SA.KEY.001

**API Server Service Account Key File Must Be Set**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 1.2.28;

The API server must be configured with --service-account-key-file to verify service account tokens with a dedicated key pair.

**Remediation:** Set --service-account-key-file on the API server.

---

### CTL.K8S.APISERVER.TLS.CERT.001

**API Server TLS Certificate Must Be Configured**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 1.2.26;

The API server must be configured with a TLS serving certificate. Without TLS, API traffic is transmitted in cleartext.

**Remediation:** Set --tls-cert-file and --tls-private-key-file on the API server.

---

### CTL.K8S.APISERVER.TOKEN.AUTH.001

**API Server Static Token Authentication Must Be Disabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 1.2.2;

The API server must not use static token authentication via --token-auth-file. Static tokens do not expire, cannot be revoked without restarting the API server, and are stored in cleartext.

**Remediation:** Remove --token-auth-file from the API server configuration. Use OIDC, service account tokens, or certificate-based authentication.

---

### CTL.K8S.AUDIT.001

**Kubernetes Audit Logging Must Be Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.8.0: 3.2.1; hipaa: 164.312(b); soc2: CC7.1;

The Kubernetes API server must have audit logging enabled. Without audit logs, API calls (including unauthorized access attempts) are not recorded for forensic analysis.

**Remediation:** Configure the API server with --audit-policy-file and --audit-log-path. For managed clusters (EKS, GKE), enable control plane logging via the cloud provider console.

---

### CTL.K8S.AUTH.ACCESSKEYMAP.001

**K8s Clusters Must Not Map Identity via AccessKeyID**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_k8s_v1.8.0: 3.1.1; nist_800_53_r5: IA-2; soc2: CC6.1;

Kubernetes clusters using AWS IAM Authenticator must not use {{AccessKeyID}} in identity mapping templates. The AccessKeyID is extracted from client-supplied presigned URL query parameters, not from the STS response, making it vulnerable to parameter injection via case-variant duplication.

**Remediation:** Replace {{AccessKeyID}} with {{SessionName}} or use ARN-based mapping (userARN matching) without template substitution. ARN and SessionName come from the STS GetCallerIdentity response and cannot be manipulated by the client.

---

### CTL.K8S.CM.BIND.ADDR.001

**Controller Manager Must Bind to Loopback Address**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 1.3.7;

The controller manager must bind to a loopback address (127.0.0.1 or ::1). Binding to 0.0.0.0 or a routable address exposes the controller manager's unsecured HTTP endpoints to the network.

**Remediation:** Set --bind-address=127.0.0.1 on the controller manager.

---

### CTL.K8S.CM.GC.001

**Controller Manager Terminated Pod GC Threshold Must Be Set**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 1.3.1;

The controller manager must have a positive terminated pod garbage collection threshold to prevent resource exhaustion from accumulated terminated pods.

**Remediation:** Set --terminated-pod-gc-threshold to a positive value (e.g. 12500).

---

### CTL.K8S.CM.PROFILING.001

**Controller Manager Profiling Must Be Disabled**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 1.3.2;

The controller manager profiling endpoint must be disabled. Profiling exposes system and program details useful for attackers to identify vulnerabilities and plan privilege escalation.

**Remediation:** Set --profiling=false on the controller manager.

---

### CTL.K8S.CM.ROOT.CA.001

**Controller Manager Root CA File Must Be Set**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 1.3.5;

The controller manager must have --root-ca-file configured. This CA bundle is injected into each service account token secret, allowing pods to verify the API server's TLS certificate and preventing man-in-the-middle attacks.

**Remediation:** Set --root-ca-file on the controller manager pointing to the cluster CA bundle.

---

### CTL.K8S.CM.ROTATE.CERTS.001

**Controller Manager Must Enable RotateKubeletServerCertificate**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 1.3.6;

The controller manager must enable the RotateKubeletServerCertificate feature gate. This allows the kubelet to request and rotate its serving certificate automatically, preventing certificate expiry and ensuring continued TLS for kubelet endpoints.

**Remediation:** Set --feature-gates=RotateKubeletServerCertificate=true on the controller manager.

---

### CTL.K8S.CM.SA.CREDS.001

**Controller Manager Must Use Individual Service Account Credentials**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 1.3.3;

The controller manager must use individual service account credentials for each controller. Without this, all controllers share the controller manager's credentials, violating least privilege.

**Remediation:** Set --use-service-account-credentials=true on the controller manager.

---

### CTL.K8S.CM.SA.KEY.001

**Controller Manager Service Account Private Key Must Be Set**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 1.3.4;

The controller manager must have a service account private key file configured for signing service account tokens.

**Remediation:** Set --service-account-private-key-file on the controller manager.

---

### CTL.K8S.ETCD.AUTO.TLS.001

**etcd Auto-TLS Must Be Disabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 2.3;

etcd auto-TLS generates self-signed certificates without CA validation, providing encryption without authentication. An attacker can MITM the connection with their own self-signed cert.

**Remediation:** Set --auto-tls=false and configure proper CA-signed certificates.

---

### CTL.K8S.ETCD.CERT.001

**etcd Must Use TLS Certificates**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 2.1;

etcd must be configured with TLS certificate and key files. Without TLS, all cluster state (including Secrets) is transmitted in cleartext.

**Remediation:** Set --cert-file and --key-file on the etcd server.

---

### CTL.K8S.ETCD.CLIENT.AUTH.001

**etcd Client Certificate Authentication Must Be Enabled**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 2.2;

etcd must require client certificate authentication. Without it, any client with network access to etcd can read and write all cluster state.

**Remediation:** Set --client-cert-auth=true on the etcd server.

---

### CTL.K8S.ETCD.PEER.AUTO.TLS.001

**etcd Peer Auto-TLS Must Be Disabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 2.6;

etcd peer auto-TLS uses self-signed certificates for cluster member communication without CA validation. A rogue etcd member can join the cluster and exfiltrate all data.

**Remediation:** Set --peer-auto-tls=false and configure --peer-cert-file, --peer-key-file, and --peer-trusted-ca-file.

---

### CTL.K8S.ETCD.PEER.CERT.001

**etcd Peer Certificate File Must Be Set**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 2.4;

etcd must be configured with a peer certificate file for mutual TLS between etcd cluster members. Without peer TLS, inter-node etcd communication is unencrypted and unauthenticated, allowing cluster state interception or injection.

**Remediation:** Set --peer-cert-file on the etcd server pointing to a valid TLS certificate for peer communication.

---

### CTL.K8S.ETCD.PEER.KEY.001

**etcd Peer Key File Must Be Set**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 2.5;

etcd must be configured with a peer key file for mutual TLS between etcd cluster members. Without the private key, peer TLS cannot be established and inter-node communication is insecure.

**Remediation:** Set --peer-key-file on the etcd server pointing to the private key corresponding to the peer certificate.

---

### CTL.K8S.EXEC.RESTRICT.001

**kubectl exec Must Be Restricted via RBAC to Authorized Roles**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_k8s_v1.9: 5.1.3; mitre_attack: T1609; nist_800_53_r5: AC-3;

kubectl exec (pods/exec) allows executing commands in running pods. Granting this to service accounts or broad principals enables arbitrary code execution in any pod the principal can target. An attacker who compromises a principal with pods/exec access can run commands in privileged pods, access secrets mounted in other pods, and pivot to the host if any pod runs with elevated privileges.

**Remediation:** Audit all ClusterRoles and Roles granting pods/exec. Restrict pods/exec to named developer roles with namespace scope, not cluster-wide roles. Remove pods/exec from service account bindings.

---

### CTL.K8S.IMDS.BLOCK.001

**Cluster Must Have NetworkPolicy Blocking Pod Egress to IMDS**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** mitre_attack: TA0006; nist_800_53_r5: AC-4;

Kubernetes clusters must have a NetworkPolicy blocking pod egress to the cloud instance metadata service at 169.254.169.254. A pod with hostNetwork=true and CAP_NET_RAW can intercept IMDS traffic and inject crafted responses containing attacker-controlled SSH keys, gaining root access to the node. A NetworkPolicy blocking 169.254.169.254/32 egress prevents this escalation even when pod security controls fail.

**Remediation:** Apply a NetworkPolicy in every namespace blocking egress to 169.254.169.254/32. For AWS, also enforce IMDSv2 with hop limit 1 on all node groups.

---

### CTL.K8S.INCOMPLETE.001

**Complete Data Required for Kubernetes Assessment**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure

Kubernetes cluster safety cannot be assessed when audit logging status is missing from the snapshot. The extractor must populate audit.audit_logging_enabled.

**Remediation:** Re-run the extractor with Kubernetes API access to describe cluster configuration, RBAC, network policies, and secrets.

---

### CTL.K8S.JOB.TTL.001

**Jobs in NetworkPolicy Namespaces Must Configure ttlSecondsAfterFinished**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** mitre_attack: TA0008; nist_800_53_r5: AC-4;

Kubernetes Jobs in namespaces with active NetworkPolicy must set ttlSecondsAfterFinished to limit completed pod residency. The VPC CNI controller does not flush NetworkPolicy firewall rules when a pod reaches Completed state. Without TTL, completed pod IPs are recycled with stale firewall rules attached, silently granting new pods the original pod's network access.

**Remediation:** Add ttlSecondsAfterFinished (60-300 seconds) to all Job specs in namespaces with NetworkPolicy. For cluster-wide enforcement, use a policy engine (OPA/Kyverno) to require this field.

---

### CTL.K8S.KUBELET.ANON.001

**Kubelet Anonymous Authentication Must Be Disabled**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 4.2.1;

The kubelet must not allow anonymous authentication. Anonymous auth permits unauthenticated requests to the kubelet API, enabling pod listing, log access, and command execution on the node.

**Remediation:** Set authentication.anonymous.enabled=false in the kubelet config or pass --anonymous-auth=false.

---

### CTL.K8S.KUBELET.AUTHZ.001

**Kubelet Must Not Use AlwaysAllow Authorization**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 4.2.2;

The kubelet authorization mode must not be set to AlwaysAllow. AlwaysAllow permits any authenticated request without RBAC checks.

**Remediation:** Set authorization.mode=Webhook in the kubelet config or pass --authorization-mode=Webhook.

---

### CTL.K8S.KUBELET.CLIENT.CA.001

**Kubelet Client CA Must Be Configured**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 4.2.3;

The kubelet must be configured with a client CA file to verify client certificates for x509 authentication.

**Remediation:** Set authentication.x509.clientCAFile in the kubelet config.

---

### CTL.K8S.KUBELET.EVENTRECORD.001

**Kubelet Event Record QPS Must Be Greater Than Zero**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 4.2.9;

The kubelet event record QPS must be greater than zero. Setting this to zero disables event creation, hiding node-level events from the API server and preventing detection of security-relevant activities.

**Remediation:** Set eventRecordQPS to a value greater than 0 (default is 5) in the kubelet config.

---

### CTL.K8S.KUBELET.HOSTNAME.001

**Kubelet Hostname Override Should Not Be Set**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 4.2.8;

The kubelet should not have --hostname-override set. Overriding the hostname can interfere with TLS certificate validation and node identity verification, as certificates are typically issued for the actual hostname.

**Remediation:** Remove --hostname-override from the kubelet configuration. If hostname override is required for cloud provider integration, ensure certificates match the overridden name.

---

### CTL.K8S.KUBELET.KERNEL.001

**Kubelet Must Protect Kernel Defaults**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 4.2.6;

The kubelet must set protectKernelDefaults to true. This prevents pods from modifying kernel parameters that could weaken node security or enable privilege escalation.

**Remediation:** Set protectKernelDefaults=true in the kubelet config.

---

### CTL.K8S.KUBELET.READONLY.001

**Kubelet Read-Only Port Must Be Disabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 4.2.4;

The kubelet read-only port (default 10255) must be disabled by setting it to 0. The read-only port exposes node and pod metrics without authentication.

**Remediation:** Set readOnlyPort=0 in the kubelet config or pass --read-only-port=0.

---

### CTL.K8S.KUBELET.ROTATE.001

**Kubelet Certificate Rotation Must Be Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 4.2.11;

The kubelet must have certificate rotation enabled to automatically renew its client and serving certificates before expiry.

**Remediation:** Set rotateCertificates=true in the kubelet config.

---

### CTL.K8S.KUBELET.ROTATE.SERVER.001

**Kubelet Server Certificate Rotation Must Be Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 4.2.12;

The kubelet must have server certificate rotation enabled via serverTLSBootstrap or the RotateKubeletServerCertificate feature gate. Without rotation, kubelet serving certificates may expire, breaking TLS for kubelet endpoints.

**Remediation:** Set serverTLSBootstrap=true or featureGates.RotateKubeletServerCertificate=true in the kubelet config.

---

### CTL.K8S.KUBELET.STREAMING.001

**Kubelet Streaming Connection Idle Timeout Must Not Be Zero**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 4.2.5;

The kubelet streaming connection idle timeout must be greater than zero. A zero timeout disables connection cleanup, allowing idle streaming connections (exec, attach, port-forward) to persist indefinitely, consuming resources and increasing attack surface.

**Remediation:** Set streamingConnectionIdleTimeout to a non-zero duration (e.g., 4h0m0s) in the kubelet config.

---

### CTL.K8S.KUBELET.TLS.001

**Kubelet TLS Certificate Must Be Configured**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 4.2.10;

The kubelet must be configured with a TLS serving certificate. Without TLS, kubelet API traffic is transmitted in cleartext.

**Remediation:** Set tlsCertFile and tlsPrivateKeyFile in the kubelet config.

---

### CTL.K8S.NETPOL.001

**Namespaces Must Have Network Policies**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.8.0: 5.3.2; hipaa: 164.312(e)(1);

Kubernetes namespaces containing workloads must have at least one NetworkPolicy defined. Without network policies, all pod-to-pod traffic is allowed by default, enabling lateral movement.

**Remediation:** Create a default-deny NetworkPolicy for the namespace, then add explicit allow rules for required traffic flows.

---

### CTL.K8S.NETPOL.DENY.001

**Namespaces Must Have Default-Deny Network Policy**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.8.0: 5.3.2;

Namespaces with network policies must include a default-deny ingress policy. Without default-deny, network policies only add allow rules on top of the implicit allow-all default.

**Remediation:** Add a default-deny ingress NetworkPolicy that selects all pods and has no ingress rules.

---

### CTL.K8S.NETPOL.EGRESS.001

**Cluster Must Have Egress Network Policies**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 5.3.2;

The cluster must have egress network policies defined. Without egress policies, compromised pods can freely communicate with external command-and-control servers, exfiltrate data, or attack other services outside the cluster.

**Remediation:** Create egress NetworkPolicies to restrict outbound traffic from pods to only approved destinations and ports.

---

### CTL.K8S.POD.CAPABILITIES.001

**Containers Must Drop NET_RAW Capability**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 5.2.7;

Containers must drop the NET_RAW capability. NET_RAW allows crafting raw network packets, enabling ARP spoofing, DNS poisoning, and other network-level attacks from within the container.

**Remediation:** Add NET_RAW to securityContext.capabilities.drop in the container spec. Prefer dropping ALL capabilities and adding back only those required.

---

### CTL.K8S.POD.HOSTIPC.001

**Pods Must Not Share the Host IPC Namespace**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_kubernetes: 5.2.3; nist_800_53_r5: SC-7;

Pods must not enable hostIPC which shares the host's IPC namespace. Shared IPC allows containers to access shared memory segments of other processes on the host, enabling cross-process data access and manipulation.

**Remediation:** Set hostIPC to false in the pod spec.

---

### CTL.K8S.POD.HOSTNET.001

**Pods Must Not Share the Host Network Namespace**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 5.2.4;

Pods must not share the host network namespace. Sharing the host network gives containers access to all network interfaces and listening services on the node, bypassing network policies and enabling network-level attacks.

**Remediation:** Set hostNetwork=false in the pod spec. Use Kubernetes Services and NetworkPolicies to control network access instead.

---

### CTL.K8S.POD.HOSTPID.001

**Pods Must Not Share the Host PID Namespace**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 5.2.2;

Pods must not share the host PID namespace. Sharing the host PID namespace allows containers to see and signal all processes on the host, enabling process inspection, injection, and denial of service.

**Remediation:** Set hostPID=false in the pod spec. Remove hostPID sharing unless there is a documented operational requirement.

---

### CTL.K8S.POD.HOSTPORT.001

**Containers Must Not Use Host Ports**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_kubernetes: 5.2.6; nist_800_53_r5: SC-7;

Containers must not declare hostPort, which binds directly to the node's network stack. HostPort bypasses Kubernetes service abstractions and network policies, exposing the container's port on the node's IP address.

**Remediation:** Remove hostPort from container spec. Use Kubernetes Services for port exposure.

---

### CTL.K8S.POD.PRIVILEGED.001

**Containers Must Not Run in Privileged Mode**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 5.2.1;

Pods must not run privileged containers. Privileged containers have full access to the host's devices, kernel capabilities, and namespaces, effectively granting root-level access to the node.

**Remediation:** Set securityContext.privileged=false on all containers. Use specific capabilities instead of privileged mode.

---

### CTL.K8S.POD.RUNASROOT.001

**Containers Must Not Run as Root**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 5.2.6;

Containers must not run as the root user. Running as root inside a container increases the impact of container breakout vulnerabilities and grants unnecessary privileges for filesystem and process operations.

**Remediation:** Set securityContext.runAsNonRoot=true and specify a non-root runAsUser in the pod or container security context.

---

### CTL.K8S.POD.SECCOMP.001

**Pods Must Use RuntimeDefault or Localhost Seccomp Profile**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_kubernetes: 5.7.2; nist_800_53_r5: SC-7;

Pods must have a seccomp profile set to RuntimeDefault or Localhost at the pod or container level. Without a seccomp profile, containers run with the full set of available syscalls, increasing the kernel attack surface for container escape.

**Remediation:** Set securityContext.seccompProfile.type to RuntimeDefault.

---

### CTL.K8S.RBAC.DEFAULT.SA.001

**Default Service Account Automount Must Be Disabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 5.1.5;

The default service account in each namespace must have automountServiceAccountToken set to false. The default service account is shared by all pods that do not specify one, and its token grants unnecessary API access to workloads.

**Remediation:** Set automountServiceAccountToken=false on the default ServiceAccount in each namespace.

---

### CTL.K8S.RBAC.SA.TOKEN.001

**Service Account Token Automount Must Be Opt-In Only**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 5.1.6;

Service account tokens must not be automatically mounted into pods unless explicitly required. Automatic token mounting provides every pod with API credentials, increasing the blast radius of container compromise.

**Remediation:** Set automountServiceAccountToken=false on ServiceAccounts and only enable it on pods that require API access.

---

### CTL.K8S.RBAC.SERVICEACCOUNT.001

**Default Service Account Must Not Have Active Tokens**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.8.0: 5.1.5;

The default service account in each namespace should not have auto-mounted tokens. Pods using the default service account inherit permissions that may allow unintended API access.

**Remediation:** Set automountServiceAccountToken to false on the default service account in every namespace. Create dedicated service accounts with minimal permissions for workloads that need API access.

---

### CTL.K8S.RBAC.WEBHOOK.001

**RBAC Must Restrict Admission Webhook Configuration Access**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_kubernetes: 5.1.4; nist_800_53_r5: AC-6(5);

Roles and ClusterRoles must not grant create, update, or delete on mutatingwebhookconfigurations or validatingwebhookconfigurations. Admission webhooks intercept every API request — an attacker with webhook configuration access can inject a mutating webhook that modifies all pod specs, secrets, or deployments passing through the API server.

**Remediation:** Restrict webhook configuration write access to cluster administrators only.

---

### CTL.K8S.RBAC.WILDCARD.001

**ClusterRoles Must Not Use Wildcard Resources or Verbs**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.8.0: 5.1.3;

Kubernetes ClusterRoles must not grant wildcard (*) access to resources or verbs. Wildcard grants provide cluster-wide permissions that bypass the principle of least privilege.

**Remediation:** Replace wildcard entries with explicit resource names and verbs. Use Roles (namespace-scoped) instead of ClusterRoles where possible.

---

### CTL.K8S.SCHEDULER.PROFILING.001

**Scheduler Profiling Must Be Disabled**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.9: 1.4.1;

The scheduler profiling endpoint must be disabled. Profiling exposes system and program details useful for attackers to identify vulnerabilities and plan privilege escalation.

**Remediation:** Set --profiling=false on the scheduler.

---

### CTL.K8S.SECRETS.ENCRYPT.001

**Kubernetes Secrets Must Be Encrypted at Rest in etcd**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.8.0: 1.2.29; hipaa: 164.312(a)(2)(iv); soc2: CC6.7;

Kubernetes Secrets stored in etcd must be encrypted at rest. By default, Secrets are stored as base64-encoded plaintext in etcd, readable by anyone with etcd access or etcd backup access.

**Remediation:** Configure the API server with --encryption-provider-config pointing to an EncryptionConfiguration that uses aescbc, aesgcm, or kms provider. For EKS, enable envelope encryption with a KMS key.

---

### CTL.K8S.SECRETS.PLAINTEXT.001

**Pods Must Not Mount Secrets as Environment Variables**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_k8s_v1.8.0: 5.4.1;

Secrets should be mounted as files, not environment variables. Environment variables are visible in process listings, crash dumps, and container inspection output, increasing the risk of credential exposure.

**Remediation:** Mount Secrets as volumes instead of environment variables. Use projected volumes with restrictive file permissions (0400).

---

### CTL.KINESIS.ENCRYPT.001

**Kinesis Streams Must Be Encrypted At Rest with KMS**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** nist_800_53_r5: SC-28; soc2: CC6.7;

Kinesis Data Streams must use server-side encryption with KMS to protect records at rest. Streams without KMS encryption store records in plaintext — readable by anyone with stream read permissions.

**Remediation:** Enable server-side encryption on the stream with a KMS key via aws kinesis start-stream-encryption.

---

### CTL.KINESIS.RETENTION.001

**Kinesis Streams Must Meet Minimum Data Retention Period**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AU-11; soc2: A1.1;

Kinesis Data Streams must retain records for at least the required minimum duration (default 168 hours / 7 days). Short retention windows reduce forensic capability and prevent replay of missed events by downstream consumers.

**Remediation:** Increase the stream retention period via aws kinesis increase-stream-retention-period.

---

### CTL.KMS.CONCENTRATION.001

**KMS Key Must Not Encrypt More Than 50 Resources**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** storage
- **Compliance:** nist_800_53_r5: SC-12; soc2: A1.1;

A single KMS key encrypting more than 50 resources represents a cryptographic single point of failure. If the key is deleted, disabled, or its policy misconfigured, all dependent resources become inaccessible. The extractor counts the number of unique resources encrypted with each KMS key.

**Remediation:** Create per-service or per-application KMS keys to distribute the encryption dependency. Use key aliases for easy migration. Enable key deletion protection on high-density keys.

---

### CTL.KMS.CONCENTRATION.002

**High-Density KMS Key Must Have Deletion Protection**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** storage
- **Compliance:** fedramp_moderate: SC-12(1); nist_800_53_r5: SC-12(1); soc2: A1.1;

KMS keys encrypting more than 50 resources must have deletion protection enabled. Without deletion protection, an accidental or malicious ScheduleKeyDeletion call can render hundreds of resources permanently unrecoverable within the 7-day minimum waiting period.

**Remediation:** Enable key deletion protection. Apply a key policy that denies kms:ScheduleKeyDeletion from all principals except a dedicated key administrator role. Add an SCP to deny key deletion at the organization level.

---

### CTL.KMS.FIPS.001

**KMS Keys Must Use FIPS 140-2 Validated HSM Origin**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-13;

KMS keys must have AWS_KMS origin, confirming they are generated and stored in FIPS 140-2 Level 2 validated hardware security modules. Keys with EXTERNAL or CUSTOM_KEY_STORE origin may not meet FedRAMP FIPS 140 cryptography requirements.

**Remediation:** Create a new key with AWS_KMS origin (default). Rotate data encrypted with the non-compliant key to the new key.

---

### CTL.KMS.INCOMPLETE.001

**Complete Data Required for KMS Assessment**

- **Severity:** info
- **Type:** unsafe_state
- **Domain:** exposure

The observation snapshot is missing required KMS key properties. A safety assessment cannot be completed without key policy data.

**Remediation:** Ensure the extractor calls aws kms get-key-policy and maps the response to the cryptography observation properties.

---

### CTL.KMS.ISOLATION.001

**PHI/CDE Encryption Key Must Not Be Shared Across Sensitivity Domains**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-12; hipaa: 164.312(a)(2)(iv); iso_27001_2022: A.8.24; nist_800_53_r5: SC-12, SC-28; pci_dss_v4.0: 3.6.1; soc2: CC6.7;

KMS keys protecting PHI or CDE data must not be shared with resources at a lower sensitivity classification. Shared keys collapse the cryptographic boundary between trust domains. A compromised developer account with access to a shared key can decrypt production PHI data even if all other access controls are correctly configured. Encryption is only as strong as the isolation of its keys.

**Remediation:** Create dedicated KMS keys per sensitivity domain. Apply key policies that restrict usage to IAM roles operating within that domain. Rotate existing PHI/CDE data to new domain-exclusive keys. Use KMS key tags (sensitivity=phi) and SCPs to prevent cross-domain key usage at the organizational level.

---

### CTL.KMS.PENDING.DELETION.001

**KMS Key Must Not Be Pending Deletion While Resources Depend On It**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-12(1); nist_800_53_r5: SC-12(1); soc2: A1.1;

KMS keys scheduled for deletion have a waiting period (7-30 days) before key material is permanently destroyed. Once deleted, all data encrypted by the key becomes permanently inaccessible — S3 objects, RDS snapshots, EBS volumes, Secrets Manager secrets, and any other resource encrypted by this key. This control detects keys pending deletion that still have dependent resources, giving operators time to cancel deletion or re-encrypt resources with a different key.

**Remediation:** Cancel key deletion with aws kms cancel-key-deletion, then re-evaluate whether the key should be deleted. If deletion is intentional, first re-encrypt all dependent resources with a different key.

---

### CTL.KMS.POLICY.001

**KMS Key Policy Must Restrict Access to Specific Roles**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-3; ffiec: ISH-4; gdpr: Art.32; hipaa: 164.312(a)(1); iso_27001_2022: A.8.24; nist_800_53_r5: AC-3; nist_csf_2.0: PR.DS; pci_dss_v4.0: 3.4.1; soc2: CC6.1;

KMS key policies must not grant wildcard principal access. A key policy with Principal "*" allows any IAM entity in the account (or any account if conditions are missing) to use the key, defeating the purpose of customer-managed encryption.

**Remediation:** Update the key policy to restrict Principal to specific IAM roles or accounts. Remove any statements with Principal "*".

---

### CTL.KMS.POLICY.ADMIN.BROAD.001

**KMS Key Administration Must Be Restricted to Key Administrators**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-6(5); iso_27001_2022: A.8.24; nist_800_53_r5: AC-6(5); pci_dss_v4.0: 3.6.1; soc2: CC6.1;

KMS key policies must not grant key administration actions (kms:Create*, kms:Put*, kms:Disable*, kms:ScheduleKeyDeletion, kms:EnableKey, kms:EnableKeyRotation, kms:UpdateKeyDescription) to principals beyond designated key administrators. Broad administrative access allows any granted principal to disable the key, schedule it for deletion, or modify its policy — disrupting every resource encrypted by the key.

**Remediation:** Restrict key administration statements to designated key administrator roles. Separate key usage (Encrypt/Decrypt) from key administration (Create*/Put*/Disable*/Schedule*) in the key policy. Use separate statements with distinct principals for usage and administration.

---

### CTL.KMS.POLICY.CONDITION.001

**KMS Key Policy Must Include Protective Conditions**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3; pci_dss_v4.0: 3.4.1; soc2: CC6.1;

KMS key policies granting usage actions (kms:Decrypt, kms:Encrypt, kms:GenerateDataKey*, kms:ReEncrypt*) should include at least one protective condition: kms:ViaService (restricts which AWS service can use the key), kms:CallerAccount (restricts which account can call through the service), or kms:EncryptionContext (restricts the context in which the key can be used). Without conditions, any principal granted by the policy can use the key for any purpose from any service — the policy is authorization without scope.

**Remediation:** Add kms:ViaService to restrict the key to specific services (e.g., "s3.us-east-1.amazonaws.com"). Add kms:CallerAccount for cross-account scenarios. Add kms:EncryptionContext for application-level scoping. At least one condition should be present on every non-administrative usage statement.

---

### CTL.KMS.POLICY.CROSSACCOUNT.001

**KMS Key Policy Must Not Grant Broad Cross-Account Access**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-3; iso_27001_2022: A.8.24; nist_800_53_r5: AC-3; pci_dss_v4.0: 3.4.1; soc2: CC6.1;

KMS key policies must not grant kms:Decrypt, kms:Encrypt, kms:GenerateDataKey, or kms:* to external account principals without restricting via kms:CallerAccount, kms:ViaService, or aws:PrincipalOrgID conditions. Unlike IAM policies, the key policy is the primary authorization mechanism — IAM policies alone cannot grant KMS access unless the key policy permits it. Broad cross-account key access allows external principals to decrypt every resource encrypted by this key.

**Remediation:** Add kms:CallerAccount or aws:PrincipalOrgID conditions to cross-account statements. Restrict kms:ViaService to the specific services that require cross-account key access. Remove statements that grant broad cross-account access.

---

### CTL.KMS.POLICY.GHOSTREF.001

**KMS Key Policy Must Not Reference Deleted Principals**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-3; hipaa: 164.312(a)(1); nist_800_53_r5: AC-3; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

KMS key policies must not grant cryptographic permissions to principal ARNs that don't exist in the IAM inventory. A ghost principal in a key policy inherits decrypt access to every resource encrypted by that key — S3 objects, RDS snapshots, EBS volumes, Secrets Manager secrets. KMS keys are the trust anchor for encryption. Resource-based policies (including key policies) evaluate ARN strings, not unique IDs. An attacker who creates a role matching the ghost principal's name inherits the key's full permission scope.

**Remediation:** Remove the ghost principal ARN from the key policy. Audit which resources use this key for encryption.

---

### CTL.KMS.ROTATION.001

**KMS Customer-Managed Key Rotation Must Be Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 3.6; fedramp_moderate: SC-12; ffiec: ISH-4; gdpr: Art.32; iso_27001_2022: A.8.24; nist_800_53_r5: SC-12; nist_csf_2.0: PR.DS; pci_dss_v4.0: 3.6.1; soc2: CC6.7;

Customer-created symmetric KMS keys must have automatic key rotation enabled. Key rotation limits the amount of data encrypted with a single key version, reducing the blast radius of key compromise.

**Remediation:** Enable key rotation: aws kms enable-key-rotation --key-id <key-id>

---

### CTL.LAMBDA.CODESIGN.001

**Lambda Functions Must Enforce Code Signing**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** aws_security_hub: Lambda.5; mitre_attack: T1059; nist_800_53_r5: SI-7;

Lambda code signing ensures only code signed by an approved entity can be deployed. Without code signing, an attacker with lambda:UpdateFunctionCode permission can replace function code with malicious payloads — exfiltrating environment variables, reading /tmp, or establishing outbound connections. Code signing uses AWS Signer to create cryptographic signatures. Lambda verifies signatures on deployment and rejects unsigned or invalidly-signed packages. This prevents supply chain attacks where a compromised CI/CD pipeline pushes malicious Lambda code to production.

**Remediation:** Create an AWS Signer signing profile, create a code signing config referencing the profile, and attach it to the function: aws lambda put-function-code-signing-config --function-name <n> --code-signing-config-arn <config-arn>

---

### CTL.LAMBDA.CODESIGN.ENFORCE.001

**Lambda Code Signing Must Be Enabled and in Enforce Mode**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SI-7; hipaa: 164.312(c)(1); nist_800_53_r5: SI-7; pci_dss_v4.0: 6.3.2; soc2: CC7.1;

Lambda functions must have a code signing configuration attached with the policy mode set to Enforce. Lambda code signing uses AWS Signer to cryptographically verify that deployment packages were signed by a trusted publisher before the function accepts them. Without a code signing configuration, any package from any source is deployed without integrity verification. In Warn mode, unsigned packages generate a finding but are deployed successfully — this provides observability without protection, the same failure mode as WAF COUNT mode and ECR image signing in audit mode. Only Enforce mode prevents unsigned or invalidly signed packages from being deployed. A supply chain attack that replaces a legitimate package executes immediately with the function's full IAM execution role permissions.

**Remediation:** Create an AWS Signer signing profile for your build pipeline. Create a Lambda code signing configuration referencing the signing profile. Attach the code signing configuration to the function with the policy mode set to Enforce. Update the CI/CD pipeline to sign packages with the Signer profile before deployment. Verify that unsigned deployment attempts are rejected.

---

### CTL.LAMBDA.CONCURRENCY.001

**Lambda Functions Must Have Reserved Concurrency Configured**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-5; hipaa: 164.308(a)(7); nist_800_53_r5: SC-5; pci_dss_v4.0: 1.3.2; soc2: A1.1;

Lambda functions must have reserved concurrency set to a non-zero value. Without reserved concurrency, a function competes for the account-wide concurrency pool with every other function. A single function experiencing a traffic spike can exhaust the account limit and prevent all other functions from executing. Reserved concurrency provides both a ceiling (blast radius limitation) and a floor (availability guarantee) for each function.

**Remediation:** Set reserved concurrency via aws lambda put-function-concurrency --reserved-concurrent-executions <value>. Choose a value that bounds the function's maximum invocations while leaving headroom for other critical functions.

---

### CTL.LAMBDA.DLQ.001

**Lambda Async Invocations Must Have a Dead Letter Queue**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.308(a)(7); soc2: PI1.1;

Lambda functions with asynchronous invocation sources must have a dead-letter queue (SQS or SNS) configured. Without a DLQ, failed async invocations are silently discarded after retries. For functions processing PHI events or compliance-relevant data, silent discard is an undetectable data integrity violation.

**Remediation:** Configure a dead-letter queue (SQS queue or SNS topic) for the function via aws lambda update-function-configuration --dead-letter-config.

---

### CTL.LAMBDA.ENV.ENCRYPT.001

**Lambda Environment Variables Must Be Encrypted with CMK**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-28; hipaa: 164.312(a)(2)(iv); nist_800_53_r5: SC-28; pci_dss_v4.0: 3.4.1; soc2: CC6.7;

Lambda functions with environment variables must encrypt them using a customer-managed KMS key, not the default AWS-managed key. Without CMK encryption, environment variable values are encrypted with a default key that any principal with lambda:GetFunction can decrypt. A CMK provides fine-grained access control over decryption — only principals with kms:Decrypt on the specific key can read the values.

**Remediation:** Create a KMS key and configure the function to use it for environment variable encryption via the aws lambda update-function-configuration --kms-key-arn command.

---

### CTL.LAMBDA.ENV.SECRETS.001

**Lambda Functions Must Not Store Secrets in Environment Variables**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-28; hipaa: 164.312(a)(2)(iv); nist_800_53_r5: SC-28; pci_dss_v4.0: 3.5.1; soc2: CC6.1;

Lambda function environment variables must not contain plaintext secrets such as database credentials, API keys, or tokens. Environment variables are visible in plaintext to anyone with lambda:GetFunction permission, are included in CloudTrail logs for UpdateFunctionConfiguration events, and are stored in the Lambda service's configuration store without application-level encryption. AWS Secrets Manager and SSM Parameter Store SecureString provide encrypted storage with rotation, audit logging, and fine-grained access control. Moving secrets out of environment variables is the single most impactful Lambda security improvement for most functions.

**Remediation:** Move secrets to AWS Secrets Manager or SSM Parameter Store SecureString. Update the function code to retrieve secrets at runtime via the AWS SDK. Remove the plaintext values from the environment variable configuration. Use the Lambda Secrets Manager extension for cached retrieval with minimal latency impact.

---

### CTL.LAMBDA.INVOKE.PUBLIC.001

**Lambda Functions Must Not Have Public Invoke Permissions**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** aws_security_hub: Lambda.1; mitre_attack: T1648; nist_800_53_r5: AC-3;

Lambda resource-based policies must not grant lambda:InvokeFunction to "*" (all principals). A publicly invokable Lambda function allows any AWS account or unauthenticated caller to trigger execution — the function runs with its full IAM execution role, providing code execution and credential access to any internet user. This is MITRE ATT&CK T1648 (Serverless Execution).

**Remediation:** Remove the public invoke permission from the function policy: aws lambda remove-permission --function-name <name> --statement-id <sid>

---

### CTL.LAMBDA.LAYER.GHOST.001

**Lambda Functions Must Not Reference Deleted Layer Versions**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SI-7; soc2: CC6.1;

Lambda functions must not reference layer versions that have been deleted. A missing layer means the function runs without the expected dependency — potentially losing security-relevant libraries, encryption modules, or authentication middleware.

**Remediation:** Update the function to reference an existing layer version or remove the layer.

---

### CTL.LAMBDA.LAYER.ORIGIN.001

**Lambda Layers Must Originate from Trusted Accounts**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SI-7; gdpr: Art.32; nist_800_53_r5: SI-7; soc2: CC7.1;

All Lambda layers referenced by a function must have ARNs whose account IDs are in the organization's trusted account list. Lambda layers execute in the function runtime with the function's execution role permissions. A layer from an untrusted account is unaudited code executing with full function permissions — a supply chain risk independent of the function's own code.

**Remediation:** Replace external layers with organization-owned layers. If third-party layers are required, vendor them into an organization-owned account and reference the vendored copy.

---

### CTL.LAMBDA.LAYER.SECRETS.001

**Lambda Layers Must Not Contain Embedded Secrets**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: IA-5; pci_dss_v4.0: 8.3.4; soc2: CC6.1;

Lambda layers must not contain embedded secrets (API keys, database credentials, certificates, private keys). Unlike environment variables (detectable via ENV.SECRETS.001), layer contents are opaque archives accessible to anyone with lambda:GetLayerVersion permission. Secrets in layers persist across function versions and are not encrypted by KMS.

**Remediation:** Remove secrets from layer contents. Use Secrets Manager or SSM Parameter Store for credentials retrieved at runtime. Republish the layer without sensitive files.

---

### CTL.LAMBDA.LIST.RESTRICT.001

**Lambda Function List Permissions Must Be Restricted**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** mitre_attack: T1526; nist_800_53_r5: AC-6;

Lambda function list permissions must be restricted to administrative roles. Unrestricted lambda:ListFunctions access reveals the entire serverless architecture including function names, runtimes, memory allocations, environment variable keys, and VPC configurations. Attackers use this to identify functions with overprivileged roles, outdated runtimes, or exposed environment variables for targeting.

**Remediation:** Restrict lambda:ListFunctions and lambda:GetFunction to administrative roles only. Apply tag-based access control to limit function enumeration scope. Use AWS Organizations SCPs to enforce lambda list restrictions across accounts.

---

### CTL.LAMBDA.LOG.001

**Lambda Functions Must Have CloudWatch Logging Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AU-2; hipaa: 164.312(b); nist_800_53_r5: AU-2; pci_dss_v4.0: 10.2.1; soc2: CC7.1;

Lambda functions must have CloudWatch Logs enabled. Without logging, function invocations — including unauthorized or malicious invocations — produce no observable output. Error conditions, security events, and application behavior are invisible. For functions with public function URLs, missing logging means a Denial of Wallet attack generates AWS costs with no audit trail. Lambda logging requires the execution role to have logs:CreateLogGroup, logs:CreateLogStream, and logs:PutLogEvents permissions — a missing log group or insufficient permissions silently disables logging without failing the function invocation.

**Remediation:** Grant the execution role CloudWatch Logs permissions: logs:CreateLogGroup, logs:CreateLogStream, logs:PutLogEvents. Verify the log group exists in CloudWatch Logs. If using a custom log group name via the function's logging configuration, ensure the log group is created and the retention policy is set.

---

### CTL.LAMBDA.PASSROLE.001

**Lambda Execution Role Must Not Have Unconstrained iam:PassRole**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6; iso_27001_2022: A.8.3; nist_800_53_r5: AC-6; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

Lambda execution roles must not have iam:PassRole with Resource: *. Unconstrained PassRole allows the function to attach any IAM role to new resources — effectively enabling privilege escalation to any role in the account including admin roles.

**Remediation:** Scope iam:PassRole in the execution role policy to specific role ARNs that the function legitimately needs to pass.

---

### CTL.LAMBDA.ROLE.LEASTPRIV.001

**Lambda Execution Role Must Follow Least Privilege**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-6; hipaa: 164.312(a)(1); nist_800_53_r5: AC-6; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

Lambda function execution roles must not have overly broad permissions. An over-privileged execution role grants the function — and any attacker who compromises or invokes it — access to AWS resources beyond what the function requires. Common violations include admin policies, wildcard resource ARNs on sensitive actions, or managed policies like AmazonS3FullAccess attached to functions that only need read access to a single bucket. When combined with a public function URL or a compromised dependency, an over-privileged role converts a single function compromise into account-wide lateral movement.

**Remediation:** Scope the execution role policy to only the specific actions and resource ARNs the function needs. Replace managed policies like AmazonS3FullAccess with inline policies scoped to specific buckets and actions. Use IAM Access Analyzer to identify unused permissions and generate a least-privilege policy from actual function activity.

---

### CTL.LAMBDA.ROLE.SHARED.001

**Lambda Execution Roles Must Not Be Shared Across Functions**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6; nist_800_53_r5: AC-6; soc2: CC6.1;

Each Lambda function must use a unique execution role not shared with other functions. Shared roles mean a compromise of one function grants the attacker the same permissions as every other function using that role. Blast radius isolation requires per-function roles.

**Remediation:** Create a unique IAM execution role per Lambda function scoped to the minimum permissions that function requires.

---

### CTL.LAMBDA.RUNTIME.001

**Lambda Functions Must Not Use Deprecated Runtimes**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: CM-6; hipaa: 164.312(a)(2)(iv); nist_800_53_r5: CM-6; pci_dss_v4.0: 2.2.1; soc2: CC7.1;

Lambda functions must not run on runtimes that AWS has deprecated. Deprecated runtimes no longer receive security patches from AWS. Unlike EC2 where the operator controls patching, Lambda runtimes are AWS-managed — the only remediation is upgrading the runtime version. AWS publishes deprecation dates months in advance. A function on a deprecated runtime is running on an unpatched execution environment for every invocation. The operator has no mechanism to patch the underlying runtime independently — the runtime version is the patch level. AWS does not forcibly block invocations on deprecated runtimes immediately; functions continue working in a vulnerable state until AWS removes the runtime entirely, at which point the function breaks rather than degrading gracefully. This control detects the compliance gap during the window between deprecation and forced removal.

**Remediation:** Upgrade the Lambda function runtime to a supported version. Check the AWS Lambda runtimes documentation for the current supported runtime list and deprecation schedule. Test the function with the new runtime in a non-production environment before updating production. For Python, Node.js, and Java runtimes, review breaking changes in the language version upgrade guide.

---

### CTL.LAMBDA.RUNTIME.EOL.001

**Lambda Functions Must Not Use End-of-Life Runtimes**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** aws_security_hub: Lambda.2; mitre_attack: T1203; nist_800_53_r5: SI-2;

Lambda functions using end-of-life runtimes do not receive security patches from AWS. Known vulnerabilities in the runtime environment can be exploited to achieve code execution, escape the function sandbox, or access credentials. AWS deprecates runtimes on a published schedule — functions on deprecated runtimes cannot be updated but continue to run, creating a growing attack surface.

**Remediation:** Migrate the function to a supported runtime version. Check the AWS Lambda runtimes page for current supported versions. Test the function with the new runtime in a non-production environment before updating production.

---

### CTL.LAMBDA.TIMEOUT.001

**Lambda Function Timeout Must Not Exceed Safe Threshold**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-5; hipaa: 164.308(a)(7); nist_800_53_r5: SC-5; soc2: A1.1;

Lambda functions must not have a timeout exceeding the safe threshold (default 60 seconds) without a documented justification. Excessively long timeouts amplify Denial of Wallet attacks (pricing is per-millisecond), mask hung or compromised functions, and contribute to account-wide concurrency exhaustion. The threshold is configurable per function via a stave/lambda-timeout-justified tag.

**Remediation:** Reduce the timeout to 60 seconds or less for synchronous API-serving functions. If a longer timeout is operationally required, add a stave/lambda-timeout-justified tag documenting the reason.

---

### CTL.LAMBDA.TRACE.001

**Lambda Functions Must Have Active X-Ray Tracing Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AU-12; hipaa: 164.312(b); nist_800_53_r5: AU-12; pci_dss_v4.0: 10.2.1; soc2: CC7.1;

Lambda functions must have X-Ray tracing set to Active, not PassThrough. Active tracing captures downstream service calls independently of function log output — providing an audit trail of what the function actually did at the infrastructure layer. PassThrough tracing only traces requests with upstream sampling decisions, creating a detection gap exploitable by compromised functions that suppress their own log output.

**Remediation:** Set the function tracing mode to Active via aws lambda update-function-configuration --tracing-config Mode=Active.

---

### CTL.LAMBDA.TRIGGER.GHOST.001

**Lambda Event Source Mappings Must Not Reference Deleted Sources**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** nist_800_53_r5: SI-4; soc2: CC7.1;

Lambda event source mappings must not reference deleted SQS queues, DynamoDB streams, or Kinesis streams. The mapping enters an error state but the failure is surfaced only in the Lambda console. If the function processes security events, that processing stops silently.

**Remediation:** Update or remove the event source mapping.

---

### CTL.LAMBDA.UPDATECODE.SCOPE.001

**lambda:UpdateFunctionCode Must Not Be Broadly Granted**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6; nist_800_53_r5: AC-6; soc2: CC6.1;

IAM policies must not grant lambda:UpdateFunctionCode with Resource: * to non-administrative principals. Broad UpdateFunctionCode allows any developer to replace the code of any Lambda function in the account — injecting malicious code that executes with that function's execution role permissions.

**Remediation:** Scope lambda:UpdateFunctionCode to specific function ARNs in IAM policies. Restrict code deployment to CI/CD pipeline roles only.

---

### CTL.LAMBDA.URL.AUTH.001

**Lambda Function URLs Must Require Authentication**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-3; hipaa: 164.312(a)(1); nist_800_53_r5: AC-3; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

Lambda function URLs must not be configured with AuthType NONE. A function URL with no authentication creates a publicly invocable HTTPS endpoint — no API Gateway, no Cognito, no IAM signature, no network boundary. Any person on the internet can invoke the function with no credentials. The function executes with its full IAM execution role permissions and generates costs for every invocation including attacker-driven invocations. Function URLs bypass every network perimeter control — VPC, security groups, NACLs — that would otherwise restrict access to Lambda invocation. This is distinct from public invocation via the Lambda resource-based policy: a function with a restrictive resource policy can still be publicly invocable if it has a function URL with AuthType NONE. The Denial of Wallet risk is significant — Lambda pricing is per invocation and an unauthenticated endpoint allows unlimited invocations with no cost ceiling.

**Remediation:** Set the function URL AuthType to AWS_IAM to require IAM signature authentication for all invocations. If the function URL is not needed, remove it entirely via aws lambda delete-function-url-config. Note that Lambda resource-based policy restrictions do not apply to function URL invocations — AuthType is the only authentication gate for function URLs.

---

### CTL.LAMBDA.URL.CORS.001

**Function URLs Must Not Combine Wildcard Origin With Credentials**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-4; nist_800_53_r5: AC-4; pci_dss_v4.0: 6.4.1; soc2: CC6.1;

Lambda function URLs can attach a Cors block whose AllowOrigins and AllowCredentials values control cross-origin access. A function URL that sets AllowOrigins to "*" together with AllowCredentials=true encodes intent that any web origin should be able to make credentialed requests against the function. Browsers refuse the combination, but the configuration reveals misaligned intent about which origins should be permitted. This compounds badly with AuthType=NONE (covered separately by CTL.LAMBDA.URL.AUTH.001): a function URL that is both unauthenticated AND has permissive CORS signals a function URL whose access control has not been thought through at all. The observation shape mirrors the Cors block returned by "aws lambda get-function-url-config".

**Remediation:** Update the function URL config via "aws lambda update-function-url-config --function-name <name> --cors '...'" with either AllowCredentials set to false or an AllowOrigins list that enumerates specific origins. If the function handles sensitive operations, also confirm AuthType is AWS_IAM (see CTL.LAMBDA.URL.AUTH.001).

---

### CTL.LAMBDA.VPC.ENDPOINTS.001

**VPC-Attached Lambda Functions Must Use VPC Endpoints for AWS Services**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** network
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.6;

Lambda functions attached to a VPC must use VPC endpoints for AWS service access (S3, DynamoDB, STS, Secrets Manager) instead of routing through NAT gateways or internet gateways. Traffic through NAT leaves the VPC, traverses the public internet, and creates an exfiltration channel.

**Remediation:** Create VPC endpoints (gateway or interface) for the AWS services the function accesses: S3 (gateway), DynamoDB (gateway), Secrets Manager (interface), STS (interface). Associate the endpoints with the function's subnets.

---

### CTL.LAMBDA.VPC.SENSITIVE.001

**Lambda Functions Accessing Sensitive Data Must Be in VPC**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-7; hipaa: 164.312(e)(1); nist_800_53_r5: SC-7; pci_dss_v4.0: 1.3.1; soc2: CC6.6;

Lambda functions tagged with data-classification phi or pii, or functions whose execution role grants access to RDS, DocumentDB, or DynamoDB, must be configured to run inside a VPC. Without VPC, the function executes in AWS-managed infrastructure with direct internet egress — data accessed by the function can be exfiltrated without traversing any network controls.

**Remediation:** Configure the function to run in a VPC with private subnets. Use a NAT gateway for outbound internet access if needed.

---

### CTL.LAMBDA.VPC.SUBNET.001

**Lambda Functions in VPC Must Use Private Subnets**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-7; nist_800_53_r5: SC-7; pci_dss_v4.0: 1.3.1; soc2: CC6.6;

Lambda functions configured to run in a VPC must use private subnets with no direct route to an internet gateway. A function in a public subnet retains direct internet egress despite VPC enrollment — negating the network isolation that VPC membership is intended to provide. This is the complement to CTL.LAMBDA.VPC.SENSITIVE.001: VPC enrollment plus private subnet enforcement together close the network isolation requirement.

**Remediation:** Move the function to private subnets. Use a NAT gateway in a public subnet for outbound access.

---

### CTL.LIGHTSAIL.DB.PUBLIC.001

**Lightsail Databases Must Not Be Publicly Accessible**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.6;

Lightsail managed databases must not be publicly accessible.

**Remediation:** Disable public mode on the database.

---

### CTL.LIGHTSAIL.INSTANCE.PUBLIC.001

**Lightsail Instances Must Not Expose Public Ports Broadly**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.6;

Lightsail instances with public IPs must not have firewall rules allowing broad public access to service ports.

**Remediation:** Restrict firewall rules to specific CIDR ranges.

---

### CTL.MACIE.ENABLED.001

**Amazon Macie Must Be Enabled for S3 Data Discovery**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: RA-5; soc2: CC7.1;

Amazon Macie must be enabled for automated sensitive data discovery in S3 buckets. Without Macie, PII and sensitive data in S3 goes undetected.

**Remediation:** Enable Macie in the account.

---

### CTL.MQ.PUBLIC.001

**Amazon MQ Brokers Must Not Be Publicly Accessible**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.6;

Amazon MQ brokers must not expose public endpoints. Public brokers allow unauthenticated or internet-based access to message queues.

**Remediation:** Disable public accessibility on the broker.

---

### CTL.MSK.AUTH.MTLS.001

**MSK Clusters Must Enforce Mutual TLS Authentication**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: IA-5; soc2: CC6.1;

MSK clusters must enforce mutual TLS (mTLS) for client-broker connections. Without mTLS, adversaries can impersonate clients, intercept sessions, and connect unauthorized producers or consumers.

**Remediation:** Enable mTLS with a certificate authority ARN in the cluster authentication configuration.

---

### CTL.MSK.AUTH.UNRESTRICTED.001

**MSK Clusters Must Not Allow Unauthenticated Access**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3; soc2: CC6.1;

MSK clusters must not enable unauthenticated client access. Without authentication, any network-reachable client can produce or consume messages — reading sensitive data, injecting malicious events, or disrupting the stream.

**Remediation:** Disable unauthenticated access and enable IAM, SASL, or mTLS authentication.

---

### CTL.MSK.CONNECTOR.ENCRYPT.001

**MSK Connect Connectors Must Encrypt Traffic in Transit**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** nist_800_53_r5: SC-8; soc2: CC6.7;

MSK Connect connectors must use TLS for in-transit encryption. Without TLS, data streams between connectors and Kafka brokers are transmitted in plaintext.

**Remediation:** Set connector EncryptionType to TLS.

---

### CTL.MSK.ENCRYPT.REST.001

**MSK Clusters Must Use Customer-Managed KMS Key for Encryption at Rest**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** nist_800_53_r5: SC-28; soc2: CC6.7;

MSK clusters must use a customer-managed KMS key for data volume encryption. Service-managed keys prevent granular key policies, independent rotation, and crypto-shredding capability.

**Remediation:** Specify a customer-managed KMS key via DataVolumeKMSKeyId.

---

### CTL.MSK.ENCRYPT.TRANSIT.001

**MSK Clusters Must Encrypt All Traffic in Transit**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** nist_800_53_r5: SC-8; soc2: CC6.7;

MSK clusters must enforce TLS for both client-broker and inter-broker traffic. Without TLS, Kafka messages — including credentials, event data, and replication traffic — are transmitted in plaintext.

**Remediation:** Set client-broker encryption to TLS only and enable inter-broker encryption.

---

### CTL.MSK.LOG.001

**MSK Clusters Must Have Broker Logging Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AU-2; soc2: CC7.1;

MSK clusters must have at least one logging destination configured (CloudWatch Logs, S3, or Firehose) for broker logs. Without logging, broker operations, authentication events, and access patterns are invisible.

**Remediation:** Enable broker logging to CloudWatch Logs, S3, or Firehose in the cluster logging configuration.

---

### CTL.MSK.MONITORING.001

**MSK Clusters Must Enable Enhanced Monitoring**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AU-6;

MSK clusters must use enhanced monitoring (PER_BROKER or higher). Default monitoring provides insufficient metrics for detecting broker health issues, replication lag, and consumer problems.

**Remediation:** Set enhanced monitoring to PER_BROKER or PER_TOPIC_PER_BROKER.

---

### CTL.MSK.PUBLIC.001

**MSK Clusters Must Not Be Publicly Accessible**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.6;

MSK cluster broker endpoints must not be exposed to the public internet. Public brokers allow unauthorized consumers to read topics, rogue producers to inject events, and internet-wide scanning to enumerate cluster metadata.

**Remediation:** Disable public access on the cluster configuration.

---

### CTL.MSK.VERSION.001

**MSK Clusters Must Run a Supported Kafka Version**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SI-2; soc2: CC7.1;

MSK clusters must run a supported Kafka version. Outdated versions lack security patches and may have known vulnerabilities.

**Remediation:** Upgrade the cluster to the latest supported Kafka version.

---

### CTL.NEPTUNE.AUTH.IAM.001

**Neptune Must Enable IAM Authentication**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: IA-2; soc2: CC6.1;

Neptune clusters must enable IAM database authentication.

**Remediation:** Enable IAM authentication on the cluster.

---

### CTL.NEPTUNE.BACKUP.001

**Neptune Automated Backups Must Be Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** resilience
- **Compliance:** nist_800_53_r5: CP-9; soc2: CC7.1;

Neptune clusters must have automated backups with adequate retention.

**Remediation:** Set backup retention period to at least 7 days.

---

### CTL.NEPTUNE.DELETEPROT.001

**Neptune Must Have Deletion Protection**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** resilience
- **Compliance:** nist_800_53_r5: CP-10; soc2: CC6.1;

Neptune clusters must have deletion protection enabled.

**Remediation:** Enable deletion protection on the cluster.

---

### CTL.NEPTUNE.ENCRYPT.REST.001

**Neptune Clusters Must Have Encryption at Rest**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-28; pci_dss_v4.0: 3.4.1; soc2: CC6.7;

Neptune clusters must encrypt data at rest with KMS.

**Remediation:** Enable encryption. Requires creating a new encrypted cluster.

---

### CTL.NEPTUNE.LOG.AUDIT.001

**Neptune Must Export Logs to CloudWatch**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** nist_800_53_r5: AU-12; soc2: CC7.1;

Neptune clusters must export audit logs to CloudWatch Logs.

**Remediation:** Enable CloudWatch log export on the cluster.

---

### CTL.NEPTUNE.MULTIAZ.001

**Neptune Clusters Must Use Multi-AZ**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** resilience
- **Compliance:** nist_800_53_r5: CP-7; soc2: CC7.1;

Neptune clusters must deploy across multiple availability zones.

**Remediation:** Add read replicas in additional availability zones.

---

### CTL.NEPTUNE.SNAPSHOT.ENCRYPT.001

**Neptune Snapshots Must Be Encrypted**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-28; soc2: CC6.7;

Neptune cluster snapshots must be encrypted.

**Remediation:** Copy snapshots with encryption enabled.

---

### CTL.NEPTUNE.SNAPSHOT.PUBLIC.001

**Neptune Snapshots Must Not Be Public**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3; soc2: CC6.6;

Neptune snapshots must not be publicly accessible.

**Remediation:** Remove public access from the snapshot.

---

### CTL.NEPTUNE.SUBNET.PUBLIC.001

**Neptune Must Not Use Public Subnets**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** network
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.6;

Neptune clusters must not be deployed in public subnets.

**Remediation:** Move the cluster to private subnets.

---

### CTL.NEPTUNE.UPGRADE.001

**Neptune Must Enable Auto Minor Version Upgrade**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SI-2;

Neptune instances must enable automatic minor version upgrades.

**Remediation:** Enable auto minor version upgrade.

---

### CTL.NETFIREWALL.DEFAULT.FRAG.001

**Network Firewall Must Not Pass Fragmented Packets by Default**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.6;

Network Firewall stateless default action for fragmented packets must be aws:drop or aws:forward_to_sfe. Fragmented packets are a common evasion technique — passing them uninspected bypasses deep packet inspection.

**Remediation:** Set StatelessFragmentDefaultActions to aws:drop or aws:forward_to_sfe.

---

### CTL.NETFIREWALL.DEFAULT.FULL.001

**Network Firewall Must Not Pass Full Packets by Default**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.6;

Network Firewall stateless default action for full packets must be aws:drop or aws:forward_to_sfe, not aws:pass. Default PASS means all traffic not matching stateless rules flows uninspected.

**Remediation:** Set StatelessDefaultActions to aws:drop or aws:forward_to_sfe.

---

### CTL.NETFIREWALL.DELETEPROT.001

**Network Firewall Must Have Deletion Protection Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: CP-10; soc2: A1.1;

Network Firewalls must enable deletion protection to prevent accidental or malicious removal. Deleting the firewall removes all traffic inspection from the VPC.

**Remediation:** Enable deletion protection on the firewall.

---

### CTL.NETFIREWALL.LOG.001

**Network Firewall Must Have Logging Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AU-2; soc2: CC7.1;

Network Firewalls must have stateful engine logging configured with at least one log type (FLOW, ALERT, or TLS) and an active destination. Without logging, inspected traffic generates no audit trail.

**Remediation:** Configure logging with FLOW, ALERT, or TLS log types.

---

### CTL.NETFIREWALL.MULTIAZ.001

**Network Firewall Must Be Deployed Across Multiple AZs**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: CP-10; soc2: A1.1;

Network Firewalls must be deployed with subnet mappings in multiple Availability Zones. Single-AZ deployment means an AZ outage removes all traffic inspection.

**Remediation:** Add subnet mappings in additional AZs.

---

### CTL.NETFIREWALL.POLICY.RULEGROUP.001

**Network Firewall Policy Must Have Rule Groups Associated**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.6;

Network Firewall policies must have at least one stateful or stateless rule group associated. An empty policy means the firewall sits in the network path without evaluating any rules — all traffic is handled by the default action alone.

**Remediation:** Associate stateful and/or stateless rule groups with the policy.

---

### CTL.OPENSEARCH.ACCESS.POLICY.001

**Access Policy Must Not Allow Wildcard Principals**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-6; nist_800_53_r5: AC-6; soc2: CC6.1;

OpenSearch domain access policies must not grant access to wildcard principals (Principal: *). A wildcard principal in the resource-based policy allows any AWS account or unauthenticated user to access the cluster, depending on whether the domain is public or VPC-only. Combined with a public endpoint, this enables completely anonymous access.

**Remediation:** Replace wildcard principals with specific IAM role ARNs or account IDs. Use condition keys (aws:SourceIp, aws:SourceVpc) to further restrict access.

---

### CTL.OPENSEARCH.AUDIT.LOG.001

**OpenSearch Domains Must Have Audit Logging Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** aws_security_hub: Opensearch.6; mitre_attack: T1213; nist_800_53_r5: AU-12;

OpenSearch audit logs record all requests to the domain including queries, index operations, and authentication events. Without audit logging, an attacker who accesses the domain can search, read, and export data without any record of what was accessed. OpenSearch domains often contain aggregated application logs, business data, and user activity — making them high-value collection targets.

**Remediation:** Enable audit logs on the domain. Audit logs require fine-grained access control to be enabled first. Update the domain configuration to publish audit logs to CloudWatch Logs.

---

### CTL.OPENSEARCH.AUTH.001

**Authentication Must Be Enabled**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-3; iso_27001_2022: A.8.5; nist_800_53_r5: AC-3; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

OpenSearch domains must have authentication enabled. A domain without authentication allows anyone with network access to query, index, delete, and enumerate all data. The Darkbeam breach (2023) exposed 3.8 billion credentials because the Elasticsearch cluster required zero authentication. The Wyze breach (2019) exposed 2.4 million user records via the same pattern. Authentication is the single most critical OpenSearch security control.

**Remediation:** Enable fine-grained access control with an internal user database or IAM authentication. At minimum, enable the security plugin with a master user. For production, use IAM-based authentication via SAML or Cognito for OpenSearch Dashboards.

---

### CTL.OPENSEARCH.ENCRYPT.001

**Encryption at Rest Must Be Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-28; hipaa: 164.312(a)(2)(iv); nist_800_53_r5: SC-28; pci_dss_v4.0: 3.4.1; soc2: CC6.1;

OpenSearch domains must have encryption at rest enabled using AWS KMS. Unencrypted data at rest is exposed if the underlying storage is compromised or if snapshots are shared.

**Remediation:** Enable encryption at rest in the domain configuration. Note: encryption at rest can only be enabled at domain creation time for some versions. If needed, create a new domain with encryption enabled and migrate data.

---

### CTL.OPENSEARCH.ENCRYPT.002

**Node-to-Node Encryption Must Be Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-8; hipaa: 164.312(e)(2)(ii); nist_800_53_r5: SC-8; soc2: CC6.7;

OpenSearch domains must have node-to-node encryption enabled. Without it, data transmitted between nodes within the cluster travels unencrypted, exposing it to interception on the internal network. Node-to-node encryption is a prerequisite for fine-grained access control.

**Remediation:** Enable node-to-node encryption in the domain configuration. This is required for fine-grained access control.

---

### CTL.OPENSEARCH.FGAC.001

**Fine-Grained Access Control Must Be Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-3; nist_800_53_r5: AC-3; soc2: CC6.1;

OpenSearch domains must have fine-grained access control (FGAC) enabled. Without FGAC, access is controlled only by resource-based policies which cannot restrict access at the index, document, or field level. FGAC enables role-based access control within the cluster, authentication via IAM or internal users, and audit logging of all access decisions.

**Remediation:** Enable fine-grained access control in the domain security configuration. This requires enabling node-to-node encryption and encryption at rest as prerequisites.

---

### CTL.OPENSEARCH.HTTPS.001

**HTTPS Must Be Enforced**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-8; hipaa: 164.312(e)(1); nist_800_53_r5: SC-8; pci_dss_v4.0: 4.2.1; soc2: CC6.7;

OpenSearch domains must enforce HTTPS for all connections. Without HTTPS enforcement, clients can connect over unencrypted HTTP, exposing queries, results, and credentials in transit.

**Remediation:** Enable HTTPS enforcement in the domain endpoint options. Set the TLS security policy to Policy-Min-TLS-1-2-PFS-2023-10 for current best practice.

---

### CTL.OPENSEARCH.INCOMPLETE.001

**Complete Data Required for OpenSearch Assessment**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure

OpenSearch domain safety cannot be proven when access control data is missing from the snapshot. The extractor must populate search_service.access.publicly_accessible to evaluate public exposure controls.

**Remediation:** Re-run the extractor with OpenSearch permissions: es:DescribeDomain, es:DescribeDomainConfig.

---

### CTL.OPENSEARCH.KIBANA.001

**OpenSearch Dashboards Must Not Be Publicly Accessible**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-3; nist_800_53_r5: AC-3; soc2: CC6.1;

OpenSearch Dashboards (Kibana) endpoints must not be publicly accessible without authentication. Dashboards provide a query interface to the entire cluster — a public, unauthenticated dashboard is functionally equivalent to giving attackers a SQL client connected to your database. The Darkbeam breach exposed both the Elasticsearch API and the Kibana dashboard to the public internet.

**Remediation:** Restrict Dashboards access via VPC, Cognito authentication, or SAML federation. Enable fine-grained access control to enforce role-based access within Dashboards.

---

### CTL.OPENSEARCH.LOG.001

**Audit Logging Must Be Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AU-2; hipaa: 164.312(b); nist_800_53_r5: AU-2; soc2: CC7.1;

OpenSearch domains must have audit logging enabled to track authentication attempts, access decisions, and data operations. Without audit logging, unauthorized access to the cluster cannot be detected or investigated after the fact.

**Remediation:** Enable audit logging in the domain configuration. Configure a CloudWatch log group as the destination. Fine-grained access control must be enabled as a prerequisite for audit logging.

---

### CTL.OPENSEARCH.PUBLIC.001

**OpenSearch Domain Must Not Be Publicly Accessible**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-3; iso_27001_2022: A.8.20; nist_800_53_r5: AC-3; pci_dss_v4.0: 1.3.1; soc2: CC6.1;

OpenSearch domains must not have public endpoints accessible from the internet. A publicly accessible domain allows anyone to query, index, or enumerate data without network-level restrictions. The Darkbeam breach (2023) exposed 3.8 billion records from an Elasticsearch instance left unprotected on the public internet. Domains must be deployed within a VPC.

**Remediation:** Migrate the domain to a VPC. Create a new domain with VPC configuration specifying private subnets and security groups. Use VPN, bastion, or AWS PrivateLink for authorized access.

---

### CTL.OPENSEARCH.SNAPSHOT.001

**Snapshots Must Be Encrypted**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-28; hipaa: 164.312(a)(2)(iv); nist_800_53_r5: SC-28; soc2: CC6.7;

OpenSearch domain snapshots must be stored in encrypted repositories. Unencrypted snapshots expose the same data as the live cluster but are often stored with weaker access controls. Snapshot repositories in S3 must use server-side encryption.

**Remediation:** Configure the snapshot repository S3 bucket with default encryption (SSE-S3 or SSE-KMS). Verify the IAM role used for snapshots has minimum required permissions.

---

### CTL.OPENSEARCH.VPC.001

**Domain Must Be Deployed in VPC**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-7; iso_27001_2022: A.8.20; nist_800_53_r5: SC-7; pci_dss_v4.0: 1.3.1; soc2: CC6.6;

OpenSearch domains must be deployed within a VPC, not on public endpoints. A domain outside a VPC is directly reachable from the internet, bypassing all network-level controls. Even with authentication enabled, a public endpoint exposes the cluster to brute-force, credential stuffing, and zero-day exploits. VPC deployment restricts access to authorized networks only.

**Remediation:** Create a new domain with VPC configuration specifying private subnets and security groups. Migrate data from the public domain. Use VPN, bastion host, or AWS PrivateLink for authorized access. Note: existing domains cannot be migrated to VPC in-place.

---

### CTL.ORG.REGION.SCP.001

**AWS Organizations Must Have an SCP Restricting Resource Creation to Approved Regions**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: CM-7; gdpr: Art.32; hipaa: 164.312(b); nist_800_53_r5: CM-7; pci_dss_v4.0: 12.5.2; soc2: CC7.1;

AWS Organizations must have a Service Control Policy that restricts resource creation to an approved set of AWS regions. Without a region restriction SCP, any IAM principal can create resources in any of 30+ regions — including regions where the organization has no CloudTrail, no GuardDuty, no Config recording, and no monitoring infrastructure. MITRE ATT&CK T1535 documents this as a defense evasion technique: attackers deliberately operate in unused regions to bypass cloud monitoring. A region restriction SCP closes all unmonitored regions simultaneously with a single organizational policy rather than requiring monitoring deployment to every region. This is the architectural complement to per-region monitoring controls — it eliminates the regions where monitoring is not deployed.

**Remediation:** Attach an SCP to the organization root with a Deny statement conditioned on aws:RequestedRegion that restricts resource creation to the organization's approved operating regions. Example condition: StringNotEquals aws:RequestedRegion [us-east-1, us-west-2, eu-west-1]. Exclude global services (IAM, CloudFront, Route 53) from the restriction using a NotAction list.

---

### CTL.RDS.AUTOUPGRADE.001

**RDS Auto Minor Version Upgrade Must Be Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 2.3.2; fedramp_moderate: CM-6; nist_800_53_r5: CM-6; pci_dss_v4.0: 2.2.1; soc2: A1.1;

RDS instances must have automatic minor version upgrades enabled. Minor versions include security patches. Without auto-upgrade, instances run known-vulnerable database engine versions.

**Remediation:** Enable auto minor version upgrade: aws rds modify-db-instance --db-instance-identifier <id> --auto-minor-version-upgrade --apply-immediately

---

### CTL.RDS.BACKUP.001

**RDS Automated Backups Must Be Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.308(a)(7); soc2: A1.1;

RDS instances must have automated backups enabled with a retention period of at least 7 days. Without backups, data loss from accidental deletion, corruption, or ransomware is permanent.

**Remediation:** Enable automated backups with at least 7 days retention. Run: aws rds modify-db-instance --db-instance-identifier xxx --backup-retention-period 7 --apply-immediately

---

### CTL.RDS.CLUSTER.DELETION.PROTECT.001

**RDS Aurora Clusters Must Have Deletion Protection Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** resilience
- **Compliance:** aws_security_hub: RDS.34; mitre_attack: TA0040; nist_800_53_r5: CP-9;

Aurora clusters without deletion protection can be permanently deleted via API or console without additional confirmation. Ransomware actors who gain IAM access with rds:DeleteDBCluster can destroy entire Aurora clusters including all instances and cluster storage. Deletion protection requires explicitly disabling the protection before deletion — breaking automated ransomware scripts.

**Remediation:** aws rds modify-db-cluster --db-cluster-identifier <id> --deletion-protection --apply-immediately

---

### CTL.RDS.CLUSTER.LOGGING.001

**RDS Aurora Clusters Must Export Logs to CloudWatch**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** aws_security_hub: RDS.36; mitre_attack: TA0005; nist_800_53_r5: AU-12;

RDS Aurora log export to CloudWatch Logs enables centralized log management, alerting on database errors, and retention beyond the default 7-day on-instance period. Without CloudWatch export, database audit logs, error logs, and slow query logs are only available via the RDS console for a limited period — making forensic investigation difficult after an incident.

**Remediation:** aws rds modify-db-cluster --db-cluster-identifier <id> --cloudwatch-logs-export-configuration EnableLogTypes=audit,error,slowquery --apply-immediately

---

### CTL.RDS.DELETEPROT.001

**RDS Instances Must Have Deletion Protection Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws: 2.3.3; nist_800_53_r5: CP-9;

RDS instances must have deletion protection enabled to prevent accidental or malicious database destruction. Without it, ransomware actors or misconfigured automation can permanently destroy production databases with a single API call.

**Remediation:** aws rds modify-db-instance --db-instance-identifier <id> --deletion-protection --apply-immediately

---

### CTL.RDS.ENCRYPT.001

**RDS Storage Encryption Must Be Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v1.4.0: 2.3.1; cis_aws_v3.0: 2.3.1; fedramp_moderate: SC-28; ffiec: ISH-4; gdpr: Art.32; hipaa: 164.312(a)(2)(iv); iso_27001_2022: A.8.24; nist_800_53_r5: SC-28; nist_csf_2.0: PR.DS; pci_dss_v4.0: 3.4.1; soc2: CC6.7;

RDS instances must have storage encryption enabled. Unencrypted database storage exposes data at rest to unauthorized access if the underlying storage is compromised.

**Remediation:** Storage encryption can only be enabled at creation time. Create a snapshot, copy it with encryption enabled, then restore to a new encrypted instance. Enable encryption by default for new instances.

---

### CTL.RDS.ENGINE.EOL.001

**RDS Instances Must Not Run End-of-Life Database Engine Versions**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SI-2; hipaa: 164.312(c)(1); nist_800_53_r5: SI-2; pci_dss_v4.0: 6.3.3; soc2: CC7.1;

RDS instances must not run major database engine versions that have reached end-of-life (EOL) and no longer receive security patches from the engine vendor. This is distinct from CTL.RDS.AUTOUPGRADE.001 which covers automatic minor version upgrades within a supported major version. Auto minor upgrade does not upgrade between major versions — an EOL major version receives no further patches regardless of the auto-upgrade setting. PostgreSQL 11 (EOL November 2023), MySQL 5.7 (EOL October 2023), and MariaDB 10.4 (EOL June 2024) are examples of major versions that continue running on RDS but receive no security patches from the upstream vendor. The engine version is permanently unpatched against any vulnerability disclosed after EOL. For PHI and cardholder data environments, running an EOL engine is a direct compliance finding — HIPAA requires maintained software and PCI-DSS 6.3.3 requires protection from known vulnerabilities through patching.

**Remediation:** Upgrade the RDS instance to a supported major engine version. For PostgreSQL, upgrade to PostgreSQL 14 or later. For MySQL, upgrade to MySQL 8.0. For MariaDB, upgrade to MariaDB 10.6 or later. Use a blue-green deployment or read replica promotion to minimize downtime. Test the application against the new major version in a staging environment before upgrading production — major version upgrades may include breaking changes in SQL behavior, function signatures, or default settings.

---

### CTL.RDS.EVENTS.001

**RDS Must Have Event Subscriptions for Critical Events**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AU-12;

RDS instances must have event subscriptions configured for critical event categories. RDS event subscriptions notify operators of configuration changes, failovers, security group modifications, and parameter group changes. Without event subscriptions, critical changes to database instances go undetected — an attacker who modifies security groups, disables encryption, or changes authentication settings generates no alert. RDS events are the primary detection mechanism for unauthorized database configuration changes. Event subscriptions are not enabled by default and must be explicitly created for each event category. The absence of event subscriptions creates a detection gap where database-level security changes occur without any notification to the security team.

**Remediation:** Create RDS event subscriptions for critical event categories including configuration change, failover, failure, maintenance, and security group. Subscribe to an SNS topic that routes to the security monitoring pipeline. At minimum, create subscriptions for the db-instance source type with the configuration change and security categories enabled.

---

### CTL.RDS.IAMAUTH.001

**RDS Must Enable IAM Authentication**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** hipaa: 164.312(d);

RDS instances should enable IAM database authentication. IAM auth eliminates long-lived database passwords and integrates with AWS identity governance for centralized access control and audit.

**Remediation:** Enable IAM authentication on the instance. Run: aws rds modify-db-instance --db-instance-identifier xxx --enable-iam-database-authentication --apply-immediately

---

### CTL.RDS.INCOMPLETE.001

**Complete Data Required for RDS Assessment**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure

RDS instance safety cannot be assessed when encryption status is missing from the snapshot. The extractor must populate database.encryption.storage_encrypted.

**Remediation:** Re-run the extractor with RDS permissions: rds:DescribeDBInstances, rds:DescribeDBClusters.

---

### CTL.RDS.LOG.001

**RDS Audit Logging Must Be Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.312(b); soc2: CC7.1;

RDS instances must export audit logs to CloudWatch. Without audit logging, database access patterns cannot be monitored and unauthorized queries are undetectable.

**Remediation:** Enable CloudWatch log exports for the database engine. Run: aws rds modify-db-instance --db-instance-identifier xxx --cloudwatch-logs-export-configuration '{"EnableLogTypes":["audit","error","slowquery"]}'

---

### CTL.RDS.MINOR.UPGRADE.001

**RDS Instances Must Enable Automatic Minor Version Upgrades**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** aws_security_hub: RDS.13; mitre_attack: TA0003; nist_800_53_r5: SI-2;

Minor version upgrades contain security patches for the database engine. Disabling automatic minor upgrades means security patches require manual intervention — patches are commonly delayed or forgotten, leaving the database engine vulnerable to known CVEs. Minor upgrades are backwards-compatible by design and the maintenance window controls when they apply.

**Remediation:** aws rds modify-db-instance --db-instance-identifier <id> --auto-minor-version-upgrade --apply-immediately

---

### CTL.RDS.MONITORING.001

**RDS Enhanced Monitoring Must Be Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 2.2.1; hipaa: 164.312(b); nist_800_53_r5: SI-4; soc2: CC7.1;

RDS instances must have Enhanced Monitoring enabled. Enhanced Monitoring provides real-time OS-level metrics (CPU, memory, disk I/O, network) that standard CloudWatch metrics do not capture. Without it, performance degradation and resource exhaustion attacks are harder to detect and investigate.

**Remediation:** Enable Enhanced Monitoring with a 60-second granularity. Run: aws rds modify-db-instance --db-instance-identifier xxx --monitoring-interval 60 --monitoring-role-arn arn:aws:iam::ACCOUNT:role/rds-monitoring-role --apply-immediately

---

### CTL.RDS.MULTIAZ.001

**RDS Instances Must Use Multi-AZ Deployment**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.308(a)(7); soc2: A1.1;

Production RDS instances must use Multi-AZ deployment for high availability. Single-AZ instances have a single point of failure that can cause data unavailability during AZ outages.

**Remediation:** Modify the instance to enable Multi-AZ. Run: aws rds modify-db-instance --db-instance-identifier xxx --multi-az --apply-immediately

---

### CTL.RDS.PARAM.GROUP.001

**RDS Instances Must Not Use the Default Parameter Group**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** aws_security_hub: RDS.19; mitre_attack: TA0005; nist_800_53_r5: CM-6;

The default RDS parameter group uses AWS-managed settings that cannot be audited for security-relevant configuration. A custom parameter group enables enforcing SSL/TLS enforcement, audit logging parameters, and password validation plugins. Without a custom parameter group, these security settings cannot be verified or enforced via configuration snapshots.

**Remediation:** Create a custom parameter group and attach it to the instance. Then set security parameters such as require_secure_transport=ON for MySQL or rds.force_ssl=1 for PostgreSQL.

---

### CTL.RDS.PERFORMANCE.INSIGHTS.001

**RDS Instances Must Have Performance Insights Enabled with KMS Encryption**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** aws_security_hub: RDS.17; mitre_attack: TA0005; nist_800_53_r5: AU-12;

Performance Insights captures database query patterns and wait events. When encrypted with a customer-managed KMS key, this data is protected and provides an additional audit source for database activity. Without Performance Insights, slow or anomalous queries such as bulk data extraction may not be visible in standard database logs.

**Remediation:** aws rds modify-db-instance --db-instance-identifier <id> --enable-performance-insights --performance-insights-kms-key-id <key-arn> --performance-insights-retention-period 731 --apply-immediately

---

### CTL.RDS.PUBLIC.001

**RDS Instances Must Not Be Publicly Accessible**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v1.4.0: 2.3.2; cis_aws_v3.0: 2.3.3; fedramp_moderate: AC-3; ffiec: ISH-4; gdpr: Art.32; hipaa: 164.312(a)(1); iso_27001_2022: A.8.3; nist_800_53_r5: AC-3; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

RDS instances must not have public accessibility enabled. A publicly accessible database is reachable from the internet, exposing it to brute force attacks, SQL injection, and unauthorized data access.

**Remediation:** Modify the instance to disable public accessibility. Run: aws rds modify-db-instance --db-instance-identifier xxx --no-publicly-accessible --apply-immediately

---

### CTL.RDS.SG.BROAD.001

**RDS Security Group Must Not Allow Broad Ingress on Database Ports**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** network
- **Compliance:** fedramp_moderate: SC-7; iso_27001_2022: A.8.20; nist_800_53_r5: SC-7; pci_dss_v4.0: 1.3.4; soc2: CC6.6;

The RDS instance's associated security group must not allow 0.0.0.0/0 ingress on the database port. Broad ingress makes the database reachable from any IP address on the internet. Combined with PubliclyAccessible=true (CTL.RDS.PUBLIC.001), this creates direct internet exposure. Even with PubliclyAccessible=false, a broad SG allows access from anywhere within the VPC — defeating network segmentation if the VPC has a compromised instance.

**Remediation:** Replace the broad 0.0.0.0/0 rule with specific CIDR ranges (application server IPs, VPN exit IPs, or security group references for application-tier instances).

---

### CTL.RDS.SNAPSHOT.ENCRYPT.001

**RDS Automated Snapshots Must Be Encrypted**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** aws_security_hub: RDS.4; hipaa: 164.312(a)(2)(iv); mitre_attack: TA0010; nist_800_53_r5: SC-28;

Unencrypted RDS snapshots can be copied to any AWS account and restored without requiring access to a KMS key. Snapshot encryption ensures that even if a snapshot is shared, it cannot be restored without the KMS key. RDS snapshot encryption follows the source instance's encryption setting — instances must be encrypted at creation.

**Remediation:** Create an encrypted copy of the snapshot, then restore a new instance from the encrypted snapshot. Migrate the application to the new encrypted instance.

---

### CTL.RDS.SNAPSHOT.EXPORT.001

**RDS Snapshot Export to S3 Must Be Restricted to Authorized Roles**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** mitre_attack: T1005; nist_800_53_r5: AC-3;

RDS snapshot export converts a database snapshot to Apache Parquet format and stores it in S3 — making the entire database contents accessible as files. An attacker with rds:StartExportTask permission can export any RDS snapshot to an attacker-controlled S3 bucket in any account. This is a complete database exfiltration primitive: no need to query row by row — export the snapshot and read all data as Parquet files.

**Remediation:** Restrict rds:StartExportTask via IAM policy to approved roles. Use a resource condition to limit S3 destination to approved buckets. Monitor for export tasks via CloudTrail alerting.

---

### CTL.RDS.SNAPSHOT.PUBLIC.001

**RDS Snapshots Must Not Be Publicly Accessible**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** mitre_attack: T1537; nist_800_53_r5: AC-3;

RDS snapshots must not be publicly accessible. A public snapshot can be copied to any AWS account and restored as a full database, granting complete read access to all data.

**Remediation:** aws rds modify-db-snapshot-attribute --db-snapshot-identifier <id> --attribute-name restore --values-to-remove all

---

### CTL.RDS.SSL.001

**RDS Must Require SSL Connections**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v1.4.0: 2.3.3; fedramp_moderate: SC-8; ffiec: ISH-4; gdpr: Art.32; hipaa: 164.312(e)(2)(ii); nist_800_53_r5: SC-8; pci_dss_v4.0: 4.2.1; soc2: CC6.6;

RDS instances must enforce SSL/TLS for all client connections. Without require_ssl, database traffic travels unencrypted over the network, exposing query data and credentials to interception.

**Remediation:** Set the rds.force_ssl parameter to 1 in the parameter group (PostgreSQL) or require_secure_transport to ON (MySQL). For Aurora, use the cluster parameter group.

---

### CTL.RDS.SSL.ENFORCE.001

**RDS Instances Must Enforce SSL/TLS for All Connections**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** aws_security_hub: RDS.25; hipaa: 164.312(e)(2)(ii); mitre_attack: TA0006; nist_800_53_r5: SC-8;

RDS connections without SSL/TLS transmit database credentials and query results in plaintext over the network. In a VPC, any compromised instance with network access can capture database passwords and sensitive data via passive network monitoring. SSL enforcement is configured via parameter group (require_secure_transport for MySQL, rds.force_ssl for PostgreSQL/SQL Server).

**Remediation:** Set the appropriate SSL parameter in the parameter group: MySQL: require_secure_transport=ON. PostgreSQL: rds.force_ssl=1. SQL Server: rds.force_ssl=1.

---

### CTL.REDSHIFT.BACKUP.001

**Redshift Automated Snapshots Must Be Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** resilience
- **Compliance:** nist_800_53_r5: CP-9; soc2: CC7.1;

Redshift clusters must have automated snapshots enabled with adequate retention.

**Remediation:** Set automated snapshot retention period to at least 7 days.

---

### CTL.REDSHIFT.CONFIG.ADMIN.001

**Redshift Must Not Use Default Admin Username**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: IA-5;

Redshift clusters must not use the default admin username (awsuser).

**Remediation:** Create a new cluster with a non-default admin username.

---

### CTL.REDSHIFT.CONFIG.DBNAME.001

**Redshift Must Not Use Default Database Name**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** identity

Redshift clusters should not use the default database name (dev).

**Remediation:** Create a new cluster with a descriptive database name.

---

### CTL.REDSHIFT.ENCRYPT.REST.001

**Redshift Clusters Must Have Encryption at Rest Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-28; pci_dss_v4.0: 3.4.1; soc2: CC6.7;

Redshift clusters must have encryption at rest enabled with KMS.

**Remediation:** Enable encryption. Requires creating a new encrypted cluster and migrating data.

---

### CTL.REDSHIFT.LOG.ACTIVITY.001

**Redshift Must Log User Activity**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** nist_800_53_r5: AU-12; soc2: CC7.1;

Redshift user activity logging must be enabled to record SQL statements.

**Remediation:** Enable user activity logging in the parameter group.

---

### CTL.REDSHIFT.LOG.AUDIT.001

**Redshift Clusters Must Have Audit Logging Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** nist_800_53_r5: AU-12; soc2: CC7.1;

Redshift audit logging must be enabled for connection, user, and query activity.

**Remediation:** Enable audit logging to S3 or CloudWatch.

---

### CTL.REDSHIFT.PUBLIC.001

**Redshift Clusters Must Not Be Publicly Accessible**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3; pci_dss_v4.0: 1.3.4; soc2: CC6.6;

Redshift clusters must not have the publicly accessible setting enabled.

**Remediation:** Disable public accessibility and place the cluster in a private subnet.

---

### CTL.REDSHIFT.SSL.001

**Redshift Clusters Must Require SSL Connections**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-8; pci_dss_v4.0: 4.2.1; soc2: CC6.7;

Redshift parameter group must set require_ssl to true.

**Remediation:** Set require_ssl=true in the cluster's parameter group.

---

### CTL.REDSHIFT.UPGRADE.001

**Redshift Must Allow Automatic Version Upgrades**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SI-2;

Redshift clusters should have automatic version upgrades enabled.

**Remediation:** Enable AllowVersionUpgrade on the cluster.

---

### CTL.REDSHIFT.VPC.ROUTING.001

**Redshift Must Use Enhanced VPC Routing**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** network
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.6;

Redshift clusters must use enhanced VPC routing to force all COPY and UNLOAD traffic through the VPC.

**Remediation:** Enable enhanced VPC routing on the cluster.

---

### CTL.ROUTE53.DANGLING.001

**Route53 A Records Must Not Point to Unassigned IP Addresses**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: CM-8; soc2: CC6.1;

Route53 A records using literal IP addresses must point to IP addresses currently assigned to resources in the account. Dangling IPs enable subdomain takeover — an attacker claims the released IP and serves content under the organization's domain.

**Remediation:** Remove the dangling record or reassign the IP.

---

### CTL.ROUTE53.GHOST.001

**Route53 Records Must Not Point to Deleted AWS Resources**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: CM-8; soc2: CC6.1;

Route53 records (A, AAAA, CNAME, Alias) must not point to AWS resources that have been deleted — ELBs, CloudFront distributions, S3 website endpoints, Elastic IPs, or API Gateways. For reclaimable resources (released EIPs, deleted S3 bucket names), an attacker claims the target and receives all traffic the DNS record directs. This extends CTL.ROUTE53.DANGLING.001 (dangling IPs) and CTL.DNS.DANGLING.001-003 (external hosting takeover) to cover deleted AWS resources specifically.

**Remediation:** Remove or update the DNS record to point to an existing resource.

---

### CTL.ROUTE53.HEALTHCHECK.001

**Route 53 Health Checks Must Be Configured**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** soc2: A1.1;

Route 53 health checks must be configured for DNS records pointing to critical endpoints. Without health checks, DNS routes to failed endpoints.

**Remediation:** Create health checks: aws route53 create-health-check and associate with failover routing.

---

### CTL.ROUTE53.INCOMPLETE.001

**Complete Data Required for Route 53 Assessment**

- **Severity:** info
- **Type:** unsafe_state
- **Domain:** exposure

The observation snapshot is missing required Route 53 properties.

**Remediation:** Ensure the extractor calls aws route53 list-hosted-zones and list-health-checks.

---

### CTL.ROUTE53.LOG.001

**Route53 Public Hosted Zones Must Enable Query Logging**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AU-2; soc2: CC7.1;

Public hosted zones must have DNS query logging enabled to CloudWatch Logs. Without logging, DNS queries — including reconnaissance and potential DNS tunneling — go undetected.

**Remediation:** Enable query logging to CloudWatch Logs.

---

### CTL.ROUTE53.PRIVACY.001

**Route53 Domains Must Enable WHOIS Privacy Protection**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3;

Registered domains must have WHOIS privacy protection enabled to redact registrant contact details from public queries.

**Remediation:** Enable privacy protection on the domain registration.

---

### CTL.ROUTE53.TRANSFER.001

**Route53 Domains Must Enable Transfer Lock**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3; soc2: CC6.1;

Registered domains must have transfer lock (clientTransferProhibited) enabled to prevent unauthorized domain transfers. Without transfer lock, an attacker who compromises registrar credentials can transfer the domain to another registrar.

**Remediation:** Enable transfer lock on the domain registration.

---

### CTL.S3.ACCEL.001

**S3 Transfer Acceleration Must Not Be Unexpectedly Enabled**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: CM-7;

S3 Transfer Acceleration creates an additional public endpoint (s3-accelerate.amazonaws.com) that bypasses VPC endpoint restrictions. It must not be enabled unless explicitly required and documented.

**Remediation:** Suspend Transfer Acceleration under bucket Properties unless explicitly required. If required, document the business justification and ensure VPC endpoint policies account for the acceleration endpoint.

---

### CTL.S3.ACCESS.001

**No Unauthorized Cross-Account Access**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v1.4.0: 1.16; nist_800_53_r5: AC-3; pci_dss_v3.2.1: 7.1; soc2: CC6.3;

S3 bucket policies must not grant access to external AWS accounts. `allowed_accounts` contains trusted external AWS account IDs (12-digit). Access from accounts outside this allowlist is unsafe.

**Remediation:** Review bucket policy Principal elements for external account IDs. Remove statements granting access to accounts not in your organization. Use aws:PrincipalOrgID condition to restrict access to your AWS Organization.

---

### CTL.S3.ACCESS.002

**No Wildcard Principal Policies**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-6;

S3 bucket policies must not grant access to a wildcard principal (Principal "*" or AWS: "*"). A wildcard principal makes every statement in the policy effectively anonymous or cross-account unless a restricting Condition (aws:PrincipalOrgID, aws:SourceVpc, aws:SourceIp with a fixed CIDR, aws:SourceArn, etc.) narrows it. Without such a Condition, the policy is a public-access grant regardless of which specific S3 actions are allowed.

**Remediation:** Replace the wildcard principal with the specific AWS account IDs or ARNs that need access, or add a restricting Condition on aws:PrincipalOrgID, aws:SourceVpc, aws:SourceIp (with a fixed CIDR), or aws:SourceArn. If the bucket genuinely needs to be public (CDN origin, static asset bucket), narrow the Actions to the minimum set and keep Public Access Block enabled where compatible.

---

### CTL.S3.ACCESS.003

**No External Write Access**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure

S3 buckets must not grant write or delete permissions to external AWS accounts. Cross-account read access may be acceptable for analytics or auditing, but write access from external accounts creates data integrity and supply chain risks.

**Remediation:** Remove bucket policy statements granting s3:PutObject, s3:DeleteObject, or s3:PutBucketPolicy to external accounts. If cross-account write is required, restrict to specific account IDs with condition keys.

---

### CTL.S3.ACCESS.004

**Bucket Policy Must Not Be Effectively Public**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.312(a)(1); nist_800_53_r5: AC-3; soc2: CC6.1;

Bucket policy evaluates as effectively public under AWS PolicyStatus.IsPublic semantics — a wildcard principal (`Principal: "*"` or `Principal: {"AWS": "*"}`) without a scoping Condition on `aws:SourceVpc`, `aws:SourceVpce`, `aws:PrincipalOrgID`, `aws:PrincipalArn`, or a narrow `aws:SourceIp`. The control reads the policy in isolation: Public Access Block state does not affect whether it fires — PAB only affects whether the exposure is active right now or latent (one account-level or bucket-level PAB toggle away from active). Paired with the PAB controls, this is the posture signal that says "if every PAB layer were removed tomorrow, this bucket would be public". Distinct from CTL.S3.ACCESS.002, which detects the raw presence of a wildcard principal without reasoning about scoping Conditions: ACCESS.002 answers "is there a wildcard whose Conditions we still need to verify?", ACCESS.004 answers "has the verification already concluded that the policy is public?".

**Remediation:** 1. Identify the Allow statement with the wildcard principal. If it is
   not intentional, remove it.
2. If the statement is intentional (CDN origin, cross-organization
   data distribution), add a Condition that fixes the caller set —
   `aws:PrincipalOrgID` for same-org access, `aws:SourceVpc` or
   `aws:SourceVpce` for VPC-bound access, `aws:SourceIp` with a
   fixed CIDR for known network ranges, or `aws:SourceArn` for a
   specific invoking service or distribution.
3. Until the policy is fixed, keep S3 Block Public Access fully
   enforced at the account and bucket level so the exposure stays
   latent rather than active.

---

### CTL.S3.ACCESS.GRANTS.001

**S3 Access Grants Must Not Grant Broad Permissions**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.312(a)(1);

S3 Access Grants provide temporary credentials scoped to a bucket or prefix. An Access Grant with READWRITE permission on a broad scope (entire bucket or wildcard prefix) bypasses bucket policy restrictions.

**Remediation:** Restrict grant scope to specific prefixes. Use READ not READWRITE.

---

### CTL.S3.ACCESS.GRANTS.002

**S3 Access Grants Identity Center Must Be Attached**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance

When S3 Access Grants are enabled, IAM Identity Center should be attached to the Access Grants instance. Without Identity Center, grants can only target IAM principals — losing the benefit of centralized identity governance and SSO-based access control.

**Remediation:** Associate IAM Identity Center with the Access Grants instance using aws s3control associate-access-grants-identity-center. This enables directory-based grantee resolution.

---

### CTL.S3.ACCESS.PHI.001

**PHI Bucket Access Must Be Scoped to Specific Principals**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-6; hipaa: 164.502(b); nist_800_53_r5: AC-6; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

S3 buckets tagged with data-classification=phi must have access restricted to explicitly named principals and prefixes. Broad bucket-level access (wildcard principals, unrestricted actions) on PHI data violates the HIPAA minimum necessary standard (§164.502(b)). Access must be narrowed to the exact IAM roles, account IDs, and object prefixes required for each authorized workflow.

**Remediation:** Restrict bucket policy to named IAM role ARNs and specific object prefixes. Remove wildcard principals and broad s3:* actions. Use IAM Access Analyzer to identify unused permissions and generate least-privilege policies from CloudTrail activity.

---

### CTL.S3.ACCOUNT.PAB.001

**Account-Level Block Public Access Must Be Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 2.1.4; fedramp_moderate: AC-3; gdpr: Art.32; iso_27001_2022: A.8.3; nist_800_53_r5: AC-3; nist_csf_2.0: PR.PS; soc2: CC6.1;

The AWS account must have S3 Block Public Access enabled at the account level. Account-level PAB overrides all bucket and object settings, providing a hard ceiling that prevents any S3 resource in the account from being made public regardless of bucket policies, ACLs, or access point policies. Without account-level PAB, each bucket's public access depends on its own settings, and a single misconfigured bucket or object ACL can expose data. Account-level PAB is the strongest single defense against accidental public exposure.

**Remediation:** Enable all four S3 Block Public Access settings at the account level using aws s3control put-public-access-block with the --account-id parameter. This blocks public access for all current and future buckets in the account. If specific buckets require public access, use CloudFront with Origin Access Control instead of making buckets directly public.

---

### CTL.S3.ACL.ESCALATION.001

**No Public ACL Modification**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure

S3 bucket ACLs must not be writable by AllUsers or AuthenticatedUsers. WRITE_ACP permission enables attackers to modify the ACL itself, granting themselves FULL_CONTROL and escalating to read, write, and delete all objects.

**Remediation:** Remove WRITE_ACP grants from the bucket ACL and remove policy statements granting s3:PutBucketAcl or s3:PutObjectAcl to public principals. Enable S3 Public Access Block with BlockPublicAcls set to true.

---

### CTL.S3.ACL.FULLCONTROL.001

**No FULL_CONTROL ACL Grants to Public**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3;

S3 bucket ACLs must not grant FULL_CONTROL to AllUsers or AuthenticatedUsers. FULL_CONTROL is the worst-case ACL misconfiguration — the grantee can read, write, and delete objects and modify the ACL itself.

**Remediation:** Replace the bucket ACL with "BucketOwnerFullControl" or remove the FULL_CONTROL grant to public groups. Enable S3 Public Access Block with BlockPublicAcls and IgnorePublicAcls set to true.

---

### CTL.S3.ACL.OBJECT.001

**Objects Must Not Be Individually Public via ACL**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-3; gdpr: Art.32; iso_27001_2022: A.8.3; nist_800_53_r5: AC-3; soc2: CC6.1;

S3 buckets must not contain objects that are individually made public through object-level ACL grants. When a bucket itself is not public, individual objects can still be accessible from the internet if their ACL grants read access to AllUsers or AuthenticatedUsers. This is the "Objects can be public" status in AWS — the bucket is private but objects inside it are exposed. This is a primary vector for data leakage through misplaced sensitive files, where a single object with a public ACL in an otherwise private bucket exposes data that was never intended to be public.

**Remediation:** Set Object Ownership to BucketOwnerEnforced to disable all ACLs. If that is not immediately possible, enable S3 Block Public Access with IgnorePublicAcls set to true, then audit object ACLs using S3 Inventory with the optional ACL fields. Remove public grants from individual objects using aws s3api put-object-acl.

---

### CTL.S3.ACL.RECON.001

**No Public ACL Readability**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure

S3 bucket ACLs should not be readable by unauthenticated users. READ_ACP permission enables attackers to enumerate ACL grants, discover which principals have access, and find escalation paths.

**Remediation:** Remove READ_ACP grants from the bucket ACL and remove policy statements granting s3:GetBucketAcl or s3:GetObjectAcl to public principals. Enable S3 Public Access Block with BlockPublicAcls set to true.

---

### CTL.S3.ACL.RECUR.001

**S3 Bucket ACL Must Not Oscillate to Public-Read Repeatedly**

- **Severity:** high
- **Type:** unsafe_recurrence
- **Domain:** exposure
- **Compliance:** hipaa: 164.308(a)(1)(ii)(D); nist_800_53_r5: IR-5; soc2: CC7.1;

S3 bucket ACL has been set to public-read more than once within 7 days. ACL modification is a deliberate action — not accidental IaC drift. A single recurrence within a week is a strong signal of intentional repeated action requiring investigation.

**Remediation:** Investigate the root cause of the repeated oscillation. Determine whether the pattern indicates a broken process, operational workaround, or active compromise. Review CloudTrail for the API calls that triggered each transition.

---

### CTL.S3.AP.BYPASS.001

**Bucket Must Not Be Publicly Accessible Via An Access Point While Its Own Controls Pass**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.312(a)(1); soc2: CC6.1;

An S3 bucket whose own controls all evaluate clean — Public Access Block fully enforcing, bucket policy not effectively public — can still be publicly reachable through a single-region S3 Access Point that names it as the delegate bucket. Access Points carry their own PAB and their own resource policy, evaluated independently of the parent bucket; a public Access Point is a parallel reach path. This control fires on the bucket, not the AP, because the finding is "this bucket is exposed via an AP it may not know about" — the bucket is the asset at risk. Mirrors the shape of CTL.S3.CDN.BYPASS.001 (the CloudFront-fronted-bucket bypass). Firing requires the bucket-side controls to be clean: if the bucket is already publicly accessible on its own, the bucket-level controls already caught it and this finding would be noise. The derived field `storage.exposure.has_public_access_point` comes from the `EnrichBucketAPExposure` derivation — a post-collection join of `aws_s3_access_point` assets onto `aws_s3_bucket` assets within the same snapshot; the trace decomposes back to the raw AP and bucket observations that produced it.

**Remediation:** 1. Identify the offending Access Point from the
   `storage.exposure.public_access_point_names` field on this
   finding, or from the co-occurring AP-side findings.
2. On the Access Point, enable Block Public Access fully
   (`put-access-point-public-access-block` with all four flags
   true) and remove any wildcard-principal Allow from its
   resource policy — or add a restricting Condition on
   `aws:SourceVpc`, `aws:SourceVpce`, `aws:PrincipalOrgID`,
   `aws:PrincipalArn`, or a fixed `aws:SourceIp`.
3. Consider whether the Access Point is still needed. Access
   Points left over from decommissioned services are a common
   source of this pattern.

---

### CTL.S3.AP.PAB.001

**S3 Access Point Must Have Block Public Access Enabled**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.312(a)(1); soc2: CC6.1;

Single-region S3 Access Points have their own Public Access Block settings, independent of the parent bucket's PAB. A bucket can be hardened with PAB fully enforcing while one of its Access Points has PAB disabled — the Access Point endpoint remains a public path to the same underlying data. Prowler and ScoutSuite treat Access Points as a distinct resource with their own exposure surface precisely because of this overlay semantics.

**Remediation:** Enable all four PAB flags on the Access Point via `aws s3control put-access-point-public-access-block` with `BlockPublicAcls=true`, `IgnorePublicAcls=true`, `BlockPublicPolicy=true`, `RestrictPublicBuckets=true`. If the Access Point is intentionally public (rare), document the exposure and add a Stave exemption.

---

### CTL.S3.AP.PAB.BLOCKPUBLICACLS.001

**S3 Access Point Block Public ACLs Flag Must Be Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.312(a)(1); soc2: CC6.1;

The `BlockPublicAcls` flag of a single-region S3 Access Point's Public Access Block configuration rejects any new ACL grant applied through the Access Point endpoint that would make the data publicly accessible. When this specific flag is `false`, new PUT-ACL calls routed via the Access Point that grant `READ`, `WRITE`, `READ_ACP`, or `WRITE_ACP` to `http://acs.amazonaws.com/groups/global/AllUsers` or `.../AuthenticatedUsers` succeed rather than being rejected at the Access Point boundary. The umbrella `CTL.S3.AP.PAB.001` fires when any of the four AP PAB flags is off; this control narrows the finding to the specific flag so remediation is a one-command fix rather than requiring the operator to enumerate which of the four is missing. Prowler and ScoutSuite both report the four flags independently.

**Remediation:** Enable the `BlockPublicAcls` flag on the Access Point's Public Access Block configuration. From the CLI:

    aws s3control put-access-point-public-access-block \
      --account-id <account> \
      --name <access-point-name> \
      --public-access-block-configuration \
      'BlockPublicAcls=true,IgnorePublicAcls=<current>,BlockPublicPolicy=<current>,RestrictPublicBuckets=<current>'

Preserve the other three flag values so enabling this one doesn't silently disable the others.

---

### CTL.S3.AP.PAB.BLOCKPUBLICPOLICY.001

**S3 Access Point Block Public Policy Flag Must Be Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.312(a)(1); soc2: CC6.1;

The `BlockPublicPolicy` flag of a single-region S3 Access Point's Public Access Block configuration rejects any new Access Point policy that grants access to a public principal (`Principal: "*"`, `Principal: {"AWS": "*"}`, or an Allow block with no Principal) without a narrowing `Condition`. When this specific flag is `false`, new policies with wildcard principals and no scoping Condition succeed at PUT time rather than being rejected at the Access Point boundary. The umbrella `CTL.S3.AP.PAB.001` fires when any of the four AP PAB flags is off; this control narrows the finding to the specific flag so remediation is a one-command fix rather than requiring the operator to enumerate which of the four is missing. Prowler and ScoutSuite both report the four flags independently.

**Remediation:** Enable the `BlockPublicPolicy` flag on the Access Point's Public Access Block configuration. From the CLI:

    aws s3control put-access-point-public-access-block \
      --account-id <account> \
      --name <access-point-name> \
      --public-access-block-configuration \
      'BlockPublicAcls=<current>,IgnorePublicAcls=<current>,BlockPublicPolicy=true,RestrictPublicBuckets=<current>'

Preserve the other three flag values so enabling this one doesn't silently disable the others.

---

### CTL.S3.AP.PAB.IGNOREPUBLICACLS.001

**S3 Access Point Ignore Public ACLs Flag Must Be Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.312(a)(1); soc2: CC6.1;

The `IgnorePublicAcls` flag of a single-region S3 Access Point's Public Access Block configuration causes any existing public ACL grants on objects exposed through the Access Point to be ignored at evaluation time. When this specific flag is `false`, existing ACLs that grant `READ`, `WRITE`, `READ_ACP`, or `WRITE_ACP` to `AllUsers` or `AuthenticatedUsers` remain effective when requests arrive through the Access Point endpoint, preserving public reachability regardless of bucket-level hardening. The umbrella `CTL.S3.AP.PAB.001` fires when any of the four AP PAB flags is off; this control narrows the finding to the specific flag so remediation is a one-command fix rather than requiring the operator to enumerate which of the four is missing. Prowler and ScoutSuite both report the four flags independently.

**Remediation:** Enable the `IgnorePublicAcls` flag on the Access Point's Public Access Block configuration. From the CLI:

    aws s3control put-access-point-public-access-block \
      --account-id <account> \
      --name <access-point-name> \
      --public-access-block-configuration \
      'BlockPublicAcls=<current>,IgnorePublicAcls=true,BlockPublicPolicy=<current>,RestrictPublicBuckets=<current>'

Preserve the other three flag values so enabling this one doesn't silently disable the others.

---

### CTL.S3.AP.PAB.RESTRICTPUBLICBUCKETS.001

**S3 Access Point Restrict Public Buckets Flag Must Be Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.312(a)(1); soc2: CC6.1;

The `RestrictPublicBuckets` flag of a single-region S3 Access Point's Public Access Block configuration suppresses any existing Access Point policy statement that grants public access; at evaluation time only AWS-service principals (via `aws:PrincipalService`) and principals in the same AWS account remain able to reach the Access Point. When this specific flag is `false`, previously-authored public Access Point policies remain effective and the endpoint stays publicly reachable regardless of bucket-level hardening. The umbrella `CTL.S3.AP.PAB.001` fires when any of the four AP PAB flags is off; this control narrows the finding to the specific flag so remediation is a one-command fix rather than requiring the operator to enumerate which of the four is missing. Prowler and ScoutSuite both report the four flags independently.

**Remediation:** Enable the `RestrictPublicBuckets` flag on the Access Point's Public Access Block configuration. From the CLI:

    aws s3control put-access-point-public-access-block \
      --account-id <account> \
      --name <access-point-name> \
      --public-access-block-configuration \
      'BlockPublicAcls=<current>,IgnorePublicAcls=<current>,BlockPublicPolicy=<current>,RestrictPublicBuckets=true'

Preserve the other three flag values so enabling this one doesn't silently disable the others.

---

### CTL.S3.AP.POLICY.001

**S3 Access Point Policy Must Not Be Public**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure

Single-region S3 Access Points carry their own resource policy that is evaluated independently of the parent bucket policy. A public Access Point policy creates a public access path to the bucket even when the bucket's own policy is scoped correctly. This mirrors the MRAP case (CTL.S3.MRAP.POLICY.001) and is the single-region analogue.

**Remediation:** Remove the public grant from the Access Point policy, or add a scoping Condition that binds the caller to a fixed VPC, IP range, organization, or ARN. If public reach is intentional, enforce it through a narrower mechanism such as CloudFront with Origin Access Control and keep the Access Point policy private.

---

### CTL.S3.AUDIT.OBJECTLEVEL.001

**CloudTrail Object-Level Logging Required**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AU-2; hipaa: 164.312(b); nist_800_53_r5: AU-2; pci_dss_v4.0: 10.2.1.3; soc2: CC7.1;

CloudTrail S3 object-level data event logging must be enabled for PHI buckets. Server access logging captures bucket-level operations but not individual object access patterns. CloudTrail data events record GetObject, PutObject, and DeleteObject calls required for HIPAA audit controls.

**Remediation:** Configure a CloudTrail trail with a data event selector for AWS::S3::Object covering this bucket. Use aws cloudtrail put-event-selectors to add the selector.

---

### CTL.S3.AUTH.READ.001

**No Authenticated-Users Read Access**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure

S3 buckets must not grant read access to all authenticated AWS users. AuthenticatedUsers scope means any AWS account can read objects, which is nearly as dangerous as fully public access.

**Remediation:** Remove the ACL grant to AuthenticatedUsers. Replace with specific IAM principals or use bucket policy with explicit account IDs. Enable S3 Public Access Block with IgnorePublicAcls set to true.

---

### CTL.S3.AUTH.WRITE.001

**No Authenticated-Users Write Access**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure

S3 buckets must not grant write or delete access to all authenticated AWS users. AuthenticatedUsers scope means any AWS account holder worldwide can upload, overwrite, or delete objects — enabling data injection, ransomware, and supply chain poisoning.

**Remediation:** Remove the ACL grant or policy statement granting write access to AuthenticatedUsers. Replace with specific IAM principals or use bucket policy with explicit account IDs. Enable S3 Public Access Block with BlockPublicAcls and IgnorePublicAcls set to true.

---

### CTL.S3.BREACH.DETECT.001

**PHI Buckets Must Have Complete Detection Infrastructure**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: IR-4; hipaa: 164.400; nist_800_53_r5: IR-4; soc2: CC7.1;

S3 buckets tagged with data-classification=phi must have all four detection components active: server access logging, CloudTrail object-level logging, GuardDuty S3 protection, and AWS Config recording. Missing any one component creates a gap in breach detection and incident investigation capability. HIPAA §§164.400-414 requires the ability to detect and investigate unauthorized access to PHI.

**Remediation:** Ensure all four components are active for this bucket: 1. Server access logging (aws s3api put-bucket-logging) 2. CloudTrail object-level data events (aws cloudtrail put-event-selectors) 3. GuardDuty S3 protection (aws guardduty update-detector) 4. AWS Config recording (aws configservice put-configuration-recorder)

---

### CTL.S3.BUCKET.TAKEOVER.001

**Referenced S3 Buckets Must Exist And Be Owned**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure

Any externally referenced S3 bucket must exist and be owned. Dangling references (missing or unowned buckets) enable bucket takeover and attacker-controlled content delivery.

**Remediation:** Create the S3 bucket in your AWS account, or remove the DNS record, CDN origin, or application reference pointing to the unclaimed bucket.

---

### CTL.S3.CDN.BYPASS.001

**CloudFront-Fronted Bucket Must Not Allow Direct Public Access**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.312(a)(1); soc2: CC6.1;

A bucket that is both fronted by a CloudFront distribution and publicly readable on its direct S3 endpoint gives an attacker a full bypass of the CloudFront layer. CloudFront typically carries the defensive controls — WAF rules, geographic restrictions, request logging, signed URLs, TLS policy — while the raw S3 URL (`bucket.s3.<region>.amazonaws.com`) carries none of them. Anyone who learns the bucket name can fetch objects around every CloudFront-layer control.

**Remediation:** 1. Enable Block Public Access on the bucket and remove any
   Principal "*" grants from the bucket policy so the direct
   S3 endpoint is no longer publicly reachable.
2. Restrict the bucket policy to the specific CloudFront
   distribution via an Origin Access Control and a condition on
   `aws:SourceArn = arn:aws:cloudfront::<account>:distribution/<id>`.
3. Verify the CloudFront distribution still serves objects
   after the lockdown (OAC-signed requests survive; direct
   anonymous requests fail).

---

### CTL.S3.CDN.EXPOSURE.001

**Private Bucket Must Not Be Publicly Exposed Via CloudFront**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.312(a)(1); soc2: CC6.1;

A bucket with Block Public Access enabled can still serve objects publicly through CloudFront if the bucket policy grants access to the cloudfront.amazonaws.com service principal. This creates a false sense of security — the bucket appears private but objects are accessible via the CloudFront distribution URL.

**Remediation:** 1. Review whether public CDN access is intentional for this bucket. 2. If not intentional, remove the CloudFront distribution or restrict
   it with signed URLs/cookies.
3. If intentional, document this as an acknowledged exposure path
   and add a Stave exemption for this bucket.

---

### CTL.S3.CDN.OAC.001

**CloudFront Access Must Use OAC Not Legacy OAI**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance

When S3 objects are served via CloudFront, Origin Access Control (OAC) should be used instead of the legacy Origin Access Identity (OAI). OAC supports SSE-KMS, SigV4, and all S3 features. OAI is a legacy mechanism that does not support KMS encryption and is being deprecated.

**Remediation:** 1. Create an Origin Access Control for the distribution. 2. Update the distribution origin to use OAC instead of OAI. 3. Update the bucket policy to grant cloudfront.amazonaws.com
   with a Condition restricting to the distribution ARN.
4. Remove the legacy OAI.

---

### CTL.S3.CLASSIFY.COVERAGE.001

**All S3 Buckets Must Have a Data Classification Tag**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 2.1.3; fedramp_moderate: CM-8; gdpr: Art.30; hipaa: 164.308(a)(1)(ii)(A); nist_800_53_r5: CM-8; pci_dss_v4.0: 12.5.2; soc2: CC6.1;

Every S3 bucket must have a data-classification tag with a value from the recognized taxonomy (phi, pii, confidential, internal, public, non-sensitive). The data-classification tag is the gating condition for the majority of Stave's sensitive data controls — PHI encryption, Object Lock, Macie scanning, lifecycle retention, and access scoping are all conditional on this tag. A bucket without the tag silently passes all tag-conditional controls regardless of its actual contents. CIS 2.1.3 requires that all S3 data is discovered, classified, and secured. This control establishes the classification baseline — it does not verify what classification was applied, only that every bucket has been explicitly classified so downstream controls can evaluate it.

**Remediation:** Apply a data-classification tag to the bucket with a value from the recognized taxonomy: phi, pii, confidential, internal, public, or non-sensitive. Use AWS Tag Editor or the S3 PutBucketTagging API to apply tags. Establish a tagging policy requiring classification at bucket creation time. Use AWS Config rules or SCPs to enforce mandatory tagging.

---

### CTL.S3.CLOUDTRAIL.PUBLIC.001

**S3 Bucket Storing CloudTrail Logs Must Not Be Public**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws: 3.3; mitre_attack: T1562.008; nist_800_53_r5: AU-9;

The S3 bucket storing CloudTrail logs must not be publicly accessible. A public CloudTrail bucket exposes the complete API activity log and allows log tampering.

**Remediation:** aws s3api put-public-access-block --bucket <cloudtrail-bucket> --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true, BlockPublicPolicy=true,RestrictPublicBuckets=true"

---

### CTL.S3.CONTROLS.001

**Public Access Block Must Be Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v1.4.0: 2.1.5; cis_aws_v3.0: 2.1.4; fedramp_moderate: AC-3; ffiec: ISH-4; gdpr: Art.32; iso_27001_2022: A.8.3; nist_800_53_r5: AC-3; nist_csf_2.0: PR.PS; pci_dss_v3.2.1: 1.3.6; pci_dss_v4.0: 2.2.1; soc2: CC6.1;

S3 buckets must have the public access block fully enabled. When disabled, the bucket has no safety net against accidental public exposure from policy or ACL changes. This detects the enabling condition for public access, not the exposure itself.

**Remediation:** Enable all four Public Access Block settings on the bucket: BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets.

---

### CTL.S3.CORS.001

**S3 CORS Wildcard Origin Must Be Explicitly Intended**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** soc2: CC6.6;

S3 bucket CORS configurations that set AllowedOrigins to "*" expose the bucket's CORS-permitted methods to every web origin. For buckets serving genuinely public static assets this may be intentional; for buckets holding tenant data, authenticated user content, or signed URLs it widens the attack surface for cross-origin abuse. S3 does not expose an AllowCredentials field on CORS rules — browsers refuse the wildcard+credentials combination — so the unsafe state for S3 is wildcard origin on a bucket that is not tagged as intentionally public. The observation shape mirrors the raw "aws s3api get-bucket-cors" response.

**Remediation:** Replace "*" in AllowedOrigins with the specific origins that need cross-origin access. If the bucket is a public CDN or static asset origin where wildcard CORS is intentional, add the tag cors_wildcard_intended=true to declare intent. To remove CORS entirely, run "aws s3api delete-bucket-cors --bucket <name>".

---

### CTL.S3.DANGLING.ORIGIN.001

**CDN S3 Origins Must Not Be Dangling**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure

CloudFront distributions must not reference S3 origins that do not exist. A missing/unclaimed origin bucket enables takeover and CDN content poisoning.

**Remediation:** Create the S3 bucket in your AWS account to claim the name, or remove the dangling origin from the CloudFront distribution. Update the distribution to use an Origin Access Control (OAC).

---

### CTL.S3.DETECT.MACIE.001

**Sensitive Data Buckets Must Have Macie Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: RA-5; gdpr: Art.30; hipaa: 164.312(b); iso_27001_2022: A.8.12; nist_800_53_r5: RA-5; pci_dss_v4.0: 11.5.1; soc2: CC7.2;

S3 buckets tagged with a non-public data classification (phi, pii, confidential, internal) must be monitored by Amazon Macie. Macie uses machine learning and pattern matching to discover and classify sensitive data, detecting PII, PHI, and credentials that may have been stored without proper controls. Without Macie, sensitive data can accumulate undetected in buckets that were not originally intended for it.

**Remediation:** Enable Amazon Macie in the account and region, then add this bucket to a Macie classification job. Use aws macie2 create-classification-job to configure automated scanning. For organization-wide coverage, enable Macie via AWS Organizations delegated administrator.

---

### CTL.S3.DETECT.MACIE.002

**Macie Automated Sensitive Data Discovery Must Be Active**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SI-4; hipaa: 164.308(a)(1)(ii)(D); nist_800_53_r5: SI-4; soc2: CC7.2;

Buckets monitored by Macie must have automated sensitive data discovery actively running, not just enabled. A Macie classification job can exist but be paused, cancelled, or have never completed a scan. Without active discovery, new sensitive data uploaded after the last scan goes undetected. Automated discovery continuously samples bucket contents to find sensitive data as it arrives.

**Remediation:** Verify the Macie classification job for this bucket is in RUNNING status. If paused, resume it with aws macie2 update-classification-job. Enable automated sensitive data discovery at the account level with aws macie2 update-automated-discovery-configuration to ensure continuous sampling of all monitored buckets.

---

### CTL.S3.ENCRYPT.001

**Encryption at Rest Required**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v1.4.0: 2.1.1; fedramp_moderate: SC-28; ffiec: ISH-4; gdpr: Art.32; hipaa: 164.312(a)(2)(iv); iso_27001_2022: A.8.24; nist_800_53_r5: SC-28; nist_csf_2.0: PR.DS; pci_dss_v3.2.1: 3.4; pci_dss_v4.0: 3.4.1; soc2: CC6.1;

S3 buckets must have server-side encryption enabled. Unencrypted storage is the top audit finding in regulated industries.

**Remediation:** Enable default bucket encryption using SSE-S3 (AES256) or SSE-KMS. Use aws s3api put-bucket-encryption to set the default encryption configuration. For sensitive data, use SSE-KMS with a customer-managed key.

---

### CTL.S3.ENCRYPT.002

**Transport Encryption Required**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v1.4.0: 2.1.2; cis_aws_v3.0: 2.1.1; fedramp_moderate: SC-8; ffiec: ISH-4; gdpr: Art.32; hipaa: 164.312(e)(2)(ii); iso_27001_2022: A.8.24; nist_800_53_r5: SC-8; nist_csf_2.0: PR.DS; pci_dss_v3.2.1: 4.1; pci_dss_v4.0: 4.2.1; soc2: CC6.1;

S3 buckets must enforce HTTPS via a deny policy on aws:SecureTransport=false. Without this, data transfers occur in plaintext.

**Remediation:** Add a bucket policy statement that denies all actions when aws:SecureTransport is false. This forces all API calls to use HTTPS.

---

### CTL.S3.ENCRYPT.003

**PHI Buckets Must Use SSE-KMS with Customer-Managed Key**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-28; ffiec: ISH-4; gdpr: Art.32; iso_27001_2022: A.8.24; nist_800_53_r5: SC-28; nist_csf_2.0: PR.DS; pci_dss_v4.0: 3.5.1; soc2: CC6.7;

S3 buckets tagged with data-classification=phi must use SSE-KMS encryption with a customer-managed key (CMK), not the default AWS-managed key or SSE-S3. This ensures the organization controls key rotation, access policies, and audit logging for PHI data at rest.

**Remediation:** Change the bucket default encryption to SSE-KMS and specify a customer-managed KMS key ARN. Ensure the KMS key policy grants access only to authorized principals. Enable KMS key rotation.

---

### CTL.S3.ENCRYPT.004

**Sensitive Data Requires KMS Encryption**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure

S3 buckets with any non-public data classification must use SSE-KMS encryption with a customer-managed key, not SSE-S3 (AES256). AES256 uses AWS-managed keys with no customer control over key rotation, access policies, or audit trails. This fires on all classified data except explicitly public or non-sensitive buckets.

**Remediation:** Change the bucket default encryption to SSE-KMS with a customer-managed key. Re-encrypt existing objects by copying them in place with the new encryption settings.

---

### CTL.S3.GOVERNANCE.001

**Data Classification Tag Required**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: CM-8;

S3 buckets must have a data-classification tag. Without this tag, tag-conditional controls for PHI, PII, confidential data, backup integrity, and compliance retention cannot evaluate — the bucket silently passes all sensitivity-gated checks regardless of actual content.

**Remediation:** Add a data-classification tag to the bucket with an appropriate value (e.g., phi, pii, confidential, internal, public, non-sensitive). Update your tagging policy to require this tag on all S3 buckets.

---

### CTL.S3.INCOMPLETE.001

**Complete Data Required for Safety Assessment**

- **Severity:** low
- **Type:** unsafe_duration
- **Domain:** storage
- **Compliance:** nist_800_53_r5: SI-12;

S3 bucket safety cannot be proven when policy or ACL data is missing from the snapshot.

**Remediation:** Re-run the observation collector with full permissions to read bucket policies and ACLs. Ensure the collector IAM role has s3:GetBucketPolicy, s3:GetBucketAcl, and s3:GetBucketPolicyStatus permissions.

---

### CTL.S3.INTELLIGENT.TIERING.EXPOSURE.001

**S3 Batch Operations Must Not Copy Objects to External Accounts**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** mitre_attack: T1074; nist_800_53_r5: AC-3;

S3 Batch Operations can copy millions of objects across buckets in a single job. An attacker with s3:CreateJob permission can initiate a batch copy of all objects in a bucket to an external account — staging data for exfiltration without triggering per-object API calls. Batch operations generate a single CloudTrail event rather than millions of GetObject events — making large-scale data collection harder to detect via API call volume monitoring.

**Remediation:** Restrict s3:CreateJob to approved IAM roles. Add bucket policy conditions preventing cross-account batch operations. Deny s3:CreateJob when the destination account does not match the source account.

---

### CTL.S3.INVENTORY.001

**S3 Inventory Must Be Enabled for Visibility**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: CM-8; hipaa: 164.312(b); nist_800_53_r5: CM-8; soc2: CC7.2;

S3 buckets must have S3 Inventory configured to provide a complete manifest of all objects, their storage classes, encryption status, and optionally their ACL grants. Without Inventory, organizations have no baseline visibility into what data exists in a bucket, making it impossible to detect misplaced sensitive files, verify encryption coverage, or audit object-level access. S3 Inventory is essential when Amazon Macie is not deployed, as it provides the only mechanism for systematic bucket content auditing at scale.

**Remediation:** Configure S3 Inventory on the bucket using aws s3api put-bucket-inventory-configuration. Include optional fields for encryption status and ACL grants. Set the inventory to report daily or weekly to a secured destination bucket. Use the inventory reports to audit for misplaced sensitive data, unencrypted objects, and objects with public ACL grants.

---

### CTL.S3.LIFECYCLE.001

**Retention-Tagged Buckets Must Have Lifecycle Rules**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SI-12; soc2: C1.2;

S3 buckets tagged with data-retention must have at least one enabled lifecycle rule configured. HIPAA requires defined data retention policies for protected health information (PHI), audit logs, and billing records. Without lifecycle rules, data persists indefinitely, increasing exposure surface and violating retention policy requirements.

**Remediation:** Add S3 lifecycle rules to manage object expiration and transitions. Configure rules matching the retention period specified in the data-retention tag. Use lifecycle transitions to move data to cheaper storage classes before expiration.

---

### CTL.S3.LIFECYCLE.002

**PHI Buckets Must Not Expire Data Before Minimum Retention**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SI-12;

S3 buckets tagged with data-classification=phi must not have lifecycle expiration rules that delete data before the minimum HIPAA retention period. HIPAA requires medical records to be retained for a minimum of 6 years (2190 days). This control detects PHI buckets with expiration rules set below this threshold, which could result in premature deletion of protected health information.

**Remediation:** Increase the lifecycle expiration period to at least the configured min_retention_days value. If the current rule is for storage class transition, ensure the expiration rule is separate and meets the minimum retention period.

---

### CTL.S3.LIST.RESTRICT.001

**S3 Buckets Must Not Allow Unauthenticated Bucket Listing**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** mitre_attack: T1619; nist_800_53_r5: AC-3;

S3 buckets must not allow anonymous s3:ListBucket access. Anonymous bucket listing exposes all object keys to unauthenticated users, enabling reconnaissance of stored data. Attackers use object key enumeration to identify sensitive files, backup archives, and configuration artifacts before attempting data exfiltration.

**Remediation:** Enable S3 Public Access Block with BlockPublicPolicy and RestrictPublicBuckets set to true. Remove any bucket policy statements granting s3:ListBucket to Principal "*". Remove any ACL grants to the AllUsers group.

---

### CTL.S3.LOCK.001

**Compliance-Tagged Buckets Must Have Object Lock Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.316(b)(2); nist_800_53_r5: AU-9; soc2: CC6.1;

S3 buckets tagged with any compliance framework (soc2, gdpr, hipaa, pci-dss, etc.) must have S3 Object Lock enabled. Object Lock provides WORM (Write Once Read Many) protection, preventing objects from being deleted or overwritten for a specified retention period. Regulatory frameworks require immutable storage for audit logs, compliance records, and protected data.

**Remediation:** Enable S3 Object Lock on the bucket. Note: Object Lock can only be enabled at bucket creation. If the bucket already exists, create a new bucket with Object Lock enabled and migrate objects. Set a default retention period appropriate for your compliance framework.

---

### CTL.S3.LOCK.002

**PHI Buckets Must Use COMPLIANCE Mode Object Lock**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure

S3 buckets tagged with data-classification=phi that have Object Lock enabled must use COMPLIANCE mode, not GOVERNANCE mode. COMPLIANCE mode prevents ANY user, including the root account, from deleting or overwriting protected objects during the retention period. GOVERNANCE mode allows users with special permissions to override retention, which is insufficient for HIPAA-regulated PHI data where tamper-proof storage is required.

**Remediation:** Change the Object Lock default retention mode from GOVERNANCE to COMPLIANCE. In COMPLIANCE mode, no user (including root) can delete or modify protected objects during the retention period.

---

### CTL.S3.LOCK.003

**PHI Object Lock Retention Must Meet Minimum Period**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure

S3 buckets tagged with data-classification=phi that have Object Lock enabled must have a default retention period of at least 2190 days (6 years) to meet HIPAA minimum retention requirements. Shorter retention periods risk premature expiration of WORM protection, allowing deletion or modification of PHI data before the regulatory retention period has elapsed.

**Remediation:** Increase the Object Lock default retention period to at least 2190 days. Use aws s3api put-object-lock-configuration to update the default retention settings.

---

### CTL.S3.LOG.001

**Access Logging Required**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v1.4.0: 2.1.3; fedramp_moderate: AU-2; ffiec: ISH-4; gdpr: Art.30; hipaa: 164.312(b); iso_27001_2022: A.8.15; nist_800_53_r5: AU-2; pci_dss_v3.2.1: 10.2.1; pci_dss_v4.0: 10.2.1.3; soc2: CC7.2;

S3 buckets must have server access logging enabled for audit trail and visibility into data access patterns.

**Remediation:** Enable S3 server access logging and specify a target bucket for log delivery. Ensure the target bucket has appropriate access controls and is in the same region.

---

### CTL.S3.LOG.BUCKET.LIFECYCLE.001

**Log Destination Bucket Must Have Lifecycle Policy**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.312(b); nist_800_53_r5: AU-11;

When server access logging is enabled, the log destination bucket must have a lifecycle policy configured. Without lifecycle management, log storage grows unbounded, increasing costs and making audit analysis impractical.

**Remediation:** Configure a lifecycle policy on the log destination bucket to manage log retention. Transition older logs to cheaper storage classes and expire logs after the required retention period.

---

### CTL.S3.LOG.BUCKET.LOCK.001

**Log Destination Bucket Must Have Object Lock Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AU-9; hipaa: 164.312(b); nist_800_53_r5: AU-9;

When server access logging is enabled, the log destination bucket must have Object Lock enabled. Without Object Lock, log files can be deleted by any principal with s3:DeleteObject permission, even with versioning enabled.

**Remediation:** Enable Object Lock on the log destination bucket with a retention policy. Object Lock prevents log file deletion for the retention period, ensuring audit trail immutability. Note that Object Lock must be enabled at bucket creation time.

---

### CTL.S3.LOG.BUCKET.PUBLIC.001

**Log Destination Bucket Must Not Be Publicly Accessible**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AU-9; hipaa: 164.312(b); nist_800_53_r5: AU-9;

When server access logging is enabled, the log destination bucket must not be publicly accessible. Public log buckets expose audit trail contents to external actors, enabling reconnaissance and detection evasion.

**Remediation:** Block all public access on the log destination bucket using the S3 Block Public Access settings. Enable all four block public access options to prevent any public access configuration.

---

### CTL.S3.LOG.BUCKET.VERSIONING.001

**Log Destination Bucket Must Have Versioning Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.312(b); nist_800_53_r5: AU-9;

When server access logging is enabled, the log destination bucket must have versioning enabled. Without versioning, deleted or overwritten log files cannot be recovered, allowing attackers to destroy audit evidence.

**Remediation:** Enable versioning on the log destination bucket to preserve all versions of log objects. This ensures that even if log files are deleted or overwritten, previous versions remain recoverable.

---

### CTL.S3.LOG.PREFIX.001

**Log Prefix Required When Logging Enabled**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.312(b); nist_800_53_r5: AU-3;

When server access logging is enabled, a target prefix must be configured to organize log files and enable efficient search and analysis of audit records.

**Remediation:** Set a target prefix for S3 server access logging to organize log files by source bucket. Use a prefix that identifies the source bucket, such as the bucket name followed by a slash.

---

### CTL.S3.LOG.RETENTION.001

**Log Retention Must Be At Least 90 Days**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AU-11; hipaa: 164.530(j); nist_800_53_r5: AU-11;

When server access logging is enabled, the log destination bucket must retain logs for at least 90 days. Short retention periods allow attackers to wait out the retention window, after which evidence of unauthorized access is automatically destroyed.

**Remediation:** Set the lifecycle expiration on the log destination bucket to at least 90 days. Many compliance frameworks require longer retention; consult your compliance team for the appropriate retention period.

---

### CTL.S3.MALWARE.001

**PHI Buckets Must Have Malware Scanning Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SI-3; hipaa: 164.308(a)(5)(ii)(B); nist_800_53_r5: SI-3; soc2: CC6.8;

S3 buckets tagged with data-classification=phi must have malware scanning enabled via GuardDuty S3 Malware Protection or an equivalent scanning pipeline. Without scanning, uploaded files containing malware can persist in PHI storage indefinitely, creating both a security risk (malware distribution) and a compliance violation (HIPAA §164.308(a)(5)(ii)(B) requires protection against malicious software).

**Remediation:** Enable GuardDuty S3 Malware Protection for the bucket. Navigate to GuardDuty > S3 Protection > Enable. Alternatively, deploy a Lambda-based AV scanning pipeline triggered by S3 PutObject events.

---

### CTL.S3.MFADELETE.001

**MFA Delete Must Be Enabled on S3 Buckets**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 2.1.2; nist_800_53_r5: CP-9; soc2: CC6.1;

S3 buckets should have MFA Delete enabled on versioned buckets. MFA Delete requires a second factor to permanently delete object versions, preventing unauthorized or accidental data destruction.

**Remediation:** Enable MFA Delete (requires root credentials): aws s3api put-bucket-versioning --bucket <name> --versioning-configuration Status=Enabled,MFADelete=Enabled --mfa "arn:aws:iam::<account>:mfa/root-account-mfa-device <code>"

---

### CTL.S3.MRAP.PAB.001

**Multi-Region Access Point Must Have Block Public Access Enabled**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.312(a)(1); soc2: CC6.1;

MRAPs have their own PAB settings independent of bucket PAB. A bucket can have PAB enabled while the MRAP has PAB disabled.

**Remediation:** Enable all four PAB flags on the MRAP.

---

### CTL.S3.MRAP.POLICY.001

**Multi-Region Access Point Policy Must Not Be Public**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure

MRAPs can have their own resource policy evaluated independently of the bucket policy. A public MRAP policy creates a public access path.

**Remediation:** Remove public access from the MRAP policy.

---

### CTL.S3.NETWORK.001

**Public-Principal Policies Must Have Network Conditions**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3;

S3 bucket policies that grant access to Principal * (any AWS principal) must include network-scoping conditions such as aws:SourceIp, aws:sourceVpce, aws:SourceVpc, or aws:PrincipalOrgID. Without these conditions, the bucket is accessible to anyone on the internet. This control detects policies where wildcard principals are used without network restrictions.

**Remediation:** Add network-scoping conditions to the bucket policy: aws:SourceIp for IP range restrictions, aws:SourceVpce for VPC endpoint restrictions, aws:SourceVpc for VPC restrictions, or aws:PrincipalOrgID for organization-only access.

---

### CTL.S3.NETWORK.POLICY.001

**VPC Endpoint Policy Must Restrict Access**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.312(e)(1);

VPC endpoint policy must be attached and must not be the default full-access policy (Allow * on *). The default policy allows any principal on the VPC to reach any S3 bucket in any account via the endpoint, bypassing firewall controls. A restrictive endpoint policy limits which bucket ARNs and actions are reachable.

**Remediation:** Replace the default endpoint policy with one that restricts Resource to specific bucket ARNs and Action to required S3 operations only.

---

### CTL.S3.NETWORK.VPC.001

**VPC Endpoint or IP Condition Required**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.312(e)(1); nist_800_53_r5: SC-7;

S3 bucket access must be restricted by a VPC endpoint condition (aws:SourceVpce) or an IP address condition (aws:SourceIp) in the bucket policy. Without network-level restrictions, the bucket is reachable from any network path. This control enforces transmission security for PHI workloads.

**Remediation:** Add a VPC gateway endpoint for S3 and route bucket traffic through it, or add an IP condition (aws:SourceIp) to the bucket policy to restrict access to known CIDR ranges.

---

### CTL.S3.NOTIFICATION.GHOST.001

**S3 Event Notifications Must Not Target Deleted Resources**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** nist_800_53_r5: SI-4; soc2: CC7.1;

S3 bucket event notification configurations must not target deleted SNS topics, SQS queues, or Lambda functions. Object events (PutObject, DeleteObject) go undelivered when the target is absent. If notifications feed security monitoring, the monitoring stops.

**Remediation:** Update the notification configuration to reference existing resources.

---

### CTL.S3.OWNERSHIP.001

**S3 Object Ownership Must Be Bucket Owner Enforced**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 2.1.2; fedramp_moderate: AC-3; iso_27001_2022: A.8.3; nist_800_53_r5: AC-3; soc2: CC6.1;

S3 buckets must have Object Ownership set to BucketOwnerEnforced, which disables ACLs entirely. When ACLs are disabled, the bucket owner automatically owns every object regardless of who uploaded it, and access is controlled exclusively through IAM and bucket policies. This eliminates the entire class of ACL-based exposure: public grants, privilege escalation via WRITE_ACP, and object-level ACL overrides. Since April 2023 new buckets default to BucketOwnerEnforced, but buckets created before this date may still have ACLs enabled.

**Remediation:** Set Object Ownership to BucketOwnerEnforced using aws s3api put-bucket-ownership-controls. This disables all ACLs on the bucket. Before enabling, audit existing ACL grants and migrate any legitimate access to bucket policies or IAM policies. All existing ACL-based access will stop working once BucketOwnerEnforced is set.

---

### CTL.S3.PAB.BLOCKPUBLICACLS.001

**S3 Bucket Block Public ACLs Flag Must Be Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v1.4.0: 2.1.5; cis_aws_v3.0: 2.1.4; fedramp_moderate: AC-3; ffiec: ISH-4; gdpr: Art.32; iso_27001_2022: A.8.3; nist_800_53_r5: AC-3; nist_csf_2.0: PR.PS; pci_dss_v3.2.1: 1.3.6; pci_dss_v4.0: 2.2.1; soc2: CC6.1;

The `BlockPublicAcls` flag of the bucket's Public Access Block configuration rejects any new ACL grant that would make the bucket or its objects publicly accessible. When this specific flag is `false`, new PUT-ACL calls that grant `READ`, `WRITE`, `READ_ACP`, or `WRITE_ACP` to `http://acs.amazonaws.com/groups/global/AllUsers` or `.../AuthenticatedUsers` succeed rather than being rejected at the API boundary. The umbrella `CTL.S3.CONTROLS.001` fires when any of the four PAB flags is off; this control narrows the finding to the specific flag so remediation is a one-command fix rather than requiring the operator to enumerate which of the four is missing. Prowler and ScoutSuite both report the four flags independently.

**Remediation:** Enable the `BlockPublicAcls` flag on the bucket's Public Access Block configuration. From the CLI:

    aws s3api put-public-access-block \
      --bucket <name> \
      --public-access-block-configuration \
      'BlockPublicAcls=true,IgnorePublicAcls=<current>,BlockPublicPolicy=<current>,RestrictPublicBuckets=<current>'

Preserve the other three flag values so enabling this one doesn't silently disable the others.

---

### CTL.S3.PAB.BLOCKPUBLICPOLICY.001

**S3 Bucket Block Public Policy Flag Must Be Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v1.4.0: 2.1.5; cis_aws_v3.0: 2.1.4; fedramp_moderate: AC-3; ffiec: ISH-4; gdpr: Art.32; iso_27001_2022: A.8.3; nist_800_53_r5: AC-3; nist_csf_2.0: PR.PS; pci_dss_v3.2.1: 1.3.6; pci_dss_v4.0: 2.2.1; soc2: CC6.1;

The `BlockPublicPolicy` flag of the bucket's Public Access Block configuration rejects any new bucket-policy update that would evaluate as public under AWS `PolicyStatus.IsPublic`. When this specific flag is `false`, a `PutBucketPolicy` call with `Principal: "*"` and no restricting Condition succeeds rather than being rejected at the API boundary. The umbrella `CTL.S3.CONTROLS.001` fires when any of the four PAB flags is off; this control narrows the finding to the specific flag so remediation targets the policy-write path rather than the full PAB tuple. Prowler and ScoutSuite both report the four flags independently.

**Remediation:** Enable the `BlockPublicPolicy` flag on the bucket's Public Access Block configuration. Preserve the other three flag values so enabling this one doesn't silently disable the others.

---

### CTL.S3.PAB.IGNOREPUBLICACLS.001

**S3 Bucket Ignore Public ACLs Flag Must Be Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v1.4.0: 2.1.5; cis_aws_v3.0: 2.1.4; fedramp_moderate: AC-3; ffiec: ISH-4; gdpr: Art.32; iso_27001_2022: A.8.3; nist_800_53_r5: AC-3; nist_csf_2.0: PR.PS; pci_dss_v3.2.1: 1.3.6; pci_dss_v4.0: 2.2.1; soc2: CC6.1;

The `IgnorePublicAcls` flag of the bucket's Public Access Block configuration causes S3 to disregard any existing ACL grant that would make the bucket or its objects publicly accessible, even if the grant is already in place. When this specific flag is `false`, historical ACL grants to `AllUsers` or `AuthenticatedUsers` stay effective — enabling `BlockPublicAcls` alone does not neutralize grants that were made before the flag was enabled. The umbrella `CTL.S3.CONTROLS.001` fires when any of the four PAB flags is off; this control narrows the finding to the specific flag so the operator knows that the fix is not "block new ACLs" but "ignore the ones already there." Prowler and ScoutSuite both report the four flags independently.

**Remediation:** Enable the `IgnorePublicAcls` flag on the bucket's Public Access Block configuration. Pair it with `BlockPublicAcls` for full ACL-path coverage — the pair prevents new public ACL grants and neutralizes existing ones.

---

### CTL.S3.PAB.RESTRICTPUBLICBUCKETS.001

**S3 Bucket Restrict Public Buckets Flag Must Be Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v1.4.0: 2.1.5; cis_aws_v3.0: 2.1.4; fedramp_moderate: AC-3; ffiec: ISH-4; gdpr: Art.32; iso_27001_2022: A.8.3; nist_800_53_r5: AC-3; nist_csf_2.0: PR.PS; pci_dss_v3.2.1: 1.3.6; pci_dss_v4.0: 2.2.1; soc2: CC6.1;

The `RestrictPublicBuckets` flag of the bucket's Public Access Block configuration restricts evaluation of any existing public bucket policy: when the flag is on, public grants in the bucket policy are limited to AWS service principals and authorized AWS services (e.g., CloudFront OAC). When this specific flag is `false`, historical `Principal: "*"` grants stay fully effective — enabling `BlockPublicPolicy` alone does not neutralize policies that were in place before the flag was turned on. The umbrella `CTL.S3.CONTROLS.001` fires when any of the four PAB flags is off; this control narrows the finding to the specific flag so the operator knows the fix is not "block new public policies" but "restrict the ones already there." Prowler and ScoutSuite both report the four flags independently.

**Remediation:** Enable the `RestrictPublicBuckets` flag on the bucket's Public Access Block configuration. Pair it with `BlockPublicPolicy` for full policy-path coverage — the pair prevents new public policy writes and limits the effect of any historical public grants to service principals.

---

### CTL.S3.POLICY.DISCLOSURE.001

**No Public Read of Bucket Policy**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure

S3 bucket policies must not grant s3:GetBucketPolicy to an anonymous or wildcard principal. A publicly readable bucket policy is a reconnaissance primitive: anyone can retrieve the policy, enumerate which specific object ARNs are granted public read, and use that map to target the exposed content. Reju Kole's disclosure (January 2026) exploited exactly this: the target bucket granted s3:GetBucketPolicy to Principal "*", the researcher read the policy to discover that backup.xlsx was publicly granted, downloaded the file, cracked its Office password offline, and used the recovered credentials for further compromise. This control is distinct from controls that fire on the exposed objects themselves (CTL.S3.PUBLIC.001, .004) — the policy-disclosure primitive is what makes object-scoped public grants discoverable, and closing it removes the reconnaissance step even when other public grants remain.

**Remediation:** Remove any policy statement granting s3:GetBucketPolicy to Principal "*" or to AWS: "*". If the policy must remain readable for tooling, restrict the grant with a Condition on aws:PrincipalOrgID, aws:SourceVpc, or a fixed aws:SourceIp CIDR. Enable S3 Public Access Block with BlockPublicPolicy set to true to reject future policies that grant public access to bucket metadata.

---

### CTL.S3.POLICY.EXISTS.001

**S3 Bucket Must Have an Explicit Bucket Policy Attached**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.312(a)(1); nist_800_53_r5: AC-3; soc2: CC6.1;

S3 buckets must have an explicit resource-based bucket policy. Without a policy, access controls rely entirely on IAM and ACLs — there is no resource-level enforcement of encryption requirements, VPC restrictions, or transport security.

**Remediation:** Attach an explicit bucket policy. At minimum the policy should deny HTTP requests (aws:SecureTransport false), deny unencrypted PutObject, and restrict access to known principals or VPC endpoints.

---

### CTL.S3.POLICY.GHOSTREF.001

**S3 Bucket Policy Must Not Reference Deleted Principals**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

S3 bucket policies must not grant access to principal ARNs that don't exist in the IAM inventory. Unlike IAM trust policies (which replace deleted ARNs with unique IDs), resource-based policies evaluate ARN strings directly. A new entity created with the same name as a deleted principal inherits every permission the bucket policy grants. An attacker with iam:CreateRole can claim the deleted principal's name and gain bucket access.

**Remediation:** Remove the ghost principal ARN from the bucket policy or recreate the intended principal.

---

### CTL.S3.POLICY.OBJECTSCOPED.001

**Public Read Grants Must Not Target Specific Objects**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-3; iso_27001_2022: A.8.3; nist_800_53_r5: AC-3; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

Bucket policy contains at least one Allow statement with a non-narrow principal whose Resource field names one or more specific object keys (e.g. `arn:aws:s3:::bucket/backup.xlsx`) rather than the whole bucket (`arn:aws:s3:::bucket/*`) or a logical prefix (`bucket/assets/*`). Object-scoped public grants are a distinct attack surface from bucket-wide public grants: the specific object ARN in the policy readback (exposed by `iam:GetBucketPolicy` if that permission is also public — see `CTL.S3.POLICY.DISCLOSURE.001`) hands an attacker a targeting list. The January 2026 Reju Kole disclosure chained exactly this pattern: a public `GetBucketPolicy` grant revealed that `backup.xlsx` was individually granted to `Principal: "*"`, the researcher fetched it, cracked its Office password offline, and reused the recovered credentials for further compromise. Prowler and Pacu treat object-scoped grants as a distinct finding class for the same reason.
Severity is medium, not high, because object-scoped public grants are a legitimate pattern for individually-published documents (PDFs, binaries, static assets pinned to specific keys). Operators triage based on the specific object keys listed in the finding's diagnostic context. When the target bucket also carries `storage.tags.data-classification in [phi, pii, confidential]`, `CTL.S3.PUBLIC.002` already fires at high severity on the composite signal — this control does not duplicate that coverage; it catches the untagged case where the object's sensitivity is not expressed in the contract.

**Remediation:** Review each object listed as a public target. For intentionally published documents, move to a published-assets prefix pattern (`bucket/public/*`) so the policy no longer enumerates individual keys. For anything not intentionally public, remove the grant. Consider moving published documents to a dedicated bucket so the host bucket never has object-scoped public grants at all. If the bucket also has `s3:GetBucketPolicy` open to the public (see `CTL.S3.POLICY.DISCLOSURE.001`), close that first — it is the discovery primitive that makes object-scoped grants exploitable without prior knowledge of key names.

---

### CTL.S3.POLICY.SCOPING.001

**Non-Narrow Bucket Policy Grants Must Carry a Scoping Condition**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** hipaa: 164.312(a)(1); nist_800_53_r5: AC-3; soc2: CC6.1;

S3 bucket policies with Allow statements whose Principal is non-narrow (`Principal: "*"`, `Principal: {"AWS": "*"}`, or an Allow block with no Principal) should constrain every such statement with at least one scoping Condition: `aws:PrincipalOrgID`, `aws:SourceVpc`, `aws:SourceIp` with a fixed CIDR, or `aws:SourceArn`. Without a scoping Condition, the effective principal set is the full internet (anonymous) or every AWS account on Earth (`AWS: "*"`). Scoping Conditions do not fix the name of the principal but they collapse the reachable principal set to callers routed through a known org, VPC, IP range, or service — a posture hardening step that prevents a future policy edit from silently expanding exposure. This control does not fire on buckets with no policy, nor on buckets whose Allow statements all name specific accounts or role ARNs; both states are captured by `policy_has_scoping_condition` being absent or null.

**Remediation:** For every Allow statement with `Principal: "*"`, `Principal: {"AWS": "*"}`, or no Principal block, add a Condition that binds the request to a fixed value: `aws:PrincipalOrgID` to limit to the organization, `aws:SourceVpc` to limit to a VPC endpoint, `aws:SourceIp` with a CIDR to limit to a known range, or `aws:SourceArn` to limit to a specific caller. If the statement is supposed to be globally reachable (CDN origin, public data distribution), replace the bucket policy grant with a narrower mechanism — Origin Access Control, Access Points, or signed URLs.

---

### CTL.S3.POLICY.WRITE.001

**No Public Write via Bucket Policy**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure

S3 bucket policies must not grant write access to an anonymous or wildcard principal. Policy-based write access — a Statement with Effect Allow, Principal "*" or AWS: "*", and an Action such as s3:PutObject or s3:DeleteObject without a restricting Condition — enables attackers to upload malicious objects, overwrite existing content, or hold data ransom. This is distinct from CTL.S3.PUBLIC.003, which fires on the composite public_write signal regardless of mechanism; this control narrows to the policy path so the finding points the operator at the bucket policy specifically. For ACL-based public write, see CTL.S3.ACL.FULLCONTROL.001 (FULL_CONTROL grants) and CTL.S3.ACL.ESCALATION.001 (WRITE_ACP grants).

**Remediation:** Remove or constrain the policy statement granting write actions to Principal "*" or AWS: "*". If broad write access is genuinely required, add a restricting Condition on aws:PrincipalOrgID, aws:SourceVpc, or a fixed aws:SourceIp CIDR. Enable S3 Public Access Block with BlockPublicPolicy set to true to reject future policies that grant public write.

---

### CTL.S3.PRESIGNED.001

**Presigned URL Access Must Be Restricted**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.312(a)(1); soc2: CC6.1;

PHI bucket policy must restrict presigned URL access using s3:signatureAge (maximum age in milliseconds) or s3:authType (require REST-HEADER to block presigned URLs). Without these guardrails, presigned URLs can provide long-lived unauthenticated access to PHI data.

**Remediation:** Add a Deny statement with Condition NumericGreaterThan s3:signatureAge (e.g., 600000 for 10 minutes) or StringNotEquals s3:authType REST-HEADER to block presigned URL access.

---

### CTL.S3.PUBLIC.001

**No Public S3 Bucket Read**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v1.4.0: 2.1.5; fedramp_moderate: AC-3; ffiec: ISH-4; gdpr: Art.32; hipaa: 164.312(a)(1); iso_27001_2022: A.8.3; nist_800_53_r5: AC-3; pci_dss_v3.2.1: 1.2.1; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

S3 buckets must not allow public read access. Detects buckets with anonymous read exposure via policy or ACL.

**Remediation:** Enable S3 Public Access Block (all four settings). Remove any bucket policy statements granting access to Principal "*". Remove any ACL grants to AllUsers or AuthenticatedUsers.

---

### CTL.S3.PUBLIC.002

**No Public S3 Buckets With Sensitive Data**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure

S3 buckets tagged with sensitive data classifications (PHI, PII, confidential) must not allow any public access.

**Remediation:** Immediately enable S3 Public Access Block (all four settings). Remove bucket policy statements granting access to Principal "*". Remove ACL grants to AllUsers or AuthenticatedUsers. Audit CloudTrail logs for unauthorized access during the exposure window.

---

### CTL.S3.PUBLIC.003

**No Public Write Access**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure

S3 buckets must not allow public write or delete access. Public write enables data injection, ransomware, and policy takeover.

**Remediation:** Remove bucket policy statements that grant s3:PutObject or s3:DeleteObject to Principal "*". Remove ACL grants that allow WRITE or FULL_CONTROL to AllUsers or AuthenticatedUsers. Enable S3 Public Access Block.

---

### CTL.S3.PUBLIC.004

**No Public Read via Bucket Policy**

- **Severity:** medium
- **Type:** unsafe_duration
- **Domain:** storage

S3 bucket policies must not grant read access to an anonymous or wildcard principal. A Statement with Effect Allow, Principal "*" or AWS: "*", and an Action such as s3:GetObject without a restricting Condition enables any unauthenticated caller to read objects. This is distinct from CTL.S3.PUBLIC.001, which fires on the composite public_read signal regardless of mechanism; this control narrows to the bucket-policy path so the finding points the operator at the policy specifically. For ACL-based public read, see CTL.S3.ACL.FULLCONTROL.001 (FULL_CONTROL grants) and CTL.S3.ACL.ESCALATION.001 (WRITE_ACP grants).

**Remediation:** Remove or constrain the policy statement granting read actions to Principal "*" or AWS: "*". If broad read access is genuinely required, add a restricting Condition on aws:PrincipalOrgID, aws:SourceVpc, or a fixed aws:SourceIp CIDR. Enable S3 Public Access Block with BlockPublicPolicy set to true to reject future policies that grant public read.

---

### CTL.S3.PUBLIC.005

**No Latent Public Read Exposure**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** storage

S3 buckets must not have latent public read exposure where a public mechanism (policy or ACL) is masked only by Public Access Block. Removing PAB would immediately expose the bucket.

**Remediation:** Remove the underlying public-granting policy statement or ACL entry so the bucket does not depend solely on PAB for protection. Then verify PAB remains enabled as defense-in-depth.

---

### CTL.S3.PUBLIC.006

**No Latent Public Bucket Listing**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure

S3 bucket has a policy or ACL that would allow public listing if the public access block were removed. The public access block is currently the only control preventing directory enumeration. This is a latent vulnerability — one configuration change away from exposing all object keys.

**Remediation:** Remove the underlying policy statement or ACL entry that grants s3:ListBucket to Principal "*" or AllUsers. Do not rely solely on PAB to prevent directory enumeration.

---

### CTL.S3.PUBLIC.007

**No Public Read via Identity Policy**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure

IAM identity-based policies attached to users or roles must not grant broad read access to S3 buckets that is effectively public — for example, a policy attached to a widely-assumed role or to a role trusted by a public federated identity provider. This is distinct from CTL.S3.PUBLIC.004 (resource-based bucket policy granting public read); the identity-policy path is a separate AWS evaluation branch and deserves its own finding so the operator fixes the right artifact.

**Remediation:** Identify the identity-based policy statement granting read access and either remove it, scope it to specific bucket/object ARNs, or add conditions restricting the requesting principal. If a widely-trusted role is the root cause, tighten that role's trust policy first.

---

### CTL.S3.PUBLIC.008

**No Public List via Identity Policy**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure

IAM identity-based policies attached to users or roles must not grant broad list access (s3:ListBucket) that is effectively public. Anonymous-or-near-anonymous listing enables enumeration of the bucket contents, which typically precedes targeted object exfiltration. This is distinct from the ACL-based list exposure covered by CTL.S3.PUBLIC.LIST.001 / .002 and from resource-based list grants; the identity-policy path is its own finding.

**Remediation:** Identify the identity-based policy statement granting s3:ListBucket and remove it, scope it to specific bucket ARNs, or add conditions restricting the requesting principal. If a widely-trusted role is the root cause, tighten that role's trust policy first.

---

### CTL.S3.PUBLIC.LIST.001

**No Public S3 Bucket Listing**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure

S3 buckets must not allow anonymous listing of objects. Public listing exposes object keys, enabling targeted data exfiltration.

**Remediation:** Remove bucket policy statements that grant s3:ListBucket to Principal "*". Remove ACL grants that allow READ to AllUsers. Enable S3 Public Access Block.

---

### CTL.S3.PUBLIC.LIST.002

**Anonymous S3 Listing Must Be Explicitly Intended**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure

Anonymous bucket listing increases exposure surface even when objects are public by design. Listing must be explicitly intended via tag.

**Remediation:** If listing is intentional, add the tag public_list_intended=true to the bucket. Otherwise, remove the policy or ACL granting s3:ListBucket to Principal "*" or AllUsers.

---

### CTL.S3.PUBLIC.PREFIX.001

**Protected Prefixes Must Not Be Publicly Readable**

- **Severity:** high
- **Type:** prefix_exposure
- **Domain:** exposure

S3 bucket prefixes marked as protected must not be publicly readable. Evaluates bucket policies, ACL grants, and public access block settings to determine effective public read access for each protected prefix. Customize the prefix lists below to match your bucket layout.

**Remediation:** 1. Review the protected_prefixes and allowed_public_prefixes lists
   in this control and adjust them to match your bucket layout.
2. Enable S3 Public Access Block to restrict policy and ACL exposure. 3. Remove bucket policy statements granting s3:GetObject to Principal "*"
   for protected prefixes.
4. Remove ACL grants to AllUsers or AuthenticatedUsers.

---

### CTL.S3.PUBLIC.RECUR.001

**S3 Bucket Must Not Become Publicly Accessible Repeatedly**

- **Severity:** critical
- **Type:** unsafe_recurrence
- **Domain:** exposure
- **Compliance:** fedramp_moderate: IR-5; hipaa: 164.308(a)(1)(ii)(D); nist_800_53_r5: IR-5; pci_dss_v4.0: 12.10; soc2: CC7.1;

S3 bucket has oscillated between private and publicly accessible more than twice within 30 days. Repeated public exposure indicates a broken deployment process, operational workaround, or an attacker re-enabling public access. The response is investigation, not remediation — determine who is making the bucket public and how they still have access.

**Remediation:** Investigate the root cause of the repeated oscillation. Determine whether the pattern indicates a broken process, operational workaround, or active compromise. Review CloudTrail for the API calls that triggered each transition.

---

### CTL.S3.REGION.001

**S3 Buckets Must Be in Approved Regions**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** gdpr: Art.44;

S3 buckets containing personal data must be located in approved regions as determined by data residency requirements (e.g., EU/EEA regions for GDPR). Storing data outside approved regions may violate data transfer restrictions.

**Remediation:** Create a new bucket in an approved region and migrate data. Use S3 replication to move data, then delete the original bucket.

---

### CTL.S3.REPLICATION.001

**Compliance-Tagged Buckets Must Have Replication Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: CP-9; hipaa: 164.308(a)(7); iso_27001_2022: A.8.13; nist_800_53_r5: CP-9; soc2: A1.1;

S3 buckets tagged with a compliance framework (soc2, gdpr, hipaa, pci-dss, etc.) must have replication configured. Without replication, a regional outage or accidental bucket deletion can cause permanent data loss for regulated data. Replication provides an independent copy that survives single-region failures and supports disaster recovery objectives.

**Remediation:** Configure S3 replication on the bucket using aws s3api put-bucket-replication. Use cross-region replication (CRR) for disaster recovery or same-region replication (SRR) for compliance copies. Ensure versioning is enabled on both source and destination buckets.

---

### CTL.S3.REPLICATION.002

**PHI Replication Must Be Cross-Region**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: CP-6(1); hipaa: 164.308(a)(7)(ii)(A); nist_800_53_r5: CP-6(1); soc2: A1.2;

S3 buckets tagged with data-classification=phi that have replication enabled must replicate to a different AWS region. Same-region replication (SRR) does not protect against regional outages, AZ-wide failures, or region-scoped service disruptions. HIPAA contingency planning requires data to survive regional disasters.

**Remediation:** Update the replication configuration to use a destination bucket in a different AWS region. Ensure the destination bucket has versioning enabled, appropriate encryption, and a bucket policy that permits the replication role.

---

### CTL.S3.REPLICATION.003

**Replication Destination Must Be Encrypted**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-28; gdpr: Art.32; hipaa: 164.312(a)(2)(iv); nist_800_53_r5: SC-28; pci_dss_v4.0: 3.4.1; soc2: CC6.1;

When S3 replication is enabled, the destination bucket must have server-side encryption configured. Replicating data to an unencrypted destination creates a shadow copy that bypasses the source bucket's encryption controls. This is especially dangerous for sensitive data where the source meets encryption requirements but the replica does not.

**Remediation:** Configure default encryption on the destination bucket using SSE-S3 or SSE-KMS. For replication of encrypted objects, add a ReplicaKmsKeyID to the replication rule so objects are re-encrypted with a key in the destination region.

---

### CTL.S3.REPO.ARTIFACT.001

**Public Buckets Must Not Expose VCS Artifacts**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure

Buckets that serve public content must not expose version control artifacts such as .git/ or .svn/. Presence of these paths enables repo reconstruction and can leak secrets.

**Remediation:** Remove .git/, .svn/, and other VCS directories from the bucket. Add a lifecycle rule or deployment script that excludes VCS artifacts from uploads. If the bucket is a static website, configure your build pipeline to strip VCS files before deployment.

---

### CTL.S3.TENANT.ISOLATION.001

**Shared-Bucket Tenant Isolation Must Enforce Prefix**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure

When a shared S3 bucket uses prefix-based tenant isolation, every app-signer identity that produces presigned URLs must enforce the tenant prefix.  An identity that allows path traversal (../) or disables prefix enforcement lets one tenant read or overwrite another tenant's objects.

**Remediation:** Update the app-signer configuration to enforce tenant prefix restrictions (enforce_prefix=true) and block path traversal (allow_traversal=false) on all presigned URL signers.

---

### CTL.S3.VERSION.001

**Versioning Required**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v1.4.0: 2.1.3; hipaa: 164.312(c)(1); nist_800_53_r5: CP-9; soc2: CC6.1;

S3 buckets must have versioning enabled to protect against accidental deletion and enable recovery from negligent operations.

**Remediation:** Enable versioning on the bucket using aws s3api put-bucket-versioning. Once enabled, configure lifecycle rules to manage noncurrent versions and control storage costs.

---

### CTL.S3.VERSION.002

**Backup Buckets Must Have MFA Delete Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure

S3 buckets tagged with backup=true must have MFA delete enabled. MFA delete requires multi-factor authentication to permanently delete object versions, protecting against ransomware attacks and accidental mass deletion of backup data. Without MFA delete, any principal with s3:DeleteObject permission can permanently destroy backup versions.

**Remediation:** Enable MFA delete on the bucket using aws s3api put-bucket-versioning with the MFA flag. This requires the root account credentials and an MFA device. Only the root account can enable or disable MFA delete.

---

### CTL.S3.WEBSITE.PUBLIC.001

**No Public Website Hosting with Public Read**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3;

S3 buckets with static website hosting enabled must not also have public read access. Website hosting combined with public read serves content directly to the internet.

**Remediation:** If public hosting is not intended, disable static website hosting and remove public read access. If hosting is intended, move content behind CloudFront with an Origin Access Control (OAC) and remove direct public access from the bucket.

---

### CTL.S3.WRITE.CONTENT.001

**S3 Signed Upload Must Restrict Content Types**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure

Signed upload policies must restrict allowed content types. Unrestricted content types enable attackers to upload SVGs with embedded JavaScript or HTML files, causing stored XSS when served from the bucket's domain.

**Remediation:** Add an exact content-type condition to the signed upload policy (e.g., eq $Content-Type image/jpeg). Avoid starts-with with empty prefix, which allows any content type.

---

### CTL.S3.WRITE.SCOPE.001

**S3 Signed Upload Must Bind To Exact Object Key**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure

Signed upload policies must restrict write permission to a single exact object key. Prefix-wide permissions (e.g., starts-with $key files/) enable arbitrary overwrite and cross-tenant tampering.

**Remediation:** Change the signed upload policy to use an exact key condition (eq instead of starts-with) that binds each upload to a specific object path. Generate unique object keys server-side.

---

### CTL.SAGEMAKER.ENDPOINT.REDUNDANCY.001

**SageMaker Endpoint Must Use Multiple Instances**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: CP-10; soc2: A1.1;

SageMaker endpoint configurations must use at least two instances per production variant for multi-AZ redundancy. Single-instance endpoints are single points of failure.

**Remediation:** Set InitialInstanceCount to at least 2 per production variant.

---

### CTL.SAGEMAKER.MODEL.ISOLATION.001

**SageMaker Models Must Enable Network Isolation**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.6;

SageMaker model containers must enable network isolation to prevent outbound network calls during inference. Without isolation, a model container can exfiltrate inference data, training data cached in the model artifact, or model weights to external endpoints.

**Remediation:** Set EnableNetworkIsolation to true on the model.

---

### CTL.SAGEMAKER.MODEL.VPC.001

**SageMaker Models Must Use VPC Configuration**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.6;

SageMaker models must define VpcConfig with subnets and security groups so inference containers communicate through a VPC rather than the public internet.

**Remediation:** Define VpcConfig with subnets and security groups.

---

### CTL.SAGEMAKER.NOTEBOOK.ENCRYPT.001

**SageMaker Notebook EBS Volume Must Be Encrypted**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** nist_800_53_r5: SC-28; soc2: CC6.7;

SageMaker notebook instances must encrypt the ML storage volume at rest with KMS. Unencrypted volumes expose notebook code, datasets, model artifacts, and credentials cached locally.

**Remediation:** Configure KmsKeyId on the notebook instance.

---

### CTL.SAGEMAKER.NOTEBOOK.INTERNET.001

**SageMaker Notebook Must Not Have Direct Internet Access**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.6;

SageMaker notebook instances must disable DirectInternetAccess, forcing VPC-only connectivity. An internet-accessible notebook is an interactive Jupyter environment reachable from the public internet with the attached IAM role's credentials available via IMDS.

**Remediation:** Disable DirectInternetAccess and deploy the notebook in a VPC with NAT gateway for outbound connectivity.

---

### CTL.SAGEMAKER.NOTEBOOK.ROOT.001

**SageMaker Notebook Must Disable Root Access**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-6(5); soc2: CC6.1;

SageMaker notebook instances must disable root access. Root privileges allow users to install arbitrary packages, modify system configuration, and bypass security controls in the notebook environment.

**Remediation:** Set RootAccess to Disabled on the notebook instance.

---

### CTL.SAGEMAKER.NOTEBOOK.VPC.001

**SageMaker Notebook Must Be Deployed in VPC**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.6;

SageMaker notebook instances must be deployed in a VPC with subnet and security group configuration for private networking.

**Remediation:** Configure the notebook with a subnet_id and security groups.

---

### CTL.SAGEMAKER.TRAINING.ENCRYPT.INTERCONTAINER.001

**SageMaker Training Must Encrypt Inter-Container Traffic**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** nist_800_53_r5: SC-8; soc2: CC6.7;

SageMaker distributed training jobs must enable inter-container traffic encryption. Without it, data sent between training containers (gradients, model parameters, training samples) is transmitted in plaintext between nodes.

**Remediation:** Set EnableInterContainerTrafficEncryption to true.

---

### CTL.SAGEMAKER.TRAINING.ENCRYPT.VOLUME.001

**SageMaker Training Job Volumes Must Be Encrypted**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** nist_800_53_r5: SC-28; soc2: CC6.7;

SageMaker training jobs must encrypt ML storage volumes at rest with KMS. Training volumes contain datasets, intermediate computations, and model checkpoints.

**Remediation:** Set VolumeKmsKeyId in the training job ResourceConfig.

---

### CTL.SAGEMAKER.TRAINING.ISOLATION.001

**SageMaker Training Jobs Must Enable Network Isolation**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.6;

SageMaker training jobs must enable network isolation to prevent training containers from making inbound or outbound network calls. Without isolation, a compromised training container can exfiltrate training data or model artifacts to external endpoints.

**Remediation:** Set EnableNetworkIsolation to true on the training job.

---

### CTL.SAGEMAKER.TRAINING.VPC.001

**SageMaker Training Jobs Must Use VPC Configuration**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.6;

SageMaker training jobs must define VpcConfig with subnets so training traffic uses private networking rather than the public internet.

**Remediation:** Define VpcConfig with subnets and security groups.

---

### CTL.SECRET.BLAST.001

**Secret with Multiple Readers Must Not Target Sensitive Resource**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.312(a)(1); nist_800_53_r5: SC-12; pci_dss_v4.0: 3.4.1; soc2: CC6.1;

Secrets in Secrets Manager that provide credentials to sensitive resources (PHI, PII, confidential) must have a minimal set of readers. A secret readable by more than 3 principals is a high-value target — compromising any one of those principals provides a direct path to the sensitive data, bypassing IAM least privilege on the data resource itself. The extractor maps which principals have secretsmanager:GetSecretValue and which resource the secret unlocks.

**Remediation:** Reduce the number of principals with secretsmanager:GetSecretValue to the minimum required. Use resource-based policies on the secret to restrict access. Enable automatic rotation via aws secretsmanager rotate-secret --secret-id <id>.

---

### CTL.SECRET.BLAST.002

**Cross-Account Secret Access Must Not Target Sensitive Resource**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-3; nist_800_53_r5: AC-3; soc2: CC6.1;

Secrets that provide credentials to sensitive resources must have access restricted to the owning account. Cross-account access to a secret that unlocks PHI or PII data doubles the blast radius — the secret is reachable from a wider set of principals across account boundaries.

**Remediation:** Remove cross-account access from the secret resource policy. If cross-account access is required, restrict to specific role ARNs and require an external ID condition.

---

### CTL.SECRET.BLAST.INCOMPLETE.001

**Complete Data Required for Secret Blast Radius Assessment**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure

Secret blast radius assessment requires the target_sensitivity field. The extractor could not determine which resource the secret provides credentials for.

**Remediation:** Tag secrets with the target resource ARN. Re-run the extractor with permissions to read secret metadata and tags.

---

### CTL.SECRETS.ROTATION.001

**Secrets Manager Secrets Must Have Automatic Rotation Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** aws_security_hub: SecretsManager.1; mitre_attack: T1528; nist_800_53_r5: IA-5;

Secrets without automatic rotation retain the same credential value indefinitely. An attacker who obtains a secret value through any means (log harvesting, memory dump, API call) has permanent access unless the secret is manually rotated. Automatic rotation limits the window of compromise — a stolen credential becomes invalid after the rotation interval.

**Remediation:** Configure automatic rotation with a Lambda rotation function: aws secretsmanager rotate-secret --secret-id <id> --rotation-lambda-arn <arn> --rotation-rules AutomaticallyAfterDays=30

---

### CTL.SECRETSMANAGER.ACCESS.001

**Secrets Must Have Rotation Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.312(a)(1); soc2: CC6.1;

Secrets Manager secrets must have automatic rotation enabled. Long-lived secrets that are never rotated increase the blast radius of credential leaks and prevent timely revocation.

**Remediation:** Configure automatic rotation with a Lambda function. Run: aws secretsmanager rotate-secret --secret-id xxx --rotation-lambda-arn arn:aws:lambda:... --rotation-rules AutomaticallyAfterDays=90

---

### CTL.SECRETSMANAGER.ENCRYPT.001

**Secrets Must Be Encrypted with Customer-Managed KMS Key**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-28; gdpr: Art.32; hipaa: 164.312(a)(2)(iv); nist_800_53_r5: SC-28; pci_dss_v4.0: 3.4.1; soc2: CC6.7;

Secrets Manager secrets must be encrypted with a customer-managed KMS key. The default AWS-managed key does not support key revocation or cross-account key policies needed for breach response.

**Remediation:** Recreate the secret with a customer-managed KMS key specified. Secrets Manager does not allow changing the encryption key after creation.

---

### CTL.SECRETSMANAGER.INCOMPLETE.001

**Complete Data Required for Secrets Manager Assessment**

- **Severity:** info
- **Type:** unsafe_state
- **Domain:** exposure

The observation snapshot is missing required Secrets Manager properties. A safety assessment cannot be completed without secret configuration data.

**Remediation:** Ensure the extractor calls aws secretsmanager describe-secret and maps the response to the secret observation properties.

---

### CTL.SECRETSMANAGER.POLICY.PUBLIC.001

**Secrets Manager Secret Must Not Have Public Resource Policy**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.312(a)(1); nist_800_53_r5: AC-3; pci_dss_v4.0: 3.4.1; soc2: CC6.1;

Secrets Manager resource policies must not grant secretsmanager:GetSecretValue or secretsmanager:* to Principal "*" or to unauthenticated principals without scoping conditions. Public secret access allows any AWS principal to retrieve the secret value, which typically contains database credentials, API keys, or certificates.

**Remediation:** Restrict the resource policy to specific IAM roles or accounts. Remove any statements with Principal "*". For cross-account access, add aws:PrincipalOrgID or aws:SourceAccount conditions.

---

### CTL.SECURITYHUB.ENABLED.001

**AWS Security Hub Must Be Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SI-4; ffiec: CAT-D3; gdpr: Art.32; iso_27001_2022: A.8.16; nist_800_53_r5: SI-4; nist_csf_2.0: DE.CM; pci_dss_v4.0: 11.3.1; soc2: CC7.1;

Security Hub must be enabled to aggregate security findings from GuardDuty, Inspector, Macie, and Config into a unified view.

**Remediation:** Enable Security Hub: aws securityhub enable-security-hub --enable-default-standards

---

### CTL.SECURITYHUB.INCOMPLETE.001

**Complete Data Required for Security Hub Assessment**

- **Severity:** info
- **Type:** unsafe_state
- **Domain:** exposure

The observation snapshot is missing required Security Hub properties.

**Remediation:** Ensure the extractor calls aws securityhub describe-hub.

---

### CTL.SECURITYHUB.STANDARDS.001

**Security Hub Must Have Relevant Standards Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: SI-4; nist_800_53_r5: SI-4; pci_dss_v4.0: 11.3.1; soc2: CC7.1;

Safety mechanism integrity control. Checks that security guardrails are actively enforcing, not just present.

**Remediation:** Review the specific guardrail identified in this finding and restore it to an enforcing state.

---

### CTL.SHIELD.ADVANCED.001

**Shield Advanced Must Be Enabled for Internet-Facing Resources**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-5; hipaa: 164.308(a)(7); nist_800_53_r5: SC-5; pci_dss_v4.0: 1.3.1; soc2: A1.1;

AWS accounts with internet-facing resources must have Shield Advanced enabled with all internet-facing resources registered as protected. Shield Standard provides basic DDoS protection automatically. Shield Advanced provides volumetric DDoS mitigation at the network edge, 24/7 DDoS Response Team (DRT) access, cost protection against scaling charges during attacks, and attack diagnostics. WAF controls protect against application-layer attacks but do not protect against volumetric network-layer DDoS that exhausts bandwidth or connection capacity before WAF can evaluate requests. A 100 Gbps UDP flood cannot be mitigated by WAF rules — it requires scrubbing at the network edge. For PHI and financial services, unmitigated DDoS is both an operational and compliance risk — HIPAA and PCI-DSS require availability of regulated systems.

**Remediation:** Subscribe to AWS Shield Advanced via the Shield console or API. Register all internet-facing resources (ALBs, NLBs, CloudFront distributions, Route 53 hosted zones, Elastic IPs) as protected resources. Configure Route 53 health checks for protected resources to enable proactive engagement by the DDoS Response Team.

---

### CTL.SNS.ENCRYPT.001

**SNS Topics Must Be Encrypted with KMS**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.312(a)(2)(iv); soc2: CC6.7;

SNS topics must use server-side encryption with a KMS key. Unencrypted topics expose message payloads at rest, which may contain PHI or other sensitive notification data.

**Remediation:** Enable SSE-KMS on the topic. Run: aws sns set-topic-attributes --topic-arn xxx --attribute-name KmsMasterKeyId --attribute-value arn:aws:kms:...

---

### CTL.SNS.ENCRYPTION.001

**SNS Topics Must Use Server-Side Encryption**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** aws_security_hub: SNS.1; mitre_attack: T1530; nist_800_53_r5: SC-28;

SNS topics without server-side encryption transmit and store messages in plaintext. An attacker with sns:Subscribe access can create a subscription to harvest all messages flowing through the topic. Messages often contain application events, alerts, and inter-service data that may include sensitive information. SSE-KMS encryption ensures messages are encrypted at rest and requires kms:Decrypt permission to read.

**Remediation:** Enable SSE-KMS on the topic: aws sns set-topic-attributes --topic-arn <arn> --attribute-name KmsMasterKeyId --attribute-value alias/aws/sns

---

### CTL.SNS.INCOMPLETE.001

**Complete Data Required for SNS Assessment**

- **Severity:** info
- **Type:** unsafe_state
- **Domain:** exposure

The observation snapshot is missing required SNS topic properties.

**Remediation:** Ensure the extractor calls aws sns get-topic-attributes and maps the KmsMasterKeyId to the messaging.encryption observation properties.

---

### CTL.SNS.POLICY.GHOSTREF.001

**SNS Topic Policy Must Not Reference Deleted Principals**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3; soc2: CC6.1;

SNS topic policies must not grant access to principal ARNs that don't exist in the IAM inventory. A recreated principal matching the ghost ARN inherits Publish (injection) or Subscribe (interception) access. Resource-based policies evaluate ARN strings, not unique IDs.

**Remediation:** Remove the ghost principal ARN from the topic policy.

---

### CTL.SNS.POLICY.PUBLIC.001

**SNS Topic Policy Must Not Allow Public Access**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** aws_security_hub: SNS.1; nist_800_53_r5: AC-3; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

SNS topic resource policies must not grant sns:Subscribe, sns:Publish, or sns:* to Principal "*" or to unauthenticated principals without restricting via aws:SourceArn, aws:SourceAccount, or aws:PrincipalOrgID conditions. Public topic access allows unauthorized subscription (receiving all published messages) or publishing (injecting messages that reach all subscribers, potentially triggering downstream Lambda functions, SQS queues, or HTTP endpoints).

**Remediation:** Restrict the topic policy to specific account IDs, source ARNs, or add an aws:PrincipalOrgID condition. For cross-service integration (e.g., S3 event → SNS), restrict via aws:SourceArn to the specific source ARN.

---

### CTL.SQS.DLQ.001

**SQS Queues Must Have Dead-Letter Queue Configured**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** soc2: PI1.1;

SQS queues processing critical workloads must have a dead-letter queue configured. Without a DLQ, messages that fail processing are silently lost.

**Remediation:** Configure a DLQ: aws sqs set-queue-attributes --queue-url <url> --attributes RedrivePolicy='{"deadLetterTargetArn":"<dlq-arn>","maxReceiveCount":"3"}'

---

### CTL.SQS.ENCRYPT.001

**SQS Queues Must Be Encrypted with KMS**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.312(a)(2)(iv); soc2: CC6.7;

SQS queues must use server-side encryption with a KMS key. Unencrypted queues expose message payloads at rest, which may contain PHI or other sensitive data.

**Remediation:** Enable SSE-KMS on the queue. Run: aws sqs set-queue-attributes --queue-url xxx --attributes KmsMasterKeyId=arn:aws:kms:...

---

### CTL.SQS.ENCRYPTION.001

**SQS Queues Must Use Server-Side Encryption**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** aws_security_hub: SQS.1; mitre_attack: T1530; nist_800_53_r5: SC-28;

SQS queues without server-side encryption store messages in plaintext. An attacker with sqs:ReceiveMessage access can read message contents directly — messages often contain application data, event payloads, and inter-service communication that may include sensitive information. SSE-KMS encryption ensures messages are encrypted at rest and requires kms:Decrypt permission to read.

**Remediation:** Enable SSE-KMS on the queue: aws sqs set-queue-attributes --queue-url <url> --attributes KmsMasterKeyId=alias/aws/sqs

---

### CTL.SQS.INCOMPLETE.001

**Complete Data Required for SQS Assessment**

- **Severity:** info
- **Type:** unsafe_state
- **Domain:** exposure

The observation snapshot is missing required SQS queue properties.

**Remediation:** Ensure the extractor calls aws sqs get-queue-attributes and maps the KmsMasterKeyId to the messaging.encryption observation properties.

---

### CTL.SQS.POLICY.GHOSTREF.001

**SQS Queue Policy Must Not Reference Deleted Principals**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3; soc2: CC6.1;

SQS queue policies must not grant access to principal ARNs that don't exist in the IAM inventory. A recreated principal matching the ghost ARN inherits SendMessage (injection) or ReceiveMessage (interception) access. Resource-based policies evaluate ARN strings, not unique IDs.

**Remediation:** Remove the ghost principal ARN from the queue policy.

---

### CTL.SQS.POLICY.PUBLIC.001

**SQS Queue Policy Must Not Allow Public Access**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** aws_security_hub: SQS.1; nist_800_53_r5: AC-3; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

SQS queue resource policies must not grant sqs:SendMessage, sqs:ReceiveMessage, sqs:DeleteMessage, or sqs:* to Principal "*" or to unauthenticated principals without restricting via aws:SourceArn, aws:SourceAccount, or aws:PrincipalOrgID conditions. Public queue access allows unauthorized message injection (sending malicious payloads to downstream consumers) or message interception (reading messages meant for internal services).

**Remediation:** Restrict the queue policy to specific account IDs, source ARNs, or add an aws:PrincipalOrgID condition. For cross-service integration (e.g., SNS → SQS), restrict via aws:SourceArn to the specific topic ARN.

---

### CTL.SSM.DOCUMENT.PUBLIC.001

**SSM Documents Must Not Be Publicly Shared**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3; soc2: CC6.1;

SSM documents must not be shared publicly or with untrusted accounts. Public documents expose internal automation procedures, infrastructure configuration, and potentially embedded credentials.

**Remediation:** Remove public sharing from the document permissions.

---

### CTL.SSM.DOCUMENT.SECRETS.001

**SSM Documents Must Not Contain Embedded Secrets**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: IA-5(7); soc2: CC6.1;

SSM documents must not contain hardcoded passwords, access keys, tokens, or private keys. Use Secrets Manager or Parameter Store references instead.

**Remediation:** Replace hardcoded credentials with Secrets Manager or Parameter Store references.

---

### CTL.SSM.INVENTORY.RESTRICT.001

**SSM Inventory Access Must Be Restricted**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** mitre_attack: T1592; nist_800_53_r5: AC-3;

SSM inventory data must not be publicly shared or broadly accessible. SSM inventory contains detailed information about managed instances including installed software, running services, network configuration, and Windows registry data. Attackers use this information to identify vulnerable software versions, exposed services, and network paths for exploitation planning.

**Remediation:** Remove public sharing from SSM inventory resource data syncs. Restrict ssm:GetInventory and ssm:GetInventorySummary to administrative roles only. Review and scope down any resource data sync configurations that share inventory across accounts.

---

### CTL.SSM.PARAMETER.COLLECT.001

**SSM Parameter Store Must Restrict Bulk Parameter Listing**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** mitre_attack: T1552; nist_800_53_r5: AC-6;

SSM Parameter Store holds database passwords, API keys, certificates, and other secrets. ssm:GetParametersByPath allows bulk retrieval of all parameters under a path prefix in a single API call — collecting all secrets at once. ssm:DescribeParameters lists all parameter names and metadata — enabling an attacker to map all stored secrets before extracting them. These permissions should be scoped to specific parameter paths needed by each application, not granted broadly.

**Remediation:** Replace ssm:GetParametersByPath with resource-scoped ssm:GetParameter grants on specific parameter ARNs. Restrict ssm:DescribeParameters to administrative roles.

---

### CTL.SSM.PATCH.COMPLIANCE.001

**SSM Managed Instances Must Be Patch Compliant**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SI-2; soc2: CC7.1;

SSM-managed instances must report patch compliance against defined baselines. Non-compliant instances are missing required security patches.

**Remediation:** Apply missing patches via SSM Patch Manager.

---

### CTL.SSM.RUNCOMMAND.APPROVE.001

**SSM Run Command Must Require Change Manager Approval for Production**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** mitre_attack: T1059.004; nist_800_53_r5: CM-3;

AWS Systems Manager Run Command allows executing arbitrary shell commands on any managed EC2 instance. An attacker with ssm:SendCommand permission can run commands on all production instances simultaneously — installing backdoors, exfiltrating data, or destroying files. Change Manager adds an approval workflow to SSM automation and Run Command. Without approval workflows, a single compromised IAM principal with ssm:SendCommand can achieve arbitrary code execution on every managed instance in the account.

**Remediation:** Enable Systems Manager Change Manager and configure approval templates requiring two or more approvers for production targets. Restrict ssm:SendCommand directly to Change Manager service role via IAM policy condition.

---

### CTL.SSM.RUNCOMMAND.RESTRICT.001

**SSM Run Command Must Be Restricted to Approved Documents**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 2.2.1; mitre_attack: T1059.009; nist_800_53_r5: AC-6;

SSM Run Command allows executing arbitrary commands on managed EC2 instances. Without restricting which command documents can be used, any principal with ssm:SendCommand can execute AWS-RunShellScript or AWS-RunPowerShellScript on any managed instance — providing remote code execution equivalent to SSH/RDP access without requiring key management or network-level access. This is MITRE ATT&CK T1059.009 (Cloud Administration Command). Restrict to approved documents only.

**Remediation:** Use IAM policy conditions to restrict ssm:SendCommand to specific document names. Deny AWS-RunShellScript and AWS-RunPowerShellScript for non-admin roles. Use Session Manager for interactive access instead of Run Command for shell access.

---

### CTL.SSM.SECURETYPE.001

**SSM Parameters in Sensitive Paths Must Use SecureString Type**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-28; hipaa: 164.312(a)(2)(iv); nist_800_53_r5: SC-28; pci_dss_v4.0: 3.4.1; soc2: CC6.1;

AWS Systems Manager Parameter Store parameters that store values in String or StringList type when their path indicates sensitive content are readable by any IAM principal with ssm:GetParameter. SecureString parameters are KMS-encrypted at rest and require kms:Decrypt to read. This control checks the parameter type field — not the parameter value.

**Remediation:** Create a new SecureString parameter with the same value and update all references. SSM does not support changing parameter type in place — you must create a new parameter. Use aws ssm put-parameter --name <path> --type SecureString --value <value> --overwrite.

---

### CTL.STEPFUNCTIONS.LOG.001

**Step Functions State Machines Must Have Logging Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AU-2; soc2: CC7.1;

Step Functions state machines must emit execution logs to CloudWatch Logs. Without logging, workflow execution details and errors are invisible.

**Remediation:** Enable execution logging to CloudWatch Logs.

---

### CTL.STEPFUNCTIONS.SECRETS.001

**Step Functions State Machines Must Not Contain Secrets in Definitions**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: IA-5(7); soc2: CC6.1;

Step Functions state machine definitions must not contain hardcoded secrets. Definition JSON is visible in the console, API responses, and CloudTrail logs.

**Remediation:** Replace hardcoded secrets with Secrets Manager or Parameter Store references.

---

### CTL.VPC.DEFAULT.001

**Default VPC Must Not Be Used**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 5.4; fedramp_moderate: SC-7; nist_800_53_r5: SC-7; soc2: CC6.6;

Workloads must not run in the default VPC. The default VPC is created automatically in every region with permissive settings: a public subnet in each AZ, an internet gateway, and a default security group that allows all internal traffic. These defaults create implicit public exposure that custom VPCs avoid. Production and sensitive workloads must use purpose-built VPCs with explicit network design.

**Remediation:** Create a custom VPC with private subnets, explicit route tables, and restrictive security groups. Migrate workloads from the default VPC. Consider deleting the default VPC in production accounts if no workloads require it.

---

### CTL.VPC.DEFAULT.IGW.001

**Default VPC Must Not Have Internet Gateway Route**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws: 4.7; nist_800_53_r5: SC-7;

The default VPC must not have an internet gateway route in its route tables. AWS creates a default VPC in every region with a route table that sends all internet-bound traffic through an attached internet gateway. Resources launched into the default VPC without explicit network configuration receive a public IP and are directly reachable from the internet. The default VPC is frequently used for ad-hoc testing and forgotten resources — any instance, Lambda VPC attachment, or RDS instance placed in the default VPC inherits internet exposure by default. Removing the internet gateway route from the default VPC eliminates this accidental exposure path without affecting production workloads which should be in purpose-built VPCs.

**Remediation:** Remove the internet gateway route from the default VPC route table. Detach and delete the internet gateway from the default VPC if no resources require it. Alternatively, delete the default VPC entirely if it is not in use. Verify no active resources depend on the default VPC internet connectivity before removing the route.

---

### CTL.VPC.ENDPOINT.ANON.001

**VPC Endpoint Policy Must Deny Anonymous Requests**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** network
- **Compliance:** nist_800_53_r5: AC-3; soc2: CC6.6;

VPC endpoint policies must explicitly deny anonymous (unsigned) requests. Without this, unauthenticated S3 requests can transit the endpoint without identity information, evading CloudTrail logging and IAM policy evaluation.

**Remediation:** Add a Deny statement to the endpoint policy for requests where aws:PrincipalArn does not exist (anonymous/unsigned requests).

---

### CTL.VPC.ENDPOINT.BUCKET.RESTRICT.001

**VPC Endpoint Policy Must Restrict Target S3 Buckets**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** network
- **Compliance:** nist_800_53_r5: AC-4; soc2: CC6.6;

VPC endpoint policies for S3 must restrict which buckets can be accessed. Without Resource constraints, any S3 bucket globally — including attacker-controlled buckets — is reachable through the organization's endpoint.

**Remediation:** Add a Resource constraint to the endpoint policy listing only the organization's buckets. Deny all other bucket ARNs.

---

### CTL.VPC.ENDPOINT.GHOST.001

**VPC Endpoint Policy Must Not Reference Deleted Resources**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3; soc2: CC6.1;

VPC endpoint policies must not grant access to resources by ARN when those resources no longer exist. For S3 bucket ARNs (globally reclaimable), traffic routed through the endpoint reaches whoever claims the bucket name. For account-scoped resources, an attacker with limited access can recreate the resource.

**Remediation:** Remove the ghost resource ARN from the endpoint policy.

---

### CTL.VPC.ENDPOINT.IAM.CONDITION.001

**VPC Endpoint Policy Must Require IAM Conditions**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** network
- **Compliance:** nist_800_53_r5: AC-3; soc2: CC6.1;

VPC endpoint policies must include IAM conditions (aws:PrincipalArn, aws:PrincipalOrgID) to verify the identity of requesters. Without these, any principal in the VPC can use the endpoint without identity verification at the policy layer.

**Remediation:** Add aws:PrincipalArn or aws:PrincipalOrgID conditions to the endpoint policy to restrict which principals can use it.

---

### CTL.VPC.ENDPOINT.S3.001

**VPCs Must Have an S3 Gateway Endpoint**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws: 4.13; nist_800_53_r5: SC-7;

VPCs must have an S3 VPC gateway endpoint to route S3 traffic privately through the AWS network. Without it, S3 access traverses the public internet, enabling monitoring and interception of data transfers.

**Remediation:** aws ec2 create-vpc-endpoint --vpc-id <vpc-id> --service-name com.amazonaws.<region>.s3 --route-table-ids <route-table-id>

---

### CTL.VPC.ENV.ISOLATION.001

**Production VPC Must Be Isolated from Non-Production**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-7; iso_27001_2022: A.8.22; nist_800_53_r5: SC-7; pci_dss_v4.0: 1.3.1; soc2: CC6.6;

Production VPCs must not share network boundaries with non-production environments. When production and dev/staging workloads share a VPC, a misconfiguration or compromise in a lower environment can reach production resources through security group rules, VPC peering, or shared subnets. Environment isolation requires separate VPCs with explicit, auditable cross-VPC connections.

**Remediation:** Create separate VPCs for each environment (prod, staging, dev). Tag VPCs with an environment classification tag. Use VPC peering or Transit Gateway with explicit route tables for any required cross-environment communication. Ensure security groups do not reference resources in other environments.

---

### CTL.VPC.FLOWLOG.001

**VPC Flow Logging Must Be Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v1.4.0: 3.9; cis_aws_v3.0: 3.7; fedramp_moderate: AU-2; hipaa: 164.312(b); nist_800_53_r5: AU-2; pci_dss_v4.0: 1.2.1; soc2: CC7.1;

VPC flow logs capture information about IP traffic going to and from network interfaces. Without flow logs, network-level access patterns cannot be audited and unauthorized traffic goes undetected.

**Remediation:** Enable VPC flow logs to CloudWatch Logs or S3. Run: aws ec2 create-flow-logs --resource-type VPC --resource-ids vpc-xxx --traffic-type ALL --log-destination-type cloud-watch-logs

---

### CTL.VPC.FLOWLOG.ENCRYPT.001

**VPC Flow Logs Must Be Encrypted**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.312(a)(2)(iv); soc2: CC6.7;

VPC flow logs contain network metadata (source/destination IPs, ports, protocols). When stored in S3, flow logs must be encrypted with a customer-managed KMS key to protect network topology information.

**Remediation:** Configure flow log destination with SSE-KMS encryption. For S3 destinations, enable default bucket encryption with a CMK.

---

### CTL.VPC.INCOMPLETE.001

**Complete Data Required for VPC Assessment**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure

VPC safety cannot be assessed when flow logging status is missing from the snapshot. The extractor must populate network.flow_log.enabled.

**Remediation:** Re-run the extractor with VPC permissions: ec2:DescribeFlowLogs, ec2:DescribeVpcs.

---

### CTL.VPC.NACL.ADMIN.001

**No NACL Ingress from 0.0.0.0/0 to Admin Ports**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 5.1; fedramp_moderate: AC-4; nist_800_53_r5: AC-4; pci_dss_v4.0: 1.3.1; soc2: CC6.6;

Network ACLs must not allow inbound traffic from 0.0.0.0/0 or ::/0 to SSH (22) or RDP (3389) ports. NACLs apply to entire subnets — open admin ports expose all instances.

**Remediation:** Replace the allow rule with a specific CIDR for authorized admin IP ranges using aws ec2 replace-network-acl-entry.

---

### CTL.VPC.NETWORK.FIREWALL.001

**VPC Must Have AWS Network Firewall Deployed**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** network
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.6;

VPCs handling sensitive or production traffic should have AWS Network Firewall deployed for stateful packet inspection beyond SG/NACL L3/L4 rules.

**Remediation:** Deploy AWS Network Firewall with inspection rules for the workload's traffic patterns.

---

### CTL.VPC.PEERING.ROUTES.001

**VPC Peering Route Tables Must Follow Least Access**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 5.5; fedramp_moderate: SC-7; hipaa: 164.312(e)(1); nist_800_53_r5: SC-7; pci_dss_v4.0: 1.3.2; soc2: CC6.6;

Route table entries for VPC peering connections must reference specific subnet CIDRs within the peered VPC, not the entire VPC CIDR. A route to the full peer VPC CIDR means any resource in the local VPC can reach any resource in the peered VPC — collapsing the network boundary between VPCs that were segmented for a reason. This is the routing-layer equivalent of east-west security group over-permissiveness (CTL.VPC.SG.EASTWEST.001). Cross-environment peering routes — production routing to development or vice versa — are a finding regardless of route specificity, as they violate environment isolation at the routing layer. CIS 5.5 requires that VPC peering route tables follow least access.

**Remediation:** Replace the broad VPC CIDR route with specific subnet CIDR routes that target only the subnets hosting the services that require cross-VPC connectivity. For example, replace a route to 10.1.0.0/16 (entire peer VPC) with a route to 10.1.2.0/24 (specific application subnet). Remove peering routes that cross environment boundaries (production to development) unless explicitly justified.

---

### CTL.VPC.SG.DEFAULT.001

**Default Security Group Must Restrict All Traffic**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v1.4.0: 5.4; cis_aws_v3.0: 5.4; fedramp_moderate: AC-4; hipaa: 164.312(a)(1); nist_800_53_r5: AC-4; pci_dss_v4.0: 1.3.2; soc2: CC6.6;

The default VPC security group should not allow any inbound or outbound traffic. Resources should use custom security groups with explicit rules instead of relying on the default group.

**Remediation:** Remove all inbound and outbound rules from the default security group. Assign custom security groups to all resources.

---

### CTL.VPC.SG.EASTWEST.001

**Security Groups Must Not Allow Unrestricted Access Between Internal Services**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-7; hipaa: 164.312(e)(1); nist_800_53_r5: SC-7; pci_dss_v4.0: 1.3.2; soc2: CC6.6;

Security groups on private resources must not allow inbound traffic on application ports from broad internal CIDR ranges or all-port rules from internal sources. East-west over-permissiveness enables lateral movement — a compromised service in the source range inherits access to every destination that grants broad internal access. This is distinct from CTL.VPC.SG.UNRESTRICTED.001 which detects north-south exposure (0.0.0.0/0). Specific conditions: inbound rules from CIDRs broader than /28 (16 addresses), rules referencing the entire VPC CIDR range, or all-port rules from any internal source. The /28 threshold accommodates small dedicated subnets while flagging rules that effectively open access to large internal populations. NSA/CISA advisory AA23-278A identifies flat internal networks as one of the ten most exploited misconfigurations — attackers consistently use over-permissive east-west rules for lateral movement from low-privilege footholds to high-value targets.

**Remediation:** Replace broad CIDR source rules with specific security group references that identify the exact source service. Replace all-port internal rules with rules specifying only the ports the service relationship requires. For database security groups, restrict inbound to the specific application server security group on the database port only. Verify no rule references the entire VPC CIDR range as a source.

---

### CTL.VPC.SG.EGRESS.001

**Security Groups Must Not Allow Unrestricted Egress**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-7; nist_800_53_r5: SC-7; soc2: CC6.6;

Security groups must not allow all outbound traffic to 0.0.0.0/0 on all ports. Unrestricted egress enables data exfiltration, command-and-control communication, and lateral movement to external attacker infrastructure. While most organizations currently allow all egress by default, restricting outbound traffic to required ports and destinations is a critical APT hardening measure.

**Remediation:** Replace the default allow-all egress rule with specific outbound rules for required ports (443 for HTTPS, 53 for DNS, etc.) and destinations. Use VPC endpoints for AWS service traffic to avoid internet egress entirely.

---

### CTL.VPC.SG.EGRESS.EXFIL.001

**Security Groups Must Restrict Egress on Data Exfiltration Ports**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** network
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.6;

Security groups must not allow unrestricted outbound traffic to 0.0.0.0/0 on ports commonly used for data exfiltration (443/HTTPS, 53/DNS, 80/HTTP) even when other ports are blocked. Exfiltration traffic hides in standard web and DNS protocols.

**Remediation:** Restrict egress to specific destination CIDRs where possible. For DNS (53), route through a DNS firewall or VPC resolver endpoint. For HTTPS (443), consider VPC endpoint routes instead of internet egress. Note: blocking 443/53 outbound breaks most applications — this control flags for awareness, not hard block.

---

### CTL.VPC.SG.GHOST.001

**Security Group Rules Must Not Reference Deleted Security Groups**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: CM-6; soc2: CC6.1;

Security group inbound and outbound rules must not reference other security groups that have been deleted. Orphaned SG references clutter the rule set, confuse security audits, and mask the effective rule set. SG IDs are system-generated and not reusable, so the rule effectively permits nothing — this is a governance finding, not an exploitable vulnerability.

**Remediation:** Remove orphaned rules referencing non-existent security group IDs.

---

### CTL.VPC.SG.IPV6.001

**No Security Group Ingress from ::/0 to Admin Ports**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 5.3; fedramp_moderate: AC-4; nist_800_53_r5: AC-4; pci_dss_v4.0: 1.3.1; soc2: CC6.6;

Security groups must not allow inbound SSH (22) or RDP (3389) from ::/0 (IPv6 any). IPv6 open admin ports are equally dangerous as IPv4 and are often overlooked during security reviews.

**Remediation:** Revoke the IPv6 ingress rule: aws ec2 revoke-security-group-ingress --group-id <sg-id> --ip-permissions IpProtocol=tcp,FromPort=22,ToPort=22,Ipv6Ranges=[{CidrIpv6=::/0}]

---

### CTL.VPC.SG.RECUR.001

**Security Group Must Not Have Unrestricted Ingress Appear Repeatedly**

- **Severity:** critical
- **Type:** unsafe_recurrence
- **Domain:** exposure
- **Compliance:** fedramp_moderate: IR-5; hipaa: 164.312(e)(1); nist_800_53_r5: IR-5; pci_dss_v4.0: 12.10; soc2: CC7.1;

Security group has had unrestricted ingress (0.0.0.0/0 or ::/0) added, removed, and added again more than twice in 30 days. Security group rules are not accidental — adding a rule is a deliberate API call. Repeated re-addition after removal indicates either a broken change process or an attacker re-enabling their access path after detection.

**Remediation:** Investigate the root cause of the repeated oscillation. Determine whether the pattern indicates a broken process, operational workaround, or active compromise. Review CloudTrail for the API calls that triggered each transition.

---

### CTL.VPC.SG.UNRESTRICTED.001

**Security Groups Must Not Allow Unrestricted Ingress**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v1.4.0: 5.2; cis_aws_v3.0: 5.2; fedramp_moderate: AC-4; hipaa: 164.312(e)(1); nist_800_53_r5: AC-4; pci_dss_v4.0: 1.3.1; soc2: CC6.6;

Security group rules must not allow ingress from 0.0.0.0/0 on sensitive ports (SSH, RDP, database). Unrestricted ingress exposes services to the entire internet.

**Remediation:** Restrict ingress rules to specific CIDR blocks or security group references. Remove 0.0.0.0/0 and ::/0 from ingress rules on ports 22 (SSH), 3389 (RDP), 3306 (MySQL), 5432 (PostgreSQL).

---

### CTL.VSPHERE.ESX.ACCEPTANCE.001

**ESXi Host Must Not Use CommunitySupported Acceptance Level**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_vmware_esxi_7: 1.6; nist_800_53_r5: CM-5;

ESXi hosts must not accept CommunitySupported VIBs. Community packages bypass VMware's signing and quality assurance process, allowing unsigned code to run in the hypervisor kernel. An attacker can exploit this to install persistent rootkits.

**Remediation:** Raise the acceptance level to at least PartnerSupported: esxcli software acceptance set --level=PartnerSupported

---

### CTL.VSPHERE.ESX.ACCOUNT.LOCKOUT.001

**ESXi Account Lockout Must Be Configured**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_vmware_esxi_7: 1.3; nist_800_53_r5: AC-7;

ESXi hosts must have account lockout configured. Without account lockout, an attacker can perform unlimited password guessing attempts against local ESXi accounts. The DCUI, SSH, and Host Client interfaces all accept local credentials. Brute-force attacks against the root account or service accounts become trivial when there is no lockout threshold to slow or block repeated failures.

**Remediation:** Configure account lockout on the ESXi host. In the vSphere Client, navigate to Host > Configure > System > Advanced System Settings. Set Security.AccountLockFailures to 5 and Security.AccountUnlockTime to 900.

---

### CTL.VSPHERE.ESX.CIM.001

**ESXi CIM (SFCBD) Service Must Be Disabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_vmware_esxi_7: 2.1; nist_800_53_r5: CM-7;

The CIM (Small Footprint CIM Broker Daemon) service on ESXi hosts must be disabled when not required. SFCBD exposes a network-accessible management interface that has been the target of multiple CVEs. If hardware monitoring is not needed, this service increases the attack surface unnecessarily.

**Remediation:** Disable the SFCBD service if hardware CIM monitoring is not required: esxcli system wbem set --enable=false

---

### CTL.VSPHERE.ESX.COREDUMP.001

**ESXi Host Must Have Core Dump Configured**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_vmware_esxi_7: 1.7; nist_800_53_r5: SI-11;

ESXi hosts must have a core dump target configured for crash analysis. Without a configured dump target, diagnostic information is lost after a host failure, preventing root cause analysis of potential security incidents.

**Remediation:** Configure a network core dump target: esxcli system coredump network set --interface-name=vmk0 --server-ipv4=<dump-server> --server-port=6500 esxcli system coredump network set --enable=true

---

### CTL.VSPHERE.ESX.DCUI.001

**DCUI Access Must Be Restricted**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_vmware_esxi_7: 1.4; nist_800_53_r5: AC-3;

Direct Console User Interface access must be restricted on ESXi hosts. The DCUI provides physical console access to ESXi management functions including network configuration, password resets, and troubleshooting. Unrestricted DCUI access allows anyone with physical or out-of-band console access to reconfigure the host, reset the root password, or disable security settings without authentication. In environments with IPMI or iLO remote console access, DCUI exposure extends beyond physical proximity.

**Remediation:** Restrict DCUI access on the ESXi host. In the vSphere Client, navigate to Host > Configure > System > Advanced System Settings. Set DCUI.Access to a specific list of authorized users. Consider disabling the DCUI service entirely if not required for operations.

---

### CTL.VSPHERE.ESX.LOCKDOWN.001

**Lockdown Mode Must Be Enabled on ESXi Hosts**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_vmware_esxi_7: 1.2; nist_800_53_r5: CM-7;

Lockdown mode must be enabled on ESXi hosts. When lockdown mode is disabled, the host can be managed directly via local clients and APIs, bypassing vCenter role-based access controls. Enabling lockdown mode forces all management through vCenter, ensuring centralized authentication, authorization, and audit logging.

**Remediation:** Enable lockdown mode on the ESXi host. In the vSphere Client, navigate to Host > Configure > System > Security Profile > Lockdown Mode and select Normal or Strict. Normal lockdown allows DCUI access for emergency troubleshooting; Strict lockdown disables DCUI as well.

---

### CTL.VSPHERE.ESX.MOB.001

**Managed Object Browser Must Be Disabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_vmware_esxi_7: 3.9; nist_800_53_r5: CM-7;

The Managed Object Browser must be disabled on ESXi hosts. The MOB is a web-based interface that provides direct access to the ESXi SDK object model. An authenticated attacker can use the MOB to invoke API methods, modify virtual machine configurations, extract credentials, and manipulate host settings. The MOB bypasses the vSphere Client permission model and exposes low-level SDK operations that are not intended for production use.

**Remediation:** Disable the Managed Object Browser on the ESXi host. In the vSphere Client, navigate to Host > Configure > System > Advanced System Settings. Set Config.HostAgent.plugins.solo.enableMob to false. No service restart is required.

---

### CTL.VSPHERE.ESX.NTP.001

**ESXi Host Must Have NTP Configured**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_vmware_esxi_7: 1.4; nist_800_53_r5: AU-8;

ESXi hosts must have NTP configured for accurate time synchronization. Without NTP, log timestamps drift and make forensic correlation unreliable. Attackers exploit time skew to hide activity across distributed systems.

**Remediation:** Configure NTP on the ESXi host using esxcli: esxcli system ntp set --server=<ntp-server> esxcli system ntp set --enabled=true

---

### CTL.VSPHERE.ESX.PERSISTLOG.001

**ESXi Host Must Have Persistent Logging Configured**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_vmware_esxi_7: 1.8; nist_800_53_r5: AU-9;

ESXi hosts must store logs on a persistent datastore. By default logs are written to a ramdisk scratch partition and are lost on reboot. An attacker can force a reboot to erase forensic evidence.

**Remediation:** Configure a persistent log location on a VMFS datastore: esxcli system syslog config set --logdir=/vmfs/volumes/<datastore>/logs esxcli system syslog reload

---

### CTL.VSPHERE.ESX.SHELL.001

**ESXi Shell Must Be Disabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_vmware_esxi_7: 1.2;

The ESXi shell must be disabled. An enabled shell provides local console access to the hypervisor, bypassing remote management audit controls.

**Remediation:** Disable the ESXi Shell service. Set startup policy to manual.

---

### CTL.VSPHERE.ESX.SLP.001

**ESXi SLP Service Must Be Disabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_vmware_esxi_7: 2.2; nist_800_53_r5: CM-7;

The Service Location Protocol (SLP) service on ESXi hosts must be disabled. SLP has been exploited in critical remote code execution attacks (CVE-2021-21974) and provides no value in environments using vCenter for management. Leaving it enabled exposes a high-risk network service.

**Remediation:** Disable the SLP service: /etc/init.d/slpd stop esxcli network firewall ruleset set --ruleset-id=CIMSLP --enabled=false chkconfig slpd off

---

### CTL.VSPHERE.ESX.SNMP.001

**SNMP Must Be Disabled or Configured Securely**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_vmware_esxi_7: 3.8; nist_800_53_r5: CM-7;

SNMP on ESXi hosts must be disabled or configured with SNMPv3 authentication and encryption. SNMPv1 and SNMPv2c transmit community strings in cleartext, allowing any attacker with network access to intercept credentials and query host information. SNMP write access with a known community string enables remote reconfiguration of the host. Even read-only SNMP access exposes detailed hardware, software, and network configuration data useful for reconnaissance.

**Remediation:** Disable SNMP if not required. If SNMP monitoring is needed, configure SNMPv3 with authentication and privacy. Use esxcli system snmp set --enable false to disable SNMP, or configure SNMPv3 with esxcli system snmp set --authentication SHA1 --privacy AES128.

---

### CTL.VSPHERE.ESX.SSH.001

**SSH Must Be Disabled on ESXi Hosts**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_vmware_esxi_7: 1.1; nist_800_53_r5: CM-7;

SSH must be disabled on ESXi hosts. An enabled SSH service exposes the ESXi management plane to remote shell access, increasing the attack surface for credential brute-force and lateral movement. ESXi management should use the vSphere Client or Host Client via HTTPS only. SSH should only be enabled temporarily for troubleshooting and disabled immediately after.

**Remediation:** Disable the SSH service on the ESXi host. In the vSphere Client, navigate to Host > Configure > System > Services, select SSH, and click Stop. Set the startup policy to "Start and stop manually" to prevent automatic re-enablement.

---

### CTL.VSPHERE.ESX.SYSLOG.001

**ESXi Host Must Have Syslog Configured**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_vmware_esxi_7: 1.5; nist_800_53_r5: AU-4;

ESXi hosts must forward logs to a remote syslog server. Without centralized logging, an attacker who compromises the host can destroy local logs and erase evidence of the intrusion.

**Remediation:** Configure remote syslog on the ESXi host using esxcli: esxcli system syslog config set --loghost=<protocol>://<host>:<port> esxcli system syslog reload

---

### CTL.VSPHERE.ESX.TLS.001

**ESXi Must Use TLS 1.2 or Higher**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_vmware_esxi_7: 1.6; nist_800_53_r5: SC-8;

ESXi hosts must use TLS 1.2 or higher for all management connections. TLS 1.0 and 1.1 have known cryptographic weaknesses including vulnerability to BEAST, POODLE, and other protocol downgrade attacks. Management traffic to ESXi hosts carries authentication credentials, virtual machine data, and configuration changes. An attacker on the network path can exploit TLS 1.0/1.1 weaknesses to decrypt or modify this traffic.

**Remediation:** Configure the ESXi host to require TLS 1.2 or higher. In the vSphere Client, navigate to Host > Configure > System > Advanced System Settings. Set UserVars.ESXiVPsDisabledProtocols to "sslv3,tlsv1,tlsv1.1" to disable all protocols below TLS 1.2. Restart management agents after the change.

---

### CTL.VSPHERE.FIREWALL.ENABLED.001

**ESXi Host Firewall Must Be Enabled**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_vmware_esxi_7: 3.1; nist_800_53_r5: SC-7;

The ESXi host firewall must be enabled to restrict network access to management services. With the firewall disabled, all ESXi services are reachable from any network, dramatically increasing the attack surface for remote exploitation.

**Remediation:** Enable the ESXi host firewall: esxcli network firewall set --enabled=true Review and restrict firewall rulesets to only required services.

---

### CTL.VSPHERE.ISCSI.CHAP.001

**iSCSI Storage Must Require CHAP Authentication**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_vmware_esxi_7: 6.2; nist_800_53_r5: IA-2;

iSCSI datastores must require CHAP authentication. Without CHAP, any host on the storage network can connect to the iSCSI target and access virtual machine disk data. This enables data exfiltration and tampering from a compromised host.

**Remediation:** Configure mutual CHAP authentication on iSCSI adapters: Navigate to Host > Configure > Storage Adapters > iSCSI Adapter > Authentication > Use bidirectional CHAP.

---

### CTL.VSPHERE.NFS.AUTH.001

**NFS Storage Must Require Authentication**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_vmware_esxi_7: 6.1; nist_800_53_r5: IA-2;

NFS datastores must require authentication (Kerberos). Unauthenticated NFS mounts rely solely on IP-based access control, which is trivially bypassed through IP spoofing or compromised hosts on the same network segment.

**Remediation:** Configure NFS datastores to use Kerberos authentication (NFS 4.1 with SEC_KRB5). Migrate from NFS 3 to NFS 4.1 if necessary to support authenticated mounts.

---

### CTL.VSPHERE.VCSA.CEIP.001

**Customer Experience Improvement Program Must Be Disabled**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_vmware_esxi_7: 2.6; nist_800_53_r5: SC-7;

The VMware Customer Experience Improvement Program must be disabled on vCenter Server. CEIP collects configuration and usage telemetry from the vCenter environment and transmits it to VMware over the internet. This telemetry includes information about host counts, virtual machine configurations, feature usage patterns, and environment topology. In regulated environments, transmitting infrastructure metadata to an external party may violate data sovereignty or confidentiality requirements. The outbound connection also increases the attack surface.

**Remediation:** Disable CEIP in the vSphere Client. Navigate to Administration > Customer Experience Improvement Program and deselect the participation checkbox. Alternatively, use the vCenter Server Management Interface at https://<vcenter>:5480 to disable CEIP under Telemetry.

---

### CTL.VSPHERE.VCSA.PLUGINS.001

**Unauthorized vCenter Plugins Must Be Removed**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_vmware_esxi_7: 2.5; nist_800_53_r5: CM-7;

Unauthorized plugins must be removed from vCenter Server. vCenter plugins execute with the privileges of the vCenter service and have full access to the vSphere API. A malicious or compromised plugin can exfiltrate credentials, modify virtual machine configurations, and persist across vCenter upgrades. Third-party plugins that are no longer maintained may contain unpatched vulnerabilities that an attacker can exploit to gain code execution within the vCenter process.

**Remediation:** Review installed plugins in the vSphere Client. Navigate to Administration > Solutions > Client Plug-Ins. Remove any plugins that are not authorized, no longer maintained, or not required for operations. Verify the publisher and version of all remaining plugins.

---

### CTL.VSPHERE.VCSA.SSO.LOCKOUT.001

**vCenter SSO Account Lockout Must Be Configured**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_vmware_esxi_7: 2.1; nist_800_53_r5: AC-7;

vCenter Single Sign-On must have account lockout configured. Without lockout, an attacker can perform unlimited password guessing attempts against the SSO identity source. The vCenter SSO service authenticates all access to the vSphere management plane including the vSphere Client, API, and PowerCLI. A compromised SSO administrator account grants full control over all ESXi hosts, virtual machines, and infrastructure managed by the vCenter instance.

**Remediation:** Configure SSO account lockout in the vSphere Client. Navigate to Administration > Single Sign-On > Configuration > Accounts. Set Maximum number of failed login attempts to 5 and Time interval between failures to 180 seconds. Set Unlock time to 900 seconds.

---

### CTL.VSPHERE.VCSA.SSO.PASSLEN.001

**vCenter SSO Password Length Must Be 15+**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_vmware_esxi_7: 2.2; nist_800_53_r5: IA-5;

vCenter SSO must enforce a minimum password length of 15 characters. Short passwords are vulnerable to brute-force and dictionary attacks. The SSO password policy applies to all accounts in the vsphere.local identity source including the administrator@vsphere.local account. A weak password on this account grants an attacker full administrative control over the entire vSphere environment. NIST SP 800-63B recommends a minimum of 15 characters for privileged accounts.

**Remediation:** Configure SSO password policy in the vSphere Client. Navigate to Administration > Single Sign-On > Configuration > Accounts. Set Minimum length to 15 characters. Existing accounts with shorter passwords will be required to change their password at next login.

---

### CTL.VSPHERE.VDS.FORGED.001

**Distributed Switch Must Not Allow Forged Transmits**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_vmware_esxi_7: 4.3; nist_800_53_r5: SC-7;

vSphere Distributed Switch port groups must not allow forged transmits. When enabled, a VM can send frames with a source MAC address different from its own, enabling network spoofing and lateral movement between virtual machines.

**Remediation:** Disable forged transmits on the distributed port group in vCenter: Navigate to Networking > Distributed Switch > Port Group > Edit Settings > Security > Forged Transmits > Reject.

---

### CTL.VSPHERE.VDS.MACCHG.001

**Distributed Switch Must Not Allow MAC Address Changes**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_vmware_esxi_7: 4.2; nist_800_53_r5: SC-7;

vSphere Distributed Switch port groups must not allow MAC address changes. When enabled, a VM can change its effective MAC address and impersonate other machines on the network, enabling lateral movement and man-in-the-middle attacks.

**Remediation:** Disable MAC address changes on the distributed port group in vCenter: Navigate to Networking > Distributed Switch > Port Group > Edit Settings > Security > MAC Address Changes > Reject.

---

### CTL.VSPHERE.VDS.PROMISC.001

**Distributed Switch Must Not Allow Promiscuous Mode**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_vmware_esxi_7: 4.1; nist_800_53_r5: SC-7;

vSphere Distributed Switch port groups must not allow promiscuous mode. When enabled, a VM can observe all network traffic on the switch, enabling credential sniffing and reconnaissance across the virtual network segment.

**Remediation:** Disable promiscuous mode on the distributed port group in vCenter: Navigate to Networking > Distributed Switch > Port Group > Edit Settings > Security > Promiscuous Mode > Reject.

---

### CTL.VSPHERE.VM.COPYPASTE.001

**Copy-Paste Between VM and Host Must Be Disabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_vmware_esxi_7: 8.3.1; nist_800_53_r5: SC-7;

Copy and paste operations between the guest VM and the host must be disabled. When enabled, the shared clipboard allows data to move between the VM and the host or client system without network controls or logging. An attacker with access to a compromised VM can exfiltrate data through the clipboard channel, bypassing network-based DLP and monitoring controls.

**Remediation:** Disable copy and paste by setting the VM advanced configuration parameters isolation.tools.copy.disable and isolation.tools.paste.disable to TRUE. Apply this via VM > Configure > Advanced Parameters in the vSphere Client.

---

### CTL.VSPHERE.VM.DISKSHRNK.001

**VM Disk Shrinking Must Be Disabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_vmware_esxi_7: 8.5; nist_800_53_r5: SC-6;

Virtual machines must not allow disk shrinking operations. Disk shrinking can be triggered from within the guest OS and causes repeated grow-shrink cycles that lead to denial of service on the underlying datastore. An attacker inside the VM can exhaust datastore capacity.

**Remediation:** Disable disk shrinking on the VM: Edit VM Settings > Advanced > Configuration Parameters > Set isolation.tools.diskShrink.disable to TRUE and isolation.tools.diskWiper.disable to TRUE.

---

### CTL.VSPHERE.VM.ENCRYPT.001

**VMs with Sensitive Data Must Be Encrypted**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_vmware_esxi_7: 8.2.1; nist_800_53_r5: SC-28;

Virtual machines containing sensitive data must have VM encryption enabled. Without encryption, VM disk files (VMDKs), snapshots, and vMotion traffic are stored and transmitted in cleartext. An attacker with access to the datastore or network can read VM contents directly. VM encryption protects data at rest on the datastore and in transit during vMotion operations.

**Remediation:** Enable VM encryption using a vSphere Trust Authority or Standard Key Provider. Configure a KMS cluster in vCenter, then apply a VM storage policy with encryption enabled. Encrypt the VM by editing its storage policy assignment. Note that VM encryption requires a compatible key management server.

---

### CTL.VSPHERE.VM.HGFS.001

**VM HGFS File Transfer Must Be Disabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_vmware_esxi_7: 8.3.2; nist_800_53_r5: CM-7;

Virtual machines must have the Host Guest File System (HGFS) transfer capability disabled. HGFS allows file transfers between the ESXi host and the guest VM, providing a covert channel for data exfiltration that bypasses network-based monitoring.

**Remediation:** Disable HGFS on the VM: Edit VM Settings > Advanced > Configuration Parameters > Set isolation.tools.hgfsServerSet.disable to TRUE.

---

### CTL.VSPHERE.VM.INDEP.001

**VM Must Not Use Independent Non-Persistent Disks**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_vmware_esxi_7: 8.6; nist_800_53_r5: AU-9;

Virtual machines must not use independent non-persistent disks. Changes to non-persistent disks are discarded on power-off or reset, which means security patches, agent updates, and forensic artifacts are lost. An attacker can reboot the VM to erase evidence of compromise.

**Remediation:** Change the disk mode to persistent or dependent: Edit VM Settings > Hard Disk > Disk Mode > Persistent. Ensure backups and snapshots capture the correct disk state.

---

### CTL.VSPHERE.VM.LOGSIZE.001

**VM Log Size Must Be Limited**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_vmware_esxi_7: 8.4.4;

VM diagnostic log size must be limited to prevent a compromised VM from filling the datastore via excessive logging, causing denial of service to other VMs on the same datastore.

**Remediation:** Set log.rotateSize and log.keepOld in the VM advanced settings.

---

### CTL.VSPHERE.VM.REMOTEDISP.001

**VM Remote Display Must Be Disabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_vmware_esxi_7: 8.1; nist_800_53_r5: CM-7;

Virtual machines must not have the remote display (VNC) feature enabled. The remote display exposes an unauthenticated VNC connection to the VM console, allowing any network-adjacent attacker to view and interact with the VM.

**Remediation:** Disable the remote display on the VM: Edit VM Settings > Advanced > Configuration Parameters > Set RemoteDisplay.vnc.enabled to FALSE.

---

### CTL.VSPHERE.VM.SNAPSHOT.AGE.001

**No VM Snapshot Older Than 30 Days**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_vmware_esxi_7: 8.4.1;

VM snapshots must not be older than 30 days. Stale snapshots consume datastore space, degrade VM performance due to increased I/O chain depth, and create operational risk during consolidation. Long-lived snapshots also represent a data exposure risk — they preserve the VM state at a point in time that may contain credentials or sensitive data that has since been rotated.

**Remediation:** Delete or consolidate stale snapshots. In the vSphere Client, right-click the VM > Snapshots > Manage Snapshots and delete snapshots older than 30 days. Establish a policy to review and clean up snapshots on a regular schedule.

---

### CTL.VSPHERE.VSAN.ENCRYPT.001

**vSAN Must Have Data-at-Rest Encryption Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_vmware_esxi_7: 5.1; nist_800_53_r5: SC-28;

vSAN clusters with encryption disabled expose virtual machine data to physical media theft and unauthorized access. When vSAN is enabled but encryption is not, all VM data on the cluster is stored in cleartext on the underlying disks.

**Remediation:** Enable vSAN encryption in vCenter: Navigate to Cluster > Configure > vSAN > Services > Encryption > Enable. A KMS server must be configured before enabling encryption.

---

### CTL.VSPHERE.VSAN.TRANSIT.001

**vSAN Must Have Data-in-Transit Encryption Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_vmware_esxi_7: 5.2; nist_800_53_r5: SC-8;

vSAN clusters must encrypt data in transit between hosts. Without transit encryption, inter-host vSAN traffic traverses the network in cleartext, allowing an attacker with network access to intercept VM data and credentials.

**Remediation:** Enable vSAN data-in-transit encryption in vCenter: Navigate to Cluster > Configure > vSAN > Services > Encryption > Enable data-in-transit encryption.

---

### CTL.WAF.EVASION.OBSERVE.001

**WAF Must Have Full Body Inspection and Request Sampling Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SI-4; hipaa: 164.312(b); nist_800_53_r5: SI-4; pci_dss_v4.0: 10.2.1; soc2: CC7.1;

WAF Web ACLs must have full request body inspection enabled and sampled allowed-request logging active. Signature-based WAF rules can be evaded through encoding techniques such as CRLF injection, Unicode surrogate pairs, and HTML parser confusion. HackerOne report #2921905 documents a WAF bypass using CRLF and HTML attribute confusion that evaded Cloudflare rule matching entirely. Prevention of encoding evasion is a vendor responsibility, but the organization must ensure that when evasion occurs it is observable. Without full body inspection, payloads in POST bodies, JSON fields, and multipart uploads are invisible to all WAF rules. Without sampled allowed-request logging, successful bypass attempts leave no forensic trace — the organization cannot distinguish between no attacks and undetected attacks. This control differs from CTL.WAF.LOGGING.001 (which checks logging is enabled) by verifying the logging and inspection configuration captures enough detail to detect evasion patterns.

**Remediation:** Enable full request body inspection on the Web ACL and increase the body size inspection limit beyond the default 8KB to cover modern API payloads. Enable sampled request logging for allowed requests — not only blocked requests. For AWS WAF, configure the Web ACL body inspection to inspect the full body and enable request sampling via the AWS WAF console or UpdateWebACL API. Reference: HackerOne report #2921905 documents a WAF bypass via CRLF injection that would be detectable with full body inspection and request sampling.

---

### CTL.WAF.INCOMPLETE.001

**Complete Data Required for WAF Assessment**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure

WAF assessment data is incomplete. The extractor must populate waf.rules.has_managed_rules to evaluate protection controls.

**Remediation:** Re-run the extractor with WAF permissions: wafv2:GetWebACL, wafv2:ListWebACLs, wafv2:GetLoggingConfiguration.

---

### CTL.WAF.LOGGING.001

**WAF Logging Must Be Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AU-2; nist_800_53_r5: AU-2; soc2: CC7.1;

WAF web ACLs must have logging enabled to record blocked and allowed requests. Without logging, attacks cannot be detected, investigated, or correlated with other security events.

**Remediation:** Enable WAF logging to S3, CloudWatch Logs, or Kinesis Data Firehose via aws wafv2 put-logging-configuration.

---

### CTL.WAF.ORIGIN.LOCKDOWN.001

**WAF Origin Must Not Accept Direct Internet Traffic**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-7; hipaa: 164.312(e)(1); nist_800_53_r5: SC-7; pci_dss_v4.0: 1.3.1; soc2: CC6.6;

When a WAF Web ACL is associated with an origin server (ALB, API Gateway, EC2 instance), the origin's network ingress controls must not permit inbound connections on application ports from the public internet. A WAF that sits in front of an origin provides zero protection if the origin also accepts direct connections from 0.0.0.0/0 or ::/0 — an attacker who discovers the origin IP address through Censys, Shodan, certificate transparency logs, historical DNS records, or timing analysis can send traffic directly to the origin, bypassing every WAF rule, DDoS protection, and rate limit. This is the architectural prerequisite for all other WAF controls — without origin lockdown, the entire WAF safety envelope is irrelevant regardless of how well the WAF rules are configured. HackerOne report (Linode) documents this exact pattern: an origin behind Cloudflare was discoverable via Censys, allowing direct unfiltered payload delivery and denial-of-service against the unprotected origin.

**Remediation:** Restrict the origin's security group inbound rules on application ports (80, 443, custom) to allow traffic only from WAF or CDN provider IP ranges. For CloudFront, use the AWS-managed prefix list com.amazonaws.global.cloudfront.origin-facing in the security group rule. For regional ALBs behind AWS WAF, restrict to the WAF endpoint subnet CIDRs. Remove all 0.0.0.0/0 and ::/0 ingress rules on application ports.

---

### CTL.WAF.PARSERLIMIT.PROTECT.001

**WAF Must Block Requests That Exceed Parser Limits**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SI-10; hipaa: 164.312(e)(1); nist_800_53_r5: SI-10; pci_dss_v4.0: 6.4.1; soc2: CC6.6;

WAF Web ACLs must contain a highest-priority rule that detects when the WAF's internal parser limits have been exceeded and blocks the request. Every WAF has parser limits — maximum header count, maximum header size, maximum body size, maximum cookie count. When a request exceeds these limits, rule evaluation silently stops at the truncation point. Rules configured to inspect content beyond the limit never fire. The request passes through as if clean. A Cloudflare HackerOne report (High severity, $1,250 bounty, 2025-11-18) documented this: 94+ HTTP headers caused all WAF rules, cache key evaluation, and cache rules to bypass simultaneously. Cloudflare's mitigation: a rule checking http.request.headers.truncated at highest priority in BLOCK mode. This vulnerability class applies to every WAF vendor — the invariant is vendor-neutral. The parser limit protection rule must execute before all other rules. A rule at lower priority allows other rules to evaluate truncated content before the overflow is detected, creating a race condition attackers can exploit. This control is the prerequisite for all other WAF rule controls — if the parser can be overflowed, managed rules, OWASP coverage, and custom rules are irrelevant for any request designed to exceed the limit.

**Remediation:** Add a rule at the highest priority position (priority 0 or the lowest numeric value) that detects parser overflow and blocks the request. For Cloudflare, check http.request.headers.truncated == true. For AWS WAF, use a size constraint rule checking header count or total header size against the documented parser limit. The rule must be in BLOCK mode — COUNT mode detects but does not prevent the bypass. Verify the rule has higher priority than all managed rule groups and custom rules in the Web ACL.

---

### CTL.WAF.RULES.001

**WAF Must Have Managed Rule Groups Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SI-3; nist_800_53_r5: SI-3; pci_dss_v4.0: 6.4.1; soc2: CC6.6;

WAF web ACLs must include AWS managed rule groups for common attack patterns (SQLi, XSS, known bad inputs). Without managed rules, the WAF provides no baseline protection against OWASP Top 10 attacks.

**Remediation:** Add AWS managed rule groups to the web ACL: AWSManagedRulesCommonRuleSet, AWSManagedRulesSQLiRuleSet, AWSManagedRulesKnownBadInputsRuleSet.

---

### CTL.WAF.RULES.BLOCKMODE.001

**WAF Rules Must Be in BLOCK Mode, Not COUNT Mode**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SI-3; nist_800_53_r5: SI-3; pci_dss_v4.0: 6.4.1; soc2: CC6.6;

All WAF rules and rule groups must have their effective action set to BLOCK. A rule in COUNT mode observes and logs attacks but does not block them. AWS WAF defaults newly added rules to COUNT mode during tuning. This becomes a permanent misconfiguration when teams never transition to BLOCK. The WAF appears active in every compliance report while blocking nothing. COUNT mode may be intentional during tuning — the stave/waf-count-mode-justified tag documents this exception.

**Remediation:** Transition COUNT-mode rules to BLOCK mode. If COUNT mode is intentional during tuning, add a stave/waf-count-mode-justified tag to the WebACL with the justification (e.g., ticket number).

---

### CTL.WAF.RULES.OWASP.001

**WAF Must Have OWASP Core Rule Coverage**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SI-3; nist_800_53_r5: SI-3; owasp_top10_2021: A03; pci_dss_v4.0: 6.4.1; soc2: CC6.6;

WAF web ACLs must include the three core AWS managed rule groups that cover OWASP Top 10 attack categories: AWSManagedRulesCommonRuleSet (XSS, path traversal, HTTP violations), AWSManagedRulesSQLiRuleSet (SQL injection), and AWSManagedRulesKnownBadInputsRuleSet (Log4Shell, deserialization, known CVE payloads). All three groups must be attached and enforcing in BLOCK mode. A WAF with custom rules only, or with managed rule groups that cover IP reputation or bot management but not OWASP attack categories, provides incomplete coverage. This control differs from CTL.WAF.RULES.001 (which checks for any managed rules) by requiring the specific groups needed for baseline OWASP coverage. HackerOne report #382625 documents a stored XSS bypass against a production WAF that was active and blocking with custom rules but lacked AWSManagedRulesCommonRuleSet — the payload used a marquee element with an inline event handler, a known vector covered by the CrossSiteScripting_BODY rule in the common rule set.

**Remediation:** Add the following AWS managed rule groups to the web ACL and ensure each is in BLOCK mode with no COUNT override at the group level or rule action override level: (1) AWSManagedRulesCommonRuleSet — covers XSS, path traversal, common exploits, (2) AWSManagedRulesSQLiRuleSet — covers SQL injection attack patterns, (3) AWSManagedRulesKnownBad InputsRuleSet — covers known CVE exploits including Log4j and Spring4Shell.

---

### CTL.WORKSPACES.ENCRYPT.001

**WorkSpaces Must Encrypt Volumes At Rest**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** nist_800_53_r5: SC-28; soc2: CC6.7;

WorkSpaces root and user EBS volumes must be encrypted at rest.

**Remediation:** Enable volume encryption on the workspace.

---

