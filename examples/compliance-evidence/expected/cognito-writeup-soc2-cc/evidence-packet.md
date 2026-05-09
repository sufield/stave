# SOC 2 Type II Compliance Evidence Packet

- Generated: 2026-01-09T00:00:00Z
- Framework: SOC 2 Type II (2017)
- Tool: Stave (proof-to-evidence translator)

## Summary

| Metric | Count |
|---|---:|
| Total controls assessed | 5 |
| Compliant | 3 |
| Non-compliant | 2 |
| Not assessed (no Stave coverage) | 0 |

## Per-control evidence

### CC6.1: Logical and Physical Access Controls  [FAIL]

- **Status:** non_compliant
- **Cross-reference:** NIST AC-3, AC-6

_The entity implements logical access security software, infrastructure, and architectures over protected information assets to protect them from security events to meet the entity's objectives._

**Stave coverage:** 1018 control(s) (1016 clean, 2 fired).

**Findings (this fixture):**
- FAIL `CTL.COGNITO.MFA.001` [unknown] on `arn:aws:cognito-idp:us-east-1:111122223333:userpool/us-east-1_appPool` — (no summary)
- FAIL `CTL.COGNITO.SELFREG.001` [unknown] on `arn:aws:cognito-idp:us-east-1:111122223333:userpool/us-east-1_appPool` — (no summary)

### CC6.3: Role-Based Access and Least Privilege  [FAIL]

- **Status:** non_compliant
- **Cross-reference:** NIST AC-2, AC-5, AC-6

_The entity authorizes, modifies, or removes access to data, software, functions, and other protected information assets based on roles, responsibilities, or the system design and changes._

**Stave coverage:** 122 control(s) (121 clean, 2 fired).

**Findings (this fixture):**
- FAIL `CTL.IAM.ROLE.INTENTTAG.001` [unknown] on `arn:aws:iam::111122223333:role/Cognito_appAuth_Role` — (no summary)
- FAIL `CTL.IAM.ROLE.INTENTTAG.001` [unknown] on `arn:aws:iam::111122223333:role/Cognito_appUnauth_Role` — (no summary)

### CC6.6: System Boundary Protection  [PASS]

- **Status:** compliant
- **Cross-reference:** NIST SC-7

_The entity implements logical access security measures to protect against threats from sources outside its system boundaries._

**Stave coverage:** 344 control(s) (344 clean, 0 fired).

**Findings (this fixture):** none — every mapped Stave control evaluated clean.

### CC7.1: System Component Detection  [PASS]

- **Status:** compliant
- **Cross-reference:** NIST CM-3, RA-5

_To meet its objectives, the entity uses detection and monitoring procedures to identify (1) changes to configurations that result in the introduction of new vulnerabilities, and (2) susceptibilities to newly discovered vulnerabilities._

**Stave coverage:** 292 control(s) (292 clean, 0 fired).

**Findings (this fixture):** none — every mapped Stave control evaluated clean.

### CC7.2: System Monitoring  [PASS]

- **Status:** compliant
- **Cross-reference:** NIST AU-2, AU-3, AU-6

_The entity monitors system components and the operation of those components for anomalies that are indicative of malicious acts, natural disasters, and errors affecting the entity's ability to meet its objectives._

**Stave coverage:** 301 control(s) (301 clean, 0 fired).

**Findings (this fixture):** none — every mapped Stave control evaluated clean.
