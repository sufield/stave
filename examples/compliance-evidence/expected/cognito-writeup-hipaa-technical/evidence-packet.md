# HIPAA Technical Safeguards Compliance Evidence Packet

- Generated: 2026-01-09T00:00:00Z
- Framework: HIPAA Technical Safeguards (45 CFR 164.312)
- Tool: Stave (proof-to-evidence translator)

## Summary

| Metric | Count |
|---|---:|
| Total controls assessed | 6 |
| Compliant | 5 |
| Non-compliant | 1 |
| Not assessed (no Stave coverage) | 0 |

## Per-control evidence

### 164.312(a)(1): Access Control — Unique User Identification  [PASS]

- **Status:** compliant
- **Cross-reference:** SOC 2 CC6.1, NIST AC-2

_Implement technical policies and procedures for electronic information systems that maintain electronic protected health information to allow access only to those persons or software programs that have been granted access rights._

**Stave coverage:** 97 control(s) (97 clean, 0 fired).

**Findings (this fixture):** none — every mapped Stave control evaluated clean.

### 164.312(a)(2)(i): Access Control — Automatic Logoff  [PASS]

- **Status:** compliant
- **Cross-reference:** SOC 2 CC6.1, NIST AC-12

_Implement electronic procedures that terminate an electronic session after a predetermined time of inactivity._

**Stave coverage:** 14 control(s) (14 clean, 0 fired).

**Findings (this fixture):** none — every mapped Stave control evaluated clean.

### 164.312(b): Audit Controls  [PASS]

- **Status:** compliant
- **Cross-reference:** SOC 2 CC7.2, NIST AU-2, AU-3

_Implement hardware, software, and/or procedural mechanisms that record and examine activity in information systems that contain or use electronic protected health information._

**Stave coverage:** 103 control(s) (103 clean, 0 fired).

**Findings (this fixture):** none — every mapped Stave control evaluated clean.

### 164.312(d): Person or Entity Authentication  [FAIL]

- **Status:** non_compliant
- **Cross-reference:** SOC 2 CC6.1, NIST IA-2

_Implement procedures to verify that a person or entity seeking access to electronic protected health information is the one claimed._

**Stave coverage:** 25 control(s) (24 clean, 1 fired).

**Findings (this fixture):**
- FAIL `CTL.COGNITO.MFA.001` [unknown] on `arn:aws:cognito-idp:us-east-1:111122223333:userpool/us-east-1_appPool` — (no summary)

### 164.312(c)(1): Integrity — Data Modification Detection  [PASS]

- **Status:** compliant
- **Cross-reference:** SOC 2 CC6.6, NIST SI-7

_Implement policies and procedures to protect electronic protected health information from improper alteration or destruction._

**Stave coverage:** 23 control(s) (23 clean, 0 fired).

**Findings (this fixture):** none — every mapped Stave control evaluated clean.

### 164.312(e)(1): Transmission Security  [PASS]

- **Status:** compliant
- **Cross-reference:** SOC 2 CC6.6, NIST SC-8

_Implement technical security measures to guard against unauthorized access to electronic protected health information that is being transmitted over an electronic communications network._

**Stave coverage:** 57 control(s) (57 clean, 0 fired).

**Findings (this fixture):** none — every mapped Stave control evaluated clean.
