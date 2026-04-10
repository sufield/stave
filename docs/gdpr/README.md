# GDPR Compliance Pack — Invariant Catalog

EU General Data Protection Regulation mapping for Stave. GDPR is
the most manual-heavy framework because it governs organizational
behavior (data subject rights, breach notification, DPIAs, processor
contracts) more than infrastructure configuration.

## Coverage

| File | GDPR Area | Total | Mapped | New | Manual |
|---|---|---|---|---|---|
| gdpr-art32-security.yaml | Art 32 — Security of Processing | 18 | 18 | 0 | 0 |
| gdpr-art25-privacy-design.yaml | Art 25 — Privacy by Design | 5 | 5 | 0 | 0 |
| gdpr-art30-accountability.yaml | Art 30 — Accountability | 7 | 5 | 0 | 2 |
| gdpr-art33-breach.yaml | Art 33/34 — Breach Notification | 5 | 2 | 0 | 3 |
| gdpr-art44-transfers.yaml | Chapter V — Data Transfers | 4 | 0 | 1 | 3 |
| gdpr-rights-process.yaml | Rights, DPIA, Processor | 10 | 0 | 0 | 10 |
| **Total** | | **49** | **30** | **1** | **18** |

## Why GDPR Is Mostly Manual

GDPR is a privacy regulation, not a security benchmark. While it
requires "appropriate technical measures" (covered by encryption,
access control, and logging controls), its core requirements are:

- **Data subject rights** (erasure, access, portability) — application-level
- **Breach notification** (72-hour rule) — organizational process
- **DPIAs** — risk assessment documents
- **Processor obligations** — contractual (DPA, sub-processors, audits)
- **Data transfers** — legal mechanisms (SCCs, adequacy decisions)

Stave's technical controls satisfy Article 32 (security of processing)
completely. The remaining articles require organizational evidence.
