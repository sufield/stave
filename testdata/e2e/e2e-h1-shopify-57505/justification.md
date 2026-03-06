# Justification: Why CTL.S3.PUBLIC.LIST.002 Is Redundant

## Existing controls that cover public listing

| Control | What it checks | When it fires |
|-----------|---------------|---------------|
| **CTL.S3.PUBLIC.001** | `public_read OR public_list` | Any bucket with public read **or** public list — blanket ban, no exceptions |
| **CTL.S3.PUBLIC.006** | `latent_public_list == true` | Listing is currently blocked by PAB but would be exposed if PAB were removed |

## What the new control does

| Control | What it checks | When it fires |
|-----------|---------------|---------------|
| **CTL.S3.PUBLIC.LIST.002** | `public_list == true AND public_list_intended is missing/not "true"` | Listing is active but **not explicitly tagged as intended** |

## The overlap problem

CTL.S3.PUBLIC.001 already catches every bucket with `public_list=true` — unconditionally. The new control CTL.S3.PUBLIC.LIST.002 is strictly a subset of PUBLIC.001. Every bucket that triggers LIST.002 also triggers PUBLIC.001.

The new control's intent-tag concept (`public_list_intended`) would only be useful if PUBLIC.001 were softened to allow intentional public access — but currently PUBLIC.001 is a blanket ban. So LIST.002 is redundant: it adds a second finding for the same bucket without providing actionable differentiation.

The HackerOne #57505 scenario (public read intended, public list unintended) is already fully caught by PUBLIC.001.
