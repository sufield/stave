# Example: Missing Public Access Block

Demonstrates detecting an S3 bucket without Public Access Block enabled using `CTL.S3.CONTROLS.001`.

## Scenario

A bucket named `example-no-pab` has `public_access_fully_blocked: false` in both snapshots (24 hours apart). It is not currently public, but has no safety net against accidental public exposure from future policy or ACL changes. With `--max-unsafe 12h`, the 24-hour unsafe duration exceeds the threshold.

## Files

```
missing-pab/
├── observations/
│   ├── 2026-01-01T000000Z.json   # Snapshot 1: PAB disabled
│   └── 2026-01-02T000000Z.json   # Snapshot 2: PAB still disabled
├── controls/
│   └── CTL.S3.CONTROLS.001.yaml     # Public Access Block Must Be Enabled
└── README.md
```

## Run

```bash
cd stave

./stave plan \
  --controls examples/missing-pab/controls \
  --observations examples/missing-pab/observations \
  --max-unsafe 12h \
  --now 2026-01-02T00:00:00Z

./stave apply \
  --controls examples/missing-pab/controls \
  --observations examples/missing-pab/observations \
  --max-unsafe 12h \
  --now 2026-01-02T00:00:00Z \
  --allow-unknown-input
```

## Expected Result

- **Exit code:** 3 (violations found)
- **Finding:** `CTL.S3.CONTROLS.001` on `res:aws:s3:bucket:example-no-pab`
- **Reason:** `properties.storage.controls.public_access_fully_blocked` is `false`
