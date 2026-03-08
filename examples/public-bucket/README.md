# Example: Public Bucket Detection

Demonstrates detecting an S3 bucket with public read access using `CTL.S3.PUBLIC.001`.

## Scenario

A bucket named `example-public-bucket` has `public_read: true` in both snapshots (24 hours apart). The control flags any bucket with public read or list access. With `--max-unsafe 12h`, the 24-hour unsafe duration exceeds the threshold.

## Files

```
public-bucket/
├── observations/
│   ├── 2026-01-01T000000Z.json   # Snapshot 1: public_read=true
│   └── 2026-01-02T000000Z.json   # Snapshot 2: public_read=true
├── controls/
│   └── CTL.S3.PUBLIC.001.yaml       # No Public S3 Buckets
└── README.md
```

## Run

```bash
cd stave

./stave plan \
  --controls examples/public-bucket/controls \
  --observations examples/public-bucket/observations \
  --max-unsafe 12h \
  --now 2026-01-02T00:00:00Z

./stave apply \
  --controls examples/public-bucket/controls \
  --observations examples/public-bucket/observations \
  --max-unsafe 12h \
  --now 2026-01-02T00:00:00Z \
  --allow-unknown-input
```

## Expected Result

- **Exit code:** 3 (violations found)
- **Finding:** `CTL.S3.PUBLIC.001` on `res:aws:s3:bucket:example-public-bucket`
- **Reason:** `properties.storage.visibility.public_read` is `true`
