# Results

Completed scorecards from specific tools run against the SadCloud
environment.

## Reference

`stave.csv` is the first completed scorecard. It demonstrates what a
filled-in result looks like and provides a baseline for comparison.

## Contributing Your Results

If you'd like to share your evaluation results publicly:

1. Copy `../scorecard/template.csv` to `results/<tool-name>.csv`
2. Fill in your tool's findings
3. Add a header comment with tool name, version, and scan date:
   ```csv
   # Tool: <name> v<version>
   # Date: YYYY-MM-DD
   # Environment: SadCloud (nccgroup/sadcloud master)
   ```
4. Submit a PR

Contributing is optional. Your results are yours by default.

## Interpretation

Results are point-in-time snapshots, not permanent rankings. A tool's
score depends on:

- Tool version at the time of the scan
- SadCloud Terraform version
- AWS environment state
- Whether all SadCloud modules deployed successfully

Compare results only when they were run against the same deployment.
