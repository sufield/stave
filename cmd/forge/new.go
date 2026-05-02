package forge

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/adapters/observations"
	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/predicate"

	stavecel "github.com/sufield/stave/internal/cel"
)

func newNewCmd() *cobra.Command {
	var nonInteractive bool
	var id, name, domain, severity, scopeTags, assetType string
	var kind, field, op, value, remediation, compliance, snapshot, out string

	cmd := &cobra.Command{
		Use:   "new",
		Short: "Interactive control authoring wizard",
		Long: `Create a new custom security control interactively. The wizard prompts
for control metadata, lets you browse property paths from a real snapshot,
and shows live CEL evaluation before writing files.

Use --non-interactive to accept all inputs from flags (equivalent to make forge).

Exit Codes:
  0   Control generated successfully
  2   Invalid input or missing required flags
  4   Internal error

Examples:
  stave forge new --snapshot obs.json

  stave forge new --non-interactive \
    --id CTL.S3.TAGS.001 \
    --name "S3 buckets must have team tag" \
    --field properties.storage.tags.team \
    --op missing \
    --severity high \
    --remediation "Add a team tag"`,
		Example: `  stave forge new --snapshot obs.json
  stave forge new --non-interactive --id CTL.S3.TAGS.001 --name "..." --field ... --remediation "..."`,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if nonInteractive {
				return runNonInteractive(cmd.Context(), cmd.OutOrStdout(), nonInteractiveOpts{
					ID: id, Name: name, Domain: domain, Severity: severity,
					ScopeTags: scopeTags, AssetType: assetType, Kind: kind,
					Field: field, Op: op, Value: value, Remediation: remediation,
					Compliance: compliance, Out: out,
				})
			}
			return runWizard(os.Stdin, cmd.OutOrStdout(), cmd, snapshot)
		},
	}

	cmd.Flags().BoolVar(&nonInteractive, "non-interactive", false, "accept all inputs from flags, skip wizard")
	cmd.Flags().StringVar(&snapshot, "snapshot", "", "snapshot for path discovery and live preview")
	cmd.Flags().StringVar(&id, "id", "", "control ID (e.g. CTL.S3.TAGS.001)")
	cmd.Flags().StringVar(&name, "name", "", "control name")
	cmd.Flags().StringVar(&domain, "domain", "exposure", "domain: exposure | identity | governance")
	cmd.Flags().StringVar(&severity, "severity", "high", "severity: critical | high | medium | low")
	cmd.Flags().StringVar(&scopeTags, "scope-tags", "aws", "comma-separated scope tags")
	cmd.Flags().StringVar(&assetType, "asset-type", "aws_s3_bucket", "asset type for fixtures")
	cmd.Flags().StringVar(&kind, "kind", "", "asset kind filter")
	cmd.Flags().StringVar(&field, "field", "", "predicate field path")
	cmd.Flags().StringVar(&op, "op", "eq", "predicate operator")
	cmd.Flags().StringVar(&value, "value", "true", "unsafe value")
	cmd.Flags().StringVar(&remediation, "remediation", "", "remediation action text")
	cmd.Flags().StringVar(&compliance, "compliance", "", "compliance refs (key=value,...)")
	cmd.Flags().StringVar(&out, "out", "testdata/e2e", "output base directory")

	return cmd
}

var (
	severityOptions = []string{"critical", "high", "medium", "low"}

	attackStageOptions = []string{
		"initial_access", "credential_access", "persistence",
		"privilege_escalation", "lateral_movement", "exfiltration",
		"detection_evasion", "resilience",
	}
	attackStageDescriptions = []string{
		"Attacker gaining first foothold",
		"Stealing or forging credentials",
		"Maintaining access after compromise",
		"Escalating to higher privileges",
		"Moving between systems",
		"Extracting data from environment",
		"Avoiding detection and monitoring",
		"Disrupting recovery and resilience",
	}

	operatorOptions = []string{"eq", "ne", "gt", "lt", "missing", "present", "contains"}

	supportedFrameworks = []string{
		"hipaa", "pci_dss_v4.0", "soc2", "fedramp_moderate",
		"nist_800_53_r5", "cis_aws_v3.0", "gdpr", "iso_27001_2022",
	}
)

func runWizard(in io.Reader, out io.Writer, cmd *cobra.Command, snapshotPath string) error {
	w := newWizard(in, out)

	fmt.Fprintln(out, "")
	fmt.Fprintln(out, "Stave Control Authoring Wizard")
	fmt.Fprintln(out, strings.Repeat("=", 40))
	fmt.Fprintln(out, "")

	// Load snapshot if provided.
	var snap *asset.Snapshot
	if snapshotPath != "" {
		snapshots, err := observations.LoadBundle(snapshotPath)
		if err != nil {
			fmt.Fprintf(out, "Warning: could not load snapshot: %v\n", err)
		} else if len(snapshots) > 0 {
			snap = &snapshots[len(snapshots)-1]
			fmt.Fprintf(out, "Loaded snapshot with %d assets.\n\n", len(snap.Assets))
		}
	}

	// Step 1: Asset type.
	fmt.Fprintln(out, "Step 1 of 11: Asset Type")
	assetTypes := knownAssetTypes
	if snap != nil {
		assetTypes = discoverAssetTypes(snap)
	}
	selectedType := w.selectOption("What type of asset does this control evaluate?", assetTypes)
	fmt.Fprintln(out, "")

	// Step 2: Control ID.
	fmt.Fprintln(out, "Step 2 of 11: Control ID")
	controlID := w.readControlID()
	fmt.Fprintln(out, "")

	// Step 3: Control name.
	fmt.Fprintln(out, "Step 3 of 11: Control Name")
	controlName := w.readLine("Control name (human-readable description):")
	if controlName == "" {
		controlName = controlID
	}
	fmt.Fprintln(out, "")

	// Step 4: Severity.
	fmt.Fprintln(out, "Step 4 of 11: Severity")
	selectedSeverity := w.selectOption("Severity:", severityOptions)
	fmt.Fprintln(out, "")

	// Step 5: Attack stage.
	fmt.Fprintln(out, "Step 5 of 11: Attack Stage")
	w.selectOptionWithDescriptions("Attack stage:", attackStageOptions, attackStageDescriptions)
	fmt.Fprintln(out, "")

	// Step 6: Property path.
	fmt.Fprintln(out, "Step 6 of 11: Property Path")
	var selectedField string
	if snap != nil {
		var pathsBuf bytes.Buffer
		if pathsErr := runPaths(&pathsBuf, snapshotPath, selectedType, ""); pathsErr != nil {
			// runPaths is informational here — surface the failure as a
			// hint instead of aborting the wizard. Without this, an
			// unreadable snapshot silently produced an empty path
			// suggestion list and the operator typed paths blind.
			fmt.Fprintf(out, "(could not enumerate paths: %v)\n", pathsErr)
		} else {
			fmt.Fprintln(out, pathsBuf.String())
		}
		fmt.Fprintln(out, "")
		selectedField = w.readLine("Enter the property path to evaluate:")
	} else {
		fmt.Fprintln(out, "No snapshot — enter property path manually.")
		selectedField = w.readLine("Property path (e.g. properties.storage.access.public_read):")
	}
	fmt.Fprintln(out, "")

	// Step 7: Predicate.
	fmt.Fprintln(out, "Step 7 of 11: Predicate")
	fmt.Fprintf(out, "Property: %s\n", selectedField)
	fmt.Fprintln(out, "The control FAILS when this predicate is TRUE.")
	selectedOp := w.selectOption("Operator:", operatorOptions)
	selectedValue := w.readLineDefault("Unsafe value:", "true")
	fmt.Fprintln(out, "")

	// Step 8: Live preview.
	if snap != nil {
		fmt.Fprintln(out, "Step 8 of 11: Live Preview")
		runLivePreview(out, snap, selectedType, selectedField, selectedOp, selectedValue)
		if !w.confirm("Is this the behavior you intended?") {
			selectedOp = w.selectOption("Operator:", operatorOptions)
			selectedValue = w.readLineDefault("Unsafe value:", selectedValue)
			runLivePreview(out, snap, selectedType, selectedField, selectedOp, selectedValue)
		}
		fmt.Fprintln(out, "")
	} else {
		fmt.Fprintln(out, "Step 8 of 11: Live Preview — skipped (no snapshot)")
		fmt.Fprintln(out, "")
	}

	// Step 9: Remediation.
	fmt.Fprintln(out, "Step 9 of 11: Remediation")
	selectedRemediation := w.readLine("Remediation message (what should the operator do?):")
	fmt.Fprintln(out, "")

	// Step 10: Compliance.
	fmt.Fprintln(out, "Step 10 of 11: Compliance Citations (optional)")
	fmt.Fprintf(out, "Supported: %s\n", strings.Join(supportedFrameworks, ", "))
	complianceStr := w.readLineDefault("Citations (framework=req, comma-separated, or blank):", "")
	fmt.Fprintln(out, "")

	// Step 11: Confirmation.
	fmt.Fprintln(out, "Step 11 of 11: Confirmation")
	fmt.Fprintln(out, strings.Repeat("-", 50))
	fmt.Fprintf(out, "ID:           %s\n", controlID)
	fmt.Fprintf(out, "Name:         %s\n", controlName)
	fmt.Fprintf(out, "Asset type:   %s\n", selectedType)
	fmt.Fprintf(out, "Severity:     %s\n", selectedSeverity)
	fmt.Fprintf(out, "Field:        %s\n", selectedField)
	fmt.Fprintf(out, "Operator:     %s\n", selectedOp)
	fmt.Fprintf(out, "Value:        %s\n", selectedValue)
	fmt.Fprintf(out, "Remediation:  %s\n", selectedRemediation)
	if complianceStr != "" {
		fmt.Fprintf(out, "Compliance:   %s\n", complianceStr)
	}
	fmt.Fprintln(out, strings.Repeat("-", 50))

	if !w.confirm("Generate?") {
		fmt.Fprintln(out, "Cancelled.")
		return nil
	}

	scopeTag := "aws"
	idParts := strings.Split(controlID, ".")
	if len(idParts) >= 2 {
		scopeTag = "aws," + strings.ToLower(idParts[1])
	}

	return runNonInteractive(cmd.Context(), out, nonInteractiveOpts{
		ID: controlID, Name: controlName, Domain: "exposure",
		Severity: selectedSeverity, ScopeTags: scopeTag,
		AssetType: selectedType, Field: selectedField,
		Op: selectedOp, Value: selectedValue,
		Remediation: selectedRemediation, Compliance: complianceStr,
		Out: "testdata/e2e",
	})
}

func runLivePreview(out io.Writer, snap *asset.Snapshot, assetType, field, op, value string) {
	celEval, err := stavecel.NewPredicateEval()
	if err != nil {
		fmt.Fprintf(out, "  CEL evaluator error: %v\n", err)
		return
	}
	ctl := policy.ControlDefinition{
		DSLVersion: "ctrl.v1",
		ID:         kernel.ControlID("CTL.FORGE.PREVIEW.000"),
		Name:       "Live Preview",
		Type:       policy.TypeUnsafeState,
		UnsafePredicate: policy.UnsafePredicate{
			All: []policy.PredicateRule{{
				Field: predicate.NewFieldPath(field),
				Op:    predicate.Operator(op),
				Value: policy.NewOperand(parseValue(value)),
			}},
		},
	}
	if err := ctl.Prepare(); err != nil {
		fmt.Fprintf(out, "  Predicate error: %v\n", err)
		return
	}
	var failCount, passCount int
	for i := range snap.Assets {
		a := &snap.Assets[i]
		if assetType != "" && string(a.Type) != assetType {
			continue
		}
		unsafe, evalErr := celEval(ctl, *a, nil)
		if evalErr != nil {
			continue
		}
		if unsafe {
			fmt.Fprintf(out, "  FAIL  %s\n", a.ID)
			failCount++
		} else {
			fmt.Fprintf(out, "  PASS  %s\n", a.ID)
			passCount++
		}
	}
	fmt.Fprintf(out, "\n%d FAIL  |  %d PASS\n\n", failCount, passCount)
}

var knownAssetTypes = []string{
	"aws_s3_bucket", "aws_iam_role", "aws_iam_user", "aws_ec2_instance",
	"aws_rds_instance", "aws_lambda_function", "aws_ecs_task_definition",
	"aws_eks_cluster", "aws_vpc_security_group", "aws_kms_key",
}

func discoverAssetTypes(snap *asset.Snapshot) []string {
	seen := make(map[string]bool)
	for _, a := range snap.Assets {
		seen[string(a.Type)] = true
	}
	var types []string
	for t := range seen {
		types = append(types, t)
	}
	if len(types) == 0 {
		return knownAssetTypes
	}
	return types
}
