package capabilities

import (
	"io/fs"
	"slices"
	"strings"

	"github.com/sufield/stave/internal/builtin/pack"
	"github.com/sufield/stave/internal/compliance"
	"github.com/sufield/stave/internal/controldata"
	"github.com/sufield/stave/internal/core/kernel"
	"gopkg.in/yaml.v3"
)

// featureManifest holds pre-sorted, immutable data describing the tool's
// supported security frameworks and cloud connectors.
type featureManifest struct {
	observationSchemas []string
	policySchemas      []string
	connectors         []ConnectorSupport
	connectorIndex     map[kernel.ObservationSourceType]struct{}
	policyLibrary      []PolicyPack
	complianceFeatures ComplianceSupport
	riskFeatures       RiskReasoning
}

func (m *featureManifest) observationSupport() ObservationSupport {
	return ObservationSupport{Schemas: m.observationSchemas}
}

func (m *featureManifest) policySupport() PolicySupport {
	return PolicySupport{Schemas: m.policySchemas}
}

func (m *featureManifest) ingressSupport() DataIngress {
	return DataIngress{Connectors: m.connectors}
}

func (m *featureManifest) libraryWithVersion(version string) []PolicyPack {
	result := slices.Clone(m.policyLibrary)
	for i := range result {
		result[i].Version = version
	}
	return result
}

func (m *featureManifest) riskReasoning() RiskReasoning {
	return m.riskFeatures
}

func (m *featureManifest) complianceSupport() ComplianceSupport {
	return ComplianceSupport{
		Enabled:            m.complianceFeatures.Enabled,
		ReportFormats:      slices.Clone(m.complianceFeatures.ReportFormats),
		SLAThresholds:      slices.Clone(m.complianceFeatures.SLAThresholds),
		SecurityFrameworks: slices.Clone(m.complianceFeatures.SecurityFrameworks),
	}
}

// Manifest is the global feature manifest for this version of Stave.
var Manifest = newFeatureManifest()

func newFeatureManifest() *featureManifest {
	observationSchemas := []string{string(kernel.SchemaObservation)}
	slices.Sort(observationSchemas)

	policySchemas := []string{string(kernel.SchemaControl)}
	slices.Sort(policySchemas)

	connectors := []ConnectorSupport{
		{Type: kernel.SourceTypeAWSS3Snapshot, Description: "AWS S3 Resource State (JSON Snapshots)"},
		{Type: "aws-iam-snapshot", Description: "AWS IAM Identity Configuration"},
		{Type: "aws-opensearch-snapshot", Description: "AWS OpenSearch Domain Configuration"},
		{Type: "aws-vpc-snapshot", Description: "AWS VPC Network Configuration"},
		{Type: "aws-rds-snapshot", Description: "AWS RDS Database Configuration"},
		{Type: "aws-ecr-snapshot", Description: "AWS ECR Container Registry"},
		{Type: "aws-waf-snapshot", Description: "AWS WAF Web ACL Configuration"},
		{Type: "gcp-gcs-snapshot", Description: "GCP Cloud Storage Bucket Configuration"},
		{Type: "dns-record-snapshot", Description: "DNS Record Configuration (vendor-agnostic)"},
		{Type: "kubernetes.rbac", Description: "Kubernetes RBAC Configuration"},
		{Type: "microsoft.ad", Description: "Active Directory / LDAP Configuration"},
		{Type: "vmware.vsphere", Description: "VMware vSphere ESXi and VM Configuration"},
		{Type: "cisco.ios", Description: "Cisco IOS Network Device Configuration"},
	}

	connectorIndex := make(map[kernel.ObservationSourceType]struct{}, len(connectors))
	for _, c := range connectors {
		connectorIndex[c.Type] = struct{}{}
	}

	packReg, err := pack.NewEmbeddedRegistry()
	if err != nil {
		panic("capabilities: failed to load embedded policy library: " + err.Error())
	}
	discovered, err := packReg.ListPacks()
	if err != nil {
		// newFeatureManifest is a constructor with no error return —
		// the embedded registry is built at compile time, so a
		// ListPacks invariant violation is a build-time bug that
		// should crash startup loudly. Consistent with the
		// NewEmbeddedRegistry panic above.
		panic("capabilities: failed to enumerate embedded policy library: " + err.Error())
	}
	library := make([]PolicyPack, len(discovered))
	for i, p := range discovered {
		library[i] = PolicyPack{
			Name:        p.Name,
			Description: p.Description,
		}
	}

	complianceFeatures := ComplianceSupport{
		Enabled:            true,
		ReportFormats:      []string{"text", "json", "sarif", "markdown", "oscal", "graph-json", "stix", "jsonld", "graphml", "openmetrics"},
		SLAThresholds:      []string{"critical", "high", "medium", "low", "none"},
		SecurityFrameworks: compliance.FrameworkStrings(compliance.SupportedFrameworks()),
	}

	attackStages := deriveAttackStages()

	return &featureManifest{
		observationSchemas: observationSchemas,
		policySchemas:      policySchemas,
		connectors:         connectors,
		connectorIndex:     connectorIndex,
		policyLibrary:      library,
		complianceFeatures: complianceFeatures,
		riskFeatures: RiskReasoning{
			Enabled:      true,
			AttackStages: attackStages,
			ScoringModel: "environmental × chain_escalation × blast_multiplier",
		},
	}
}

// controlParams is a minimal struct for extracting attack_stage from
// control YAML without importing the adapters layer.
type controlParams struct {
	Params struct {
		AttackStage string `yaml:"attack_stage"`
	} `yaml:"params"`
}

// deriveAttackStages scans the embedded control YAMLs and returns the
// sorted, deduplicated set of attack_stage values actually used.
func deriveAttackStages() []string {
	seen := make(map[string]struct{})
	_ = fs.WalkDir(controldata.FS, "embedded", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".yaml") {
			return nil
		}
		data, readErr := fs.ReadFile(controldata.FS, path)
		if readErr != nil {
			return nil //nolint:nilerr // skip unreadable
		}
		var cp controlParams
		if yamlErr := yaml.Unmarshal(data, &cp); yamlErr != nil {
			return nil //nolint:nilerr // skip unparseable
		}
		if cp.Params.AttackStage != "" {
			seen[cp.Params.AttackStage] = struct{}{}
		}
		return nil
	})
	stages := make([]string, 0, len(seen))
	for s := range seen {
		stages = append(stages, s)
	}
	slices.Sort(stages)
	return stages
}
