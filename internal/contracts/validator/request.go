package validator

// SchemaValidationRequest captures context for validating one schema payload.
type SchemaValidationRequest struct {
	Raw              []byte
	ActualVersion    string
	AcceptedVersions []string
	Kind             string
	IsYAML           bool
	PathPrefix       string
	Action           string
}
