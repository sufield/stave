package asset

import "github.com/sufield/stave/internal/pkg/maps"

// Metadata provides a typed view over vendor-specific resource properties.
func (r Asset) Metadata() maps.Value {
	return maps.ParseMap(r.Properties)
}

// ARN returns the resource ARN when present in properties.
func (r Asset) ARN() string {
	return r.Metadata().GetPath("arn").String()
}

// Identities returns all identifiers a scope allowlist may match for this resource.
func (r Asset) Identities() []string {
	identities := []string{r.ID.String()}
	if arn := r.ARN(); arn != "" {
		identities = append(identities, arn)
	}
	return identities
}
