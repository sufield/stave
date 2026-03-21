package asset

import "github.com/sufield/stave/pkg/alpha/domain/maps"

// Metadata provides a typed view over vendor-specific asset properties.
func (r Asset) Metadata() maps.Value {
	return maps.ParseMap(r.Properties)
}

// ExternalID returns a secondary identifier provided by the infrastructure.
func (r Asset) ExternalID() string {
	return r.Metadata().GetPath("external_id").String()
}

// Identities returns all identifiers a scope allowlist may match for this asset.
func (r Asset) Identities() []string {
	identities := []string{r.ID.String()}
	if ext := r.ExternalID(); ext != "" {
		identities = append(identities, ext)
	}
	return identities
}
