package sanitize

import "github.com/sufield/stave/internal/domain/asset"

// ScrubConfig defines which property keys to remove or sanitize during scrubbing.
type ScrubConfig struct {
	RemovedKeys   map[string]struct{}
	SanitizedKeys map[string]struct{}
}

// DefaultResourceScrub is the default scrub config for resource properties.
// Sensitive keys (tags, policy, ACL) are removed; identifying keys (bucket_name,
// arn) are replaced with deterministic tokens.
var DefaultResourceScrub = ScrubConfig{
	RemovedKeys: map[string]struct{}{
		"tags":                     {},
		"policy":                   {},
		"policy_json":              {},
		"policy_public_statements": {},
		"acl_grants":               {},
		"acl_public_grantees":      {},
	},
	SanitizedKeys: map[string]struct{}{
		"bucket_name": {},
		"arn":         {},
	},
}

// DefaultIdentityScrub is the default scrub config for identity properties.
var DefaultIdentityScrub = ScrubConfig{
	RemovedKeys: map[string]struct{}{
		"owner":   {},
		"purpose": {},
	},
}

// ScrubSnapshot returns a copy of the snapshot with sensitive properties removed.
// Retains boolean fields needed for evaluation, removes raw policy/ACL/tag data.
// Resource IDs, identity owner/purpose fields are also sanitized.
func (r *Sanitizer) ScrubSnapshot(s asset.Snapshot) asset.Snapshot {
	if !r.enabled() {
		return s
	}
	out := asset.Snapshot{
		SchemaVersion: s.SchemaVersion,
		GeneratedBy:   s.GeneratedBy,
		CapturedAt:    s.CapturedAt,
	}

	out.Resources = make([]asset.Asset, len(s.Resources))
	for i, res := range s.Resources {
		out.Resources[i] = r.scrubResource(res)
	}

	if len(s.Identities) > 0 {
		out.Identities = make([]asset.CloudIdentity, len(s.Identities))
		for i, id := range s.Identities {
			out.Identities[i] = r.scrubIdentity(id)
		}
	}

	return out
}

func (r *Sanitizer) scrubResource(res asset.Asset) asset.Asset {
	return asset.Asset{
		ID:         r.Asset(res.ID),
		Type:       res.Type,
		Vendor:     res.Vendor,
		Source:     r.scrubSource(res.Source),
		Properties: r.ScrubMap(res.Properties, r.resourceScrub),
	}
}

func (r *Sanitizer) scrubIdentity(id asset.CloudIdentity) asset.CloudIdentity {
	return asset.CloudIdentity{
		ID:         r.Asset(id.ID),
		Type:       id.Type,
		Vendor:     id.Vendor,
		Source:     r.scrubSource(id.Source),
		Properties: r.ScrubMap(id.Properties, r.identityScrub),
	}
}

func (r *Sanitizer) scrubSource(s *asset.SourceRef) *asset.SourceRef {
	if s == nil {
		return nil
	}
	return &asset.SourceRef{
		File: r.Path(s.File),
		Line: s.Line,
	}
}

// ScrubMap returns a deep copy of a properties map with keys removed or
// sanitized according to cfg. Nested maps are recursed.
func (r *Sanitizer) ScrubMap(props map[string]any, cfg ScrubConfig) map[string]any {
	if props == nil {
		return nil
	}
	out := make(map[string]any, len(props))
	for k, v := range props {
		if _, ok := cfg.RemovedKeys[k]; ok {
			continue
		}
		if _, ok := cfg.SanitizedKeys[k]; ok {
			out[k] = r.redactValue(v)
			continue
		}
		if nested, ok := v.(map[string]any); ok {
			out[k] = r.ScrubMap(nested, cfg)
			continue
		}
		out[k] = v
	}
	return out
}

func (r *Sanitizer) redactValue(v any) string {
	s, ok := v.(string)
	if !ok {
		return "[SANITIZED]"
	}
	return r.sanitizeAssetID(s)
}
