package scrub

import (
	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/kernel"
)

// Scrubber sanitizes observation snapshots by removing or replacing
// sensitive property values according to configured scrub profiles.
// It delegates identifier sanitization to a kernel.Sanitizer.
type Scrubber struct {
	sanitizer    kernel.Sanitizer
	assetProfile Profile
	identProfile Profile
}

// NewScrubber creates a Scrubber with default asset and identity profiles.
// If s is nil, scrubbing is a no-op.
func NewScrubber(s kernel.Sanitizer) *Scrubber {
	return &Scrubber{
		sanitizer:    s,
		assetProfile: AssetProfile(),
		identProfile: IdentityProfile(),
	}
}

func (sc *Scrubber) enabled() bool {
	return sc != nil && sc.sanitizer != nil
}

// ScrubSnapshot returns a copy of the snapshot with sensitive properties removed.
// Retains boolean fields needed for evaluation, removes raw policy/ACL/tag data.
// Asset IDs, identity owner/purpose fields are also sanitized.
func (sc *Scrubber) ScrubSnapshot(s asset.Snapshot) asset.Snapshot {
	if !sc.enabled() {
		return s
	}
	out := asset.Snapshot{
		SchemaVersion: s.SchemaVersion,
		GeneratedBy:   s.GeneratedBy,
		CapturedAt:    s.CapturedAt,
	}

	out.Assets = make([]asset.Asset, len(s.Assets))
	for i, res := range s.Assets {
		out.Assets[i] = sc.scrubAsset(res)
	}

	if len(s.Identities) > 0 {
		out.Identities = make([]asset.CloudIdentity, len(s.Identities))
		for i, id := range s.Identities {
			out.Identities[i] = sc.scrubIdentity(id)
		}
	}

	return out
}

func (sc *Scrubber) scrubAsset(res asset.Asset) asset.Asset {
	return asset.Asset{
		ID:         asset.ID(sc.sanitizer.ID(string(res.ID))),
		Type:       res.Type,
		Vendor:     res.Vendor,
		Source:     sc.scrubSource(res.Source),
		Properties: sc.ScrubMap(res.Properties, sc.assetProfile),
	}
}

func (sc *Scrubber) scrubIdentity(id asset.CloudIdentity) asset.CloudIdentity {
	return asset.CloudIdentity{
		ID:         asset.ID(sc.sanitizer.ID(string(id.ID))),
		Type:       id.Type,
		Vendor:     id.Vendor,
		Source:     sc.scrubSource(id.Source),
		Properties: sc.ScrubMap(id.Properties, sc.identProfile),
	}
}

func (sc *Scrubber) scrubSource(s *asset.SourceRef) *asset.SourceRef {
	if s == nil {
		return nil
	}
	return &asset.SourceRef{
		File: sc.sanitizer.Path(s.File),
		Line: s.Line,
	}
}

// ScrubMap returns a deep copy of a properties map with keys removed or
// sanitized according to profile. Nested maps are recursed.
func (sc *Scrubber) ScrubMap(props map[string]any, profile Profile) map[string]any {
	if props == nil {
		return nil
	}
	out := make(map[string]any, len(props))
	for k, v := range props {
		if profile.ShouldRemove(k) {
			continue
		}
		if profile.ShouldSanitize(k) {
			out[k] = sc.sanitizeValue(v)
			continue
		}
		if nested, ok := v.(map[string]any); ok {
			out[k] = sc.ScrubMap(nested, profile)
			continue
		}
		out[k] = v
	}
	return out
}

func (sc *Scrubber) sanitizeValue(v any) string {
	s, ok := v.(string)
	if !ok {
		return "[SANITIZED]"
	}
	return sc.sanitizer.ID(s)
}
