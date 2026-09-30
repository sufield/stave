package schema

import (
	"maps"

	"github.com/sufield/stave/internal/core/kernel"
)

func (r *schemaRegistry) remove(t kernel.AssetType) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.entries, t)
}

func (r *schemaRegistry) all() map[kernel.AssetType]Schema {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make(map[kernel.AssetType]Schema, len(r.entries))
	maps.Copy(out, r.entries)
	return out
}
