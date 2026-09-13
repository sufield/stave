package asset

// SnapshotReader provides read-only access to a point-in-time
// observation. Consumers that only query snapshot metadata and look
// up assets by ID depend on this interface instead of the concrete
// Snapshot struct, decoupling them from its storage layout.
type SnapshotReader interface {
	FindAsset(id string) (Asset, bool)
	HasTimestamp() bool
}

// ResourceMapper exposes an infrastructure component's properties as
// a flat key-value map suitable for predicate evaluation. Both Asset
// and CloudIdentity satisfy this interface.
type ResourceMapper interface {
	Map() map[string]any
}

var (
	_ SnapshotReader = (*Snapshot)(nil)
	_ ResourceMapper = Asset{}
	_ ResourceMapper = CloudIdentity{}
)
