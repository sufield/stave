package terraform

// State collects S3 resource fragments extracted from Terraform resources.
type State struct {
	Buckets     map[string]*Bucket
	Policies    map[string]string
	ACLs        map[string][]ACLGrant
	PABs        map[string]*PublicAccessBlock
	Encryptions map[string]*EncryptionConfig
	Versionings map[string]*VersioningConfig
	Loggings    map[string]*LoggingConfig
	Lifecycles  map[string]*LifecycleConfig
	ObjectLocks map[string]*ObjectLockConfig
	AccountPAB  *PublicAccessBlock
}

func NewState() *State {
	return &State{
		Buckets:     make(map[string]*Bucket),
		Policies:    make(map[string]string),
		ACLs:        make(map[string][]ACLGrant),
		PABs:        make(map[string]*PublicAccessBlock),
		Encryptions: make(map[string]*EncryptionConfig),
		Versionings: make(map[string]*VersioningConfig),
		Loggings:    make(map[string]*LoggingConfig),
		Lifecycles:  make(map[string]*LifecycleConfig),
		ObjectLocks: make(map[string]*ObjectLockConfig),
	}
}

// HydrateBuckets merges collected sub-resource fragments into canonical bucket state.
func (s *State) HydrateBuckets() {
	for name, bucket := range s.Buckets {
		bucket.PolicyJSON = s.Policies[name]
		bucket.ACLGrants = s.ACLs[name]
		bucket.PublicAccessBlock = s.PABs[name]
		bucket.Encryption = s.Encryptions[name]
		bucket.Versioning = s.Versionings[name]
		bucket.Logging = s.Loggings[name]
		bucket.Lifecycle = s.Lifecycles[name]
		bucket.ObjectLock = s.ObjectLocks[name]
	}
}

// SetObjectLock merges object-lock fragments for a bucket.
func (s *State) SetObjectLock(bucket string, olc *ObjectLockConfig) {
	if olc == nil || bucket == "" {
		return
	}
	existing, ok := s.ObjectLocks[bucket]
	if !ok {
		s.ObjectLocks[bucket] = olc
		return
	}
	if olc.Mode != "" {
		existing.Mode = olc.Mode
	}
	if olc.RetentionDays > 0 {
		existing.RetentionDays = olc.RetentionDays
	}
	if olc.Enabled {
		existing.Enabled = true
	}
}
