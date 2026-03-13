package terraform

import s3storage "github.com/sufield/stave/internal/adapters/input/extract/s3/storage"

// State collects S3 resource fragments extracted from Terraform resources.
type State struct {
	Buckets     map[string]*Bucket
	Policies    map[string]string
	ACLs        map[string][]ACLGrant
	PABs        map[string]*s3storage.PublicAccessBlock
	Encryptions map[string]*s3storage.EncryptionConfig
	Versionings map[string]*s3storage.VersioningConfig
	Loggings    map[string]*s3storage.LoggingConfig
	Lifecycles  map[string]*s3storage.LifecycleConfig
	ObjectLocks map[string]*s3storage.ObjectLockConfig
	AccountPAB  *s3storage.PublicAccessBlock
}

func NewState() *State {
	return &State{
		Buckets:     make(map[string]*Bucket),
		Policies:    make(map[string]string),
		ACLs:        make(map[string][]ACLGrant),
		PABs:        make(map[string]*s3storage.PublicAccessBlock),
		Encryptions: make(map[string]*s3storage.EncryptionConfig),
		Versionings: make(map[string]*s3storage.VersioningConfig),
		Loggings:    make(map[string]*s3storage.LoggingConfig),
		Lifecycles:  make(map[string]*s3storage.LifecycleConfig),
		ObjectLocks: make(map[string]*s3storage.ObjectLockConfig),
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
func (s *State) SetObjectLock(bucket string, olc *s3storage.ObjectLockConfig) {
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
