package storage

type PABStatus struct {
	BlockPublicAcls       bool `json:"block_public_acls"`
	IgnorePublicAcls      bool `json:"ignore_public_acls"`
	BlockPublicPolicy     bool `json:"block_public_policy"`
	RestrictPublicBuckets bool `json:"restrict_public_buckets"`
}

type PublicAccessBlockModel struct {
	Account   *PABStatus `json:"account,omitempty"`
	Bucket    *PABStatus `json:"bucket,omitempty"`
	Effective PABStatus  `json:"effective"`
}

type S3Controls struct {
	PublicAccessFullyBlocked        bool                   `json:"public_access_fully_blocked"`
	AccountPublicAccessFullyBlocked bool                   `json:"account_public_access_fully_blocked"`
	PublicAccessBlockEffective      bool                   `json:"public_access_block_effective"`
	PolicyBlockEffective            bool                   `json:"public_access_policy_block_effective"`
	ACLBlockEffective               bool                   `json:"public_access_acl_block_effective"`
	PublicAccessBlock               PublicAccessBlockModel `json:"public_access_block"`
}

func NewPABStatus(p *PublicAccessBlock) *PABStatus {
	if p == nil {
		return nil
	}
	return &PABStatus{
		BlockPublicAcls:       p.BlockPublicAcls,
		IgnorePublicAcls:      p.IgnorePublicAcls,
		BlockPublicPolicy:     p.BlockPublicPolicy,
		RestrictPublicBuckets: p.RestrictPublicBuckets,
	}
}

func (p PABStatus) IsFullyBlocked() bool {
	return p.BlockPublicAcls &&
		p.IgnorePublicAcls &&
		p.BlockPublicPolicy &&
		p.RestrictPublicBuckets
}

func buildS3Controls(in BuildModelInput) S3Controls {
	effective := NewPABStatus(&in.EffectivePAB)
	controls := S3Controls{
		PublicAccessFullyBlocked:        false,
		AccountPublicAccessFullyBlocked: false,
		PublicAccessBlockEffective:      false,
		PolicyBlockEffective:            in.Visibility.IdentityExposureBlocked,
		ACLBlockEffective:               in.Visibility.ResourceExposureBlocked,
		PublicAccessBlock: PublicAccessBlockModel{
			Account: NewPABStatus(in.AccountPAB),
			Bucket:  NewPABStatus(in.Bucket.PublicAccessBlock),
		},
	}
	if effective != nil {
		controls.PublicAccessBlock.Effective = *effective
		controls.PublicAccessFullyBlocked = effective.IsFullyBlocked()
		controls.PublicAccessBlockEffective = controls.PublicAccessFullyBlocked
	}
	if account := controls.PublicAccessBlock.Account; account != nil {
		controls.AccountPublicAccessFullyBlocked = account.IsFullyBlocked()
	}
	return controls
}
