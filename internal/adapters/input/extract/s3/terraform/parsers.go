package terraform

import "strings"

const (
	cannedACLPublicRead      = "public-read"
	cannedACLPublicReadWrite = "public-read-write"
	cannedACLAuthenticated   = "authenticated-read"
)

func getBucketName(resName string, picker *MapPicker) string {
	if picker == nil {
		return resName
	}
	if name := picker.String("bucket"); name != "" {
		return name
	}
	return resName
}

// extractEncryptionConfig extracts encryption configuration from Terraform values.
func extractEncryptionConfig(values map[string]any) *EncryptionConfig {
	p := newMapPicker(values)
	def := p.Dig("rule").Dig("apply_server_side_encryption_by_default")
	return &EncryptionConfig{
		Algorithm: def.String("sse_algorithm"),
		KMSKeyARN: def.String("kms_master_key_id"),
	}
}

// extractVersioningConfig extracts versioning configuration from Terraform values.
func extractVersioningConfig(values map[string]any) *VersioningConfig {
	p := newMapPicker(values)
	config := p.Dig("versioning_configuration")
	return &VersioningConfig{
		Status:    config.String("status"),
		MFADelete: config.String("mfa_delete"),
	}
}

// extractLoggingConfig extracts logging configuration from Terraform values.
func extractLoggingConfig(values map[string]any) *LoggingConfig {
	return &LoggingConfig{
		TargetBucket: getString(values, "target_bucket"),
		TargetPrefix: getString(values, "target_prefix"),
	}
}

// extractLifecycleConfig extracts lifecycle configuration from Terraform values.
func extractLifecycleConfig(values map[string]any) *LifecycleConfig {
	lc := &LifecycleConfig{}
	rules, _ := values["rule"].([]any)
	minExpSet := false

	for _, r := range rules {
		rule, ok := r.(map[string]any)
		if !ok {
			continue
		}
		if getString(rule, "status") != "Enabled" {
			continue
		}
		lc.RulesConfigured = true
		lc.RuleCount++
		p := newMapPicker(rule)

		applyExpirationRule(p, lc, &minExpSet)

		if !p.Dig("transition").IsEmpty() {
			lc.HasTransition = true
		}
		if !p.Dig("noncurrent_version_expiration").IsEmpty() {
			lc.HasNoncurrentVersionExpiration = true
		}
	}
	return lc
}

func applyExpirationRule(p *MapPicker, lc *LifecycleConfig, minExpSet *bool) {
	exp := p.Dig("expiration")
	if exp.IsEmpty() {
		return
	}
	days := exp.Int("days")
	if days <= 0 {
		return
	}
	lc.HasExpiration = true
	if !*minExpSet || days < lc.MinExpirationDays {
		lc.MinExpirationDays = days
		*minExpSet = true
	}
}

// extractObjectLockConfig extracts object lock configuration from Terraform values.
func extractObjectLockConfig(values map[string]any) *ObjectLockConfig {
	p := newMapPicker(values)
	ret := p.Dig("rule").Dig("default_retention")
	if ret.IsEmpty() {
		return &ObjectLockConfig{}
	}

	olc := &ObjectLockConfig{Mode: ret.String("mode")}
	if days := ret.Int("days"); days > 0 {
		olc.RetentionDays = days
	} else if years := ret.Int("years"); years > 0 {
		olc.RetentionDays = years * 365
	}
	return olc
}

func extractACLGrants(values map[string]any) []ACLGrant {
	var grants []ACLGrant

	grants = append(grants, extractACLPolicyGrants(values)...)
	grants = append(grants, extractCannedACLGrants(values)...)
	return grants
}

func extractACLPolicyGrants(values map[string]any) []ACLGrant {
	p := newMapPicker(values)
	grantList := p.Dig("access_control_policy").AnySlice("grant")
	if len(grantList) == 0 {
		return nil
	}

	grants := make([]ACLGrant, 0, len(grantList))
	for _, entry := range grantList {
		grant, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		gp := newMapPicker(grant)
		grantee := gp.Dig("grantee")
		target := grantee.String("uri")
		if target == "" {
			target = grantee.String("id")
		}
		grants = append(grants, ACLGrant{
			Permission: gp.String("permission"),
			Grantee:    target,
		})
	}
	return grants
}

func extractCannedACLGrants(values map[string]any) []ACLGrant {
	acl := strings.ToLower(getString(values, "acl"))
	switch acl {
	case cannedACLPublicRead:
		return []ACLGrant{{Grantee: AllUsersGranteeURI, Permission: permRead}}
	case cannedACLPublicReadWrite:
		return []ACLGrant{
			{Grantee: AllUsersGranteeURI, Permission: permRead},
			{Grantee: AllUsersGranteeURI, Permission: permWrite},
		}
	case cannedACLAuthenticated:
		return []ACLGrant{{Grantee: AuthenticatedUsersGranteeURI, Permission: permRead}}
	default:
		return nil
	}
}
