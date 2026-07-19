// Package diff provides risk direction classification for configuration
// changes. It determines whether a property change increases or decreases
// risk by consulting the known polarity of boolean observation fields.
package diff

// RiskDirection classifies a property change's effect on security posture.
type RiskDirection int

const (
	RiskNeutral    RiskDirection = iota // change does not affect risk (non-boolean or unknown field)
	RiskIncreasing                      // was safe, now unsafe
	RiskDecreasing                      // was unsafe, now safe
)

func (d RiskDirection) String() string {
	switch d {
	case RiskIncreasing:
		return "increasing"
	case RiskDecreasing:
		return "decreasing"
	default:
		return "neutral"
	}
}

// Polarity describes whether true means safe or unsafe for a boolean field.
type Polarity int

const (
	TrueIsSafe   Polarity = iota // true = safe (e.g., is_encrypted, imdsv2_enforced)
	TrueIsUnsafe                 // true = unsafe (e.g., has_public_ip, public_read)
)

// fieldPolarity maps known boolean fields to their safety polarity.
// Fields prefixed with "denies_" are TrueIsSafe (a deny = protective).
var fieldPolarity = map[string]Polarity{
	// Protective booleans (true = safe)
	"is_encrypted":                        TrueIsSafe,
	"imdsv2_enforced":                     TrueIsSafe,
	"imdsv2_required":                     TrueIsSafe,
	"ssl_enforced":                        TrueIsSafe,
	"tls_enforced":                        TrueIsSafe,
	"https_enforced":                      TrueIsSafe,
	"mfa_enabled":                         TrueIsSafe,
	"account_public_access_fully_blocked": TrueIsSafe,
	"versioning_enabled":                  TrueIsSafe,
	"logging_enabled":                     TrueIsSafe,
	"rotation_enabled":                    TrueIsSafe,
	"backup_enabled":                      TrueIsSafe,
	"deletion_protection_enabled":         TrueIsSafe,
	"access_logging_enabled":              TrueIsSafe,
	"flow_logs_enabled":                   TrueIsSafe,
	"guard_duty_enabled":                  TrueIsSafe,
	"config_enabled":                      TrueIsSafe,
	"cloudtrail_enabled":                  TrueIsSafe,
	"waf_enabled":                         TrueIsSafe,
	"shield_enabled":                      TrueIsSafe,
	"private_access_enforced":             TrueIsSafe,
	"secure_transport_enforced":           TrueIsSafe,
	"cross_zone_load_balancing_enabled":   TrueIsSafe,
	"multi_az_enabled":                    TrueIsSafe,
	"auto_minor_version_upgrade_enabled":  TrueIsSafe,
	"enhanced_monitoring_enabled":         TrueIsSafe,
	"performance_insights_enabled":        TrueIsSafe,
	"point_in_time_recovery_enabled":      TrueIsSafe,
	"transit_encryption_enabled":          TrueIsSafe,
	"at_rest_encryption_enabled":          TrueIsSafe,
	"server_side_encryption_enabled":      TrueIsSafe,

	// Exposure booleans (true = unsafe)
	"has_public_ip":               TrueIsUnsafe,
	"public_read":                 TrueIsUnsafe,
	"public_write":                TrueIsUnsafe,
	"is_effectively_public":       TrueIsUnsafe,
	"has_admin_access":            TrueIsUnsafe,
	"is_dormant":                  TrueIsUnsafe,
	"is_orphan":                   TrueIsUnsafe,
	"has_wildcard_principal":      TrueIsUnsafe,
	"has_star_action":             TrueIsUnsafe,
	"allows_privilege_escalation": TrueIsUnsafe,
	"password_reuse_allowed":      TrueIsUnsafe,
	"root_access_key_active":      TrueIsUnsafe,
}

// ClassifyRisk determines whether a property change increases or
// decreases risk. Returns RiskNeutral for non-boolean fields or
// fields with unknown polarity.
func ClassifyRisk(field string, was, now any) RiskDirection {
	wasBool, wasOk := asBool(was)
	nowBool, nowOk := asBool(now)
	if !wasOk || !nowOk || wasBool == nowBool {
		return RiskNeutral
	}

	pol, known := fieldPolarity[field]
	if !known {
		pol, known = polarityByPrefix(field)
	}
	if !known {
		return RiskNeutral
	}

	switch pol {
	case TrueIsSafe:
		if wasBool && !nowBool {
			return RiskIncreasing // lost protection
		}
		return RiskDecreasing // gained protection
	case TrueIsUnsafe:
		if !wasBool && nowBool {
			return RiskIncreasing // gained exposure
		}
		return RiskDecreasing // lost exposure
	}
	return RiskNeutral
}

// polarityByPrefix handles field families like "denies_*" and "has_data_access_*".
func polarityByPrefix(field string) (Polarity, bool) {
	if len(field) > 7 && field[:7] == "denies_" {
		return TrueIsSafe, true
	}
	if len(field) > 15 && field[:15] == "has_credential_" {
		return TrueIsUnsafe, true
	}
	if len(field) > 16 && field[:16] == "has_data_access_" {
		return TrueIsUnsafe, true
	}
	return 0, false
}

func asBool(v any) (bool, bool) {
	b, ok := v.(bool)
	return b, ok
}
