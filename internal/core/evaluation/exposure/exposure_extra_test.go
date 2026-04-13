package exposure

import "testing"

func TestValidateControlIDs(t *testing.T) {
	// All built-in exposure control IDs must conform to the required format.
	if err := ValidateControlIDs(); err != nil {
		t.Fatalf("ValidateControlIDs() error: %v", err)
	}
}

func TestResourceExposure_IsPubliclyExposed_NilReceiver(t *testing.T) {
	var e *ResourceExposure
	if e.IsPubliclyExposed() {
		t.Error("nil receiver should return false")
	}
}

func TestResourceExposure_IsPubliclyExposed_AllFalse(t *testing.T) {
	e := &ResourceExposure{}
	if e.IsPubliclyExposed() {
		t.Error("zero-value ResourceExposure should not be publicly exposed")
	}
}

func TestResourceExposure_IsPubliclyExposed_PublicRead(t *testing.T) {
	e := &ResourceExposure{PublicRead: true}
	if !e.IsPubliclyExposed() {
		t.Error("PublicRead=true should be publicly exposed")
	}
}

func TestResourceExposure_IsPubliclyExposed_PublicWrite(t *testing.T) {
	e := &ResourceExposure{PublicWrite: true}
	if !e.IsPubliclyExposed() {
		t.Error("PublicWrite=true should be publicly exposed")
	}
}

func TestResourceExposure_IsPubliclyExposed_PublicAdmin(t *testing.T) {
	e := &ResourceExposure{PublicAdmin: true}
	if !e.IsPubliclyExposed() {
		t.Error("PublicAdmin=true should be publicly exposed")
	}
}

func TestResourceExposure_IsPubliclyExposed_PublicList(t *testing.T) {
	e := &ResourceExposure{PublicList: true}
	if !e.IsPubliclyExposed() {
		t.Error("PublicList=true should be publicly exposed")
	}
}

func TestResourceExposure_IsPubliclyExposed_OnlyLatent(t *testing.T) {
	// Latent exposure (suppressed by guardrail) should NOT count as publicly exposed.
	e := &ResourceExposure{LatentPublicRead: true, LatentPublicList: true}
	if e.IsPubliclyExposed() {
		t.Error("latent-only exposure should not be counted as publicly exposed")
	}
}

func TestResourceExposure_IsPubliclyExposed_OnlyAuthenticated(t *testing.T) {
	// Authenticated-only access should NOT count as publicly exposed.
	e := &ResourceExposure{AuthenticatedRead: true, AuthenticatedWrite: true}
	if e.IsPubliclyExposed() {
		t.Error("authenticated-only access should not be counted as publicly exposed")
	}
}
