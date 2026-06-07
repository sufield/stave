package stave

import "testing"

func TestListEmbeddedProfiles_NonEmpty(t *testing.T) {
	profiles, err := ListEmbeddedProfiles()
	if err != nil {
		t.Fatalf("ListEmbeddedProfiles: %v", err)
	}
	if len(profiles) == 0 {
		t.Fatal("expected at least one embedded profile")
	}
	for _, p := range profiles {
		if p.ID == "" {
			t.Errorf("profile has empty ID: %+v", p)
		}
	}
}

func TestLoadProfile_MissingFileErrors(t *testing.T) {
	if _, err := LoadProfile("/nonexistent/profile.yaml"); err == nil {
		t.Fatal("expected an error loading a missing profile file")
	}
}
