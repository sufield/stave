package evidence

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	coreevidence "github.com/sufield/stave/internal/core/evidence"
	"gopkg.in/yaml.v3"
)

//go:embed embedded/profiles/*.yaml
var profilesFS embed.FS

// yamlProfile is the wire-format representation of a framework profile.
type yamlProfile struct {
	ID           string            `yaml:"id"`
	Name         string            `yaml:"name"`
	Version      string            `yaml:"version"`
	Description  string            `yaml:"description"`
	FrameworkKey string            `yaml:"framework_key"`
	Requirements []yamlRequirement `yaml:"requirements"`
}

type yamlRequirement struct {
	ID            string   `yaml:"id"`
	Description   string   `yaml:"description"`
	Section       string   `yaml:"section"`
	Controls      []string `yaml:"controls"`
	PassThreshold string   `yaml:"pass_threshold"`
}

// LoadEmbeddedProfiles loads all framework profiles from the embedded FS.
func LoadEmbeddedProfiles() ([]*coreevidence.FrameworkProfile, error) {
	var profiles []*coreevidence.FrameworkProfile

	err := fs.WalkDir(profilesFS, "embedded/profiles", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".yaml") {
			return nil
		}
		data, readErr := profilesFS.ReadFile(path)
		if readErr != nil {
			return fmt.Errorf("read %s: %w", path, readErr)
		}
		p, parseErr := parseProfile(data, filepath.Base(path))
		if parseErr != nil {
			return fmt.Errorf("parse %s: %w", path, parseErr)
		}
		profiles = append(profiles, p)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return profiles, nil
}

// LoadProfile loads a single framework profile by ID.
func LoadProfile(id string) (*coreevidence.FrameworkProfile, error) {
	profiles, err := LoadEmbeddedProfiles()
	if err != nil {
		return nil, err
	}
	for _, p := range profiles {
		if p.ID == id {
			return p, nil
		}
	}
	return nil, fmt.Errorf("profile %q not found", id)
}

// LoadProfileFromFile loads a custom framework profile from a YAML file.
func LoadProfileFromFile(path string) (*coreevidence.FrameworkProfile, error) {
	data, err := os.ReadFile(path) //nolint:gosec // user-specified path
	if err != nil {
		return nil, fmt.Errorf("read profile %s: %w", path, err)
	}
	return parseProfile(data, filepath.Base(path))
}

func parseProfile(data []byte, filename string) (*coreevidence.FrameworkProfile, error) {
	var dto yamlProfile
	if err := yaml.Unmarshal(data, &dto); err != nil {
		return nil, fmt.Errorf("unmarshal %s: %w", filename, err)
	}
	if dto.ID == "" {
		return nil, fmt.Errorf("%s: missing required field 'id'", filename)
	}

	reqs := make([]coreevidence.Requirement, len(dto.Requirements))
	for i, r := range dto.Requirements {
		threshold, err := coreevidence.ParsePassThreshold(r.PassThreshold)
		if err != nil {
			return nil, fmt.Errorf("%s: requirement %q: %w", filename, r.ID, err)
		}
		reqs[i] = coreevidence.Requirement{
			ID:            r.ID,
			Description:   r.Description,
			Section:       r.Section,
			ControlIDs:    r.Controls,
			PassThreshold: threshold,
		}
	}

	return &coreevidence.FrameworkProfile{
		ID:           dto.ID,
		Name:         dto.Name,
		Version:      dto.Version,
		Description:  dto.Description,
		FrameworkKey: dto.FrameworkKey,
		Requirements: reqs,
	}, nil
}
