package evidence

import (
	"embed"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	coreevidence "github.com/sufield/stave/internal/core/evidence"
	"github.com/sufield/stave/internal/platform/fsutil"
	"gopkg.in/yaml.v3"
)

//go:embed embedded/profiles/*.yaml
var profilesFS embed.FS

// yamlProfile is the wire-format representation of a framework profile.
// Supports both the original requirements-based format and the sections-based
// format used by custom compliance framework files.
type yamlProfile struct {
	SchemaVersion string            `yaml:"schema_version"`
	ID            string            `yaml:"id"`
	Name          string            `yaml:"name"`
	Version       string            `yaml:"version"`
	Description   string            `yaml:"description"`
	FrameworkKey  string            `yaml:"framework_key"`
	Extends       string            `yaml:"extends"`
	Requirements  []yamlRequirement `yaml:"requirements"`
	Sections      []yamlSection     `yaml:"sections"`
	SLADeadlines  *yamlSLADeadlines `yaml:"sla_deadlines"`
	EvidenceMeta  *yamlEvidenceMeta `yaml:"evidence_metadata"`
}

type yamlRequirement struct {
	ID            string   `yaml:"id"`
	Description   string   `yaml:"description"`
	Section       string   `yaml:"section"`
	Controls      []string `yaml:"controls"`
	PassThreshold string   `yaml:"pass_threshold"`
}

// yamlSection is the enhanced section-based format for custom profiles.
type yamlSection struct {
	ID               string                `yaml:"id"`
	Title            string                `yaml:"title"`
	Description      string                `yaml:"description"`
	Priority         string                `yaml:"priority"`
	RequiredControls []yamlRequiredControl `yaml:"required_controls"`
}

type yamlRequiredControl struct {
	ControlID string `yaml:"control_id"`
	Rationale string `yaml:"rationale"`
}

type yamlSLADeadlines struct {
	Critical string `yaml:"critical"`
	High     string `yaml:"high"`
	Medium   string `yaml:"medium"`
	Low      string `yaml:"low"`
}

type yamlEvidenceMeta struct {
	Regulation    string `yaml:"regulation"`
	EffectiveDate string `yaml:"effective_date"`
	Jurisdiction  string `yaml:"jurisdiction"`
	Contact       string `yaml:"contact"`
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
		return nil, fmt.Errorf("walk profiles: %w", err)
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
	data, err := fsutil.ReadFileLimited(path)
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

	// Convert requirements from either format.
	var reqs []coreevidence.Requirement

	// Original format: requirements[]
	for _, r := range dto.Requirements {
		threshold, err := coreevidence.ParsePassThreshold(r.PassThreshold)
		if err != nil {
			return nil, fmt.Errorf("%s: requirement %q: %w", filename, r.ID, err)
		}
		reqs = append(reqs, coreevidence.Requirement{
			ID:            r.ID,
			Description:   r.Description,
			Section:       r.Section,
			ControlIDs:    r.Controls,
			PassThreshold: threshold,
		})
	}

	// Enhanced format: sections[] with required_controls[]
	for _, s := range dto.Sections {
		var controlIDs []string
		for _, rc := range s.RequiredControls {
			controlIDs = append(controlIDs, rc.ControlID)
		}
		reqs = append(reqs, coreevidence.Requirement{
			ID:            s.ID,
			Description:   s.Title,
			Section:       s.ID,
			ControlIDs:    controlIDs,
			PassThreshold: coreevidence.PassThreshold{Mode: coreevidence.ThresholdAll},
		})
	}

	// Handle extends: inherit parent requirements.
	if dto.Extends != "" {
		parent, parentErr := LoadProfile(dto.Extends)
		if parentErr != nil {
			return nil, fmt.Errorf("%s: extends %q: %w", filename, dto.Extends, parentErr)
		}
		// Merge: parent requirements first, child overrides by ID.
		childIDs := make(map[string]struct{}, len(reqs))
		for _, r := range reqs {
			childIDs[r.ID] = struct{}{}
		}
		var merged []coreevidence.Requirement
		for _, pr := range parent.Requirements {
			if _, ok := childIDs[pr.ID]; !ok {
				merged = append(merged, pr)
			}
		}
		merged = append(merged, reqs...)
		reqs = merged
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
