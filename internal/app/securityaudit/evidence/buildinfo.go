package evidence

import (
	"encoding/json"
	"fmt"
	"runtime"
	"runtime/debug"
	"sort"
	"time"
)

type DefaultBuildInfoProvider struct{}

type buildInfoModule struct {
	Path    string           `json:"path,omitempty"`
	Version string           `json:"version,omitempty"`
	Sum     string           `json:"sum,omitempty"`
	Replace *buildInfoModule `json:"replace,omitempty"`
}

type buildInfoPayload struct {
	Available bool              `json:"available"`
	GoVersion string            `json:"go_version,omitempty"`
	Path      string            `json:"path,omitempty"`
	Main      buildInfoModule   `json:"main"`
	Deps      []buildInfoModule `json:"deps,omitempty"`
	Settings  map[string]string `json:"settings,omitempty"`
	Runtime   map[string]string `json:"runtime"`
	Generated string            `json:"generated_at"`
}

func (DefaultBuildInfoProvider) Collect(now time.Time) (BuildInfoSnapshot, error) {
	out := BuildInfoSnapshot{
		Settings: map[string]string{},
		Deps:     []BuildModuleSnapshot{},
	}

	payload := buildInfoPayload{
		Runtime: map[string]string{
			"goos":   runtime.GOOS,
			"goarch": runtime.GOARCH,
		},
		Generated: now.UTC().Format(time.RFC3339),
	}

	info, ok := debug.ReadBuildInfo()
	if ok && info != nil {
		out.Available = true
		out.GoVersion = info.GoVersion
		payload.Available = true
		payload.GoVersion = info.GoVersion
		payload.Path = info.Path
		payload.Main = toBuildInfoModule(info.Main)
		out.Main = BuildModuleSnapshot{
			Path:    info.Main.Path,
			Version: info.Main.Version,
			Sum:     info.Main.Sum,
		}
		payload.Deps = make([]buildInfoModule, 0, len(info.Deps))
		for _, dep := range info.Deps {
			if dep == nil {
				continue
			}
			payload.Deps = append(payload.Deps, toBuildInfoModule(*dep))
			out.Deps = append(out.Deps, BuildModuleSnapshot{
				Path:    dep.Path,
				Version: dep.Version,
				Sum:     dep.Sum,
			})
		}
		sort.Slice(out.Deps, func(i, j int) bool {
			return out.Deps[i].Path < out.Deps[j].Path
		})
		if len(info.Settings) > 0 {
			settings := make(map[string]string, len(info.Settings))
			for _, setting := range info.Settings {
				settings[setting.Key] = setting.Value
			}
			payload.Settings = settings
			out.Settings = settings
		}
	}

	raw, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return BuildInfoSnapshot{}, fmt.Errorf("marshal build info: %w", err)
	}
	out.RawJSON = append(raw, '\n')
	return out, nil
}

func toBuildInfoModule(in debug.Module) buildInfoModule {
	out := buildInfoModule{
		Path:    in.Path,
		Version: in.Version,
		Sum:     in.Sum,
	}
	if in.Replace != nil {
		replace := toBuildInfoModule(*in.Replace)
		out.Replace = &replace
	}
	return out
}
