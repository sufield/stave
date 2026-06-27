package pack

import (
	"sort"
	"strings"
)

// service.go adds the service-keyed lookup axis: packs are the one grouping
// concept; "service groups" are just packs queried by AWS service instead of by
// name. A pack "covers" a service when any control it resolves belongs to that
// service. `stave discover --services iam,s3` resolves to the packs covering
// those services and merges their requirement manifests.

// ServiceForControlID maps a control ID to its AWS service. Control IDs are
// CTL.<DOMAIN>.<...>; the domain lowercased is the service (CTL.IAM.* -> iam,
// CTL.S3.* -> s3). Returns "" for an unrecognizable ID.
func ServiceForControlID(id string) string {
	parts := strings.Split(id, ".")
	if len(parts) < 2 || parts[0] != "CTL" {
		return ""
	}
	return strings.ToLower(parts[1])
}

// ServicesForPack returns the distinct, sorted AWS services the pack's resolved
// controls touch.
func ServicesForPack(p *Pack, catalog []ControlMeta) []string {
	seen := map[string]bool{}
	for _, id := range p.Resolve(catalog) {
		if s := ServiceForControlID(id); s != "" {
			seen[s] = true
		}
	}
	return sortedKeys(seen)
}

// PacksForServices returns the names of packs covering any of the given services
// (sorted). Service names are matched case-insensitively against control domains.
func PacksForServices(services []string, all map[string]*Pack, catalog []ControlMeta) []string {
	want := map[string]bool{}
	for _, s := range services {
		want[strings.ToLower(strings.TrimSpace(s))] = true
	}
	hit := map[string]bool{}
	for name, p := range all {
		for _, svc := range ServicesForPack(p, catalog) {
			if want[svc] {
				hit[name] = true
				break
			}
		}
	}
	return sortedKeys(hit)
}

// MergeRequirements unions the requirement manifests of several packs: API calls
// grouped by service (calls deduped), observation signals deduped, and minimum
// permissions concatenated line-wise (deduped). This is the combined collection
// manifest for `stave discover`.
func MergeRequirements(packs []*Pack) Requirements {
	callsByService := map[string][]string{}
	notesByService := map[string]string{}
	var serviceOrder []string
	signals := map[string]bool{}
	permLines := []string{}
	permSeen := map[string]bool{}

	for _, p := range packs {
		for _, sc := range p.Requirements.AWSAPICalls {
			if _, ok := callsByService[sc.Service]; !ok {
				serviceOrder = append(serviceOrder, sc.Service)
			}
			callsByService[sc.Service] = dedupAppend(callsByService[sc.Service], sc.Calls)
			if sc.Notes != "" && notesByService[sc.Service] == "" {
				notesByService[sc.Service] = sc.Notes
			}
		}
		for _, sig := range p.Requirements.ObservationSignals {
			signals[sig] = true
		}
		for line := range strings.SplitSeq(p.Requirements.MinimumPermissions, "\n") {
			if t := strings.TrimRight(line, " "); t != "" && !permSeen[t] {
				permSeen[t] = true
				permLines = append(permLines, t)
			}
		}
	}

	sort.Strings(serviceOrder)
	merged := Requirements{ObservationSignals: sortedKeys(signals)}
	for _, svc := range serviceOrder {
		merged.AWSAPICalls = append(merged.AWSAPICalls, ServiceCalls{
			Service: svc, Calls: callsByService[svc], Notes: notesByService[svc],
		})
	}
	merged.MinimumPermissions = strings.Join(permLines, "\n")
	return merged
}

func dedupAppend(dst, src []string) []string {
	seen := map[string]bool{}
	for _, s := range dst {
		seen[s] = true
	}
	for _, s := range src {
		if !seen[s] {
			seen[s] = true
			dst = append(dst, s)
		}
	}
	return dst
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
