// Package netutil provides shared URL / network helpers for cmd-side
// and platform-layer construction of external links (docs, telemetry,
// issue trackers).
package netutil

import (
	"net/url"
	"strings"
)

// EscapeFragment escapes characters that are unsafe in a URL fragment
// (RFC 3986 § 3.5) but preserves "/" so hierarchical fragment paths
// like "guides/getting-started" survive intact. url.PathEscape would
// encode "/" as "%2F", which breaks hierarchical doc topic IDs;
// url.QueryEscape applied segment-wise plus a slash rejoin produces
// a fragment that browsers route correctly.
//
// Callers (DocsRef, future JiraRef / TelemetryRef helpers) share
// this so the segment-wise escape rule lives in one place.
func EscapeFragment(topic string) string {
	parts := strings.Split(topic, "/")
	for i, p := range parts {
		parts[i] = url.PathEscape(p)
	}
	return strings.Join(parts, "/")
}
