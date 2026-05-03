package metadata

// OntologyVersion is the canonical version string for the Stave
// ontology / graph wire format. Bumped on schema-affecting changes
// to docs/ontology/v0.1/* and reflected in every consumer that
// labels its output with the supported ontology revision.
//
// The authoritative changelog lives at
// docs/ontology/v0.1/CHANGELOG.md — update both this constant and
// the changelog in the same commit when the value changes. Versions
// 0.1.3 and 0.1.4 were issued and withdrawn; 0.1.2 is the current
// shipping version.
//
// This constant is in internal/metadata (not internal/graph) so the
// CLI version surface, documentation generators, and other
// non-graph callers can read it without taking a transitive
// dependency on the graph package.
const OntologyVersion = "0.1.2"
