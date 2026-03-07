// Package exposure classifies asset visibility by combining policy, ACL, and
// PublicAccessBlock signals.
//
// The classification engine resolves effective visibility (Public, Authenticated,
// or Private) through a multi-stage pipeline: fact extraction from observations,
// policy and ACL inspection, context assembly, and final resolution when signals
// conflict. [Mapper] projects findings into exposure data for output enrichment.
package exposure
