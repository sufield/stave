// Package risk provides security-risk scoring and predictive threshold analysis.
//
// [SecurityScore] classifies findings from Safe through Catastrophic. StmtPerm
// is a bitmask covering Read, Write, List, ACLRead, ACLWrite, and Delete
// permissions. The upcoming module performs predictive analysis to identify
// controls approaching their unsafe-duration threshold.
package risk
