// Package risk provides security-risk scoring and predictive threshold analysis.
//
// [Score] classifies findings from Safe through Catastrophic. [Permission]
// is a bitmask covering Read, Write, List, AdminRead, AdminWrite, and Delete
// capabilities. The upcoming module performs predictive analysis to identify
// controls approaching their unsafe-duration threshold.
package risk
