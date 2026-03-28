package risk

// CalculateRiskIndex computes a composite risk index from individual permission scores.
// Formula: max(scores) + sum(scores)/10, capped at 100. Returns 0 for empty input.
func CalculateRiskIndex(scores []int) int {
	if len(scores) == 0 {
		return 0
	}
	var maxScore, sum int
	for _, s := range scores {
		sum += s
		if s > maxScore {
			maxScore = s
		}
	}
	index := maxScore + sum/10
	if index > 100 {
		return 100
	}
	return index
}

// GetRiskLevel classifies a risk index into a human-readable severity.
func GetRiskLevel(index int) string {
	switch {
	case index >= 90:
		return "CRITICAL"
	case index >= 70:
		return "HIGH"
	case index >= 40:
		return "MEDIUM"
	case index > 0:
		return "LOW"
	default:
		return "SAFE"
	}
}
