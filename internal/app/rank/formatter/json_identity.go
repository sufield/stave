package formatter

import (
	"encoding/json"
	"fmt"
	"io"

	apprank "github.com/sufield/stave/internal/app/rank"
)

// JSONIdentityRanking renders an identity-centric blast radius
// ranking as indented JSON. The text counterpart is
// TextIdentityRanking.
type JSONIdentityRanking struct{}

var _ IdentityRankingFormatter = (*JSONIdentityRanking)(nil)

// Render writes ranking as JSON with two-space indentation.
func (JSONIdentityRanking) Render(w io.Writer, ranking apprank.IdentityRanking) error {
	data, err := json.MarshalIndent(ranking, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal identity ranking: %w", err)
	}
	_, err = fmt.Fprintln(w, string(data))
	return err
}
