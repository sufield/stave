// Package catalog provides domain types and use cases for built-in
// control pack discovery: list and show.
package catalog

type PacksListRequest struct{}

type PackEntry struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

type PacksListResponse struct {
	Packs []PackEntry `json:"packs"`
}

type PacksShowRequest struct {
	Name string `json:"name"`
}

type PacksShowResponse struct {
	PackData any `json:"pack_data"`
}
