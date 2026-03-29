// Package catalog provides request/response types and use case orchestration
// for built-in control pack discovery. Packs are curated sets of controls
// (e.g., s3, hipaa) registered in the pack index and queryable via
// list and show operations.
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
