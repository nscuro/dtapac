package opa

type Status struct {
	Bundles map[string]struct {
		ActiveRevision string `json:"active_revision"`
	} `json:"bundles"`
}
