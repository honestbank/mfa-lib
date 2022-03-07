package entities

type MFAResult struct {
	Token      string   `json:"token"`
	Challenges []string `json:"challenges"`
	Reference  *string  `json:"reference"`
	Metadata   *string  `json:"metadata"`
}
