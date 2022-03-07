package entities

type Challenge struct {
	Status string `json:"status"`
}

type JWTData struct {
	Flow       string               `json:"flow"`
	Challenges map[string]Challenge `json:"challenges"`
}
