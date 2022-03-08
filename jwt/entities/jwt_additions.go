package entities

type JWTAdditions struct {
	Identifier string `json:"identifier"`
	Type       string `json:"type"`
	Meta       []Meta `json:"meta"`
}

type Meta struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}
