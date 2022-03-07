package entities

type JWTAdditions struct {
	Identifier string
	Type       string
	Meta       []Meta
}

type Meta struct {
	Key   string
	Value string
}
