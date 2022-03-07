package entities

import (
	JWTEntities "github.com/honestbank/mfa-lib/jwt/entities"
)

type Challenge struct {
	Status string `json:"status"`
}

type JWTData struct {
	Flow       string               `json:"flow"`
	Challenges map[string]Challenge `json:"challenges"`
	Identifier string
	Type       string
	Meta       []JWTEntities.Meta
}
