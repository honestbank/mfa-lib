package jwt

import "github.com/honestbank/mfa-lib/mfa/entities"

type IJWTService interface {
	GenerateToken(claims entities.JWTData, scopes []string) (string, error)
}
