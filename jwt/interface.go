package jwt

import "github.com/honestbank/mfa-lib/mfa/entities"

type IJWTService interface {
	GenerateToken(claims entities.JWTData, scopes []string) (string, error)
	// VerifyToken verifies a token that GenerateToken issued and returns its claims.
	// Implementations MUST verify the signature with a fixed expected algorithm (never
	// trust the alg in the token header), check the expiry and the audience, and return
	// the verified claims. They MUST return an error if any check fails.
	// The MFA service reads the flow, the challenge statuses and the identifier only
	// from the claims that VerifyToken returns.
	VerifyToken(token string) (*entities.JWTData, error)
}
