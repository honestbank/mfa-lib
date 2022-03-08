package flow

import (
	"context"

	"github.com/honestbank/mfa-lib/jwt/entities"
	mfaEntities "github.com/honestbank/mfa-lib/mfa/entities"
)

type IFlow interface {
	Solve(challenge string, input string, JWTData mfaEntities.JWTData) (*map[string]interface{}, error)
	Request(challenge string, input string, JWTData mfaEntities.JWTData) (*map[string]interface{}, error)
	Resolve() (*map[string]interface{}, error)
	Validate(ctx context.Context, challenge string, JWTData mfaEntities.JWTData) error
	GetChallenges() []string
	GetName() string
	Initialize(ctx context.Context) (*entities.JWTAdditions, error)
}
