package flow

import (
	"context"

	"github.com/honestbank/mfa-lib/jwt/entities"
	mfaEntities "github.com/honestbank/mfa-lib/mfa/entities"
)

type IFlow interface {
	Solve(ctx context.Context, challenge string, input string, JWTData mfaEntities.JWTData) (*map[string]interface{}, error)
	Request(ctx context.Context, challenge string, input string, JWTData mfaEntities.JWTData) (*map[string]interface{}, error)
	Resolve(JWTData mfaEntities.JWTData) (*map[string]interface{}, error)
	Validate(ctx context.Context, challenge string, JWTData mfaEntities.JWTData, challengeInput *string) (context.Context, error)
	GetChallenges(challengesStatus *map[string]mfaEntities.Challenge, challenge *string, getAll bool) []string
	GetName() string
	Initialize(ctx context.Context) (*entities.JWTAdditions, error)
	GetJWT(ctx context.Context) *string
	GetIdentifier(ctx context.Context) *string
	SetIdentifier(ctx context.Context, value string) context.Context
	SetJWT(ctx context.Context, value string) context.Context
}
