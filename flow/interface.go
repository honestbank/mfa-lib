package flow

import (
	mfaEntities "github.com/honestbank/mfa-lib/mfa/entities"
)

type IFlow interface {
	Solve(challenge string, input string, JWTData mfaEntities.JWTData) (*map[string]interface{}, error)
	Request(challenge string, input string, JWTData mfaEntities.JWTData) (*map[string]interface{}, error)
	Resolve() (*map[string]interface{}, error)
	Validate(challenge string, JWTData mfaEntities.JWTData) error
	GetChallenges() []string
	GetName() string
}
