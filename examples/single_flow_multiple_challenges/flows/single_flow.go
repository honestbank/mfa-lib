package flows

import (
	"context"
	"log"

	"github.com/honestbank/mfa-lib/challenge"
	"github.com/honestbank/mfa-lib/examples/single_flow_multiple_challenges/challenges"
	"github.com/honestbank/mfa-lib/flow"
	"github.com/honestbank/mfa-lib/flow/entities"
	JWTEntities "github.com/honestbank/mfa-lib/jwt/entities"
	mfaEntities "github.com/honestbank/mfa-lib/mfa/entities"
)

type SingleFlow struct {
	entities.Flow
}

func (f SingleFlow) Resolve(jwtData mfaEntities.JWTData) (*map[string]interface{}, error) {
	return &map[string]interface{}{
		"token": "new_token",
	}, nil
}

func (f SingleFlow) Validate(ctx context.Context, challenge string, JWTData mfaEntities.JWTData) error {
	//TODO implement me
	return nil
}

func (f SingleFlow) Initialize(ctx context.Context) (*JWTEntities.JWTAdditions, error) {
	log.Println(ctx)
	//TODO implement me
	return &JWTEntities.JWTAdditions{
		Identifier: "",
		Type:       "",
		Meta:       []JWTEntities.Meta{},
	}, nil
}

func NewSingleFlow() flow.IFlow {
	flow := entities.Flow{
		Name: "single_flow_single_challenge",
		Challenges: map[string]challenge.IChallenge{
			"dummy":  challenges.NewDummyChallenge(),
			"dummy2": challenges.NewDummyTwoChallenge(),
		},
	}
	return &SingleFlow{
		flow,
	}
}
