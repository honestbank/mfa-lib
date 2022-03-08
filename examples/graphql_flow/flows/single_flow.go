package flows

import (
	"github.com/honestbank/mfa-lib/challenge"
	"github.com/honestbank/mfa-lib/examples/single_flow_single_challenge/challenges"
	"github.com/honestbank/mfa-lib/flow"
	"github.com/honestbank/mfa-lib/flow/entities"
	entities2 "github.com/honestbank/mfa-lib/jwt/entities"
)

type SingleFlow struct {
	entities.Flow
}

func (f SingleFlow) Resolve() (*map[string]interface{}, error) {
	return nil, nil
}

func (f SingleFlow) Validate(challenge string, JWTData entities2.JWTData) error {
	//TODO implement me
	return nil
}

func NewSingleFlow() flow.IFlow {
	flow := entities.Flow{
		Name: "single_flow",
		Challenges: map[string]challenge.IChallenge{
			"dummy": challenges.NewDummyChallenge(),
		},
	}
	return &SingleFlow{
		flow,
	}
}
