package entities

import (
	"context"
	"encoding/json"
	"errors"

	challengeEntity "github.com/honestbank/mfa-lib/challenge"
	mfaEntities "github.com/honestbank/mfa-lib/mfa/entities"
)

type Flow struct {
	Name       string                                `json:"name"`
	Challenges map[string]challengeEntity.IChallenge `json:"challenges"`
}

func (f Flow) GetName() string {
	return f.Name
}

func (f Flow) Solve(ctx context.Context, challenge string, input string, JWTData mfaEntities.JWTData) (*map[string]interface{}, error) {
	var marshaledInput map[string]interface{}
	err := json.Unmarshal([]byte(input), &marshaledInput)
	if err != nil {
		return nil, err
	}
	if challenge, ok := f.Challenges[challenge]; ok {
		return challenge.Solve(ctx, marshaledInput)
	}

	return nil, errors.New("Challenge not found")
}

func (f Flow) Request(ctx context.Context, challenge string, input string, JWTData mfaEntities.JWTData) (*map[string]interface{}, error) {
	var marshaledInput map[string]interface{}
	err := json.Unmarshal([]byte(input), &marshaledInput)
	if err != nil {
		return nil, err
	}
	if challenge, ok := f.Challenges[challenge]; ok {
		return challenge.Request(ctx, marshaledInput)
	}

	return nil, errors.New("Challenge not found")
}

func (f Flow) GetChallenges() []string {
	var challenges []string
	for k := range f.Challenges {
		challenges = append(challenges, k)
	}

	return challenges
}
