package entities

import (
	"context"
	"encoding/json"
	"errors"

	challengeEntity "github.com/honestbank/mfa-lib/challenge"
	mfaEntities "github.com/honestbank/mfa-lib/mfa/entities"
)

type Flow struct {
	Name       string                       `json:"name"`
	Challenges []challengeEntity.IChallenge `json:"challenges"`
}

func (f Flow) GetName() string {
	return f.Name
}

type identifier struct{}
type jwt struct{}

func (f Flow) Solve(ctx context.Context, challenge string, input string, JWTData mfaEntities.JWTData) (*map[string]interface{}, error) {
	var marshaledInput map[string]interface{}
	err := json.Unmarshal([]byte(input), &marshaledInput)
	if err != nil {
		return nil, err
	}
	if ichallenge, ok := f.GetChallenge(challenge); ok == nil {
		return ichallenge.Solve(ctx, marshaledInput)
	}

	return nil, errors.New("Challenge not found")
}

func (f Flow) GetChallenge(name string) (challengeEntity.IChallenge, error) {
	var challenge challengeEntity.IChallenge
	for _, c := range f.Challenges {
		if c.GetName() == name {
			challenge = c

			break
		}
	}
	if challenge == nil {
		return nil, errors.New("Challenge not found")
	}

	return challenge, nil
}

func (f Flow) Request(ctx context.Context, challenge string, input string, JWTData mfaEntities.JWTData) (*map[string]interface{}, error) {
	var marshaledInput map[string]interface{}
	err := json.Unmarshal([]byte(input), &marshaledInput)
	if err != nil {
		return nil, err
	}

	if ichallenge, ok := f.GetChallenge(challenge); ok == nil {
		return ichallenge.Request(ctx, marshaledInput)
	}

	return nil, errors.New("Challenge not found")
}

func (f Flow) SetIdentifier(ctx context.Context, value string) context.Context {
	return context.WithValue(ctx, &identifier{}, value)
}

func (f Flow) GetIdentifier(ctx context.Context) *string {
	if value := ctx.Value(&identifier{}); value != nil {
		valString := value.(string)

		return &valString
	}

	return nil
}

func (f Flow) SetJWT(ctx context.Context, value string) context.Context {
	return context.WithValue(ctx, &jwt{}, value)
}

func (f Flow) GetJWT(ctx context.Context) *string {
	if value := ctx.Value(&jwt{}); value != nil {
		valString := value.(string)

		return &valString
	}

	return nil
}

func (f Flow) GetChallenges(ctx context.Context, challengesStatus *map[string]mfaEntities.Challenge, challenge *string, getAll bool) []string {
	var challenges []string
	for _, k := range f.Challenges {
		challenges = append(challenges, k.GetName())
	}

	return challenges
}
