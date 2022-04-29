package challenge

import "context"

type IChallenge interface {
	GetName() string
	Solve(ctx context.Context, body map[string]interface{}) (*map[string]interface{}, error)
	Request(ctx context.Context, body map[string]interface{}) (*map[string]interface{}, error) // Request a challenge, ex: for OTP you have to request an OTP before you can solve it
}
