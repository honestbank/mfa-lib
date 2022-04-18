package graph

// This file will be automatically regenerated based on the schema, any resolver implementations
// will be copied through when generating and any unknown code will be moved to the end.

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"github.com/honestbank/mfa-lib/examples/graphql_flow/graph/generated"
	"github.com/honestbank/mfa-lib/examples/graphql_flow/graph/model"
)

func (r *mutationResolver) InitializeFlow(ctx context.Context, flowName string) (*model.InitializeFlowResponse, error) {
	result, err := r.MFAService.Request(ctx, flowName, nil)
	if err != nil {
		return nil, err
	}
	return &model.InitializeFlowResponse{
		Token:      result.Token,
		Challenges: result.Challenges,
	}, nil
}

func (r *mutationResolver) ChallengesSolveOtp(ctx context.Context, input *model.SolveOTPInput) (*model.SolveOTPResult, error) {
	jsonInput, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}
	log.Println(string(jsonInput))
	result, err := r.MFAService.Process(ctx, ctx.Value("jwt").(string), "dummy", string(jsonInput), false, nil)
	if err != nil {
		return nil, err
	}
	log.Println(result)
	return &model.SolveOTPResult{
		Token:      result.Token,
		Challenges: result.Challenges,
	}, nil
}

func (r *mutationResolver) ChallengesRequestOtp(ctx context.Context) (*model.RequestOTPResult, error) {
	result, err := r.MFAService.Process(ctx, ctx.Value("jwt").(string), "dummy", "{}", true, nil)
	if err != nil {
		return nil, err
	}
	log.Println(result)
	return &model.RequestOTPResult{
		Token:      result.Token,
		Challenges: result.Challenges,
		Reference:  *result.Reference,
	}, nil
}

func (r *queryResolver) Hello(ctx context.Context) (string, error) {
	panic(fmt.Errorf("not implemented"))
}

// Mutation returns generated.MutationResolver implementation.
func (r *Resolver) Mutation() generated.MutationResolver { return &mutationResolver{r} }

// Query returns generated.QueryResolver implementation.
func (r *Resolver) Query() generated.QueryResolver { return &queryResolver{r} }

type mutationResolver struct{ *Resolver }
type queryResolver struct{ *Resolver }
