package graph

// This file will be automatically regenerated based on the schema, any resolver implementations
// will be copied through when generating and any unknown code will be moved to the end.

import (
	"context"
	"fmt"

	"github.com/honestbank/mfa-lib/examples/graphql_flow/graph/generated"
	"github.com/honestbank/mfa-lib/examples/graphql_flow/graph/model"
)

func (r *mutationResolver) InitializeFlow(ctx context.Context, flowName string) (*model.InitializeFlowResponse, error) {
	panic(fmt.Errorf("not implemented"))
}

func (r *mutationResolver) ChallengesSolveOtp(ctx context.Context, input *model.SolveOTPInput) (*model.SolveOTPResult, error) {
	panic(fmt.Errorf("not implemented"))
}

func (r *mutationResolver) ChallengesRequestOtp(ctx context.Context, input *model.RequestOTPInput) (*model.RequestOTPResult, error) {
	panic(fmt.Errorf("not implemented"))
}

// Mutation returns generated.MutationResolver implementation.
func (r *Resolver) Mutation() generated.MutationResolver { return &mutationResolver{r} }

type mutationResolver struct{ *Resolver }
