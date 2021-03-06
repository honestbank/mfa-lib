package mfa

import (
	"context"

	"github.com/honestbank/mfa-lib/mfa/entities"
)

type IMFAService interface {
	Request(ctx context.Context, flow string, input *FlowInput) (*entities.MFAResult, error)
	Process(ctx context.Context, jwt string, challenge string, input string, request bool, beforeHook *func(ctx context.Context, challenge string, input string) (context.Context, error)) (*entities.MFAResult, error)
}
