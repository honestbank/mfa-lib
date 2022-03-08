package mfa

import (
	"context"

	"github.com/honestbank/mfa-lib/mfa/entities"
)

type IMFAService interface {
	Request(ctx context.Context, flow string) (*entities.MFAResult, error)
	Process(ctx context.Context, jwt string, challenge string, input string, request bool) (*entities.MFAResult, error)
}
