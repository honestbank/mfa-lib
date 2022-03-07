package mfa

import "github.com/honestbank/mfa-lib/mfa/entities"

type IMFAService interface {
	Request(flow string) (*entities.MFAResult, error)
	Process(jwt string, challenge string, input string, request bool) (*entities.MFAResult, error)
}
