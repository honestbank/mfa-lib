package graph

import "github.com/honestbank/mfa-lib/mfa"

// This file will not be regenerated automatically.
//
// It serves as dependency injection for your app, add any dependencies you require here.

type Resolver struct {
	MFAService mfa.IMFAService
}
