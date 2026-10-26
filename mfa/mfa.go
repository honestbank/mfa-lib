package mfa

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/samber/lo"

	"github.com/honestbank/mfa-lib/flow"
	"github.com/honestbank/mfa-lib/jwt"
	"github.com/honestbank/mfa-lib/mfa/entities"
)

type Service struct {
	Flows map[string]flow.IFlow
	// The MFA service configuration
	Config     entities.Config
	JWTService jwt.IJWTService
}

type FlowInput struct {
	Identifier string
	JWT        string
}

func NewMFAService(config entities.Config, jwtService jwt.IJWTService, flows map[string]flow.IFlow) *Service {
	return &Service{
		Flows:      flows,
		JWTService: jwtService,
		Config:     config,
	}
}

func (m *Service) getFlow(ctx context.Context, flow string, decodedJWT *entities.JWTData, challenge *string, input *string) (context.Context, flow.IFlow, error) {
	requestedFlow := m.Flows[flow]
	if requestedFlow == nil {
		return ctx, nil, fmt.Errorf("flow %s not found in challenge %s", flow, lo.FromPtrOr(challenge, "nil"))
	}

	if challenge == nil {
		return ctx, requestedFlow, nil
	}
	newCtx, err := requestedFlow.Validate(ctx, *challenge, *decodedJWT, input)
	if err != nil {
		return ctx, nil, err
	}

	return newCtx, requestedFlow, nil
}

func (m *Service) Process(ctx context.Context, jwt string, challenge string, input string, request bool, beforeHook *func(ctx context.Context, challenge string, input string) (context.Context, error)) (*entities.MFAResult, error) {
	// The JWT service verifies the signature, expiry and audience. We read the
	// flow, challenge statuses and identifier only from the verified claims.
	decodedJWT, err := m.JWTService.VerifyToken(jwt)
	if err != nil {
		return nil, err
	}
	if decodedJWT == nil {
		return nil, errors.New("invalid JWT")
	}
	newCtx, requestFlow, err := m.getFlow(ctx, decodedJWT.Flow, decodedJWT, &challenge, &input)
	if err != nil {
		return nil, err
	}

	if beforeHook != nil {
		newCtx, err = (*beforeHook)(newCtx, challenge, input)
		if err != nil {
			return nil, err
		}
	}
	if request {
		return m.handleRequest(newCtx, *decodedJWT, challenge, input, requestFlow)
	}

	return m.handleSolve(newCtx, *decodedJWT, challenge, input, requestFlow)
}

func (m *Service) setContext(ctx context.Context, requestFlow flow.IFlow, input FlowInput) context.Context {
	newCtx := ctx

	if input.Identifier != "" {
		newCtx = requestFlow.SetIdentifier(newCtx, input.Identifier)
	}
	if input.JWT != "" {
		newCtx = requestFlow.SetJWT(newCtx, input.JWT)
	}

	return newCtx
}

func (m *Service) Request(ctx context.Context, flow string, input *FlowInput) (*entities.MFAResult, error) {
	newCtx, requestFlow, err := m.getFlow(ctx, flow, &entities.JWTData{}, nil, nil)
	if err != nil {
		return nil, err
	}
	if input != nil {
		newCtx = m.setContext(newCtx, requestFlow, *input)
	}

	challenge := requestFlow.GetChallenges(newCtx, nil, nil, true)[0]

	additionalJWTData, err := requestFlow.Initialize(newCtx)
	if err != nil {
		return nil, err
	}

	scopes := make([]string, 0)
	claims, _ := m.generateClaims(newCtx, requestFlow, entities.JWTData{
		Flow:       flow,
		Identifier: requestFlow.GetIdentifier(newCtx),
		Type:       additionalJWTData.Type,
		Meta:       additionalJWTData.Meta,
	}, nil)
	token, err := m.JWTService.GenerateToken(claims, scopes)
	if err != nil {
		return nil, err
	}
	var challenges []string
	challenges = append(challenges, requestFlow.GetChallenges(newCtx, &claims.Challenges, &challenge, false)...)

	return &entities.MFAResult{
		Token:      token,
		Challenges: challenges,
	}, nil
}

func (m *Service) generateClaims(ctx context.Context, requestFlow flow.IFlow, jwtData entities.JWTData, challenge *string) (entities.JWTData, error) {
	var claims entities.JWTData
	claims.Meta = jwtData.Meta
	claims.Identifier = jwtData.Identifier
	claims.Type = jwtData.Type
	claims.Flow = requestFlow.GetName()
	claims.Challenges = map[string]entities.Challenge{}
	challenges := requestFlow.GetChallenges(ctx, &claims.Challenges, challenge, true)

	for _, challenge := range challenges {
		jwtDataClaim := jwtData.Challenges[challenge]
		claims.Challenges[challenge] = m.getChallengeStatus(jwtDataClaim.Status)
	}

	return claims, nil
}

func (m *Service) getChallengeStatus(claimStatus string) entities.Challenge {
	if claimStatus == "" {
		return entities.Challenge{
			Status: "PENDING",
		}
	}

	return entities.Challenge{
		Status: claimStatus,
	}
}

func (m *Service) handleRequest(ctx context.Context, decodedJWT entities.JWTData, challenge string, input string, requestFlow flow.IFlow) (*entities.MFAResult, error) {
	result, err := requestFlow.Request(ctx, challenge, input, decodedJWT)

	resultJson, _ := json.Marshal(result)
	resultJsonString := string(resultJson)

	scopes := make([]string, 0)
	claims, _ := m.generateClaims(ctx, requestFlow, decodedJWT, &challenge)

	if err != nil {
		claims.Challenges[challenge] = entities.Challenge{
			Status: errorStatus(err),
		}
	}

	var challenges []string
	for _, flowChallenge := range requestFlow.GetChallenges(ctx, &claims.Challenges, &challenge, false) {
		if claims.Challenges[flowChallenge].Status != entities.StatusPassed {
			challenges = append(challenges, flowChallenge)
		}
	}

	token, jwtErr := m.JWTService.GenerateToken(claims, scopes)

	if jwtErr != nil {
		return &entities.MFAResult{
			Token:      token,
			Challenges: challenges,
		}, jwtErr
	}

	if err != nil {
		return &entities.MFAResult{
			Token:      token,
			Challenges: challenges,
		}, err
	}
	if result != nil {
		reference, ok := (*result)["Reference"].(string)
		if !ok {
			return &entities.MFAResult{
				Token:      token,
				Challenges: challenges,
			}, errors.New("challenge request did not return a reference")
		}

		return &entities.MFAResult{
			Token:      token,
			Challenges: challenges,
			Reference:  &reference,
		}, nil
	}

	return &entities.MFAResult{
		Token:      token,
		Challenges: challenges,
		Metadata:   &resultJsonString,
	}, nil
}

func (m *Service) handleSolve(ctx context.Context, decodedJWT entities.JWTData, challenge string, input string, requestFlow flow.IFlow) (*entities.MFAResult, error) {
	result, err := requestFlow.Solve(ctx, challenge, input, decodedJWT)

	resultJson, _ := json.Marshal(result)
	resultJsonString := string(resultJson)
	scopes := make([]string, 0)
	if err != nil {
		status := errorStatus(err)
		claims, _ := m.generateClaims(ctx, requestFlow, decodedJWT, &challenge)
		claims.Challenges[challenge] = entities.Challenge{
			Status: status,
		}

		var challenges []string
		challenges = append(challenges, requestFlow.GetChallenges(ctx, &claims.Challenges, &challenge, false)...)

		for _, flowChallenge := range challenges {
			if flowChallenge == challenge {
				claims.Challenges[flowChallenge] = entities.Challenge{
					Status: status,
				}
			} else {
				claims.Challenges[flowChallenge] = entities.Challenge{
					Status: entities.StatusPending,
				}
			}
		}

		token, jwtErr := m.JWTService.GenerateToken(claims, scopes)
		if jwtErr != nil {
			return &entities.MFAResult{
				Token:      "",
				Challenges: challenges,
			}, jwtErr
		}

		return &entities.MFAResult{
			Token:      token,
			Challenges: challenges,
		}, err
	}

	claims, _ := m.generateClaims(ctx, requestFlow, decodedJWT, &challenge)
	claims.Challenges[challenge] = entities.Challenge{
		Status: entities.StatusPassed,
	}

	var challenges []string
	challenges = append(challenges, requestFlow.GetChallenges(ctx, &claims.Challenges, &challenge, false)...)
	token, err := m.JWTService.GenerateToken(claims, scopes)
	if err != nil {
		return &entities.MFAResult{
			Token:      "",
			Challenges: challenges,
			Metadata:   &resultJsonString,
		}, err
	}

	if len(challenges) > 1 {
		return &entities.MFAResult{
			Token:      token,
			Challenges: challenges,
			Metadata:   &resultJsonString,
		}, nil
	}
	if len(challenges) == 1 && claims.Challenges[challenges[0]].Status != entities.StatusPassed {
		return &entities.MFAResult{
			Token:      token,
			Challenges: challenges,
		}, nil
	}
	resolveRes, err := requestFlow.Resolve(decodedJWT)
	if err != nil {
		return &entities.MFAResult{
			Token:      token,
			Challenges: challenges,
			Metadata:   &resultJsonString,
		}, err
	}
	var resolveToken string
	var ok bool
	if resolveRes != nil {
		resolveToken, ok = (*resolveRes)["token"].(string)
	}
	if !ok {
		return &entities.MFAResult{
			Token:      token,
			Challenges: challenges,
			Metadata:   &resultJsonString,
		}, errors.New("unable to resolve flow")
	}

	return &entities.MFAResult{
		Token:      resolveToken,
		Challenges: nil,
		Metadata:   &resultJsonString,
	}, nil
}

// errorStatus maps a challenge error to a challenge status. An MFAError carries its own
// status code. Any other error marks the challenge as failed.
func errorStatus(err error) string {
	var mfaErrPtr *entities.MFAError
	if errors.As(err, &mfaErrPtr) && mfaErrPtr != nil {
		return mfaErrPtr.Code
	}
	var mfaErr entities.MFAError
	if errors.As(err, &mfaErr) {
		return mfaErr.Code
	}

	return entities.StatusFailed
}
