package mfa

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"

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

func NewMFAService(config entities.Config, jwtService jwt.IJWTService, flows map[string]flow.IFlow) *Service {
	return &Service{
		Flows:      flows,
		JWTService: jwtService,
		Config:     config,
	}
}

func (m *Service) decodeJWT(jwt string) (*entities.JWTData, error) {
	var decodedJWT entities.JWTData
	base64Claims := strings.Split(jwt, ".")
	if len(base64Claims) != 3 {
		return nil, errors.New("Invalid JWT")
	}
	claimsJson, _ := base64.StdEncoding.DecodeString(base64Claims[1])
	err := json.Unmarshal(claimsJson, &decodedJWT)
	if err != nil {
		return nil, err
	}

	return &decodedJWT, nil
}

func (m *Service) getFlow(ctx context.Context, flow string, decodedJWT *entities.JWTData, challenge *string) (context.Context, flow.IFlow, error) {
	requestedFlow := m.Flows[flow]
	if requestedFlow == nil {
		return ctx, nil, errors.New("Flow not found")
	}

	if challenge == nil {
		return ctx, requestedFlow, nil
	}
	newCtx, err := requestedFlow.Validate(ctx, *challenge, *decodedJWT)
	if err != nil {
		return ctx, nil, err
	}

	return newCtx, requestedFlow, nil
}

func (m *Service) Process(ctx context.Context, jwt string, challenge string, input string, request bool, beforeHook *func(ctx context.Context, challenge string, input string) (context.Context, error)) (*entities.MFAResult, error) {
	decodedJWT, err := m.decodeJWT(jwt)
	if err != nil {
		return nil, err
	}
	newCtx, requestFlow, err := m.getFlow(ctx, decodedJWT.Flow, decodedJWT, &challenge)
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

func (m *Service) Request(ctx context.Context, flow string) (*entities.MFAResult, error) {
	newCtx, requestFlow, err := m.getFlow(ctx, flow, &entities.JWTData{}, nil)
	if err != nil {
		return nil, err
	}
	challenge := requestFlow.GetChallenges()[0]

	additionalJWTData, err := requestFlow.Initialize(newCtx)
	if err != nil {
		return nil, err
	}

	return m.handleRequest(ctx, entities.JWTData{
		Flow:       flow,
		Identifier: additionalJWTData.Identifier,
		Type:       additionalJWTData.Type,
		Meta:       additionalJWTData.Meta,
	}, challenge, "{}", requestFlow)
}

func (m *Service) generateClaims(requestFlow flow.IFlow, jwtData entities.JWTData) (entities.JWTData, error) {
	var claims entities.JWTData
	claims.Meta = jwtData.Meta
	claims.Identifier = jwtData.Identifier
	claims.Type = jwtData.Type
	claims.Flow = requestFlow.GetName()
	claims.Challenges = map[string]entities.Challenge{}
	challenges := requestFlow.GetChallenges()

	for _, challenge := range challenges {
		jwtDataClaim := jwtData.Challenges[challenge]
		claims.Challenges[challenge] = m.getChallengeStatus(jwtDataClaim.Status)
	}

	return claims, nil
}

func (m *Service) getChallengeStatus(claimStatus string) entities.Challenge {
	if claimStatus == "" {
		return entities.Challenge{
			Status: "pending",
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
	claims, _ := m.generateClaims(requestFlow, decodedJWT)
	token, _ := m.JWTService.GenerateToken(claims, scopes)

	var challenges []string
	for _, flowChallenge := range requestFlow.GetChallenges() {
		if claims.Challenges[flowChallenge].Status != "passed" {
			challenges = append(challenges, flowChallenge)
		}
	}

	if err != nil {
		return &entities.MFAResult{
			Token:      token,
			Challenges: challenges,
		}, err
	}
	if result != nil {
		reference := (*result)["Reference"].(string)

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
	if err != nil {
		scopes := make([]string, 0)
		claims, _ := m.generateClaims(requestFlow, decodedJWT)
		claims.Challenges[challenge] = entities.Challenge{
			Status: "failed",
		}
		token, _ := m.JWTService.GenerateToken(claims, scopes)
		var challenges []string
		challenges = append(challenges, requestFlow.GetChallenges()...)

		return &entities.MFAResult{
			Token:      token,
			Challenges: challenges,
		}, err
	}

	scopes := make([]string, 0)
	claims, _ := m.generateClaims(requestFlow, decodedJWT)
	claims.Challenges[challenge] = entities.Challenge{
		Status: "passed",
	}
	token, _ := m.JWTService.GenerateToken(claims, scopes)
	var challenges []string
	for _, flowChallenge := range requestFlow.GetChallenges() {
		if claims.Challenges[flowChallenge].Status != "passed" {
			challenges = append(challenges, flowChallenge)
		}
	}
	if len(challenges) > 0 {
		return &entities.MFAResult{
			Token:      token,
			Challenges: challenges,
			Metadata:   &resultJsonString,
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
	resolveTokenRef := (*resolveRes)["token"]
	if resolveTokenRef == nil {
		return &entities.MFAResult{
			Token:      token,
			Challenges: challenges,
			Metadata:   &resultJsonString,
		}, errors.New("Unable to resolve flow")
	}
	resolveToken := resolveTokenRef.(string)

	return &entities.MFAResult{
		Token:      resolveToken,
		Challenges: challenges,
		Metadata:   &resultJsonString,
	}, nil
}
