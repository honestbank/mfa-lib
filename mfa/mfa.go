package mfa

import (
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
	if len(base64Claims) < 2 {
		return nil, errors.New("Invalid JWT")
	}
	claimsJson, _ := base64.StdEncoding.DecodeString(base64Claims[1])
	err := json.Unmarshal(claimsJson, &decodedJWT)
	if err != nil {
		return nil, err
	}

	return &decodedJWT, nil
}

func (m *Service) getFlow(flow string, decodedJWT *entities.JWTData, challenge *string) (flow.IFlow, error) {
	requestedFlow := m.Flows[flow]
	if requestedFlow == nil {
		return nil, errors.New("Flow not found")
	}

	if challenge == nil {
		return requestedFlow, nil
	}
	err := requestedFlow.Validate(*challenge, *decodedJWT)
	if err != nil {
		return nil, err
	}

	return requestedFlow, nil
}

func (m *Service) Process(jwt string, challenge string, input string, request bool) (*entities.MFAResult, error) {
	decodedJWT, err := m.decodeJWT(jwt)
	if err != nil {
		return nil, err
	}
	requestFlow, err := m.getFlow(decodedJWT.Flow, decodedJWT, &challenge)
	if err != nil {
		return nil, err
	}

	if request {
		return m.handleRequest(*decodedJWT, challenge, input, requestFlow)
	}

	return m.handleSolve(*decodedJWT, challenge, input, requestFlow)
}

func (m *Service) Request(flow string) (*entities.MFAResult, error) {
	requestFlow, err := m.getFlow(flow, &entities.JWTData{}, nil)
	if err != nil {
		return nil, err
	}
	challenge := requestFlow.GetChallenges()[0]

	return m.handleRequest(entities.JWTData{
		Flow: flow,
	}, challenge, "{}", requestFlow)
}

func (m *Service) generateClaims(requestFlow flow.IFlow, jwtData entities.JWTData) (entities.JWTData, error) {
	var claims entities.JWTData
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

func (m *Service) handleRequest(decodedJWT entities.JWTData, challenge string, input string, requestFlow flow.IFlow) (*entities.MFAResult, error) {
	result, err := requestFlow.Request(challenge, input, decodedJWT)

	resultJson, _ := json.Marshal(result)
	resultJsonString := string(resultJson)

	scopes := make([]string, 0)
	claims, _ := m.generateClaims(requestFlow, decodedJWT)
	token, _ := m.JWTService.GenerateToken(claims, scopes)

	var challenges []string
	challenges = append(challenges, requestFlow.GetChallenges()...)

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

func (m *Service) handleSolve(decodedJWT entities.JWTData, challenge string, input string, requestFlow flow.IFlow) (*entities.MFAResult, error) {
	result, err := requestFlow.Solve(challenge, input, decodedJWT)

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

	return &entities.MFAResult{
		Token:      token,
		Challenges: challenges,
		Metadata:   &resultJsonString,
	}, nil
}
