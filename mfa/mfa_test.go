package mfa_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/honestbank/mfa-lib/flow"
	JWTEntities "github.com/honestbank/mfa-lib/jwt/entities"
	"github.com/honestbank/mfa-lib/mfa"
	"github.com/honestbank/mfa-lib/mfa/entities"
	"github.com/honestbank/mfa-lib/mocks"
)

func TestNewMFAService(t *testing.T) {
	t.Run("Create MFA Service", func(t *testing.T) {
		a := assert.New(t)
		ctrl := gomock.NewController(t)
		config := entities.Config{}
		jwtService := mocks.NewMockIJWTService(ctrl)
		mockflow := mocks.NewMockIFlow(ctrl)

		flowMap := map[string]flow.IFlow{
			"test": mockflow,
		}

		mfaService := mfa.NewMFAService(config, jwtService, flowMap)

		a.NotNil(mfaService)
	})

	t.Run("Create MFA Service with nil flowMap", func(t *testing.T) {
		a := assert.New(t)
		ctrl := gomock.NewController(t)
		config := entities.Config{}
		jwtService := mocks.NewMockIJWTService(ctrl)

		mfaService := mfa.NewMFAService(config, jwtService, nil)

		a.NotNil(mfaService)
	})

	t.Run("MFA_Process", func(t *testing.T) {
		validJWT := "nil.eyJmbG93IjoidGVzdCIsImNoYWxsZW5nZXMiOnsiZHVtbXkiOnsic3RhdHVzIjoicGVuZGluZyJ9fX0."
		a := assert.New(t)
		ctrl := gomock.NewController(t)
		config := entities.Config{}
		jwtService := mocks.NewMockIJWTService(ctrl)
		jwtService.EXPECT().VerifyToken(validJWT).Return(verifiedClaims(), nil)
		mockflow := mocks.NewMockIFlow(ctrl)

		jwtService.EXPECT().GenerateToken(gomock.Any(), gomock.Any()).Return(validJWT, nil)

		mockflow.EXPECT().Request(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, nil)
		mockflow.EXPECT().Validate(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, nil)
		mockflow.EXPECT().GetName().Return("test")
		mockflow.EXPECT().GetChallenges(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return([]string{"dummy"})
		mockflow.EXPECT().GetChallenges(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return([]string{"dummy"})

		flowMap := map[string]flow.IFlow{
			"test": mockflow,
		}

		mfaService := mfa.NewMFAService(config, jwtService, flowMap)

		result, err := mfaService.Process(context.TODO(), validJWT, "dummy", "{}", true, nil)

		nullMetadata := "null"
		expectedResult := entities.MFAResult{
			Token:      validJWT,
			Challenges: []string{"dummy"},
			Reference:  nil,
			Metadata:   &nullMetadata,
		}

		a.NoError(err)
		a.Equal(expectedResult, *result)
	})

	t.Run("MFA_Process_verify_error", func(t *testing.T) {
		a := assert.New(t)
		ctrl := gomock.NewController(t)
		config := entities.Config{}
		jwtService := mocks.NewMockIJWTService(ctrl)
		// No expectations: the flow must not be called for a token that fails verification.
		mockflow := mocks.NewMockIFlow(ctrl)

		jwtService.EXPECT().VerifyToken("forged").Return(nil, errors.New("invalid signature"))

		flowMap := map[string]flow.IFlow{
			"test": mockflow,
		}

		mfaService := mfa.NewMFAService(config, jwtService, flowMap)

		result, err := mfaService.Process(context.TODO(), "forged", "dummy", "{}", false, nil)

		a.Error(err)
		a.Equal("invalid signature", err.Error())
		a.Nil(result)
	})

	t.Run("MFA_Process_verify_nil_claims", func(t *testing.T) {
		a := assert.New(t)
		ctrl := gomock.NewController(t)
		config := entities.Config{}
		jwtService := mocks.NewMockIJWTService(ctrl)
		mockflow := mocks.NewMockIFlow(ctrl)

		jwtService.EXPECT().VerifyToken("token").Return(nil, nil)

		flowMap := map[string]flow.IFlow{
			"test": mockflow,
		}

		mfaService := mfa.NewMFAService(config, jwtService, flowMap)

		result, err := mfaService.Process(context.TODO(), "token", "dummy", "{}", false, nil)

		a.Error(err)
		a.Equal("invalid JWT", err.Error())
		a.Nil(result)
	})

	t.Run("MFA_Process_HandleSolve", func(t *testing.T) {
		validJWT := "nil.eyJmbG93IjoidGVzdCIsImNoYWxsZW5nZXMiOnsiZHVtbXkiOnsic3RhdHVzIjoicGVuZGluZyJ9fX0."
		a := assert.New(t)
		ctrl := gomock.NewController(t)
		config := entities.Config{}
		jwtService := mocks.NewMockIJWTService(ctrl)
		jwtService.EXPECT().VerifyToken(validJWT).Return(verifiedClaims(), nil)
		mockflow := mocks.NewMockIFlow(ctrl)

		flowMap := map[string]flow.IFlow{
			"test": mockflow,
		}

		jwtService.EXPECT().GenerateToken(gomock.Any(), gomock.Any()).Return(validJWT, nil)

		mockflow.EXPECT().Solve(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, nil)
		mockflow.EXPECT().Validate(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, nil)
		mockflow.EXPECT().GetName().Return("test")
		mockflow.EXPECT().GetChallenges(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return([]string{"dummy"})
		mockflow.EXPECT().GetChallenges(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return([]string{"dummy"})
		mockflow.EXPECT().Resolve(gomock.Any()).Return(&map[string]interface{}{
			"token": validJWT,
		}, nil)

		mfaService := mfa.NewMFAService(config, jwtService, flowMap)

		result, err := mfaService.Process(context.TODO(), validJWT, "dummy", "{}", false, nil)

		nullMetadata := "null"
		expectedResult := entities.MFAResult{
			Token:    validJWT,
			Metadata: &nullMetadata,
		}

		a.NoError(err)
		a.Equal(expectedResult, *result)
	})

	t.Run("MFA_Process_HandleSolve - jwt error", func(t *testing.T) {
		validJWT := "nil.eyJmbG93IjoidGVzdCIsImNoYWxsZW5nZXMiOnsiZHVtbXkiOnsic3RhdHVzIjoicGVuZGluZyJ9fX0."
		a := assert.New(t)
		ctrl := gomock.NewController(t)
		config := entities.Config{}
		jwtService := mocks.NewMockIJWTService(ctrl)
		jwtService.EXPECT().VerifyToken(validJWT).Return(verifiedClaims(), nil)
		mockflow := mocks.NewMockIFlow(ctrl)

		flowMap := map[string]flow.IFlow{
			"test": mockflow,
		}

		jwtService.EXPECT().GenerateToken(gomock.Any(), gomock.Any()).Return("", errors.New("GenerateToken error"))

		mockflow.EXPECT().Solve(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, nil)
		mockflow.EXPECT().Validate(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, nil)
		mockflow.EXPECT().GetName().Return("test")
		mockflow.EXPECT().GetChallenges(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return([]string{"dummy"})
		mockflow.EXPECT().GetChallenges(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return([]string{"dummy"})

		mfaService := mfa.NewMFAService(config, jwtService, flowMap)

		_, err := mfaService.Process(context.TODO(), validJWT, "dummy", "{}", false, nil)

		a.Error(err)
		a.Equal("GenerateToken error", err.Error())
	})

	t.Run("MFA_Process_Solve_error", func(t *testing.T) {
		validJWT := "nil.eyJmbG93IjoidGVzdCIsImNoYWxsZW5nZXMiOnsiZHVtbXkiOnsic3RhdHVzIjoicGVuZGluZyJ9fX0."
		a := assert.New(t)
		ctrl := gomock.NewController(t)
		config := entities.Config{}
		jwtService := mocks.NewMockIJWTService(ctrl)
		jwtService.EXPECT().VerifyToken(validJWT).Return(verifiedClaims(), nil)
		mockflow := mocks.NewMockIFlow(ctrl)

		flowMap := map[string]flow.IFlow{
			"test": mockflow,
		}

		jwtService.EXPECT().GenerateToken(gomock.Any(), gomock.Any()).Return(validJWT, nil)

		mockflow.EXPECT().Solve(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, &entities.MFAError{
			Code:    "FAILED",
			Message: "Failed to solve",
		})
		mockflow.EXPECT().Validate(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, nil)
		mockflow.EXPECT().GetName().Return("test")
		mockflow.EXPECT().GetChallenges(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return([]string{"dummy"})
		mockflow.EXPECT().GetChallenges(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return([]string{"dummy"})

		mfaService := mfa.NewMFAService(config, jwtService, flowMap)

		result, err := mfaService.Process(context.TODO(), validJWT, "dummy", "{}", false, nil)

		expectedResult := entities.MFAResult{
			Token:      validJWT,
			Challenges: []string{"dummy"},
		}

		a.Error(err)
		a.Equal("Failed to solve", err.Error())
		a.Equal(expectedResult, *result)
	})

	t.Run("MFA_Process_Solve_error_GenerateToken_error_happens", func(t *testing.T) {
		validJWT := "nil.eyJmbG93IjoidGVzdCIsImNoYWxsZW5nZXMiOnsiZHVtbXkiOnsic3RhdHVzIjoicGVuZGluZyJ9fX0."
		a := assert.New(t)
		ctrl := gomock.NewController(t)
		config := entities.Config{}
		jwtService := mocks.NewMockIJWTService(ctrl)
		jwtService.EXPECT().VerifyToken(validJWT).Return(verifiedClaims(), nil)
		mockflow := mocks.NewMockIFlow(ctrl)

		flowMap := map[string]flow.IFlow{
			"test": mockflow,
		}

		jwtService.EXPECT().GenerateToken(gomock.Any(), gomock.Any()).Return("", errors.New("GenerateToken error"))

		mockflow.EXPECT().Solve(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, &entities.MFAError{
			Code:    "FAILED",
			Message: "Failed to solve",
		})
		mockflow.EXPECT().Validate(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, nil)
		mockflow.EXPECT().GetName().Return("test")
		mockflow.EXPECT().GetChallenges(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return([]string{"dummy"})
		mockflow.EXPECT().GetChallenges(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return([]string{"dummy"})

		mfaService := mfa.NewMFAService(config, jwtService, flowMap)

		result, err := mfaService.Process(context.TODO(), validJWT, "dummy", "{}", false, nil)

		expectedResult := entities.MFAResult{
			Token:      "",
			Challenges: []string{"dummy"},
		}

		a.Error(err)
		a.Equal("GenerateToken error", err.Error())
		a.Equal(expectedResult, *result)
	})

	t.Run("MFA_Request_handle_reference", func(t *testing.T) {
		validJWT := "nil.eyJmbG93IjoidGVzdCIsImNoYWxsZW5nZXMiOnsiZHVtbXkiOnsic3RhdHVzIjoicGVuZGluZyJ9fX0."
		a := assert.New(t)
		ctrl := gomock.NewController(t)
		config := entities.Config{}
		jwtService := mocks.NewMockIJWTService(ctrl)
		mockflow := mocks.NewMockIFlow(ctrl)

		flowMap := map[string]flow.IFlow{
			"test": mockflow,
		}

		jwtService.EXPECT().GenerateToken(gomock.Any(), gomock.Any()).Return(validJWT, nil)

		mockflow.EXPECT().GetChallenges(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return([]string{"dummy"})
		mockflow.EXPECT().GetName().Return("test")
		mockflow.EXPECT().GetChallenges(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return([]string{"dummy"})
		mockflow.EXPECT().GetChallenges(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return([]string{"dummy"})
		mockflow.EXPECT().Initialize(gomock.Any()).Return(&JWTEntities.JWTAdditions{
			Identifier: "",
			Type:       "",
			Meta:       []JWTEntities.Meta{},
		}, nil)
		emptyString := ""
		mockflow.EXPECT().GetIdentifier(gomock.Any()).Return(&emptyString)

		mfaService := mfa.NewMFAService(config, jwtService, flowMap)

		result, err := mfaService.Request(context.TODO(), "test", nil)

		expectedResult := entities.MFAResult{
			Token:      validJWT,
			Challenges: []string{"dummy"},
		}

		a.NoError(err)

		a.Equal(expectedResult, *result)
	})

	t.Run("MFA_Request_handle_error", func(t *testing.T) {
		a := assert.New(t)
		ctrl := gomock.NewController(t)
		config := entities.Config{}
		jwtService := mocks.NewMockIJWTService(ctrl)
		mockflow := mocks.NewMockIFlow(ctrl)

		flowMap := map[string]flow.IFlow{
			"test": mockflow,
		}

		mockflow.EXPECT().GetChallenges(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return([]string{"dummy"})

		mockflow.EXPECT().Initialize(gomock.Any()).Return(&JWTEntities.JWTAdditions{
			Identifier: "",
			Type:       "",
			Meta:       []JWTEntities.Meta{},
		}, errors.New("initialize error"))

		mfaService := mfa.NewMFAService(config, jwtService, flowMap)

		result, err := mfaService.Request(context.TODO(), "test", nil)

		a.Error(err)
		a.Equal("initialize error", err.Error())
		a.Nil(result)
	})
	t.Run("MFA_Request_handle_jwt_error", func(t *testing.T) {
		validJWT := "nil.eyJmbG93IjoidGVzdCIsImNoYWxsZW5nZXMiOnsiZHVtbXkiOnsic3RhdHVzIjoicGVuZGluZyJ9fX0."
		a := assert.New(t)
		ctrl := gomock.NewController(t)
		config := entities.Config{}
		jwtService := mocks.NewMockIJWTService(ctrl)
		mockflow := mocks.NewMockIFlow(ctrl)

		flowMap := map[string]flow.IFlow{
			"test": mockflow,
		}

		jwtService.EXPECT().GenerateToken(gomock.Any(), gomock.Any()).Return(validJWT, errors.New("failed"))

		mockflow.EXPECT().GetName().Return("test")
		mockflow.EXPECT().GetChallenges(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return([]string{"dummy"})
		mockflow.EXPECT().GetChallenges(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return([]string{"dummy"})
		mockflow.EXPECT().Initialize(gomock.Any()).Return(&JWTEntities.JWTAdditions{
			Identifier: "",
			Type:       "",
			Meta:       []JWTEntities.Meta{},
		}, nil)
		emptyString := ""
		mockflow.EXPECT().GetIdentifier(gomock.Any()).Return(&emptyString)

		mfaService := mfa.NewMFAService(config, jwtService, flowMap)

		result, err := mfaService.Request(context.TODO(), "test", nil)

		a.Error(err)
		a.Equal("failed", err.Error())
		a.Nil(result)
	})

	t.Run("MFA_Request_PassAdditional", func(t *testing.T) {
		validJWT := "nil.eyJmbG93IjoidGVzdCIsImNoYWxsZW5nZXMiOnsiZHVtbXkiOnsic3RhdHVzIjoicGVuZGluZyJ9fSwiaWRlbnRpZmllciI6ImlkZW50aWZpZXIiLCJ0eXBlIjoic29tZXR5cGUiLCJtZXRhIjpbeyJrZXkiOiJtZXRha2V5IiwidmFsdWUiOiJtdWNoTWV0YSJ9XX0."
		a := assert.New(t)
		ctrl := gomock.NewController(t)
		config := entities.Config{}
		jwtService := mocks.NewMockIJWTService(ctrl)
		mockflow := mocks.NewMockIFlow(ctrl)

		flowMap := map[string]flow.IFlow{
			"test": mockflow,
		}

		identifier := "identifier"
		jwtService.EXPECT().GenerateToken(entities.JWTData{
			Flow: "test",
			Challenges: map[string]entities.Challenge{
				"dummy": {
					Status: "PENDING",
				},
			},
			Identifier: &identifier,
			Type:       "sometype",
			Meta: []JWTEntities.Meta{
				{
					Key:   "metakey",
					Value: "muchMeta",
				},
			},
		}, gomock.Any()).Return(validJWT, nil)

		mockflow.EXPECT().GetChallenges(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return([]string{"dummy"})
		mockflow.EXPECT().GetName().Return("test")
		mockflow.EXPECT().GetChallenges(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return([]string{"dummy"})
		mockflow.EXPECT().GetChallenges(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return([]string{"dummy"})
		mockflow.EXPECT().Initialize(gomock.Any()).Return(&JWTEntities.JWTAdditions{
			Identifier: "identifier",
			Type:       "sometype",
			Meta: []JWTEntities.Meta{
				{
					Key:   "metakey",
					Value: "muchMeta",
				},
			},
		}, nil)
		mockflow.EXPECT().GetIdentifier(gomock.Any()).Return(&identifier)

		mfaService := mfa.NewMFAService(config, jwtService, flowMap)

		result, err := mfaService.Request(context.TODO(), "test", nil)

		expectedResult := entities.MFAResult{
			Token:      validJWT,
			Challenges: []string{"dummy"},
			Metadata:   nil,
		}

		var decodedJWT entities.JWTData
		base64Claims := strings.Split(result.Token, ".")

		claimsJson, _ := base64.StdEncoding.WithPadding(base64.NoPadding).DecodeString(base64Claims[1])
		_ = json.Unmarshal(claimsJson, &decodedJWT)

		a.Equal("identifier", *decodedJWT.Identifier)
		a.Equal("metakey", decodedJWT.Meta[0].Key)

		a.NoError(err)
		a.Equal(expectedResult, *result)
	})

	t.Run("MFA_Process_request_error", func(t *testing.T) {
		validJWT := "nil.eyJmbG93IjoidGVzdCIsImNoYWxsZW5nZXMiOnsiZHVtbXkiOnsic3RhdHVzIjoicGVuZGluZyJ9fX0."
		a := assert.New(t)
		ctrl := gomock.NewController(t)
		config := entities.Config{}
		jwtService := mocks.NewMockIJWTService(ctrl)
		jwtService.EXPECT().VerifyToken(validJWT).Return(verifiedClaims(), nil)
		mockflow := mocks.NewMockIFlow(ctrl)

		flowMap := map[string]flow.IFlow{
			"test": mockflow,
		}

		jwtService.EXPECT().GenerateToken(gomock.Any(), gomock.Any()).Return(validJWT, nil)

		mockflow.EXPECT().Request(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, &entities.MFAError{
			Code:     "ERROR",
			Message:  "error",
			Metadata: nil,
		})
		mockflow.EXPECT().Validate(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, nil)
		mockflow.EXPECT().GetName().Return("test")
		mockflow.EXPECT().GetChallenges(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return([]string{"dummy"})
		mockflow.EXPECT().GetChallenges(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return([]string{"dummy"})

		mfaService := mfa.NewMFAService(config, jwtService, flowMap)

		result, err := mfaService.Process(context.TODO(), validJWT, "dummy", "{}", true, nil)

		expectedResult := entities.MFAResult{
			Token:      validJWT,
			Challenges: []string{"dummy"},
			Metadata:   nil,
		}

		a.Error(err)
		a.Equal("error", err.Error())
		a.Equal(expectedResult, *result)
	})

	t.Run("MFA_Process_requestChallenge_handle_jwtError", func(t *testing.T) {
		validJWT := "nil.eyJmbG93IjoidGVzdCIsImNoYWxsZW5nZXMiOnsiZHVtbXkiOnsic3RhdHVzIjoicGVuZGluZyJ9fX0."
		a := assert.New(t)
		ctrl := gomock.NewController(t)
		config := entities.Config{}
		jwtService := mocks.NewMockIJWTService(ctrl)
		jwtService.EXPECT().VerifyToken(validJWT).Return(verifiedClaims(), nil)
		mockflow := mocks.NewMockIFlow(ctrl)

		flowMap := map[string]flow.IFlow{
			"test": mockflow,
		}

		jwtService.EXPECT().GenerateToken(gomock.Any(), gomock.Any()).Return("", errors.New("GenerateToken error"))

		mockflow.EXPECT().Request(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, nil)
		mockflow.EXPECT().Validate(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, nil)
		mockflow.EXPECT().GetName().Return("test")
		mockflow.EXPECT().GetChallenges(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return([]string{"dummy"})
		mockflow.EXPECT().GetChallenges(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return([]string{"dummy"})

		mfaService := mfa.NewMFAService(config, jwtService, flowMap)

		result, err := mfaService.Process(context.TODO(), validJWT, "dummy", "{}", true, nil)

		expectedResult := entities.MFAResult{
			Token:      "",
			Challenges: []string{"dummy"},
			Metadata:   nil,
		}

		a.Error(err)
		a.Equal("GenerateToken error", err.Error())
		a.Equal(expectedResult, *result)
	})

	t.Run("MFA_Process_solve_error", func(t *testing.T) {
		validJWT := "nil.eyJmbG93IjoidGVzdCIsImNoYWxsZW5nZXMiOnsiZHVtbXkiOnsic3RhdHVzIjoicGVuZGluZyJ9fX0."
		a := assert.New(t)
		ctrl := gomock.NewController(t)
		config := entities.Config{}
		jwtService := mocks.NewMockIJWTService(ctrl)
		jwtService.EXPECT().VerifyToken(validJWT).Return(verifiedClaims(), nil)
		mockflow := mocks.NewMockIFlow(ctrl)

		flowMap := map[string]flow.IFlow{
			"test": mockflow,
		}

		jwtService.EXPECT().GenerateToken(gomock.Any(), gomock.Any()).Return(validJWT, nil)

		mockflow.EXPECT().Solve(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, nil)
		mockflow.EXPECT().Validate(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, nil)
		mockflow.EXPECT().GetName().Return("test")
		mockflow.EXPECT().GetChallenges(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return([]string{"dummy"})
		mockflow.EXPECT().GetChallenges(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return([]string{"dummy"})
		mockflow.EXPECT().Resolve(gomock.Any()).Return(nil, errors.New("Failed to resolve"))

		mfaService := mfa.NewMFAService(config, jwtService, flowMap)

		result, err := mfaService.Process(context.TODO(), validJWT, "dummy", "{}", false, nil)

		nullMetadata := "null"
		expectedResult := entities.MFAResult{
			Token:      validJWT,
			Challenges: []string{"dummy"},
			Metadata:   &nullMetadata,
		}

		a.Error(err)
		a.Equal("Failed to resolve", err.Error())
		a.Equal(expectedResult, *result)
	})

	t.Run("MFA_Process_solve_no_token", func(t *testing.T) {
		validJWT := "nil.eyJmbG93IjoidGVzdCIsImNoYWxsZW5nZXMiOnsiZHVtbXkiOnsic3RhdHVzIjoicGVuZGluZyJ9fX0."
		a := assert.New(t)
		ctrl := gomock.NewController(t)
		config := entities.Config{}
		jwtService := mocks.NewMockIJWTService(ctrl)
		jwtService.EXPECT().VerifyToken(validJWT).Return(verifiedClaims(), nil)
		mockflow := mocks.NewMockIFlow(ctrl)

		flowMap := map[string]flow.IFlow{
			"test": mockflow,
		}

		jwtService.EXPECT().GenerateToken(gomock.Any(), gomock.Any()).Return(validJWT, nil)

		mockflow.EXPECT().Solve(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, nil)
		mockflow.EXPECT().Validate(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, nil)
		mockflow.EXPECT().GetName().Return("test")
		mockflow.EXPECT().GetChallenges(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return([]string{"dummy"})
		mockflow.EXPECT().GetChallenges(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return([]string{"dummy"})
		mockflow.EXPECT().Resolve(gomock.Any()).Return(&map[string]interface{}{}, nil)

		mfaService := mfa.NewMFAService(config, jwtService, flowMap)

		result, err := mfaService.Process(context.TODO(), validJWT, "dummy", "{}", false, nil)

		nullMetadata := "null"
		expectedResult := entities.MFAResult{
			Token:      validJWT,
			Challenges: []string{"dummy"},
			Metadata:   &nullMetadata,
		}

		a.Error(err)
		a.Equal("unable to resolve flow", err.Error())
		a.Equal(expectedResult, *result)
	})

	t.Run("MFA_Process_Solve_plain_error", func(t *testing.T) {
		validJWT := "token"
		a := assert.New(t)
		ctrl := gomock.NewController(t)
		config := entities.Config{}
		jwtService := mocks.NewMockIJWTService(ctrl)
		jwtService.EXPECT().VerifyToken(validJWT).Return(verifiedClaims(), nil)
		mockflow := mocks.NewMockIFlow(ctrl)

		flowMap := map[string]flow.IFlow{
			"test": mockflow,
		}

		jwtService.EXPECT().GenerateToken(failedClaims(), gomock.Any()).Return(validJWT, nil)

		mockflow.EXPECT().Solve(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, errors.New("plain error"))
		mockflow.EXPECT().Validate(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, nil)
		mockflow.EXPECT().GetName().Return("test")
		mockflow.EXPECT().GetChallenges(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return([]string{"dummy"})
		mockflow.EXPECT().GetChallenges(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return([]string{"dummy"})

		mfaService := mfa.NewMFAService(config, jwtService, flowMap)

		result, err := mfaService.Process(context.TODO(), validJWT, "dummy", "{}", false, nil)

		a.Error(err)
		a.Equal("plain error", err.Error())
		a.Equal(entities.MFAResult{Token: validJWT, Challenges: []string{"dummy"}}, *result)
	})

	t.Run("MFA_Process_Request_plain_error", func(t *testing.T) {
		validJWT := "token"
		a := assert.New(t)
		ctrl := gomock.NewController(t)
		config := entities.Config{}
		jwtService := mocks.NewMockIJWTService(ctrl)
		jwtService.EXPECT().VerifyToken(validJWT).Return(verifiedClaims(), nil)
		mockflow := mocks.NewMockIFlow(ctrl)

		flowMap := map[string]flow.IFlow{
			"test": mockflow,
		}

		jwtService.EXPECT().GenerateToken(failedClaims(), gomock.Any()).Return(validJWT, nil)

		mockflow.EXPECT().Request(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, errors.New("plain error"))
		mockflow.EXPECT().Validate(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, nil)
		mockflow.EXPECT().GetName().Return("test")
		mockflow.EXPECT().GetChallenges(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return([]string{"dummy"})
		mockflow.EXPECT().GetChallenges(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return([]string{"dummy"})

		mfaService := mfa.NewMFAService(config, jwtService, flowMap)

		result, err := mfaService.Process(context.TODO(), validJWT, "dummy", "{}", true, nil)

		a.Error(err)
		a.Equal("plain error", err.Error())
		a.Equal(entities.MFAResult{Token: validJWT, Challenges: []string{"dummy"}}, *result)
	})

	t.Run("MFA_Process_Request_value_MFAError", func(t *testing.T) {
		validJWT := "token"
		a := assert.New(t)
		ctrl := gomock.NewController(t)
		config := entities.Config{}
		jwtService := mocks.NewMockIJWTService(ctrl)
		jwtService.EXPECT().VerifyToken(validJWT).Return(verifiedClaims(), nil)
		mockflow := mocks.NewMockIFlow(ctrl)

		flowMap := map[string]flow.IFlow{
			"test": mockflow,
		}

		jwtService.EXPECT().GenerateToken(entities.JWTData{
			Flow: "test",
			Challenges: map[string]entities.Challenge{
				"dummy": {Status: "LOCKED"},
			},
		}, gomock.Any()).Return(validJWT, nil)

		mockflow.EXPECT().Request(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, entities.MFAError{
			Code:    "LOCKED",
			Message: "locked",
		})
		mockflow.EXPECT().Validate(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, nil)
		mockflow.EXPECT().GetName().Return("test")
		mockflow.EXPECT().GetChallenges(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return([]string{"dummy"})
		mockflow.EXPECT().GetChallenges(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return([]string{"dummy"})

		mfaService := mfa.NewMFAService(config, jwtService, flowMap)

		_, err := mfaService.Process(context.TODO(), validJWT, "dummy", "{}", true, nil)

		a.Error(err)
		a.Equal("locked", err.Error())
	})

	t.Run("MFA_Process_Request_missing_reference", func(t *testing.T) {
		validJWT := "token"
		a := assert.New(t)
		ctrl := gomock.NewController(t)
		config := entities.Config{}
		jwtService := mocks.NewMockIJWTService(ctrl)
		jwtService.EXPECT().VerifyToken(validJWT).Return(verifiedClaims(), nil)
		mockflow := mocks.NewMockIFlow(ctrl)

		flowMap := map[string]flow.IFlow{
			"test": mockflow,
		}

		jwtService.EXPECT().GenerateToken(gomock.Any(), gomock.Any()).Return(validJWT, nil)

		mockflow.EXPECT().Request(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(&map[string]interface{}{
			"Reference": 42,
		}, nil)
		mockflow.EXPECT().Validate(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, nil)
		mockflow.EXPECT().GetName().Return("test")
		mockflow.EXPECT().GetChallenges(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return([]string{"dummy"})
		mockflow.EXPECT().GetChallenges(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return([]string{"dummy"})

		mfaService := mfa.NewMFAService(config, jwtService, flowMap)

		result, err := mfaService.Process(context.TODO(), validJWT, "dummy", "{}", true, nil)

		a.Error(err)
		a.Equal("challenge request did not return a reference", err.Error())
		a.Equal(entities.MFAResult{Token: validJWT, Challenges: []string{"dummy"}}, *result)
	})

	t.Run("MFA_Process_solve_non_string_token", func(t *testing.T) {
		validJWT := "token"
		a := assert.New(t)
		ctrl := gomock.NewController(t)
		config := entities.Config{}
		jwtService := mocks.NewMockIJWTService(ctrl)
		jwtService.EXPECT().VerifyToken(validJWT).Return(verifiedClaims(), nil)
		mockflow := mocks.NewMockIFlow(ctrl)

		flowMap := map[string]flow.IFlow{
			"test": mockflow,
		}

		jwtService.EXPECT().GenerateToken(gomock.Any(), gomock.Any()).Return(validJWT, nil)

		mockflow.EXPECT().Solve(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, nil)
		mockflow.EXPECT().Validate(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, nil)
		mockflow.EXPECT().GetName().Return("test")
		mockflow.EXPECT().GetChallenges(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return([]string{"dummy"})
		mockflow.EXPECT().GetChallenges(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return([]string{"dummy"})
		mockflow.EXPECT().Resolve(gomock.Any()).Return(&map[string]interface{}{
			"token": 42,
		}, nil)

		mfaService := mfa.NewMFAService(config, jwtService, flowMap)

		result, err := mfaService.Process(context.TODO(), validJWT, "dummy", "{}", false, nil)

		nullMetadata := "null"
		a.Error(err)
		a.Equal("unable to resolve flow", err.Error())
		a.Equal(entities.MFAResult{Token: validJWT, Challenges: []string{"dummy"}, Metadata: &nullMetadata}, *result)
	})
}

// verifiedClaims returns the claims that a mocked VerifyToken returns for a valid token.
func verifiedClaims() *entities.JWTData {
	return &entities.JWTData{
		Flow: "test",
		Challenges: map[string]entities.Challenge{
			"dummy": {Status: "pending"},
		},
	}
}

// failedClaims returns the claims that the service signs after the dummy challenge failed.
func failedClaims() entities.JWTData {
	return entities.JWTData{
		Flow: "test",
		Challenges: map[string]entities.Challenge{
			"dummy": {Status: entities.StatusFailed},
		},
	}
}
