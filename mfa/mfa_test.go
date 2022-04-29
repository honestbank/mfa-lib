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
		mockflow := mocks.NewMockIFlow(ctrl)

		jwtService.EXPECT().GenerateToken(gomock.Any(), gomock.Any()).Return(validJWT, nil)

		mockflow.EXPECT().Request(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, nil)
		mockflow.EXPECT().Validate(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, nil)
		mockflow.EXPECT().GetName().Return("test")
		mockflow.EXPECT().GetChallenges(gomock.Any(), gomock.Any(), gomock.Any()).Return([]string{"dummy"})
		mockflow.EXPECT().GetChallenges(gomock.Any(), gomock.Any(), gomock.Any()).Return([]string{"dummy"})

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

	t.Run("MFA_Process_invalid_jwt", func(t *testing.T) {
		a := assert.New(t)
		ctrl := gomock.NewController(t)
		config := entities.Config{}
		jwtService := mocks.NewMockIJWTService(ctrl)
		mockflow := mocks.NewMockIFlow(ctrl)

		flowMap := map[string]flow.IFlow{
			"test": mockflow,
		}

		mfaService := mfa.NewMFAService(config, jwtService, flowMap)

		result, err := mfaService.Process(context.TODO(), "", "dummy", "{}", true, nil)

		a.Error(err)
		a.Equal("Invalid JWT", err.Error())
		a.Nil(result)
	})

	t.Run("MFA_Process_invalid_jwt", func(t *testing.T) {
		invalidJWT := "nil.eyJmbG93IjoidGVzdCIsImNoYWxsZW5nZXMiOnsiZHVtbXkiOnsic3RhdHVzIjoicGVuZGluZyJ9fQ."
		a := assert.New(t)
		ctrl := gomock.NewController(t)
		config := entities.Config{}
		jwtService := mocks.NewMockIJWTService(ctrl)
		mockflow := mocks.NewMockIFlow(ctrl)

		flowMap := map[string]flow.IFlow{
			"test": mockflow,
		}

		mfaService := mfa.NewMFAService(config, jwtService, flowMap)

		result, err := mfaService.Process(context.TODO(), invalidJWT, "dummy", "{}", true, nil)

		a.Error(err)
		a.Equal("unexpected end of JSON input", err.Error())
		a.Nil(result)
	})

	t.Run("MFA_Process_HandleSolve", func(t *testing.T) {
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

		mockflow.EXPECT().Solve(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, nil)
		mockflow.EXPECT().Validate(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, nil)
		mockflow.EXPECT().GetName().Return("test")
		mockflow.EXPECT().GetChallenges(gomock.Any(), gomock.Any(), gomock.Any()).Return([]string{"dummy"})
		mockflow.EXPECT().GetChallenges(gomock.Any(), gomock.Any(), gomock.Any()).Return([]string{"dummy"})
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

	t.Run("MFA_Process_Solve_error", func(t *testing.T) {
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

		mockflow.EXPECT().Solve(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, &entities.MFAError{
			Code:    "FAILED",
			Message: "Failed to solve",
		})
		mockflow.EXPECT().Validate(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, nil)
		mockflow.EXPECT().GetName().Return("test")
		mockflow.EXPECT().GetChallenges(gomock.Any(), gomock.Any(), gomock.Any()).Return([]string{"dummy"})
		mockflow.EXPECT().GetChallenges(gomock.Any(), gomock.Any(), gomock.Any()).Return([]string{"dummy"})

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

		mockflow.EXPECT().GetChallenges(gomock.Any(), gomock.Any(), gomock.Any()).Return([]string{"dummy"})
		mockflow.EXPECT().GetName().Return("test")
		mockflow.EXPECT().GetChallenges(gomock.Any(), gomock.Any(), gomock.Any()).Return([]string{"dummy"})
		mockflow.EXPECT().GetChallenges(gomock.Any(), gomock.Any(), gomock.Any()).Return([]string{"dummy"})
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

		mockflow.EXPECT().GetChallenges(gomock.Any(), gomock.Any(), gomock.Any()).Return([]string{"dummy"})

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

		mockflow.EXPECT().GetChallenges(gomock.Any(), gomock.Any(), gomock.Any()).Return([]string{"dummy"})
		mockflow.EXPECT().GetName().Return("test")
		mockflow.EXPECT().GetChallenges(gomock.Any(), gomock.Any(), gomock.Any()).Return([]string{"dummy"})
		mockflow.EXPECT().GetChallenges(gomock.Any(), gomock.Any(), gomock.Any()).Return([]string{"dummy"})
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

	t.Run("MFA_Process_solve_error", func(t *testing.T) {
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

		mockflow.EXPECT().Solve(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, nil)
		mockflow.EXPECT().Validate(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, nil)
		mockflow.EXPECT().GetName().Return("test")
		mockflow.EXPECT().GetChallenges(gomock.Any(), gomock.Any(), gomock.Any()).Return([]string{"dummy"})
		mockflow.EXPECT().GetChallenges(gomock.Any(), gomock.Any(), gomock.Any()).Return([]string{"dummy"})
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
		mockflow := mocks.NewMockIFlow(ctrl)

		flowMap := map[string]flow.IFlow{
			"test": mockflow,
		}

		jwtService.EXPECT().GenerateToken(gomock.Any(), gomock.Any()).Return(validJWT, nil)

		mockflow.EXPECT().Solve(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, nil)
		mockflow.EXPECT().Validate(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, nil)
		mockflow.EXPECT().GetName().Return("test")
		mockflow.EXPECT().GetChallenges(gomock.Any(), gomock.Any(), gomock.Any()).Return([]string{"dummy"})
		mockflow.EXPECT().GetChallenges(gomock.Any(), gomock.Any(), gomock.Any()).Return([]string{"dummy"})
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
		a.Equal("Unable to resolve flow", err.Error())
		a.Equal(expectedResult, *result)
	})
}
