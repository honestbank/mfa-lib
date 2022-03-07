package entities_test

import (
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/honestbank/mfa-lib/challenge"
	"github.com/honestbank/mfa-lib/flow/entities"
	mfaEntities "github.com/honestbank/mfa-lib/mfa/entities"
	"github.com/honestbank/mfa-lib/mocks"
)

func TestFlow_GetChallenges(t *testing.T) {
	t.Run("GetChallenges", func(t *testing.T) {
		a := assert.New(t)
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		dummyChallenge := mocks.NewMockIChallenge(ctrl)

		flow := entities.Flow{
			Name: "test",
			Challenges: map[string]challenge.IChallenge{
				"dummy": dummyChallenge,
			},
		}
		challenges := flow.GetChallenges()

		a.Equal(1, len(challenges))
		a.Equal([]string{"dummy"}, challenges)
	})
	t.Run("Solve", func(t *testing.T) {
		a := assert.New(t)
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		dummyChallenge := mocks.NewMockIChallenge(ctrl)

		flow := entities.Flow{
			Name: "test",
			Challenges: map[string]challenge.IChallenge{
				"dummy": dummyChallenge,
			},
		}

		dummyChallenge.EXPECT().Solve(gomock.Any()).Return(nil, nil)

		solved, err := flow.Solve("dummy", "{}", mfaEntities.JWTData{
			Flow: "test",
			Challenges: map[string]mfaEntities.Challenge{
				"dummy": {
					Status: "pending",
				},
			},
		})
		a.Nil(solved)
		a.NoError(err)
	})

	t.Run("Solve_Error", func(t *testing.T) {
		a := assert.New(t)
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		dummyChallenge := mocks.NewMockIChallenge(ctrl)

		flow := entities.Flow{
			Name: "test",
			Challenges: map[string]challenge.IChallenge{
				"dummy": dummyChallenge,
			},
		}

		dummyChallenge.EXPECT().Solve(gomock.Any()).Return(nil, errors.New("error"))

		solved, err := flow.Solve("dummy", "{}", mfaEntities.JWTData{
			Flow: "test",
			Challenges: map[string]mfaEntities.Challenge{
				"dummy": {
					Status: "pending",
				},
			},
		})
		a.Nil(solved)
		a.Error(err)
	})

	t.Run("Solve_MarshalError", func(t *testing.T) {
		a := assert.New(t)
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		dummyChallenge := mocks.NewMockIChallenge(ctrl)

		flow := entities.Flow{
			Name: "test",
			Challenges: map[string]challenge.IChallenge{
				"dummy": dummyChallenge,
			},
		}

		solved, err := flow.Solve("dummy", "", mfaEntities.JWTData{
			Flow: "test",
			Challenges: map[string]mfaEntities.Challenge{
				"dummy": {
					Status: "pending",
				},
			},
		})
		a.Nil(solved)
		a.Error(err)
	})

	t.Run("Solve_ChallengeNotFound", func(t *testing.T) {
		a := assert.New(t)
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		dummyChallenge := mocks.NewMockIChallenge(ctrl)

		flow := entities.Flow{
			Name: "test",
			Challenges: map[string]challenge.IChallenge{
				"dummy": dummyChallenge,
			},
		}

		solved, err := flow.Solve("dummy2", "{}", mfaEntities.JWTData{
			Flow: "test",
			Challenges: map[string]mfaEntities.Challenge{
				"dummy": {
					Status: "pending",
				},
			},
		})
		a.Nil(solved)
		a.Error(err)
	})

	t.Run("Request", func(t *testing.T) {
		a := assert.New(t)
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		dummyChallenge := mocks.NewMockIChallenge(ctrl)

		flow := entities.Flow{
			Name: "test",
			Challenges: map[string]challenge.IChallenge{
				"dummy": dummyChallenge,
			},
		}

		dummyChallenge.EXPECT().Request(gomock.Any()).Return(nil, nil)

		reqested, err := flow.Request("dummy", "{}", mfaEntities.JWTData{
			Flow: "test",
			Challenges: map[string]mfaEntities.Challenge{
				"dummy": {
					Status: "pending",
				},
			},
		})

		a.NoError(err)
		a.Nil(reqested)
	})

	t.Run("Request_ChallengeNotFound", func(t *testing.T) {
		a := assert.New(t)
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		dummyChallenge := mocks.NewMockIChallenge(ctrl)

		flow := entities.Flow{
			Name: "test",
			Challenges: map[string]challenge.IChallenge{
				"dummy": dummyChallenge,
			},
		}

		reqested, err := flow.Request("dummy2", "{}", mfaEntities.JWTData{
			Flow: "test",
			Challenges: map[string]mfaEntities.Challenge{
				"dummy": {
					Status: "pending",
				},
			},
		})

		a.Error(err)
		a.Nil(reqested)
	})

	t.Run("Request_MarshalError", func(t *testing.T) {
		a := assert.New(t)
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		dummyChallenge := mocks.NewMockIChallenge(ctrl)

		flow := entities.Flow{
			Name: "test",
			Challenges: map[string]challenge.IChallenge{
				"dummy": dummyChallenge,
			},
		}

		reqested, err := flow.Request("dummy", "", mfaEntities.JWTData{
			Flow: "test",
			Challenges: map[string]mfaEntities.Challenge{
				"dummy": {
					Status: "pending",
				},
			},
		})

		a.Error(err)
		a.Nil(reqested)
	})

	t.Run("GetName", func(t *testing.T) {
		a := assert.New(t)
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		dummyChallenge := mocks.NewMockIChallenge(ctrl)

		flow := entities.Flow{
			Name: "test",
			Challenges: map[string]challenge.IChallenge{
				"dummy": dummyChallenge,
			},
		}

		name := flow.GetName()

		a.Equal("test", name)
	})
}
