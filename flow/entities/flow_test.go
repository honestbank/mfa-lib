package entities_test

import (
	"context"
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
		dummyChallenge.EXPECT().GetName().Return("dummy")

		flow := entities.Flow{
			Name: "test",
			Challenges: []challenge.IChallenge{
				dummyChallenge,
			},
		}
		challenges := flow.GetChallenges(nil, nil, true)

		a.Equal(1, len(challenges))
		a.Equal([]string{"dummy"}, challenges)
	})
	t.Run("Solve", func(t *testing.T) {
		a := assert.New(t)
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		dummyChallenge := mocks.NewMockIChallenge(ctrl)
		dummyChallenge.EXPECT().GetName().Return("dummy")

		flow := entities.Flow{
			Name: "test",
			Challenges: []challenge.IChallenge{
				dummyChallenge,
			},
		}

		dummyChallenge.EXPECT().Solve(gomock.Any(), gomock.Any()).Return(nil, nil)

		solved, err := flow.Solve(context.TODO(), "dummy", "{}", mfaEntities.JWTData{
			Flow: "test",
			Challenges: map[string]mfaEntities.Challenge{
				"dummy": {
					Status: "PENDING",
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
		dummyChallenge.EXPECT().GetName().Return("dummy")

		flow := entities.Flow{
			Name: "test",
			Challenges: []challenge.IChallenge{
				dummyChallenge,
			},
		}

		dummyChallenge.EXPECT().Solve(gomock.Any(), gomock.Any()).Return(nil, errors.New("error"))

		solved, err := flow.Solve(context.TODO(), "dummy", "{}", mfaEntities.JWTData{
			Flow: "test",
			Challenges: map[string]mfaEntities.Challenge{
				"dummy": {
					Status: "PENDING",
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
			Challenges: []challenge.IChallenge{
				dummyChallenge,
			},
		}

		solved, err := flow.Solve(context.TODO(), "dummy", "", mfaEntities.JWTData{
			Flow: "test",
			Challenges: map[string]mfaEntities.Challenge{
				"dummy": {
					Status: "PENDING",
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
		dummyChallenge.EXPECT().GetName().Return("dummy")

		flow := entities.Flow{
			Name: "test",
			Challenges: []challenge.IChallenge{
				dummyChallenge,
			},
		}

		solved, err := flow.Solve(context.TODO(), "dummy2", "{}", mfaEntities.JWTData{
			Flow: "test",
			Challenges: map[string]mfaEntities.Challenge{
				"dummy": {
					Status: "PENDING",
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
		dummyChallenge.EXPECT().GetName().Return("dummy")

		flow := entities.Flow{
			Name: "test",
			Challenges: []challenge.IChallenge{
				dummyChallenge,
			},
		}

		dummyChallenge.EXPECT().Request(gomock.Any(), gomock.Any()).Return(nil, nil)

		reqested, err := flow.Request(context.TODO(), "dummy", "{}", mfaEntities.JWTData{
			Flow: "test",
			Challenges: map[string]mfaEntities.Challenge{
				"dummy": {
					Status: "PENDING",
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
		dummyChallenge.EXPECT().GetName().Return("dummy")

		flow := entities.Flow{
			Name: "test",
			Challenges: []challenge.IChallenge{
				dummyChallenge,
			},
		}

		reqested, err := flow.Request(context.TODO(), "dummy2", "{}", mfaEntities.JWTData{
			Flow: "test",
			Challenges: map[string]mfaEntities.Challenge{
				"dummy": {
					Status: "PENDING",
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
			Challenges: []challenge.IChallenge{
				dummyChallenge,
			},
		}

		reqested, err := flow.Request(context.TODO(), "dummy", "", mfaEntities.JWTData{
			Flow: "test",
			Challenges: map[string]mfaEntities.Challenge{
				"dummy": {
					Status: "PENDING",
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
			Challenges: []challenge.IChallenge{
				dummyChallenge,
			},
		}

		name := flow.GetName()

		a.Equal("test", name)
	})

	t.Run("SetIdentifier", func(t *testing.T) {
		a := assert.New(t)

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		dummyChallenge := mocks.NewMockIChallenge(ctrl)

		flow := entities.Flow{
			Name: "test",
			Challenges: []challenge.IChallenge{
				dummyChallenge,
			},
		}

		ctx := flow.SetIdentifier(context.TODO(), "identifier")
		a.Equal("identifier", *flow.GetIdentifier(ctx))
	})

	t.Run("GetIdentifier - fail", func(t *testing.T) {
		a := assert.New(t)

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		dummyChallenge := mocks.NewMockIChallenge(ctrl)

		flow := entities.Flow{
			Name: "test",
			Challenges: []challenge.IChallenge{
				dummyChallenge,
			},
		}

		ctx := context.TODO()
		identifier := flow.GetIdentifier(ctx)
		a.Nil(identifier)
	})

	t.Run("SetJWT", func(t *testing.T) {
		a := assert.New(t)

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		dummyChallenge := mocks.NewMockIChallenge(ctrl)

		flow := entities.Flow{
			Name: "test",
			Challenges: []challenge.IChallenge{
				dummyChallenge,
			},
		}

		ctx := flow.SetJWT(context.TODO(), "identifier")
		a.Equal("identifier", *flow.GetJWT(ctx))
	})

	t.Run("GetJWT - fail", func(t *testing.T) {
		a := assert.New(t)

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		dummyChallenge := mocks.NewMockIChallenge(ctrl)

		flow := entities.Flow{
			Name: "test",
			Challenges: []challenge.IChallenge{
				dummyChallenge,
			},
		}

		ctx := context.TODO()
		jwt := flow.GetJWT(ctx)
		a.Nil(jwt)
	})
}
