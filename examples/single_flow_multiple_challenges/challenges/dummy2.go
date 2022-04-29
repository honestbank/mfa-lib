package challenges

import (
	"context"
	"log"
	"math/rand"
	"time"

	"github.com/honestbank/mfa-lib/challenge"
	"github.com/honestbank/mfa-lib/challenge/entities"
	mfaEntities "github.com/honestbank/mfa-lib/mfa/entities"
)

type DummyTwoChallenge struct {
	entities.Challenge
	Seed string `json:"seed"`
}

func (c *DummyTwoChallenge) Solve(ctx context.Context, body map[string]interface{}) (*map[string]interface{}, error) {
	log.Println("seed:", c.Seed)
	log.Println("password:", body["password"])
	if body["username"] == "admin" && body["password"].(string) == c.Seed {
		return nil, nil
	}
	return nil, &mfaEntities.MFAError{
		Code:    "failed",
		Message: "failed",
	}
}

func (c *DummyTwoChallenge) Request(ctx context.Context, body map[string]interface{}) (*map[string]interface{}, error) {
	rand.Seed(time.Now().UnixNano())
	c.Seed = randSeq(10)
	log.Println("Seed:", c.Seed)
	return &map[string]interface{}{
		"Reference": c.Seed,
	}, nil
}

func NewDummyTwoChallenge() challenge.IChallenge {
	dummyChallenge := entities.Challenge{
		Name: "dummy2",
	}
	return &DummyTwoChallenge{
		Challenge: dummyChallenge,
	}
}
