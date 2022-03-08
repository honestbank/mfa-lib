package challenges

import (
	"errors"
	"log"
	"math/rand"
	"time"

	"github.com/honestbank/mfa-lib/challenge"
	"github.com/honestbank/mfa-lib/challenge/entities"
)

var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func randSeq(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

type DummyChallenge struct {
	entities.Challenge
	Seed string `json:"seed"`
}

func (c *DummyChallenge) Solve(body map[string]interface{}) (*map[string]interface{}, error) {
	log.Println("seed:", c.Seed)
	log.Println("password:", body["code"])
	if body["reference"] == c.Seed && body["code"] == "123" {
		return nil, nil
	}
	return nil, errors.New("failed!")
}

func (c *DummyChallenge) Request(body map[string]interface{}) (*map[string]interface{}, error) {
	rand.Seed(time.Now().UnixNano())
	c.Seed = randSeq(10)
	log.Println("Seed:", c.Seed)
	return &map[string]interface{}{
		"Reference": c.Seed,
	}, nil
}

func NewDummyChallenge() challenge.IChallenge {
	dummyChallenge := entities.Challenge{
		Name: "dummy",
	}
	return &DummyChallenge{
		Challenge: dummyChallenge,
	}
}
