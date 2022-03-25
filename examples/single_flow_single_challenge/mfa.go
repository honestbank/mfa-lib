package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"log"

	"github.com/honestbank/mfa-lib/examples/single_flow_single_challenge/flows"
	"github.com/honestbank/mfa-lib/flow"
	"github.com/honestbank/mfa-lib/mfa"
	"github.com/honestbank/mfa-lib/mfa/entities"
)

type JwtService struct {
}

func (j *JwtService) GenerateToken(claims entities.JWTData, scopes []string) (string, error) {
	claimsJSON, _ := json.Marshal(claims)
	return "nil." + base64.StdEncoding.EncodeToString(claimsJSON) + ".", nil
}

func main() {
	var jwt string

	config := entities.Config{}
	jwtService := &JwtService{}

	// Create a new MFA Service
	mfaService := mfa.NewMFAService(config, jwtService, map[string]flow.IFlow{
		"single_flow_single_challenge": flows.NewSingleFlow(),
	})

	// Request first challenge
	res, err := mfaService.Request(context.TODO(), "single_flow_single_challenge")
	if err != nil {
		panic(err)
	}
	resJSON, _ := json.Marshal(*res)
	log.Println(string(resJSON))

	jwt = res.Token

	key := *res.Reference
	pass := "{\"username\": \"admin\", \"password\": \"" + key + "\"}"
	fail := "{}"
	log.Println(pass)
	log.Println(fail)

	// Attempt to solve
	res, err = mfaService.Process(context.TODO(), jwt, "dummy", fail, false, nil)
	if err != nil {
		log.Println("Failed")
	}
	resJSON, _ = json.Marshal(*res)
	log.Println(string(resJSON))
	jwt = res.Token

	res, err = mfaService.Process(context.TODO(), jwt, "dummy", pass, false, nil)
	if err != nil {
		log.Println("Failed")
	}
	resJSON, _ = json.Marshal(*res)
	log.Println(string(resJSON))

}
