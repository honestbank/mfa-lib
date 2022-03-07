package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"log"

	"github.com/honestbank/mfa-lib/examples/single_flow_multiple_challenges/flows"
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

	mfaService := mfa.NewMFAService(config, jwtService, map[string]flow.IFlow{
		"single_flow_single_challenge": flows.NewSingleFlow(),
	})

	res, err := mfaService.Request(context.TODO(), "single_flow_single_challenge")
	if err != nil {
		panic(err)
	}
	resJSON, _ := json.Marshal(*res)
	log.Println(string(resJSON))

	key := *res.Reference
	pass := "{\"username\": \"admin\", \"password\": \"" + key + "\"}"
	fail := "{}"
	log.Println(pass)
	log.Println(fail)

	jwt = res.Token
	res, err = mfaService.Process(context.TODO(), jwt, "dummy", fail, false)
	if err != nil {
		log.Println("Failed")
	}
	resJSON, _ = json.Marshal(*res)
	log.Println(string(resJSON))

	jwt = res.Token
	res, err = mfaService.Process(context.TODO(), jwt, "dummy", pass, false)
	if err != nil {
		log.Println("Failed")
	}
	resJSON, _ = json.Marshal(*res)
	log.Println(string(resJSON))

	jwt = res.Token
	res, err = mfaService.Process(context.TODO(), jwt, "dummy2", pass, true)
	if err != nil {
		log.Println("Failed")
	}
	resJSON, _ = json.Marshal(*res)
	log.Println(string(resJSON))
	key = *res.Reference
	pass = "{\"username\": \"admin\", \"password\": \"" + key + "\"}"
	fail = "{}"
	log.Println(pass)
	log.Println(fail)

	res, err = mfaService.Process(context.TODO(), jwt, "dummy2", pass, false)
	if err != nil {
		log.Println("Failed")
	}
	resJSON, _ = json.Marshal(*res)
	log.Println(string(resJSON))

}
