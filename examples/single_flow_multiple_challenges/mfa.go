package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"strings"
	"time"

	"github.com/honestbank/mfa-lib/examples/single_flow_multiple_challenges/flows"
	"github.com/honestbank/mfa-lib/flow"
	"github.com/honestbank/mfa-lib/mfa"
	"github.com/honestbank/mfa-lib/mfa/entities"
)

// The demo JWT service signs tokens with HMAC-SHA256 and a random key that it creates at
// startup. Production code must sign with asymmetric keys from its key service and must
// never use a shared demo secret.
const (
	demoAudience = "mfa-lib-example"
	demoTokenTTL = 15 * time.Minute
)

// demoHeader is the only header that the demo JWT service accepts. VerifyToken never reads
// the alg from the token.
var demoHeader = base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))

type demoClaims struct {
	entities.JWTData
	Audience  string `json:"aud"`
	ExpiresAt int64  `json:"exp"`
}

type JwtService struct {
	secret []byte
}

func NewJwtService() *JwtService {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		panic(err)
	}

	return &JwtService{secret: secret}
}

func (j *JwtService) sign(signingInput string) []byte {
	mac := hmac.New(sha256.New, j.secret)
	mac.Write([]byte(signingInput))

	return mac.Sum(nil)
}

func (j *JwtService) GenerateToken(claims entities.JWTData, scopes []string) (string, error) {
	claimsJSON, err := json.Marshal(demoClaims{
		JWTData:   claims,
		Audience:  demoAudience,
		ExpiresAt: time.Now().Add(demoTokenTTL).Unix(),
	})
	if err != nil {
		return "", err
	}
	signingInput := demoHeader + "." + base64.RawURLEncoding.EncodeToString(claimsJSON)

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(j.sign(signingInput)), nil
}

func (j *JwtService) VerifyToken(token string) (*entities.JWTData, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] != demoHeader {
		return nil, errors.New("invalid JWT")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, errors.New("invalid JWT")
	}
	// hmac.Equal compares in constant time.
	if !hmac.Equal(signature, j.sign(parts[0]+"."+parts[1])) {
		return nil, errors.New("invalid JWT signature")
	}
	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("invalid JWT")
	}
	var claims demoClaims
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return nil, errors.New("invalid JWT")
	}
	if claims.Audience != demoAudience {
		return nil, errors.New("invalid JWT audience")
	}
	if time.Now().Unix() >= claims.ExpiresAt {
		return nil, errors.New("JWT expired")
	}

	return &claims.JWTData, nil
}

func main() {
	var jwt string

	config := entities.Config{}
	jwtService := NewJwtService()

	mfaService := mfa.NewMFAService(config, jwtService, map[string]flow.IFlow{
		"single_flow_single_challenge": flows.NewSingleFlow(),
	})

	res, err := mfaService.Request(context.TODO(), "single_flow_single_challenge", nil)
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

	jwt = res.Token
	res, err = mfaService.Process(context.TODO(), jwt, "dummy2", pass, true, nil)
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

	res, err = mfaService.Process(context.TODO(), jwt, "dummy2", pass, false, nil)
	if err != nil {
		log.Println("Failed")
	}
	resJSON, _ = json.Marshal(*res)
	log.Println(string(resJSON))
}
