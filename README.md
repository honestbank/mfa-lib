# mfa-lib

This library serves to provide a simple way to do MFA flows without having to think of previous challenges.

There are 2 parts: Flows, and Challenges.

<!-- toc -->

- [Challenges](#challenges)
  * [Solve](#solve)
  * [Request](#request)
  * [Initializing a Challenge](#initializing-a-challenge)
- [Flows](#flows)
  * [Initialize](#initialize)
  * [Validate](#validate)
  * [Resolve](#resolve)
- [MFA Service](#mfa-service)
  * [Graphql](#graphql)

<!-- tocstop -->

## Challenges

Challenges do not have any predefined functions but require a `Solve` and `Request` function.

```go
package challenge

type IChallenge interface {
	Solve(body map[string]interface{}) (*map[string]interface{}, error)
	// Request a challenge, ex: for OTP you have to request an OTP before you can solve it
	Request(body map[string]interface{}) (*map[string]interface{}, error)
}

```

### Solve

The `Solve` function is called when the user is trying to solve the challenge. It accepts a body which is the input
passed from the user.

```go
func (c *DummyChallenge) Solve(body map[string]interface{}) (*map[string]interface{}, error) {
log.Println("seed:", c.Seed)
log.Println("password:", body["password"])
if body["username"] == "admin" && body["password"].(string) == c.Seed {
return nil, nil
}
return nil, errors.New("failed!")
}
```

The input passed above would be:

```json
{
  "username": "admin",
  "password": "123456"
}
```

If the input matches, we can assume all is good. We may also pass back some data to the user which will show up as
Metadata in MFAResult.

### Request

The `Request` function is called when the user is trying to request a challenge. It accepts a body which is the input
passed from the user (if any).

```go
func (c *DummyChallenge) Request(body map[string]interface{}) (*map[string]interface{}, error) {
rand.Seed(time.Now().UnixNano())
c.Seed = randSeq(10)
log.Println("Seed:", c.Seed)
return &map[string]interface{}{
"Reference": c.Seed,
}, nil
}
```

In the above example, we generate a random string and return it as the `Reference` field which can later be used to
solve the challenge.

### Initializing a Challenge

```go
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
	log.Println("password:", body["password"])
	if body["username"] == "admin" && body["password"].(string) == c.Seed {
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
```
In above example, we define `Solve` and `Request` functions for the challenge as well as
some other functions which the challenge will use. It is up to the developer on what the
challenge does.

## Flows
Flows define the order in which challenges are asked. By default, these are in the order they are defined.
To define a Flow, you must have already defined a Challenge.
A flow has some predefined functions: `GetName`,`Solve`, `Request`, and `GetChallenges`.
These functions are called by MFA service and do not need to be changed.

You, the developer, need to define `Resolve`, `Validate`, `Initialize`.

### Initialize
This initializes the flow and consumes a context. From here you should be able to define additional
JWT data that you wish to append to all requests. It requires you pass an `Identifier`, `Type` (type
f the identifier), and `Meta` (metadata you wish to add).

```go
func (f SingleFlow) Initialize(ctx context.Context) (*JWTEntities.JWTAdditions, error) {
	return &JWTEntities.JWTAdditions{
		Identifier: ctx.Value("identifier").(string),
		Type:       ctx.Value("type").(string),
		Meta:       []JWTEntities.Meta{},
	}, nil
}
```

### Validate
The `Validate` function is called to verify that a certain challenge is available to be called.
This defines the flow and allows when user is available to skip certain challenges. Context,
challenge name, and JWTData is passed to the function.

```go
func (f SingleFlow) Validate(ctx context.Context, challenge string, JWTData mfaEntities.JWTData) error {
	// can only take dummy2 if dummy is done
	if challenge == "dummy2" && JWTData.Challenges["dummy"].Status == "pending" {
        return errors.New("dummy challenge is not available")
    }
	return nil
}
```

### Resolve
This is the final function and is where you will return what was initially asked for whether it is a
JWT token, or just a confirmation of an action. You are able to pass any other data back, which will
end up in the MFAResult object.

```go
func (f SingleFlow) Resolve(jwtData mfaEntities.JWTData) (*map[string]interface{}, error) {
	return &map[string]interface{}{
		"token": "new_token",
	}, nil
}
```

## MFA Service
Given the above has been done, calling the MFA service is really simple and only requires 2 functions:

**Reqest first challenge of the flow**
```go
// Request the first challenge
res, err := mfaService.Request(context.TODO(), "single_flow_single_challenge")
```

**Attmept to solve the challenge**

```go
// Attempt to solve the challenge
res, err = mfaService.Process(context.TODO(), jwt, "dummy", fail, false)
```

**Reqest the next challenge**
```go
// Request the next challenge
res, err = mfaService.Process(context.TODO(), jwt, "dummy2", pass, true)
```

see example in `examples/single_flow_multiple_challenges`

### Graphql
For use with graphql, it is the same as above however have your resolvers call the respective functions
