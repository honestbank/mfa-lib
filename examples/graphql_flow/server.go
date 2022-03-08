package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/playground"

	"github.com/honestbank/mfa-lib/examples/graphql_flow/flows"
	"github.com/honestbank/mfa-lib/examples/graphql_flow/graph"
	"github.com/honestbank/mfa-lib/examples/graphql_flow/graph/generated"
	"github.com/honestbank/mfa-lib/flow"
	"github.com/honestbank/mfa-lib/mfa"
	"github.com/honestbank/mfa-lib/mfa/entities"
)

const defaultPort = "8080"

type JwtService struct {
}

func (j *JwtService) GenerateToken(claims entities.JWTData, scopes []string) (string, error) {
	claimsJSON, _ := json.Marshal(claims)
	return "nil." + base64.StdEncoding.EncodeToString(claimsJSON) + ".", nil
}

func Handler() func(http.Handler) http.Handler {
	return func(handler http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), "jwt", strings.Replace(r.Header.Get("Authorization"), "Bearer ", "", 1))
			handler.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = defaultPort
	}

	config := entities.Config{}
	jwtService := &JwtService{}

	mfaService := mfa.NewMFAService(config, jwtService, map[string]flow.IFlow{
		"single_flow_single_challenge": flows.NewSingleFlow(),
	})

	srv := handler.NewDefaultServer(generated.NewExecutableSchema(generated.Config{Resolvers: &graph.Resolver{
		MFAService: mfaService,
	}}))

	http.Handle("/", playground.Handler("GraphQL playground", "/query"))
	http.Handle("/query", Handler()(srv))

	log.Printf("connect to http://localhost:%s/ for GraphQL playground", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
