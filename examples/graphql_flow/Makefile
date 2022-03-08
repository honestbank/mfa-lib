prepare:
	curl https://pre-commit.com/install-local.py | python3 -
	pre-commit install
	go mod download
	make generate

generate: interface-mocks

interface-mocks:
	go install github.com/golang/mock/mockgen@v1.6.0
	mockgen -destination=./mocks/mock_flow.go -package=mocks github.com/honestbank/mfa-lib/flow IFlow
	mockgen -destination=./mocks/mock_challenge.go -package=mocks github.com/honestbank/mfa-lib/challenge IChallenge
	mockgen -destination=./mocks/mock_jwt.go -package=mocks github.com/honestbank/mfa-lib/jwt IJWTService

gql:
	go get -d github.com/99designs/gqlgen/cmd@v0.15.1
	go run github.com/99designs/gqlgen generate
