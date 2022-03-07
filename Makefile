prepare:
	curl https://pre-commit.com/install-local.py | python3 -
	pre-commit install
	go mod download
	make generate

generate: interface-mocks

interface-mocks:
	go get github.com/golang/mock/mockgen/model
	go install github.com/golang/mock/mockgen@v1.6.0
	mockgen -destination=./mocks/mock_flow.go -package=mocks github.com/honestbank/mfa-lib/flow IFlow
	mockgen -destination=./mocks/mock_challenge.go -package=mocks github.com/honestbank/mfa-lib/challenge IChallenge
	mockgen -destination=./mocks/mock_jwt.go -package=mocks github.com/honestbank/mfa-lib/jwt IJWTService
