.PHONY: lint test

# Run golangci-lint on the project
lint:
	@golangci-lint run

# Run tests for the project
test:
	@go test ./...

# If golangci-lint is not installed, you can add an install target:
install-lint:
	@GO111MODULE=off go get -u github.com/golangci/golangci-lint/cmd/golangci-lint
