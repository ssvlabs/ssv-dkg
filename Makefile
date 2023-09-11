# This Makefile is meant to be used by people that do not usually work
# with Go source code. If you know what GOPATH is then you probably
# don't need to bother with make.

.PHONY: dkgcli test clean build docker-build

GOBIN = ./build/bin
GO ?= latest
GORUN = env GO111MODULE=on go run
GOINSTALL = env GO111MODULE=on go install -v
GOTEST = env GO111MODULE=on go test -v
# Name of the Go binary output
BINARY_NAME=./bin/dkgcli
# Docker image name
DOCKER_IMAGE=ssv-dkg-tool

install:
	$(GOINSTALL) cmd/dkgcli/dkgcli.go
	@echo "Done building."
	@echo "Run dkgcli to launch the tool."

clean:
	env GO111MODULE=on go clean -cache

# Recipe to compile the Go program
build:
	@echo "Building Go binary..."
	go build -o $(BINARY_NAME) ./cmd/dkgcli/dkgcli.go

# Recipe to run tests
test:
	@echo "running tests"
	go test -p 1 ./...

# Recipe to build the Docker image
docker-build:
	@echo "Building Docker image..."
	docker build -t $(DOCKER_IMAGE) .

docker-demo:
	@echo "Running docker compose demo"
	docker-compose up --build