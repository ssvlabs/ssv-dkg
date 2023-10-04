# This Makefile is meant to be used by people that do not usually work
# with Go source code. If you know what GOPATH is then you probably
# don't need to bother with make.

.PHONY: install clean build test docker-build-image docker-operators docker-initiator mockgen-install lint-prepare lint

GOBIN = ./build/bin
GO ?= latest
GORUN = env GO111MODULE=on go run
GOINSTALL = env GO111MODULE=on go install -v
GOTEST = env GO111MODULE=on go test -v
# Name of the Go binary output
BINARY_NAME=./bin/ssv-dkg
# Docker image name
DOCKER_IMAGE=ssv-dkg

install:
	$(GOINSTALL) cmd/ssv-dkg/ssv-dkg.go
	@echo "Done building."
	@echo "Run ssv-dkg to launch the tool."

clean:
	env GO111MODULE=on go clean -cache

# Recipe to compile the Go program
build:
	@echo "Building Go binary..."
	go build -o $(BINARY_NAME) ./cmd/ssv-dkg/ssv-dkg.go

# Recipe to run tests
test:
	@echo "running tests"
	go test -v -p 1 ./...

# Recipe to build the Docker image
docker-build-image:
	@echo "Building Docker image..."
	docker build -t $(DOCKER_IMAGE) .

docker-demo-operators:
	@echo "Running operators in docker demo"
	docker-compose up --build operator1 operator2 operator3 operator4

docker-demo-initiator:
	@echo "Running initiator in docker demo"
	docker-compose up --build initiator

docker-operator:
	@echo "Running operator docker, make sure to update ./examples/config/operator1.example.yaml"
	docker run -d \
	  --name svv-dkg-operator \
	  -p 3030:3030 \
	  -v $(shell pwd)/examples:/data \
	  --entrypoint /app \
	  $(DOCKER_IMAGE):latest \
	  start-operator --configPath /data/config/operator1.example.yaml

docker-initiator:
	@echo "Running initiator docker, make sure to update ./examples/config/initiator.example.yaml"
	docker run -d \
	  --name ssv-dkg-initiator \
	  -v $(shell pwd)/examples:/data \
	  --entrypoint /app \
	  $(DOCKER_IMAGE):latest \
	  init --configPath /data/config/initiator.example.yaml

mockgen-install:
	go install github.com/golang/mock/mockgen@v1.6.0
	@which mockgen || echo "Error: ensure `go env GOPATH` is added to PATH"

lint-prepare:
	@echo "Preparing Linter"
	curl -sfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh| sh -s latest

lint:
	./bin/golangci-lint run -v ./...
	@if [ ! -z "${UNFORMATTED}" ]; then \
		echo "Some files requires formatting, please run 'go fmt ./...'"; \
		exit 1; \
	fi
