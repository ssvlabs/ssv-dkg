# Name of the Go binary output
BINARY_NAME=./bin/dkgcli

# Docker image name
DOCKER_IMAGE=ssv-dkg-tool

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
	docker-compose up

.PHONY: build docker-build