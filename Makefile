.PHONY: install clean build test test-unit-race test-integration lint deadcode
.PHONY: docker-build-image docker-demo-operators docker-demo-initiator
.PHONY: docker-demo-generate-resign-msg docker-demo-resign docker-demo-generate-reshare-msg docker-demo-reshare
.PHONY: docker-demo-ping docker-demo-ethnode docker-operator docker-initiator
.PHONY: docker-build-deposit-verify docker-deposit-verify

BINARY_NAME     = ./bin/ssv-dkg
DOCKER_IMAGE    = ssv-dkg
GIT_VERSION     = $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME      = $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
LDFLAGS         = -s -w -X main.Version=$(GIT_VERSION) -X main.BuildTime=$(BUILD_TIME)

install:
	go install -trimpath -v -ldflags "$(LDFLAGS)" ./cmd/ssv-dkg/ssv-dkg.go
	@echo "Done installing."
	@echo "Run ssv-dkg to launch the tool."

clean:
	rm -rf ./bin

build:
	@echo "Building Go binary..."
	go build -trimpath -o $(BINARY_NAME) -ldflags "$(LDFLAGS)" ./cmd/ssv-dkg/ssv-dkg.go

test:
	@echo "Running tests..."
	go tool gotestsum --format testdox -- -timeout=3600s ./...

test-unit-race:
	@echo "Running unit tests with race detector..."
	go tool gotestsum --format standard-verbose -- -race -timeout=600s ./pkgs/...

test-integration:
	@echo "Running integration tests..."
	go tool gotestsum --format standard-verbose -- -timeout=3600s ./integration_test/...

lint:
	go tool golangci-lint run -v ./...

deadcode:
	go tool deadcode -test ./...

# Docker targets

docker-build-image:
	@echo "Building Docker image..."
	DOCKER_BUILDKIT=1 docker build \
		--build-arg VERSION=$(GIT_VERSION) \
		-t $(DOCKER_IMAGE) .

docker-demo-operators:
	@echo "Running operators in docker demo"
	docker compose up --build operator1 operator2 operator3 operator4 operator5 operator6 operator7 operator8 operator9 operator10 operator11 operator12 operator13

docker-demo-initiator:
	@echo "Running initiator in docker demo"
	docker compose up --build initiator

docker-demo-generate-resign-msg:
	@echo "Running generate re-sign message in docker demo"
	docker compose up --build generate-resign-msg

docker-demo-resign:
	@echo "Running re-sign ceremony in docker demo"
	docker compose up --build resign

docker-demo-generate-reshare-msg:
	@echo "Running generate re-share message in docker demo"
	docker compose up --build generate-reshare-msg

docker-demo-reshare:
	@echo "Running re-share ceremony in docker demo"
	docker compose up --build reshare

docker-demo-ping:
	@echo "Running ping operators in docker demo"
	docker compose up --build ping

docker-demo-ethnode:
	@echo "Running ethereum node in docker demo"
	docker compose up --build ethnode

docker-operator:
	@echo "Running operator docker, make sure to update ./examples/config/operator1.example.yaml"
	docker run --rm \
	  --name ssv-dkg-operator \
	  -p 3030:3030 \
	  -v $(shell pwd)/examples:/ssv-dkg/data \
	  $(DOCKER_IMAGE):latest \
	  start-operator --configPath ./data/config/operator1.example.yaml

docker-initiator:
	@echo "Running initiator docker, make sure to update ./examples/config/initiator.example.yaml"
	docker run --rm \
	  --name ssv-dkg-initiator \
	  -v $(shell pwd)/examples:/ssv-dkg/data \
	  $(DOCKER_IMAGE):latest \
	  init --configPath ./data/config/initiator.example.yaml

docker-build-deposit-verify:
	DOCKER_BUILDKIT=1 docker build --progress=plain --no-cache -f $(shell pwd)/utils/deposit_verify/Dockerfile -t deposit-verify .

docker-deposit-verify:
	cp $(DEPOSIT_FILE_PATH) /tmp/deposit_data.json && \
	docker run --rm \
	  --name dkg-deposit-verify \
	  -v /tmp/deposit_data.json:/deposit-verify/utils/deposit_verify/deposit_data.json \
	  -v $(NETWORK_ENV_PATH):/deposit-verify/utils/deposit_verify/.env \
	  -e DEPOSIT_FILE_PATH=deposit_data.json \
	  deposit-verify:latest && \
	  rm /tmp/deposit_data.json
