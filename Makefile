# This Makefile is meant to be used by people that do not usually work
# with Go source code. If you know what GOPATH is then you probably
# don't need to bother with make.

.PHONY: dkgcli test clean

GOBIN = ./build/bin
GO ?= latest
GORUN = env GO111MODULE=on go run
GOINSTALL = env GO111MODULE=on go install -v
GOTEST = env GO111MODULE=on go test -v

dkgcli:
	$(GOINSTALL) cmd/dkgcli/dkgcli.go
	@echo "Done building."
	@echo "Run dkgcli to launch the tool."

clean:
	env GO111MODULE=on go clean -cache

test:
	$(GOTEST) -p 1 ./...