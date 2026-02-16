# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Test Commands

```bash
# Build binary (requires CGO for BLS crypto)
make build                    # outputs ./bin/ssv-dkg

# Run all tests (unit + integration, uses gotestsum)
make test

# Run a single test
go test -v -run TestName ./pkgs/operator/...

# Run integration tests only
go test -v -timeout=3600s ./integration_test/...

# Lint
make lint

# Dead code detection
make deadcode

# Docker
make docker-build-image

# Regenerate SSZ encoding (after modifying wire types in pkgs/wire/types.go)
go generate ./pkgs/wire/...
```

CGO_ENABLED=1 is required for all builds and tests (BLS crypto via herumi/bls-eth-go-binary).

## Architecture

This is a **Distributed Key Generation (DKG)** tool for Ethereum validators on the SSV network. Two roles participate in a ceremony:

### Two-Role Model

**Initiator** (`pkgs/initiator/`) — Orchestrates the DKG ceremony. Sends init messages to operators, collects responses at each round, redistributes combined messages, and aggregates final results. Communicates over HTTPS using `imroc/req` client. No persistent state.

**Operator** (`pkgs/operator/`) — Runs an HTTP server (Chi router, port 3030, TLS required) that processes ceremony messages. The `Server` struct holds the router; the `Switch` struct manages concurrent DKG instances keyed by `InstanceID [24]byte`. Each instance wraps a `dkg.LocalOwner` via the `Instance` interface. Instances auto-expire after `MaxInstanceTime` (1 min).

### DKG Protocol Flow

The ceremony has multiple HTTP round-trips between initiator and operators:

1. Initiator → `/init` → Operators create DKG identity (kyber scalar + G1 point), return Exchange message
2. Initiator → `/dkg` (exchange) → Operators start deal phase, return deal bundles
3. Initiator → `/dkg` (deals) → Operators process deals, complete DKG, sign deposit data with key share, return encrypted shares
4. Initiator aggregates signatures → writes `deposit_data.json`, `keyshares.json`, `proofs.json`
5. Initiator → `/results` → Operators store result data locally

Additional ceremonies: **reshare** (operator rotation via `/reshare`) and **resign** (re-signing via `/resign`). Both require EIP-1271 owner signature verification against an Ethereum node.

### Key Packages

- **`pkgs/wire/`** — All protocol message types. Uses SSZ encoding (fastssz) for on-wire format and JSON for CLI output types. `types.go` defines structs; `types_encoding.go` is auto-generated via `go generate`. `types_json.go` has CLI-facing types (`OperatorsCLI`, `KeySharesCLI`, `DepositDataCLI`). `TransportType` enum identifies message kinds.
- **`pkgs/dkg/`** — Wraps Drand's kyber DKG library. `LocalOwner` holds per-ceremony state (secret scalar, DKG protocol handler, BLS suite). Processes protocol phases: Init/Exchange → Deal → Response → Result.
- **`pkgs/board/`** — Implements kyber's `Board` interface for DKG message passing (deals, responses, justifications) via channels + broadcast function.
- **`pkgs/crypto/`** — BLS/RSA operations, deposit data construction, keyshare encryption, `Signer` interface.
- **`pkgs/validator/`** — Validates and writes DKG ceremony output files (deposit data, keyshares, proofs). Organizes output into directories per validator.
- **`pkgs/consts/`** — API route constants.
- **`pkgs/utils/`** — Helpers for instance ID computation, error types, message hashing. `test_utils/` has `CreateTestOperator` for spinning up in-process operator servers in tests.

### CLI Layer

`cli/` uses Cobra. Commands: `init`, `start-operator`, `health-check`/`ping`, `verify`, `generate-resign-msg`, `resign`, `generate-reshare-msg`, `reshare`. Flags are organized by command in `cli/flags/`. Entry point: `cmd/ssv-dkg/ssv-dkg.go`.

### SSZ Code Generation

Wire types use SSZ tags (`ssz-size`, `ssz-max`). After changing `pkgs/wire/types.go`, regenerate with `go generate ./pkgs/wire/...`. The generated `types_encoding.go` file should not be edited manually. The `sszgen` tool path includes a pinned `dkg-spec` version in `generate.go`.

### Integration Tests

`integration_test/` spins up real operator servers (TLS with local certs in `integration_test/certs/`) and runs full ceremony flows. Tests use `stubs.Client` to mock Ethereum RPC calls. Test fixtures for reshare/resign ceremonies are in `integration_test/stubs/`.

### External Specifications

Core DKG types (`Init`, `Reshare`, `Resign`, `Operator`, `SignedProof`, `Result`) and validation logic come from `github.com/ssvlabs/dkg-spec`. Crypto operations (RSA sign/verify, EIP-1271) come from `github.com/ssvlabs/dkg-spec/crypto`. The DKG protocol itself uses `github.com/drand/kyber` with BLS12-381 curve.

## CI

GitHub Actions (`.github/workflows/ci.yml`): build → test-unit (race) → test-integration → lint → security (govulncheck) on `main` and PRs. GitLab CI (`.gitlab-ci.yml`): Docker build + K8s deploy to production on `main`.
