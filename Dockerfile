FROM golang:1.25-alpine@sha256:724e212d86d79b45b7ace725b44ff3b6c2684bfd3131c43d5d60441de151d98e AS build

ARG VERSION=dev

WORKDIR /ssv-dkg

# Install build dependencies required for CGO
RUN apk add --no-cache musl-dev gcc g++ libstdc++ openssl

# Copy the go.mod and go.sum first and download the dependencies.
# This layer will be cached unless these files change.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,mode=0755,target=/go/pkg \
    go mod download && go mod verify

# Copy the rest of the source code
COPY . .

# Build the binary with caching
ENV CGO_ENABLED=1
ENV GOOS=linux

RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,mode=0755,target=/go/pkg \
    go build -trimpath -o /bin/ssv-dkg \
    -ldflags "-s -w -X main.Version=$VERSION -linkmode external -extldflags \"-static -lm\"" \
    ./cmd/ssv-dkg

# Final stage
FROM alpine:3.21@sha256:22e0ec13c0db6b3e1ba3280e831fc50ba7bffe58e81f31670a64b1afede247bc
WORKDIR /ssv-dkg

LABEL org.opencontainers.image.title="SSV DKG" \
      org.opencontainers.image.description="Distributed Key Generation tool for SSV network Ethereum validators" \
      org.opencontainers.image.vendor="SSV Labs" \
      org.opencontainers.image.source="https://github.com/ssvlabs/ssv-dkg"

RUN apk add --no-cache openssl ca-certificates && update-ca-certificates

COPY --from=build /bin/ssv-dkg /bin/ssv-dkg
COPY --chmod=755 entry-point.sh /entry-point.sh

ENTRYPOINT ["/entry-point.sh"]

EXPOSE 3030
