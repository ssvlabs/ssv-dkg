# Use golang base image
FROM golang:1.24.0-alpine3.21@sha256:2d40d4fc278dad38be0777d5e2a88a2c6dee51b0b29c97a764fc6c6a11ca893c AS build

WORKDIR /ssv-dkg

# Install build dependencies required for CGO
RUN apk add --no-cache musl-dev gcc g++ libstdc++ git openssl

# Copy the go.mod and go.sum first and download the dependencies.
# This layer will be cached unless these files change.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,mode=0755,target=/go/pkg \
    go mod download

# Copy the rest of the source code
COPY . .

# Build the binary with caching
ENV CGO_ENABLED=1
ENV GOOS=linux

RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,mode=0755,target=/go/pkg \
    VERSION=$(git describe --tags $(git rev-list --tags --max-count=1)) && \
    go build -o /bin/ssv-dkg -ldflags "-X main.Version=$VERSION -linkmode external -extldflags \"-static -lm\"" \
    ./cmd/ssv-dkg

# Final stage
FROM alpine:3.21@sha256:a8560b36e8b8210634f77d9f7f9efd7ffa463e380b75e2e74aff4511df3ef88c  
WORKDIR /ssv-dkg

# Install openssl
RUN apk add --no-cache openssl 
RUN apk add --no-cache ca-certificates && update-ca-certificates

# Copy the built binary and entry-point script from the previous stage/build context
COPY --from=build /bin/ssv-dkg /bin/ssv-dkg
COPY entry-point.sh /entry-point.sh

# Ensure the entry-point script is executable
RUN chmod +x /entry-point.sh

ENTRYPOINT ["/entry-point.sh"]

EXPOSE 3030
