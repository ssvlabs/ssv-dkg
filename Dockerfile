# Use golang base image
FROM golang:1.20-alpine3.18 as build

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
FROM alpine:3.18  
WORKDIR /ssv-dkg

# Install openssl
RUN apk add --no-cache openssl

# Copy the built binary and entry-point script from the previous stage/build context
COPY --from=build /bin/ssv-dkg /bin/ssv-dkg
COPY entry-point.sh /entry-point.sh

# Ensure the entry-point script is executable
RUN chmod +x /entry-point.sh

ENTRYPOINT ["/entry-point.sh"]

EXPOSE 3030
