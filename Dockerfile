FROM golang:1.20-alpine3.18 as build
WORKDIR /ssv-dkg

# Install build dependencies required for CGO
RUN apk add --no-cache musl-dev gcc g++ libstdc++ git

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

#
# Run stage.
#
FROM alpine:3.18  
WORKDIR /ssv-dkg

# Copy the built binary from the previous stage
COPY --from=build /bin/ssv-dkg /bin/ssv-dkg

ENTRYPOINT ["/bin/ssv-dkg"]

EXPOSE 3030