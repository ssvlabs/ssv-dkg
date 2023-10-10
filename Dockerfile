FROM golang:1.20-alpine3.17
RUN apk add build-base

WORKDIR /

COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY ./ ./

# Build
RUN CGO_ENABLED=1 GOOS=linux go build -o /app /cmd/ssv-dkg/ssv-dkg.go


EXPOSE 3030
