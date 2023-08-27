FROM golang:1.20

WORKDIR /

COPY go.mod go.sum ./
RUN go mod download

COPY ./ ./

# Build
RUN CGO_ENABLED=1 GOOS=linux go build -o /app /cmd/dkgcli/dkgcli.go


EXPOSE 3030
