FROM golang:1.20

WORKDIR /

COPY go.mod go.sum ./
RUN go mod download

COPY ./ ./

# Build
RUN CGO_ENABLED=0 GOOS=linux go build -o /client /cmd/ssv-dkg-init/main.go
RUN CGO_ENABLED=0 GOOS=linux go build -o /server /cmd/ssv-dkg-server/main.go


EXPOSE 3030
