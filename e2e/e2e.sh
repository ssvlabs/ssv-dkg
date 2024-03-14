alias compose="docker-compose -f docker-compose.e2e.yml"

# Exit on error.
set -e

# Build image.
docker build -t ssv-dkg-e2e .

# Spin up operators.
compose up -d operator1 operator2 operator3 operator4 operator5 operator6 operator7 operator8

# Ping them.
compose down operator1 operator2 operator3 operator4 operator5 operator6 operator7 operator8
compose up ping

# Run DKG.
compose up initiator

# Ping them again.
compose up ping

# Check outputs.
go run e2e/e2e.go