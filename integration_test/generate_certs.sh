#!/bin/bash

# Generate certificates for integration tests with very long expiration dates
# These certificates will be valid for ~100 years (36500 days)

echo "Generating root CA certificate..."
# Generate root CA private key
openssl genrsa -out ./certs/rootCA.key 4096

# Generate root CA certificate (valid for ~100 years)
openssl req -x509 -new -key ./certs/rootCA.key \
    -subj "/C=CN/ST=GD/L=SZ/O=localhost, Inc./CN=localhost" \
    -days 36500 -out ./certs/rootCA.crt

echo "Generating localhost certificate..."
# Generate localhost private key
openssl genrsa -out ./certs/localhost.key 2048

# Generate localhost certificate signing request
openssl req -newkey rsa:2048 -nodes -keyout ./certs/localhost.key \
    -subj "/C=CN/ST=GD/L=SZ/O=localhost, Inc./CN=localhost" \
    -out ./certs/localhost.csr

# Sign localhost certificate with root CA (valid for ~100 years)
openssl x509 -req -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1") \
    -days 36500 -in ./certs/localhost.csr \
    -CA ./certs/rootCA.crt -CAkey ./certs/rootCA.key \
    -CAcreateserial -out ./certs/localhost.crt

echo "Certificate generation complete!"
echo "Generated files:"
echo "  - rootCA.key (private key)"
echo "  - rootCA.crt (root certificate, valid for ~100 years)"
echo "  - localhost.key (private key)"
echo "  - localhost.csr (certificate signing request)"
echo "  - localhost.crt (signed certificate, valid for ~100 years)"
echo "  - rootCA.srl (serial number file)" 