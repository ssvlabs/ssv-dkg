#!/bin/bash

# Generate certificates with very long expiration dates (~100 years)
# These certificates will effectively never expire

echo "Generating root CA certificate..."
openssl genrsa -out ./initiator/rootCA.key 4096
openssl req -x509 -new -key ./initiator/rootCA.key -subj "/C=CN/ST=GD/L=SZ/O=localhost, Inc./CN=localhost" -days 36500 -out ./initiator/rootCA.crt

echo "Generating operator certificates..."
for i in $(seq 1 8);
do
    echo "Generating certificate for operator${i}..."
    openssl genrsa -out ./operator${i}/operator${i}.key 2048 && \
    openssl req -newkey rsa:2048 -nodes -keyout ./operator${i}/operator${i}.key -subj "/C=CN/ST=GD/L=SZ/O=localhost, Inc./CN=localhost" -out ./operator${i}/operator${i}.csr && \
    openssl x509 -req -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1") -days 36500 -in ./operator${i}/operator${i}.csr -CA ./initiator/rootCA.crt -CAkey ./initiator/rootCA.key -CAcreateserial -out ./operator${i}/operator${i}.crt
done

echo "Certificate generation complete!"
echo "All certificates are valid for ~100 years (36500 days)"
