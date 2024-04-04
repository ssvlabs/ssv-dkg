#!/bin/sh

# Setup directory for certificates
CERT_DIR=/ssl
mkdir -p "$CERT_DIR"

# Paths to the certificate and key files
CERT_FILE="$CERT_DIR/tls.crt"
KEY_FILE="$CERT_DIR/tls.key"

# Check if the first argument is "start-operator"
if [ "$1" = "start-operator" ]; then
    # Generate a self-signed SSL certificate only if it doesn't exist
    if [ ! -f "$CERT_FILE" ] || [ ! -f "$KEY_FILE" ]; then
      echo "Certificate or key file not found. Generating new SSL certificate and key."
      openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
        -keyout "$KEY_FILE" -out "$CERT_FILE" \
        -subj "/C=CN/ST=GD/L=SZ/O=localhost, Inc./CN=localhost"
    else
      echo "Existing SSL certificate and key found. Using them."
    fi
fi

# Execute the main binary and pass all script arguments
exec /bin/ssv-dkg "$@"
