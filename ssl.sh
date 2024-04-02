#!/bin/bash

# Generate a self-signed SSL certificate
if openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
  -keyout /ssl/ssl.key -out /ssl/ssl.crt \
  -subj "/C=CN/ST=GD/L=SZ/O=ssv, Inc./CN=*ssvlabs.io"
  echo ssl certificates generated successfully
else
  echo error generating ssl certificates
  exit 1
  