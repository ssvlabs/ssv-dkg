#!/bin/bash

openssl genrsa -out ./initiator/rootCA.key 4096
openssl req -x509 -new -key ./initiator/rootCA.key -subj "/C=CN/ST=GD/L=SZ/O=localhost, Inc./CN=localhost" -days 3650 -out ./initiator/rootCA.crt


for i in $(seq 1 8);
do
    openssl genrsa -out ./operator${i}/operator${i}.key 2048 && \
    openssl req -newkey rsa:2048 -nodes -keyout ./operator${i}/operator${i}.key -subj "/C=CN/ST=GD/L=SZ/O=localhost, Inc./CN=localhost" -out ./operator${i}/operator${i}.csr && \
    openssl x509 -req -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1") -days 365 -in ./operator${i}/operator${i}.csr -CA ./initiator/rootCA.crt -CAkey ./initiator/rootCA.key -CAcreateserial -out ./operator${i}/operator${i}.crt
done
