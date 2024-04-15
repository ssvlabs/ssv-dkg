#!/bin/bash


# run all exits in the folder 
find $(pwd)/output -mindepth 1 -maxdepth 1 -type f -name "validator-exit-*.json" | while read fname; do
    echo "Executing $fname"
    epoch= jq .message.epoch $fname
    validator_index= jq .message.validator_index $fname
    signature= jq .signature $fname

    if curl -X 'POST' \  
        'http://bn-h-3.stage.bloxinfra.com:3500/eth/v1/beacon/pool/voluntary_exits' \
        -H 'accept: */*' \
        -H 'Content-Type: application/json' \
        -d '{
        "message": {
            "epoch": '$epoch',
            "validator_index": '$validator_index'
        },
        "signature": '$signature'
        }'
    then
        exit 1
    fi
done