#!/bin/bash

# Directory containing the exit files
exit_dir="."

# Find and process each exit file in the specified directory
find "${exit_dir}" -mindepth 1 -maxdepth 1 -type f -name "validator-exit-*.json" | while read -r fname; do
    echo "Executing $fname"
    
    # Extract values using jq and remove quotes
    epoch=$(jq -r '.message.epoch' "$fname")
    validator_index=$(jq -r '.message.validator_index' "$fname")
    signature=$(jq -r '.signature' "$fname")

    # Create the JSON payload
    json_payload=$(cat <<-EOF
    {
        "message": {
            "epoch": "${epoch}",
            "validator_index": "${validator_index}"
        },
        "signature": "${signature}"
    }
EOF
    )

    # Send the data using curl
    if ! curl -X 'POST' \
        'http://bn-h-3.stage.bloxinfra.com:3500/eth/v1/beacon/pool/voluntary_exits' \
        -H 'accept: */*' \
        -H 'Content-Type: application/json' \
        -d "$json_payload"
    then
        echo "Failed to send data for $fname"
        # Optionally, you can choose to exit or continue based on requirements
        # exit 1
    fi
done
