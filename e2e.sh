#!/bin/bash

# prepare
if [ ! -d $(pwd)/output ]; then
  mkdir -p $(pwd)/output;
fi

# get latest version
VESRION=$(git -c 'versionsort.suffix=-' ls-remote --exit-code --refs --sort='version:refname' --tags https://github.com/bloxapp/ssv-dkg.git '*.*.*' | tail --lines=1 | cut --delimiter='/' --fields=3)

# install fresh binary
env GO111MODULE=on go install -v -ldflags "-X main.Version=$VESRION" cmd/ssv-dkg/ssv-dkg.go

# run init ceremony

for val in 1 10 100; do 
  if ssv-dkg init \
          --validators $val \
          --operatorIDs 1,2,3,4 \
          --operatorsInfo '[{"id": 1,"public_key": "LS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBMVg2MUFXY001QUNLaGN5MTlUaEIKby9HMWlhN1ByOVUralJ5aWY5ZjAyRG9sd091V2ZLLzdSVUlhOEhEbHBvQlVERDkwRTVQUGdJSy9sTXB4RytXbwpwQ2N5bTBpWk9UT0JzNDE5bEh3TzA4bXFja1JsZEg5WExmbmY2UThqWFR5Ym1yYzdWNmwyNVprcTl4U0owbHR1CndmTnVTSzNCZnFtNkQxOUY0aTVCbmVaSWhjRVJTYlFLWDFxbWNqYnZFL2cyQko4TzhaZUgrd0RzTHJiNnZXQVIKY3BYWG1uelE3Vlp6ZklHTGVLVU1CTTh6SW0rcXI4RGZ4SEhSeVU1QTE3cFU4cy9MNUp5RXE1RGJjc2Q2dHlnbQp5UE9BYUNzWldVREI3UGhLOHpUWU9WYi9MM1lnSTU4bjFXek5IM0s5cmFreUppTmUxTE9GVVZzQTFDUnhtQ2YzCmlRSURBUUFCCi0tLS0tRU5EIFJTQSBQVUJMSUMgS0VZLS0tLS0K","ip": "http://35.161.207.60:3030"},
                            {"id": 2,"public_key": "LS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBeUtVWTVEUmZZREljengzcjhVY0UKTlpFMFdIQXFuV2FIRjZYRlUydVdObjVOVE94Zkt4ZmZaLzkyeVE1citQVkJPRmQrcHhILzI2QXJVT3dNL1lBRQpRbDZ0VzBtc1FqdUtIU1Q4aUtvTDRTNUt0aDNoeTBqeFRHR1ZZaWdjWG1vRURjd2YxaG8wdWRxRmlEN3dFWXN1CmZHa2E2U1ZQNnBab1NMaU9HZFRKUWVzVDI5WEVCdDZnblhMaFB1MER2K0xsQUJJQ1pqWEFTZWtpSFVKUHRjYlgKRjZFL0lScGpkWHVNSmUyOXZDcmZudXhWWk93a1ptdzJXdGljYlNDOVJpSFRYWUQ1dnVGakZXRHNZMERHUDhzOAoyc1haVHdsNWl4dEhlUWM2N1lLRFN6YU1MNnY1VUVZblhUTzZzNHFVSWVnTXJwZjd3S0xGVWxqRTMwbnNIaVBUCjBRSURBUUFCCi0tLS0tRU5EIFJTQSBQVUJMSUMgS0VZLS0tLS0K","ip": "http://35.88.187.25:3030"},
                            {"id": 3,"public_key": "LS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBNWVUNUwwV0h6ZTdyTWZPb2xtVHMKdWtIQ2E4K3dtbUw2OTFJQ1RpREE1UkJ1TkxqSVQ2WkE0YzMxcVRIY3FBVHl5eVkwLzk3R3lKZ2doYnlFR2RoZQovalh6aWVTOXJ2RytJVGF1QjhMVlhkekxGYVQxWEZWeFlnN2x2TlB4OURPL1ZoRkhkWWxnT3I2d0RtV3FjRGo3ClhWUWFOWEFtRng3NjVQNTlXNXZzVGRXVWFHRWxXSm93SkZKdnc2UlRISkZ1TVhjSzZVaWJ0cUZMSmJwOW5kdUgKQjlLSzNWcmYrZmtJOWRBZ2txRDFHOElxQ0tKMVl3bjUyeGxxbTRCNitOOGZUZE1MS1JucWpFZmRzV1dwMFVzMQpLTW9vSXcyc3BoaXAzUFpNYnJaaU0wNjJ2ZUo0U3ovYjBObWdPTnhTd0JJTnNxcG54QjhFUVQxSTNjNklqNXhhCm5RSURBUUFCCi0tLS0tRU5EIFJTQSBQVUJMSUMgS0VZLS0tLS0K","ip": "http://34.217.180.37:3030"},
                            {"id": 4,"public_key": "LS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBdXZleUpUMURwM21mQ3FRTUora2YKZHdhV0d1bkRURUFaWmNTOHdtUTJBcjU1bE5venl5cHRwb1lGSTgxaW1RSmpwdVV0akR2am15RDRQSmt1SzFXRQovZG9TSzFraWlTSEYvZFBaeE5ZT2swMlRiTGIvTXBjMG12VE1nZmRsVDBoTlVOWDZIMnJzZzNlc2NEOStENEdDCmxtZGpCdmdxUDQydXdDbFlQUVhuN3Z6OWlOOEpXdEFtd1JkQ25USkZ6M2tYSEFPVGMyMjJGYXp4ZGJVNEVPYkIKVmJNejd2UXRmMWtNSGtacEh5UXNpL3F0WmhQaThtTlNQTWpMTDBtcmc4Ly9xVjIyeEVPNENmSHFKZkZOWEhKVwpEbU85M2h2QXE2dDFZOGN5UVZkSGZ2WEp5VzRxR29MY25HZzV1S2ZSYWVCSSt1aXFSeExOL2dtTnA2RzdpZVNkCkl3SURBUUFCCi0tLS0tRU5EIFJTQSBQVUJMSUMgS0VZLS0tLS0K","ip": "http://52.12.84.255:3030"}]' \
          --owner 0x81592c3de184a3e2c0dcb5a261bc107bfa91f494 \
          --nonce 1 \
          --withdrawAddress 0xa1a66cc5d309f19fb2fda2b7601b223053d0f7f4  \
          --network "mainnet" \
          --outputPath $(pwd)/output \
          --logLevel info \
          --logFormat json \
          --logLevelFormat capitalColor \
          --logFilePath $(pwd)/output/debug.log
    echo init successfull
  else
    exit 1
  fi

  # verify all ceremony results
  find $(pwd)/output -mindepth 1 -maxdepth 1 -type d -name "ceremony*" | while read fname; do
    echo "$fname" 
    if ssv-dkg verify \
          --ceremonyDir $fname \
          --nonce 1 \
          --owner 0x81592c3de184a3e2c0dcb5a261bc107bfa91f494 \
          --validators $val \
          --withdrawAddress 0xa1a66cc5d309f19fb2fda2b7601b223053d0f7f4; then
      echo results verify success
    else
      exit 1
    fi
    rm -rf $(pwd)/output/ceremony*
  done
done


 

