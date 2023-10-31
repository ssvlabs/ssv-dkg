# `ssv-dkg`


- [`ssv-dkg`](#ssv-dkg)
  - [Goal and Introduction](#goal-and-introduction)
    - [DKG](#dkg)
    - [DKG tool by SSV](#dkg-tool-by-ssv)
  - [Overview](#overview)
  - [Initiator Quick start](#initiator-quick-start)
    - [Obtaining Operators data](#obtaining-operators-data)
    - [Start DKG Initiator](#start-dkg-initiator)
      - [Launch with Docker and YAML file](#launch-with-docker-and-yaml-file)
      - [Generate Initiator identity RSA key pair](#generate-initiator-identity-rsa-key-pair)
      - [Build from source](#build-from-source)
        - [Build](#build)
        - [Launch with command line parameters](#launch-with-command-line-parameters)
        - [Launch with YAML config file](#launch-with-yaml-config-file)
      - [Key resharing](#Key-resharing)
    - [Deposit and register Validator](#deposit-and-register-validator)
    - [Troubleshooting](#troubleshooting)
      - [dial tcp timeout](#dial-tcp-timeout)
      - [invalid URI for request](#invalid-uri-for-request)
      - [connection refused](#connection-refused)
  - [Operator Quick start](#operator-quick-start)
    - [Pre requisites](#pre-requisites)
    - [Start a DKG-operator](#start-a-dkg-operator)
      - [Launch with Docker and YAML file](#launch-with-docker-and-yaml-file-1)
      - [Build from source](#build-from-source-1)
        - [Build](#build-1)
        - [Launch with command line parameters](#launch-with-command-line-parameters-1)
        - [Launch with YAML config file](#launch-with-yaml-config-file-1)
    - [Update Operator metadata](#update-operator-metadata)
  - [Example](#example)
  - [Flow Description:](#flow-description)
    - [Note on DKG instance management](#note-on-dkg-instance-management)
  - [Security notes](#security-notes)

## Goal and Introduction

> 🚫 This tool was not audited.
> 
> When using distributed key generation you understand all the risks involved with experimental cryptography. 

### DKG

Distributed Key Generation is a cryptographic process that aims to solve the problem of coordinating N parties to cryptographically sign and verify signatures without relying on Trusted Third Parties. The process is demonstrated to be successful in computing a key pair in the presence of a number T attackers in a decentralized network. To do so, this algorithm generates a public key, and a secret key of which no single party knows, but has some share of. The involvement of many parties requires Distributed key generation to ensure secrecy in the presence of malicious contributions to the key calculation.
For more information about DKG in general, [please visit this page](https://en.wikipedia.org/wiki/Distributed_key_generation).

### DKG tool by SSV

The SSV team built this tool leveraging [drand](https://drand.love/)'s DKG protocol implementation ([please visit their documentation](https://drand.love/docs/cryptography/#setup-phase) for more details on it). This implementation operates under the assumption of a p2p network, allowing operators to communicate.
The `ssv-dkg` was built to lift this assumption and provide a communication layer that centered on an Initiator figure, to facilitate communication between operators. The introduced potential risk for centralization and bad actors is handled with signatures and signature verifications, as explained in the Security notes section.
Finally, the outcome of the DKG ceremony is a BLS key pair to be used for validator duties by operators on the ssv.network. As such, the tool ends the process by creating a deposit file to activate the newly created validator key pair, and proceeds to generating the payload for the transaction.

## Overview

In order for the DKG protocol to execute successfully:

* all the chosen Operators must be running the `ssv-dkg` tool as Operators
* separately, an Initiator (one of the Operators, or a separate entity), starts the DKG ceremony by running the ssv-dkg tool with the init parameter
* the tool automatically exchange data between the interested parties, as outlined in the [Flow Description](#flow-description) section, until the key shares are created

For details on how to run the tool as an Operator, please head over [to this section containing the related instructions](#operator-quick-start).
Similarly, head over to [this other section](#initiator-quick-start) for instructions on how to launch the tool as the Initiator of the DKG ceremony.

## Initiator Quick start

### Obtaining Operators data

The `ssv-dkg` tool does not provide Operators data for the operations described above (ID, endpoint, public key).
Teams integrating with SSV are responsible for sourcing it however they see fit. This information can be collected in various ways, such as the [official SSV API](https://api.ssv.network/documentation/#/v4). Other suggested options are, for example, building an ad-hoc Operator data service, or a preset file where all Operators data is stored.

Information about Operators must be collected in a JSON file and supplied to Initiator to be used use for the key generation ceremony, as shown above.

Operators info file example:
```json
[
  {
    "id": 143,
    "public_key": "LS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBM2VyQk9IUTVJYkJmL3lxak1UMmYKNElQYWJBMkY4YmwzQWlJVStRQlBUd2s2UFRRZS9EZVZMVkx6cm5wWFdZemNTRUZVSnZZeU5WM3ZhYkxGN2VDZwpxNlptRUJhSHN5S2NYS0g5N0JCb21VaDF4TGl5OFRGTkk0VGdjL0JwSU51dEdrRGkrVUhCT0tBcHE0TUVaSXlsCnJpTHlaeDFNZnJ6QTF0ZUNRaVJ3T2tzN0wrT1IraElNOEwvNFRtTUd4RDFhS2tXOHhpUzlKL256YXB5YkxsczMKR3cwWER0Q25XLzREWFVLSm1wLzFrMHlNeHZjT1phUjJWSjB0aUFVMjBKNDcrcUtndi9kZHI1YjNjQ2F5NDhpVQptcks2MkNEaHdyNVpqaU1WSHg2R1NJK0kvZmhMckI2Z2dSdTBYVVVFYTljNzVvR3k1SHVKSFA5dTJIQ0dZSXI5CjBRSURBUUFCCi0tLS0tRU5EIFJTQSBQVUJMSUMgS0VZLS0tLS0K",
    "ip": "http://141.94.143.182:3030"
  },
  {
    "id": 219,
    "public_key": "LS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBcjNlTjVhR205NTN5U0VrcHBDZnAKZmp2bFpMaG51Y0c2ajI2emxHYjNobHcvVXE5aG9tSmhzOVUzTHFuYzU4dk5RR2pENzhCTUZOMy8xUStXanZRSgpuQVJJVVdJTnJONWNoMFBTMXBqb21CVlB0Nkg0RE5ha1lSamxCM0V0QmZGaGFOcDdlQzd4dGFMbzc3Qk5velMxCjBBOFpSRC9IaGg3T3lkNWttUWVnV1pIOGlGRCszcHZnV1ZMUWFibkZuK00xWW9LYUhDNkRHSzdnSzdEYTRlMGcKUTF4MFRhSmRZMUUvcStUQ01oUGhwcmtoVlFlNFBLU0NKOWJHSnRDblBpRUFqa2VWa09RZlA0Z095b0VjaW5jMQpTR2pveVo1dVZPU1hEZGYzVzdYUE9pZEpFU1VoY1hqS05DMC9IN09ZM2pqdTZyUU9NZmFqSERhb3VSWEJGaHZDCnp3SURBUUFCCi0tLS0tRU5EIFJTQSBQVUJMSUMgS0VZLS0tLS0K",
    "ip": "http://209.35.77.243:12015"
  },
  {
    "id": 33,
    "public_key": "LS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBdmo5UmpQTFk5YXd1WVc3NVRVcVoKVWozRWRMN2NkdDFnUjlydHowQU02TENNbTdCNG5DcW1RYjRCeFBsUktVeVl1ZnNEbXIzeTVqUmdVbHBHR0ZRawpOWmU0VGRZQkxPNnRUZ1NyMXphMUlGR0R2dzdJUUJZSHoramFEYVN6Zk9vYnNiUldiMDVaZFdGc01keGlEam5vCnR2NHZ4eGpCOWlXa2xmaytUNXB4K3ZwTWZnd1M2Ui9EOU84Y0dZdTg1b0RpQXgzQ0tPampuY3BPV0pndHhxZUMKbENDbldxSS9PeTFSa1FVcFNYL1hsRHozSHhCN0NlY0IzeUUwNnNTbXd1WTZHdk9tMUEvMmdNVUprbDFTUmFjbgpDeFhYK1hVWWFEemZGdXBBeWxPVnIxMEFnUkpTcVd2SkoxcnJCZkFwSzBMNzFMQzFzVzRyWjloMGFIN2pweW1aCjF3SURBUUFCCi0tLS0tRU5EIFJTQSBQVUJMSUMgS0VZLS0tLS0K",
    "ip": "http://51.81.109.67:3030"
  },
  {
    "id": 190,
    "public_key": "LS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBeEowZDYxN09BSHpxOUQzTUt2WFoKTEJRR2VzVU4xZGFXOC9MNEt4UWJFVlN6Y2JzTlY1Q1RqNm5OWGtnOW1LQzIyWWRRazRZcGpNbk9reENrMXNXRApvUXI4bG4zZTJxbU9zeHJuOGFxZEJhVGZmaFZ4WDJrTU9BZUZCcEJPN0lrTXBOUTFwMzdDMzh0Rmx0eFpxSEt3CkFJVXg5UjVGWWhOZXhrOEUrQlpMYzJFSzl4bjZIMTFUY21hN2NVZW03VUpDeUR3VFlLVC9JN21ZTXV3UGFpTTAKTm1Ta0JoeFYrdkd3bmJqWWhCaEZQTi9MMTJRWi9YZUVJcHFzcGRKTFpkUmhRd2VlZG1MdTNLcXdFdnhhNEJZVQpWcTlkeG9qd1JDdU9TL2tvM1pTQ3hubWpJaHlGQUJXYW5WU2x5TW5xdGFaZTFkdm1STG12RTFpL3RjN251MnRnCi93SURBUUFCCi0tLS0tRU5EIFJTQSBQVUJMSUMgS0VZLS0tLS0K",
    "ip": "http://80.181.85.114:3030"
  },
  {
    "id": 34,
    "public_key": "LS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBNHZMUm93Ry9HeVFYdnFaS092MzEKYlNkRVFId3FoTmR2d2JCckdyYlQ0dmVWVHNPbDNPRVF6K3dWMjBVaXJjeHBVVVRKc081K0wrTzlnR0xNMWdTRgpFMVJRU01zMXEzSkZtNlY0VXFQU3pMK09DcDlMS3ZIRnJKMmU4VGwyZ25UU0tPNzFncGtUdFRrb2ZlLzlJRjFOCmNZMDlJbkQwTWNtZzk1Qm14alBuREV3VE1uVzBQU3JVTnJQYVNlMTJTVHJ0Q2JCTUJFUFR5RnI5elovRWFESFIKSHFaZjlkeE9VMjBiQnNSUVlSMnhCZFBtWHFKaFZZMTQrOExmaWpLRmhMcDNmZ25IL0xtK0NjTE5FOFQ3ZjhTTApoZUhLcnMrcUV4VERTcDR4MWhLMzk4dnpWTElOL0h6T20yeXV3Z3cxeG9zdThTOFlVUzNCeTFGZ3g2RExZc3RyCmxRSURBUUFCCi0tLS0tRU5EIFJTQSBQVUJMSUMgS0VZLS0tLS0K",
    "ip": "http://148.113.20.206:3030"
  }
]
```

### Start DKG Initiator

There are a couple of options to launch the DKG tool:
* [Launch with Docker and YAML file](#launch-with-docker-and-yaml-file)
* [Build from source](#build-from-source)

It is advised launching the tool as a Docker image as it is the most convenient way and only requires to have Docker installed. The team builds a Docker image with every release of the tool.

#### Launch with Docker and YAML file

All of the necessary configuration information can be provided in a YAML file (referenced as `initiator.yaml` from now on).

A good way to manage all the necessary files (`operators_info.json`, `encrypted_private_key.json`, `password`) is to store them in a single folder (in this case `initiator-config`) together with the `initiator.yaml` configuration file, like so:

```sh
ssv@localhost:~/ssv-dkg# tree initiator-config
initiator-config
├── encrypted_private_key.json
├── initiator.yaml
├── operators_info.json
└── password

1 directory, 4 files
```

With this configuration, a typical configuration file would look like this:

```yaml
operatorIDs: [143, 219, 33, 34]    # array of Operator IDs which will be used for a DKG ceremony
withdrawAddress: "0xa1a66cc5d309f19fb2fda2b7601b223053d0f7f4"    # Address where reward payments for the validator are sent
owner: "0xb64923DA2c1A9907AdC63617d882D824033a091c"    # Address of owner of the Cluster that will manage the validator on ssv.network
nonce: 0    # Owner nonce for the SSV contract
network: "prater"    # Network name (default: mainnet)
operatorsInfoPath: /data/operators_info.json    # Path to the file containing operators information
# Alternatively:
# operatorsInfo: '[{"id": 1,"public_key": "LS0tLS1CRUdJTiBSU0....","ip": "http://localhost:3030"}, {"id": 2,"public_key": "LS0tLS1CRUdJTiBSU0....","ip": "http://localhost:3030"},...]'    # Raw content of the JSON file with operators information
outputPath: /data/output   #  Path to store the resulting staking deposit and ssv contract payload files
initiatorPrivKey: /data/encrypted_private_key.json    # Path to private key of ssv initiator
initiatorPrivKeyPassword: /data/password    # Path to password file to decrypt the key
# Alternatively:
# generateInitiatorKey: false # If set true - generates a new RSA key pair + random secure password. The result is stored at `outputPath`
logLevel: info    # Logger's log level (default: debug)
logFormat: json    # Logger's encoding (default: json)
logLevelFormat: capitalColor    # Logger's level format (default: capitalColor)
logFilePath: /data/debug.log    # Path to file where logs should be written (default: ./data/debug.log)
```

> ℹ️ In the config file above, `/data/` represents the container's shared volume created by the docker command itself with the `-v` option.

A special note goes to the `nonce` field, which represents how many validators the address identified in the owner parameter has already registered to the ssv.network.
You can keep track of this counter yourself, or you can use the `ssv-scanner` tool made available by the SSV team to source it. For more information, please refer to the related user guide or to its [SDK documentation page](https://docs.ssv.network/developers/tools/ssv-scanner).

> ℹ️ Note: For more details on `operatorsInfoPath` parameter, head over to the [Operators data section](#obtaining-operators-data) above

Under the assumption that all the necessary files (`operators_info.json`, `encrypted_private_key.json`, `password`) are under the same folder (represented below with `<PATH_TO_FOLDER_WITH_CONFIG_FILES>`) you can run the tool using the command below:

```sh
docker run --name ssv_dkg_initiator \
-v "<PATH_TO_FOLDER_WITH_CONFIG_FILES>":/data -it \
"ssv-dkg:latest" /app init --generateInitiatorKey \
--configPath /data/initiator.yaml && \
docker rm ssv_dkg_initiator
```

Just make sure to substitute `<PATH_TO_FOLDER_WITH_CONFIG_FILES>` with the actual folder containing all the files.
You can, of course, change the configuration above to one that suits you better, just be mindful about changing the path references in the docker command **and** in the `operator.yaml` file as well.

> ℹ️ Note: The Initiator needs to sign all messages exchanged with DKG participants with an RSA key. The `--generateInitiatorKey` option will automatically create it, and encrypt it with a random password. Both the key and the password will be returned as output.
> 
> If you already have a password-encrypted RSA key, make sure to omit this option.

<details>
  <summary><b>Click here if you want to generate an RSA with a password of your choosing</b></summary>
  
  First of all, write down your chosen password in a text file, for example `password`, replacing `<PASSWORD>` with a password of your choosing:

  ```sh
  echo "<PASSWORD>" >> password
  ```

  #### Generate Initiator identity RSA key pair

    To generate Initiator RSA keys, make sure to update `initiator.yaml`:
  ```yaml
  # initiatorPrivKey: /data/encrypted_private_key.json  
  initiatorPrivKeyPassword: /data/password    # Path to password file
  generateInitiatorKey: true 
  ```
  Run:

  ```sh
  docker run --name ssv_dkg_initiator \
  -v "<PATH_TO_FOLDER_WITH_CONFIG_FILES>":/data -it \
  "ssv-dkg:latest" /app init --configPath /data/initiator.yaml && \
  docker rm ssv_dkg_initiator
  ```

  This will create `encrypted_private_key-<VALIDATOR_PUBKEY>.json` with encrypted by password RSA key pair.
</details>

#### Build from source

To build from source you'll need to have Go version 1.20 installed on your system

##### Build

A prerequisite for this is to have `go` version 1.20 installed on the system, and an optional requirement is to have the `make` tool installed as well (alternatively you could run the corresponding command defined in the `Makefile`).
```sh
make install
```
##### Launch with command line parameters

It is advised to store all the necessary files (operators_info.json, encrypted_private_key.json, password) in a single folder (in this case initiator-config), as shown below:
```sh
ssv@localhost:~/ssv-dkg# tree initiator-config
initiator-config
├── encrypted_private_key.json
├── operators_info.json
└── password

1 directory, 3 files
```

The Initiator creates the initial details needed to run DKG between all operators via the init command. You can launch the following command with the appropriate values to each parameter:
```sh
ssv-dkg init \
          --operatorIDs 1,2,3,4 \
          --operatorsInfoPath ./examples/operators_integration.json \
          # Alternatively:
          # --operatorsInfo: '[{"id": 1,"public_key": "LS0tLS1CRUdJTiBSU0....","ip": "http://localhost:3030"}, {"id": 2,"public_key": "LS0tLS1CRUdJTiBSU0....","ip": "http://localhost:3030"},...]'
          --owner 0x81592c3de184a3e2c0dcb5a261bc107bfa91f494 \
          --nonce 4 \
          --withdrawAddress 0xa1a66cc5d309f19fb2fda2b7601b223053d0f7f4  \
          --network "mainnet" \
          --outputPath /output \
          --initiatorPrivKey ./encrypted_private_key.json \
          --initiatorPrivKeyPassword ./password \
          # Alternatively:
          # generateInitiatorKey: false # If set true - generates a new RSA key pair + random secure password. The result is stored at `outputPath`
          --logLevel info \
          --logFormat json \
          --logLevelFormat capitalColor \
          --logFilePath ./initiator_logs/debug.log
```

Here's an explanation of each parameter:

| Argument                   | type                                      | description                                                                                        |
| -------------------------- | :---------------------------------------- | :------------------------------------------------------------------------------------------------- |
| --operatorIDs              | int[]                                     | Operator IDs which will be used for a DKG ceremony                                                 |
| --operatorsInfoPath        | string                                    | Path to operators info: ID, base64(RSA pub key), endpoint                                          |
| --operatorsInfo            | string                                    | Raw content of the JSON file with operators information                                            |
| --owner                    | address                                   | Owner address for the SSV contract                                                                 |
| --nonce                    | int                                       | Owner nonce for the SSV contract                                                                   |
| --withdrawAddress          | address                                   | Address where reward payments for the validator are sent                                           |
| --network                  | mainnet / prater / pyrmont                | Network name (default: `mainnet`)                                                                  |
| --outputPath               | string                                    | Path to store the output files                                                                     |
| --initiatorPrivKey         | string                                    | Private key of ssv initiator (path, or plain text, if not encrypted)                               |
| --initiatorPrivKeyPassword | string                                    | Path to password file to decrypt the key (if absent, provide plain text private key)               |
| --generateInitiatorKey     | boolean                                   | Generates a new RSA key pair + random secure password. Result stored at `outputPath` (default: `false`)|
| --logLevel                 | debug / info / warning / error / critical | Logger's log level (default: `debug`)                                                              |
| --logFormat                | json / console                            | Logger's encoding (default: `json`)                                                                |
| --logLevelFormat           | capitalColor / capital / lowercase        | Logger's level format (default: `capitalColor`)                                                    |
| --logFilePath              | string                                    | Path to file where logs should be written (default: `./data/debug.log`)                            |

A special note goes to the `nonce` field, which represents how many validators the address identified in the owner parameter has already registered to the ssv.network.

You can keep track of this counter yourself, or you can use the `ssv-scanner` tool made available by the SSV team to source it. For more information, please refer to the related user guide or to its [SDK documentation page](https://docs.ssv.network/developers/tools/ssv-scanner).

> ℹ️ Note: For more details on `operatorsInfoPath` parameter, head over to the [Operators data](#obtaining-operators-data) section.

##### Launch with YAML config file

It is also possible to use YAML configuration file. Just pay attention to the path of the necessary files, which needs to be changed to reflect the local configuration.
If the `initiator.yaml` file is created in the same folder as the other files, and the folder structure looks like this:

```sh
ssv@localhost:~/ssv-dkg# tree initiator-config
initiator-config
├── encrypted_private_key.json
├── initiator.yaml
├── operators_info.json
└── password

1 directory, 4 files
```

Then the content of the YAML file should be changed to this:
```yaml
operatorIDs: [143, 219, 33, 34]    # array of Operator IDs which will be used for a DKG ceremony
withdrawAddress: "0xa1a66cc5d309f19fb2fda2b7601b223053d0f7f4"    # Address where reward payments for the validator are sent
owner: "0xb64923DA2c1A9907AdC63617d882D824033a091c"    # Address of owner of the Cluster that will manage the validator on ssv.network
nonce: 0    # Owner nonce for the SSV contract
network: "prater"    # Network name (default: mainnet)
operatorsInfoPath: ./initiator-config/operators_info.json    # Path to the file containing operators information
# Alternatively:
# operatorsInfo: '[{"id": 1,"public_key": "LS0tLS1CRUdJTiBSU0....","ip": "http://localhost:3030"}, {"id": 2,"public_key": "LS0tLS1CRUdJTiBSU0....","ip": "http://localhost:3030"},...]'    # Raw content of the JSON file with operators information
outputPath: ./output    # Path to store the resulting staking deposit and ssv contract payload files
initiatorPrivKey: ./initiator-config/encrypted_private_key.json    # Path to private key of ssv initiator
initiatorPrivKeyPassword: ./initiator-config/password    # Path to password file to decrypt the key
# Alternatively:
# generateInitiatorKey: true # If set true - generates a new RSA key pair + random secure password. The result is stored at `outputPath`
logLevel: info    # Logger's log level (default: debug)
logFormat: json    # Logger's encoding (default: json)
logLevelFormat: capitalColor    # Logger's level format (default: capitalColor)
logFilePath: ./initiator-config/debug.log    # Path to file where logs should be written (default: ./data/debug.log)
```

A special note goes to the `nonce` field, which represents how many validators the address identified in the owner parameter has already registered to the ssv.network.

You can keep track of this counter yourself, or you can use the `ssv-scanner` tool made available by the SSV team to source it. For more information, please refer to the related user guide or to its [SDK documentation page](https://docs.ssv.network/developers/tools/ssv-scanner).

> ℹ️ Note: For more details on `operatorsInfoPath` parameter, head over to the [Operators data](#obtaining-operators-data) section.

Then the tool can be launched from the root folder, by running this command:
```sh
ssv-dkg init --configPath ./initiator-config/initiator.yaml
```

If the `--configPath` parameter is not provided, `ssv-dkg` will be looking for a file named `config.yaml` in `./config/` folder at the same root as the binary (i.e. `./config/config.yaml`)

#### Key resharing

Using DKG tool is possible to reshare existing validator key to a new set of operators. For example, at initial DKG we created a validator with [1,2,3,4] operator shares, now we can use these operators to reshare the validator to a new set of disjoint operators [5,6,7,8] or to a joint set [1,2,5,6] etc. 

⚠️ All operators (old set and new set) should be online to complete the resharing protocol. 

⚠️ New threshold will be computed based on a new set of operators using 3f+1 tolerance. 

⚠️ Generating a new RSA key pair is not possible at resharing. It is assumed that the inititators RSA key is already exists. 

The Initiator creates the initial details needed to run DKG between all operators via the init command. You can launch the following command with the appropriate values to each parameter:
```sh
ssv-dkg reshare \
          --operatorIDs 1,2,3,4 \
          --newOperatorIDs 5, 6, 7, 8 \
          --oldID "dbd12b3155454666a6710a2262695bb82cda41948d612d98" \
          --operatorsInfoPath ./examples/operators_integration.json \
          # Alternatively:
          # --operatorsInfo: '[{"id": 1,"public_key": "LS0tLS1CRUdJTiBSU0....","ip": "http://localhost:3030"}, {"id": 2,"public_key": "LS0tLS1CRUdJTiBSU0....","ip": "http://localhost:3030"},...]'
          --owner 0x81592c3de184a3e2c0dcb5a261bc107bfa91f494 \
          --nonce 4 \
          --outputPath /output \
          --initiatorPrivKey ./encrypted_private_key.json \
          --initiatorPrivKeyPassword ./password \
          --logLevel info \
          --logFormat json \
          --logLevelFormat capitalColor \
          --logFilePath ./initiator_logs/debug.log
```

Here's an explanation of each parameter:

| Argument                   | type                                      | description                                                                                        |
| -------------------------- | :---------------------------------------- | :------------------------------------------------------------------------------------------------- |
| --operatorIDs              | int[]                                     | Old operator IDs participated at initial or resharing DKG ceremony                                 |
| --newOperatorIDs           | int[]                                     | New operator IDs which will have private shares for an existing validator                          |
| --oldID                    | string                                    | HEX of previous DKG ceremony ID. Can be found at the keyshares-[validator pk]-[ID].json            |


Under the assumption that all the necessary files (`operators_info.json`, `encrypted_private_key.json`, `password`) are under the same folder (represented below with `<PATH_TO_FOLDER_WITH_CONFIG_FILES>`) you can run the tool using the command below:

```sh
docker run --name ssv_dkg_reshare \
-v "<PATH_TO_FOLDER_WITH_CONFIG_FILES>":/data -it \
"ssv-dkg:latest" /app reshare --configPath /data/reshare.yaml
```

### Deposit and register Validator

When the `ssv-dkg` tool is launched as shown above, it will commence a DKG ceremony with the selected operators, which will end in the creation of two files:
* a deposit JSON file - necessary to perform the transaction on the Deposit contract and activate the validator on the Beacon layer
* a key shares JSON file - necessary to register the validator on the ssv.network
### Troubleshooting

#### dial tcp timeout
```sh
2023-10-11T16:36:26.745937Z     FATAL   dkg-initiator   😥 Failed to initiate DKG ceremony:     {"error": "Post \"http://79.44.117.213:3030/init\": dial tcp 79.44.117.213:3030: i/o timeout"}
```
When this error appears, it means that the `ssv-dkg` tool cannot connect to one of the selected operators.
This could be temporary, but if it persists, we recommend changing one of the operators.
#### invalid URI for request
```sh
2023-10-11T16:29:47.226138Z     FATAL   dkg-initiator   😥 Failed to load operators:    {"error": "invalid operator URL parse \"80.181.85.114:3030\": invalid URI for request"}
```
When this error appears, it means that the endpoint information for one of the operators is incorrect.
You could manually verify the `operators_info.json` or the initiator command-generated by the webapp, or simply change one of the operators.
#### connection refused
```sh
2023-10-13T15:21:54.597429Z     FATAL   dkg-initiator   😥 Failed to initiate DKG ceremony:     {"error": "Post \"http://80.181.85.114:3030/init\": dial tcp 80.181.85.114:3030: connect: connection refused"}
```
When this error appears, it means that the `ssv-dkg` tool cannot connect to one of the selected operators, and the reason could be because their `ssv-dkg` operator node has shut down.
This could be temporary, as they will likely start the node again, but if it persists, we recommend changing one of the operators.


## Operator Quick start

A DKG-Operator is able to participate in multiple DKG ceremonies in parallel thanks to the `ssv-dkg` tool.
The `ssv-dkg` tool is separate from the `ssv-node`, and could be running on a different machine, but the two are heavily correlated, as the keyshare generated by the `ssv-dkg` tool, will ultimately be used by the Node itself to manage the related validator.

> ⚠️ The `ssv-dkg` client **should be kept online at all times**.
> This is paramount if you want to participate in DKG ceremonies initiated by stakers, thus having the chance to operate their validators.
> Please select the machine where you want to launch it in accordance to this principle.

### Pre requisites
In order to successfully participate in DKG ceremonies initiated by stakers, you will need to possess and/or provide this information:

* **operator ID** - the ID of the operator you want to receive keyshares created with DKG
* **machine endpoint** - the endpoint (protocol:ip:port) of the machine where you intend to execute the `ssv-dkg` tool (if you have a domain name, instead of an `ip` that works as well)
* **encrypted operator RSA private key** - this is a password-encrypted file, containing the operator's private key (follow [this guide to generate an encrypted private key file](https://docs.ssv.network/operator-user-guides/operator-node/installation#generate-operator-keys-encrypted) or [this migration guide to encrypt existing keys](https://docs.ssv.network/operator-user-guides/operator-node/installation#how-do-i-migrate-raw-deprecated-operator-keys))

So make sure to have them available before proceeding.

> ⚠️ The RSA key pair is needed to sign all of the messages exchanged between ceremony participants, but the public key linked to it will also be used to encrypt the generated keyshares.
> Thus, SSV Node Operators must use the private key already in their possession when running the DKG tool, otherwise they won't be able to decrypt the keyshare and perform validator duties.

### Start a DKG-operator

There are a couple of options to launch the DKG tool:
* [Launch with Docker and YAML file](#launch-with-docker-and-yaml-file-1)
* [Build from source](#build-from-source-1)

It is advised launching the tool as a Docker image as it is the most convenient way and only requires to have Docker installed. The team builds a Docker image with every release of the tool.

#### Launch with Docker and YAML file
All of the necessary configuration information can be provided in a YAML file (referenced as `operator.yaml` from now on).
A good way to manage all the necessary files (`encrypted_private_key.json`, `password`) is to store them in a single folder (in this case `operator-config`), together with the `operator.yaml` configuration file, like so:

```sh
ssv@localhost:~/ssv-dkg# tree operator-config
operator-config
├── encrypted_private_key.json
├── operator.yaml
└── password

1 directory, 3 files
```
With this configuration, a typical configuration file would look like this:

```yaml
operatorPrivKey: /data/encrypted_private_key.json
operatorPrivKeyPassword: /data/password
port: 3030
storeShare: true
logLevel: info
logFormat: json
logLevelFormat: capitalColor
logFilePath: /data/debug.log
outputPath: ./output
```

> ℹ️ In the config file above, `/data/` represents the container's shared volume created by the docker command itself with the `-v` option.

Under the assumption that all the necessary files (`encrypted_private_key.json`, `operator.yaml`, `password`) are under the same folder (represented below with `<PATH_TO_FOLDER_WITH_CONFIG_FILES>`) you can run the tool using the command below:

```sh
docker run --restart unless-stopped --name ssv_dkg -p 3030:3030  \
-v "<PATH_TO_FOLDER_WITH_CONFIG_FILES>":/data -it \
"ssv-dkg:latest" /app start-operator --configPath /data/operator.yaml
```

Just make sure to substitute `<PATH_TO_FOLDER_WITH_CONFIG_FILES>` with the actual folder containing all the files.

You can, of course, change the configuration above to one that suits you better, just be mindful about changing the path references in the docker command **and** in the `operator.yaml`` file as well.

#### Build from source

To build from source you'll need to have Go version 1.20 installed on your system

##### Build

A prerequisite for this is to have `go` version 1.20 installed on the system, and an optional requirement is to have the `make` tool installed as well (alternatively you could run the corresponding command defined in the `Makefile`).

```sh
make install
```

##### Launch with command line parameters

It is advised to store all the necessary files (`encrypted_private_key.json`, `password`) in a single folder (in this case `operator-config`), as shown below:

```sh
ssv@localhost:~/ssv-dkg# tree operator-config
operator-config
├── encrypted_private_key.json
└── password

1 directory, 2 files
```

To run the DKG tool as an operator, you can launch the following command with the appropriate values to each parameter:

```sh
ssv-dkg start-operator \
            --operatorPrivKey ./operator-config/encrypted_private_key.json  \
            --operatorPrivKeyPassword ./operator-config/password \
            --port 3030 \
            --storeShare true \
            --logLevel info \
            --logFormat json \
            --logLevelFormat capitalColor \
            --logFilePath ./operator-config/debug.log
            --DBPath ./output/operator1_db/
            --outputPath /output
```

Here's an explanation of each parameter:

| Argument         | type                                      | description                                                                                       |
| ---------------- | :---------------------------------------- | :------------------------------------------------------------------------------------------------ |
| --privKey        | string                                    | Private key of ssv operator (path, or plain text, if not encrypted)                               |
| --port           | int                                       | Port for listening messages (default: `3030`)                                                     |
| --password       | string                                    | Path to password file to decrypt the key (if absent, provide plain text private key)              |
| --storeShare     | boolean                                   | Whether to store the created bls key share to a file for later reuse if needed (default: `false`) |
| --outputPath              | string                                    | Path to store the output files (ecrypted share)                                                                     |
| --logLevel       | debug / info / warning / error / critical | Logger's log level (default: `debug`)                                                             |
| --logFormat      | json / console                            | Logger's encoding (default: `json`)                                                               |
| --logLevelFormat | capitalColor / capital / lowercase        | Logger's level format (default: `capitalColor`)                                                   |
| --logFilePath    | string                                    | Path to file where logs should be written (default: `./data/debug.log`)                           |
| --DBPath         | string                                    | Path to folder where Badger DB should be written (default: `./data/db.log`)                       |

##### Launch with YAML config file

It is also possible to use YAML configuration file, just as it was shown in the Docker section above.
Just pay attention to the path of the necessary files, which needs to be changed to reflect the local configuration. If the operator.yaml file is created in the same folder as the other files, and the folder structure looks like this:

```sh
ssv@localhost:~/ssv-dkg# tree operator-config
operator-config
├── encrypted_private_key.json
├── operator.yaml
└── password

1 directory, 3 files
```

Then the content of the YAML file should be changed to this:
```yaml
privKey: ./operator-config/encrypted_private_key.json
password: ./operator-config/password
port: 3030
storeShare: true
logLevel: info
logFormat: json
logLevelFormat: capitalColor
logFilePath: ./operator-config/debug.log
outputPath: ./output
```

Then the tool can be launched from the root folder, by running this command:
```sh
ssv-dkg start-operator --configPath "./operator-config/operator.yaml"
```

If the `--configPath` parameter is not provided, `ssv-dkg` will be looking for a file named `operator.yaml` in `./config/` folder at the same root as the binary (i.e. `./config/operator.yaml`)

### Update Operator metadata

> ⚠️ If you want to make sure to participate in DKG ceremonies initiated by stakers, and have the chance to operate their validators, it is absolutely necessary to the update operator with the proper information, and verify their correctness.

Once the DKG tool is up and running, please make sure to update your operator metadata, and provide your DKG Operator endpoint, in the form of `protocol:ip:port` (if you have a domain name, instead of an `ip` that works as well).

Please head over to [the Operator User guide on how to update metadata](https://docs.ssv.network/operator-user-guides/operator-management/setting-operator-metadata) and follow the instructions

## Example

To run localy an example with 4 operators. Configuration files: `examples/config`

1. Build the image
```sh
make docker-build-image # build the Docker image
```
2. Run 4 operators locally
```sh
make docker-demo-operators # run 4 local operators
```
3. In a separate terminal window, run inititator
```sh
make docker-demo-initiator # run 1 local initiator
```

Results will be placed to `examples/output`

## Flow Description:

1. The Initiator creates an initiation (`init`) message, signs it and sends it to all Operators
2. Upon receiving initiation message, the Operators check Initiator message signature and create their own DKG identity:
  * new DKG secrets created
  * if a new `init` message with ID [24]byte is received and at least 5 minutes have passed from the last init message with the same ID, the DKG instance is recreated
  * Exchange signed message containing the DKG identity is created
  * Operator replies to init message with the created Exchange message
3. The Initiator collects all responses into one combined message and verifies signatures
4. The Initiator sends back the combined message to all Operators
5. Each Operator receives combined exchange message and starts the DKG process, responding back to Initiator with a signed dkg deal bundle
6. The Initiator packs the deal bundles together and sends them back to all Operators
7. Operators process dkg bundles and finish the DKG protocol of creating a shared key. After DKG process is finished each Operator has a share of the shared key which can be used for signing
8. Each Operator signs a deposit root, using its share of the shared key, then encrypts the share with the initial RSA key and sends it to the Initiator
9. Initiator receives all messages from Operators with signatures/encrypted shares and prepares the deposit data with a signature and save it as JSON file
10. Initiator prepares a payload for SSV contract
11. After the deposit is successful and SSV contract transaction is accepted, Operators can continue with their duties using their share of the distributes key

> ℹ️ NOTE: Threshold is computed automatically using 3f+1 tolerance.

### Note on DKG instance management

A DKG-operator can handle multiple DKG instances, it saves up to `MaxInstances` (1024) up to `MaxInstanceTime` (5 minutes). If a new `init` arrives the DKG-operator tries to clean instances older than `MaxInstanceTime` from the list. If any of them are found, they are removed and the incoming is added, otherwise it responds with an error, saying that the maximum number of instances is already running.

## Security notes

It is important to briefly explain how the communication between DKG ceremony Initiator and Operators is secured:

1. Initiator is using RSA key (2048 bits) to sign init message sent to Operators. Upon receiving the signature, Operators verify it using public key included in the init message. If the signature is valid, Operators store this pub key for further verification of messages coming from the Initiator(s).
2. Operators are using RSA key (ssv Operator key - 2048 bits) to sign every message sent back to Initiator.
3. Initiator verifies every incoming message from any Operator using ID and Public Key provided by Operators' info file, then Initiator creates a combined message and signs it.
4. Operators verify each of the messages from other Operators participating in the ceremony and verifies Initiator's signature of the combined message.
5. During the DKG protocol execution, the BLS auth scheme is used - G2 for its signature space and G1 for its public keys


---

More info about how things are designed/work under the hood can be found [here](./design.md)
