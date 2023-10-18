# ssv-dkg

## Quick start

```sh
make docker-build-image # build the Docker image
```

Run

```sh
make docker-operator # run operator at docker, make sure to update ./examples/config/operator1.example.yaml
```


```sh
make docker-initiator # run initiator at docker, make sure to update ./examples/config/initiator.example.yaml
```

##### Docker demo example

```sh
make docker-demo-operators # run 4 local operators
```

```sh
make docker-demo-initiator # run 1 local initiator
```

To compile a binary at system, run:

```sh
make build
```

compiled binary will be placed to `./bin`

To instal system wide, run

```sh
make install
```

### Operators data

The data of the operators (ID, IP, Pubkey) can be collected in any way, for example a central server that you can pull the data from, or a preset file where all operators data exist.

Information about operators can be collected at `json` file and supplied to initiator.

Operators info file example (`./examples/operators_integration.json`):

```json
[
  {
    "id": 1,
    "public_key": "LS0tLS1CRUdJTiBSU0....",
    "ip": "http://localhost:3030"
  },
  {
    "id": 2,
    "public_key": "LS0tLS1CRUdJTiB....",
    "ip": "http://localhost:3031"
  }
]
```

### Operator

The dkg-operator is ran by aт SSV operator (operator RSA private key is a requirement).
The operator is able to participate in multiple DKG ceremonies in parallel.

NOTE: ssv-dkg tool is using an ssv operator private key file. Both encrypted and plaintext versions are supported. If `password` parameter is provided then the ssv-dkg tool assumes that the operator`s RSA key is encrypted, if not that the key is a plaintext.

#### Start a DKG-operator

```sh
ssv-dkg start-operator \
            --privKey ./examples/operator1/encrypted_private_key.json  \
            --port 3030 \
            --password ./examples/operator1/password \
            --storeShare true \
            --logLevel info \
            --logFormat json \
            --logLevelFormat capitalColor \
            --logFilePath ./examples/output/operator1_logs_debug.log

### where
--privKey ./examples/operator1/encrypted_private_key.json # path to ssv operator`s private key
--port 3030 # port for listening messages
--password: ./examples/operator1/password # path to password file to decrypt the key
--storeShare: true # store created bls key share to a file for later reuse if needed
--logLevel: info # logger's log level (info/debug/
--logFormat: json # logger's encoding, valid values are 'json' (default) and 'console'
--logLevelFormat: capitalColor # logger's level format, valid values are 'capitalColor' (default), 'capital' or 'lowercase''
--logFilePath: ./examples/operator1_logs_debug.log # a file path to write logs into
```

Its also possible to use yaml configuration file `./config/operator.yaml` for parameters. `ssv-dkg` will be looking for the config file `config.yaml` at `./config/` folder if only a folder path is provided.

Example:

```yaml
privKey: /data/operator1/encrypted_private_key.json
password: /data/operator1/password
port: 3030
storeShare: false
logLevel: info
logFormat: json
logLevelFormat: capitalColor
logFilePath: /data/output/operator1_logs_debug.log
```

When using configuration file, run:

```sh
ssv-dkg start-operator --configPath ./examples/config/operator1.example.yaml
```

### Initiator

The initiator uses `init` to create the initial details needed to run DKG between all operators.

Run:

```sh
ssv-dkg init \
          --operatorIDs 1,2,3,4 \
          --operatorsInfoPath ./examples/operators_integration.json \
          --owner 0x81592c3de184a3e2c0dcb5a261bc107bfa91f494 \
          --nonce 4 \
          --withdrawAddress 0000000000000000000000000000000000000009  \
          --network "mainnet" \
          --outputPath ./output/ \
          --initiatorPrivKey ./examples/initiator/encrypted_private_key.json \
          --initiatorPrivKeyPassword ./examples/initiator/password \
          --logLevel info \
          --logFormat json \
          --logLevelFormat capitalColor \
          --logFilePath ./examples/output/initiator_debug.log

#### where
--operatorIDs 1,2,3,4 # operator IDs which will be used for a DKG ceremony
###### Operators info data part.
###### operatorsInfoPath or operatorsInfo, not both.
--operatorsInfoPath ./operators_integration.json # path to operators info file or directory.
--operatorsInfo '[{"id": 1,"public_key": "LS0tLS1CRUdJTiBSU0....","ip": "http://localhost:3030"}, {"id": 2,"public_key": "LS0tLS1CRUdJTiBSU0....","ip": "http://localhost:3030"},...]' # raw JSON string containing operators info.
######
--owner 0x81592c3de184a3e2c0dcb5a261bc107bfa91f494 # owner address for the SSV contract
--nonce 4 # owner nonce for the SSV contract
--withdrawAddress # Reward payments of excess balance over 32 ETH will automatically and regularly be sent to a withdrawal address linked to each validator, once provided by the user. Users can also exit staking entirely, unlocking their full validator balance.
--network "mainnet" # network name: mainnet, prater, or now_test_network
--outputPath: ./output/ # path to store results
###### Initiator RSA key management part.
###### Use either key file (if password is provided, will try to decrypted, else plaintext) or generate a new key pair. Not both.
--initiatorPrivKey ./encrypted_private_key.json # path to ssv initiators`s private key
--initiatorPrivKeyPassword: ./password # path to password file to decrypt the key. If not provided key file considered contains plaintext key.
##
--generateInitiatorKey: true # default false. If set true - generates a new RSA key pair + random secure password. Result stored at `outputPath`
#####
--logLevel: info # logger's log level (info/debug/
--logFormat: json # logger's encoding, valid values are 'json' (default) and 'console'
--logLevelFormat: capitalColor # logger's level format, valid values are 'capitalColor' (default), 'capital' or 'lowercase''
--logFilePath: ./initiator_logs/debug.log # a file path to write logs into
```

Its also possible to use yaml configuration file `./config/initiator.yaml` for parameters. `ssv-dkg` will be looking for the config file `config.yaml` at `./config/` folder if only a folder path is provided.

Example:

```yaml
operatorIDs: [1, 2, 3, 4]
withdrawAddress: "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494"
owner: "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494"
nonce: 0
network: "mainnet"
operatorsInfoPath: /data/docker_operators.json
outputPath: /data/output/
initiatorPrivKey: /data/initiator/encrypted_private_key.json
initiatorPrivKeyPassword: /data/initiator/password
logLevel: info
logFormat: json
logLevelFormat: capitalColor
logFilePath: /data/output/initiator_debug.log
```

When using configuration file, run:

```sh
ssv-dkg init --configPath /examples/config/initiator.example.yaml
```

**_NOTE: Threshold is computed automatically using 3f+1 tolerance._**

---

## Security notes

Here we explain how we secure the communication between DKG ceremony initiator and operators

1. Initiator is using RSA key (2048 bits) to sign init message sent to operators. Upon receiving operators verify the sig using pub key at init message. If the sig is valid, operators store this pub key for further verification of messages coming from the initiator(s).
2. Operators are using RSA key (ssv operator key - 2048 bits) to sign every message sent back to initiator.
3. Initiator verifies every message incoming from any operator using ID and Public Key provided by operators info file, then initiator creates a combined message and signs it.
4. Operators verify each of the messages of other operators participating in the ceremony and verifies initiator`s signature of the combined message.
5. During the DKG protocol execution, the BLS auth scheme is used - G2 for its signature space and G1 for its public keys

### `Switch` instance management

The DKG-operator can handle multiple DKG instances, it saves up to MaxInstances(1024) up to `MaxInstanceTime` (5 minutes). If a new Init arrives we try to clean our list from instances older than `MaxInstanceTime` if we find any, we remove them and add the incoming, otherwise we respond with error that the maximum number of instances is already running.

More info about how things are designed/work under the hood can be found [here](./design.md)
