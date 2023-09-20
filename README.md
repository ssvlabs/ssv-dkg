# ssv-dkg

## Quickstart

### Overview

In order for the DKG protocol to execute successfully:
* all the chosen operators must be running the `ssv-dkg` tool as Operators
* separately, an Initiator (one of the Operators, or a separate entity), starts the DKG ceremony by running the `ssv-dkg` tool with the `init` parameter
* the tool automatically exchange data between the interested parties, as outlined in the [Architecture](#basic-flow-description) section, until the key shares are created

### Build

```sh
make install
```

### Operator

SSV Operators typically play the role of dkg-operators, running the `ssv-dkg` tool as Operators. As a result, it is an Operator RSA private key is a requirement. A dkg-operator is able to participate in multiple DKG ceremonies in parallel.

⚠️ **NOTE:** `ssv-dkg` tool is using an ssv operator private key file. Both encrypted and plain text versions are supported. If `password` parameter is provided then the `ssv-dkg` tool assumes that the operator's RSA key is encrypted, otherwise it assumes that the key is provided as plain text.

#### Start a DKG-operator

```sh
ssv-dkg start-operator \
            --privKey ./examples/operator1/encrypted_private_key.json  \
            --port 3030 \
            --password ./password \
            --storeShare true \
            --logLevel info \
            --logFormat json \
            --logLevelFormat capitalColor \
            --logFilePath ./operator1_logs/debug.log

### where
--privKey ./encrypted_private_key.json # path to ssv operator`s private key
--port 3030 # port for listening messages
--password: ./password # path to password file to decrypt the key
--storeShare: true # store the bls key share created during DKG ceremony to a file for later reuse if needed
--logLevel: info # logger's log level (info/debug/
--logFormat: json # logger's encoding, valid values are 'json' (default) and 'console'
--logLevelFormat: capitalColor # logger's level format, valid values are 'capitalColor' (default), 'capital' or 'lowercase''
--logFilePath: ./operator1_logs/debug.log # a file path to write logs into
```

It is also possible to use a YAML configuration file

Example:

```yaml
privKey: ./encrypted_private_key.json
password: ./password
port: 3030
storeShare: true
logLevel: info
logFormat: json
logLevelFormat: capitalColor
logFilePath: ./operator1_logs/debug.log
```

When using configuration file, run:

```sh
ssv-dkg start-operator --configPath "/examples/config/operator4.example.yaml"
```

`ssv-dkg` will be looking for a file named `operator.yaml` in `./config/` folder at the same root as the binary (i.e. `./config/operator.yaml`)

### Initiator

#### Generate initiator identity RSA key pair

The initiator needs to sign all messages exchanged with DKG participants with an RSA key.

To generate initiator RSA keys, launch the following command, replacing `<PASSWORD>` with a password of your choosing:

```sh
ssv-dkg generate-initiator-keys --password <PASSWORD>
```

This will create `encrypted_private_key.json` with encrypted by password RSA key pair.
Write down your chosen password in any text file, for example to `./password`.

⚠️ **NOTE:** For more details on `operatorsInfoPath` please read the [note on obtaining Operators data](#note-on-operators-data) below.

The initiator creates the initial details needed to run DKG between all operators via the `init` command. Copy (or type) and run the following:

```sh
ssv-dkg init \
          --operatorIDs 1,2,3,4 \
          --operatorsInfoPath ./operators_integration.json \
          --owner 0x81592c3de184a3e2c0dcb5a261bc107bfa91f494 \
          --nonce 4 \
          --withdrawAddress 0000000000000000000000000000000000000009  \
          --fork "mainnet" \
          --depositResultsPath deposit.json \
          --ssvPayloadResultsPath payload.json \
          --initiatorPrivKey ./encrypted_private_key.json \
          --initiatorPrivKeyPassword ./password \
          --logLevel info \
          --logFormat json \
          --logLevelFormat capitalColor \
          --logFilePath ./initiator_logs/debug.log

#### where
--operatorIDs 1,2,3,4 # operator IDs which will be used for a DKG ceremony
--operatorsInfoPath ./operators_integration.json # path to operators info: ID,base64(RSA pub key),
--owner 0x81592c3de184a3e2c0dcb5a261bc107bfa91f494 # owner address for the SSV contract
--nonce 4 # owner nonce for the SSV contract
--withdrawAddress # Reward payments of excess balance over 32 ETH will automatically and regularly be sent to a withdrawal address linked to each validator, once provided by the user. Users can also exit staking entirely, unlocking their full validator balance.
--fork "mainnet" # fork name: mainnet, prater, or now_test_network
--depositResultsPath: ./output/ # path and filename to store the staking deposit file
--ssvPayloadResultsPath: ./output/ # path and filename to store ssv contract payload file
--initiatorPrivKey ./encrypted_private_key.json # path to ssv initiators`s private key
--initiatorPrivKeyPassword: ./password # path to password file to decrypt the key
--logLevel: info # logger's log level (info/debug/
--logFormat: json # logger's encoding, valid values are 'json' (default) and 'console'
--logLevelFormat: capitalColor # logger's level format, valid values are 'capitalColor' (default), 'capital' or 'lowercase''
--logFilePath: ./initiator_logs/debug.log # a file path to write logs into
```

It is also possible to use YAML configuration file for parameters:

Example:

```yaml
operatorIDs: [1, 2, 3, 4]
withdrawAddress: "0000000000000000000000000000000000000009"
owner: "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494"
nonce: 4
fork: "00000000"
operatorsInfoPath: ./examples/operators_integration.json
depositResultsPath: ./output/
ssvPayloadResultsPath: ./output/
privKey: ./encrypted_private_key.json
password: ./password
```

When using configuration file, simply run:

```sh
ssv-dkg init --configPath /examples/config/initiator.example.yaml
```

`ssv-dkg` will be looking for a file named `initiator.yaml` in `./config/` folder in the same root as the binary (i.e. `./config/initiator.yaml`)

`init` message fields:

```go
 ID [16]byte //   random UUID
 // Operators involved in the DKG
 Operators []byte  // [ ID:pubkey ]  // uint8 ID 1byte + RSA pub key
 // T is the threshold for signing
 T uint64
 // WithdrawalCredentials for deposit data
 WithdrawalCredentials []byte
 // Fork ethereum fork for signing
 Fork [4]byte
  // Owner address
 Owner [20]byte
 // Nonce
 Nonce int
```

⚠️ **NOTE:** Threshold is computed automatically using 3f+1 tolerance.

#### Obtaining Operators data

SSV does not provide operators data for the operations described above (ID, URL, Pub key), teams integrating with SSV are responsible for sourcing it however they see fit. This information is publicly available though, and can be collected in various ways.

Suggested options are, for example, a centralized ad-hoc Operator data service, or a preset file where all operators data is stored.

Information about operators can be collected in a `json` file and supplied to initiator to be used use for the key generation ceremony, as shown above.

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

---

### Security notes

It is important to briefly explain how the communication between DKG ceremony initiator and operators is secured:

1. Initiator is using RSA key (2048 bits) to sign `init` message sent to operators. Upon receiving the signature, operators verify it using public key included in the `init` message. If the signature is valid, operators store this pub key for further verification of messages coming from the initiator(s).

2. Operators are using RSA key (ssv operator key - 2048 bits) to sign every message sent back to initiator.

3. Initiator verifies every incoming message from any operator using ID and Public Key provided by operators' info file, then initiator creates a combined message and signs it.

4. Operators verify each of the messages from other operators participating in the ceremony and verifies initiator's signature of the combined message.

5. During the DKG protocol execution, the BLS auth scheme is used - G2 for its signature space and G1 for its public keys

More details in the [Architecture](#architecture) section below.

## Architecture

![flow](./docs/imgs/DKGinit.drawio.png)

### Flow Description:

1. The initiator creates an initiation message, signs it and sends it to all operators (`/init`)

2. The operators upon receiving initiation message check initiator message signature and create their DKG identity:

- new DKG secrets created
- if 5 mins pass after the last `init` message with ID [24]byte and new `init` message with the same ID is incoming, the DKG instance is recreated
- `Exchange` signed message containing the DKG identity is created
- operator replies to `init` message with the created `Exchange` message

3. The initiator collects all responses into one message and verifies signatures

4. The initiator sends back to all operators the combined message (`/dkg`)

5. Operators receive all exchange messages to start the DKG process, responding back to initiator with a signed `dkg` deal bundle

6. Initiator packs the deal bundles together and sends them back to all operators (`/dkg`)

7. Operators process `dkg` bundles and finish the DKG protocol of creating a shared key. After DKG process is finished each operator has a share of the shared key which can be used for signing

8. Operator using its share of the shared key signs a deposit root, encrypts with the initial RSA key the share and sends it to the initiator

9.  Initiator receives all messages from operators with signatures/encrypted shares and prepares the deposit data with a signature and save it as JSON file

10. Initiator prepares a payload for SSV contract

11. After the deposit is successful and SSV contract transaction is accepted, operators can continue with their duties using their share of the distributes key

Result of successful DKG protocol execution for an operator:

```go
type Result struct {
	QUAL []Node // list of nodes that successfully ran the protocol
	Key  *DistKeyShare // the share of the node
}
type DistKeyShare struct {
    // Coefficients of the public polynomial holding the public key.
    Commits []kyber.Point
    // Share of the distributed secret which is private information. This will be used to sign. All sigs can be aggregated to create a T-threshold signature
    Share *share.PriShare
}
```

Output of an operator when DKG ceremony is complete:

```go
	// RequestID for the DKG instance (not used for signing)
	RequestID [24]byte
	// EncryptedShare standard SSV encrypted shares
	EncryptedShare []byte
	// SharePubKey is the share's BLS pubkey
	SharePubKey []byte
	// ValidatorPubKey the resulting public key corresponding to the shared private key
	ValidatorPubKey types.ValidatorPK
	// Partial Operator Signature of Deposit Data
	PartialSignature types.Signature
```

## DKG protocol description - Operator Point of View

#### `init` phase

1. Upon receiving `init` message from initiator, operator verifies that the same `init` message ID[24]byte does not exist. If not, the operator creates a kyber-bls12381 instance. Otherwise, the same instance is used. The instance consists of:

- randomly generated scalar
- corresponding point in elliptic curve group G1 (384 bit)

#### `exchange` phase

1. The Operator then creates a signed `exchange` message consisting of ID[24]byte and point bits

2. Operator creates DKG node, made of:

  - operator ID uint64;
  - operators G1 point;

3. Operator creates a time phaser

#### `deal` phase

1. DKG time phaser starts `deal` phase

  - computes a private share for each of the operators ids
  - encrypts with a corresponding to the operator BLS public key created during the exchange step
  - pack all `deal`s together and signs

2. `deal` bundle is created and sent back to the initiator
3. Operator creates the public polynomial from received bundle
4. For each `deal` decrypts a deal share
5. Checks if share is valid w.r.t. public commitment
6. Forms a response bundle

### `Switch` instance management

The DKG-operator can handle multiple DKG instances, it saves up to `MaxInstances` (1024) up to `MaxInstanceTime` (5 minutes). If a new `Init` arrives the DKG-operator tries to clean instances older than `MaxInstanceTime` from the list. If any of them are found, they are removed and the incoming is added, otherwise it responds with an error, saying that the maximum number of instances is already running.

## Development Notes:

### Features list and implementation:

- [x] Complete design with flows and structure
- [x] output - signed ssv deposit data + encrypted shares for SSV contract
- [x] verification of ssv deposit data and encrypted shares
- [ ] existing validator public key resharing
- [x] CLI for initiator and operators
- [x] keystore for operators
- [x] more testing
- [x] logging

### Additional:

- [x] limit max of operators (T-threshold min/max)
- [x] secure the communication between initiator and operators

### Flows coverage:

---

- [~100%] New key generation

#### Round 1

- [x] CLI for initiator
- [x] CLI for operator
- [x] RSA secret storage for operator
- [x] Init message:
  - [x] Message sig validation
  - [x] Init message owner + nonce fields. ID is random UUID
  - [x] Timeouts
  - [x] Error handling
- [x] Exchange message:
  - [x] Message sig validation
  - [x] Timeouts
  - [x] Error handling
- [x] Code refactoring
- [x] Unit tests
- [x] integration tests

#### Round 2

- [x] Deal message:
- [x] Result message:
  - [x] Storage for key shares and DKG result
  - [x] Validate signature shares + validator pub key + pub and encrypted shares at initiator
- [x] Timeouts
- [x] Code refactoring
- [x] Error handling
- [x] Unit tests

---

- [50%] Key resharing (new operator keys but same validator pub key) - implemented 0%

- [x] CLI command and message to initiate resharing protocol
- [x] Handlers of DKG key resharing messages exchange
- [ ] Store new keys, update storage at operators
- [ ] Error handling
- [ ] Unit tests
