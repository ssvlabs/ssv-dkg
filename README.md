# ssv-dkg-tool

## Architecture

### Operators data 

The data of the operators (ID, IP, Pubkey) can be collected in any way, for example a central server that you can pull the data from, or a preset file where all operators data exist.

### CLI Client

The initiator uses `ssv-dkg-init` to create the initial details needed to run DKG between all operators.

Basic Flow:

1. The initiator creates an initial message, signs it and sends it to all operators (/init)
2. The operators upon receiving initial message check initiator message signature and create their DKG identity:
 - new DKG secrets created 
 - if 5 mins pass after the last init message with ID [24]byte and new init message with the same ID is incoming the DKG instance is recreated 
 - `Exchange` signed message containing the DKG identity is created
 - operator replies to init message with the created `Exchange` message
3. The initiator collects all responses into one message and verify signatures
4. The initiator  sends back to all operators the combined message (/dkg)
5. Operators receive all exchange messages to start the DKG process, responding back to initiator with a signed dkg deal bundle
6. Initiator packs the deal bundles together and sends them back to all operators (/dkg)
7. Operators process dkg bundles and finish the DKG protocol of creating a shared key

Output? : TBD

### Server

The dkg server is ran by a SSV operator, an Operator RSA private key is a requirement. 
The server is able to participate in multiple instances in parallel. 
Whenever the server recieves a message it directs it to the right instance by the identifier, and respond with an answer.

Initial message fields:

```go
 ID [24]byte //  [ addres:nonce ] or random
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
 // Timestamp prevent replay account in unix time
 Timestamp uint64 // ??? 
 // Initiator signature
 Sig []byte
```

### TODO: 
- [ ] Complete design with flows and structure
- [ ] Add pubkeys to init message
- [ ] output - signed ssv deposit data
- [ ] more testing
- [ ] logging
