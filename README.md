# ssv-dkg-tool

## Architecture

### Operators data 

The data of the operators (ID, IP, Pubkey) can be collected in any way, for example a central server that you can pull the data from, or a preset file where all operators data exist.

### CLI Client

The initiator uses `ssv-dkg-init` to create the initial details needed to run DKG between all operators.
Init data -
```go

 ID [24]byte //  todo: [ addres:nonce ] or random
 // Operators involved in the DKG
 Operators []{uint64, []byte}  // ID, PUBKEY
 // T is the threshold for signing
 T uint64
 // WithdrawalCredentials for deposit data
 WithdrawalCredentials []byte
 // Fork ethereum fork for signing
 Fork [4]byte

//TODO:
Owner address, 
Nonce
Timestamp - prevent replay account

```

The initiator shoots the init message to all operators and listens to response from them,
the operators use this data and create their DKG identity, they response with an `Exchange` message containing the key of this identity.
The initiator collects all responses into one message and disseminates it back to all operators as one message.
Operators recv enough exchange messages to start the DKG process, responding back to initiator with a dkg deal bundle.
initiator packs the deal bundles together and sends them to all operators. this should be enough to finish DKG.

Output? : TBD

### Server

The dkg server is ran by a SSV operator, an Operator RSA private key is a requirement. 
The server is able to participate in multiple instances in parallel. 
Whenever the server recieves a message it directs it to the right instance by the identifier, and respond with an answer.


### TODO: 
- [ ] Complete design with flows and structure
- [ ] output - signed ssv deposit data
- [ ] more testing
- [ ] logging