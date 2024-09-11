# The code sample of how to use the Gnosis Safe SDK for Multisig reshare message

## Getting Started

Deploy the Gnosis Safe smart contract:

```
$ git clone https://github.com/gnosis/safe-contracts/
$ cd safe-contracts
$ git checkout v1.3.0-libs.0
$ yarn add hardhat
$ npx hardhat node
```

Notice where `GnosisSafeProxyFactory`, `GnosisSafe`, `MultiSend` are deployed from the output of the
`npx hardhat node` command. Make sure they are the same as MULTI_SEND_ADDRESS, SAFE_MASTER_COPY_ADDRESS,
SAFE_PROXY_FACTORY_ADDRESS on the `.env` file from this repository.
Then open a new terminal.

Clone this repository, install dependencies, and run the code:

```
$ yarn install
$ node index.js
```
