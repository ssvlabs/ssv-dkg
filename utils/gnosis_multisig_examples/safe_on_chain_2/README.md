# The code sample of how to use the Gnosis Safe Wallet for Multisig reshare message

## Getting Started

Use Safe wallet https://app.safe.global/:

1. create a new Safe wallet with 3 accounts and 2 threshold
2. Load the RPC URL and owner private keys from environment variables instead of editing the script:

```
$ export ETH_RPC_URL=https://eth-sepolia.g.alchemy.com/v2/<your-key>
$ export OWNER1_PRIVATE_KEY=<owner-1-private-key>
$ export OWNER2_PRIVATE_KEY=<owner-2-private-key>
$ export OWNER3_PRIVATE_KEY=<owner-3-private-key>
$ yarn install
$ npx tsc
$ node index.js
```

You can also keep those values in a local `*.env` file and source it before running the script.
