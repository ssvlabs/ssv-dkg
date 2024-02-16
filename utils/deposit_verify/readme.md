Prerequisites:

- node > 10
- npm > 6

1. `npm install`
2. `source .env.[network]`
3. `npm --path=[path to deposit_data.json] run-script start`

Example of successful deposit file validation:

```sh
[
  {
    pubkey: '98908cdf9865d05e9f8492eb8d8d965ba367e44204f7f1081d22e459f7d8a85e209ce8b6655ea7b6173873db4f311180',
    withdrawal_credentials: '01000000000000000000000081592c3de184a3e2c0dcb5a261bc107bfa91f494',
    amount: 32000000000,
    signature: 'b75b97b2ab86aa92cd31e9c490504691952ece8967df32626dadbf00a40500afad3d1b2b7c3c5546aa7c153434d0839f04a6f7fc4062c42234df1ac19fd64214ff7cf371a78ec235bc18cfef8f2d083a1cc918aebec3f48904ab63821fbc576d',
    deposit_message_root: 'fe4622f5aeaf99e533334e5bf1905da5c3e259a50a80d478ec19cb1ad5d9ddaa',
    deposit_data_root: '42e69087b9df3ac372d75465aab7caf8404d4d6e441a5682fc672bb090ed7cb5',
    fork_version: '01017000',
    network_name: 'holesky',
    deposit_cli_version: '2.7.0'
  }
]
Ready for deposit  98908cdf9865d05e9f8492eb8d8d965ba367e44204f7f1081d22e459f7d8a85e209ce8b6655ea7b6173873db4f311180

```

Example of failed deposit file validation:

```sh
[
  {
    pubkey: '08908cdf9865d05e9f8492eb8d8d965ba367e44204f7f1081d22e459f7d8a85e209ce8b6655ea7b6173873db4f311180',
    withdrawal_credentials: '01000000000000000000000081592c3de184a3e2c0dcb5a261bc107bfa91f494',
    amount: 32000000000,
    signature: 'b75b97b2ab86aa92cd31e9c490504691952ece8967df32626dadbf00a40500afad3d1b2b7c3c5546aa7c153434d0839f04a6f7fc4062c42234df1ac19fd64214ff7cf371a78ec235bc18cfef8f2d083a1cc918aebec3f48904ab63821fbc576d',
    deposit_message_root: 'fe4622f5aeaf99e533334e5bf1905da5c3e259a50a80d478ec19cb1ad5d9ddaa',
    deposit_data_root: '42e69087b9df3ac372d75465aab7caf8404d4d6e441a5682fc672bb090ed7cb5',
    fork_version: '01017000',
    network_name: 'holesky',
    deposit_cli_version: '2.7.0'
  }
]
err verifying deposit root
not accepted
```
