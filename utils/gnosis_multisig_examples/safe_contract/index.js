// Reading .env file
require('dotenv').config();

// Importing Gnosis Safe SDK library
const { SafeFactory, SafeAccountConfig, ContractNetworksConfig } = require('@gnosis.pm/safe-core-sdk');
const Safe = require('@gnosis.pm/safe-core-sdk')["default"];

// Addresses
const ceo = process.env.ACCOUNT_1;
const cto = process.env.ACCOUNT_2;
const meme_artist = process.env.ACCOUNT_3;
const solidity_engineer = process.env.ACCOUNT_4;
const advisor = process.env.ACCOUNT_5;
const investor = process.env.ACCOUNT_6;
const yacht_shop = process.env.ACCOUNT_7;

// Importing ethers.js library
const { ethers } = require('ethers');
const provider = new ethers.providers.JsonRpcProvider("http://127.0.0.1:8545");

// Creating three signers
const ceo_signer = provider.getSigner(ceo);
const cto_signer = provider.getSigner(cto);
const advisor_signer = provider.getSigner(advisor);

// Creating three adapters
const EthersAdapter = require('@gnosis.pm/safe-ethers-lib')["default"];
const ethAdapter_ceo = new EthersAdapter({ ethers, signer: ceo_signer });
const ethAdapter_cto = new EthersAdapter({ ethers, signer: cto_signer });
const ethAdapter_advisor = new EthersAdapter({ ethers, signer: advisor_signer });

async function main() {
  // Creating a dictionary of three necessary smart contracts
  const id = await ethAdapter_ceo.getChainId();
  const contractNetworks = {
    [id]: {
      multiSendAddress: process.env.MULTI_SEND_ADDRESS,
      safeMasterCopyAddress: process.env.SAFE_MASTER_COPY_ADDRESS,
      safeProxyFactoryAddress: process.env.SAFE_PROXY_FACTORY_ADDRESS
    }
  }

  // Creating a safe factory
  const safeFactory = await SafeFactory.create({ ethAdapter: ethAdapter_ceo, contractNetworks: contractNetworks });

  // Creating a configuration of 3-to-5 multi-sig safe (needs 3 signatures of 5 to approve transactions)
  const owners = [ceo, cto, meme_artist, solidity_engineer, advisor];
  const threshold = 5;
  const safeAccountConfig = { owners: owners, threshold: threshold};

  // Deploying a safe
  const safeSdk_ceo = await safeFactory.deploySafe({safeAccountConfig});

  // Getting the address of the safe
  const treasury = safeSdk_ceo.getAddress();

  // 10 ETH in hexadecimal format
  const ten_ethers = ethers.utils.parseUnits("10", 'ether').toHexString();

  // Transaction of sending 10 ETH from the investor to the treasury (or the safe)
  const params = [{
        from: investor,
        to: treasury,
        value: ten_ethers
  }];

  // Executing the transaction
  await provider.send("eth_sendTransaction", params);
  console.log("Fund raising.");

  // Checking the balance
  const balance = await safeSdk_ceo.getBalance();
  console.log(`Initial balance of the treasury: ${ethers.utils.formatUnits(balance, "ether")} ETH`);

  // 3 ETH in hexadecimal format
  const three_ethers = ethers.utils.parseUnits("3", 'ether').toHexString();

  // Transaction of buying a yacht with 3 ETH
  const transaction = {
    to: yacht_shop,
    data: '0x',
    value: three_ethers
  };

  // CEO creates a transaction to be executed in the safe
  const safeTransaction = await safeSdk_ceo.createTransaction(transaction);
  const hash = await safeSdk_ceo.getTransactionHash(safeTransaction);

  // CEO approves the transaction
  const txResponse = await safeSdk_ceo.approveTransactionHash(hash);
  await txResponse.transactionResponse?.wait();

  // Constructing a Safe object from the treasury address from the CTO side
  const safeSdk_cto = await Safe.create({ ethAdapter: ethAdapter_cto,
                                          safeAddress: treasury,
                                          contractNetworks: contractNetworks });

  // CTO also approves the transaction to buy the yacht
  const safeTransactionCTO = await safeSdk_cto.createTransaction(transaction);
  const hashCTO = await safeSdk_ceo.getTransactionHash(safeTransaction);
  const txResponse_cto = await safeSdk_cto.approveTransactionHash(hashCTO);
  await txResponse_cto.transactionResponse?.wait();

  // Constructing a Safe object from the treasury address from the advisor side
  const safeSdk_advisor = await Safe.create({ ethAdapter: ethAdapter_advisor,
                                              safeAddress: treasury,
                                              contractNetworks: contractNetworks });

  // The advisor approves and executes the transaction to buy the yacht
  const safeTransactionAdvisor = await safeSdk_advisor.createTransaction(transaction);
  const txResponse_advisor = await safeSdk_advisor.executeTransaction(safeTransactionAdvisor);
  await txResponse_advisor.transactionResponse?.wait();
  console.log("Buying a yacht.");

  // Check the balance of the treasury after buying a yacht
  const afterBalance = await safeSdk_ceo.getBalance();
  console.log(`Final balance of the treasury: ${ethers.utils.formatUnits(afterBalance, "ether")} ETH`);
}

main();
