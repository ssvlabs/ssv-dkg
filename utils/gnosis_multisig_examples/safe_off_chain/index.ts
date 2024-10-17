import Safe, {
  SigningMethod,
  buildContractSignature,
  getSignMessageLibContract,
} from "@safe-global/protocol-kit";
import { hashSafeMessage } from "@safe-global/protocol-kit";
import {
  OperationType,
  SafeTransactionDataPartial,
} from "@safe-global/safe-core-sdk-types";
import SafeApiKit, {
  EIP712TypedData as ApiKitEIP712TypedData,
} from "@safe-global/api-kit";
// This file can be used to play around with the Safe Core SDK
import fs from "fs";

interface Config {
  RPC_URL: string;
  OWNER1_PRIVATE_KEY: string;
  OWNER2_PRIVATE_KEY: string;
  OWNER3_PRIVATE_KEY: string;
  SAFE_ADDRESS: string;
  CHAIN_ID: bigint;
}

// To run this script, you need a Safe with the following configuration
// - 3/3 Safe with 3 owners and threshold 3
//   - Owner 1: public address from OWNER1_PRIVATE_KEY
//   - Owner 2: public address from OWNER2_PRIVATE_KEY
//   - Owner 3: public address from OWNER3_PRIVATE_KEY
//   - SAFE_WALLET: public of safe wallet address with 2/3 threshold
const config: Config = {
  RPC_URL:
    "https://eth-sepolia.g.alchemy.com/v2/YyqRIEgydRXKTTT-w_0jtKSAH6sfr8qz",
  OWNER1_PRIVATE_KEY:
    "",
  OWNER2_PRIVATE_KEY:
    "",
  OWNER3_PRIVATE_KEY:
    "",
  SAFE_ADDRESS: "0x43908b5794da9A8f714f001567D8dA1523e68bDb",
  CHAIN_ID: 11155111n,
};

async function main() {
  // Create Safe API Kit instance
  const apiKit = new SafeApiKit({
    chainId: config.CHAIN_ID,
  });

  let protocolKit1 = await Safe.init({
    provider: config.RPC_URL,
    signer: config.OWNER1_PRIVATE_KEY,
    safeAddress: config.SAFE_ADDRESS,
  });

  let version = await protocolKit1.getContractVersion();

  console.log("Creating transaction with Safe:");
  console.log(" - Address: ", await protocolKit1.getAddress());
  console.log(" - ChainID: ", await protocolKit1.getChainId());
  console.log(" - Version: ", version);
  console.log(" - Threshold: ", await protocolKit1.getThreshold(), "\n");

  const MESSAGE =
    "a20beb9b6520db317bb4555d0c0d889519808166352348883e91e28eb91124c2";
  var safeMessage = protocolKit1.createMessage(MESSAGE);
  const messageHash = hashSafeMessage(MESSAGE);
  const signedMessage = await protocolKit1.signMessage(safeMessage);
  const safeMessageHash = await protocolKit1.getSafeMessageHash(
    hashSafeMessage(safeMessage.data)
  );

  await apiKit.addMessage(config.SAFE_ADDRESS, {
    message: safeMessage.data as string | ApiKitEIP712TypedData,
    signature: signedMessage.encodedSignatures(),
  });

  // confirm by Owner 2
  let protocolKit2 = await Safe.init({
    provider: config.RPC_URL,
    signer: config.OWNER2_PRIVATE_KEY,
    safeAddress: config.SAFE_ADDRESS,
  });
  safeMessage = await protocolKit2.signMessage(safeMessage);

  await apiKit.addMessageSignature(
    safeMessageHash,
    safeMessage.encodedSignatures()
  );
  var messageResponse = await apiKit.getMessage(safeMessageHash);
  console.log(" - Confirmations: ", messageResponse.confirmations.length);

  const isValid = await protocolKit1.isValidSignature(
    messageHash,
    messageResponse.preparedSignature
  );

  console.log("Message: ", MESSAGE);
  console.log("Message Hash: ", messageHash);
  console.log("Safe Message Hash: ", safeMessageHash);
  console.log("Encoded Signatures: ", messageResponse.preparedSignature);

  console.log(`The signature is ${isValid ? "valid" : "invalid"}`);
}
main();
