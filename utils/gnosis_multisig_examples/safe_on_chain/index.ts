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
import SafeApiKit from "@safe-global/api-kit";
// This file can be used to play around with the Safe Core SDK

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
  SAFE_ADDRESS: "0x0205c708899bde67330456886a05Fe30De0A79b6",
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

  const MESSAGE = "I am the owner of DKG validator";
  let message = protocolKit1.createMessage(MESSAGE);

  // Get the contract with the correct version
  const signMessageLibContract = await getSignMessageLibContract({
    safeProvider: protocolKit1.getSafeProvider(),
    safeVersion: version,
  });

  // Validate the signature sending the Safe message hash and the concatenated signatures
  const messageHash = hashSafeMessage(MESSAGE);
  const txData = signMessageLibContract.encode("signMessage", [messageHash]);

  const safeTransactionData: SafeTransactionDataPartial = {
    to: await signMessageLibContract.getAddress(),
    value: "0",
    data: txData,
    operation: OperationType.DelegateCall,
  };

  const signMessageTx = await protocolKit1.createTransaction({
    transactions: [safeTransactionData],
  });

  let signerAddress =
    (await protocolKit1.getSafeProvider().getSignerAddress()) || "0x";
  var safeTxHash = await protocolKit1.getTransactionHash(signMessageTx);
  var signature = await protocolKit1.signHash(safeTxHash);

  // Propose transaction to the service
  await apiKit.proposeTransaction({
    safeAddress: config.SAFE_ADDRESS,
    safeTransactionData: signMessageTx.data,
    safeTxHash,
    senderAddress: signerAddress,
    senderSignature: signature.data,
  });

  console.log("Proposed a transaction with Safe:", config.SAFE_ADDRESS);
  console.log("- safeTxHash:", safeTxHash);
  console.log("- Sender:", signerAddress);
  console.log("- Sender signature:", signature.data);

  // Confirm safeTransaction by Owner 2
  let protocolKit2 = await Safe.init({
    provider: config.RPC_URL,
    signer: config.OWNER2_PRIVATE_KEY,
    safeAddress: config.SAFE_ADDRESS,
  });
  // Get the transaction
  const safeTransaction = await apiKit.getTransaction(safeTxHash);
  safeTxHash = safeTransaction.safeTxHash;
  signature = await protocolKit2.signHash(safeTxHash);
  // Confirm the Safe transaction
  const signatureResponse = await apiKit.confirmTransaction(
    safeTxHash,
    signature.data
  );
  console.log(
    "Added a new signature to transaction with safeTxGas:",
    safeTxHash
  );
  console.log(
    "- Signer:",
    await protocolKit2.getSafeProvider().getSignerAddress()
  );
  console.log("- Signer signature:", signatureResponse.signature);

  console.log("Message: ", MESSAGE);
  console.log("Message Hash: ", messageHash);
  console.log("Encoded Signatures: ", message.encodedSignatures());
}

main();
