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

  const MESSAGE = "I am the owner of DKG validator 5";
  var safeMessage = protocolKit1.createMessage(MESSAGE);
  const messageHash = hashSafeMessage(MESSAGE);

  const isValid = await protocolKit1.isValidSignature(
    messageHash,
    "0x94ed7e91987dad7470e528ad11af59d4cd5e8c9195e69d752d083646b5c2141a3b54abe2bc069f72c7d49bb7be7185490e0cd349669903751573d656d35e04c51b6d0689838c826594c71919d091f7cbd83517b3ef18e54f1c0cf951fe792e957c2cf241a64ac126939c7394f01d945613c4a0c82bc249e251dd65dffaf70ae0d11c"
  );

  console.log("Message: ", MESSAGE);
  console.log("Message Hash: ", messageHash);

  console.log(
    "Encoded Signatures: ",
    "0x94ed7e91987dad7470e528ad11af59d4cd5e8c9195e69d752d083646b5c2141a3b54abe2bc069f72c7d49bb7be7185490e0cd349669903751573d656d35e04c51b6d0689838c826594c71919d091f7cbd83517b3ef18e54f1c0cf951fe792e957c2cf241a64ac126939c7394f01d945613c4a0c82bc249e251dd65dffaf70ae0d11c"
  );

  console.log(`The signature is ${isValid ? "valid" : "invalid"}`);
}
main();
