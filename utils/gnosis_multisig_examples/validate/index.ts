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
  OWNER1_PRIVATE_KEY: "",
  OWNER2_PRIVATE_KEY: "",
  OWNER3_PRIVATE_KEY: "",
  SAFE_ADDRESS: "0xC4D860871fb983d17eC665a305e98F1B3035a817",
  CHAIN_ID: 11155111n,
};

async function main() {
  // Create Safe API Kit instance
  const apiKit = new SafeApiKit({
    chainId: config.CHAIN_ID,
  });

  let protocolKit1 = await Safe.init({
    provider: config.RPC_URL,
    safeAddress: config.SAFE_ADDRESS,
  });

  let version = await protocolKit1.getContractVersion();

  console.log("Creating transaction with Safe:");
  console.log(" - Address: ", await protocolKit1.getAddress());
  console.log(" - ChainID: ", await protocolKit1.getChainId());
  console.log(" - Version: ", version);
  console.log(" - Threshold: ", await protocolKit1.getThreshold(), "\n");

  var reshareBulk = JSON.parse(
    fs.readFileSync(
      "../../../integration_test/stubs/reshare/reshare_msgs.json",
      "utf-8"
    )
  );

  var MESSAGE = JSON.stringify(reshareBulk);
  var safeMessage = protocolKit1.createMessage(MESSAGE);
  var messageHash = hashSafeMessage(MESSAGE);

  var isValid = await protocolKit1.isValidSignature(
    messageHash,
    "0xdf8a3b71559cebe3f293b49febc5aa601c5b521f21d636077a0abeb7f1f17d1940b73df475f6ee2d7a9cfab9b3dd16dec7fed154ab00bbf50d246d2d058cc8a21c51e2a506f58b95f42a8cc2994373ba29c96d261fceba3df388c9d54690ab69c0681e52b8fe7c62b62dd1ff9e201cfc4d405bbf91ce0d945387fa792a154c932f1b"
  );

  console.log("Message: ", MESSAGE);
  console.log("Message Hash: ", messageHash);
  console.log(`The signature is ${isValid ? "valid" : "invalid"}`);


  var resignBulk = JSON.parse(
    fs.readFileSync(
      "../../../integration_test/stubs/resign/resign_msgs.json",
      "utf-8"
    )
  );

  MESSAGE = JSON.stringify(resignBulk);
  safeMessage = protocolKit1.createMessage(MESSAGE);
  messageHash = hashSafeMessage(MESSAGE);

  isValid = await protocolKit1.isValidSignature(
    messageHash,
    "0x781f8e5f0dfbb704e94594bcb765c9b41d303fcffe552e3c6a01c43681b50612772c679c9d71cd6cbe1054a9421b297d054db7dda9a66e44b199f6e5611164e51bec04fef73413a5109ebf7f9b281b56f8130429aa929a0400f929dfa8ba363e08700bda3d68363780977c8e1e7876cdcd136292a093bab8a51118cb73dfaa034c1b"
  );

  console.log("Message: ", MESSAGE);
  console.log("Message Hash: ", messageHash);
  console.log(`The signature is ${isValid ? "valid" : "invalid"}`);
}
main();
