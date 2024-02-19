import {
  getExistingDepositsForPubkeys,
  validateDepositKey,
} from "./validateDepositKey.js";
import { readFileSync } from "fs";
import { GENESIS_FORK_VERSION, DEPOSIT_FILE } from "./envVars.js";

export interface DepositFileInterface {
  name: string;
  beaconChainApiStatus: BeaconChainStatus;
  keys: DepositKeyInterface[];
}

interface BeaconchainDepositDataInterface {
  amount: number;
  block_number: number;
  block_ts: number;
  from_address: string;
  merkletree_index: string;
  publickey: string;
  removed: boolean;
  signature: string;
  tx_hash: string;
  tx_index: number;
  tx_input: string;
  valid_signature: boolean;
  withdrawal_credentials: string;
}

export interface BeaconchainDepositInterface {
  data: BeaconchainDepositDataInterface[];
  status: string;
}

export interface DepositKeyInterface {
  pubkey: string;
  withdrawal_credentials: string;
  amount: number;
  signature: string;
  deposit_message_root: string;
  deposit_data_root: string;
  fork_version: string;
  deposit_cli_version: string;
  transactionStatus: TransactionStatus;
  txHash?: string;
  depositStatus: DepositStatus;
}

export enum TransactionStatus {
  "READY",
  "PENDING",
  "STARTED",
  "SUCCEEDED",
  "FAILED",
  "REJECTED",
}

export enum DepositStatus {
  VERIFYING,
  ALREADY_DEPOSITED,
  READY_FOR_DEPOSIT,
}

export enum BeaconChainStatus {
  HEALTHY,
  DOWN,
}

var check = async () => {
  try {
    if (DEPOSIT_FILE === "") {
      console.log("Please provide deposit file path");
      return;
    }
    var path = <string>DEPOSIT_FILE;
    const file = readFileSync(path, "utf-8");
    const fileData: any[] = JSON.parse(file as string);
    console.log(fileData);
    // perform BLS check
    if (await validateDepositKey(fileData as DepositKeyInterface[])) {
      // perform double deposit check
      try {
        const existingDeposits = await getExistingDepositsForPubkeys(fileData);
        const existingDepositPubkeys = existingDeposits.data.flatMap((x) =>
          x.publickey.substring(2)
        );
        (fileData as DepositKeyInterface[]).forEach(async (file) => {
          if (existingDepositPubkeys.includes(file.pubkey)) {
            console.log("Already deposited ", file.pubkey);
            return;
          } else {
            console.log("Ready for deposit ", file.pubkey);
            return;
          }
        });
      } catch (error) {
        console.log(BeaconChainStatus.DOWN, error);
        return;
      }
    } else {
      // there are a couple special cases that can occur
      const { fork_version: forkVersion } = fileData[0] || {};
      const hasCorrectStructure = checkJsonStructure(fileData[0] || {});
      if (!hasCorrectStructure) {
        console.log("Wrong file structure", fileData);
      }
      if (
        hasCorrectStructure &&
        forkVersion !== GENESIS_FORK_VERSION.toString()
      ) {
        // file doesn't match the correct network
        handleWrongNetwork();
      }
      console.log("not accepted");
      return;
    }
  } catch (e) {
    // possible error example: json is invalid or empty so it cannot be parsed
    console.log(e);
    return e;
  }
};
check();

const checkJsonStructure = (depositDataJson: { [field: string]: any }) => {
  return !!(
    depositDataJson.pubkey ||
    depositDataJson.withdrawal_credentials ||
    depositDataJson.amount ||
    depositDataJson.signature ||
    depositDataJson.deposit_message_root ||
    depositDataJson.deposit_data_root ||
    depositDataJson.fork_version
  );
};

const handleWrongNetwork = () => {
  return "This JSON file isn't for the right network. Upload a file generated for your current network: {consensusLayerName}.";
};
