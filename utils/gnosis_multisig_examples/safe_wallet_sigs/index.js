"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
const protocol_kit_1 = __importStar(require("@safe-global/protocol-kit"));
const protocol_kit_2 = require("@safe-global/protocol-kit");
// To run this script, you need a Safe with the following configuration
// - 3/3 Safe with 3 owners and threshold 3
//   - Owner 1: public address from OWNER1_PRIVATE_KEY
//   - Owner 2: public address from OWNER2_PRIVATE_KEY
//   - Owner 3: SIGNER_SAFE_ADDRESS (1/1 with OWNER1_PRIVATE_KEY public address as owner)
const config = {
    RPC_URL: 'https://eth-sepolia.g.alchemy.com/v2/YyqRIEgydRXKTTT-w_0jtKSAH6sfr8qz',
    OWNER1_PRIVATE_KEY: '92d1dde14c809ac3e1e1c5d70ac1e0586bf295ecb58d3dda4d8f0d208fc6d540',
    OWNER2_PRIVATE_KEY: 'fa495598199effb5ef8e150d5c232a19ced7edb646d9cd1c6eeb6a5df1c79844',
    OWNER3_PRIVATE_KEY: '56ac4b651c81556ede41e93cb97f62fe5273c63c6ab2e7f137fb77e43f29d6d0',
    SAFE_3_3_ADDRESS: '0x0205c708899bde67330456886a05Fe30De0A79b6'
};
function main() {
    return __awaiter(this, void 0, void 0, function* () {
        // Create safeSdk instances
        let protocolKit = yield protocol_kit_1.default.init({
            provider: config.RPC_URL,
            signer: config.OWNER1_PRIVATE_KEY,
            safeAddress: config.SAFE_3_3_ADDRESS
        });
        const MESSAGE = 'I am the owner of this Safe account';
        let message = protocolKit.createMessage(MESSAGE);
        message = yield protocolKit.signMessage(message); // Owner 1 signature
        protocolKit = yield protocolKit.connect({
            signer: config.OWNER2_PRIVATE_KEY,
            safeAddress: config.SAFE_3_3_ADDRESS
        }); // Connect another owner
        message = yield protocolKit.signMessage(message, protocol_kit_1.SigningMethod.ETH_SIGN_TYPED_DATA_V4); // Owner 2 signature
        protocolKit = yield protocolKit.connect({
            signer: config.OWNER3_PRIVATE_KEY,
            safeAddress: config.SAFE_3_3_ADDRESS
        }); // Connect another owner
        message = yield protocolKit.signMessage(message, protocol_kit_1.SigningMethod.ETH_SIGN_TYPED_DATA_V4); // Owner 3 signature
        // Validate the signature sending the Safe message hash and the concatenated signatures
        const messageHash = (0, protocol_kit_2.hashSafeMessage)(MESSAGE);
        const safeMessageHash = yield protocolKit.getSafeMessageHash(messageHash);
        const isValid = yield protocolKit.isValidSignature(messageHash, message.encodedSignatures());
        console.log('Message: ', MESSAGE);
        console.log('Message Hash: ', messageHash);
        console.log('Safe Message Hash: ', safeMessageHash);
        console.log('Signatures: ', message.signatures.values());
        console.log('Encoded Signatures: ', message.encodedSignatures());
        console.log(`The signature is ${isValid ? 'valid' : 'invalid'}`);
    });
}
main();
