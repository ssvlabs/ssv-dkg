import Safe, { SigningMethod, buildContractSignature } from '@safe-global/protocol-kit'
import { hashSafeMessage } from '@safe-global/protocol-kit'

// This file can be used to play around with the Safe Core SDK

interface Config {
  RPC_URL: string
  OWNER1_PRIVATE_KEY: string
  OWNER2_PRIVATE_KEY: string
  OWNER3_PRIVATE_KEY: string
  SAFE_3_3_ADDRESS: string
}

// To run this script, you need a Safe with the following configuration
// - 3/3 Safe with 3 owners and threshold 3
//   - Owner 1: public address from OWNER1_PRIVATE_KEY
//   - Owner 2: public address from OWNER2_PRIVATE_KEY
//   - Owner 3: public address from OWNER3_PRIVATE_KEY
//   - SAFE_WALLET: public of safe wallet address with 2/3 threshold
const config: Config = {
  RPC_URL: 'https://eth-sepolia.g.alchemy.com/v2/YyqRIEgydRXKTTT-w_0jtKSAH6sfr8qz',
  OWNER1_PRIVATE_KEY: '',
  OWNER2_PRIVATE_KEY: '',
  OWNER3_PRIVATE_KEY: '',
  SAFE_3_3_ADDRESS: '0x0205c708899bde67330456886a05Fe30De0A79b6'
}

async function main() {
  // Create safeSdk instances
  let protocolKit = await Safe.init({
    provider: config.RPC_URL,
    signer: config.OWNER1_PRIVATE_KEY,
    safeAddress: config.SAFE_3_3_ADDRESS
  })

  const MESSAGE = 'I am the owner of this Safe account'

  let message = protocolKit.createMessage(MESSAGE)

  message = await protocolKit.signMessage(message) // Owner 1 signature

  protocolKit = await protocolKit.connect({
    signer: config.OWNER2_PRIVATE_KEY,
    safeAddress: config.SAFE_3_3_ADDRESS
  }) // Connect another owner

  message = await protocolKit.signMessage(message, SigningMethod.ETH_SIGN_TYPED_DATA_V4) // Owner 2 signature

  protocolKit = await protocolKit.connect({
    signer: config.OWNER3_PRIVATE_KEY,
    safeAddress: config.SAFE_3_3_ADDRESS
  }) // Connect another owner

  message = await protocolKit.signMessage(message, SigningMethod.ETH_SIGN_TYPED_DATA_V4) // Owner 3 signature

  // Validate the signature sending the Safe message hash and the concatenated signatures
  const messageHash = hashSafeMessage(MESSAGE)
  const safeMessageHash = await protocolKit.getSafeMessageHash(messageHash)

  const isValid = await protocolKit.isValidSignature(messageHash, message.encodedSignatures())

  console.log('Message: ', MESSAGE)
  console.log('Message Hash: ', messageHash)
  console.log('Safe Message Hash: ', safeMessageHash)
  console.log('Signatures: ', message.signatures.values())
  console.log('Encoded Signatures: ', message.encodedSignatures())

  console.log(`The signature is ${isValid ? 'valid' : 'invalid'}`)
}

main()
