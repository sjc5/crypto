import { decode, encode } from "@stablelib/base64"
import { randomBytes, secretbox } from "tweetnacl"

/**
 * @returns {string} Random 32-byte, base-64 encoded key.
 */
export const random_key = (): string => encode(randomBytes(32))

/**
 * Encrypts any string with any 32-byte, base-64 encoded key.
 * Uses the tweetnacl library, as demo'd here: https://tweetnacl.js.org/#/secretbox.
 *
 * @param {Object} payload - The payload object.
 * @param {string} payload.message - The message to encrypt. Can be any string.
 * @param {string} payload.key - The key to encrypt the message with. Must be a 32-byte, base-64 encoded string.
 * @returns {string} The base-64 encoded encrypted message.
 */
export const encrypt = ({
  message,
  key,
}: {
  message: string
  key: string
}): string => {
  const key_bytes = decode(key) // base64 key --> uint8array key
  const nonce = randomBytes(24) // generate a random 24 byte nonce
  const message_bytes = new TextEncoder().encode(message) // plain text string --> uint8array
  const box = secretbox(message_bytes, nonce, key_bytes) // encrypt message to uint8array
  const encrypted_bytes = new Uint8Array(nonce.length + box.length) // create a new uint8array to hold the nonce and encrypted message
  encrypted_bytes.set(nonce) // add the nonce to the front of the new uint8array
  encrypted_bytes.set(box, nonce.length) // add the encrypted message to the end of the new uint8array
  return encode(encrypted_bytes) // encrypted message as uint8array --> return base64 encrypted message
}

/**
 * Decrypts a base-64 encoded, encrypted message with the 32-byte, base-64 encoded key used to encrypt it.
 * Uses the tweetnacl library, as demo'd here: https://tweetnacl.js.org/#/secretbox.
 *
 * @param {Object} payload - The payload object.
 * @param {string} payload.encrypted_message - The encrypted message to decrypt. Must be a base-64 encoded string.
 * @param {string} payload.key - The key to decrypt the message with. Must be a 32-byte, base-64 encoded string.
 * @returns {string} The decrypted plain text message.
 */
export const decrypt = ({
  encrypted_message,
  key,
}: {
  encrypted_message: string
  key: string
}): string => {
  const key_bytes = decode(key) // base64 key --> uint8array key
  const encrypted_bytes = decode(encrypted_message) // base64 encrypted message --> uint8array encrypted message
  const nonce = encrypted_bytes.slice(0, secretbox.nonceLength) // extract nonce (first 24 bytes of encrypted message)
  const message_bytes = encrypted_bytes.slice(
    secretbox.nonceLength,
    encrypted_message.length
  ) // extract encrypted message (everything after the first 24 bytes)
  const raw_bytes = secretbox.open(message_bytes, nonce, key_bytes) // decrypt message to uint8array
  if (!raw_bytes) throw new Error("Could not decrypt message")
  return new TextDecoder().decode(raw_bytes) // decrypted message as uint8array --> return plain text string
}
