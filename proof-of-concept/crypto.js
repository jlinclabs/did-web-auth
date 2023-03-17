import crypto from 'crypto'
import * as jose from 'jose'
import { base58btc } from 'multiformats/bases/base58'
import { base64url } from 'multiformats/bases/base64' // replace with jose.base64url

const PublicKeyObject = crypto.generateKeyPairSync('ed25519').publicKey.constructor
const PrivateKeyObject = crypto.generateKeyPairSync('ed25519').privateKey.constructor

export { PublicKeyObject, PrivateKeyObject }

export function createNonce(length = 16){
  return base64url.encode(crypto.randomBytes(length))
}

export async function generateSigningKeyPair(){
  return crypto.generateKeyPairSync('ed25519')
}

export async function generateEncryptingKeyPair(){
  return crypto.generateKeyPairSync('x25519')
}

export async function keyPairToPublicJWK({ publicKey, privateKey }){
  return await jose.exportJWK(publicKey)
}
export async function keyPairToPrivateJWK({ publicKey, privateKey }){
  return await jose.exportJWK(privateKey)
}
export function publicKeyFromJWK(publicJWK){
  return crypto.createPublicKey({ format: 'jwk', key: publicJWK })
}
export async function keyPairFromJWK(privateJWK){
  const publicJWK = {...privateJWK}
  delete publicJWK.d // TODO there is more to delete here
  return {
    publicKey: publicKeyFromJWK(publicJWK),
    privateKey: crypto.createPrivateKey({ format: 'jwk', key: privateJWK }),
  }
}

export function publicKeyToBuffer(publicKey){
  return publicKey.export({ type: 'spki', format: 'der' })
}
export function publicKeyFromBuffer(publicKey){
  return crypto.createPublicKey({ key: publicKey, type: 'spki', format: 'der' })
}
export function privateKeyToBuffer(privateKey){
  return privateKey.export({ type: 'pkcs8', format: 'der' })
}

export function isSamePublicKeyObject(a, b){
  if (!(a instanceof PublicKeyObject)) throw new Error(`first argument is not an instance of PublicKeyObject`)
  if (!(b instanceof PublicKeyObject)) throw new Error(`second argument is not an instance of PublicKeyObject`)
  if (a === b) return true
  return publicKeyToBuffer(a).equals(publicKeyToBuffer(b))
}
export function isSamePrivateKeyObject(a, b){
  if (!(a instanceof PrivateKeyObject)) throw new Error(`first argument is not an instance of PrivateKeyObject`)
  if (!(b instanceof PrivateKeyObject)) throw new Error(`second argument is not an instance of PrivateKeyObject`)
  if (a === b) return true
  return privateKeyToBuffer(a).equals(privateKeyToBuffer(b))
}

export async function createJWS({ payload, signers }){
  const proto = new jose.GeneralSign(
    new TextEncoder().encode(JSON.stringify(payload))
  )
  for (const privateKey of signers){
    proto
      .addSignature(privateKey)
      .setProtectedHeader({ alg: 'EdDSA' })
  }
  return await proto.sign()
}

export async function verifyJWS(jws, publicKey){
  const { payload, protectedHeader } = await jose.generalVerify(jws, publicKey)
  // console.log({ protectedHeader })
  return JSON.parse(payload)
}

export async function createJWE({ payload, recipients }){
  const proto = new jose.GeneralEncrypt(
    new TextEncoder().encode(JSON.stringify(payload))
  )
  for (const publicKey of recipients){
    proto
      .setProtectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' })
      .addRecipient(publicKey)
  }
  return await proto.encrypt()
}

export async function verifyJWE(jwe, privateKey){
  const { plaintext, protectedHeader, additionalAuthenticatedData } = await jose.generalDecrypt(jwe, privateKey)
  // console.log({ protectedHeader, additionalAuthenticatedData })
  return JSON.parse(plaintext)
}

/**
 * Ok this is weird, we need to cut this secret down to 32 bits so we just take the first 32 bytes
 */
function truncateSecret(secret){
  return secret.slice(0, 32)
}

export async function createEncryptedJWT({
  payload, issuer, audience, subject, expirationTime = '1month', secret
}){
  secret = truncateSecret(secret)
  const jwt = await new jose.EncryptJWT(payload)
    .setProtectedHeader({ alg: 'dir', enc: 'A128CBC-HS256' })
    .setIssuedAt()
    .setIssuer(issuer)
    .setAudience(audience)
    .setSubject(subject)
    .setExpirationTime(expirationTime)
    .encrypt(secret)

  return jwt
}

export async function decryptJWT(jwt, secret, options){
  secret = truncateSecret(secret)
  const { payload, protectedHeader } = await jose.jwtDecrypt(jwt, secret, options)
  return payload
}

export function publicKeyToBase58(publicKey){
  return base58btc.encode(publicKeyToBuffer(publicKey))
}
export function publicKeyFromBase58(publicKey){
  return publicKeyFromBuffer(base58btc.decode(publicKey))
}

/**
 * used to start a Diffie Hellman secret handshake
 */
export function createDiffieHellman(){
  const actor = crypto.createDiffieHellman(512)
  const publicKey = actor.generateKeys()
  const prime = actor.getPrime()
  const generator = actor.getGenerator()
  return {
    actor, publicKey, prime, generator,
    message: {
      publicKey: publicKey.toString('base64url'),
      prime: prime.toString('base64url'),
      generator: generator.toString('base64url'),
    }
  }
}

/**
 * used to accept a Diffie Hellman secret handshake
 */
export function acceptDiffieHellman({ prime, generator, publicKey }){
  prime = Buffer.from(prime, 'base64url')
  generator = Buffer.from(generator, 'base64url')
  publicKey = Buffer.from(publicKey, 'base64url')
  const actor = crypto.createDiffieHellman(prime, generator)
  const ourPublicKey = actor.generateKeys()
  const secret = actor.computeSecret(publicKey)
  return {
    actor,
    publicKey: ourPublicKey,
    secret,
    message: {
      publicKey: ourPublicKey.toString('base64url'),
    }
  }
  // acceptor.computeSecret(publicKey)
}

/**
 * used by the initiator to finalize the secret
 */
export function finalizeDiffieHellman(actor, { publicKey }){
  publicKey = Buffer.from(publicKey, 'base64url')
  return actor.computeSecret(publicKey)
}
