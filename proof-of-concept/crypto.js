import crypto from 'crypto'
import * as jose from 'jose'
import { base58btc } from 'multiformats/bases/base58'
import {
  createVerifiableCredentialJwt,
  createVerifiablePresentationJwt,
} from 'did-jwt-vc'

const PublicKeyObject = crypto.generateKeyPairSync('ed25519').publicKey.constructor
const PrivateKeyObject = crypto.generateKeyPairSync('ed25519').privateKey.constructor

export { PublicKeyObject, PrivateKeyObject }

export function createNonce(length = 16){
  return crypto.randomBytes(length).toString('base64url')
}

export async function generateSigningKeyPair(){
  return crypto.generateKeyPairSync('ed25519')
}

export async function generateEncryptingKeyPair(){
  return crypto.generateKeyPairSync('x25519')
}

export async function publicKeyToJWK(publicKey){
  return await jose.exportJWK(publicKey)
}
export async function keyPairToPublicJWK({ publicKey }){
  return await publicKeyToJWK(publicKey)
}
export async function keyPairToPrivateJWK({ privateKey }){
  return await jose.exportJWK(privateKey)
}
export function publicKeyFromJWK(publicJWK){
  return crypto.createPublicKey({ format: 'jwk', key: publicJWK })
}
export async function keyPairFromJWK(privateJWK){
  const publicJWK = {...privateJWK}
  delete publicJWK.d // TODO ensure we are deleting enough here
  return {
    publicKey: publicKeyFromJWK(publicJWK),
    privateKey: crypto.createPrivateKey({ format: 'jwk', key: privateJWK }),
  }
}
export function signingKeyPairToDIDKey(signingKeyPair){
  return `did:key${base58btc.encode(publicKeyToBuffer(signingKeyPair.publicKey))}`
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

/**
 * create a JSON Web Signature
 */
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

/**
 * verify a JSON Web Signature
 */
export async function verifyJWS(jws, publicKeys){
  if (!Array.isArray(publicKeys)) publicKeys = [publicKeys]
  let lastError, result
  for (const publicKey of publicKeys){
    try{
      result = await jose.generalVerify(jws, publicKey)
    }catch(error){
      lastError = error
    }
  }
  if (result){
    const { payload } = result
    return JSON.parse(payload)
  }
  if (lastError) throw lastError
}

/**
 * create a JSON Web Encryption
 */
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

/**
 * decrypt a JSON Web Encryption
 */
export async function decryptJWE(jwe, privateKey){
  const { plaintext } = await jose.generalDecrypt(jwe, privateKey)
  return JSON.parse(plaintext)
}

/**
 * truncate Diffie Hellman derived secret to 32 bytes as
 * expected by jose.SignJWT
 */
function truncateSecret(secret){
  return secret.slice(0, 32)
}

/**
 * create a signed JSON Web Token
 */
export async function createSignedJWT({
  privateKey, payload, issuer, audience, subject, expirationTime = '4weeks',
}){
  const signedJWT = await new jose.SignJWT(payload)
    .setProtectedHeader({ alg: 'EdDSA' })
    .setIssuedAt()
    .setIssuer(issuer)
    .setAudience(audience)
    .setSubject(subject)
    .setExpirationTime(expirationTime)
    .sign(privateKey)
  return signedJWT
}

/**
 * verify a signed JSON Web Token
 */
export async function verifySignedJWT(jwt, publicKeys){
  if (!Array.isArray(publicKeys)) publicKeys = [publicKeys]
  let lastError, result
  for (const publicKey of publicKeys){
    try{
      result = await jose.jwtVerify(jwt, publicKey)
    }catch(error){
      lastError = error
    }
  }
  if (result){
    const { payload } = result
    return payload
  }
  if (lastError) throw lastError
}

/**
 * encrypt a JWT containing a JWS
 */
export async function createEncryptedSignedJWT({
  payload, issuer, audience, subject, expirationTime = '1month', secret,
  signWith
}){
  if (signWith){
    const signedJWT = await new jose.SignJWT(payload)
      .setProtectedHeader({ alg: 'EdDSA' })
      .sign(signWith)
    payload = { signedJWT }
  }

  const proto = new jose.EncryptJWT(payload)
  proto.setProtectedHeader({ alg: 'dir', enc: 'A128CBC-HS256' })
  proto.setIssuedAt()
  proto.setIssuer(issuer)
  proto.setAudience(audience)
  proto.setSubject(subject)
  proto.setExpirationTime(expirationTime)
  return await proto.encrypt(truncateSecret(secret))
}
/**
 * Decrypt a JWT containing a JWS
 */
export async function decryptSignedJWT({
  jwt, secret, publicKey, issuer, audience,
}){
  secret = truncateSecret(secret)
  const options = { issuer, audience }
  const { payload } = await jose.jwtDecrypt(jwt, secret, options)
  if (payload.signedJWT){
    const {
      payload: innerPayload,
      // protectedHeader: innerProtectedHeader,
    } = await jose.jwtVerify(payload.signedJWT, publicKey)
    delete payload.signedJWT
    Object.assign(payload, innerPayload)
  }
  return payload
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
}

/**
 * used by the initiator to finalize the secret
 */
export function finalizeDiffieHellman(actor, { publicKey }){
  publicKey = Buffer.from(publicKey, 'base64url')
  return actor.computeSecret(publicKey)
}

