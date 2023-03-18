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

export async function publicKeyToJWK(publicKey){
  return await jose.exportJWK(publicKey)
}
export async function keyPairToPublicJWK({ publicKey, privateKey }){
  return await publicKeyToJWK(publicKey)
}
export async function keyPairToPrivateJWK({ publicKey, privateKey }){
  return await jose.exportJWK(privateKey)
}
export function publicKeyFromJWK(publicJWK){
  console.log('publicKeyFromJWK', publicJWK)
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
    const { payload, protectedHeader } = result
    return JSON.parse(payload)
  }
  if (lastError) throw lastError
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

export async function verifySignedJWT(jwt, publicKeys){
  // const { payload, protectedHeader } = await jose.jwtVerify(jwt, publicKey)
  // return payload
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
    const { payload, protectedHeader } = result
    return payload
  }
  if (lastError) throw lastError
}

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
  // if (secret) return await proto.encrypt(truncateSecret(secret))
  // if (publicKey) return await proto.encrypt(publicKey)
  // return jwt
}

export async function decryptSignedJWT({
  jwt, secret, publicKey, issuer, audience,
}){
  secret = truncateSecret(secret)
  const options = { issuer, audience }
  const { payload, protectedHeader } = await jose.jwtDecrypt(jwt, secret, options)
  if (payload.signedJWT){
    const {
      payload: innerPayload,
      protectedHeader: innerProtectedHeader,
    } = await jose.jwtVerify(payload.signedJWT, publicKey)
    delete payload.signedJWT
    Object.assign(payload, innerPayload)
  }
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
