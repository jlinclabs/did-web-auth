import { promisify } from 'util'
import crypto from 'crypto'
import * as jose from 'jose'
import { base64url } from 'multiformats/bases/base64'
import { base58btc } from 'multiformats/bases/base58'
import nacl from 'tweetnacl'
// TODO remove these
// import ed25519 from 'ed25519'
// import forge from 'node-forge'

const generateKeyPair = promisify(crypto.generateKeyPair) //.bind(null, 'ed25519')


// export function keyBufferToString(buffer){
//   return base58btc.encode(buffer)
// }

// export function keyToBuffer(string){
//   return Buffer.from(base58btc.decode(string))
// }

function seedToBuffer(seed){
  if (!seed) return
  const seedBuffer = Buffer.alloc(32)
  Buffer.from(seed).copy(seedBuffer)
  return seedBuffer
}

export async function generateEncryptingKeyPair(seed){
  let { publicKey, secretKey: privateKey } = seed
    ? nacl.box.keyPair.fromSecretKey(seedToBuffer(seed))
    : nacl.box.keyPair()
  // console.log('generateEncryptingKeyPair', { privateKey, publicKey })
  publicKey = publicKeyFromBuffer(createX25519PublicKeySpkiBuffer(Buffer.from(publicKey)))
  privateKey = privateKeyFromBuffer(createX25519PrivateKeyPkcs8Buffer(Buffer.from(privateKey)))
  // console.log('generateEncryptingKeyPair', { privateKey, publicKey })
  return { publicKey, privateKey }
}

export async function generateSigningKeyPair(seed){
  let { publicKey, secretKey: privateKey } = seed
    ? nacl.sign.keyPair.fromSeed(seedToBuffer(seed))
    : nacl.sign.keyPair()
  // console.log('generateSigningKeyPair', { publicKey, privateKey })
  publicKey = publicKeyFromBuffer(createEd25519PublicKeySpkiBuffer(publicKey))
  privateKey = privateKeyFromBuffer(createEd25519PrivateKeyPkcs8Buffer(privateKey))
  // console.log('generateSigningKeyPair', { publicKey, privateKey })
  return { publicKey, privateKey }
}

// Magic ChatGPT wrote for me :D
function createEd25519PublicKeySpkiBuffer(publicKeyBuffer) {
  return Buffer.concat([
    Buffer.from('302a300506032b6570032100', 'hex'),
    publicKeyBuffer
  ])
}
function createEd25519PrivateKeyPkcs8Buffer(privateKeyBuffer) {
  return Buffer.concat([
    Buffer.from('302e020100300506032b657004220420', 'hex'),
    privateKeyBuffer
  ])
}
function createX25519PublicKeySpkiBuffer(publicKeyBuffer) {
  return Buffer.concat([
    Buffer.from('302a300506032b656e032100', 'hex'),
    publicKeyBuffer,
  ])
}
function createX25519PrivateKeyPkcs8Buffer(privateKeyBuffer) {
  return Buffer.concat([
    Buffer.from('302e020100300506032b656e042204', 'hex'),
    privateKeyBuffer,
  ])
}
function ed25519PublicJwkToSpkiBuffer(jwk) {
  return createEd25519PublicKeySpkiBuffer(
    Buffer.from(jwk.x, 'base64')
  )
}
function ed25519PrivateJwkToPkcs8Buffer(jwk) {
  return createEd25519PrivateKeyPkcs8Buffer(
    Buffer.from(jwk.d, 'base64')
  )
}
export function privateKeyJwkToPublicKeyJwk(privateKeyJwk) {
  return {
    kty: privateKeyJwk.kty,
    crv: privateKeyJwk.crv,
    x:   privateKeyJwk.x,
    alg: privateKeyJwk.alg,
    ext: privateKeyJwk.ext,
  }
}


export function publicKeyToBuffer(publicKey){
  return publicKey.export({
    type: 'spki',
    format: 'der',
  })
}
export function privateKeyToBuffer(privateKey){
  return privateKey.export({
    type: 'pkcs8',
    format: 'der',
  })
}

export function publicKeyFromBuffer(publicKeyBuffer){
  return crypto.createPublicKey({
    key: publicKeyBuffer,
    type: 'spki',
    format: 'der',
  })
}
export function privateKeyFromBuffer(privateKeyBuffer){
  return crypto.createPrivateKey({
    key: privateKeyBuffer,
    type: 'pkcs8',
    format: 'der',
  })
}

export function publicKeyToJKW(publicKey){
  return publicKey.export({ format: 'jwk' })
}

export function privateKeyToJKW(privateKey){
  return privateKey.export({ format: 'jwk' })
}

export function publicKeyFromJKW(publicKeyJWK){
  return crypto.createPublicKey({
    key: ed25519PublicJwkToSpkiBuffer(publicKeyJWK),
    format: 'der',
    type: 'spki',
  });
}

export function privateKeyFromJKW(privateKeyJWK){
  return crypto.createPrivateKey({
    key: ed25519PrivateJwkToPkcs8Buffer(privateKeyJWK),
    format: 'der',
    type: 'pkcs8',
  })
}

export async function createJWS({ payload, signers }){
  const text = new TextEncoder().encode(JSON.stringify(payload))
  let proto = new jose.GeneralSign(text)
  for (const privateKey of signers){
    proto
      .addSignature(privateKey)
      .setProtectedHeader({ alg: 'EdDSA' })
  }
  const jws = await proto.sign()
  return jws
}

export async function verifyJWS({ jws, publicKey }){
  const { payload, protectedHeader } = await jose.generalVerify(jws, publicKey)
  const data = JSON.parse(new TextDecoder().decode(payload))
  // console.log({ protectedHeader, data })
  return data
}