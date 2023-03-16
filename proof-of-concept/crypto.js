import { promisify } from 'util'
import crypto from 'crypto'
import { base64url } from 'multiformats/bases/base64'
import { base58btc } from 'multiformats/bases/base58'
import * as jose from 'jose'
// import ed25519 from '@stablelib/ed25519'
// import x25519 from '@stablelib/x25519'
import sodium from 'sodium-native'
// import nacl from 'tweetnacl'
// TODO remove these
// import ed25519 from 'ed25519'
// import forge from 'node-forge'

// console.log({ sodium })
const generateKeyPair = promisify(crypto.generateKeyPair) //.bind(null, 'ed25519')


// export function keyBufferToString(buffer){
//   return base58btc.encode(buffer)
// }

// export function keyToBuffer(string){
//   return Buffer.from(base58btc.decode(string))
// }

function seedToBuffer(seed){
  // var hash = crypto.createHash('sha256').update(bobsPassword).digest(); //returns a buffer
  if (!seed) return
  const seedBuffer = Buffer.alloc(sodium.crypto_sign_SEEDBYTES)
  Buffer.from(seed).copy(seedBuffer)
  return seedBuffer
}


export async function generateSigningKeyPair(seed){
  let publicKey = Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  let privateKey = Buffer.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  if (seed){
    seed = seedToBuffer(seed)
    // sodium.crypto_sign_seed25519_keypair(pk, sk, seed)
    sodium.crypto_sign_seed_keypair(publicKey, privateKey, seed)
  }else{
    sodium.crypto_sign_keypair(publicKey, privateKey)
  }
  console.log('generateSigningKeyPair (Buffers)', { publicKey, privateKey })

  // Prepend the X25519 public key buffer with the ASN.1 sequence
  const publicKeyBuffer = Buffer.concat([
    Buffer.from('3059301306072a8648ce3d020106082a8648ce3d030107034200', 'hex'),
    publicKey
  ]);

  // Create a public key object using crypto.createPublicKey()
  const publicKeyObject = crypto.createPublicKey({
    key: publicKeyBuffer,
    type: 'spki',
    format: 'der',
  })
  console.log({ publicKeyObject })

  throw new Error('NOT DONE YET!!')
  // publicKey = signingPublicKeyFromBuffer(createEd25519PublicKeySpkiBuffer(publicKey))
  // privateKey = signingPrivateKeyFromBuffer(createEd25519PrivateKeyPkcs8Buffer(privateKey))
  // console.log('generateSigningKeyPair (objects)', { publicKey, privateKey })
  // let { publicKey, secretKey: privateKey } = seed
  //   ? ed25519.generateKeyPairFromSeed(seedToBuffer(seed))
  //   : ed25519.generateKeyPair()

  // console.log('generateSigningKeyPair (Uint8Arrays)', { publicKey, privateKey })
  // // let { publicKey, secretKey: privateKey } = seed
  // //   ? nacl.sign.keyPair.fromSeed(seedToBuffer(seed))
  // //   : nacl.sign.keyPair()
  // // // console.log('generateSigningKeyPair', { publicKey, privateKey })

  // const publicKeyAsUint8Array = publicKey
  // const privateKeyAsUint8Array = privateKey


  // publicKey = signingPublicKeyFromBuffer(createEd25519PublicKeySpkiBuffer(publicKey))
  // privateKey = signingPrivateKeyFromBuffer(createEd25519PrivateKeyPkcs8Buffer(privateKey))
  // console.log('generateSigningKeyPair (objects)', { publicKey, privateKey })

  // // console.log('generateSigningKeyPair', { publicKey, privateKey })
  return { publicKey, privateKey }
}

export async function generateEncryptingKeyPairFromSigningKeyPair({ publicKey, privateKey }){
  // sodium.crypto_sign_ed25519_pk_to_curve25519(Buffer.from(some-ed-key))

  publicKey = encryptingPublicKeyFromBuffer(
    createX25519PublicKeySpkiBuffer(
      ed25519.convertPublicKeyToX25519(
        publicSigningKeyToUint8Array(publicKey)
      )
    )
  )
  privateKey = encryptingPrivateKeyFromBuffer(
    // createX25519PrivateKeyPkcs8Buffer(
      ed25519.convertSecretKeyToX25519(
        privateSigningKeyToUint8Array(privateKey)
      )
    // )
  )
  console.log('generateEncryptingKeyPairFromSigningKeyPair', { publicKey, privateKey })
  return { publicKey, privateKey }
}

export async function generateEncryptingKeyPair(seed){
  let { publicKey, secretKey: privateKey } = seed
    ? nacl.box.keyPair.fromSecretKey(seedToBuffer(seed))
    : nacl.box.keyPair()
  // console.log('generateEncryptingKeyPair', { privateKey, publicKey })
  publicKey = signingPublicKeyFromBuffer(createX25519PublicKeySpkiBuffer(Buffer.from(publicKey)))
  privateKey = signingPrivateKeyFromBuffer(createX25519PrivateKeyPkcs8Buffer(Buffer.from(privateKey)))
  // console.log('generateEncryptingKeyPair', { privateKey, publicKey })
  return { publicKey, privateKey }
}


function publicSigningKeyToUint8Array(publicKey){
  return new Uint8Array(signingPublicKeyToBuffer(publicKey).buffer)
}

function privateSigningKeyToUint8Array(privateKey){
  console.log('🔺 privateSigningKeyToUint8Array', {privateKey})
  const buffer = signingPrivateKeyToBuffer(privateKey)
  console.log('🔺 privateSigningKeyToUint8Array', {buffer})
  const uint8Array = new Uint8Array(buffer.buffer)
  console.log('🔺 privateSigningKeyToUint8Array', {uint8Array})
  return uint8Array
}

// Magic ChatGPT wrote for me :D
const DER_PREFIX_ED25519_PUBLIC  = '302a300506032b656e032100'
const DER_PREFIX_ED25519_PRIVATE = '302e020100300506032b657004220420'
const DER_PREFIX_X25519_PUBLIC   = '302a300506032b6570032100'
const DER_PREFIX_X25519_PRIVATE  = '302e020100300506032b656e042204'
function createEd25519PublicKeySpkiBuffer(publicKeyBuffer) {
  return Buffer.concat([
    Buffer.from('302a300506032b656e032100', 'hex'),
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
    Buffer.from('302a300506032b6570032100', 'hex'),
    publicKeyBuffer,
  ])
}
function createX25519PrivateKeyPkcs8Buffer(privateKeyBuffer) {
  console.log('createX25519PrivateKeyPkcs8Buffer', { privateKeyBuffer })
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


export function signingPublicKeyToBuffer(publicKey){
  return publicKey.export({
    type: 'spki',
    format: 'der',
  })
}
export function signingPrivateKeyToBuffer(privateKey){
  return privateKey.export({
    type: 'pkcs8',
    format: 'der',
  })
}

export function signingPublicKeyFromBuffer(publicKeyBuffer){
  return crypto.createPublicKey({
    key: publicKeyBuffer,
    type: 'spki',
    format: 'der',
  })
}
export function signingPrivateKeyFromBuffer(privateKeyBuffer){
  return crypto.createPrivateKey({
    key: privateKeyBuffer,
    type: 'pkcs8',
    format: 'der',
  })
}


export function encryptingPublicKeyFromBuffer(publicKeyBuffer){
  return crypto.createPublicKey({
    key: publicKeyBuffer,
    type: 'spki',
    format: 'der',
  })
}
export function encryptingPrivateKeyFromBuffer(privateKeyBuffer){
  console.log({ privateKeyBuffer })
  console.log(privateKeyBuffer.toString('hex'))
  console.log(privateKeyBuffer.length)
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

export async function createJWE({ payload, recipients }){
  const text = new TextEncoder().encode(JSON.stringify(payload))
  const proto = await new jose.GeneralEncrypt(text)
  for (const publicKey of recipients){
    proto
      .addRecipient(publicKey)
      .setProtectedHeader({ alg: 'EdDSA' })
  }
    // .setProtectedHeader({ enc: 'A256GCM' })
    // .addRecipient(ecPublicKey)
    // .setUnprotectedHeader({ alg: 'ECDH-ES+A256KW' })
    // .addRecipient(rsaPublicKey)
    // .setUnprotectedHeader({ alg: 'RSA-OAEP-384' })
    // .encrypt()

  const jwe = await proto.encrypt()
  console.log({ jwe })
  return jwe
}
