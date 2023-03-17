import crypto from 'crypto'
import test from 'brittle'
import ed25519 from '@stablelib/ed25519'
import x25519 from '@stablelib/x25519'
import * as jose from 'jose'
import * as u8a from 'uint8arrays'
import { base64url } from 'multiformats/bases/base64'

const DER_PREFIX_ED25519_PUBLIC  = Buffer.from('302a300506032b6570032100', 'hex')
const DER_PREFIX_ED25519_PRIVATE = Buffer.from('302e020100300506032b657004220420', 'hex')
const DER_PREFIX_X25519_PUBLIC   = Buffer.from('302a300506032b656e032100', 'hex')
const DER_PREFIX_X25519_PRIVATE  = Buffer.from('302e020100300506032b656e042204', 'hex')

const PublicKeyObject = crypto.generateKeyPairSync('ed25519').publicKey.constructor
const PrivateKeyObject = crypto.generateKeyPairSync('ed25519').privateKey.constructor

export { PublicKeyObject, PrivateKeyObject }
/**
 * WHAT WE NEED
 * - a way to generate a single signing key pair
 * - a way to generate a single encrypting keypair 
 * - a way to serialize those keypairs into sql and back out
 * - a way to make JWK, JWS and JWT with jose that work
 * - keys should be passed around as instances of `PublicKeyObject` and `PrivateKeyObject`
 */

function signingPublicKeyToBuffer(publicKey){
  const buffer = publicKey.export({ type: 'spki', format: 'der' })
  let hex = buffer.toString('hex')
  hex = hex.slice(DER_PREFIX_ED25519_PUBLIC.toString('hex').length, -1)
  return Buffer.from(hex, 'hex')
}
function signingPrivateKeyToBuffer(privateKey){
  const buffer = privateKey.export({ type: 'pkcs8', format: 'der' })
  let hex = buffer.toString('hex')
  hex = hex.slice(DER_PREFIX_ED25519_PRIVATE.toString('hex').length, -1)
  return Buffer.from(hex, 'hex')
}

export async function generateSigningKeyPair(seed){
  const normal = crypto.generateKeyPairSync('ed25519')
  normal.publicJwk = await jose.exportJWK(normal.publicKey)
  normal.privateJwk = await jose.exportJWK(normal.privateKey)
  normal.publicBuffer = signingPublicKeyToBuffer(normal.publicKey)
  normal.privateBuffer = signingPrivateKeyToBuffer(normal.privateKey)
  normal.publicBufferAsHex = Buffer.from(normal.publicBuffer).toString('hex')
  normal.privateBufferAsHex = Buffer.from(normal.privateBuffer).toString('hex')
  normal.publicBufferAsBase64url = Buffer.from(normal.publicBuffer).toString('base64url')
  normal.privateBufferAsBase64url = Buffer.from(normal.privateBuffer).toString('base64url')
  normal.publicKeyU8 = new Uint8Array(normal.publicBuffer)
  normal.privateKeyU8 = new Uint8Array(normal.privateBuffer)
  normal.publicJwkByHand = {
    kty: 'OKP',
    crv: 'Ed25519',
    x: Buffer.from(normal.publicKeyU8).toString('base64url'),
  }
  normal.privateJwkByHand = {
    kty: 'OKP',
    crv: 'Ed25519',
    x: Buffer.from(normal.publicKeyU8).toString('base64url'),
    d: Buffer.from(normal.privateKeyU8).toString('base64url'),  
  } 
  normal.privateKeyFromJWK = crypto.createPrivateKey({ format: 'jwk', key: normal.privateJwk })
  normal.publicKeyFromJWK = crypto.createPublicKey({ format: 'jwk', key: normal.publicJwk })
  console.log({ normal })



  
  let {
    publicKey: publicKeyU8,
    secretKey: privateKeyU8
  } = seed
    ? ed25519.generateKeyPairFromSeed(seedToBuffer(seed))
    : ed25519.generateKeyPair()
  
  const skp = { publicKeyU8, privateKeyU8 }
  skp.publicBuffer = Buffer.from(skp.publicKeyU8)
  skp.privateBuffer = Buffer.from(privateKeyU8)
  skp.publicHex = Buffer.from(skp.publicBuffer).toString('hex')
  skp.privateHex = Buffer.from(skp.privateBuffer).toString('hex')
  console.log({ skp })
  // skp.publicBuffer = signingPublicKeyToBuffer(normal.publicKey)
  // skp.privateBuffer = signingPrivateKeyToBuffer(normal.privateKey)
  console.log({
    fromEd25519: {
      publicKeyU8, 
      privateKeyU8,
    }
  })

  // const publicJwk = await jose.exportJWK(publicKeyU8)
  // const privateJwk = await jose.exportJWK(privateKeyU8)
  // publicJwk.kty = 'OKP'
  // publicJwk.crv = 'Ed25519'
  // privateJwk.kty = 'OKP'
  // privateJwk.crv = 'Ed25519'
  const privateJwk = {
    kty: 'OKP',
    crv: 'Ed25519',
    x: Buffer.from(publicKeyU8).toString('base64url'),
    d: Buffer.from(privateKeyU8).toString('base64url'),

    x: Buffer.from(publicKeyU8).toString('base64url'),
    d: Buffer.from(privateKeyU8).toString('base64url'),
  }
  const publicJwk = {...privateJwk}
  delete publicJwk.d
  console.log({ publicJwk, privateJwk })

  // const publicKey = await jose.importJWK(publicJwk, 'EdDSA')
  // const privateKey = await jose.importJWK(privateJwk, 'EdDSA')
  const privateKey = crypto.createPrivateKey({ format: 'jwk', key: privateJwk })
  const publicKey = crypto.createPublicKey({ format: 'jwk', key: publicJwk })

  // const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519')
  console.log({ publicKey, privateKey })
  return { publicKey, privateKey }
}


// export class KeyPair {
//   constructor({ publicKeyU8, privateKeyU8 }){
//     this.publicKeyU8 = publicKeyU8
//     this.privateKeyU8 = privateKeyU8
//   }
// }

// export class SigningKeyPair extends KeyPair {

//   static async fromSeed(seed){
//     let {
//       publicKey: publicKeyU8,
//       secretKey: privateKeyU8,
//     } = ed25519.generateKeyPairFromSeed(seedToBuffer(seed))
//     return new this({ publicKeyU8, privateKeyU8 })
//   }

//   static async generate(){
//     let {
//       publicKey: publicKeyU8,
//       secretKey: privateKeyU8,
//     } = ed25519.generateKeyPair()
//     return new this({ publicKeyU8, privateKeyU8 })
//   }

//   constructor({ publicKeyU8, privateKeyU8 }){
//     this.publicKey = new SigningPublicKey(publicKeyU8)
//     this.privateKeyU8 = privateKeyU8
//   }

//   get publicKeyAsJWK(){
//     return await jose.exportJWK(publicKeyU8)
//     //  await jose.exportJWK(privateKeyU8)
//   }
//   get publicKeyObject(){

//   }
//   get privateKeyObject(){

//   }
// }

// export class EncryptingKeyPair extends KeyPair {

//   static async generate(){
//     let {
//       publicKey: publicKeyU8,
//       secretKey: privateKeyU8
//     } = x25519.generateKeyPair()
//     return new({ publicKeyU8, privateKeyU8 })
//   }
// }


function seedToBuffer(seed){
  const hash = crypto.createHash('sha256').update(seed).digest(); //returns a buffer
  console.log({ seed, hash })
  return hash
  // if (!seed) return
  // const seedBuffer = Buffer.alloc(sodium.crypto_sign_SEEDBYTES)
  // Buffer.from(seed).copy(seedBuffer)
  // console.log({ seed, hash, seedBuffer })
  // return seedBuffer
}


// import { promisify } from 'util'
// import crypto from 'crypto'
// import { base64url } from 'multiformats/bases/base64'
// import { base58btc } from 'multiformats/bases/base58'
// import * as jose from 'jose'
// // import ed25519 from '@stablelib/ed25519'
// // import x25519 from '@stablelib/x25519'
// import sodium from 'sodium-native'
// // import nacl from 'tweetnacl'
// // TODO remove these
// // import ed25519 from 'ed25519'
// // import forge from 'node-forge'

// // console.log({ sodium })
// const generateKeyPair = promisify(crypto.generateKeyPair) //.bind(null, 'ed25519')


// // export function keyBufferToString(buffer){
// //   return base58btc.encode(buffer)
// // }

// // export function keyToBuffer(string){
// //   return Buffer.from(base58btc.decode(string))
// // }

// function seedToBuffer(seed){
//   // var hash = crypto.createHash('sha256').update(bobsPassword).digest(); //returns a buffer
//   if (!seed) return
//   const seedBuffer = Buffer.alloc(sodium.crypto_sign_SEEDBYTES)
//   Buffer.from(seed).copy(seedBuffer)
//   return seedBuffer
// }


// export async function generateSigningKeyPair(seed){
//   let publicKey = Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
//   let privateKey = Buffer.alloc(sodium.crypto_sign_SECRETKEYBYTES)
//   if (seed){
//     seed = seedToBuffer(seed)
//     // sodium.crypto_sign_seed25519_keypair(pk, sk, seed)
//     sodium.crypto_sign_seed_keypair(publicKey, privateKey, seed)
//   }else{
//     sodium.crypto_sign_keypair(publicKey, privateKey)
//   }
//   console.log('generateSigningKeyPair (Buffers)', { publicKey, privateKey })

//   // Prepend the X25519 public key buffer with the ASN.1 sequence
//   const publicKeyBuffer = Buffer.concat([
//     Buffer.from('3059301306072a8648ce3d020106082a8648ce3d030107034200', 'hex'),
//     publicKey
//   ]);

//   // Create a public key object using crypto.createPublicKey()
//   const publicKeyObject = crypto.createPublicKey({
//     key: publicKeyBuffer,
//     type: 'spki',
//     format: 'der',
//   })
//   console.log({ publicKeyObject })

//   throw new Error('NOT DONE YET!!')
//   // publicKey = signingPublicKeyFromBuffer(createEd25519PublicKeySpkiBuffer(publicKey))
//   // privateKey = signingPrivateKeyFromBuffer(createEd25519PrivateKeyPkcs8Buffer(privateKey))
//   // console.log('generateSigningKeyPair (objects)', { publicKey, privateKey })
//   // let { publicKey, secretKey: privateKey } = seed
//   //   ? ed25519.generateKeyPairFromSeed(seedToBuffer(seed))
//   //   : ed25519.generateKeyPair()

//   // console.log('generateSigningKeyPair (Uint8Arrays)', { publicKey, privateKey })
//   // // let { publicKey, secretKey: privateKey } = seed
//   // //   ? nacl.sign.keyPair.fromSeed(seedToBuffer(seed))
//   // //   : nacl.sign.keyPair()
//   // // // console.log('generateSigningKeyPair', { publicKey, privateKey })

//   // const publicKeyAsUint8Array = publicKey
//   // const privateKeyAsUint8Array = privateKey


//   // publicKey = signingPublicKeyFromBuffer(createEd25519PublicKeySpkiBuffer(publicKey))
//   // privateKey = signingPrivateKeyFromBuffer(createEd25519PrivateKeyPkcs8Buffer(privateKey))
//   // console.log('generateSigningKeyPair (objects)', { publicKey, privateKey })

//   // // console.log('generateSigningKeyPair', { publicKey, privateKey })
//   return { publicKey, privateKey }
// }

// export async function generateEncryptingKeyPairFromSigningKeyPair({ publicKey, privateKey }){
//   // sodium.crypto_sign_ed25519_pk_to_curve25519(Buffer.from(some-ed-key))

//   publicKey = encryptingPublicKeyFromBuffer(
//     createX25519PublicKeySpkiBuffer(
//       ed25519.convertPublicKeyToX25519(
//         publicSigningKeyToUint8Array(publicKey)
//       )
//     )
//   )
//   privateKey = encryptingPrivateKeyFromBuffer(
//     // createX25519PrivateKeyPkcs8Buffer(
//       ed25519.convertSecretKeyToX25519(
//         privateSigningKeyToUint8Array(privateKey)
//       )
//     // )
//   )
//   console.log('generateEncryptingKeyPairFromSigningKeyPair', { publicKey, privateKey })
//   return { publicKey, privateKey }
// }

// export async function generateEncryptingKeyPair(seed){
//   let { publicKey, secretKey: privateKey } = seed
//     ? nacl.box.keyPair.fromSecretKey(seedToBuffer(seed))
//     : nacl.box.keyPair()
//   // console.log('generateEncryptingKeyPair', { privateKey, publicKey })
//   publicKey = signingPublicKeyFromBuffer(createX25519PublicKeySpkiBuffer(Buffer.from(publicKey)))
//   privateKey = signingPrivateKeyFromBuffer(createX25519PrivateKeyPkcs8Buffer(Buffer.from(privateKey)))
//   // console.log('generateEncryptingKeyPair', { privateKey, publicKey })
//   return { publicKey, privateKey }
// }


// function publicSigningKeyToUint8Array(publicKey){
//   return new Uint8Array(signingPublicKeyToBuffer(publicKey).buffer)
// }

// function privateSigningKeyToUint8Array(privateKey){
//   console.log('🔺 privateSigningKeyToUint8Array', {privateKey})
//   const buffer = signingPrivateKeyToBuffer(privateKey)
//   console.log('🔺 privateSigningKeyToUint8Array', {buffer})
//   const uint8Array = new Uint8Array(buffer.buffer)
//   console.log('🔺 privateSigningKeyToUint8Array', {uint8Array})
//   return uint8Array
// }

// // Magic ChatGPT wrote for me :D
// const DER_PREFIX_ED25519_PUBLIC  = '302a300506032b656e032100'
// const DER_PREFIX_ED25519_PRIVATE = '302e020100300506032b657004220420'
// const DER_PREFIX_X25519_PUBLIC   = '302a300506032b6570032100'
// const DER_PREFIX_X25519_PRIVATE  = '302e020100300506032b656e042204'
// function createEd25519PublicKeySpkiBuffer(publicKeyBuffer) {
//   return Buffer.concat([
//     Buffer.from('302a300506032b656e032100', 'hex'),
//     publicKeyBuffer
//   ])
// }
// function createEd25519PrivateKeyPkcs8Buffer(privateKeyBuffer) {
//   return Buffer.concat([
//     Buffer.from('302e020100300506032b657004220420', 'hex'),
//     privateKeyBuffer
//   ])
// }
// function createX25519PublicKeySpkiBuffer(publicKeyBuffer) {
//   return Buffer.concat([
//     Buffer.from('302a300506032b6570032100', 'hex'),
//     publicKeyBuffer,
//   ])
// }
// function createX25519PrivateKeyPkcs8Buffer(privateKeyBuffer) {
//   console.log('createX25519PrivateKeyPkcs8Buffer', { privateKeyBuffer })
//   return Buffer.concat([
//     Buffer.from('302e020100300506032b656e042204', 'hex'),
//     privateKeyBuffer,
//   ])
// }
// function ed25519PublicJwkToSpkiBuffer(jwk) {
//   return createEd25519PublicKeySpkiBuffer(
//     Buffer.from(jwk.x, 'base64')
//   )
// }
// function ed25519PrivateJwkToPkcs8Buffer(jwk) {
//   return createEd25519PrivateKeyPkcs8Buffer(
//     Buffer.from(jwk.d, 'base64')
//   )
// }
// export function privateKeyJwkToPublicKeyJwk(privateKeyJwk) {
//   return {
//     kty: privateKeyJwk.kty,
//     crv: privateKeyJwk.crv,
//     x:   privateKeyJwk.x,
//     alg: privateKeyJwk.alg,
//     ext: privateKeyJwk.ext,
//   }
// }


// export function signingPublicKeyToBuffer(publicKey){
//   return publicKey.export({
//     type: 'spki',
//     format: 'der',
//   })
// }
// export function signingPrivateKeyToBuffer(privateKey){
//   return privateKey.export({
//     type: 'pkcs8',
//     format: 'der',
//   })
// }

// export function signingPublicKeyFromBuffer(publicKeyBuffer){
//   return crypto.createPublicKey({
//     key: publicKeyBuffer,
//     type: 'spki',
//     format: 'der',
//   })
// }
// export function signingPrivateKeyFromBuffer(privateKeyBuffer){
//   return crypto.createPrivateKey({
//     key: privateKeyBuffer,
//     type: 'pkcs8',
//     format: 'der',
//   })
// }


// export function encryptingPublicKeyFromBuffer(publicKeyBuffer){
//   return crypto.createPublicKey({
//     key: publicKeyBuffer,
//     type: 'spki',
//     format: 'der',
//   })
// }
// export function encryptingPrivateKeyFromBuffer(privateKeyBuffer){
//   console.log({ privateKeyBuffer })
//   console.log(privateKeyBuffer.toString('hex'))
//   console.log(privateKeyBuffer.length)
//   return crypto.createPrivateKey({
//     key: privateKeyBuffer,
//     type: 'pkcs8',
//     format: 'der',
//   })
// }

// export function publicKeyToJKW(publicKey){
//   return publicKey.export({ format: 'jwk' })
// }

// export function privateKeyToJKW(privateKey){
//   return privateKey.export({ format: 'jwk' })
// }

// export function publicKeyFromJKW(publicKeyJWK){
//   return crypto.createPublicKey({
//     key: ed25519PublicJwkToSpkiBuffer(publicKeyJWK),
//     format: 'der',
//     type: 'spki',
//   });
// }

// export function privateKeyFromJKW(privateKeyJWK){
//   return crypto.createPrivateKey({
//     key: ed25519PrivateJwkToPkcs8Buffer(privateKeyJWK),
//     format: 'der',
//     type: 'pkcs8',
//   })
// }

// export async function createJWS({ payload, signers }){
//   const text = new TextEncoder().encode(JSON.stringify(payload))
//   let proto = new jose.GeneralSign(text)
//   for (const privateKey of signers){
//     proto
//       .addSignature(privateKey)
//       .setProtectedHeader({ alg: 'EdDSA' })
//   }
//   const jws = await proto.sign()
//   return jws
// }

// export async function verifyJWS({ jws, publicKey }){
//   const { payload, protectedHeader } = await jose.generalVerify(jws, publicKey)
//   const data = JSON.parse(new TextDecoder().decode(payload))
//   // console.log({ protectedHeader, data })
//   return data
// }

// export async function createJWE({ payload, recipients }){
//   const text = new TextEncoder().encode(JSON.stringify(payload))
//   const proto = await new jose.GeneralEncrypt(text)
//   for (const publicKey of recipients){
//     proto
//       .addRecipient(publicKey)
//       .setProtectedHeader({ alg: 'EdDSA' })
//   }
//     // .setProtectedHeader({ enc: 'A256GCM' })
//     // .addRecipient(ecPublicKey)
//     // .setUnprotectedHeader({ alg: 'ECDH-ES+A256KW' })
//     // .addRecipient(rsaPublicKey)
//     // .setUnprotectedHeader({ alg: 'RSA-OAEP-384' })
//     // .encrypt()

//   const jwe = await proto.encrypt()
//   console.log({ jwe })
//   return jwe
// }
