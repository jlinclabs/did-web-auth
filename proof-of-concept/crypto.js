import crypto from 'crypto'
import * as jose from 'jose'

const PublicKeyObject = crypto.generateKeyPairSync('ed25519').publicKey.constructor
const PrivateKeyObject = crypto.generateKeyPairSync('ed25519').privateKey.constructor

export { PublicKeyObject, PrivateKeyObject }

export async function generateSigningKeyPair(seed){
  return crypto.generateKeyPairSync('ed25519')
}

export async function generateEncryptingKeyPair(){
  return crypto.generateKeyPairSync('x25519')
}

export async function keyPairToJWK({ publicKey, privateKey }){
  return await jose.exportJWK(privateKey)
}
export async function keyPairFromJWK(privateJWK){
  const publicJWK = {...privateJWK}
  delete publicJWK.d // TODO there is more to delete here
  return {
    publicKey: crypto.createPublicKey({ format: 'jwk', key: publicJWK }),
    privateKey: crypto.createPrivateKey({ format: 'jwk', key: privateJWK }),
  }
}

export function isSamePublicKeyObject(a, b){
  if (!(a instanceof PublicKeyObject)) throw new Error(`first argument is not an instance of PublicKeyObject`)
  if (!(b instanceof PublicKeyObject)) throw new Error(`second argument is not an instance of PublicKeyObject`)
  if (a === b) return true
  a = a.export({ type: 'spki', format: 'der' })
  b = b.export({ type: 'spki', format: 'der' })
  return a.equals(b)
}

export function isSamePrivateKeyObject(a, b){
  if (!(a instanceof PrivateKeyObject)) throw new Error(`first argument is not an instance of PrivateKeyObject`)
  if (!(b instanceof PrivateKeyObject)) throw new Error(`second argument is not an instance of PrivateKeyObject`)
  if (a === b) return true
  a = a.export({ type: 'pkcs8', format: 'der' })
  b = b.export({ type: 'pkcs8', format: 'der' })
  return a.equals(b)
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
