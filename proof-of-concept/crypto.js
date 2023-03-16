import { promisify } from 'util'
import ed25519 from 'ed25519'
import crypto from 'crypto'
import * as jose from 'jose'
import { base58btc } from 'multiformats/bases/base58'

const generateKeyPair = promisify(crypto.generateKeyPair).bind(null, 'ed25519')
export { generateKeyPair }


export async function generateSigningKeyPair(seed){
  const hash = seed
    ? crypto.createHash('sha256').update(seed).digest()
    : crypto.randomBytes(32)

  const { privateKey, publicKey } = ed25519.MakeKeypair(hash)
  return { publicKey, privateKey }
}

const keyToJWK = key => jose.exportJWK(key)
export { keyToJWK }

const JWKToKey = jwk => jose.importJWK(jwk)
export { JWKToKey }

// export function keyToString(key){
//   return base58btc.encode(key)
// }
// export function base5String(key){
//   return base58btc.encode(key)
// }


export function publicKeyToBase58(publicKey){
  // console.log({ publicKey })
  // const base64 = Buffer.from(publicKey.x, 'base64')
  console.log({ publicKey })
  return base58btc.encode(publicKey)
}

export async function createJWS(data){
  const text = new TextEncoder().encode(JSON.stringify(data))
  const jws = await new jose.GeneralSign(text)
    // .addSignature(ecPrivateKey)
    // .setProtectedHeader({ alg: 'ES256' })
    // .addSignature(rsaPrivateKey)
    // .setProtectedHeader({ alg: 'PS256' })
    .sign()
  return jws
}
