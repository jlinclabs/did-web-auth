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

  // crypto.subtle.importKey(
  //   'raw', // format of the key data
  //   privateKey, // key data as a buffer
  //   'sha256', // algorithm object
  //   true, // whether the key is extractable
  //   ['signing'] // array of key usages
  // )
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

export async function createJWS({ payload, signers }){
  const text = new TextEncoder().encode(JSON.stringify(payload))
  let proto = new jose.GeneralSign(text)
  for (const privateKey in signers){

    // const privateKey = jose.JWK.asKey(privateKey, {
    //   kty: 'OKP',
    //   crv: 'Ed25519',
    //   d: privateKey,
    // });
    // const jwk = await jose.importJWK({
    //   kty: 'OKP',
    //   crv: 'Ed25519',
    //   // d: Buffer.from(privateKeyHex, 'hex')
    //   d: privateKey,
    // }, 'EdDSA', { alg: 'EdDSA' }, true);
    const x = crypto.createPrivateKey({
      key: privateKey,
      // format: "der",
      type: "Ed25519",
    })
    console.log(x)


    proto = proto
      // .addSignature(privateKey)
      .addSignature(jwk)
      .setProtectedHeader({ alg: 'ED25519' })
  }
    // .addSignature(ecPrivateKey)
    // .setProtectedHeader({ alg: 'ES256' })
    // .addSignature(rsaPrivateKey)
    // .setProtectedHeader({ alg: 'PS256' })
    // .sign()
  const jws = proto.sign()
  console.log({ jws })
  return jws
}
