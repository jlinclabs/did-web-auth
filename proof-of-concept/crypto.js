import { promisify } from 'util'
import crypto from 'crypto'
import ed25519 from 'ed25519'
import * as jose from 'jose'
import { base64url } from 'multiformats/bases/base64'
import { base58btc } from 'multiformats/bases/base58'



// > kp.privateKey.export({ format: 'jwk' })
// {
//   crv: 'Ed25519',
//   d: 'Sd3YrCwdJHzxw7TGiIf1-3DcrxnTZbyPzlRw57VaGpM',
//   x: '6_ywZ8Lyg4KfppQf_zdc-okxro-msjebtxCVMCrg8n4',
//   kty: 'OKP'
// }
// > kp.publicKey.export({ format: 'jwk' })
// {
//   crv: 'Ed25519',
//   x: '6_ywZ8Lyg4KfppQf_zdc-okxro-msjebtxCVMCrg8n4',
//   kty: 'OKP'
// }
// > crypto.createPrivateKey({ format: 'jwk', key: kp.privateKey.export({ format: 'jwk' }) })


export function keyBufferToString(buffer){
  return base58btc.encode(buffer)
}

export function keyToBuffer(string){
  return Buffer.from(base58btc.decode(string))
}

export async function generateSigningKeyPair(seed){
  const generateKeyPair = promisify(crypto.generateKeyPair).bind(null, 'ed25519')
  // WE NEED A DETERMINISTIC WAY TO MAKE THESE!?!?!
  const { publicKey, privateKey } = await generateKeyPair()
  return { publicKey, privateKey }
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
  // return publicKey.export({ format: 'jwk' })
}

export function privateKeyFromJKW(privateKeyJWK){
  // return privateKey.export({ format: 'jwk' })
}

async function publicKeyToKeyObject(publicKey){
  return crypto.KeyObject.create(keyToBuffer(publicKey))
}
async function privateKeyToKeyObject(privateKey){
  console.log({ privateKey })
  const x = {
    kty: 'OKP',
    crv: 'Ed25519',
    x: keyToBuffer(privateKey).toString('hex'),
    // x: 'HccjhsDiu7QNg_8ehFvTqroV5NTV1Cuk-TeMjn99tBY',
    kid: 'did:jlinx:h:did.jlinx.io:k-c_YNhjMkTtyPcCsfbks4VYRTQWyQfZf5XBhQQtsXU',

    // crv: 'P-256',
    // kty: 'EC',
    // x: 'ySK38C1jBdLwDsNWKzzBHqKYEE5Cgv-qjWvorUXk9fw',
    // y: '_LeQBw07cf5t57Iavn4j-BqJsAD1dpoz8gokd3sBsOo',
  }
  console.log({ x })
  crypto.createPrivateKey({ format: 'jwk', key: x })
  // : createPublicKey({ format: 'jwk', key: jwk });
  return await jose.importJWK(
    x,
    'ES256',
  )
  // const { KeyObject } = crypto
  // const privateKeyObject = new KeyObject('pkcs8')
  // privateKeyObject.import(privateKey, 'buffer')
  // return privateKeyObject
  // return crypto.KeyObject.create(keyToBuffer(privateKey), 'pkcs8')

  // const jwk = await jose.importJWK({
  //   kty: 'OKP',
  //   crv: 'Ed25519',
  //   x: 'HccjhsDiu7QNg_8ehFvTqroV5NTV1Cuk-TeMjn99tBY',
  //   // TODO do we need the did here?
  //   // kid: 'did:jlinx:h:did.jlinx.io:k-c_YNhjMkTtyPcCsfbks4VYRTQWyQfZf5XBhQQtsXU'
  //   // d: privateKey,
  // }, 'EdDSA', { alg: 'EdDSA' }, true)


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
  // const x = crypto.createPrivateKey({
  //   key: privateKey,
  //   // format: "der",
  //   type: "Ed25519",
  // })
  // console.log(x)

}

export async function createJWS({ payload, signers }){
  const text = new TextEncoder().encode(JSON.stringify(payload))
  let proto = new jose.GeneralSign(text)
  for (const privateKey of signers){
    proto
      // .addSignature(privateKey)
      .addSignature(
        await privateKeyToKeyObject(privateKey)
        // privateKey
      )
      .setProtectedHeader({ alg: 'ed25519' })
  }
    // .addSignature(ecPrivateKey)
    // .setProtectedHeader({ alg: 'ES256' })
    // .addSignature(rsaPrivateKey)
    // .setProtectedHeader({ alg: 'PS256' })
    // .sign()
  const jws = await proto.sign()
  console.log({ jws })
  return jws
}
