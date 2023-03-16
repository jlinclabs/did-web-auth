import { promisify } from 'util'
import crypto from 'crypto'
import ed25519 from 'ed25519'
import * as jose from 'jose'
import forge from 'node-forge'
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
  // node's crypto.generateKeyPair has no way to provide a seed
  // const generateKeyPair = promisify(crypto.generateKeyPair).bind(null, 'ed25519')
  // const { publicKey, privateKey } = await generateKeyPair()

  // WE NEED A DETERMINISTIC WAY TO MAKE THESE!?!?!

  if (seed){
    const seedBuffer = Buffer.alloc(32)
    Buffer.from(seed).copy(seedBuffer)
    seed = seedBuffer
  }

  // const seed = forge.random.getBytesSync(32);
  let { publicKey, privateKey } = forge.pki.ed25519
    .generateKeyPair({ seed })

  publicKey = publicKeyFromBuffer(createEd25519PublicKeySpkiBuffer(publicKey))
  privateKey = privateKeyFromBuffer(createEd25519PrivateKeyPkcs8Buffer(privateKey))

  return { publicKey, privateKey }
}

// Magic ChatGPT wrote for me :D
function createEd25519PublicKeySpkiBuffer(publicKeyBuffer) {
  const prefix = Buffer.from('302a300506032b6570032100', 'hex');
  return Buffer.concat([prefix, publicKeyBuffer]);
}
function createEd25519PrivateKeyPkcs8Buffer(privateKeyBuffer) {
  const prefix = Buffer.from('302e020100300506032b657004220420', 'hex');
  return Buffer.concat([prefix, privateKeyBuffer]);
}
function ed25519PublicJwkToSpkiBuffer(jwk) {
  const prefix = Buffer.from('302a300506032b6570032100', 'hex');
  const publicKeyBuffer = Buffer.from(jwk.x, 'base64');
  return Buffer.concat([prefix, publicKeyBuffer]);
}
function ed25519PrivateJwkToPkcs8Buffer(jwk) {
  const prefix = Buffer.from('302e020100300506032b657004220420', 'hex');
  const privateKeyBuffer = Buffer.from(jwk.d, 'base64');
  return Buffer.concat([prefix, privateKeyBuffer]);
}
function privateKeyJwkToPublicKeyJwk(privateKeyJwk) {
  const publicKeyJwk = {
    kty: privateKeyJwk.kty,
    crv: privateKeyJwk.crv,
    x: privateKeyJwk.x,
    alg: privateKeyJwk.alg,
    ext: privateKeyJwk.ext,
  };
  return publicKeyJwk;
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
