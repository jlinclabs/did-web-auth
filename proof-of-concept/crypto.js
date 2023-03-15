import { promisify } from 'util'
import crypto from 'crypto'
import * as jose from 'jose'
import { base58btc } from 'multiformats/bases/base58'

const generateKeyPair = promisify(crypto.generateKeyPair).bind(null, 'ed25519')
export { generateKeyPair }


export async function generateSigningKeyPair(seed){
  // Convert the seed string to a buffer
  if (seed) seed = Buffer.from(seed, 'utf8')

  // Generate the keypair from the seed
  const { publicKey, privateKey } = crypto.sign.generateKeyPair('ed25519', {
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'der',
      // Set the seed as the private key
      privateKey: seed
    }
  });

  console.log('Public key:', publicKey.toString('hex'));
  console.log('Private key:', privateKey.toString('hex'));
  return { publicKey, privateKey }
}

const keyToJWK = key => jose.exportJWK(key)
export { keyToJWK }

const JWKToKey = jwk => jose.importJWK(jwk)
export { JWKToKey }


export function publicKeyToBase58(publicKey){
  console.log({ publicKey })
  const base64 = Buffer.from(publicKey.x, 'base64')
  return base58btc.encode(base64)
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

const hostSigningKeys = generateSigningKeyPair()