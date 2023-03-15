import { promisify } from 'util'
import crypto from 'crypto'
import * as jose from 'jose'
import { base58btc } from 'multiformats/bases/base58'

const generateKeyPair = promisify(crypto.generateKeyPair).bind(null, 'ed25519')
export { generateKeyPair }

const keyToJWK = key => jose.exportJWK(key)
export { keyToJWK }

const JWKToKey = jwk => jose.importJWK(jwk)
export { JWKToKey }


export function publicKeyToBase58(publicKey){
  console.log({ publicKey })
  const base64 = Buffer.from(publicKey.x, 'base64')
  return base58btc.encode(base64)
}