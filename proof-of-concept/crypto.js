import { promisify } from 'util'
import crypto from 'crypto'
import * as jose from 'jose'

const generateKeyPair = promisify(crypto.generateKeyPair).bind(null, 'ed25519')
export { generateKeyPair }

const keyToJWK = key => jose.exportJWK(key)
export { keyToJWK }

const JWKToKey = jwk => jose.importJWK(jwk)
export { JWKToKey }
