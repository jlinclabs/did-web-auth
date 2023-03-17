import crypto from 'crypto'
import test from 'brittle'
import ed25519 from '@stablelib/ed25519'
import * as jose from 'jose'
import * as u8a from 'uint8arrays'
import { base64url } from 'multiformats/bases/base64'

const DER_PREFIX_ED25519_PUBLIC  = Buffer.from('302a300506032b6570032100', 'hex')
const DER_PREFIX_ED25519_PRIVATE = Buffer.from('302e020100300506032b657004220420', 'hex')
const DER_PREFIX_X25519_PUBLIC   = Buffer.from('302a300506032b656e032100', 'hex')
const DER_PREFIX_X25519_PRIVATE  = Buffer.from('302e020100300506032b656e042204', 'hex')

const PublicKeyObject = crypto.generateKeyPairSync('ed25519').publicKey.constructor
const PrivateKeyObject = crypto.generateKeyPairSync('ed25519').privateKey.constructor

function isSamePublicKeyObject(a, b){
  if (!(a instanceof PublicKeyObject)) throw new Error(`first argument is not an instance of PublicKeyObject`)
  if (!(b instanceof PublicKeyObject)) throw new Error(`second argument is not an instance of PublicKeyObject`)
  if (a === b) return true
  a = a.export({ type: 'spki', format: 'der' })
  b = b.export({ type: 'spki', format: 'der' })
  return a.equals(b)
}
function isSamePrivateKeyObject(a, b){
  if (!(a instanceof PrivateKeyObject)) throw new Error(`first argument is not an instance of PrivateKeyObject`)
  if (!(b instanceof PrivateKeyObject)) throw new Error(`second argument is not an instance of PrivateKeyObject`)
  if (a === b) return true
  a = a.export({ type: 'pkcs8', format: 'der' })
  b = b.export({ type: 'pkcs8', format: 'der' })
  return a.equals(b)
}

test.solo('crypto smoke', async t => {
  const signing = crypto.generateKeyPairSync('ed25519')

  // CONVERTING SIGNING KEYS TO JWKs
  signing.publicJwk = await jose.exportJWK(signing.publicKey)
  signing.privateJwk = await jose.exportJWK(signing.privateKey)

  // CONVERTING JWKs BACK TO SIGNING KEY OBJECTS
  t.ok(isSamePublicKeyObject(signing.publicKey, await jose.importJWK(signing.publicJwk, 'EdDSA')))
  t.ok(isSamePrivateKeyObject(signing.privateKey, await jose.importJWK(signing.privateJwk, 'EdDSA')))

  // CONVERTING SIGNING KEYS TO BUFFERS
  signing.publicKeyBuffer = signing.publicKey.export({ type: 'spki', format: 'der' })
  signing.privateKeyBuffer = signing.privateKey.export({ type: 'pkcs8', format: 'der' })

  // CONVERTING BUFFER BACK TO SIGNING KEY OBJECTS
  t.ok(isSamePublicKeyObject(signing.publicKey, crypto.createPublicKey({ key: signing.publicKeyBuffer, type: 'spki', format: 'der' })))
  t.ok(isSamePrivateKeyObject(signing.privateKey, crypto.createPrivateKey({ key: signing.privateKeyBuffer, type: 'pkcs8', format: 'der' })))

  // CONVERTING SIGNING KEYS TO Uint8Arrays
  signing.publicKeyU8 = new Uint8Array(signing.publicKeyBuffer)
  signing.privateKeyU8 = new Uint8Array(signing.privateKeyBuffer)

  // CONVERTING Uint8Arrays BACK TO SIGNING KEY OBJECTS
  t.ok(isSamePublicKeyObject(signing.publicKey, crypto.createPublicKey({ key: Buffer.from(signing.publicKeyU8, 'hex'), type: 'spki', format: 'der' })))
  t.ok(isSamePrivateKeyObject(signing.privateKey, crypto.createPrivateKey({ key: Buffer.from(signing.privateKeyU8, 'hex'), type: 'pkcs8', format: 'der' })))


  // CONVERTING SIGNING KEYS TO HEX
  signing.publicKeyHex = signing.publicKeyBuffer.toString('hex')
  signing.privateKeyHex = signing.privateKeyBuffer.toString('hex')

  // CONVERTING HEX BACK TO SIGNING KEY OBJECTS
  t.alike(signing.publicKey, crypto.createPublicKey({ key: Buffer.from(signing.publicKeyHex, 'hex'), type: 'spki', format: 'der' }))
  t.alike(signing.privateKey, crypto.createPrivateKey({ key: Buffer.from(signing.privateKeyHex, 'hex'), type: 'pkcs8', format: 'der' }))


  const encrypting = {}
  encrypting.publicKeyU8 = ed25519.convertPublicKeyToX25519(
    new Uint8Array(
      Buffer.from(
        Buffer.from(signing.publicKeyBuffer).toString('hex').replace(DER_PREFIX_ED25519_PUBLIC.toString('hex'), ''),
        'hex'
      )
    )
  )
  encrypting.privateKeyU8 = ed25519.convertSecretKeyToX25519(
    new Uint8Array(
      Buffer.from(
        Buffer.from(signing.privateKeyBuffer).toString('hex').replace(DER_PREFIX_ED25519_PRIVATE.toString('hex'), ''),
        'hex'
      )
    )
  )
  encrypting.publicKeyHex = Buffer.concat([
    DER_PREFIX_X25519_PUBLIC,
    // Buffer.from(''),
    Buffer.from(encrypting.publicKeyU8),
  ]).toString('hex')
  encrypting.privateKeyHex = Buffer.concat([
    DER_PREFIX_X25519_PRIVATE,
    // Buffer.from(''),
    Buffer.from(encrypting.privateKeyU8),
  ]).toString('hex')

  encrypting.publicJwk = {
    kty: 'OKP',
    crv: 'X25519',
    x: base64url.encode(Buffer.from(encrypting.publicKeyU8)).replace(/^u/, ''),
  }
  encrypting.privateJwk = {
    kty: 'OKP',
    crv: 'X25519',
    x: base64url.encode(Buffer.from(encrypting.publicKeyU8)).replace(/^u/, ''),
    d: base64url.encode(Buffer.from(encrypting.privateKeyU8)).replace(/^u/, ''),
  }

  encrypting.publicKey = await jose.importJWK(encrypting.publicJwk, 'EdDSA')
  encrypting.privateKey = await jose.importJWK(encrypting.privateJwk, 'EdDSA')

  // CREATE A JWS
  let jws
  {
    const payload = { hello: 'world' }
    const jwsProto = new jose.GeneralSign(
      new TextEncoder().encode(
        JSON.stringify(payload)
      )
    )
    jwsProto
      .addSignature(signing.privateKey)
      .setProtectedHeader({ alg: 'EdDSA' })
    jws = await jwsProto.sign()
  }

  // VALIDATE A JWS
  {
    const { payload, protectedHeader } = await jose.generalVerify(jws, signing.publicKey)
    t.alike(JSON.parse(payload), { hello: 'world' })

    const otherKp = crypto.generateKeyPairSync('ed25519')
    await t.exception(async () => {
      await jose.generalVerify(jws, otherKp.publicKey)
    })
  }

  // CREATE A JWS WITH A COPPIED PrivateKeyObject
  {
    function signingPrivateKeyJWK(publicKey){
      return publicKey.export({ type: 'pkcs8', format: 'jwk' })
    }
    function signingPublicKeyJWK(publicKey){
      return publicKey.export({ type: 'spki', format: 'jwk' })
    }
    function signingPrivateKeyJWKToKeyObject(privateKeyJWK){
      return crypto.createPrivateKey({ format: 'jwk', key: privateKeyJWK })
    }
    function signingPublicKeyJWKToKeyObject(publicKeyJWK){
      return crypto.createPublicKey({ format: 'jwk', key: publicKeyJWK })
    }
    const privateKey = signingPrivateKeyJWKToKeyObject(
      signingPrivateKeyJWK(signing.privateKey)
    )
    const publicKey = signingPublicKeyJWKToKeyObject(
      signingPublicKeyJWK(signing.publicKey)
    )
    const jwsProto = new jose.GeneralSign(
      new TextEncoder().encode(JSON.stringify({ whatever: 12 }))
    )
    jwsProto.addSignature(privateKey).setProtectedHeader({ alg: 'EdDSA' })
    const jws = await jwsProto.sign()
    const { payload, protectedHeader } = await jose.generalVerify(jws, publicKey)
    t.alike(JSON.parse(payload), { whatever: 12 })
  }

  // CREATE A JWE
  let jwe
  {
    const payload = { friendship: 'is rare' }
    const proto = await new jose.GeneralEncrypt(
      new TextEncoder().encode(
        JSON.stringify(payload)
      )
    )
      .setProtectedHeader({
        alg: 'ECDH-ES',
        // alg: 'Ed25519',
        enc: 'A256GCM'
      })
      .addRecipient(encrypting.publicKey)

    jwe = await proto.encrypt()
  }

  // VALIDATE A JWE
  {
    const { plaintext, protectedHeader, additionalAuthenticatedData } =
      await jose.generalDecrypt(jwe, encrypting.privateKey)
    // t.alike(protectedHeader, {
    //   alg: 'ECDH-ES',
    //   enc: 'A256GCM',
    //   epk: {
    //     x: 'dFwHaD_HWJ1mFJMIxbY67Ny2OfkuybC7MQVAb_SScyI',
    //     crv: 'X25519',
    //     kty: 'OKP'
    //   }
    // })
    t.alike(JSON.parse(new TextDecoder().decode(plaintext)), { friendship: 'is rare' })
  }

  // console.log({ signing, encrypting })
})
