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

// publicKeyHex:  '302a300506032b65700321005da461af429b5a9f993f4e770d5cc48c08fb882dd82e76e7dcebf5e69daa4c94',
// privateKeyHex: '302e020100300506032b65700422042088165832a9244f5688b8d1b6d92b0deca1c66c3c95168e1df4aa9ac95958541c'
function isSamePublicKeyObject(a, b){
  console.log({ a, b })
  if (!(a instanceof PublicKeyObject)) throw new Error(`first argument is not an instance of PublicKeyObject`)
  if (!(b instanceof PublicKeyObject)) throw new Error(`second argument is not an instance of PublicKeyObject`)
  if (a === b) return true

  a = a.export({ type: 'spki', format: 'der' })
  b = b.export({ type: 'spki', format: 'der' })
  console.log({ a, b })
  return a.equals(b)
  // if (
  //   typeof a !== typeof b
  // ) return false
  // return false
}
function isSamePrivateKeyObject(a, b){
  console.log({ a, b })
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
  t.alike(signing.privateKey, crypto.createPublicKey({ key: Buffer.from(signing.privateKeyHex, 'hex'), type: 'pkcs8', format: 'der' }))

  console.log({ signing })

  const signing2 = ed25519.generateKeyPair()
  signing2.publicKeyU8 = signing2.publicKey
  signing2.privateKeyU8 = signing2.secretKey
  delete signing2.publicKey
  delete signing2.secretKey
  signing2.publicKeyHex = Buffer.concat([
    DER_PREFIX_ED25519_PUBLIC,
    Buffer.from(signing2.publicKeyU8),
  ]).toString('hex')
  signing2.privateKeyHex = Buffer.concat([
    DER_PREFIX_ED25519_PRIVATE,
    Buffer.from(signing2.privateKeyU8),
  ]).toString('hex')
  signing2.publicKeyBuffer = Buffer.from(signing2.publicKeyHex, 'hex')
  signing2.privateKeyBuffer = Buffer.from(signing2.privateKeyHex, 'hex')

  signing2.publicKey = crypto.createPublicKey({ key: signing2.publicKeyBuffer, type: 'spki', format: 'der' })
  signing2.privateKey = crypto.createPublicKey({ key: signing2.privateKeyBuffer, type: 'pkcs8', format: 'der' })
  console.log({ signing2 })

  // CONVERT ed25519 to X25519
  // const encrypting2 = crypto.generateKeyPairSync('x25519')
  // console.log({ encrypting2 })
  // console.log({ encrypting2: {
  //   publicKey: await jose.exportJWK(encrypting2.publicKey),
  //   privateKey: await jose.exportJWK(encrypting2.privateKey),
  // } })

  // const publicKeyWithoutPrefixBuffer = signing.publicKeyBuffer.slice(6)
  // console.log('publicKeyWithoutPrefixBuffer', publicKeyWithoutPrefixBuffer.toString('hex'))

  // const publicBytes = u8a.fromString(publicKeyWithoutPrefixBuffer.toString('hex'), 'base16')
  // console.log({ publicBytes })
  // // key.publicKeyHex = u8a.toString(convertPublicKeyToX25519(publicBytes), 'base16')

  // console.log('signing.publicKeyBuffer', Buffer.from(signing.publicKeyBuffer).slice(6).toString('hex'))
  // console.log('signing.publicKeyBuffer', signing.publicKeyBuffer.toString('hex'))
  const encrypting = {
    publicKeyBuffer: Buffer.from(
      ed25519.convertPublicKeyToX25519(
        // new Uint8Array(signing.publicKeyBuffer.buffer)
        // new Uint8Array(signing.publicKeyBuffer)
        // signing.publicKeyBuffer.slice(32)
        // publicBytes

        // u8a.fromString(signing.publicKeyBuffer.slice(6).toString('hex'), 'base16')
        signing2.publicKeyU8
      )
    ),
    privateKeyBuffer: Buffer.from(
      ed25519.convertSecretKeyToX25519(
        // new Uint8Array(signing.publicKeyBuffer.buffer)
        // new Uint8Array(signing.publicKeyBuffer)
        // signing.publicKeyBuffer.slice(32)
        // publicBytes
        // u8a.fromString(signing.privateKeyBuffer.slice(4).toString('hex'), 'base16')
        signing2.privateKeyU8
      )
    ),
  }
  console.log({ encrypting })
  encrypting.publicKey = await jose.importJWK({
    kty: 'OKP',
    crv: 'X25519',
    x: base64url.encode(encrypting.publicKeyBuffer),
  })
  console.log({ encrypting })

  // encrypting.privateKey = await jose.importJWK({
  //   privateKey: ed25519.convertSecretKeyToX25519(
  //     // signing.privateKeyBuffer
  //     u8a.fromString(signing.privateKeyBuffer.slice(6).toString('hex'), 'base16')
  //   ),
  // }
  console.log({ encrypting })

  throw new Error('DOES KEY CONVERSION WORK!?!?')

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
  console.log({ jws })

  // VALIDATE A JWS
  {
    const { payload, protectedHeader } = await jose.generalVerify(jws, signing.publicKey)
    t.alike(JSON.parse(payload), { hello: 'world' })

    const otherKp = crypto.generateKeyPairSync('ed25519')
    await t.exception(async () => {
      await jose.generalVerify(jws, otherKp.publicKey)
    })
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
      .setProtectedHeader({ alg: 'EdDSA', enc: 'A256GCM' })
      .addRecipient(encrypting.publicKey)

    jwe = await proto.encrypt()
  }
  console.log(jwe)
  // VALIDATE A JWE







  // const jws = jose.createSign({
  //   header: {
  //     alg: 'EdDSA',
  //     b64: false,
  //     crit: ['b64']
  //   },
  //   payload,
  //   signingKey: privateKey
  // })
})
