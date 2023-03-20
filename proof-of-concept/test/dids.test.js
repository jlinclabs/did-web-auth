import test from 'brittle'
import {
  generateSigningKeyPair,
  generateEncryptingKeyPair,
  keyPairToPublicJWK,
  PublicKeyObject,
} from '../crypto.js'
import {
  praseDIDWeb,
  didToDidDocumentURL,
  resolveDIDDocument,
  getSigningKeysFromDIDDocument,
  getEncryptionKeysFromDIDDocument,
} from '../dids.js'

test('praseDIDWeb', async t => {
  t.alike(
    praseDIDWeb('did:web:example.com'),
    {
      host: 'example.com',
    }
  )
  t.alike(
    praseDIDWeb('did:web:example.com:u:jared'),
    {
      host: 'example.com',
      path: ':u:jared',
      username: 'jared'
    }
  )
})


test('didToDidDocumentURL', async t => {
  t.is(
    didToDidDocumentURL(`did:web:example.com`),
    `https://example.com/.well-known/did.json`
  )
  t.is(
    didToDidDocumentURL(`did:web:example.com:u:alice`),
    `https://example.com/u/alice/did.json`
  )
})

test('resolveDIDDocument', async t => {
  t.is(typeof resolveDIDDocument, 'function')
  // TODO more tests that stub http requests
})

test('getSigningKeysFromDIDDocument', async t => {
  {
    const keys = await getSigningKeysFromDIDDocument({})
    t.is(keys.length, 0)
  }
  {
    const didDocument = await generateDIDDocument()
    const keys = await getSigningKeysFromDIDDocument(didDocument)
    t.is(keys.length, 1)
    t.is(typeof keys[0], 'object')
    t.ok(keys[0] instanceof PublicKeyObject)
  }
})

test('getEncryptionKeysFromDIDDocument', async t => {
  {
    const keys = await getEncryptionKeysFromDIDDocument({})
    t.is(keys.length, 0)
  }
  {
    const didDocument = await generateDIDDocument()
    const keys = await getEncryptionKeysFromDIDDocument(didDocument)
    t.is(keys.length, 1)
    t.is(typeof keys[0], 'object')
    t.ok(keys[0] instanceof PublicKeyObject)
  }
})


async function generateDIDDocument(){
  const signingKeyPair = await generateSigningKeyPair()
  const encryptingKeyPair = await generateEncryptingKeyPair()
  const did = `did:example.com:u:alice`
  return {
    "@context": [
      "https://www.w3.org/ns/did/v1",
      "https://schema.org/"
    ],
    "id": did,
    "verificationMethod": [
      {
        "id": `${did}#signing-keys-1`,
        "type": "JsonWebKey2020",
        "controller": did,
        "publicKeyJwk": await keyPairToPublicJWK(signingKeyPair),
      },
      {
        "id": `${did}#encrypting-keys-1`,
        "type": "JsonWebKey2020",
        "controller": did,
        "publicKeyJwk": await keyPairToPublicJWK(encryptingKeyPair),
      },
    ],
    "authentication": [
      {
        "type": "Ed25519SignatureAuthentication2018",
        "publicKey": `${did}#keys-1`
      }
    ],
    "service": [
    ]
  }
}