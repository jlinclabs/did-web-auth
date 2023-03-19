import fetch from 'node-fetch'
import { Resolver } from 'did-resolver'
import * as KeyResolver from 'key-did-resolver'
import * as WebResolver from 'web-did-resolver'
import { Ed25519Provider } from 'key-did-provider-ed25519'
import { DID } from 'dids'
import { publicKeyFromJWK } from './crypto.js'

const resolver = new Resolver({
  ...KeyResolver.getResolver(),
  ...WebResolver.getResolver(),
})

export function praseDIDWeb(did){
  const matches = did.match(/^did:web:([^:]+)(:u:([^:]+)$|:.*|$)/)
  if (!matches) throw new Error(`invalid did:web "${did}"`)
  const parts = {}
  parts.host = matches[1]
  if (matches[2]) parts.path = matches[2]
  if (matches[3]) parts.username = matches[3]
  return parts
}

export function didToDidDocumentURL(did){
  const [_did, method, host, ...path] = did.split(':')
  if (_did !== 'did' && method !== 'web')
    throw new Error(`unsupported did method "${did}"`)

  const url = `https://${host}/${path.join('/')}/did.json`
  console.log({url})
  return url
}

export async function resolveDIDDocument(did){
  const {
    didDocument,
    didDocumentMetadata,
    didResolutionMetadata,
  } = await resolver.resolve(did)
  if (didResolutionMetadata?.error){
    throw new Error(
      `failed to resolve DID="${did}" ` +
      `${didResolutionMetadata?.error} ` +
      `${didResolutionMetadata?.message}`
    )
  }
  if (didDocument.id !== did) {
    throw new Error(`invalid did document for ${did}. id mismatch.`)
  }
  return didDocument
}

export async function getSigningKeysFromDIDDocument(didDocument){
  const signingPublicKeys = []
  for (const method of (didDocument.verificationMethod || [])){
    if (
      method.type === 'JsonWebKey2020' &&
      method.publicKeyJwk.crv === 'Ed25519'
    ){
      signingPublicKeys.push(publicKeyFromJWK(method.publicKeyJwk))
    }
    // const { type, publicKeyBase58 } = method
    // if (!publicKeyBase58 || type !== 'Ed25519VerificationKey2018') return
    // signingPublicKeys.push(publicKeyFromBase58(publicKeyBase58))
  }
  return signingPublicKeys
}
export async function getEncryptionKeysFromDIDDocument(didDocument){
  const encryptingPublicKeys = []
  for (const method of (didDocument.verificationMethod || [])){
    if (
      method.type === 'JsonWebKey2020' &&
      method.publicKeyJwk.crv === 'X25519'
    ){
      encryptingPublicKeys.push(publicKeyFromJWK(method.publicKeyJwk))
    }
    // const { type, publicKeyBase58 } = method
    // if (publicKeyBase58  type !== 'Ed25519VerificationKey2018') return
    // encryptingPublicKeys.push(publicKeyFromBase58(publicKeyBase58))
  }
  return encryptingPublicKeys
}