import fetch from 'node-fetch'
import { Resolver } from 'did-resolver'
import * as KeyResolver from 'key-did-resolver'
import * as WebResolver from 'web-did-resolver'
import { Ed25519Provider } from 'key-did-provider-ed25519'
import { DID } from 'dids'
import { publicKeyFromBase58, publicKeyFromJWK } from './crypto.js'

const resolver = new Resolver({
  ...KeyResolver.getResolver(),
  ...WebResolver.getResolver(),
})

export function praseDIDWeb(did){
  const matches = did.match(/^did:web:([^:]+)(?::(.*)|$)/)
  if (matches) return {
    host: matches[1],
    path: matches[2],
  }
}
export async function resolveDIDDocument(did){
  console.log('[resolve did]', { did })
  const {
    didDocument,
    didDocumentMetadata,
    didResolutionMetadata,
  } = await resolver.resolve(did)
  console.log('[resolve did]', {
    didDocument,
    didDocumentMetadata,
    didResolutionMetadata,
  })
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