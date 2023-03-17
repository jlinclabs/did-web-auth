import fetch from 'node-fetch'
import { Resolver } from 'did-resolver'
import * as KeyResolver from 'key-did-resolver'
import * as WebResolver from 'web-did-resolver'
import { Ed25519Provider } from 'key-did-provider-ed25519'
import { DID } from 'dids'
import { publicKeyFromBase58 } from './crypto.js'

const resolver = new Resolver({
  ...KeyResolver.getResolver(),
  ...WebResolver.getResolver(),
})

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
  return
}

export async function getSigningKeysFromDIDDocument(didDocument){
  const signingPublicKeys = []
  (didDocument.verificationMethod || []).forEach(method => {
    const { type, publicKeyBase58 } = method
    if (!publicKeyBase58 || type !== 'Ed25519VerificationKey2018') return
    signingPublicKeys.push(publicKeyFromBase58(publicKeyBase58))

    // "type": "Ed25519VerificationKey2018",
    // "publicKeyBase58": "4jYU6LsU6JfUj3sPy6ZYtnNMX8wG6Ngtxj6T1R6T9s9"
  })
  return signingPublicKeys
}