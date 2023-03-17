import fetch from 'node-fetch'
import { Resolver } from 'did-resolver'
import * as KeyResolver from 'key-did-resolver'
import * as WebResolver from 'web-did-resolver'
import { Ed25519Provider } from 'key-did-provider-ed25519'
import { DID } from 'dids'

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