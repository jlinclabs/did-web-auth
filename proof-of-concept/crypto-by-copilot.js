import ed25519 from '@stablelib/ed25519'
import crypto from 'crypto'
import * as jose from 'jose'

function generateEd25519KeyPair(){
  const {publicKey, secretKey: privateKey} = ed25519.generateKeyPair()
  return {publicKey, privateKey}
}

function convertEd25519KeyPairToX25519({publicKey, privateKey}){
  return {
    publicKey: ed25519.convertPublicKeyToX25519(publicKey), 
    privateKey: ed25519.convertSecretKeyToX25519(privateKey),
  }
}


const skp1 = generateEd25519KeyPair()
skp1.publicJwk = await jose.exportJWK(skp1.publicKey)
skp1.privateJwk = await jose.exportJWK(skp1.privateKey)


console.log({ skp1 })


const ekp1 = convertEd25519KeyPairToX25519(skp1)
ekp1.publicJwk = await jose.exportJWK(ekp1.publicKey)
ekp1.privateJwk = await jose.exportJWK(ekp1.privateKey)

console.log({ ekp1 })
