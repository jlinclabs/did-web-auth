import test from 'brittle'
import {
  generateSigningKeyPair,
  publicKeyToJKW,
  privateKeyToJKW,
  publicKeyFromJKW,
  privateKeyFromJKW,
  keyBufferToString,
  keyToBuffer,
  createJWS,
} from '../crypto.js'

test('generate keys from seed', async t => {
  const kp1 = await generateSigningKeyPair('seed one')
  t.alike(
    publicKeyToJKW(kp1.publicKey),
    {
      crv: 'Ed25519',
      x: 'Odqt3JEB83JgwD1oGzv9lavRV0XxI4231BtzU5X1t4o',
      kty: 'OKP',
    }
  )
  t.alike(
    privateKeyToJKW(kp1.privateKey),
    {
      crv: 'Ed25519',
      d: 'c2VlZCBvbmUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      x: 'Odqt3JEB83JgwD1oGzv9lavRV0XxI4231BtzU5X1t4o',
      kty: 'OKP',
    }
  )
  const kp2 = await generateSigningKeyPair('seed two')
  t.alike(
    publicKeyToJKW(kp2.publicKey),
    {
      crv: 'Ed25519',
      x: '19EcNkJdcqM0_K8qY0nWnzQvkYtB4T7WB0kC4aRUHtE',
      kty: 'OKP',
    }
  )
  t.alike(
    privateKeyToJKW(kp2.privateKey),
    {
      crv: 'Ed25519',
      d: 'c2VlZCB0d28AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      x: '19EcNkJdcqM0_K8qY0nWnzQvkYtB4T7WB0kC4aRUHtE',
      kty: 'OKP',
    }
  )
})

test.solo('serialize keys', async t => {
  const kp = await generateSigningKeyPair()
  t.alike(
    kp.publicKey,
    publicKeyFromJKW(publicKeyToJKW(kp.publicKey))
  )
  t.alike(
    kp.privateKey,
    privateKeyFromJKW(privateKeyToJKW(kp.privateKey))
  )
})

test('JWS', async t => {
  const kp1 = await generateSigningKeyPair('JWS Test KP 1')
  const kp2 = await generateSigningKeyPair('JWS Test KP 2')

  const jws = await createJWS({
    payload: { stuff: true },
    signers: [
      kp1.privateKey,
      kp2.privateKey,
    ]
  })

  t.alike(jws, {
    payload: 'eyJzdHVmZiI6dHJ1ZX0',
    signatures: [
      {
        signature: 'N0N-LQM55FGs6yvBD1lu2efvbM9MgfnC9J0FRfAfjdQukIfcpMehxlPb4cFMzR4Co2b_b_cPCWigu-_IpIDaDA',
        protected: 'eyJhbGciOiJFZERTQSJ9',
      },
      {
        signature: 'f7Oh2onkcNrt_0YDZTSKIOYuwTs4NZcPee2IqPOTE-BmWe2IprmOLWzlzi4t7e2cFotBOcU_Ribgj6olRDnOAQ',
        protected: 'eyJhbGciOiJFZERTQSJ9',
      }
    ],
  })
})

// // test('JWK', async t => {
// //   const kp1 = await generateSigningKeyPair('seed one')
// //   t.alike(
// //     publicKeyToJWK(kp1.publicKey),
// //     {
// //       crv: 'Ed25519',
// //       x: 'ygNF8KvZrkf4r7-NSWdSNjLvZuhTj-G2TDYOVnDfr1s',
// //       kty: 'OKP',
// //     }
// //   )
// //   t.alike(
// //     privateKeyToJWK(kp1.privateKey),
// //     {}
// //   )
// // })
