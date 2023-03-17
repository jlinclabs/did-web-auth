import test from 'brittle'
import {
  PublicKeyObject, 
  PrivateKeyObject,
  generateSigningKeyPair,
  // generateEncryptingKeyPair,
  // generateEncryptingKeyPairFromSigningKeyPair,
  // publicKeyToJKW,
  // privateKeyToJKW,
  // publicKeyFromJKW,
  // privateKeyFromJKW,
  // privateKeyJwkToPublicKeyJwk,
  // createJWS,
  // verifyJWS,
} from '../crypto.js'

test('generate signing keys from seed', async t => {
  await generateSigningKeyPair()
  const skp1 = await generateSigningKeyPair('seed one')
  console.log({ skp1 })
  t.ok(skp1.publicKey instanceof PublicKeyObject)
  t.ok(skp1.privateKey instanceof PrivateKeyObject)

  // t.alike(
  //   publicKeyToJKW(kp1.publicKey),
  //   {
  //     crv: 'Ed25519',
  //     x: 'Odqt3JEB83JgwD1oGzv9lavRV0XxI4231BtzU5X1t4o',
  //     kty: 'OKP',
  //   }
  // )
  // t.alike(
  //   privateKeyToJKW(kp1.privateKey),
  //   {
  //     crv: 'Ed25519',
  //     d: 'c2VlZCBvbmUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
  //     x: 'Odqt3JEB83JgwD1oGzv9lavRV0XxI4231BtzU5X1t4o',
  //     kty: 'OKP',
  //   }
  // )
})

// test('generate encrypting keys from seed', async t => {
//   const skp1 = await generateSigningKeyPair('encryption test kp1')
//   const ekp1 = await generateEncryptingKeyPairFromSigningKeyPair(skp1)
//   console.log({ skp1, ekp1 })

//   t.alike(
//     publicKeyToJKW(kp1.publicKey),
//     {
//       kty: 'OKP',
//       crv: 'X25519',
//       x: 'fWXL4vmA19dADXAqCH25ZV6etOQ_TZhF2AjZrcOFsgs',
//     }
//   )
//   t.alike(
//     privateKeyToJKW(kp1.privateKey),
//     {
//       kty: 'OKP',
//       crv: 'X25519',
//       // d: 'c2VlZCBvbmUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
//       x: 'fWXL4vmA19dADXAqCH25ZV6etOQ_TZhF2AjZrcOFsgs',
//     }
//   )
// })

// test('serialize keys', async t => {
//   const kp = await generateSigningKeyPair()
//   t.alike(
//     kp.publicKey,
//     publicKeyFromJKW(publicKeyToJKW(kp.publicKey))
//   )
//   t.alike(
//     kp.privateKey,
//     privateKeyFromJKW(privateKeyToJKW(kp.privateKey))
//   )

//   t.alike(
//     kp.publicKey,
//     publicKeyFromJKW(
//       privateKeyJwkToPublicKeyJwk(
//         privateKeyToJKW(kp.privateKey)
//       )
//     )
//   )
// })

// test('JWS', async t => {
//   const kp1 = await generateSigningKeyPair('JWS Test KP 1')
//   const kp2 = await generateSigningKeyPair('JWS Test KP 2')

//   const jws = await createJWS({
//     payload: { stuff: true },
//     signers: [
//       kp1.privateKey,
//       kp2.privateKey,
//     ]
//   })

//   t.alike(jws, {
//     payload: 'eyJzdHVmZiI6dHJ1ZX0',
//     signatures: [
//       {
//         signature: 'N0N-LQM55FGs6yvBD1lu2efvbM9MgfnC9J0FRfAfjdQukIfcpMehxlPb4cFMzR4Co2b_b_cPCWigu-_IpIDaDA',
//         protected: 'eyJhbGciOiJFZERTQSJ9',
//       },
//       {
//         signature: 'f7Oh2onkcNrt_0YDZTSKIOYuwTs4NZcPee2IqPOTE-BmWe2IprmOLWzlzi4t7e2cFotBOcU_Ribgj6olRDnOAQ',
//         protected: 'eyJhbGciOiJFZERTQSJ9',
//       }
//     ],
//   })

//   // TODO verify JWS
//   t.alike(
//     await verifyJWS({ jws, publicKey: kp1.publicKey }),
//     { stuff: true }
//   )
//   t.alike(
//     await verifyJWS({ jws, publicKey: kp2.publicKey }),
//     { stuff: true }
//   )

//   const kp3 = await generateSigningKeyPair()
//   await t.exception(async () => {
//     await verifyJWS({ jws, publicKey: kp3.publicKey })
//   })
// })

// test.skip('JWE', async t => {
//   const kp1 = await generateEncryptingKeyPair('JWE Test KP 1')
//   const kp2 = await generateEncryptingKeyPair('JWE Test KP 2')

//   const jwe = await createJWE({
//     payload: { stuff: true },
//     recipients: [
//       kp1.publicKey,
//       kp2.publicKey,
//     ]
//   })
// })
