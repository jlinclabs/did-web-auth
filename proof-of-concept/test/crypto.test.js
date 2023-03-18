import test from 'brittle'
import {
  createNonce,
  generateSigningKeyPair,
  generateEncryptingKeyPair,
  keyPairToPrivateJWK,
  keyPairFromJWK,
  isSamePublicKeyObject,
  isSamePrivateKeyObject,
  createJWS,
  verifyJWS,
  createJWE,
  verifyJWE,
  encryptedSignedJWT,
  decryptSignedJWT,
  publicKeyToBase58,
  publicKeyFromBase58,
  createDiffieHellman,
  acceptDiffieHellman,
  finalizeDiffieHellman,
} from '../crypto.js'


test('createNonce', async t => {
  t.is(createNonce(12).length, 17)
  t.is(createNonce(32).length, 44)
  const n1 = createNonce()
  t.is(typeof n1, 'string')
  t.ok(!n1.includes(' '))
})
test('comparing signing keypairs', async t => {
  const skp1 = await generateSigningKeyPair()
  const skp2 = await generateSigningKeyPair()
  t.ok(isSamePublicKeyObject(skp1.publicKey, skp1.publicKey))
  t.ok(isSamePrivateKeyObject(skp1.privateKey, skp1.privateKey))
  t.ok(!isSamePublicKeyObject(skp1.publicKey, skp2.publicKey))
  t.ok(!isSamePrivateKeyObject(skp1.privateKey, skp2.privateKey))
})

test('serializing signing keypair', async t => {
  const skp1 = await generateSigningKeyPair()
  const skp1JWK = await keyPairToPrivateJWK(skp1)
  const skp1Copy = await keyPairFromJWK(JSON.parse(JSON.stringify(skp1JWK)))
  t.ok(isSamePublicKeyObject(skp1.publicKey, skp1Copy.publicKey))
  t.ok(isSamePrivateKeyObject(skp1Copy.privateKey, skp1.privateKey))
  t.ok(isSamePublicKeyObject(skp1.publicKey, publicKeyFromBase58(publicKeyToBase58(skp1.publicKey))))
})

test('JWKs', async t => {

})

test('JWSs', async t => {
  const skp1 = await generateSigningKeyPair()
  const skp2 = await generateSigningKeyPair()
  const jws = await createJWS({
    payload: { panda: 18 },
    signers: [skp1.privateKey]
  })
  const payload = await verifyJWS(jws, skp1.publicKey)
  t.alike(payload, { panda: 18 })
})


test('comparing encrypting keypairs', async t => {
  const skp1 = await generateEncryptingKeyPair()
  const skp2 = await generateEncryptingKeyPair()
  t.ok(isSamePublicKeyObject(skp1.publicKey, skp1.publicKey))
  t.ok(isSamePrivateKeyObject(skp1.privateKey, skp1.privateKey))
  t.ok(!isSamePublicKeyObject(skp1.publicKey, skp2.publicKey))
  t.ok(!isSamePrivateKeyObject(skp1.privateKey, skp2.privateKey))
})

test('serializing encrypting keypair', async t => {
  const ekp1 = await generateEncryptingKeyPair()
  const ekp1JWK = await keyPairToPrivateJWK(ekp1)
  const ekp1Copy = await keyPairFromJWK(
    JSON.parse(JSON.stringify(ekp1JWK))
  )
  t.ok(isSamePublicKeyObject(ekp1.publicKey, ekp1Copy.publicKey))
  t.ok(isSamePrivateKeyObject(ekp1Copy.privateKey, ekp1.privateKey))
  t.ok(isSamePublicKeyObject(ekp1.publicKey, publicKeyFromBase58(publicKeyToBase58(ekp1.publicKey))))
})

test('JWEs', async t => {
  const ekp1 = await generateEncryptingKeyPair()
  const ekp2 = await generateEncryptingKeyPair()

  const jwe1 = await createJWE({
    payload: { dont: 'tell', anyone: 'ok' },
    recipients: [ekp2.publicKey],
  })

  t.alike(
    await verifyJWE(jwe1, ekp2.privateKey),
    { dont: 'tell', anyone: 'ok' }
  )
})


test('Diffie Hellman', async t => {
  /** AS ALICE **/
  const {
    actor: alice,
    publicKey: alicePublicKey,
    message: message1,
  } = createDiffieHellman()
  // Alice sends the message to Bob
  const message1Copy = JSON.parse(JSON.stringify(message1))

  /** AS BOB **/
  const {
    actor: bob,
    publicKey: bobPublicKey,
    secret: bobSecret,
    message: message2,
  } = await acceptDiffieHellman(message1Copy)
  // Bob sends the message to back to Alice
  const message2Copy = JSON.parse(JSON.stringify(message2))

  /** AS ALICE **/
  const aliceSecret = finalizeDiffieHellman(alice, message2Copy)
  t.ok(aliceSecret.equals(bobSecret))
})


test('apps exchanging JWTs using Diffie Hellman', async t => {
  const app1 = {
    did: `did:web:app1.com`,
    encryptingKeyPair: await generateEncryptingKeyPair(),
    signingKeyPair: await generateSigningKeyPair(),
  }
  const app2 = {
    did: `did:web:app2.com`,
    encryptingKeyPair: await generateEncryptingKeyPair(),
    signingKeyPair: await generateSigningKeyPair(),
  }

  app1.diffieHellman = createDiffieHellman()
  const message1 = app1.diffieHellman.message
  // app1 sends their initiating diffie hellman message to app2
  app2.diffieHellman = acceptDiffieHellman(message1)
  const message2 = app2.diffieHellman.message
  // app2 sends their accepting diffie hellman message to back to app1
  app1.diffieHellman.secret = finalizeDiffieHellman(app1.diffieHellman.actor, message2)
  t.ok(app1.diffieHellman.secret.equals(app2.diffieHellman.secret))
  // app1 and app2 now have the same secret
  t.is(
    app1.diffieHellman.secret.toString('base64url'),
    app2.diffieHellman.secret.toString('base64url'),
  )

  // Alice constructs a JWT for BOB
  const jwt = await encryptedSignedJWT({
    signWith: app1.signingKeyPair.privateKey,
    payload: {
      something: 'important',
      also: 'dont forget',
    },
    issuer: app1.did,
    audience: app2.did,
    subject: app2.did+':u:alicia',
    expirationTime: `1h`,
    secret: app1.diffieHellman.secret,
  })

  const jwtPayload = await decryptSignedJWT({
    jwt,
    secret: app2.diffieHellman.secret,
    publicKey: app1.signingKeyPair.publicKey,
    issuer: app1.did,
    audience: app2.did,
  })
  t.alike(
    jwtPayload,
    {
      something: 'important',
      also: 'dont forget',
      iss: 'did:web:app1.com',
      aud: 'did:web:app2.com',
      sub: 'did:web:app2.com:u:alicia',
      iat: jwtPayload.iat,
      exp: jwtPayload.exp,
    }
  )
})

// test.solo('apps exchanging JWTs using public keys', async t => {
//   const app1 = {
//     did: `did:web:app1.com`,
//     encryptingKeyPair: await generateEncryptingKeyPair(),
//     signingKeyPair: await generateSigningKeyPair(),
//   }
//   const app2 = {
//     did: `did:web:app2.com`,
//     encryptingKeyPair: await generateEncryptingKeyPair(),
//     signingKeyPair: await generateSigningKeyPair(),
//   }
//   console.log({ app2 })
//   const jwt = await encryptedSignedJWT({
//     payload: {
//       superSecret: 42,
//       yourPII: { name: 'steve' },
//     },
//     issuer: app1.did,
//     audience: app2.did,
//     subject: app2.did+':u:alicia',
//     expirationTime: `1h`,
//     // secret: app2.encryptingKeyPair.publicKey,
//     publicKey: app2.encryptingKeyPair.publicKey,
//   })
//   console.log({ jwt })

// })

// test('generate signing keys from seed', async t => {
//   // await generateSigningKeyPair()
//   const skp1 = await generateSigningKeyPair('seed one')
//   console.log({ skp1 })
//   t.ok(skp1.publicKey instanceof PublicKeyObject)
//   t.ok(skp1.privateKey instanceof PrivateKeyObject)

//   // t.alike(
//   //   publicKeyToJKW(kp1.publicKey),
//   //   {
//   //     crv: 'Ed25519',
//   //     x: 'Odqt3JEB83JgwD1oGzv9lavRV0XxI4231BtzU5X1t4o',
//   //     kty: 'OKP',
//   //   }
//   // )
//   // t.alike(
//   //   privateKeyToJKW(kp1.privateKey),
//   //   {
//   //     crv: 'Ed25519',
//   //     d: 'c2VlZCBvbmUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
//   //     x: 'Odqt3JEB83JgwD1oGzv9lavRV0XxI4231BtzU5X1t4o',
//   //     kty: 'OKP',
//   //   }
//   // )
// })

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
