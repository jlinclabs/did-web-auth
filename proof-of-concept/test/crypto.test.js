import test from 'brittle'
import {
  generateSigningKeyPair,
  publicKeyToJKW,
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
      x: '9xHbcUKsllob4fu75FedlPN_FpJeGabXauQfCJo6gDo',
      kty: 'OKP',
    }
  )
  // t.alike(
  //   await generateSigningKeyPair('seed two'),
  //   {
  //     publicKey: 'z56NkB1NtdVvq4CiCSNz46EZH23nMuRjZJy7Y8L8M4mTE',
  //     privateKey: 'z4jr374ChpDMhgiAMPGeBNDf6ntYJY6eaWyqDRCDf6RMLLzsKrYw21SJRA6SgaTdzjVKEmBy3XnW7SHd21YH8rXBe',
  //   }
  // )
  // t.unlike(
  //   await generateSigningKeyPair(),
  //   {
  //     publicKey: 'z56NkB1NtdVvq4CiCSNz46EZH23nMuRjZJy7Y8L8M4mTE',
  //     privateKey: 'z4jr374ChpDMhgiAMPGeBNDf6ntYJY6eaWyqDRCDf6RMLLzsKrYw21SJRA6SgaTdzjVKEmBy3XnW7SHd21YH8rXBe',
  //   }
  // )
})

// test('serialize keys', async t => {
//   const kp = await generateSigningKeyPair()
//   t.is(
//     kp.publicKey,
//     keyBufferToString(keyToBuffer(kp.publicKey))
//   )
//   t.is(
//     kp.privateKey,
//     keyBufferToString(keyToBuffer(kp.privateKey))
//   )
// })

// test('JWS', async t => {
//   const kp1 = await generateSigningKeyPair()
//   const kp2 = await generateSigningKeyPair()
//   const jws = await createJWS({
//     payload: { stuff: true },
//     signers: [
//       kp1.privateKey,
//       kp2.privateKey,
//     ]
//   })

// })

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
