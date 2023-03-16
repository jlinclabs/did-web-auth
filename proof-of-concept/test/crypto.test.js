import test from 'brittle'
import {
  generateSigningKeyPair,
  keyBufferToString,
  keyToBuffer,
  createJWS,
} from '../crypto.js'

test('generate keys from seed', async t => {
  t.alike(
    await generateSigningKeyPair('seed one'),
    {
      publicKey: 'zCLsjCYk9yYQgTMwt1eQnP8YnN7j5yC6djk73to1hLyv9',
      privateKey: 'z2LoBGoron1HUu7JVVPdufMZ14ycKzUgm1ZQLbTiVYRxXQcAVxSSFp7Y9vFqDc869ps53GzPyMXSFqPY8HRBUdjXX',
    }
  )
  t.alike(
    await generateSigningKeyPair('seed two'),
    {
      publicKey: 'z56NkB1NtdVvq4CiCSNz46EZH23nMuRjZJy7Y8L8M4mTE',
      privateKey: 'z4jr374ChpDMhgiAMPGeBNDf6ntYJY6eaWyqDRCDf6RMLLzsKrYw21SJRA6SgaTdzjVKEmBy3XnW7SHd21YH8rXBe',
    }
  )
  t.unlike(
    await generateSigningKeyPair(),
    {
      publicKey: 'z56NkB1NtdVvq4CiCSNz46EZH23nMuRjZJy7Y8L8M4mTE',
      privateKey: 'z4jr374ChpDMhgiAMPGeBNDf6ntYJY6eaWyqDRCDf6RMLLzsKrYw21SJRA6SgaTdzjVKEmBy3XnW7SHd21YH8rXBe',
    }
  )
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
