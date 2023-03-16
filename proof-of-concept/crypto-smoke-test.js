import crypto from 'crypto'
import nacl from 'tweetnacl'

function generateEncryptionKeys(){
  let { publicKey, secretKey: privateKey } = nacl.sign.keyPair()
  console.log({publicKey, privateKey})
  const publicKeyDer = Buffer.concat([
    Buffer.from('302a300506032b656e032100', 'hex'),
    Buffer.from(publicKey),
  ])
  const privateKeyDer = Buffer.concat([
    Buffer.from('302e020100300506032b656e042204', 'hex'),
    Buffer.from(privateKey),
  ])
  console.log({publicKeyDer, privateKeyDer})
  publicKey = crypto.createPublicKey({
    key: publicKeyDer,
    type: 'spki',
    format: 'der',
  })
  privateKey = crypto.createPrivateKey({
    key: privateKeyDer,
    type: 'pkcs8',
    format: 'der',
  })
  return {publicKey, privateKey}
}


console.log(generateEncryptionKeys())