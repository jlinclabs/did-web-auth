import * as u8a from 'uint8arrays'
import {
  createVerifiableCredentialJwt,
  createVerifiablePresentationJwt,
} from 'did-jwt-vc'
import { hash } from '@stablelib/sha256'


function sha256(payload) {
  const data = typeof payload === 'string' ? u8a.fromString(payload) : payload;
  return hash(data);
}

function toJose({
  r,
  s,
  recoveryParam
}, recoverable) {
  const jose = new Uint8Array(recoverable ? 65 : 64);
  jose.set(u8a.fromString(r, 'base16'), 0);
  jose.set(u8a.fromString(s, 'base16'), 32);

  if (recoverable) {
    if (typeof recoveryParam === 'undefined') {
      throw new Error('Signer did not return a recoveryParam');
    }

    jose[64] = recoveryParam;
  }

  return bytesToBase64url(jose);
}

export async function createVC({
  issuerDID,
  signingKeyPair,
  credentialSubject,
}){
  const issuer = {
    did: issuerDID,
    async signer(data) {
      try {
        const {
          r,
          s,
          recoveryParam
        } = keyPair.sign(sha256(data));
        return Promise.resolve(toJose({
          r: leftpad(r.toString('hex')),
          s: leftpad(s.toString('hex')),
          recoveryParam
        }, recoverable));
      } catch (e) {
        return Promise.reject(e);
      }
    },
    alg: 'Ed25519'
  }
  const payload = {
    sub: 'did:ethr:0x435df3eda57154cf8cf7926079881f2912f54db4',
    nbf: 1562950282,
    vc: {
      '@context': ['https://www.w3.org/2018/credentials/v1'],
      type: ['VerifiableCredential'],
      credentialSubject
    }
  }
  return await createVerifiableCredentialJwt(payload, issuer)
}