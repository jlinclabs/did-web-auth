import Path from 'path'
import { fileURLToPath } from 'url'
import pumaDev from 'node-puma-dev'
import fetch from 'node-fetch'
import { spawn } from 'child-process-promise'

const appRoot = Path.resolve(fileURLToPath(import.meta.url), '../../')



export async function startAppInstance(t){
  const app = {}

  const cp = await spawn(
    './scripts/start.js',
    [],
    {
      cwd: appRoot,
      PORT: port,
      HOST: host,
    }
  )

  // t.teardown(() => { })
  console.log({ cp })
}

// TODO convert these to take `t` and use assertions
export function isSamePublicKeyObject(a, b){
  if (!(a instanceof PublicKeyObject)) throw new Error(`first argument is not an instance of PublicKeyObject`)
  if (!(b instanceof PublicKeyObject)) throw new Error(`second argument is not an instance of PublicKeyObject`)
  if (a === b) return true
  a = a.export({ type: 'spki', format: 'der' })
  b = b.export({ type: 'spki', format: 'der' })
  return a.equals(b)
}

export function isSamePrivateKeyObject(a, b){
  if (!(a instanceof PrivateKeyObject)) throw new Error(`first argument is not an instance of PrivateKeyObject`)
  if (!(b instanceof PrivateKeyObject)) throw new Error(`second argument is not an instance of PrivateKeyObject`)
  if (a === b) return true
  a = a.export({ type: 'pkcs8', format: 'der' })
  b = b.export({ type: 'pkcs8', format: 'der' })
  return a.equals(b)
}