
import Path from 'path'
import { fileURLToPath } from 'url'
import pumaDev from 'node-puma-dev'
import fetch from 'node-fetch'
import { spawn } from 'child-process-promise'

const appRoot = Path.resolve(fileURLToPath(import.meta.url), '../../')

export async function startAppInstance(t){
  // const app = {}

  // const cp = await spawn(
  //   './scripts/start.js',
  //   [],
  //   {
  //     cwd: appRoot,
  //     PORT: port,
  //     HOST: host,
  //   }
  // )

  // // t.teardown(() => { })
  // console.log({ cp })
}

// TODO convert these to take `t` and use assertions
