#!/usr/bin/env node

import yargs from 'yargs'
import { hideBin } from 'yargs/helpers'
import app from '../app.js'

const { host, port } = yargs(hideBin(process.argv))
  .usage('Usage: $0 --port 3001 --host app.test')
  .option('host', {
    alias: 'h',
    type: 'string',
    description: 'host',
    default: process.env.HOST,
  })
  .option('port', {
    alias: 'p',
    type: 'number',
    description: 'port',
    default: process.env.PORT,
  })
  .parse()

const bail = message => {
  console.error(message)
  process.exit(1)
}

if (!host || typeof host !== 'string') bail(`host is required`)
if (!port || typeof port !== 'number') bail(`port is required`)
app
  .set('port', port)
  .set('host', host)
  .start()
  .catch(error => {
    console.error(error)
    process.exit(1)
  })
