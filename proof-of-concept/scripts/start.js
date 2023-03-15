#!/usr/bin/env node

import yargs from 'yargs'
import { hideBin } from 'yargs/helpers'
import app from '../app.js'

const argv = yargs(hideBin(process.argv))
  .usage('Usage: $0 --port 3001 --host app.test')
  .demandOption(['port','host'])
  .argv

app
  .set('port', argv.port)
  .set('host', argv.host)
  .start()
  .catch(error => {
    console.error(error)
    process.exit(1)
  })
