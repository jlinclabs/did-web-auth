import crypto from 'crypto'
import express from 'express'
import bodyParser from 'body-parser'
import { create } from 'express-handlebars'
import toColor from '@mapbox/to-color'
import chroma from 'chroma-js'

import { publicKeyToBuffer } from './crypto.js'
import { didToDidDocumentURL }from './dids.js'
import db from './db.js'
import { sessionRoutes } from './session.js'
import routes from './routes.js'
const app = express()

const hbs = create({
  extname: '.hbs',
  defaultLayout: 'main',
  layoutsDir: './views/layouts/',
  partialsDir: './views/partials/',
  helpers: {
    toJSON: object => JSON.stringify(object, null, 2),
    equals: (a, b) => a === b,
    usernameToEmail: username => {
      if (!username) throw new Error(`username is required`)
      if (username.includes('@')) return username
      return `${username}@${app.get('host')}`.trim()
    },
    didToDidDocumentURL
  }
})

// app.engine('.hbs', engine({extname: '.hbs'}));
app.engine('.hbs', hbs.engine)
app.set('view engine', '.hbs');
app.set('views', './views')

app.use(express.static('./static'))

app.use(express.urlencoded({
  extended: true,
}))

app.use(bodyParser.json())

app.use(sessionRoutes)

app.use(routes)

app.start = async function start(){
  const port = app.get('port')
  const host = app.get('host')

  app.host = host
  app.origin = `https://${host}`
  app.did = `did:web:${host}`

  const cryptoKeyPairs = await db.getOrCreateAppCryptoKeyPairs()
  app.signingKeyPair = cryptoKeyPairs.signingKeyPairs[0]
  app.encryptingKeyPair = cryptoKeyPairs.encryptingKeyPairs[0]

  const colorRand = crypto.createHash('sha256').update(`${host}:${port}${port}${port}`).digest('hex')
  const appColor = new toColor(colorRand).getColor().hsl.formatted

  app.locals.app = {
    host: app.host,
    origin: app.origin,
    did: app.did,
    color: chroma(appColor).hex(),
    colorLight: chroma(appColor).brighten(3).alpha(0.25).hex(),
    colorDark: chroma(appColor).darken(3).alpha(0.4).hex(),
  }
  console.log('APP DID', app.did)
  console.log('APP signing public key', publicKeyToBuffer(app.signingKeyPair.publicKey).toString('base64url'))
  console.log('APP encrypting public key', publicKeyToBuffer(app.encryptingKeyPair.publicKey).toString('base64url'))

  return new Promise((resolve, reject) => {
    app.server = app.listen(port, error => {
      if (error) reject(error)
      console.log(`Started at -> https://${host} -> http://localhost:${port}`)
      resolve()
    })
  })
}
export default app
