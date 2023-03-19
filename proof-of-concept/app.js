import express from 'express'
import bodyParser from 'body-parser'
import { create } from 'express-handlebars'
import toColor from '@mapbox/to-color'

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
  console.log('APP DID', app.did)

  const cryptoKeyPairs = await db.getOrCreateAppCryptoKeyPairs()
  app.signingKeyPair = cryptoKeyPairs.signingKeyPairs[0]
  app.encryptingKeyPair = cryptoKeyPairs.encryptingKeyPairs[0]
  console.log('APP signing public key', publicKeyToBuffer(app.signingKeyPair.publicKey).toString('base64url'))
  console.log('APP encrypting public key', publicKeyToBuffer(app.encryptingKeyPair.publicKey).toString('base64url'))

  const appColor = new toColor(`${host}:${port}${port}${port}`).getColor().hsl.formatted
  app.locals.app = {
    host: app.host,
    origin: app.origin,
    did: app.did,
    color: appColor
  }

  return new Promise((resolve, reject) => {
    app.server = app.listen(port, error => {
      if (error) reject(error)
      console.log(`Started at -> https://${host} -> http://localhost:${port}`)
      resolve()
    })
  })
}
export default app
