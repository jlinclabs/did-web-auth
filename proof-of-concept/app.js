import express from 'express'
import bodyParser from 'body-parser'
import { create } from 'express-handlebars'
import toColor from '@mapbox/to-color'

import { generateSigningKeyPair, generateEncryptingKeyPair } from './crypto.js'
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
    usernameToEmail: username => {
      if (username.includes('@')) return username
      return `${username}@${app.get('host')}`.trim()
    }
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
  const appColor = new toColor(`${host}`).getColor().hsl.formatted
  app.set('appColor', appColor)
  app.locals.host = host
  app.locals.port = port
  app.locals.appColor = appColor
  app.host = host
  app.origin = `https://${host}`
  // TODO persist these keypair in the DB
  app.signingKeyPair = await generateSigningKeyPair()
  app.encryptingKeyPair = await generateEncryptingKeyPair()
  app.did = `did:web:${host}`
  return new Promise((resolve, reject) => {
    app.server = app.listen(port, error => {
      if (error) reject(error)
      console.log(`Started at -> https://${host} -> http://localhost:${port}`)
      resolve()
    })
  })
}
export default app
