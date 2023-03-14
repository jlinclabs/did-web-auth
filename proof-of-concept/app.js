import express from 'express'
import bodyParser from 'body-parser'
import { create } from 'express-handlebars'

import handlebars from './handlebars.js'
import { db, sessionStore } from './db.js'
import routes from './routes.js'
const app = express()

const hbs = create({
  defaultLayout: 'main',
  layoutsDir: './views/layouts/',
  partialsDir: './views/partials/',
  helpers: {
    toJSON: object => JSON.stringify(object, null, 2),
  }
})

app.engine('handlebars', handlebars.engine)
app.set('view engine', 'handlebars')
app.set('views', './views')

app.use(express.static('./static'))

app.use(express.urlencoded({
  extended: true,
}))

app.use(bodyParser.json())

app.use(sessionMiddleware)

app.use(routes)

export default app
