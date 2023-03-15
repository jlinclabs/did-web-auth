import express from 'express'
import bodyParser from 'body-parser'
import { create } from 'express-handlebars'

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
      return `${username}@${app.get('host')}`
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
  return new Promise((resolve, reject) => {
    app.server = app.listen(port, error => {
      if (error) reject(error)
      console.log(`Started at -> https://${host} -> http://localhost:${port}`)
      resolve()
    })
  })
}
export default app
