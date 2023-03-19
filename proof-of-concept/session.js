import Router from 'express-promise-router'
import expressSession from 'express-session'
import KnexSessionStore from 'connect-session-knex'
import db, { knex } from './db.js'
import app from './app.js'

const SessionStore = KnexSessionStore(expressSession)
const sessionStore = new SessionStore({
  knex,
  createtable: true,
})

const sessionMiddleware = expressSession({
  name: 'SESSION',
  secret: `${process.env.HOST}:${process.env.PORT}`.toString('hex'),
  resave: true,
  saveUninitialized: true,
  // trustProxy: process.env.NODE_ENV === 'production',
  trustProxy: true,
  cookie: {
    sameSite: false,
    maxAge: 7 * 24 * 60 * 60 * 1000, // ms
    secure: false, // true unless behind reverse proxy
    httpOnly: true,
  },
  store: sessionStore,
})

const sessionRoutes = new Router
sessionRoutes.use(sessionMiddleware)

sessionRoutes.use(async (req, res, next) => {
  res.locals.requestURL = req.url
  req.userId = req.session.userId
  req.user = req.userId
    ? await db.getUserById(req.userId)
    : undefined
  res.locals.userId = req.userId
  res.locals.user = req.user
  if (req.user) {
    res.locals.userIsLocal = req.user.authentication_host === req.app.host
    res.locals.userIsRemote = !res.locals.userIsLocal
  }

  req.login = async (userId) => {
    await new Promise((resolve, reject) => {
      req.session.userId = userId
      req.session.save((error) => {
        if (error) reject(error); else resolve()
      })
    })
  }
  req.logout = async () => {
    await new Promise((resolve, reject) => {
      req.session.destroy((error) => {
        if (error) reject(error); else resolve()
      })
    })
  }
  next()
})


export { sessionStore, sessionRoutes }