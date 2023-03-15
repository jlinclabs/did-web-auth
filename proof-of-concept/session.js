import expressSession from 'express-session'
import KnexSessionStore from 'connect-session-knex'
// const KnexSessionStore = require('connect-session-knex')(session);
import { knex } from './db.js'

const SessionStore = KnexSessionStore(expressSession)
const sessionStore = new SessionStore({
  knex,
  createtable: true,
})
console.log({ sessionStore })

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

export { sessionStore, sessionMiddleware }