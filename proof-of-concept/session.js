import expressSession from 'express-session'
import KnexSessionStore from 'connect-session-knex'
// const KnexSessionStore = require('connect-session-knex')(session);
import { knex } from './db.js'

const sessionStore = new KnexSessionStore(session)({
  knex,
  createtable: true,
})

const sessionMiddleware = expressSession({
  name: 'SESSION',
  secret: process.env.SESSION_SECRET,
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