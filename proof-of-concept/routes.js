import { URL } from 'url'
import Router from 'express-promise-router'

import db from './db.js'
import { sessionStore } from './session.js'

const routes = new Router
export default routes

routes.use((req, res, next) => {
  console.log({
    user: req.user,
    session: req.session,
    locals: res.locals,
  })
  next()
})

/*
homepage route
*/
routes.get('/.well-knwown/did.json', async (req, res, next) => {
  res.json({
    id: `did:web:${process.env.APP_HOST}`,

  })
})

/*
homepage route
*/
routes.get('/', async (req, res, next) => {
  res.render('pages/home')
})


/*
login route
*/
routes.post('/login', async (req, res, next) => {
  const { email, password } = req.body

  const [username, host] = email.split('@')

  // if the email is just a username or the email's host matches this host
  if (!host || process.env.APP_HOST === host){ // normal login to this app
    if (!password) { // if we didn't prompt for a password
      return res.render('pages/login', { // prompt for password
        email,
        showPasswordField: true
      })
    }
    const user = await db.authenticateUser(username, password)
    if (user){ // success
      // set http session to logged in as this user
      res.login({ userId: user.id })
      res.redirect('/')
    }else{
      return res.render('pages/login', {
        email,
        showPasswordField: true,
        error: 'invalid email or password'
      })
    }
  }

  const redirectUrl = await tryDidWebAuth(username, host)
  if (redirectUrl) return res.redirect(redirectUrl)

  // res.render('pages/login', {
  //   showPasswordField: true,
  // })
})

async function tryDidWebAuth(username, host){
  const hostDid = `did:web:${host}`
  const did = `did:web:${host}:u:${username}`
  const hostDidDocumentUrl = new URL(`https://${host}/.well-knwown/did.json`)
  const didDocumentUrl = new URL(`https://${host}/u/${username}/did.json`)

  const hostDidDocument = await fetch(hostDidDocumentUrl, {
    method: 'GET',
    headers: {
      'Accept': 'application/json',
    },
  }).then(res => res.json())
  if (!hostDidDocument) return

  const didDocument = await fetch(didDocumentUrl, {
    method: 'GET',
    headers: {
      'Accept': 'application/json',
    },
  }).then(res => res.json())
  if (
    !didDocument ||
    !Array.isArray(didDocument.services) ||
    didDocument.id !== did
  ) return

  // search the didDocument for an auth service endpoint
  const didWebAuthServices = didDocument.services.filter(service =>
    service.id === '#did-web-auth' // TODO TDB this is more complex
  )
  for (const didWebAuthService of didWebAuthServices){
    // didWebAuthService
  }

  /* TODO
   * create auth request object encrypted to the didDocument's keys
   * send a JWE and get a JWT
   */

}

/*
login callback
*/
routes.get('/', async (req, res, next) => {

  res.redirect('/')
})



/*
profile
GET /u/alice
*/
routes.get('/u/:identifier/did.json', async (req, res, next) => {
  res.json({

  })
})

/*
profile
GET /u/alice
*/
routes.get('/u/:identifier', async (req, res, next) => {

  res.render('pages/profile')
})








/*
debug route
*/
routes.get('/debug', async (req, res, next) => {
  console.log({ sessionStore })
  // sessionStore.get(sid, fn)
  // sessionStore.set(sid, sessObject, fn)
  // sessionStore.touch(sid, sess, fn)
  // sessionStore.destroy(sid, fn)
  // sessionStore.length(fn)
  // sessionStore.clear(fn)
  // sessionStore.stopDbCleanup()
  // sessionStore.getNextDbCleanup()
  // sessionStore.all(fn)
  const sessions = new Promise((resolve, reject) => {
    sessionStore.all((error, sessions) => {
      if (error) return reject(error)
      resolve(sessions)
    })
  })
  res.render('pages/debug', {
    sessions
  })
})
