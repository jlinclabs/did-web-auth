import { URL } from 'url'
import Router from 'express-promise-router'

import db from './db.js'
import { sessionStore } from './session.js'

const routes = new Router
export default routes

routes.use((req, res, next) => {
  res.locals.host = req.host
  console.log({
    user: req.user,
    // session: req.session,
    // locals: res.locals,
  })
  next()
})

/*
homepage route
*/
routes.get('/.well-knwown/did.json', async (req, res, next) => {
  res.json({
    id: `did:web:${req.host}`,
    services: [
      // {} TODO set the did web service here
    ]
  })
})

/*
homepage route
*/
routes.get('/', async (req, res, next) => {
  res.render('pages/home', {
    email: 'jared@did-auth2.test', //TODO remove me
  })
})

/*
signup route
*/
routes.post('/signup', async (req, res, next) => {
  const { username, password, passwordConfirmation } = req.body
  console.log({ username, password, passwordConfirmation })
  const renderSignupPage = locals => {
    res.render('pages/signup', { username, ...locals })
  }
  if (password !== passwordConfirmation){
    return renderSignupPage({ error: 'passwords do not match' })
  }
  let user
  try{
    user = await db.createUser({ username, password })
  }catch(error){
    return renderSignupPage({ error: `${error}` })
  }
  res.signin({ userId: user.id })
  res.redirect('/')
})

/*
signin route
*/
routes.post('/signin', async (req, res, next) => {
  const { email, password } = req.body

  const [username, host] = email.split('@')
  console.log({ email, password, username, host })

  const renderSigninPage = locals => {
    res.render('pages/signin', {
      email,
      showPasswordField: true,
      ...locals
    })
  }

  // if the email is just a username or the email's host matches this host
  if (!host || host === req.host){ // normal signin to this app
    if (!password) { // if we didn't prompt for a password
      return renderSigninPage() // prompt for password
    }
    const user = await db.authenticateUser(username, password)
    if (user){ // success
      // set http session to logged in as this user
      res.signin({ userId: user.id })
      res.redirect('/')
    }else{
      return renderSigninPage({
        error: 'invalid email or password'
      })
    }
  }

  const redirectUrl = await tryDidWebAuth(username, host)
  if (redirectUrl) return res.redirect(redirectUrl)

  return renderSigninPage({
    error: `${host} does not appear to support did-web-auth`,
  })
})

async function tryDidWebAuth(username, host){
  const hostDid = `did:web:${host}`
  const did = `did:web:${host}:u:${username}`
  const hostDidDocumentUrl = new URL(`https://${host}/.well-knwown/did.json`)
  const didDocumentUrl = new URL(`https://${host}/u/${username}/did.json`)

  const hostDidDocument = await fetchDidDocument(hostDidDocumentUrl)
  if (!hostDidDocument) {
    console.log(`failed to fetch host did document at ${hostDidDocumentUrl}`)
    return
  }

  const didDocument = await fetchDidDocument(didDocumentUrl)
  if (!didDocument) {
    console.log(`failed to fetch signin did document at ${didDocumentUrl}`)
    return
  }
  if (
    !Array.isArray(didDocument.services) ||
    didDocument.id !== did
  ) {
    console.log(`invalid did document for signin at ${didDocumentUrl}`)
    return
  }

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

async function fetchDidDocument(url){
  try{
    const response = await fetch(url, {
      method: 'GET',
      headers: {
        'Accept': 'application/json',
      },
    })
    const data = await response.json()
    return data
  }catch(error){
    console.log(`failed to fetch DID Document from ${url}`)
    console.error(error)
  }
}

/*
signin callback
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
