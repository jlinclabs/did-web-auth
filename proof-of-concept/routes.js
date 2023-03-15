import { promisify } from 'util'
import { URL } from 'url'
import Router from 'express-promise-router'

import db from './db.js'
// import { sessionStore } from './session.js'

const routes = new Router
export default routes

routes.use(async (req, res, next) => {
  console.log({
    user: req.user,
    session: req.session,
    userId: req.userId,
    user: req.user,
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
    console.log({ error })
    return renderSignupPage({ error: `${error}` })
  }
  console.log({ user })
  await req.login(user.id)
  // req.session.userId = user.id
  // await new Promise((resolve, reject) => {
  //   req.session.save((error) => {
  //     if (error) reject(error); else resolve()
  //   })
  // })
  // console.log('req.session 2', req.session)
  res.render('redirect', { to: '/' })
})

/*
signin route
*/
routes.post('/signin', async (req, res, next) => {
  let { username, password, email } = req.body
  console.log('/signin', { username, password, email })

  let emailUsername, emailHost
  if (email){
    ([emailUsername, emailHost] = email.trim().split('@'))
    // treat the email as a username since were the host
    if (emailHost.toLowerCase() === req.host.toLowerCase()){
      username = emailUsername
      email = undefined
    }
  }

  const renderSigninPage = locals => {
    res.render('pages/signin', {
      email,
      ...locals
    })
  }

  if (username && password){
    const user = await db.authenticateUser({username, password})
    if (user){ // success
      await req.login(user.id)
      return res.render('redirect', { to: '/' })
    }else{
      return renderSigninPage({
        error: 'invalid email or password'
      })
    }
  }
  if (email){
    // you could lookup a user by this email at this point
    const redirectUrl = await tryDidWebAuth(emailUsername, emailHost)
    if (redirectUrl) return res.redirect(redirectUrl)

    return renderSigninPage({
      error: `${emailHost} does not appear to support did-web-auth`,
    })
  }


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

routes.post('/signout', async (req, res, next) => {
  await req.logout()
  res.render('redirect', { to: '/' })
})
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
routes.get('/u/:username/did.json', async (req, res, next) => {
  const { username } = req.params
  console.log({ username })
  const user = await db.getUserByUsername({username})
  if (!user) return res.status(404).json({})
  const did = `did:web:${req.host}:u:${username}`
  // more complex did management would require persisting records
  // and generating this document in a more complex way
  res.json({
    "@context": "",
    "id": did,
    "authentication": [
      {
        "type": "Ed25519SignatureAuthentication2018",
        "publicKey": `${did}#keys-1`
      }
    ],
    "service": [
      {
        "type": "DidWebAuth",
        "serviceEndpoint": `https://${req.host}/auth/did`,
        "username": username,
        "profileUrl": `https://${req.host}/@${username}`,
      }
    ]
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

  // const sessions = new Promise((resolve, reject) => {
  //   sessionStore.all((error, sessions) => {
  //     if (error) return reject(error)
  //     resolve(sessions)
  //   })
  // })

  const sessions = await db.getAllSessions()
  const users = await db.getAllUsers()
  res.render('pages/debug', {
    debug: {
      sessions,
      users,
    }
  })
})
