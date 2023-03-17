import { promisify } from 'util'
import { URL } from 'url'
import Router from 'express-promise-router'

import db from './db.js'
import { publicKeyToBase58, createJWS, verifyJWS } from './crypto.js'
import { resolveDIDDocument, getSigningKeysFromDIDDocument } from './dids.js'
// import { sessionStore } from './session.js'

const routes = new Router
export default routes

routes.use(async (req, res, next) => {
  console.log('📥', {
    method: req.method,
    url: req.url,
    query: req.query,
    params: req.params,
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
routes.get('/.well-known/did.json', async (req, res, next) => {
  // const hostPublicKey = db.getHostPublicKey()
  const { signingKeyPair, host } = req.app
  // console.log({ signingKeyPair, host })
  const did = `did:web:${host}`
  res.json({
    "@context": [
      "https://www.w3.org/ns/did/v1",
      "https://w3id.org/security/suites/jws-2020/v1"
    ],
    "id": `did:web:${req.hostname}`,
    "verificationMethod": [
      {
        "id": `${did}#keys-1`,
        "type": "Ed25519VerificationKey2018",
        // "controller": `${did}`,
        "controller": `did:web:${host}`,
        // "publicKeyBase58": "Gj7X9iYzY5zkh3qsiwMfzF8hSZ5f67Ft7RGxmvhDfdjC"
        "publicKeyBase58": publicKeyToBase58(signingKeyPair.publicKey),
      }
    ],
    "services": [
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
    if (emailHost.toLowerCase() === req.hostname.toLowerCase()){
      username = emailUsername
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
    let loginWithDidWebAuthError
    console.log('attempting DID Web Auth', {
      username: emailUsername,
      host: emailHost,
    })
    try{
      const redirectUrl = await loginWithDidWebAuth({
        username: emailUsername,
        host: emailHost,
        appDid: req.app.did,
        appSigningKeyPair: req.app.signingKeyPair,
      })
      return res.redirect(redirectUrl)
    }catch(error){
      loginWithDidWebAuthError = error
    }
    return renderSigninPage({
      error: (
        `${emailHost} does not appear to support did-web-auth.` +
        ( loginWithDidWebAuthError ? `\n${loginWithDidWebAuthError.message}` : '')
      ),
    })
  }


})

async function loginWithDidWebAuth({ username, host, appDid, appSigningKeyPair }){
  const hostDid = `did:web:${host}`
  const did = `did:web:${host}:u:${username}`
  const hostDidDocumentUrl = new URL(`https://${host}/.well-knwown/did.json`)
  const didDocumentUrl = new URL(`https://${host}/u/${username}/did.json`)
  console.log({ hostDid, did, hostDidDocumentUrl, didDocumentUrl })
  // const hostDidDocument = await fetchDidDocument(hostDidDocumentUrl)
  // if (!hostDidDocument) {
  //   console.log(`failed to fetch host did document at ${hostDidDocumentUrl}`)
  //   return
  // }

  const didDocument = await fetchDidDocument(didDocumentUrl)
  if (!didDocument) {
    throw new Error(`failed to fetch signin did document at ${didDocumentUrl}`)
  }

  console.log({ didDocument })
  if (didDocument.id !== did) {
    throw new Error(`invalid did document for signin at ${didDocumentUrl}. bad id`)
  }
  // search the didDocument for an auth service endpoint
  const didWebAuthServices = (didDocument.service || [])
    .filter(service =>
      // service.id === '#did-web-auth' // TODO TDB this is more complex
      service.type === "DidWebAuth"
    )

  if (didWebAuthServices.length === 0){
    throw new Error(`invalid did document for signin at ${didDocumentUrl}. no valid service listed`)
  }
  const didWebAuthService = didWebAuthServices[0] // for now just try the first matching endpoint
  const url = didWebAuthService.serviceEndpoint
  const jws = await createJWS({
    payload: {
      did,
      now: Date.now(),
    },
    signers: [
      appSigningKeyPair.privateKey
    ]
  })
  console.log({ jws })
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ did: appDid, jws }),
  })
  const data = await response.json()
  console.log({ response: data })
  /* TODO
   * create auth request object encrypted to the didDocument's keys
   * send a JWE and get a JWT
   */
  throw new Error('NOT DONE YET')
}

/*
signout callback
*/
routes.post('/auth/did', async (req, res, next) => {
  const { did, jws } = req.body
  console.log({ did, jws })

  const { host } = praseDIDWeb(did)
  // get the did document of whoever send this request
  const didDocument = await resolveDIDDocument(did)
  console.log({ didDocument })
  // extract the signing keys from the did document
  const senderSigningKeys = await getSigningKeysFromDIDDocument(didDocument)
  console.log({ senderSigningKeys })
  let data
  for (const senderSigningKey of senderSigningKeys){
    try{
      data = await verifyJWS(jws, senderSigningKey)
      break
    }catch(error){
      console.error('verifyJWS error'. error)
    }
  }
  console.log({ data })
  const { did, now } = data

  // const jwe =
  const jwe = createJWE({
    payload:{
      redirectTo: `${req.app.origin}/login/to/${}`
    }
  })
  res.json({ did: req.app.did, jwe })
})


/*
signout callback
*/
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
  console.log({ user })
  if (!user) return res.status(404).json({})
  const host = req.hostname
  const origin = `https://${host}`
  const did = `did:web:${host}:u:${username}`
  // more complex did management would require persisting records
  // and generating this document in a more complex way
  res.json({
    "@context": [
      "https://www.w3.org/ns/did/v1",
      "https://schema.org/"
    ],
    "id": did,
    "publicKey": [
      {
        "id": `${did}#keys-1`,
        "type": "Ed25519VerificationKey2018",
        // "type": `${user.public_key.crv}VerificationKey2018`,
        // "controller": `${did}`,
        "controller": `did:web:${host}`,
        // "publicKeyBase58": "Gj7X9iYzY5zkh3qsiwMfzF8hSZ5f67Ft7RGxmvhDfdjC"
        "publicKeyBase58": publicKeyToBase58(user.signing_jwk.publicKey),
      }
    ],
    "authentication": [
      {
        "type": "Ed25519SignatureAuthentication2018",
        "publicKey": `${did}#keys-1`
      }
    ],
    "service": [
      {
        "type": "DidWebAuth",
        "serviceEndpoint": `${origin}/auth/did`,
        "username": username,
        "profileUrl": `${origin}/@${username}`,
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



// -- helpers


async function fetchJSON(url, options = {}){
  const response = await fetch(url, {
    ...options,
    headers: {
      'Accept': 'application/json',
      'Content-Type': 'application/json',
      ...options.headers
    },
    body: options.body
      ? JSON.stringify(options.body)
      : undefined,
  })
  return await response.json()
}

async function fetchDidDocument(url){
  try{
    return await fetchJSON(url)
  }catch(error){
    console.log(`failed to fetch DID Document from ${url}`)
    console.error(error)
  }
}

