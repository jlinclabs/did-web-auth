import { promisify } from 'util'
import { URL } from 'url'
import Router from 'express-promise-router'

import db from './db.js'
import {
  createNonce,
  keyPairToPublicJWK,
  createJWS,
  verifyJWS,
  createJWE,
  verifyJWE,
  createSignedJWT,
  verifySignedJWT,
} from './crypto.js'
import {
  praseDIDWeb,
  resolveDIDDocument,
  getSigningKeysFromDIDDocument,
  getEncryptionKeysFromDIDDocument,
} from './dids.js'
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
the DID Document route for this http host
*/
routes.get('/.well-known/did.json', async (req, res, next) => {
  // const hostPublicKey = db.getHostPublicKey()
  const { signingKeyPair, encryptingKeyPair, host } = req.app
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
        "id": `${did}#signing-keys-1`,
        "type": "JsonWebKey2020",
        "controller": req.app.did,
        "publicKeyJwk": await keyPairToPublicJWK(signingKeyPair),
      },
      {
        "id": `${did}#encrypting-keys-1`,
        "type": "JsonWebKey2020",
        "controller": req.app.did,
        "publicKeyJwk": await keyPairToPublicJWK(encryptingKeyPair),
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
  /**
   * NORMAL LOGIN
   */
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
    let loginWithDIDWebAuthError
    console.log('attempting DID Web Auth', {
      username: emailUsername,
      host: emailHost,
    })
    try{
      let redirectUrl = await loginWithDIDWebAuth({
        username: emailUsername,
        host: emailHost,
        hostDID: req.app.did,
        hostSigningKeyPair: req.app.signingKeyPair,
        hostEncryptingKeyPair: req.app.encryptingKeyPair,
      })
      redirectUrl = new URL(redirectUrl)
      redirectUrl.searchParams.set('returnTo', `${req.app.origin}/login/from`)
      console.log({ redirectUrl })
      return res.redirect(redirectUrl)
    }catch(error){
      console.error(error)
      loginWithDIDWebAuthError = error
    }
    return renderSigninPage({
      error: (
        `${emailHost} does not appear to support did-web-auth.` +
        ( loginWithDIDWebAuthError ? `\n${loginWithDIDWebAuthError.message}` : '')
      ),
    })
  }


})

/**
 * This function is intended to isolate part of the steps dictated by
 * the DID Web Auth spec.
 */
async function loginWithDIDWebAuth({
  username, host, hostDID, hostSigningKeyPair, hostEncryptingKeyPair
}){
  const userDID = `did:web:${host}:u:${username}`

  const hostDIDDocument = await resolveDIDDocument(hostDID)
  console.log({ hostDIDDocument })
  // TODO validate the host harder

  const userDIDDocument = await resolveDIDDocument(userDID)
  if (!userDIDDocument) {
    throw new Error(`failed to fetch signin did document at ${userDIDDocumentUrl}`)
  }
  console.log({ userDIDDocument })
  // search the userDIDDocument for an auth service endpoint
  const didWebAuthServices = (userDIDDocument.service || [])
    .filter(service =>
      // service.id === '#did-web-auth' // TODO TDB this is more complex
      service.type === "DIDWebAuth"
    )

  if (didWebAuthServices.length === 0){
    throw new Error(`invalid did document for signin at ${userDIDDocumentUrl}. no valid service listed`)
  }
  const didWebAuthService = didWebAuthServices[0] // for now just try the first matching endpoint
  const url = didWebAuthService.serviceEndpoint
  const jws = await createJWS({
    payload: {
      '@context': [
        '/tbd/app-login-request'
      ],
      userDID,
      now: Date.now(),
      requestId: createNonce(),
    },
    signers: [
      hostSigningKeyPair.privateKey
    ]
  })
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      '@context': [
        '/tbd/host-to-host-message'
      ],
      hostDID,
      jws,
    })
  })
  const { jwe } = await response.json()
  const data = await verifyJWE(jwe, hostEncryptingKeyPair.privateKey)
  console.log({ data })
  if (data.redirectTo) return data.redirectTo
  throw new Error('NOT DONE YET')
}

/*
user login request endpoint

This endpoint is used by other apps trying to sign a
user into their app.

The auth destination app sends
a JWS to the auth provider app containing a session
request.

The Auth provider responds with a JWE
containing information on how to the destination app
can continue the sign in process.

The only supported option in this POC is a redirect
url. Much like oauth, the destination app receives a
redirectTo url from the Auth provider and redirects
the user there.

body:
  - hostDID `the sending app's DID`
  - jws `a JSON Web Signature token`
    - payload
      - userDID
      - now
      - requestId
*/
routes.post('/auth/did', async (req, res, next) => {
  const { hostDID, jws } = req.body
  console.log({ hostDID, jws })

  /**
   * here is where apps can optionally white/black list
   * other sites from login requests
   */

  const { host } = praseDIDWeb(hostDID)
  // get the did document of whoever sent this request
  const hostDIDDocument = await resolveDIDDocument(hostDID)
  console.log(JSON.stringify({ hostDIDDocument }, null, 2))
  // extract the signing keys from the did document
  const senderSigningKeys = await getSigningKeysFromDIDDocument(hostDIDDocument)
  const data = await verifyJWS(jws, senderSigningKeys)
  const { userDID, now, requestId } = data
  // TODO check now to see if its too old

  console.log('🔺🔺🔺🔺', { hostDID })
  // TODO check that the useDID actually maps to a user in this app

  const senderEncryptionKeys = await getEncryptionKeysFromDIDDocument(hostDIDDocument)
  console.log({ senderEncryptionKeys })

  const redirectTo = new URL(`${req.app.origin}/login/to/${host}`)
  redirectTo.searchParams.set('userDID', userDID)

  const jwe = await createJWE({
    payload: {
      redirectTo,
      hostDID, // redundant?
      userDID,
      requestId,
    },
    recipients: senderEncryptionKeys,
  })
  console.log({ jwe })
  res.json({ did: req.app.did, jwe })
})

/**
 * login to another app page
 *
 * the user is redirected here to get permission to login
 */
routes.get('/login/to/:host', async (req, res, next) => {
  const { host } = req.params
  const { userDID } = req.query
  const returnTo = req.query.returnTo || `https://${host}`
  // if were not logged in, redirect or reder login form
  // if we are logged in
  //    if userDID does not match current user
  //        show an error?
  if (host.toLowerCase() === req.app.host.toLowerCase()){
    res.status(400).render('pages/error', { message: 'bad request' })
  }
  const didDocument = await resolveDIDDocument(`did:web:${host}`)
  res.render('pages/signInToAnotherApp', {
    app: {
      host,
      didDocument,
      returnTo,
    }
  })
})

routes.post('/login/to/', async (req, res, next) => {
  let { host, accept, returnTo, userDID, duration, durationUnit } = req.body
  const hostDID = `did:web:${host}`
  const didDocument = await resolveDIDDocument(hostDID)
  returnTo = new URL(returnTo || `https://${host}`)

  if (accept === '1') {
    // create a signed JWT as the new issues auth token
    const jwt = await createSignedJWT({
      privateKey: req.app.signingKeyPair.privateKey,
      payload: {
        // claims: 'I make a mean smash burger'
      },
      issuer: req.app.did,
      audience: hostDID,
      subject: userDID,
      expirationTime: `${duration}${durationUnit}`,
    })
    returnTo.searchParams.set('jwt', jwt)
  }else{
    returnTo.searchParams.set('rejected', '1')
  }
  res.redirect(returnTo)
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
  if (!user) return res.status(404).json({
    error: 'not found'
  })
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
    "verificationMethod": [
      {
        "id": `${did}#signing-keys-1`,
        "type": "JsonWebKey2020",
        "controller": req.app.did,
        "publicKeyJwk": await keyPairToPublicJWK(user.signing_jwk),
      },
      {
        "id": `${did}#encrypting-keys-1`,
        "type": "JsonWebKey2020",
        "controller": req.app.did,
        "publicKeyJwk": await keyPairToPublicJWK(user.encrypting_jwk),
      },
    ],
    "authentication": [
      {
        "type": "Ed25519SignatureAuthentication2018",
        "publicKey": `${did}#keys-1`
      }
    ],
    "service": [
      {
        "type": "DIDWebAuth",
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

