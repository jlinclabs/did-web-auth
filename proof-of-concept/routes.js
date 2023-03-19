import { promisify } from 'util'
import { URL } from 'url'
import Router from 'express-promise-router'

import db from './db.js'
import {
  createNonce,
  keyPairToPublicJWK,
  createJWS,
  verifyJWS,
  createSignedJWT,
  verifySignedJWT,
} from './crypto.js'
import {
  praseDIDWeb,
  resolveDIDDocument,
  getSigningKeysFromDIDDocument,
} from './dids.js'


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

/**
 * the DID Document route
 *
 * This route is required but all parties
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


/**
 * homepage route
 */
routes.get('/', async (req, res, next) => {
  res.render('pages/home', {
    email: 'jared@did-auth2.test', //TODO remove me
  })
})

/*
 * signup route
 */
routes.post('/signup', async (req, res, next) => {
  const {
    username,
    password,
    passwordConfirmation,
    name,
    avatarURL,
    bio,
  } = req.body
  const renderSignupPage = locals => {
    res.render('pages/signup', { username, ...locals })
  }
  if (password !== passwordConfirmation){
    return renderSignupPage({ error: 'passwords do not match' })
  }
  let user
  try{
    user = await db.createUser({
      username,
      password,
      did: `did:web:${req.app.host}:u:${username}`,
      profile: {
        name,
        avatarURL,
        bio,
      },
    })
  }catch(error){
    console.log({ error })
    return renderSignupPage({
      error: `${error}`,
      username,
      name,
      avatarURL,
    })
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
 * signin route
 *
 * All apps need a signin route, this routes serves
 * as both the classic username + password and the
 * new DID Web Auth endpoint.
 */
routes.post('/signin', async (req, res, next) => {
  let { username, password, email, returnTo = '/' } = req.body
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
    res.render('pages/signin', { email, returnTo, ...locals })
  }
  /**
   * NORMAL LOGIN
   */
  if (username && password){
    const user = await db.authenticateUser({username, password})
    if (user){ // success
      await req.login(user.id)
      return res.render('redirect', { to: returnTo })
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
        ourHostDID: req.app.did,
        ourHostSigningKeyPair: req.app.signingKeyPair,
        ourHostEncryptingKeyPair: req.app.encryptingKeyPair,
        username: emailUsername,
        authProviderHost: emailHost,
      })
      redirectUrl = new URL(redirectUrl)
      /**
       *
       * here is where you can specify the callback url
       **/
      redirectUrl.searchParams.set('returnTo', `${req.app.origin}/login/from/${emailHost}`)
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
 *
 * Code like this might be wrapped in a shared library
 */
async function loginWithDIDWebAuth({
  ourHostDID, ourHostSigningKeyPair, ourHostEncryptingKeyPair,
  username, authProviderHost,
}){
  const authProviderDID = `did:web:${authProviderHost}`
  const userDID = `${authProviderDID}:u:${username}`

  const authProviderDIDDocument = await resolveDIDDocument(authProviderDID)
  // TODO validate the host's DID Document harder
  const authProviderSigningKeys = await getSigningKeysFromDIDDocument(authProviderDIDDocument)
  console.log({ authProviderDIDDocument, authProviderSigningKeys })

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
  const outgoingJWS = await createJWS({
    payload: {
      '@context': [
        '/tbd/app-login-request'
      ],
      userDID,
      now: Date.now(),
      requestId: createNonce(),
    },
    signers: [
      ourHostSigningKeyPair.privateKey
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
      hostDID: ourHostDID,
      jws: outgoingJWS,
    })
  })
  const { jws: incomingJWS } = await response.json()
  const data = await verifyJWS(incomingJWS, authProviderSigningKeys)
  console.log('destination app received response from auth provider', data)
  if (data.redirectTo) return data.redirectTo
  throw new Error('unsupported response from auth provider')
}

/*
user login request endpoint

The is an auth provider endpoint

This endpoint is used by destination apps to sign in
a user into their app.

The auth destination app sends a JWS to the auth
provider app containing a session request.

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
  const {
    hostDID: destinationDID,
    jws: incomingJWS
  } = req.body
  //
  if (!destinationDID){
    res.status(400).json({ error: 'destinationDID is required' })
  }
  if (!incomingJWS){
    res.status(400).json({ error: 'jws is required' })
  }

  /**
   * here is where apps can optionally white/black list
   * other sites from login requests
   */

  const { host: destinationHost } = praseDIDWeb(destinationDID)
  if (req.app.host === destinationHost){
    return res.status(401).json({ error: 'your host cannot be our host' })
  }
  // get the did document of whoever sent this request
  const destinationDIDDocument = await resolveDIDDocument(destinationDID)
  console.log({ destinationDID })

  console.log(JSON.stringify({ destinationDIDDocument }, null, 2))
  // extract the signing keys from the did document
  const senderSigningKeys = await getSigningKeysFromDIDDocument(destinationDIDDocument)
  const data = await verifyJWS(incomingJWS, senderSigningKeys)
  const { userDID, now, requestId } = data
  // TODO check now to see if its too old

  console.log({ destinationDID })
  const userDIDParts = praseDIDWeb(userDID)
  if (req.app.host !== userDIDParts.host){
    return res.status(404).json({ error: 'user not found' })
  }
  const user = await db.getUserByUsername(userDIDParts.username)
  // TODO check that the useDID actually maps to a user in this app

  // const senderEncryptionKeys = await getEncryptionKeysFromDIDDocument(destinationDIDDocument)
  // console.log({ senderEncryptionKeys })

  /**
   * This redirectTo tells the destination app where to redirect
   * the user at the auth provider app to prompt for authorization
   */
  const redirectTo = new URL(`${req.app.origin}/login/to/${destinationHost}`)
  redirectTo.searchParams.set('userDID', userDID)

  /**
   * This JWS…
   */
  const jws = await createJWS({
    payload: {
      redirectTo,
      // hostDID, // redundant?
      userDID,
      requestId,
    },
    signers: [req.app.signingKeyPair.privateKey],
  })
  console.log(
    `auth provider responding to destination app`,
    { did: req.app.did, jws }
  )
  res.json({ did: req.app.did, jws })
})

/**
 * login to another app page route
 *
 * This is an Auth Provider route
 *
 * the user is redirected here to get permission to login
 * to the destination app. This page propts the user to
 * accept or reject the sign in request.
 */
routes.get('/login/to/:host', async (req, res, next) => {
  const { host: destinationHost } = req.params
  // if were trying to login to ourselves
  if (destinationHost.toLowerCase() === req.app.host.toLowerCase()){
    // render an error
    res.status(400).render('pages/error', { message: 'bad request' })
  }
  const { userDID } = req.query
  if (typeof userDID !== 'string' || !userDID) {
    return res.status(400).json({ error: `userDID is required` })
  }
  const returnTo = req.query.returnTo || `https://${host}`

  let didHost, username
  {
    const matches = userDID.match(/^did:web:([^:]+):u:([^:]+)$/)
    if (matches) ([, didHost, username] = matches)
  }

  const user = (didHost === req.app.host)
    ? await db.getUserByUsername(username)
    : undefined

  // if we dont find a matching user
  if (!user) {
    // render an error
    return res.status(400).render('pages/error', {
      title: 'User not found',
      message: `userDID "${userDID}" is not hosted here`
    })
  }

  // if we're logged as a different user
  if (req.userId && req.userId !== user.id){
    // render an error
    // return res.status(400).json({ error: `you are not logged in as "${userDID}". Pleas` })
    return res.status(400).render('pages/error', {
      title: 'ERROR: Wrong user',
      message: (
        `You are trying to login to "${destinationHost}" as @${user.username} but ` +
        `you are currently logged in as @${req.user.username}.\n\n` +
        `If you own @${user.username}, please login and login as them first.`
      )
    })
  }

  res.render('pages/signInToAnotherApp', { destinationHost, returnTo })
})


/**
 * This is the route that the above route's form posts to
 *
 * Then the user accepts or rejects the request to login
 * it posts here
 */
routes.post('/login/to', async (req, res, next) => {
  let { destinationHost, returnTo, accept, duration, durationUnit } = req.body
  const destinationHostDID = `did:web:${destinationHost}`
  const destinationHostDIDDocument = await resolveDIDDocument(destinationHostDID)
  console.log({ destinationHostDIDDocument })
  returnTo = new URL(returnTo || `https://${destinationHost}`)

  const userDID = `did:web:${req.app.host}:u:${req.user.username}`
  console.log({ userDID })

  if (accept) {
    const jwt = await createSignedJWT({
      privateKey: req.app.signingKeyPair.privateKey,
      payload: {
        profileURL: `${req.app.origin}/@${req.user.username}/profile.json`,
        // claims: 'I make a mean smash burger'
        /**
         * I dont know what goes in here yet
         * this is where I left off
         */
      },
      issuer: req.app.did,
      audience: destinationHostDID,
      subject: userDID,
      expirationTime: `${duration}${durationUnit}`,
    })
    returnTo.searchParams.set('jwt', jwt)
  }else{
    returnTo.searchParams.set('rejected', '1')
  }
  console.log(`auth provider redirecting back to destination app ${returnTo}`)
  res.redirect(returnTo)
})


/**
 * complete DID Web Auth sign in
 *
 * this is a destination app routes
 *
 * the JWT from the above route is sent from the auth
 * provider to this route at the destination app
 *
 * the JWT should be signed by the auth provider and
 * contain claims we need to access any auth provider
 * APIs
 */
routes.get('/login/from/:host', async (req, res, next) => {
  const { host } = req.params
  const { jwt } = req.query

  const authProviderDID = `did:web:${host}`
  const authProviderDIDDocument = await resolveDIDDocument(authProviderDID)
  const authProviderSigningKeys = await getSigningKeysFromDIDDocument(authProviderDIDDocument)
  const jwtData = await verifySignedJWT(jwt, authProviderSigningKeys)
  const userDID = jwtData.sub
  /**
   *  we need to make sure that one of the users singing keys
   *  has signed something we gave them before this point
   *
   *  that serves as their authentication
   **/
  const user = await db.findOrCreateRemoteUser({
    did: userDID,
    profileURL: jwtData.profileURL,
  })
  await req.login(user.id)
  res.redirect('/') // TODO pass around a destination url
})


/**
 * user profile as json route
 **/
routes.get('/@:username/profile.json', async (req, res, next) => {
  const { username } = req.params
  const user = await db.getUserByUsername(username)
  if (!user) return res.status(404).json({ error: 'user not found' })
  const profile = {
    '@context': [
      '/tbd/profile/json-ld/schema'
    ],
    name: user.name,
    avatar_url: user.avatar_url,
    bio: user.bio,
  }
  res.json(profile)
})



/**
 * sign out route
 */
routes.post('/signout', async (req, res, next) => {
  await req.logout()
  res.render('redirect', { to: '/' })
})



/*
 * user did document route
 *
 * GET /u/alice/did.json
 *
 * This is an auth provider endpoint
 *
 **/
routes.get('/u/:username/did.json', async (req, res, next) => {
  const { username } = req.params
  console.log({ username })
  const user = await db.getUserByUsername(username)
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
        "publicKeyJwk": await keyPairToPublicJWK(user.signing_key_pair),
      },
      {
        "id": `${did}#encrypting-keys-1`,
        "type": "JsonWebKey2020",
        "controller": req.app.did,
        "publicKeyJwk": await keyPairToPublicJWK(user.encrypting_key_pair),
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



/**
 * update profile route
 */
routes.post('/profile', async (req, res, next) => {
  if (!req.user) return res.status(401).json({ error: 'unauthorized' })
  const { name, avatarURL, bio } = req.body
  await db.updateUserProfile({ userId: req.user.id, name, avatarURL, bio })
  res.render('redirect', { to: '/' })
})








/*
debug route
*/
routes.get('/debug', async (req, res, next) => {
  res.render('pages/debug', {
    debug: {
      users: await db.knex.select('*').from('users'),
      profiles: await db.knex.select('*').from('profiles'),
      sessions: await db.knex.select('*').from('sessions'),
    }
  })
})
