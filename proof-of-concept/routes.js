import Debug from 'debug'
import { URL } from 'url'
import Router from 'express-promise-router'

const debug = Debug('did-web-auth.routes')

import db from './db.js'
import {
  createNonce,
  keyPairToPublicJWK,
  signingKeyPairToDIDKey,
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
import { createVC } from './credentials.js'


const routes = new Router
export default routes

routes.use(async (req, res, next) => {
  debug({
    method: req.method,
    url: req.url,
    query: req.query,
    params: req.params,
    body: req.body,
    // session: req.session,
    userId: req.userId,
    user: req.user,
  })
  next()
})

/**
 * the DID Document route
 *
 * This route is required but all parties
 *
 * docs: https://identity.foundation/.well-known/resources/did-configuration/#did-configuration-uri
 */
routes.get('/.well-known/did-configuration.json', async (req, res, next) => {
  const didWeb = req.app.did
  const didKey = signingKeyPairToDIDKey(req.app.signingKeyPair)
  const issuanceDate = req.app.signingKeyPair.createdAt

  // const verifiableCredential = createVC({
  //   issuerDID: didWeb,
  //   signingKeyPair: req.app.signingKeyPair,
  //   credentialSubject: {
  //     id: `${didWeb}`,
  //     origin: req.app.origin,
  //   }
  // })

  /**
   * NOTE: This is a temporary and invalid placeholder until I can fix a
   * bug in the above code
   */
  const verifiableCredential = {
    "@context": [
      "https://www.w3.org/2018/credentials/v1",
      "https://identity.foundation/.well-known/did-configuration/v1"
    ],
    "issuer": `${didKey}`,
    "issuanceDate": issuanceDate,
    "expirationDate": "2025-12-04T14:08:28-06:00",
    "type": [
      "VerifiableCredential",
      "DomainLinkageCredential"
    ],
    "credentialSubject": {
      "id": `${didWeb}`,
      "origin": req.app.origin,
    },
    "proof": {
      "type": "Ed25519Signature2018",
      "created": issuanceDate,
      "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..D0eDhglCMEjxDV9f_SNxsuU-r3ZB9GR4vaM9TYbyV7yzs1WfdUyYO8rFZdedHbwQafYy8YOpJ1iJlkSmB4JaDQ",
      "proofPurpose": "assertionMethod",
      "verificationMethod": `${didKey}#z6MkoTHsgNNrby8JzCNQ1iRLyW5QQ6R8Xuu6AA8igGrMVPUM`,
    }
  }

  res.json({
    "@context": "https://identity.foundation/.well-known/did-configuration/v1",
    "linked_dids": [
      verifiableCredential,
    ]
  })
})

/**
 * the DID Document route
 *
 * This route is required but all parties
 */
routes.get('/.well-known/did.json', async (req, res, next) => {
  const { signingKeyPair, encryptingKeyPair, host } = req.app

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
    "service": [
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
    debug('signup error', { error })
    return renderSignupPage({
      error: `${error}`,
      username,
      name,
      avatarURL,
    })
  }
  debug('signed up as', { user })
  await req.login(user.id)
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

  let emailUsername, emailHost
  if (email){
    ([emailUsername, emailHost] = email.trim().split('@'))
    // treat the email as a username since were the host
    if (emailHost.toLowerCase() === req.hostname.toLowerCase()){
      username = emailUsername
    }
  }

  const renderSignInPage = locals => {
    res.render('pages/signin', { email, returnTo, ...locals })
  }
  /**
   * NORMAL LOGIN
   */
  if (username && password){
    debug('signin with', { username, password: !!password })
    const user = await db.authenticateUser({username, password})
    if (user){ // success
      await req.login(user.id)
      return res.render('redirect', { to: returnTo })
    }else{
      return renderSignInPage({
        error: 'invalid email or password'
      })
    }
  }

  if (email){
    // you could lookup a user by this email at this point
    let loginWithDIDWebAuthError
    debug('attempting DID Web Auth with', email)
    try{
      let redirectUrl = await loginWithDIDWebAuth({
        clientDID: req.app.did,
        clientSigningKeyPair: req.app.signingKeyPair,
        // clientEncryptingKeyPair: req.app.encryptingKeyPair,
        username: emailUsername,
        authProviderHost: emailHost,
      })
      redirectUrl = new URL(redirectUrl)
      /**
       *
       * here is where you can specify the callback url
       **/
      redirectUrl.searchParams.set('returnTo', `${req.app.origin}/login/from/${emailHost}`)
      debug(`redirecting to login via did-web ${redirectUrl}`)
      return res.redirect(redirectUrl)
    }catch(error){
      console.error(error)
      debug('failed to login via DID Web with', email, 'error', error)
      loginWithDIDWebAuthError = error
    }
    return renderSignInPage({
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
  clientDID, clientSigningKeyPair,
  // clientEncryptingKeyPair,
  username, authProviderHost,
}){
  const authProviderDID = `did:web:${authProviderHost}`
  const userDID = `${authProviderDID}:u:${username}`

  const authProviderDIDDocument = await resolveDIDDocument(authProviderDID)
  // TODO validate the host's DID Document harder
  const authProviderSigningKeys = await getSigningKeysFromDIDDocument(authProviderDIDDocument)

  const userDIDDocument = await resolveDIDDocument(userDID)
  if (!userDIDDocument) {
    throw new Error(`failed to fetch signin did document for "${userDID}"`)
  }
  debug('did document for', { userDID, userDIDDocument })
  // search the userDIDDocument for an DIDWebAuth service endpoint
  const didWebAuthServices = (userDIDDocument.service || [])
    .filter(service => service.type === "DIDWebAuth")

  if (didWebAuthServices.length === 0){
    throw new Error(`no valid service found in did document for ${userDID}`)
  }
  // for now just try the first matching endpoint
  const didWebAuthService = didWebAuthServices[0]
  const url = didWebAuthService.serviceEndpoint

  /**
   * Create and Authentication Request
   */
  const authenticationRequest = await createJWS({
    payload: {
      '@context': [
        '/tbd/app-login-request'
      ],
      userDID,
      now: Date.now(),
      requestId: createNonce(),
    },
    signers: [
      clientSigningKeyPair.privateKey
    ]
  })
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      // '@context': [
      //   '/tbd/host-to-host-message'
      // ],
      clientDID: clientDID,
      authenticationRequest
    })
  })
  // const { authenticationRequest } = await response.json()
  const { authenticationResponse } = await response.json()
  const data = await verifyJWS(authenticationResponse, authProviderSigningKeys)
  debug('client app received response from auth provider', data)
  if (data.redirectTo) return data.redirectTo
  throw new Error('unsupported response from auth provider')
}

/*

did auth endpoint

The is an auth provider endpoint

This endpoint is used by client apps to sign in
a user into their app.

The client app sends a JWS to the auth
provider app containing a session request.

The Auth provider responds with a JWE
containing information on how to the client app
can continue the sign in process.

The only supported option in this POC is a redirect
url. Much like oauth, the client app receives a
redirectTo url from the Auth provider and redirects
the user there.

body:
  - clientDID (the sending app's DID)
  - authenticationRequest (a JSON Web Signature token)
    - payload
      - userDID
      - now
      - requestId
*/
routes.post('/auth/did', async (req, res, next) => {
  const {
    clientDID,
    authenticationRequest,
  } = req.body

  if (!clientDID){
    res.status(400).json({ error: 'clientDID is required' })
  }
  if (!authenticationRequest){
    res.status(400).json({ error: 'jws is required' })
  }

  /**
   * here is where apps can optionally white/black list
   * auth providers by domain
   */

  const { host: clientHost } = praseDIDWeb(clientDID)
  if (req.app.host === clientHost){
    return res.status(401).json({ error: 'your host cannot be our host' })
  }
  // get the did document of whoever sent this request
  const clientDIDDocument = await resolveDIDDocument(clientDID)
  debug('client DIDDocument', clientDID, clientDIDDocument)

  // extract the signing keys from the did document
  const senderSigningKeys = await getSigningKeysFromDIDDocument(clientDIDDocument)
  const data = await verifyJWS(authenticationRequest, senderSigningKeys)
  debug('authenticationRequest data', data)
  const { userDID, /*now,*/ requestId } = data
  const jwsCreatedAt = new Date(data.now)
  // if the signed `now` datetime was < 60 seconds ago
  if (jwsCreatedAt < new Date(Date.now() - (1000 * 60))){
    return res.status(400).json({ error: 'invalid authenticationRequest' })
  }
  // TODO check now to see if its too old


  /**
   * ensure the user exists and we are its auth provider
   */
  const userDIDParts = praseDIDWeb(userDID)
  // if the hosts doesn't match us: 404
  if (req.app.host !== userDIDParts.host){
    return res.status(404).json({ error: 'user not found' })
  }
  const user = await db.getUserByUsername(userDIDParts.username)
  if (!user){ // if the user record doesn't exist: 404
    return res.status(404).json({ error: 'user not found' })
  }

  /**
   * This redirectTo tells the client app where to redirect
   * the user at the auth provider app to prompt for authorization
   */
  const redirectTo = new URL(`${req.app.origin}/login/to/${clientHost}`)
  redirectTo.searchParams.set('userDID', userDID)

  /**
   * This JWS…
   */
  const payload = {
    redirectTo: redirectTo.toString(),
    userDID,
    requestId,
    // TODO add a JWS of the requestId signed by a signing key in the users did
    // signature: jws
  }
  const authenticationResponse = await createJWS({
    payload,
    signers: [req.app.signingKeyPair.privateKey],
  })
  debug(`auth provider responding to client app`, { authenticationResponse: payload })
  console.log({ authenticationResponse })
  res.json({ authenticationResponse })
})

/**
 * login to another app page route
 *
 * The is an auth provider endpoint
 *
 * the user is redirected here to get permission to login
 * to the client app. This page propts the user to
 * accept or reject the sign in request.
 */
routes.get('/login/to/:host', async (req, res, next) => {
  const { host: clientHost } = req.params
  // if were trying to login to ourselves
  if (clientHost.toLowerCase() === req.app.host.toLowerCase()){
    // render an error
    res.status(400).render('pages/error', { message: 'bad request' })
  }
  const { userDID } = req.query
  if (typeof userDID !== 'string' || !userDID) {
    return res.status(400).json({ error: `userDID is required` })
  }
  const returnTo = req.query.returnTo || `https://${clientHost}/`

  let didHost, username
  {// TODO replace this with the helper methods parseDIDWeb ???
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
        `You are trying to login to "${clientHost}" as @${user.username} but ` +
        `you are currently logged in as @${req.user.username}.\n\n` +
        `If you own @${user.username}, please login and login as them first.`
      )
    })
  }

  res.render('pages/signinToAnotherApp', { clientHost, returnTo })
})


/**
 * receive result of redirecting to auth provider
 *
 * The is an auth provider endpoint
 *
 * This is the route that the above route's form posts to
 *
 * Then the user accepts or rejects the request to login
 * it posts here
 */
routes.post('/login/to', async (req, res, next) => {
  let { clientHost, returnTo, accept, duration, durationUnit } = req.body
  const clientHostDID = `did:web:${clientHost}`
  const clientHostDIDDocument = await resolveDIDDocument(clientHostDID)
  debug({ clientHostDID })
  debug({ clientHostDIDDocument })
  returnTo = new URL(returnTo || `https://${clientHost}`)

  if (accept) {
    const authToken = await createSignedJWT({
      privateKey: req.app.signingKeyPair.privateKey,
      payload: {
        profileURL: `${req.app.origin}/@${req.user.username}/profile.json`,

        // maybe add a proof here of the users signing keys signing

        /**
         * NOTE: more data can be shared here
         */
      },
      // TODO add more claims https://www.iana.org/assignments/jwt/jwt.xhtml
      issuer: req.app.did,
      audience: clientHostDID,
      subject: req.user.did,
      expirationTime: `${duration}${durationUnit}`,
    })
    debug('[auth provider] replying with authToken', authToken)
    returnTo.searchParams.set('authToken', authToken)
  }else{
    returnTo.searchParams.set('rejected', '1')
  }
  debug(`[auth provider] redirecting back to client app at ${returnTo}`)
  res.redirect(returnTo)
})


/**
 * Complete DID Web Auth sign in
 *
 * this is a client app route
 *
 * the JWT from the above route is sent from the auth
 * provider to this route at the client app
 *
 * the JWT should be signed by the auth provider and
 * contain claims we need to access any auth provider
 * APIs
 */
routes.get('/login/from/:host', async (req, res, next) => {
  const { host } = req.params
  const { authToken } = req.query

  const authProviderDID = `did:web:${host}`
  const authProviderDIDDocument = await resolveDIDDocument(authProviderDID)
  const authProviderSigningKeys = await getSigningKeysFromDIDDocument(authProviderDIDDocument)
  const authTokenData = await verifySignedJWT(authToken, authProviderSigningKeys)
  debug({ authTokenData })
  const userDID = authTokenData.sub

  // TODO persist auth tokens

  /**
   *  we need to make sure that one of the users singing keys
   *  has signed something we gave them before this point
   *
   *  that serves as their authentication
   **/
  const user = await db.findOrCreateRemoteUser({
    did: userDID,
    profileURL: authTokenData.profileURL,
  })
  await req.login(user.id)
  res.redirect('/') // TODO pass around a client url
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
  const user = await db.getUserByUsername(username)
  if (!user) return res.status(404).json({ error: 'not found' })
  const host = req.hostname
  const origin = `https://${host}`
  const did = user.did
  /**
   * in production this did document should/could have more than
   * just two key pairs.
   */
  res.json({
    "@context": [
      "https://www.w3.org/ns/did/v1",
      "https://schema.org/"
    ],
    "id": did,
    "verificationMethod": [
      /**
      * in production these keys should come from a set of variable site,
      * here were just using the minimum two necessary for this POC
      */
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
      cryptoKeys: await (await db.knex.select('*').from('crypto_keys'))
        .map(x => { x.jwk = JSON.parse(x.jwk); return x }),
      profiles: await db.knex.select('*').from('profiles'),
      sessions: await db.knex.select('*').from('sessions'),
    }
  })
})
