# The DID Web Authorization Framework

## Status of this document

This is a work in progress

## Abstract

The DID Web Authorization Framework expands upon the [did:web spec][did-web-spec]
enabling cross-domain authentication and the ability to grant and revokable
access to protected HTTP resources to other identities.

[[table of contents here]]


## Introduction

As of 2023 authentication on the web is dominated by OAuth2. One-click-login
buttons are limited to a small set of mega corporations. This is not open
enough. A truly open authentication framework would allow you to host your
identifiers and credentials anywhere you like. And ideally move them at will.

What's wrong with OAuth 2.0? In short [OAuth 2.0][oauth-2-spec]
was never designed to be a decentralized authentication framework. Oauth 2.0
was designed to enable a third-party application to obtain limited access to
an HTTP service on behalf of a user. It later reached massive adoption when
it was used to simplify the signup and login process with one-click-login.

The major limitation with using OAuth2 as a basis for decentralized
authentication is [The NASCAR Problem](https://indieweb.org/NASCAR_problem).
There is only so much room for "sign in with X" brands.

The DID Web Authorization Framework addresses these limitations by introducing
decentralized cooperative protocols that allow any domain to both host and
consume cross-domain identifiers and credentials.

Instead of authenticating in with an email and password, or with a major
centralized brand, users can authenticate using any valid identifier hosted
at any domain.

This specification is designed for use with HTTP ([RFC2616][http-spec]). The
use of The DID Web Authorization Framework over any protocol other than HTTP
is out of scope.

## Specs

This SPEC builds upon and inherits the terminology from the following spec:

- HTTP - https://www.rfc-editor.org/rfc/rfc2616
- SMTP - https://www.rfc-editor.org/rfc/rfc2821
- DID - https://www.w3.org/TR/did-core/
- well-known DIDs - https://identity.foundation/.well-known/resources/did-configuration/
- DID Web - https://w3c-ccg.github.io/did-method-web/
- JWT - https://www.rfc-editor.org/rfc/rfc7519
- Verifiable Credentials Data Model v1.1 -
  https://www.w3.org/TR/vc-data-model/
- Well Known DID Configuration -
  https://identity.foundation/.well-known/resources/did-configuration/


## Notational Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
specification are to be interpreted as described in [RFC2119].

This specification uses the Augmented Backus-Naur Form (ABNF)
notation of [RFC5234].  Additionally, the rule URI-reference is
included from "Uniform Resource Identifier (URI): Generic Syntax"
[RFC3986].

Certain security-related terms are to be understood in the sense
defined in [RFC4949].  These terms include, but are not limited to,
"attack", "authentication", "authorization", "certificate",
"confidentiality", "credential", "encryption", "identity", "sign",
"signature", "trust", "validate", and "verify".

Unless otherwise noted, all the protocol parameter names and values
are case sensitive.


## Terms

### User

The human interacting with a device.

### Auth Provider

An HTTP Web application that:

- hosts users with did:web DIDs
- serves did documents
- exposes the [auth provider endpoints](#auth-provider-endpoints)

### Client App

An HTTP Web applications that wants to allow users to login with an identifier
hosted at a DID Web Auth Provider. The client does not need to be registered
with the Auth Provider to request a JWT. It must expose the
[client app endpoints](#client-app-endpoints)

### Distributed Identifier

A [DID][did-spec] hosted at a single http domain, using the [did:web method]
[did-web-spec], representing an individual human, organization or app. It
can be granted revocable rights via verifiable credentials. It can also have
aliases.

Examples:

| Identifier                  | Format | Resolves to URL                          |
|-----------------------------|--------|------------------------------------------|
| did:web:example.com         | did    | https://example.com/.well-known/did.json |
| did:web:example.com:u:alice | did    | https://example.com/dids/alice/did.json  |
| alice@example.com           | email  | https://example.com/dids/alice/did.json  |

Using an email address format allows for a backward compatability feel when
using a unique identifier to authenticate into applications on the web.

Applications wanting to support authentication via The DID Web Authorization
Framework should detect if a provided email address represents a
decentralized identifier. For example when user provides
`alice@example.com` as their login, the client applications should
assume it could represent `did:web:example.com:dids:alice` and attempt to
communicate with `example.com` as if it was a compliant auth provider.

For more on this see
[Validating Auth Providers](#validating-auth-providers)


### Credential

see [Verifiable Credentials](https://www.w3.org/TR/vc-data-model/)


<!-- /# TERMS -->





## Authentication Flow


### Flow

Roles:
[User](#user),
[Client App](#client-app),
[Auth Provider](#auth-provider)

### Initial Flow

```mermaid
sequenceDiagram
  actor U as User
  participant C as Client App
  participant A as Auth Provider
  Note right of U: 1. user visits new app and submits signup form
  U->>+C: HTTP POST with did email
  Note right of C: 2. check local users table for email
  Note right of C: 3. extract auth provider domain from email
  Note right of C: 4. validate the auth provider
  C-->>+A: request auth provider's did document
  A-->>-C: 
  Note right of C: 5. validate the user did document
  C-->>+A: request user's did document
  A-->>-C: 
  Note right of C: 6. extract the users did-web-auth service endpoint(s)
  Note right of C: 7. POST authentication request
  C-->>+A: request sign in via HTTP POST to DID Auth Endpoint
  Note right of A: 8. validate client app
  A-->>+C: get client app DID Document
  C-->>-A: 
  Note right of A: 9. validate the authentication request
  Note right of A: 10. choose redirect strategy
  A-->>-C: respond with next signing step
  Note right of C: 11. present one of the offered strategies
  C->>-U: present the next step to the user
```


1. User visits a new app and gives them their did in email address form
2. The client app attempts to use the email to login the user
   * if the client app supports email based authentication it should check its local user collection first before attempting did-web-auth
   * Extract the username and hostname from the email
   * Check if the domain looks like a [valid DID Web identifier host](#validating-auth-providers).
   * request the
   * Post a authentication request to the auth provider
3. Extract auth provider domain from email
4. Validate the Auth Provider
5. Validate the user did document
6. Extract the users did-web-auth service endpoint(s)
7. POST authentication request to Auth Provider
8. Validate Client App
9. Validate the authentication request
10. choose redirect strategy
11. present one of the offered strategies


### Authentication Strategy Flows


#### Browser Redirect

*This strategy only possible if user is authenticating to a website in a
browser*

*…continues from [Initial Flow](#initial-flow)*

```mermaid
sequenceDiagram
  actor U as User
  participant C as Client App
  participant A as Auth Provider
  U->>+C: [Initial Flow]
  C->>+A: client request auth from auth provider
  Note right of A: 1. auth provider offered redirect strategy
  A->>-C: provider responds with redirect strategy
  Note right of C: 2. Client App redirects the user
  C->>-U: HTTP redirect
  U->>+A: user is redirected to auth provider via HTTP GET
  Note right of A: 3. validate data in url query params
  Note right of A: 4. validate current user matches login request
  A->>-U: render authentication request approval page
  Note right of U: 5. user approves login request
  U->>+A: user approves login request
  Note right of A: 6. generate a new authentication JWT
  A->>-U: redirects user back to client app with JWT as query param
  U->>+C: user is redirected back to client app
  Note right of C: 7. validate and unpack JWT
  Note right of C: 8. create new local user record
  C->>+U: user is now logged into the client app
```

1. auth provider offered redirect strategy
2. Client App redirects the user
3. Auth Provider validates the data in url query params
4. Auth Provider ensures the current user matches login request
5. User approves login request by using some user interface
6. Auth Provider generates a new authentication JWT in reply to the Client App
7. Client App unpacks and validates the JSON Web Token
8. Client App creates a new user record if needed, stores the JWT and logs in the user

#### Magic Link

*This strategy only possible if the destination app has a public http
endpoint*


*…continues from [Initial Flow](#initial-flow)*

```mermaid
sequenceDiagram
  actor U as User
  participant C as Client App
  participant A as Auth Provider
  U->>+C: [Initial Flow]
  C->>+A: client request auth from auth provider
  Note right of A: 1. chooses magic link strategy
  Note right of A: 2. send user the magic link
  A->>-C: provider responds with magic link strategy
  Note right of C: 3. prompts user to go click the link
  C->>-U: 
  Note right of U: 4. user receives notification from Auth Provider
  U->>+A: User clicks the link from the Auth Provider
  Note right of A: 5. validated the link payload
  Note right of A: 6. creates a new session for the user
  Note right of A: 7. post the new session to the Client App
  A->>+C: 
  Note right of C: 8. create and login the user
  C->>U: reload the page as logged in
  Note right of U: 9. the tab is now logged in
  C->>-A: 
  A->>-U: render success page directing user back to original tab
  Note right of U: 10. the second browser tab shows success
```

1. Auth Provider chooses magic link strategy
2. Auth Provider send user the magic link
3. Client App prompts user to go click the link sent to them by their Auth Provider 
4. User receives notification from Auth Provider
5. Auth Provider validates the payload within the link the user clicked
6. Auth Provider creates a new session for the user
7. Auth Provider HTTP posts the new session to the Client App
8. Client App creates and logs in the user
9. Client App re-renders the original the tab and shows the user as now logged in
10. The second browser tab (from the auth provider login link) now shows success and instructs the user to return to their orignial tab.




#### Secret Code

*This strategy the only strategy available to *

*…continues from [Initial Flow](#initial-flow)*


```mermaid
sequenceDiagram
  actor U as User
  participant C as Client App
  participant A as Auth Provider
  U->>+C: [Initial Flow]
  C-->>+A: request auth from auth provider
  Note right of A: 1. chooses magic code strategy
  Note right of A: 2. creates a new magic code
  A-->>-C: 
  Note right of C: 3. prompts the user for the secret code
  C->>-U: 
  A->>U: Auth provider notifies the user of their login code
  Note right of U: 4. receives the notification with secret code
  Note right of U: 5. enters the secret code
  U->>+C: 
  Note right of C: 6. pass code onto auth provider
  C-->>+A: 
  Note right of A: 7. validate secret code
  Note right of A: 8. create a new session
  A-->>-C: 
  Note right of C: 9. create and login new user
  C->>-U: render page as logged in
```

1. Auth Provider chooses the magic code strategy
2. Auth Provider creates a new one-time magic code and persists it
3. Client App prompts the user for the secret code
4. User receives the notification with secret code
5. User enters the secret code
6. Client App passes the secret code onto the Auth Provider
7. Auth Provider validates the secret code
8. Auth Provider creates a new session and passes it back to the Client App
9. Client App creates a new user, logs them in and renders a success page



## Auth Providers

An auth provider is a web application that meeds the following
specification:

### HTTP Endpoints

Auth providers must respond to the following HTTP endpoints:

| name                                                   | path
|--------------------------------------------------------|-
| [Domain DID Document](#domain-did-document-endpoint)   | `/.well-known/did.json`
| [Domain DID Conf](#domain-did-conf-endpoint)           | `/.well-known/did-configuration.json`
| [User DID Document](#user-did-document-endpoint)       | `/u/:alice/did.json`
| [DID Auth Endpoint](#did-auth-endpoint)       | defined in User DID Document services
| [Sign in Confirmation](#sign-in-confirmation-endpoint) | defined in response from [DID Auth Endpoint](#did-auth-endpoint)


## Client Applications

### HTTP Endpoints

Auth providers must respond to the following HTTP endpoints:

| name                                                   | path
|--------------------------------------------------------|-
| [Domain DID Document](#domain-did-document-endpoint)   | `/.well-known/did.json`
| [Domain DID Conf](#domain-did-conf-endpoint)           | `/.well-known/did-configuration.json`
| [Sign in Completion](#sign-in-completion-endpoint)     | defined by the `returnTo` param sent the Auth Providers [Sign in Confirmation endpoint](#sign-in-confirmation-endpoint)





## Endpoints


### Domain DID Document Endpoint

Must render a valid DID Document in JSON format.

Must comply with the [DID Web SPEC](https://w3c-ccg.github.io/did-method-web/) and contain a proof that this
DID Document owns this domain.

### Domain DID Conf Endpoint

Must comply with the [Well Known DID Configuration SPEC](https://identity.foundation/.well-known/resources/did-configuration/) and contain a verifiable credential
for the claim over this domain.

### User DID Document Endpoint

Must render a valid DID Document in JSON format.

Must comply with the [DID Web SPEC](https://w3c-ccg.github.io/did-method-web/) and contain a proof that this
DID Document owns this domain.

Must contain a an entry in the services sections like this:

```js
{
  "service": [
    {
      "type": "DIDWebAuth",
      "serviceEndpoint": "https://example-auth-provider.com/auth/did"
    }
  ]
}
```

The `serviceEndpoint` must be at the same domain as the DID.
The pathname portion of the `serviceEndpoint` can be any path.


### DID Auth Endpoint

This endpoint can be at any pathname under the same domain as the Auth Provider. Client apps get this endpoint url from the service endpoint in the user's DID Document.

This endpoint is called with HTTP method POST

The post body should be `application/json`

example
```js
{
  "clientDID": "did:web:example-client.com", // Client App's host DID
  "authenticationRequest": { // An Authentication Request JWS
    "signatures": [],
    "payload": "…"
  }
}
```

The Authentication Request JWS should contain

```js
// example
{
  "@context": [ "/tbd/app-login-request" ],
  "userDID": "did:web:example.com:u:alice",
  "now": 1679337797475, // Date.now() / seconds from epoch
  "requestId": "EvgbfZevI5MEL31ZUbtpPw" // a nonce
}
```

Auth providers should resolve and
[verify the Client](#verifying-client-apps)'s well-known DID Document.

The Auth provider should verify the `authenticationRequest` `JWS`
using the signing keys listing in the Client's well-known DID Document.

The `now` value should be use to establish a limited time window where
the `authenticationRequest` is invalidated. This is to prevent old
`authenticationRequest` request from being used. If the
`authenticationRequest` is too old a 401 should be rendered.

*TODO: this should render a JSON response with an ERROR_CODE*

The `userDID` value should be used to find a local user. If a user is
not found a 404 should be rendered.

The response should be content type `application/json` and contain
an `authenticationResponse` JWS.

#### Authentication Response

```js
//example
{
  "authenticationResponse": { // An Authentication Response JWS
    "signatures": [],
    "payload": "…"
  }
}
```

The `authenticationResponse` payload should contain the keys


| property   | description
|------------|---------
| redirectTo | The auth provider's [Sign in Confirmation endpoint](#sign-in-confirmation-endpoint)
| userDID    | the previously provided userDID
| requestId  | the previously provided requestId

The Auth Provider can use any pathname they like but the `redirectTo` URL
must be at the same origin. The url can also include any query params
needed to to ensure the right user is properly identified after redirection.

```js
// Example Authentication Response
{
  "redirectTo": "https://example-auth-provider.com/login/to/example-client.com",
  "userDID": "did:web:example-auth-provider.com:u:alice",
  "requestId": "MRmHXKKVB-wf9kIh3a9Edg",
}
```


The Client App can optionally append a `redirectTo` query param to the
`redirectTo` URL provided by the Auth Provider. The Auth Provider
should use this value to redirect the user back to.


### Sign in Confirmation Endpoint

This is the http endpoint that users are redirect to after requesting
to sign in to a client application.

The pathname for this endpoint can be anything but must be specified
in the [Authentication Response](#authentication-response).

This endpoint is where the auth provider prompts its user to
either `accept` or `reject` the authentication request.

If no user is logged in the Auth Provider app should first request
the user to sign into their Auth Provider account.

**NODE: How Auth Providers authenticate their users is our of scope for this SPEC**

Once the user is logged into the Auth provider should prompt the user
to either `accept` or `reject` the authentication request.

Optionally the user can also be prompted to specify how long until her
permission expires.


If the user chooses `reject` the auth provider should redirect the user
to the client app (via the redirectTo) with the additional query param
`rejected=1`.


If the user chooses `accept` the auth provider should redirect the user
to the client app (via the redirectTo) with the additional query param
`authToken` containing a JWT [Auth Token](#auth-token)




### Sign in Completion Endpoint

This endpoint is required to be a client application.

This endpoint can be at any pathname the client application desires.











## Validating Auth Providers

Client applications should allow authentication via any valid auth provider.
When a client application is given an identifier it should attempt to
communicate with the auth provider over https.

Steps:

1. resolve the auth providers DID according to [the did:web spec](https://w3c-ccg.github.io/did-method-web/#read-resolve)
2. request the auth provider's well known did document (defined in the did:web spec)
3. extract the signing key pairs

https://identity.foundation/.well-known/resources/did-configuration/

```
MOVE ME TO AUTH STEPS SECTION

3. request the user's did document
4. find all matching services of type `DIDWebAuth`
5. Repeat the remaining steps for each matching service, in the order listed in the user's did document.
    1. create an [Authentication Request](#authentication-request)
    2. post it to the auth provider serviceEndpoint url
    3. verify the
```


<!--
TODO: add a link to a set of free tools to help test your domains compliance*
a link to the lighthouse app would go here
-->


## Credentials

### Granting a Credential

TDB…

### Verifying a Credential

Credentials are revokable so verifying applications should request updated
copies before granting access.

























### Encoding

Public keys should always be encoded as strings using
[URL Safe Base64 Encoding](https://www.rfc-editor.org/rfc/rfc4648).

### TLS

Transport Layer Security is considered essential at all times. Using this
protocol over insecure connections is not recommended.


### HTTP Redirections

This specification makes extensive use of HTTP redirections, in which the
client or the authorization server directs the resource owner's user-agent
to another destination.  While the examples in this specification show the
use of the HTTP 302 status code, any other method available via the
user-agent to accomplish this redirection is allowed and is considered to be
an implementation detail.




### Client Registration

Unlike OAuth there is not client registration. Any http domain that complies
with this specification should interoperate with any other.

## DNS Attack Prevention

To protect against
[DNS attacks](https://w3c-ccg.github.io/did-method-web/#dns-security-considerations)
an additional response header containing a signature of the body is required
for all responses that don't return a signed response (like a JWT).

The signature must be from a key present in the current domain did document.










[http-spec]: https://www.rfc-editor.org/rfc/rfc2616
[smtp-spec]: https://www.rfc-editor.org/rfc/rfc821
[did-spec]: https://www.w3.org/TR/did-core/
[did-web-spec]: https://w3c-ccg.github.io/did-method-web/
[oauth-2-spec]: https://www.rfc-editor.org/rfc/rfc6749#section-1.1
[jwt-spec]: https://www.rfc-editor.org/rfc/rfc7519
[vc-data-model]: https://www.w3.org/TR/vc-data-model/
[well-known-did-configuration]: https://identity.foundation/.well-known/resources/did-configuration/
[did-configuration-resource]: https://identity.foundation/. well-known/resources/did-configuration/#DIDConfigurationResource




### TODO

- [ ] define error codes for JSON responses
- [ ] add sequence diagrams for
  - [ ] verifying an Auth Provider
  - [ ] verifying a Client App
- [ ] read and integrate with
  - https://github.com/WebOfTrustInfo/rwot6-santabarbara/blob/master/final-documents/did-auth.md
  - https://github.com/decentralized-identity/did-auth-jose/blob/master/docs/OIDCAuthentication.md#enroll-beta
  - selective disclosure request
    - https://github.com/uport-project/specs/blob/develop/messages/sharereq.md
