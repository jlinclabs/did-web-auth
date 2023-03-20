# The DID Web Authorization Framework

## TODO

  Update this spec to rename things given new understanding of how did documents
  are used to resolve service endpoints.


  ```
  redo the  `Auth Resolution Methods` part of this spec
  ### Auth Resolution Methods
  #### magic-link
  #### secret-code
  #### http-redirect
  #### callback
  ```


- [ ] define the nessesary routes
- [ ] define error codes for JSON responses









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
- SMPT - https://www.rfc-editor.org/rfc/rfc2821
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





## Auth Providers

An auth provider is a web application that meeds the following
specification:

### HTTP Endpoints

Auth providers must respond to the following HTTP endpoints:

| name                 | path                                           |
|----------------------|------------------------------------------------|
| Domain DID Doc       | /.well-known/did.json                          |
| Domain DID Conf      | /.well-known/did-configuration.json            |
| User DID Document    | /u/:alice/did.json                             |
| DID Auth Endpoint    | [defined in User DID Document services]        |
| Sign in Confirmation | [defined in response from "DID Auth Endpoint"] |


#### Domain DID Doc

Must render a valid DID Document in JSON format.

Must comply with the [DID Web SPEC](https://w3c-ccg.github.io/did-method-web/) and contain a proof that this
DID Document owns this domain.

#### Domain DID Conf

Must comply with the [Well Known DID Configuration SPEC](https://identity.foundation/.well-known/resources/did-configuration/) and contain a verifiable credential
for the claim over this domain.

#### User DID Document

Must render a valid DID Document in JSON format.

Must comply with the [DID Web SPEC](https://w3c-ccg.github.io/did-method-web/) and contain a proof that this
DID Document owns this domain.

Must contain a an entry in the services sections like this:

```json
{
  "type": "DIDWebAuth",
  "serviceEndpoint": "https://example-auth-provider.com/auth/did"
}
```

The `serviceEndpoint` must be at the same domain as the DID.
The pathname portion of the `serviceEndpoint` can be any path.


#### DID Auth Endpoint

This endpoint can be at any path the Auth Provider wants.

This path is give then to clients as the

- method: POST
- path: [defined by the service endpoint in the user's DID Document]

The post body should be `application/json`

```json
// example
{
  "clientDID": "did:web:example-client.com", // Client App's host DID
  "authenticationRequest": { // An Authentication Request JWS
    "signatures": [],
    "payload": "…"
  }
}
```

The Authentication Request JWS should contain

```json
// example
{
  "@context": [ '/tbd/app-login-request' ],
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

##### Authentication Response

```json
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
| redirectTo | The auth provider's "Sign in Confirmation" endpoint
| userDID    | the previously provided userDID
| requestId  | the previously provided requestId

The Auth Provider can use any pathname they like but the `redirectTo` URL
must be at the same origin. The url can also include any query params
needed to to ensure the right user is properly identified after redirection.

```
// Example Authentication Response
{
  "redirectTo": "https://example-auth-provider.com/login/to/example-client.com",
  "userDID": "did:web:example-auth-provider.com:u:alice",
  "requestId": "MRmHXKKVB-wf9kIh3a9Edg",
}
```



#### Sign in Confirmation

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




## Client Applications

### HTTP Endpoints

Auth providers must respond to the following HTTP endpoints:

| name                 | path                                           |
|----------------------|------------------------------------------------|
| Domain DID Doc       | /.well-known/did.json                          |
| Domain DID Conf      | /.well-known/did-configuration.json            |
| Sign in Completion   | [defined by the `returnTo` param send to ]



------


### User DID Document

Must have an entry in the Services



####

### Protocol Endpoints

Any HTTP domain can host [did:web][did-web-spec] [identifiers][did-spec].
Hosting DIDs requires the host to respond to the following endpoints:

- host did document endpoint
- identifier did document endpoint
- authentication endpoint
- message endpoint


#### Host DID Document Endpoint

The host should have its own identifier as a did document in accordance to the
[Well Known DID Configuration](https://identity.foundation/.well-known/resources/did-configuration/) spec.

An HTTPS GET request to `https://${origin}/.well-known/did.json` should
return  valid DID Document including at least one signing keys pair.

*response body signature header required*

https://www.w3.org/TR/did-core/#example-usage-of-the-service-property

```json
{
  "service": [{
    "id":"did:example:123#linked-domain",
    "type": "LinkedDomains",
    "serviceEndpoint": "https://example.com"
  }]
}
```

#### Identifier DID Document Endpoint

GET `https://${origin}/dids/${id}/did.json`

A valid DID Document including at least one signing keys pair.

This DID document can and should include entries in their `"services"` section.


#### Authentication Endpoint

POST `https://${origin}/dids/${id}/auth`

This endpoint takes a one-time authorization grant token and, if valid,
returns a access token. The access token is verifiable
[JSON Web Token][jwt-spec]. Applications should validate this JWT keep it a
secret.


Example post body:

```json
{
  "authToken": "d58c27ba1de705af6a41e54d7bacfdad9f74dee7"
}
```

example response body:

```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.
  eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
}
```

For information on how to obtain an authorization grant token see the
[Authentication Flow](#authentication-flow).





#### Message Endpoint

Optional endpoint to receive message for an identifier

POST `https://${origin}/dids/${id}/inbox`






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




## Authentication Flow

[[see roles]]

### Flow

#### Roles

 - User - a human logging in
 - IdHost - the website that hosts the identifier being used to authenticate
 - App - the website being logged into

```mermaid
sequenceDiagram
  User->>+App: Step 1
  App->>+IdHost: Step 2
  IdHost->>-App: Step 3
  App->>-User: Step 4
```

1. User visits a new app and gives them their did in email address form
2. The app extracts the host from the email and checks if that host is a
   valid DID Web identifier host by getting and validating:
   * host did document from `https://${host}/.well-known/did.json`
   * user did document from `https://${host}/dids/${username}/did.json`
   * *what to do here if the host is invalid is outside the scope of this
     document but a fallback to a more classic form of authentication might
     be appropriate here.*
3. The app uses one of the 4 authentication methods to request a session
   token.
4. Success. The app can now use your session token to gain limited access to
   other api endpoints on your identifier host.

#### Authentication Methods

##### Browser Redirect

*This strategy only possible if user is authenticating to a website in a
browser*

1. The app redirects the user to their identifier host's authentication
   endpoint using query params to define the scopes for the requested session
2. the user is propmpted to confirm the details of the session request
3. the user approves the session and is redirected back to the app



##### Magic Link

*This strategy only possible if the destination app has a public http
endpoint*

1. The app generates a one-time secret login token, embeds it into a url
   and post that to the Authentication endpoint
2. The app then instructs the user to follow the link sent to their identifier
   host


##### Secret Code

*This strategy the only strategy available to *

1. The app generates a one-time secret login token, persists a copy of it,
   embeds it into a callback url and posts that url to the Authentication
   endpoint.
2. The app then instructs the user to follow the link sent to their identifier
   host
3. The user follows the link sent to their identifier host


##### Identifier Host Prompt

*this strategy requires that the identifier host have a UX*

4. The app requests






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







[http-spec]: https://www.rfc-editor.org/rfc/rfc2616
[smtp-spec]: https://www.rfc-editor.org/rfc/rfc821
[did-spec]: https://www.w3.org/TR/did-core/
[did-web-spec]: https://w3c-ccg.github.io/did-method-web/
[oauth-2-spec]: https://www.rfc-editor.org/rfc/rfc6749#section-1.1
[jwt-spec]: https://www.rfc-editor.org/rfc/rfc7519
[vc-data-model]: https://www.w3.org/TR/vc-data-model/
[well-known-did-configuration]: https://identity.foundation/.well-known/resources/did-configuration/
[did-configuration-resource]: https://identity.foundation/. well-known/resources/did-configuration/#DIDConfigurationResource
