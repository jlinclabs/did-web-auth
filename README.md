# DID Web Auth

This repo contains the [SPEC](./SPEC.md) and a working [proof-of-concept](./proof-of-concept).


## Proof of concept

```
?? how many example apps do we need ??
we need to consider the set of permutations over the types of login dances

- client passes identifier to auth-provider
  - auth provider can
    A. notify the user directly
      - in this case the client must wait for the user to resolve the login request
      - waiting can be done via a subsequent long-polled request or a separate client callback url?
    B. return a redirect URL for which to redirect the user to request auth
      - in this case the client just redirects the user and doesn't wait in anyway, the client picks up from the return redirection
  - after the response is received you should have a JWT for a session as that user
  - the client app can relate private records to this users DID (one or any form)

?? should we punt on the about A example to simplify? ??


OK! we need to simplify v1 into the simplest happy path, and expand the spec later.
  - dont do the alternate path where the auth provider can notify the user directly, only support redirect for now
  - the first request from the client should specify some set/subset of the resolution methods it support:
    - Set(magic-link, secret-code, http-redirect, callback)

```

one node app that when hosted at multiple domains can
- host dids
- host profiles
- allow login to other instances


### Auth



