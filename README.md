# MockPass

[![Gitpod Ready-to-Code](https://img.shields.io/badge/Gitpod-ready--to--code-blue?logo=gitpod)](https://gitpod.io/#https://github.com/opengovsg/mockpass)

A mock SingPass/CorpPass/MyInfo server for dev purposes

## Quick Start (hosted by Gitpod)

- Click the ready-to-code badge above
- Wait for MockPass to start
- Make port 5156 public
- Open Browser to note the URL hosting MockPass
- Configure your application per local machine quick start, changing
  the localhost:5156 to the Gitpod hostname

## Quick Start (on local machine)

Configure your application to point to the following endpoints:

SingPass:
 - http://localhost:5156/singpass/logininitial - SAML login redirect with optional page
 - http://localhost:5156/singpass/soap - receives SAML artifact and returns assertion
 - http://localhost:5156/singpass/authorize - OIDC login redirect with optional page
 - http://localhost:5156/singpass/token - receives OIDC authorization code and returns id_token

CorpPass:
 - http://localhost:5156/corppass/logininitial
 - http://localhost:5156/corppass/soap
 - http://localhost:5156/corppass/authorize - OIDC login redirect with optional page
 - http://localhost:5156/corppass/token - receives OIDC authorization code and returns id_token

MyInfo:
 - http://localhost:5156/myinfo/{v2,v3}/person-basic (exclusive to government systems)
 - http://localhost:5156/myinfo/{v2,v3}/authorise
 - http://localhost:5156/myinfo/{v2,v3}/token
 - http://localhost:5156/myinfo/{v2,v3}/person

Provide your application with the `spcp*` certs found in `static/certs`
and with application certs at `static/certs/{key.pem|server.crt}`

Alternatively, provide the paths to your app cert as env vars
`SERVICE_PROVIDER_CERT_PATH` and `SERVICE_PROVIDER_PUB_KEY`

```
$ npm install @opengovsg/mockpass

# Some familiarity with SAML Artifact Binding is assumed
# Optional: Configure where MockPass should send SAML artifact to, default endpoint will be `PartnerId` in request query parameter.
$ export SINGPASS_ASSERT_ENDPOINT=http://localhost:5000/singpass/assert
$ export CORPPASS_ASSERT_ENDPOINT=http://localhost:5000/corppass/assert

# All values shown here are defaults
$ export MOCKPASS_PORT=5156
$ export MOCKPASS_NRIC=S8979373D
$ export MOCKPASS_UEN=123456789A

$ export SHOW_LOGIN_PAGE=true # Optional, defaults to `false`

# Disable signing/encryption (Optional, by default `true`)
$ export SIGN_ASSERTION=false
$ export ENCRYPT_ASSERTION=false
$ export SIGN_RESPONSE=false
$ export RESOLVE_ARTIFACT_REQUEST_SIGNED=false

# Encrypt payloads returned by /myinfo/*/{person, person-basic},
# equivalent to MyInfo Auth Level L2 (testing and production)
$ export ENCRYPT_MYINFO=false

# If specified, will verify token provided in Authorization header
# for requests to /myinfo/*/token
$ export SERVICE_PROVIDER_MYINFO_SECRET=<your secret here>

$ npx mockpass
MockPass listening on 5156
```

## Background

There currently is nothing widely available to test an application's integration
with SingPass/CorpPass using a dev machine alone. This is awkward for developers
who then need to connect to the staging servers hosted by SingPass/CorpPass,
which may not always be available (eg, down for maintenance, or no Internet).

MockPass tries to solves this by providing an extremely lightweight implementation
of a SAML 2.0 Identity Provider that returns mock SingPass and CorpPass assertions.
It optionally provides a mock login page that (badly) mimics the SingPass/CorpPass
login experience.

## Contributing

We welcome contributions to code open-sourced by the Government Technology
Agency of Singapore. All contributors will be asked to sign a Contributor
License Agreement (CLA) in order to ensure that everybody is free to use their
contributions.
