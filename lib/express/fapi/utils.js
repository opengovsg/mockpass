const {
  generateKeyPairSync,
  createPrivateKey,
  createPublicKey,
  randomUUID,
} = require('crypto')
const jose = require('jose')
const { readFileSync } = require('fs')
const path = require('path')

const issuer = 'http://localhost:5156/v3/fapi'

const SupportedScope = {
  OPENID: 'openid',
  UINFIN: 'uinfin',
  USER_IDENTITY: 'user.identity',
}
const SupportedClaims = {
  NONCE: 'nonce',
  AUDIENCE: 'aud',
  ISS: 'iss',
  SUB: 'sub',
  EXP: 'exp',
  IAT: 'iat',
}
const SupportedGrantTypes = {
  AUTHORIZATION_CODE: 'authorization_code',
}
const AllowedAcrValues = [
  'urn:singpass:authentication:loa:1',
  'urn:singpass:authentication:loa:2',
  'urn:singpass:authentication:loa:3',
]
const AllowedAuthenticationContextTypes = ['APP_AUTHENTICATION_DEFAULT']
const AllowedHttpsRedirectTypes = ['app_claimed_https', 'standard_https']
const clientAssertionConfig = {
  CLOCK_SKEW: 60, // 1 minute
  MAX_AGE: 120, //2 minutes
}
const dpopConfiguration = {
  MAX_AGE: 120,
  ALLOWED_DPOP_HEADER_TYP: ['dpop+jwt'],
  ALLOWED_DPOP_HEADER_ALG: ['ES256'],
  DPOP_CLOCK_SKEW: 60,
}

const idTokenConfiguration = {
  TOKEN_EXPIRY: 1800,
}

const fapiOidcConfiguration = {
  issuer,
  pushed_authorization_request_endpoint: `${issuer}/par`,
  authorization_endpoint: `${issuer}/auth`,
  jwks_uri: `${issuer}/.well-known/keys`,
  token_endpoint: `${issuer}/token`,
  response_types_supported: ['code'],
  scopes_supported: Object.values(SupportedScope),
  subject_types_supported: ['public'],
  claims_supported: Object.values(SupportedClaims),
  grant_types_supported: Object.values(SupportedGrantTypes),
  token_endpoint_auth_methods_supported: ['private_key_jwt'],
  token_endpoint_auth_signing_alg_values_supported: ['ES256'],
  id_token_signing_alg_values_supported: ['ES256'],
  id_token_encryption_alg_values_supported: [
    'ECDH-ES+A256KW',
    'ECDH-ES+A192KW',
    'ECDH-ES+A128KW',
  ],
  id_token_encryption_enc_values_supported: ['A256CBC-HS512'],
}
const fapiClientConfiguration = {
  //This is only used for the /generate-tokens call. If used, your POST request must also use the same client_id
  client_id: 'mock-fapi-client-id',

  //If populated, mockpass will fetch from this endpoint. Ensure that enc key and sig key are included
  client_jwks: process.env.FAPI_CLIENT_JWKS_ENDPOINT || null,
}

/**
 * Helper function to generate a DPoP, client assertion token, and return the ephemeral private key.
 */
async function generateDpopAndClientAssertionToken(req) {
  const { publicKey, privateKey } = generateKeys(req.body.ephemeralPrivateKey)
  const dpopToken = await generateDpopToken(req, publicKey, privateKey)
  const clientAssertionToken = await generateClientAssertionToken()
  return {
    ephemeralPrivateKey: privateKey,
    dpopToken,
    clientAssertionToken,
  }
}
function generateKeys(ephemeralPrivateKey) {
  let publicKey, privateKey
  if (ephemeralPrivateKey) {
    //For later part of the FAPI flow, as the ephemeral private key needs to be reused.
    privateKey = ephemeralPrivateKey
    if (typeof privateKey === 'string') {
      privateKey = privateKey.replace(/\\n/g, '\n')
    }
    const keyObject = createPrivateKey({
      key: privateKey,
      format: 'pem',
    })
    publicKey = createPublicKey(keyObject).export({ format: 'jwk' })
  } else {
    //Generate a new key if no private key is provided.
    const keyPair = generateKeyPairSync('ec', {
      namedCurve: 'P-256',
      publicKeyEncoding: { format: 'jwk' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    })
    publicKey = keyPair.publicKey
    privateKey = keyPair.privateKey
  }
  return { publicKey, privateKey }
}
async function generateDpopToken(req, publicKey, privateKey) {
  const dpop = {
    max_age: dpopConfiguration.MAX_AGE,
    header: {
      alg: 'ES256',
      typ: 'dpop+jwt',
      jwk: {
        kty: publicKey.kty,
        crv: publicKey.crv,
        x: publicKey.x,
        y: publicKey.y,
      },
    },
    body: {
      htu: req.body.endpoint,
      htm: 'POST',
      jti: randomUUID(),
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + dpopConfiguration.MAX_AGE,
      nonce: randomUUID(),
    },
  }
  const dpopKey = createPrivateKey({
    key: privateKey,
    format: 'pem',
    type: 'pkcs8',
  })
  return await new jose.SignJWT(dpop.body)
    .setProtectedHeader(dpop.header)
    .sign(dpopKey)
}
async function generateClientAssertionToken() {
  const clientAssertionPrivateKey = JSON.parse(
    readFileSync(
      path.resolve(__dirname, '../../../static/certs/fapi-private.json'),
    ),
  )['keys'].find((key) => key.use === 'sig')
  const clientAssertionPublicKey = JSON.parse(
    readFileSync(
      path.resolve(__dirname, '../../../static/certs/fapi-public.json'),
    ),
  )['keys'].find((key) => key.use === 'sig')
  const clientAssertion = {
    headers: {
      alg: 'ES256',
      kid: clientAssertionPublicKey.kid,
      typ: 'JWT',
    },
    payload: {
      iss: fapiClientConfiguration.client_id,
      sub: fapiClientConfiguration.client_id,
      aud: fapiOidcConfiguration.issuer,
      jti: randomUUID(),
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 120,
    },
  }

  const clientKey = await jose.importJWK(clientAssertionPrivateKey, 'ES256')
  return await new jose.SignJWT(clientAssertion.payload)
    .setProtectedHeader(clientAssertion.headers)
    .sign(clientKey)
}

module.exports = {
  AllowedAcrValues,
  AllowedAuthenticationContextTypes,
  AllowedHttpsRedirectTypes,
  clientAssertionConfig,
  dpopConfiguration,
  fapiOidcConfiguration,
  fapiClientConfiguration,
  generateDpopAndClientAssertionToken,
  idTokenConfiguration,
  SupportedGrantTypes,
  SupportedScope,
}
