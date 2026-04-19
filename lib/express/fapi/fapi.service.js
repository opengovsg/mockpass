const assert = require('assert')
const crypto = require('crypto')
const FapiUtils = require('./utils.js')
const { readFileSync } = require('fs')
const path = require('path')
const jose = require('jose')
const { lookUpByAuthCode, generateAuthCodeForFapi } = require('../../auth-code')
const fs = require('fs')
const { buildAssertURL, idGenerator } = require('../oidc/utils')
const { render } = require('mustache')
const ExpiryMap = require('expiry-map')

class FapiService {
  constructor() {
    this.map = new ExpiryMap(5 * 60 * 1000) // PAR request expires in 5 minutes
  }

  async handleParRequest(req) {
    verifyParRequestBody(req)
    const parEndpoint =
      FapiUtils.getFapiOpenIdConfiguration(
        req,
      ).pushed_authorization_request_endpoint
    const [, dpopJkt] = await Promise.all([
      verifyClientAssertion(req),
      verifyDpop(
        req.headers['dpop'],
        // clients can pass either the DPoP header, or POST body dpop_jkt
        req.body['dpop_jkt'] ?? null,
        parEndpoint,
      ),
    ])

    const request_uri = `urn:ietf:params:oauth:request_uri:${crypto
      .randomBytes(64)
      .toString('base64url')}`

    const object = {
      request_uri,
      redirect_uri: req.body.redirect_uri,
      client_id: req.body.client_id,
      code_challenge: req.body.code_challenge,
      code_challenge_method: req.body.code_challenge_method,
      scope: req.body.scope,
      nonce: req.body.nonce,
      state: req.body.state,
      dpopJkt,
    }

    this.map.set(request_uri, object)

    return request_uri
  }

  async handleAuthorizationRequest(req) {
    const authRequest = this.map.get(req.query.request_uri)
    if (!authRequest) throw new Error('No PAR request found in session')
    verifyAuthRequestBody(req, authRequest)
    return authRequest
  }

  async handleTokenRequest(req) {
    const authCodeSession = lookUpByAuthCode(req.body.code, {
      isStateless: false,
    })
    if (!authCodeSession) throw new Error('No auth request found in session')
    const { authRequest } = authCodeSession
    verifyTokenRequestBody(req, authRequest)
    const tokenEndpoint =
      FapiUtils.getFapiOpenIdConfiguration(req).token_endpoint
    await verifyClientAssertion(req)
    await verifyDpop(req.headers['dpop'], authRequest.dpopJkt, tokenEndpoint)
    return await this.generateIdToken(req, authRequest)
  }

  handleCustomProfileAuthorizationRequest(req) {
    const { nric, uuid, request_uri } = req.query
    assert(request_uri, 'Request URI is required')
    assert(nric, 'NRIC is required')
    assert(uuid, 'UUID is required')

    const authRequest = this.map.get(request_uri)
    if (!authRequest) throw new Error('No PAR request found in session')

    const profile = { nric, uuid }
    const authCode = generateAuthCodeForFapi({ profile, authRequest })
    return buildAssertURL(authRequest.redirect_uri, authCode, authRequest.state)
  }

  generateLoginPage(profiles, idp, authRequest) {
    const state = authRequest.state
    const values = profiles.map((profile) => {
      const authCode = generateAuthCodeForFapi({ profile, authRequest })
      const assertURL = buildAssertURL(
        authRequest.redirect_uri,
        authCode,
        state,
      )
      const id = idGenerator[idp](profile)
      return { id, assertURL }
    })
    const LOGIN_TEMPLATE = fs.readFileSync(
      path.resolve(__dirname, '../../../static/html/login-page.html'),
      'utf8',
    )
    // console.debug('values: ', values) //useful when you want to test without a RP system
    return render(LOGIN_TEMPLATE, {
      values,
      customProfileConfig: {
        endpoint: `${FapiUtils.getFapiPath(
          idp.toLowerCase(),
        )}/auth/custom-profile`,
        showUuid: true,
        showUen: idp === 'corpPass',
        requestUri: authRequest.request_uri,
        redirectURI: authRequest.redirect_uri,
        state: authRequest.state,
        nonce: authRequest.nonce,
      },
    })
  }

  async generateIdToken(req, authRequest) {
    //Generate tokens
    const expires_in = FapiUtils.idTokenConfiguration.TOKEN_EXPIRY //30 minutes
    const { profile } = lookUpByAuthCode(req.body.code, { isStateless: false })
    if (!profile) throw new Error('No profile found in session')
    const id_token = {
      sub: profile.uuid,
      sub_attributes: {
        // coi, type, name are all needed by Corppass
        account_type: 'standard',
        identity_number: profile.nric,
        identity_coi: 'SG',
        name: `USER ${profile.nric}`,
      },
      aud: authRequest.client_id,
      acr: 'urn:singpass:authentication:loa:1', //Mockpass only
      sub_type: 'user',
      amr: ['pwd'],
      iss: FapiUtils.getFapiOpenIdConfiguration(req).issuer,
      exp: Math.floor(Date.now() / 1000) + expires_in,
      iat: Date.now() / 1000,
      nonce: authRequest.nonce,
    }

    //Sign Id Token
    const signingKid = FapiUtils.FAPI_ASP_SIGNING_KID
    const fapiPrivateJwks = JSON.parse(
      fs.readFileSync(
        path.resolve(__dirname, FapiUtils.FAPI_ASP_PRIVATE_JWKS_PATH),
      ),
    )
    const fapiSigningPrivateKey = fapiPrivateJwks.keys.find(
      (item) => item.use === 'sig' && item.kid === signingKid,
    )
    if (!fapiSigningPrivateKey)
      throw new Error(`No signing key found for kid "${signingKid}"`)

    const signingKey = await jose.importJWK(fapiSigningPrivateKey, 'ES256')
    const signedProtectedHeader = {
      alg: 'ES256',
      typ: 'JWT',
      kid: signingKid,
    }
    const signedIdToken = await new jose.CompactSign(
      new TextEncoder().encode(JSON.stringify(id_token)),
    )
      .setProtectedHeader(signedProtectedHeader)
      .sign(signingKey)

    //Encrypt signed id token
    let rpEncPublicKey
    if (FapiUtils.fapiClientConfiguration.client_jwks) {
      const jwks = await fetch(
        FapiUtils.fapiClientConfiguration.client_jwks,
      ).then((res) => res.json())
      if (!jwks.keys) throw new Error('Unable to fetch client jwks')
      rpEncPublicKey = jwks.keys.find((key) => key.use === 'enc')
    } else {
      rpEncPublicKey = JSON.parse(
        readFileSync(
          path.resolve(__dirname, FapiUtils.FAPI_RP_PUBLIC_JWKS_PATH),
        ),
      )['keys'].find((key) => key.use === 'enc')
    }
    if (!rpEncPublicKey) throw new Error('No suitable encryption key found')
    const encKey = await jose.importJWK(rpEncPublicKey)
    const encrpytionProtectedHeader = {
      alg: rpEncPublicKey.alg,
      typ: 'JWT',
      kid: rpEncPublicKey.kid,
      enc: 'A256GCM',
      cty: 'JWT',
    }
    const encryptedIdToken = await new jose.CompactEncrypt(
      new TextEncoder().encode(signedIdToken),
    )
      .setProtectedHeader(encrpytionProtectedHeader)
      .encrypt(encKey)

    return {
      access_token: crypto.randomBytes(64).toString('base64url'),
      id_token: encryptedIdToken,
      token_type: 'DPoP',
    }
  }
}

//Verification functions
async function verifyDpop(dpop, dpop_jkt, expectedEndpoint) {
  if (!dpop && !dpop_jkt) throw new Error('Dpop or Dpop jkt is required')
  if (dpop) {
    const dpopToken = dpop.split(' ')[0]
    const [headerB64] = dpopToken.split('.')
    const header = JSON.parse(Buffer.from(headerB64, 'base64').toString())
    const jwk = header.jwk
    if (!jwk) throw new Error('DPoP header missing jwk')
    try {
      const key = await jose.importJWK(jwk, 'ES256')
      await jose.jwtVerify(dpopToken, key, {
        clockTolerance: FapiUtils.dpopConfiguration.DPOP_CLOCK_SKEW,
        requiredClaims: ['jti', 'iat', 'exp', 'htu', 'htm'],
      })
    } catch (error) {
      throw new Error(`Invalid DPoP token signature, ${error.message}`)
    }
    // Extract payload from DPoP token
    const payloadB64 = dpopToken.split('.')[1]
    const payload = JSON.parse(Buffer.from(payloadB64, 'base64').toString())
    const { htu, htm } = payload
    if (htu.toLowerCase() !== expectedEndpoint.toLowerCase()) {
      throw new Error('Invalid DPoP htu')
    }
    if (typeof htm !== 'string' || !htm) {
      throw new Error('DPoP htm must be a non-empty string')
    }
    if (htm.toUpperCase() !== 'POST') {
      throw new Error('Only POST requests are supported with DPoP')
    }
    const jwkThumbprint = crypto
      .createHash('sha256')
      .update(
        JSON.stringify({
          crv: jwk.crv,
          kty: jwk.kty,
          x: jwk.x,
          y: jwk.y,
        }),
      )
      .digest('base64url')
    if (dpop_jkt && dpop_jkt !== jwkThumbprint)
      throw new Error('Invalid DPoP jkt')
    return jwkThumbprint
  }
  // if dpop_jkt was passed in, then we store it for later reference
  return dpop_jkt
}
async function verifyClientAssertion(req) {
  const { client_assertion, client_assertion_type } = req.body
  assert(client_assertion, 'Client assertion is required')
  assert(client_assertion_type, 'Client assertion type is required')
  if (
    client_assertion_type !==
    'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
  )
    throw new Error('Invalid client assertion type')
  let jwks
  if (FapiUtils.fapiClientConfiguration.client_jwks)
    jwks = await fetch(FapiUtils.fapiClientConfiguration.client_jwks).then(
      (res) => res.json(),
    )
  else
    jwks = JSON.parse(
      readFileSync(path.resolve(__dirname, FapiUtils.FAPI_RP_PUBLIC_JWKS_PATH)),
    )
  if (!jwks.keys) throw new Error('Unable to fetch client jwks')

  const [headerB64] = client_assertion.split('.')
  const header = JSON.parse(Buffer.from(headerB64, 'base64').toString())

  const verifyOpts = {
    algorithms: ['ES256'],
    clockTolerance: FapiUtils.dpopConfiguration.DPOP_CLOCK_SKEW,
    requiredClaims: ['iss', 'sub', 'aud', 'exp', 'iat', 'jti'],
  }

  let payload
  if (header.kid) {
    // if a kid is provided in the header, we assert a matching jwk
    const matchingJwk = jwks.keys.find((k) => k.kid === header.kid)
    if (!matchingJwk) throw new Error('No matching key found for kid')
    const key = await jose.importJWK(matchingJwk, 'ES256')
    const result = await jose
      .jwtVerify(client_assertion, key, verifyOpts)
      .catch(() => {
        throw new Error('Invalid client assertion signature')
      })
    payload = result.payload
  } else {
    // if no kid was provided, then we look for a usable key. this is consistent with
    // SP auth implementation/behaviour.
    for (const jwk of jwks.keys) {
      try {
        const key = await jose.importJWK(jwk, 'ES256')
        const result = await jose.jwtVerify(client_assertion, key, verifyOpts)
        payload = result.payload
        break
      } catch {
        /* empty */
      }
    }
    if (!payload) throw new Error('Invalid client assertion signature')
  }

  if (payload.aud !== FapiUtils.getFapiOpenIdConfiguration(req).issuer)
    throw new Error('Invalid client assertion aud')
  return payload.iss
}
function verifyParRequestBody(req) {
  const {
    response_type,
    scope,
    state,
    nonce,
    client_id,
    redirect_uri,
    acr_values,
    code_challenge,
    code_challenge_method,
    authentication_context_type,
    authentication_context_message,
    redirect_uri_https_type,
  } = req.body

  verifyClientInfo(client_id, redirect_uri, redirect_uri_https_type)
  verifyStateAndNonce(state, nonce)
  verifyAllowedScopes(scope)
  verifyAcrValues(acr_values)
  verifyResponseType(response_type)
  verifyCodeChallenge(code_challenge, code_challenge_method)
  verifyAuthenticationContext(
    authentication_context_type,
    authentication_context_message,
  )
}
function verifyAuthRequestBody(req, parRequest) {
  const { client_id, request_uri } = req.query
  if (!client_id) throw new Error('No Client ID in query')
  if (!request_uri) throw new Error('No Request URI in query')
  if (request_uri !== parRequest.request_uri)
    throw new Error('Request URI not found')
  if (client_id !== parRequest.client_id)
    throw new Error('Client ID does not match')
  if (!parRequest.scope.includes('openid'))
    throw new Error('Scope must include openid')
}
function verifyTokenRequestBody(req, authRequest) {
  const { grant_type, code, redirect_uri, code_verifier } = req.body
  assert(
    FapiUtils.SupportedGrantTypes.AUTHORIZATION_CODE.includes(grant_type),
    'Only authorization code grant type is supported',
  )
  assert(code, 'Authorization code is required')
  assert(redirect_uri, 'Redirect URI is required')
  if (redirect_uri !== authRequest.redirect_uri)
    throw new Error('Redirect URI does not match')
  verifyCodeVerifier(code_verifier, authRequest.code_challenge)
}
function verifyClientInfo(clientId, redirect_uri, redirect_uri_https_type) {
  /**
   * Since this is a demo, will not enforce client id and redirect uri must match, but must be provided.
   */
  assert(clientId, 'Client ID is required')
  assert(redirect_uri, 'Redirect URI is required')
  let parsedUri
  try {
    parsedUri = new URL(redirect_uri)
  } catch {
    throw new Error('Invalid redirect uri')
  }
  const { protocol } = parsedUri
  if (protocol !== 'https:' && protocol !== 'http:')
    throw new Error('Invalid redirect uri protocol')
  if (
    redirect_uri_https_type &&
    !FapiUtils.AllowedHttpsRedirectTypes.includes(redirect_uri_https_type)
  )
    throw new Error('Invalid redirect uri https type')
}
function verifyAllowedScopes(scope) {
  assert(scope, 'Scope is required')
  const scopes = scope.split(' ')
  for (const s of scopes) {
    if (!Object.values(FapiUtils.SupportedScope).includes(s))
      throw new Error(`Scope ${s} is not supported`)
  }
}
function verifyStateAndNonce(state, nonce) {
  assert(state, 'State is required')
  if (/^[A-Za-z0-9/+_\-=.]{30,255}$/.test(state) === false)
    throw new Error('Invalid state')
  assert(nonce, 'Nonce is required')
  if (/^[A-Za-z0-9/+_\-=.]{30,255}$/.test(nonce) === false)
    throw new Error('Invalid nonce')
}
function verifyResponseType(responseType) {
  assert(responseType, 'Response type is required')
  if (!Object.values(FapiUtils.SupportedResponseTypes).includes(responseType))
    throw new Error('Invalid response type')
}
function verifyAcrValues(acrValue) {
  //Optional parameter
  if (!acrValue) return
  if (!FapiUtils.AllowedAcrValues.includes(acrValue)) {
    throw new Error('Invalid acr values')
  }
}
function verifyCodeChallenge(codeChallenge, codeChallengeMethod) {
  assert(codeChallenge, 'Code challenge is required')
  if (codeChallengeMethod !== 'S256')
    throw new Error('Invalid code challenge method')
  assert(codeChallenge, 'Code challenge is required')
  if (!/^[A-Za-z0-9\-_]{43,128}$/.test(codeChallenge))
    throw new Error(
      'Code challenge must be base64 encoded and at least 43 to 128 characters long',
    )
}
function verifyAuthenticationContext(
  authenticationContextType,
  authenticationContextMessage,
) {
  // for non-login apps, this is rejected if present, and since mockpass
  // won't have context of the app type, we just make it optional
  if (!authenticationContextType) return
  if (
    !FapiUtils.AllowedAuthenticationContextTypes.includes(
      authenticationContextType,
    )
  )
    throw new Error('Invalid authentication context type')

  // this is optional by SP FAPI spec, and should only be validated when provided.
  if (authenticationContextMessage && authenticationContextMessage.length > 100)
    throw new Error(
      'Authentication context message must be less than 100 characters',
    )
}
function verifyCodeVerifier(codeVerifier, codeChallenge) {
  const verifierSha256 = crypto
    .createHash('sha256')
    .update(codeVerifier)
    .digest('base64url')
  if (verifierSha256 !== codeChallenge)
    throw new Error('Code verifier and code challenge do not match')
}

module.exports = FapiService
