// This file implements NDI OIDC for Singpass authentication and Corppass OIDC
// for Corppass authentication.

const express = require('express')
const fs = require('fs')
const { render } = require('mustache')
const jose = require('jose')
const path = require('path')

const assertions = require('../../assertions')
const { generateAuthCode, lookUpByAuthCode } = require('../../auth-code')
const {
  buildAssertURL,
  idGenerator,
  customProfileFromHeaders,
} = require('./utils')

const LOGIN_TEMPLATE = fs.readFileSync(
  path.resolve(__dirname, '../../../static/html/login-page.html'),
  'utf8',
)

const aspPublic = fs.readFileSync(
  path.resolve(__dirname, '../../../static/certs/oidc-v2-asp-public.json'),
)

const aspSecret = fs.readFileSync(
  path.resolve(__dirname, '../../../static/certs/oidc-v2-asp-secret.json'),
)

const rpPublic = fs.readFileSync(
  path.resolve(__dirname, '../../../static/certs/oidc-v2-rp-public.json'),
)

const singpass_token_endpoint_auth_signing_alg_values_supported = [
  'ES256',
  'ES384',
  'ES512',
]

const corppass_token_endpoint_auth_signing_alg_values_supported = ['ES256']

const token_endpoint_auth_signing_alg_values_supported = {
  singPass: singpass_token_endpoint_auth_signing_alg_values_supported,
  corpPass: corppass_token_endpoint_auth_signing_alg_values_supported,
}

const singpass_id_token_encryption_alg_values_supported = [
  'ECDH-ES+A256KW',
  'ECDH-ES+A192KW',
  'ECDH-ES+A128KW',
  'RSA-OAEP-256',
]

const corppass_id_token_encryption_alg_values_supported = ['ECDH-ES+A256KW']

const id_token_encryption_alg_values_supported = {
  singPass: singpass_id_token_encryption_alg_values_supported,
  corpPass: corppass_id_token_encryption_alg_values_supported,
}

function findEcdhEsEncryptionKey(jwks, crv, algs) {
  let encryptionKey = jwks.keys.find(
    (item) =>
      item.use === 'enc' &&
      item.kty === 'EC' &&
      item.crv === crv &&
      (!item.alg ||
        (item.alg === 'ECDH-ES+A256KW' &&
          algs.some((alg) => alg === item.alg))),
  )
  if (encryptionKey) {
    return {
      ...encryptionKey,
      ...(!encryptionKey.alg ? { alg: 'ECDH-ES+A256KW' } : {}),
    }
  }
  encryptionKey = jwks.keys.find(
    (item) =>
      item.use === 'enc' &&
      item.kty === 'EC' &&
      item.crv === crv &&
      (!item.alg ||
        (item.alg === 'ECDH-ES+A192KW' &&
          algs.some((alg) => alg === item.alg))),
  )
  if (encryptionKey) {
    return {
      ...encryptionKey,
      ...(!encryptionKey.alg ? { alg: 'ECDH-ES+A256KW' } : {}),
    }
  }
  encryptionKey = jwks.keys.find(
    (item) =>
      item.use === 'enc' &&
      item.kty === 'EC' &&
      item.crv === crv &&
      (!item.alg ||
        (item.alg === 'ECDH-ES+A128KW' &&
          algs.some((alg) => alg === item.alg))),
  )
  if (encryptionKey) {
    return {
      ...encryptionKey,
      ...(!encryptionKey.alg ? { alg: 'ECDH-ES+A256KW' } : {}),
    }
  }
  return null
}

function findEncryptionKey(jwks, algs) {
  let encryptionKey = findEcdhEsEncryptionKey(jwks, 'P-521', algs)
  if (encryptionKey) {
    return encryptionKey
  }
  if (!encryptionKey) {
    encryptionKey = findEcdhEsEncryptionKey(jwks, 'P-384', algs)
  }
  if (encryptionKey) {
    return encryptionKey
  }
  if (!encryptionKey) {
    encryptionKey = findEcdhEsEncryptionKey(jwks, 'P-256', algs)
  }
  if (encryptionKey) {
    return encryptionKey
  }
  if (!encryptionKey) {
    encryptionKey = jwks.keys.find(
      (item) =>
        item.use === 'enc' &&
        item.kty === 'RSA' &&
        (!item.alg ||
          (item.alg === 'RSA-OAEP-256' &&
            algs.some((alg) => alg === item.alg))),
    )
  }
  if (encryptionKey) {
    return { ...encryptionKey, alg: 'RSA-OAEP-256' }
  }
}

function config(app, { showLoginPage }) {
  for (const idp of ['singPass', 'corpPass']) {
    const profiles = assertions.oidc[idp]
    const defaultProfile =
      profiles.find((p) => p.nric === process.env.MOCKPASS_NRIC) || profiles[0]

    app.get(`/${idp.toLowerCase()}/v2/authorize`, (req, res) => {
      const {
        scope,
        response_type,
        client_id,
        redirect_uri: redirectURI,
        state,
        nonce,
      } = req.query

      if (scope !== 'openid') {
        return res.status(400).send({
          error: 'invalid_scope',
          error_description: `Unknown scope ${scope}`,
        })
      }
      if (response_type !== 'code') {
        return res.status(400).send({
          error: 'unsupported_response_type',
          error_description: `Unknown response_type ${response_type}`,
        })
      }
      if (!client_id) {
        return res.status(400).send({
          error: 'invalid_request',
          error_description: 'Missing client_id',
        })
      }
      if (!redirectURI) {
        return res.status(400).send({
          error: 'invalid_request',
          error_description: 'Missing redirect_uri',
        })
      }
      if (!nonce) {
        return res.status(400).send({
          error: 'invalid_request',
          error_description: 'Missing nonce',
        })
      }
      if (!state) {
        return res.status(400).send({
          error: 'invalid_request',
          error_description: 'Missing state',
        })
      }

      // Identical to OIDC v1
      if (showLoginPage(req)) {
        const values = profiles.map((profile) => {
          const authCode = generateAuthCode({ profile, nonce })
          const assertURL = buildAssertURL(redirectURI, authCode, state)
          const id = idGenerator[idp](profile)
          return { id, assertURL }
        })
        const response = render(LOGIN_TEMPLATE, {
          values,
          customProfileConfig: {
            endpoint: `/${idp.toLowerCase()}/v2/authorize/custom-profile`,
            showUuid: true,
            showUen: idp === 'corpPass',
            redirectURI,
            state,
            nonce,
          },
        })
        res.send(response)
      } else {
        const profile = customProfileFromHeaders[idp](req) || defaultProfile
        const authCode = generateAuthCode({ profile, nonce })
        const assertURL = buildAssertURL(redirectURI, authCode, state)
        console.warn(
          `Redirecting login from ${req.query.client_id} to ${redirectURI}`,
        )
        res.redirect(assertURL)
      }
    })

    app.get(`/${idp.toLowerCase()}/v2/authorize/custom-profile`, (req, res) => {
      const { nric, uuid, uen, redirectURI, state, nonce } = req.query

      const profile = { nric, uuid }
      if (idp === 'corpPass') {
        profile.name = `Name of ${nric}`
        profile.isSingPassHolder = false
        profile.uen = uen
      }

      const authCode = generateAuthCode({ profile, nonce })
      const assertURL = buildAssertURL(redirectURI, authCode, state)
      res.redirect(assertURL)
    })

    app.post(
      `/${idp.toLowerCase()}/v2/token`,
      express.urlencoded({ extended: false }),
      async (req, res) => {
        const {
          client_id,
          redirect_uri: redirectURI,
          grant_type,
          code: authCode,
          client_assertion_type,
          client_assertion: clientAssertion,
        } = req.body

        // Only SP requires client_id
        if (idp === 'singPass' && !client_id) {
          console.error('Missing client_id')
          return res.status(400).send({
            error: 'invalid_request',
            error_description: 'Missing client_id',
          })
        }
        if (!redirectURI) {
          console.error('Missing redirect_uri')
          return res.status(400).send({
            error: 'invalid_request',
            error_description: 'Missing redirect_uri',
          })
        }
        if (grant_type !== 'authorization_code') {
          console.error('Unknown grant_type', grant_type)
          return res.status(400).send({
            error: 'unsupported_grant_type',
            error_description: `Unknown grant_type ${grant_type}`,
          })
        }
        if (!authCode) {
          return res.status(400).send({
            error: 'invalid_request',
            error_description: 'Missing code',
          })
        }
        if (
          client_assertion_type !==
          'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
        ) {
          console.error('Unknown client_assertion_type', client_assertion_type)
          return res.status(400).send({
            error: 'invalid_request',
            error_description: `Unknown client_assertion_type ${client_assertion_type}`,
          })
        }
        if (!clientAssertion) {
          console.error('Missing client_assertion')
          return res.status(400).send({
            error: 'invalid_request',
            error_description: 'Missing client_assertion',
          })
        }

        // Step 0: Get the RP keyset
        const rpJwksEndpoint =
          idp === 'singPass'
            ? process.env.SP_RP_JWKS_ENDPOINT
            : process.env.CP_RP_JWKS_ENDPOINT

        let rpKeysetString

        if (rpJwksEndpoint) {
          try {
            const rpKeysetResponse = await fetch(rpJwksEndpoint, {
              method: 'GET',
            })
            rpKeysetString = await rpKeysetResponse.text()
            if (!rpKeysetResponse.ok) {
              throw new Error(rpKeysetString)
            }
          } catch (e) {
            console.error(
              'Failed to fetch RP JWKS from',
              rpJwksEndpoint,
              e.message,
            )
            return res.status(400).send({
              error: 'invalid_client',
              error_description: `Failed to fetch RP JWKS from specified endpoint: ${e.message}`,
            })
          }
        } else {
          // If the endpoint is not defined, default to the sample keyset we provided.
          rpKeysetString = rpPublic
        }

        let rpKeysetJson
        try {
          rpKeysetJson = JSON.parse(rpKeysetString)
        } catch (e) {
          console.error('Unable to parse RP keyset', e.message)
          return res.status(400).send({
            error: 'invalid_client',
            error_description: `Unable to parse RP keyset: ${e.message}`,
          })
        }

        const rpKeyset = jose.createLocalJWKSet(rpKeysetJson)
        // Step 0.5: Verify client assertion with RP signing key
        let clientAssertionResult
        try {
          clientAssertionResult = await jose.jwtVerify(
            clientAssertion,
            rpKeyset,
          )
        } catch (e) {
          console.error(
            'Unable to verify client_assertion',
            e.message,
            clientAssertion,
          )
          return res.status(401).send({
            error: 'invalid_client',
            error_description: `Unable to verify client_assertion: ${e.message}`,
          })
        }

        const { payload: clientAssertionClaims, protectedHeader } =
          clientAssertionResult
        console.debug(
          'Received client_assertion',
          clientAssertionClaims,
          protectedHeader,
        )
        if (
          !token_endpoint_auth_signing_alg_values_supported[idp].some(
            (item) => item === protectedHeader.alg,
          )
        ) {
          console.warn(
            'The client_assertion alg',
            protectedHeader.alg,
            'does not meet required token_endpoint_auth_signing_alg_values_supported',
            token_endpoint_auth_signing_alg_values_supported[idp],
          )
        }

        if (!protectedHeader.typ) {
          console.error('The client_assertion typ should be set')
          return res.status(401).send({
            error: 'invalid_client',
            error_description: 'The client_assertion typ should be set',
          })
        }

        if (idp === 'singPass') {
          if (clientAssertionClaims['sub'] !== client_id) {
            console.error(
              'Incorrect sub in client_assertion claims. Found',
              clientAssertionClaims['sub'],
              'but should be',
              client_id,
            )
            return res.status(401).send({
              error: 'invalid_client',
              error_description: 'Incorrect sub in client_assertion claims',
            })
          }
        } else {
          // Since client_id is not given for corpPass, sub claim is required in
          // order to get aud for id_token.
          if (!clientAssertionClaims['sub']) {
            console.error('Missing sub in client_assertion claims')
            return res.status(401).send({
              error: 'invalid_client',
              error_description: 'Missing sub in client_assertion claims',
            })
          }
        }

        // According to OIDC spec, asp must check the aud claim.
        const iss = `${req.protocol}://${req.get(
          'host',
        )}/${idp.toLowerCase()}/v2`

        if (clientAssertionClaims['aud'] !== iss) {
          console.error(
            'Incorrect aud in client_assertion claims. Found',
            clientAssertionClaims['aud'],
            'but should be',
            iss,
          )
          return res.status(401).send({
            error: 'invalid_client',
            error_description: 'Incorrect aud in client_assertion claims',
          })
        }

        // Step 1: Obtain profile for which the auth code requested data for
        const { profile, nonce } = lookUpByAuthCode(authCode)

        // Step 2: Get ID token
        const aud = clientAssertionClaims['sub']
        console.debug('Received token request', {
          code: authCode,
          client_id: aud,
          redirect_uri: redirectURI,
        })

        const { idTokenClaims, accessToken } = await assertions.oidc.create[
          idp
        ](profile, iss, aud, nonce)

        // Step 3: Sign ID token with ASP signing key
        const aspKeyset = JSON.parse(aspSecret)
        const aspSigningKey = aspKeyset.keys.find(
          (item) =>
            item.use === 'sig' && item.kty === 'EC' && item.crv === 'P-256',
        )
        if (!aspSigningKey) {
          console.error('No suitable signing key found', aspKeyset.keys)
          return res.status(400).send({
            error: 'invalid_request',
            error_description: 'No suitable signing key found',
          })
        }
        const signingKey = await jose.importJWK(aspSigningKey, 'ES256')
        const signedProtectedHeader = {
          alg: 'ES256',
          typ: 'JWT',
          kid: aspSigningKey.kid,
        }
        const signedIdToken = await new jose.CompactSign(
          new TextEncoder().encode(JSON.stringify(idTokenClaims)),
        )
          .setProtectedHeader(signedProtectedHeader)
          .sign(signingKey)

        // Step 4: Encrypt ID token with RP encryption key
        const rpEncryptionKey = findEncryptionKey(
          rpKeysetJson,
          id_token_encryption_alg_values_supported[idp],
        )
        if (!rpEncryptionKey) {
          console.error('No suitable encryption key found', rpKeysetJson.keys)
          return res.status(400).send({
            error: 'invalid_request',
            error_description: 'No suitable encryption key found',
          })
        }
        console.debug('Using encryption key', rpEncryptionKey)
        const encryptedProtectedHeader = {
          alg: rpEncryptionKey.alg,
          typ: 'JWT',
          kid: rpEncryptionKey.kid,
          enc: 'A256CBC-HS512',
          cty: 'JWT',
        }
        const idToken = await new jose.CompactEncrypt(
          new TextEncoder().encode(signedIdToken),
        )
          .setProtectedHeader(encryptedProtectedHeader)
          .encrypt(await jose.importJWK(rpEncryptionKey, rpEncryptionKey.alg))

        console.debug('ID Token', idToken)
        // Step 5: Send token
        res.status(200).send({
          access_token: accessToken,
          token_type: 'Bearer',
          id_token: idToken,
          ...(idp === 'corpPass'
            ? { scope: 'openid', expires_in: 10 * 60 }
            : {}),
        })
      },
    )

    app.get(
      `/${idp.toLowerCase()}/v2/.well-known/openid-configuration`,
      (req, res) => {
        const baseUrl = `${req.protocol}://${req.get(
          'host',
        )}/${idp.toLowerCase()}/v2`

        // Note: does not support backchannel auth
        const data = {
          issuer: baseUrl,
          authorization_endpoint: `${baseUrl}/authorize`,
          jwks_uri: `${baseUrl}/.well-known/keys`,
          response_types_supported: ['code'],
          scopes_supported: ['openid'],
          subject_types_supported: ['public'],
          claims_supported: ['nonce', 'aud', 'iss', 'sub', 'exp', 'iat'],
          grant_types_supported: ['authorization_code'],
          token_endpoint: `${baseUrl}/token`,
          token_endpoint_auth_methods_supported: ['private_key_jwt'],
          token_endpoint_auth_signing_alg_values_supported:
            token_endpoint_auth_signing_alg_values_supported[idp],
          id_token_signing_alg_values_supported: ['ES256'],
          id_token_encryption_alg_values_supported:
            id_token_encryption_alg_values_supported[idp],
          id_token_encryption_enc_values_supported: ['A256CBC-HS512'],
        }

        if (idp === 'corpPass') {
          data['claims_supported'] = [
            ...data['claims_supported'],
            'userInfo',
            'EntityInfo',
            'rt_hash',
            'at_hash',
            'amr',
          ]
          // Omit authorization-info_endpoint for CP
        }

        res.status(200).send(data)
      },
    )

    app.get(`/${idp.toLowerCase()}/v2/.well-known/keys`, (req, res) => {
      res.status(200).send(JSON.parse(aspPublic))
    })
  }
  return app
}

module.exports = config
