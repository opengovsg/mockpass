const express = require('express')
const fs = require('fs')
const { render } = require('mustache')
const jose = require('node-jose')
const path = require('path')
const ExpiryMap = require('expiry-map')

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
const REFRESH_TOKEN_TIMEOUT = 24 * 60 * 60 * 1000
const profileStore = new ExpiryMap(REFRESH_TOKEN_TIMEOUT)

const signingPem = fs.readFileSync(
  path.resolve(__dirname, '../../../static/certs/spcp-key.pem'),
)

function config(app, { showLoginPage, serviceProvider }) {
  for (const idp of ['singPass', 'corpPass']) {
    const profiles = assertions.oidc[idp]
    const defaultProfile =
      profiles.find((p) => p.nric === process.env.MOCKPASS_NRIC) || profiles[0]

    app.get(`/${idp.toLowerCase()}/authorize`, (req, res) => {
      const { redirect_uri: redirectURI, state, nonce } = req.query
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
            endpoint: `/${idp.toLowerCase()}/authorize/custom-profile`,
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

    app.get(`/${idp.toLowerCase()}/authorize/custom-profile`, (req, res) => {
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
      `/${idp.toLowerCase()}/token`,
      express.urlencoded({ extended: false }),
      async (req, res) => {
        const { client_id: aud, grant_type: grant } = req.body
        let profile, nonce

        if (grant === 'refresh_token') {
          const { refresh_token: suppliedRefreshToken } = req.body
          console.warn(`Refreshing tokens with ${suppliedRefreshToken}`)

          profile = profileStore.get(suppliedRefreshToken)
        } else {
          const { code: authCode } = req.body
          console.warn(
            `Received auth code ${authCode} from ${aud} and ${req.body.redirect_uri}`,
          )
          ;({ profile, nonce } = lookUpByAuthCode(authCode))
        }

        const iss = `${req.protocol}://${req.get('host')}`

        const { idTokenClaims, accessToken, refreshToken } =
          await assertions.oidc.create[idp](profile, iss, aud, nonce)

        profileStore.set(refreshToken, profile)

        const signingKey = await jose.JWK.asKey(signingPem, 'pem')
        const signedIdToken = await jose.JWS.createSign(
          { format: 'compact' },
          signingKey,
        )
          .update(JSON.stringify(idTokenClaims))
          .final()

        const encryptionKey = await jose.JWK.asKey(serviceProvider.cert, 'pem')
        const idToken = await jose.JWE.createEncrypt(
          { format: 'compact', fields: { cty: 'JWT' } },
          encryptionKey,
        )
          .update(signedIdToken)
          .final()

        res.send({
          access_token: accessToken,
          refresh_token: refreshToken,
          expires_in: 24 * 60 * 60,
          scope: 'openid',
          token_type: 'bearer',
          id_token: idToken,
        })
      },
    )
  }
  return app
}

module.exports = config
