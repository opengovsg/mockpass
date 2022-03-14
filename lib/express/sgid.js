const express = require('express')
const fs = require('fs')
const { render } = require('mustache')
const jose = require('node-jose')
const path = require('path')

const assertions = require('../assertions')
const { generateAuthCode, lookUpByAuthCode } = require('../auth-code')

const LOGIN_TEMPLATE = fs.readFileSync(
  path.resolve(__dirname, '../../static/html/login-page.html'),
  'utf8',
)

const PATH_PREFIX = '/sgid/v1/oauth'

const signingPem = fs.readFileSync(
  path.resolve(__dirname, '../../static/certs/spcp-key.pem'),
)

const idGenerator = {
  singPass: ({ nric }) =>
    assertions.myinfo.v3.personas[nric] ? `${nric} [MyInfo]` : nric,
}

const buildAssertURL = (redirectURI, authCode, state) =>
  `${redirectURI}?code=${encodeURIComponent(
    authCode,
  )}&state=${encodeURIComponent(state)}`

function config(app, { showLoginPage, serviceProvider }) {
  const profiles = assertions.oidc.singPass
  const defaultProfile =
    profiles.find((p) => p.nric === process.env.MOCKPASS_NRIC) || profiles[0]

  app.get(`${PATH_PREFIX}/authorize`, (req, res) => {
    const { redirect_uri: redirectURI, state, nonce } = req.query
    if (showLoginPage(req)) {
      const values = profiles
        .filter((profile) => assertions.myinfo.v3.personas[profile.nric])
        .map((profile) => {
          const authCode = generateAuthCode({ profile, nonce })
          const assertURL = buildAssertURL(redirectURI, authCode, state)
          const id = idGenerator.singPass(profile)
          return { id, assertURL }
        })
      const response = render(LOGIN_TEMPLATE, { values })
      res.send(response)
    } else {
      const profile = defaultProfile
      const authCode = generateAuthCode({ profile, nonce })
      const assertURL = buildAssertURL(redirectURI, authCode, state)
      console.warn(
        `Redirecting login from ${req.query.client_id} to ${assertURL}`,
      )
      res.redirect(assertURL)
    }
  })

  app.post(
    `${PATH_PREFIX}/token`,
    express.json(),
    express.urlencoded({ extended: true }),
    async (req, res) => {
      console.log(req.body)
      const { client_id: aud, code: authCode } = req.body

      console.warn(
        `Received auth code ${authCode} from ${aud} and ${req.body.redirect_uri}`,
      )
      try {
        const { profile, nonce } = lookUpByAuthCode(authCode)

        const accessToken = profile.uuid
        const iss = `${req.protocol}://${req.get('host')}`

        const { idTokenClaims, refreshToken } = assertions.oidc.create.singPass(
          profile,
          iss,
          aud,
          nonce,
          accessToken,
        )
        // Change sub from `s=${nric},u=${uuid}`
        // to `u=${uuid}` to be consistent with userinfo sub
        idTokenClaims.sub = idTokenClaims.sub.split(',')[1]

        const signingKey = await jose.JWK.asKey(signingPem, 'pem')
        const idToken = await jose.JWS.createSign(
          { format: 'compact' },
          signingKey,
        )
          .update(JSON.stringify(idTokenClaims))
          .final()

        res.json({
          access_token: accessToken,
          refresh_token: refreshToken,
          expires_in: 24 * 60 * 60,
          scope: 'openid',
          token_type: 'Bearer',
          id_token: idToken,
        })
      } catch (error) {
        console.error(error)
        res.status(500).json({ message: error.message })
      }
    },
  )

  app.get(`${PATH_PREFIX}/userinfo`, async (req, res) => {
    const uuid = (
      req.headers.authorization || req.headers.Authorization
    ).replace('Bearer ', '')
    const nric = assertions.oidc.singPass.find((p) => p.uuid === uuid).nric
    const persona = assertions.myinfo.v3.personas[nric]
    const name = persona.name.value
    const dateOfBirth = persona.dob.value

    const payloadKey = await jose.JWK.createKey('oct', 256, {
      alg: 'A256GCM',
    })

    const encryptedNric = await jose.JWE.createEncrypt(
      { format: 'compact' },
      payloadKey,
    )
      .update(nric)
      .final()
    const encryptedName = await jose.JWE.createEncrypt(
      { format: 'compact' },
      payloadKey,
    )
      .update(name)
      .final()
    const encryptedDateOfBirth = await jose.JWE.createEncrypt(
      { format: 'compact' },
      payloadKey,
    )
      .update(dateOfBirth)
      .final()
    const data = {
      'myinfo.nric_number': encryptedNric,
      'myinfo.name': encryptedName,
      'myinfo.date_of_birth': encryptedDateOfBirth,
    }
    const encryptionKey = await jose.JWK.asKey(serviceProvider.pubKey, 'pem')

    const plaintextPayloadKey = JSON.stringify(payloadKey.toJSON(true))
    console.log(plaintextPayloadKey)
    const encryptedPayloadKey = await jose.JWE.createEncrypt(
      { format: 'compact' },
      encryptionKey,
    )
      .update(plaintextPayloadKey)
      .final()
    res.json({
      sub: `u=${uuid}`,
      key: encryptedPayloadKey,
      data,
    })
  })

  app.get('/.well-known/jwks.json', async (_req, res) => {
    const key = await jose.JWK.asKey(signingPem, 'pem')
    const jwk = key.toJSON()
    jwk.use = 'sig'
    res.json({ keys: [jwk] })
  })
}

module.exports = config
