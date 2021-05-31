const express = require('express')
const fs = require('fs')
const { render } = require('mustache')
const jose = require('node-jose')
const path = require('path')
const ExpiryMap = require('expiry-map')

const assertions = require('../assertions')
const samlArtifact = require('../saml-artifact')

const LOGIN_TEMPLATE = fs.readFileSync(
  path.resolve(__dirname, '../../static/html/login-page.html'),
  'utf8',
)
const NONCE_TIMEOUT = 5 * 60 * 1000
const nonceStore = new ExpiryMap(NONCE_TIMEOUT)

const PATH_PREFIX = '/sgid/v1/oauth'

const idGenerator = {
  singPass: (rawId) =>
    assertions.myinfo.v3.personas[rawId] ? `${rawId} [MyInfo]` : rawId,
}

function config(app, { showLoginPage, idpConfig, serviceProvider }) {
  app.get(`${PATH_PREFIX}/authorize`, (req, res) => {
    const redirectURI = req.query.redirect_uri
    const state = encodeURIComponent(req.query.state)
    if (showLoginPage) {
      const oidc = assertions.oidc.singPass
      const values = oidc
        .filter((rawId) => assertions.myinfo.v3.personas[rawId])
        .map((rawId) => {
          const index = oidc.indexOf(rawId)
          const code = encodeURIComponent(
            samlArtifact(idpConfig.singPass.id, index),
          )
          if (req.query.nonce) {
            nonceStore.set(code, req.query.nonce)
          }
          const assertURL = `${redirectURI}?code=${code}&state=${state}`
          const id = idGenerator.singPass(rawId)
          return { id, assertURL }
        })
      const response = render(LOGIN_TEMPLATE, { values })
      res.send(response)
    } else {
      const code = encodeURIComponent(samlArtifact(idpConfig.singPass.id))
      if (req.query.nonce) {
        nonceStore.set(code, req.query.nonce)
      }
      const assertURL = `${redirectURI}?code=${code}&state=${state}`
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
      const { client_id: aud, code: artifact } = req.body
      let uuid

      console.warn(
        `Received artifact ${artifact} from ${aud} and ${req.body.redirect_uri}`,
      )
      try {
        const artifactBuffer = Buffer.from(artifact, 'base64')
        uuid = artifactBuffer.readInt8(artifactBuffer.length - 1)
        const nonce = nonceStore.get(encodeURIComponent(artifact))

        // use env NRIC when SHOW_LOGIN_PAGE is false
        if (uuid === -1) {
          uuid = assertions.oidc.singPass.indexOf(assertions.singPassNric)
        }

        const { idTokenClaims, refreshToken } =
          await assertions.oidc.create.singPass(
            uuid,
            `${req.protocol}://${req.get('host')}`,
            aud,
            nonce,
          )
        const accessToken = uuid

        const signingPem = fs.readFileSync(
          path.resolve(__dirname, '../../static/certs/spcp-key.pem'),
        )
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
          token_type: 'bearer',
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
    const nric = assertions.oidc.singPass[uuid]
    const persona = assertions.myinfo.v3.personas[nric]
    const name = persona.name.value
    const dateOfBirth = persona.dob.value

    const payloadKey = await jose.JWK.createKey('oct', 256, {
      alg: 'A256GCM',
    })

    const encryptedNric = await jose.JWE.createEncrypt(payloadKey)
      .update(nric)
      .final()
    const encryptedName = await jose.JWE.createEncrypt(payloadKey)
      .update(name)
      .final()
    const encryptedDateOfBirth = await jose.JWE.createEncrypt(payloadKey)
      .update(dateOfBirth)
      .final()
    const data = {
      'myinfo.nric_number': encryptedNric,
      'myinfo.name': encryptedName,
      'myinfo.date_of_birth': encryptedDateOfBirth,
    }
    const encryptionKey = await jose.JWK.asKey(serviceProvider.cert, 'pem')

    const plaintextPayloadKey = JSON.stringify(payloadKey.toJSON(true))
    console.log(plaintextPayloadKey)
    const encryptedPayloadKey = await jose.JWE.createEncrypt(encryptionKey)
      .update(plaintextPayloadKey)
      .final()
    res.json({
      sub: `u=${uuid}`,
      key: encryptedPayloadKey,
      data,
    })
  })
}

module.exports = config
