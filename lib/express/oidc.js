const bodyParser = require('body-parser')
const fs = require('fs')
const { render } = require('mustache')
const jose = require('node-jose')
const path = require('path')

const assertions = require('../assertions')
const samlArtifact = require('../saml-artifact')

const LOGIN_TEMPLATE = fs.readFileSync(
  path.resolve(__dirname, '../../static/html/login-page.html'),
  'utf8',
)

const NONCE_TIMEOUT = 5 * 60 * 1000
const nonceStore = new Map()

function config(app, { showLoginPage, idpConfig, serviceProvider }) {
  app.get('/singpass/authorize', (req, res) => {
    const redirectURI = req.query.redirect_uri
    const state = encodeURIComponent(req.query.state)
    const nonceExpiry = Date.now() + NONCE_TIMEOUT
    if (showLoginPage) {
      const oidc = assertions.oidc.singPass
      const generateIdFrom = (rawId) =>
        assertions.myinfo.v3.personas[rawId] ? `${rawId} [MyInfo]` : rawId
      const values = oidc.map((rawId, index) => {
        const code = encodeURIComponent(
          samlArtifact(idpConfig.singPass.id, index),
        )
        if (req.query.nonce) {
          nonceStore.set(code, { nonce: req.query.nonce, expires: nonceExpiry })
        }
        const assertURL = `${redirectURI}?code=${code}&state=${state}`
        const id = generateIdFrom(rawId)
        return { id, assertURL }
      })
      const response = render(LOGIN_TEMPLATE, values)
      res.send(response)
    } else {
      const code = encodeURIComponent(samlArtifact(idpConfig.singPass.id))
      if (req.query.nonce) {
        nonceStore.set(code, { nonce: req.query.nonce, expires: nonceExpiry })
      }
      const assertURL = `${redirectURI}?code=${code}&state=${state}`
      console.warn(
        `Redirecting login from ${req.query.client_id} to ${redirectURI}`,
      )
      res.redirect(assertURL)
    }
  })

  app.post(
    '/singpass/token',
    bodyParser.urlencoded({ extended: false }),
    async (req, res) => {
      const { client_id: aud, code: artifact } = req.body
      console.warn(
        `Received artifact ${artifact} from ${aud} and ${req.body.redirect_uri}`,
      )

      const artifactBuffer = Buffer.from(artifact, 'base64')
      const uuid = artifactBuffer.readInt8(artifactBuffer.length - 1)
      const nric = assertions.oidc.singPass[uuid]
      const sub = `s=${nric},u=${uuid}`

      const nonceEntry = nonceStore.get(encodeURIComponent(artifact))
      const nonce = nonceEntry ? nonceEntry.nonce : undefined

      const payload = {
        rt_hash: '',
        at_hash: '',
        iat: Date.now(),
        exp: Date.now() + 24 * 60 * 60 * 1000,
        iss: req.get('host'),
        amr: ['pwd'],
        aud,
        sub,
        ...(nonce && { nonce }),
      }

      const signingPem = fs.readFileSync(
        path.resolve(__dirname, '../../static/certs/spcp-key.pem'),
      )
      const signingKey = await jose.JWK.asKey(signingPem, 'pem')
      const signedPayload = await jose.JWS.createSign(
        { format: 'compact' },
        signingKey,
      )
        .update(JSON.stringify(payload))
        .final()

      const encryptionKey = await jose.JWK.asKey(serviceProvider.cert, 'pem')
      const idToken = await jose.JWE.createEncrypt(
        { format: 'compact', fields: { cty: 'JWT' } },
        encryptionKey,
      )
        .update(signedPayload)
        .final()

      res.send({
        access_token: '',
        refresh_token: 'refresh',
        scope: 'openid',
        token_type: 'bearer',
        id_token: idToken,
      })

      const now = Date.now()
      nonceStore.forEach((value, key) => {
        if (now > value.expires) {
          nonceStore.delete(key)
        }
      })
    },
  )

  return app
}

module.exports = config
