const jose = require('jose')
const assert = require('node:assert')
const fs = require('fs')
const path = require('path')
const { SignJWT, importJWK } = require('jose')

const PATH_PREFIX = '/sign-v3'
const CLIENT_JWKS_URL =
  process.env.SIGNV3_CLIENT_JWKS_URL || 'http://localhost:4000/jwks'
const CLIENT_ID = process.env.SIGNV3_CLIENT_ID || 'mockpass-sign-v3-client'
const MOCKPASS_SERVER_HOST =
  process.env.MOCKPASS_SERVER_HOST || 'http://localhost:5156'
const CLIENT_REDIRECT_URI =
  process.env.SIGNV3_CLIENT_REDIRECT_URI || 'http://localhost:4000/redirect'
const CLIENT_WEBHOOK_URL =
  process.env.SIGNV3_CLIENT_WEBHOOK_URL || 'http://localhost:4000/webhook'
const SIGNED_DOC_URL = `${MOCKPASS_SERVER_HOST}/mockpass/resources/dummy-signed.pdf`
const MOCKPASS_SIGNV3_PRIVATE_JWK = JSON.parse(
  fs.readFileSync(
    path.resolve(__dirname, '../../static/certs/sign-v3-secret.json'),
  ),
)

function config(app) {
  app.post(`${PATH_PREFIX}/sign-requests`, async (req, res) => {
    try {
      assert(req.headers['content-type'] === 'application/octet-stream')
      assert(req.headers.authorization)
      const { payload } = await jose.jwtVerify(
        req.headers.authorization,
        jose.createRemoteJWKSet(new URL(CLIENT_JWKS_URL)),
        { requiredClaims: ['client_id', 'x', 'y', 'page', 'doc_name'] },
      )
      assert(payload.client_id === CLIENT_ID)
    } catch (err) {
      console.error(err)
      return res
        .status(400)
        .json({ error: 'UNAUTHORIZED', error_description: 'Unauthorized.' })
    }

    const request_id = `signv3-${crypto.randomUUID()}`
    console.info(`Creating sign request: ${request_id}`)
    return res.status(200).json({
      signing_url: `${MOCKPASS_SERVER_HOST}/sign-v3/sign?request_id=${request_id}`,
      request_id,
      exchange_code: crypto.randomUUID(),
    })
  })

  app.get(`${PATH_PREFIX}/sign`, async (req, res) => {
    const { request_id } = req.query
    await sendSignedDocWebhook(request_id)

    const redirect_uri = new URL(CLIENT_REDIRECT_URI)
    redirect_uri.searchParams.set('request_id', request_id)
    return res.redirect(redirect_uri)
  })

  app.get(`${PATH_PREFIX}/sign-requests/:request_id/signed_doc`, (req, res) => {
    console.info(`Retrieving signed doc of: ${req.params.request_id}`)
    return res.status(200).json({ signed_doc_url: SIGNED_DOC_URL })
  })

  app.get(`${PATH_PREFIX}/jwks`, async (req, res) => {
    // eslint-disable-next-line no-unused-vars
    const { d, ...publicJwk } = { ...MOCKPASS_SIGNV3_PRIVATE_JWK }
    return res.status(200).json({ keys: [publicJwk] })
  })
}

const sendSignedDocWebhook = async (request_id) => {
  await fetch(CLIENT_WEBHOOK_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      token: await new SignJWT({
        signed_doc_url: SIGNED_DOC_URL,
        request_type: 'signed_doc_url',
        request_id,
      })
        .setIssuedAt()
        .setProtectedHeader({
          alg: 'ES256',
          kid: MOCKPASS_SIGNV3_PRIVATE_JWK.kid,
        })
        .setExpirationTime('120s')
        .sign(await importJWK(MOCKPASS_SIGNV3_PRIVATE_JWK)),
    }),
  }).then((response) => {
    if (!response.ok) {
      console.error('signed doc webhook failed', response)
    }
    console.info(`signed doc webhook success ${CLIENT_WEBHOOK_URL}`)
  })
}

module.exports = config
