#!/usr/bin/env node
const fs = require('fs')
const express = require('express')
const morgan = require('morgan')
const path = require('path')
require('dotenv').config()

const { configSAML, configOIDC, configMyInfo } = require('./lib/express')

const PORT = process.env.MOCKPASS_PORT || process.env.PORT || 5156

if (
  !process.env.SINGPASS_ASSERT_ENDPOINT &&
  !process.env.CORPPASS_ASSERT_ENDPOINT
) {
  console.warn(
    'SINGPASS_ASSERT_ENDPOINT or CORPPASS_ASSERT_ENDPOINT is not set. ' +
      'Value of `PartnerId` request query parameter in redirect URL will be used.',
  )
}

const serviceProvider = {
  cert: fs.readFileSync(
    path.resolve(
      __dirname,
      process.env.SERVICE_PROVIDER_CERT_PATH || './static/certs/server.crt',
    ),
  ),
  pubKey: fs.readFileSync(
    path.resolve(
      __dirname,
      process.env.SERVICE_PROVIDER_PUB_KEY || './static/certs/key.pub',
    ),
  ),
}

const cryptoConfig = {
  signAssertion: process.env.SIGN_ASSERTION !== 'false', // default to true to be backward compatable
  signResponse: process.env.SIGN_RESPONSE !== 'false',
  encryptAssertion: process.env.ENCRYPT_ASSERTION !== 'false',
  resolveArtifactRequestSigned:
    process.env.RESOLVE_ARTIFACT_REQUEST_SIGNED !== 'false',
}

const options = {
  serviceProvider,
  idpConfig: {
    singPass: {
      id:
        process.env.SINGPASS_IDP_ID || 'http://localhost:5156/singpass/saml20',
      assertEndpoint: process.env.SINGPASS_ASSERT_ENDPOINT,
    },
    corpPass: {
      id:
        process.env.CORPPASS_IDP_ID || 'http://localhost:5156/corppass/saml20',
      assertEndpoint: process.env.CORPPASS_ASSERT_ENDPOINT,
    },
  },
  showLoginPage: process.env.SHOW_LOGIN_PAGE === 'true',
  encryptMyInfo: process.env.ENCRYPT_MYINFO === 'true',
  cryptoConfig,
}

const app = express()
app.use(morgan('combined'))

configSAML(app, options)
configOIDC(app, options)

configMyInfo.consent(app)
configMyInfo.v2(app, options)
configMyInfo.v3(app, options)

app.enable('trust proxy')
app.use(express.static(path.join(__dirname, 'public')))

app.listen(PORT, (err) =>
  err
    ? console.error('Unable to start MockPass', err)
    : console.warn(`MockPass listening on ${PORT}`),
)
