#!/usr/bin/env node
const express = require('express')

const { config } = require('./lib/express')

const PORT = process.env.PORT || 5156

if (!process.env.SINGPASS_ASSERT_ENDPOINT && !process.env.CORPPASS_ASSERT_ENDPOINT) {
  throw new Error('Either SINGPASS_ASSERT_ENDPOINT or CORPPASS_ASSERT_ENDPOINT must be set')
}

const app = config(express(), {
  serviceProviderPaths: {
    cert: process.env.SERVICE_PROVIDER_CERT_PATH || './static/certs/server.crt',
    pubKey: process.env.SERVICE_PROVIDER_PUB_KEY || './static/certs/key.pub',
  },
  idpConfig: {
    singPass: {
      id: process.env.SINGPASS_IDP_ID || 'https://saml-internet.singpass.gov.sg/FIM/sps/SingpassIDPFed/saml20',
      assertEndpoint: process.env.SINGPASS_ASSERT_ENDPOINT,
    },
    corpPass: {
      id: process.env.CORPPASS_IDP_ID || 'https://saml.corppass.gov.sg/FIM/sps/CorpIDPFed/saml20',
      assertEndpoint: process.env.CORPPASS_ASSERT_ENDPOINT,
    },
  },
  showLoginPage: process.env.SHOW_LOGIN_PAGE === 'true',
})

app.listen(
  PORT,
  err => err
    ? console.error('Unable to start MockPass', err)
    : console.warn(`MockPass listening on ${PORT}`)
)
