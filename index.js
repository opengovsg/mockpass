#!/usr/bin/env node
const express = require('express')

const { config } = require('./lib/express')

const PORT = process.env.PORT || 5156

const assertEndpoint = process.env.ASSERT_ENDPOINT
if (!assertEndpoint) {
  throw new Error('ASSERT_ENDPOINT must be set')
}

const app = config(express(), {
  assertEndpoint,
  serviceProviderPaths: {
    cert: process.env.SERVICE_PROVIDER_CERT_PATH,
    pubKey: process.env.SERVICE_PROVIDER_PUB_KEY,
  },
  showLoginPage: process.env.SHOW_LOGIN_PAGE === 'true',
})

app.listen(
  PORT,
  err => err
    ? console.error('Unable to start mock-spcp-server', err)
    : console.warn(`mock-spcp-server listening on ${PORT}`)
)
