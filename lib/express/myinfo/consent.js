const express = require('express')
const cookieParser = require('cookie-parser')
const fs = require('fs')
const { pick } = require('lodash')
const { render } = require('mustache')
const path = require('path')
const qs = require('querystring')
const { v1: uuid } = require('uuid')

const assertions = require('../../assertions')
const { lookUpByAuthCode } = require('../../auth-code')

const MYINFO_ASSERT_ENDPOINT = '/consent/myinfo-com'
const AUTHORIZE_ENDPOINT = '/consent/oauth2/authorize'
const CONSENT_TEMPLATE = fs.readFileSync(
  path.resolve(__dirname, '../../../static/html/consent.html'),
  'utf8',
)

const authorizations = {}

const authorize = (redirectTo) => (req, res) => {
  const {
    client_id, // eslint-disable-line camelcase
    redirect_uri, // eslint-disable-line camelcase
    attributes,
    purpose,
    state,
  } = req.query
  const relayStateParams = qs.stringify({
    client_id,
    redirect_uri,
    state,
    purpose,
    scope: (attributes || '').replace(/,/g, ' '),
    realm: MYINFO_ASSERT_ENDPOINT,
    response_type: 'code',
  })
  const relayState = `${AUTHORIZE_ENDPOINT}${encodeURIComponent(
    '?' + relayStateParams,
  )}`
  res.redirect(redirectTo(relayState))
}

const authorizeViaOIDC = authorize(
  (state) =>
    `/singpass/authorize?client_id=MYINFO-CONSENTPLATFORM&redirect_uri=${MYINFO_ASSERT_ENDPOINT}&state=${state}`,
)

function config(app) {
  app.get(MYINFO_ASSERT_ENDPOINT, (req, res) => {
    const rawArtifact = req.query.SAMLart || req.query.code
    const artifact = rawArtifact.replace(/ /g, '+')
    const state = req.query.RelayState || req.query.state

    const profile = lookUpByAuthCode(artifact).profile
    const myinfoVersion = 'v3'

    const { nric: id } = profile

    const persona = assertions.myinfo[myinfoVersion].personas[id]
    if (!persona) {
      res.status(404).send({
        message: 'Cannot find MyInfo Persona',
        artifact,
        myinfoVersion,
        id,
      })
    } else {
      res.cookie('connect.sid', id)
      res.redirect(state)
    }
  })

  app.get(AUTHORIZE_ENDPOINT, cookieParser(), (req, res) => {
    const params = {
      ...req.query,
      scope: req.query.scope.replace(/\+/g, ' '),
      id: req.cookies['connect.sid'],
      action: AUTHORIZE_ENDPOINT,
    }

    res.send(render(CONSENT_TEMPLATE, params))
  })

  app.post(
    AUTHORIZE_ENDPOINT,
    cookieParser(),
    express.urlencoded({
      extended: false,
      type: 'application/x-www-form-urlencoded',
    }),
    (req, res) => {
      const id = req.cookies['connect.sid']
      const code = uuid()
      authorizations[code] = [
        {
          sub: id,
          auth_level: 0,
          scope: req.body.scope.split(' '),
          iss: `${req.protocol}://${req.get(
            'host',
          )}/consent/oauth2/consent/myinfo-com`,
          tokenName: 'access_token',
          token_type: 'Bearer',
          authGrantId: code,
          auditTrackingId: code,
          jti: code,
          aud: 'myinfo',
          grant_type: 'authorization_code',
          realm: '/consent/myinfo-com',
        },
        req.body.redirect_uri,
      ]
      const callbackParams = qs.stringify(
        req.body.decision === 'allow'
          ? {
              code,
              ...pick(req.body, ['state', 'scope', 'client_id']),
              iss: `${req.protocol}://${req.get(
                'host',
              )}/consent/oauth2/consent/myinfo-com`,
            }
          : {
              state: req.body.state,
              'error-description':
                'Resource Owner did not authorize the request',
              error: 'access_denied',
            },
      )
      res.redirect(`${req.body.redirect_uri}?${callbackParams}`)
    },
  )

  return app
}

module.exports = {
  authorizeViaOIDC,
  authorizations,
  config,
}
