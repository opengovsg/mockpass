const _ = require('lodash')
const bodyParser = require('body-parser')
const cookieParser = require('cookie-parser')
const fs = require('fs')
const jwt = require('jsonwebtoken')
const { pick, partition } = require('lodash')
const { render } = require('mustache')
const path = require('path')
const qs = require('querystring')
const { v1: uuid } = require('uuid')

const assertions = require('../assertions')
const crypto = require('../crypto')

const MYINFO_ASSERT_ENDPOINT = '/consent/myinfo-com'
const AUTHORIZE_ENDPOINT = '/consent/oauth2/authorize'
const CONSENT_TEMPLATE = fs.readFileSync(path.resolve(__dirname, '../../static/html/consent.html'), 'utf8')

const MOCKPASS_PRIVATE_KEY = fs.readFileSync(path.resolve(__dirname, '../../static/certs/spcp-key.pem'))
const MOCKPASS_PUBLIC_KEY = fs.readFileSync(path.resolve(__dirname, '../../static/certs/spcp.crt'))

const authorizations = {}

function config (app, { serviceProvider, port }) {
  const { verifyMyInfoSignature } = crypto(serviceProvider)

  const lookupPerson = allowedAttributes => (req, res) => {
    const requestedAttributes = (req.query.attributes || '').split(',')

    const [attributes, disallowedAttributes] = partition(
      requestedAttributes,
      v => allowedAttributes.includes(v)
    )

    if (disallowedAttributes.length > 0) {
      res.status(401).send({ code: 401, message: 'Disallowed', fields: disallowedAttributes.join(',') })
    } else {
      const persona = assertions.myinfo.personas[req.params.uinfin]
      res.status(persona ? 200 : 404)
        .send(
          persona
            ? pick(persona, attributes)
            : { code: 404, message: 'UIN/FIN does not exist in MyInfo.', fields: '' }
        )
    }
  }

  const allowedAttributes = assertions.myinfo.attributes

  app.get(
    '/myinfo/person-basic/:uinfin/',
    (req, res, next) => {
      const [, authHeader] = req.get('Authorization').split(' ')
      const authHeaderFieldPairs = _(authHeader)
        .replace(/"/g, '')
        .replace(/apex_l2_eg_/g, '')
        .split(',')
        .map(v => v.replace('=', '~').split('~'))

      const authHeaderFields = _(authHeaderFieldPairs)
        .fromPairs()
        .mapKeys((v, k) => _.camelCase(k))
        .value()

      authHeaderFields.clientId = authHeaderFields.appId
      authHeaderFields.singpassEserviceId = authHeaderFields.appId.replace(/^[^-]+-/, '')

      authHeaderFields.httpMethod = req.method

      authHeaderFields.url = `${req.protocol}://${req.get('host')}${req.baseUrl}${req.path}`
      authHeaderFields.requestedAttributes = req.query.attributes

      if (verifyMyInfoSignature(authHeaderFields.signature, authHeaderFields)) {
        next()
      } else {
        res.status(403).send({ code: 403, message: 'Digital Service is invalid', fields: '' })
      }
    },
    lookupPerson(allowedAttributes.basic)
  )
  app.get('/myinfo/person/:uinfin/', (req, res) => {
    const [, token] = req.get('Authorization').split(' ')
    const { sub, scope } = jwt.verify(token, MOCKPASS_PUBLIC_KEY, { algorithms: ['RS256'] })
    if (sub !== req.params.uinfin) {
      res.status(401).send({ code: 401, message: 'UIN requested does not match logged in user', fields: '' })
    } else {
      lookupPerson(scope)(req, res)
    }
  })

  app.get('/myinfo/authorise', (req, res) => {
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
      realm: '/consent/myinfo-com',
      response_type: 'code',
    })
    const relayState = `${AUTHORIZE_ENDPOINT}${encodeURIComponent('?' + relayStateParams)}`
    res.redirect(`/singpass/logininitial?esrvcID=MYINFO-CONSENTPLATFORM&PartnerId=/consent/myinfo-com&Target=${relayState}`)
  })

  app.get(MYINFO_ASSERT_ENDPOINT, (req, res) => {
    const { SAMLart, RelayState: relayState } = req.query
    const samlArtifact = SAMLart.replace(/ /g, '+')
    const samlArtifactBuffer = Buffer.from(samlArtifact, 'base64')
    let index = samlArtifactBuffer.readInt8(samlArtifactBuffer.length - 1)
    // use env NRIC when SHOW_LOGIN_PAGE is false
    if (index === -1) {
      index = assertions.identities.singPass.indexOf(assertions.singPassNric)
    }
    const id = assertions.identities.singPass[index]
    const persona = assertions.myinfo.personas[id]
    if (!persona) {
      res.status(404).send({ message: 'Cannot find MyInfo Persona', samlArtifact, index, id, persona })
    } else {
      res.cookie('connect.sid', id)
      res.redirect(relayState)
    }
  })

  app.get(AUTHORIZE_ENDPOINT,
    cookieParser(),
    (req, res) => {
      const params = {
        ...req.query,
        scope: req.query.scope.replace(/\+/g, ' '),
        id: req.cookies['connect.sid'],
        action: AUTHORIZE_ENDPOINT,
      }

      res.send(render(CONSENT_TEMPLATE, params))
    }
  )

  app.post(AUTHORIZE_ENDPOINT,
    cookieParser(),
    bodyParser.urlencoded({ extended: false, type: 'application/x-www-form-urlencoded' }),
    (req, res) => {
      const id = req.cookies['connect.sid']
      const code = uuid()
      authorizations[code] = {
        sub: id,
        auth_level: 0,
        scope: req.body.scope.split(' '),
        iss: `${req.protocol}://${req.get('host')}/consent/oauth2/consent/myinfo-com`,
        tokenName: 'access_token',
        token_type: 'Bearer',
        authGrantId: code,
        auditTrackingId: code,
        jti: code,
        aud: 'myinfo',
        grant_type: 'authorization_code',
        realm: '/consent/myinfo-com',
      }
      const callbackParams = qs.stringify(
        req.body.decision === 'allow'
          ? {
            code,
            ...pick(req.body, ['state', 'scope', 'client_id']),
            iss: `${req.protocol}://${req.get('host')}/consent/oauth2/consent/myinfo-com`,
          }
          : {
            state: req.body.state,
            error_description: 'Resource Owner did not authorize the request',
            error: 'access_denied',
          }
      )
      res.redirect(`${req.body.redirect_uri}?${callbackParams}`)
    }
  )

  app.post('/myinfo/token',
    bodyParser.urlencoded({ extended: false, type: 'application/x-www-form-urlencoded' }),
    (req, res) => {
      const tokenTemplate = authorizations[req.body.code]
      if (!tokenTemplate) {
        res.status(400).send({ code: 400, message: 'No such authorization given', fields: '' })
      } else {
        const token = jwt.sign(
          { ...tokenTemplate, auth_time: Date.now() },
          MOCKPASS_PRIVATE_KEY,
          { expiresIn: '1800 seconds', algorithm: 'RS256' }
        )
        res.send({
          access_token: token,
          token_type: 'Bearer',
          expires_in: 1798,
        })
      }
    }
  )

  return app
}

module.exports = config
