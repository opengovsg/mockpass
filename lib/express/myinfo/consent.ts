import bodyParser from 'body-parser'
import cookieParser from 'cookie-parser'
import fs from 'fs'
import { pick } from 'lodash'
import { render } from 'mustache'
import path from 'path'
import qs from 'querystring'
import { v1 as uuid } from 'uuid'
import { Express, RequestHandler, Request } from 'express'
import * as assertions from '../../assertions'

const MYINFO_ASSERT_ENDPOINT = '/consent/myinfo-com'
const AUTHORIZE_ENDPOINT = '/consent/oauth2/authorize'
const CONSENT_TEMPLATE = fs.readFileSync(
  path.resolve(__dirname, '../../../static/html/consent.html'),
  'utf8',
)

export const authorizations: Record<string, unknown> = {}

const authorize = (
  redirectTo: (relayState: string) => string,
): RequestHandler<
  unknown,
  unknown,
  unknown,
  {
    client_id: string
    attributes: string
    redirect_uri: string
    purpose: string
    state: string
  }
> => (req, res) => {
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

export const authorizeViaSAML = authorize(
  (relayState) =>
    `/singpass/logininitial?esrvcID=MYINFO-CONSENTPLATFORM&PartnerId=${MYINFO_ASSERT_ENDPOINT}&Target=${relayState}`,
)

export const authorizeViaOIDC = authorize(
  (relayState) =>
    `/singpass/authorize?client_id=MYINFO-CONSENTPLATFORM&redirect_uri=${MYINFO_ASSERT_ENDPOINT}&state=${relayState}`,
)

export const config = (app: Express): Express => {
  app.get(
    MYINFO_ASSERT_ENDPOINT,
    (
      req: Request<
        unknown,
        unknown,
        unknown,
        { SAMLart: string; code: string; RelayState: string; state: string }
      >,
      res,
    ) => {
      const rawArtifact = req.query.SAMLart || req.query.code
      const state = req.query.RelayState || req.query.state
      const artifact = rawArtifact.replace(/ /g, '+')
      const artifactBuffer = Buffer.from(artifact, 'base64')
      let index = artifactBuffer.readInt8(artifactBuffer.length - 1)

      const assertionType = req.query.code ? 'oidc' : 'saml'

      // use env NRIC when SHOW_LOGIN_PAGE is false
      if (index === -1) {
        index = assertions[assertionType].singPass.indexOf(
          assertions.singPassNric,
        )
      }
      const id = assertions[assertionType].singPass[index]
      const persona =
        assertions.myinfo[req.query.code ? 'v3' : 'v2'].personas[id]
      if (!persona) {
        res.status(404).send({
          message: 'Cannot find MyInfo Persona',
          artifact,
          index,
          id,
          persona,
        })
      } else {
        res.cookie('connect.sid', id)
        res.redirect(state)
      }
    },
  )

  app.get(
    AUTHORIZE_ENDPOINT,
    cookieParser(),
    (req: Request<unknown, unknown, unknown, { scope: string }>, res) => {
      const params = {
        ...req.query,
        scope: req.query.scope.replace(/\+/g, ' '),
        id: req.cookies['connect.sid'],
        action: AUTHORIZE_ENDPOINT,
      }

      res.send(render(CONSENT_TEMPLATE, params))
    },
  )

  app.post(
    AUTHORIZE_ENDPOINT,
    cookieParser(),
    bodyParser.urlencoded({
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
              error_description: 'Resource Owner did not authorize the request',
              error: 'access_denied',
            },
      )
      res.redirect(`${req.body.redirect_uri}?${callbackParams}`)
    },
  )

  return app
}
