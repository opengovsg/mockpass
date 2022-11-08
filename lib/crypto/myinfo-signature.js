const _ = require('lodash')
const qs = require('node:querystring')

const pki = function pki(authHeader, req, context = {}) {
  const authHeaderFieldPairs = _(authHeader)
    .replace(/"/g, '')
    .split(',')
    .map((v) => v.replace('=', '~').split('~'))

  const authHeaderFields = Object.fromEntries(authHeaderFieldPairs)

  const url = `${req.protocol}://${req.get('host')}${req.baseUrl}${req.path}`

  const { method: httpMethod, query, body } = req

  const { signature, app_id, nonce, timestamp } = authHeaderFields

  const params = Object.assign(
    {},
    query,
    body,
    {
      nonce,
      app_id,
      signature_method: 'RS256',
      timestamp,
    },
    context.client_secret && context.redirect_uri ? context : {},
  )

  const sortedParams = Object.fromEntries(
    Object.entries(params).sort(([k1], [k2]) => k1.localeCompare(k2)),
  )

  const baseString =
    httpMethod.toUpperCase() +
    '&' +
    url +
    '&' +
    qs.unescape(qs.stringify(sortedParams))

  return { signature, baseString }
}

module.exports = { pki }
