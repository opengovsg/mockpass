const _ = require('lodash')

const apex = function apex(authHeader, req) {
  const authHeaderFieldPairs = _(authHeader)
    .replace(/"/g, '')
    .replace(/apex_l2_eg_/g, '')
    .split(',')
    .map((v) => v.replace('=', '~').split('~'))

  const authHeaderFields = _(authHeaderFieldPairs)
    .fromPairs()
    .mapKeys((v, k) => _.camelCase(k))
    .value()

  authHeaderFields.clientId = authHeaderFields.appId
  authHeaderFields.singpassEserviceId = req.query.singpassEserviceId

  authHeaderFields.httpMethod = req.method

  authHeaderFields.url = `${req.protocol}://${req.get('host')}${req.baseUrl}${
    req.path
  }`
  authHeaderFields.requestedAttributes = req.query.attributes

  const {
    signature,
    httpMethod,
    url,
    appId,
    clientId,
    singpassEserviceId,
    nonce,
    requestedAttributes,
    timestamp,
  } = authHeaderFields

  const baseString =
    httpMethod.toUpperCase() +
    // url string replacement was dictated by MyInfo docs - no explanation
    // was provided for why this is necessary
    '&' +
    url.replace('.api.gov.sg', '.e.api.gov.sg') +
    '&apex_l2_eg_app_id=' +
    appId +
    '&apex_l2_eg_nonce=' +
    nonce +
    '&apex_l2_eg_signature_method=SHA256withRSA' +
    '&apex_l2_eg_timestamp=' +
    timestamp +
    '&apex_l2_eg_version=1.0' +
    '&attributes=' +
    requestedAttributes +
    '&client_id=' +
    clientId +
    '&singpassEserviceId=' +
    singpassEserviceId

  console.log(authHeaderFields, signature, baseString)
  return {
    signature,
    baseString,
  }
}

const pki = function pki(authHeader, req) {
  const authHeaderFieldPairs = _(authHeader)
    .replace(/"/g, '')
    .split(',')
    .map((v) => v.replace('=', '~').split('~'))

  const authHeaderFields = _(authHeaderFieldPairs)
    .fromPairs()
    .mapKeys((v, k) => _.camelCase(k))
    .value()

  authHeaderFields.httpMethod = req.method

  const { signature, httpMethod, appId, nonce, timestamp } = authHeaderFields
  return {
    signature,
    baseString:
      httpMethod.toUpperCase() +
      '&app_id=' +
      appId +
      '&nonce=' +
      nonce +
      '&signature_method=RS256' +
      '&timestamp=' +
      timestamp,
  }
}

module.exports = { pki, apex }
