const _ = require('lodash')

const apex = function apex(authHeader, req, context = {}) {
  const authHeaderFieldPairs = _(authHeader)
    .replace(/"/g, '')
    .replace(/apex_l2_eg_/g, '')
    .split(',')
    .map((v) => v.replace('=', '~').split('~'))

  const authHeaderFields = _(authHeaderFieldPairs)
    .fromPairs()
    .mapKeys((v, k) => _.camelCase(k))
    .value()

  const url = `${req.protocol}://${req.get('host')}${req.baseUrl}${req.path}`

  const { clientSecret, redirectURI } = context

  const {
    method: httpMethod,
    query: { attributes, singpassEserviceId },
  } = req

  const { code } = req.body || {}

  const {
    signature,
    appId,
    appId: clientId,
    nonce,
    timestamp,
  } = authHeaderFields

  const baseString = req.path.endsWith('/token')
    ? httpMethod.toUpperCase() +
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
      '&client_id=' +
      clientId +
      '&client_secret=' +
      clientSecret +
      '&code=' +
      code +
      '&grant_type=authorization_code' +
      '&redirect_uri=' +
      redirectURI
    : httpMethod.toUpperCase() +
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
      attributes +
      '&client_id=' +
      clientId +
      (req.path.includes('/person-basic')
        ? '&singpassEserviceId=' + singpassEserviceId
        : '')

  return {
    signature,
    baseString,
  }
}

const pki = function pki(authHeader, req, context = {}) {
  const authHeaderFieldPairs = _(authHeader)
    .replace(/"/g, '')
    .split(',')
    .map((v) => v.replace('=', '~').split('~'))

  const authHeaderFields = _(authHeaderFieldPairs)
    .fromPairs()
    .mapKeys((_v, k) => _.camelCase(k))
    .value()

  const url = `${req.protocol}://${req.get('host')}${req.baseUrl}${req.path}`

  const { clientSecret, redirectURI } = context

  const {
    method: httpMethod,
    query: { attributes, sp_esvcId },
  } = req

  const { code } = req.body || {}

  const {
    signature,
    appId,
    appId: clientId,
    nonce,
    timestamp,
  } = authHeaderFields
  return {
    signature,
    baseString: req.path.endsWith('/token')
      ? httpMethod.toUpperCase() +
        '&' +
        url +
        '&app_id=' +
        appId +
        '&client_id=' +
        clientId +
        '&client_secret=' +
        clientSecret +
        '&code=' +
        code +
        '&grant_type=authorization_code' +
        '&nonce=' +
        nonce +
        '&redirect_uri=' +
        redirectURI +
        '&signature_method=RS256' +
        '&timestamp=' +
        timestamp
      : httpMethod.toUpperCase() +
        '&' +
        url +
        '&app_id=' +
        appId +
        '&attributes=' +
        attributes +
        '&client_id=' +
        clientId +
        '&nonce=' +
        nonce +
        '&signature_method=RS256' +
        (req.path.includes('/person-basic') ? '&sp_esvcId=' + sp_esvcId : '') +
        '&timestamp=' +
        timestamp,
  }
}

module.exports = { pki, apex }
