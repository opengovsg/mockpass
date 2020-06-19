const _ = require('lodash')

const apex = function apex(authHeader, req, isPersonRequest) {
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
  authHeaderFields.attributes = req.query.attributes

  const {
    signature,
    httpMethod,
    url,
    appId,
    clientId,
    singpassEserviceId,
    nonce,
    attributes,
    timestamp,
  } = authHeaderFields

  const baseString = isPersonRequest
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
      '&attributes=' +
      attributes +
      '&client_id=' +
      clientId
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
      '&singpassEserviceId=' +
      singpassEserviceId

  return {
    signature,
    baseString,
  }
}

const pki = function pki(authHeader, req, isPersonRequest) {
  const authHeaderFieldPairs = _(authHeader)
    .replace(/"/g, '')
    .split(',')
    .map((v) => v.replace('=', '~').split('~'))

  const authHeaderFields = _(authHeaderFieldPairs)
    .fromPairs()
    .mapKeys((v, k) => _.camelCase(k))
    .value()

  authHeaderFields.clientId = authHeaderFields.appId
  authHeaderFields.httpMethod = req.method
  authHeaderFields.url = `${req.protocol}://${req.get('host')}${req.baseUrl}${
    req.path
  }`
  authHeaderFields.attributes = req.query.attributes

  const {
    signature,
    httpMethod,
    appId,
    clientId,
    nonce,
    timestamp,
    attributes,
    url,
  } = authHeaderFields
  return {
    signature,
    baseString: isPersonRequest
      ? httpMethod.toUpperCase() +
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
        '&timestamp=' +
        timestamp
      : httpMethod.toUpperCase() +
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
