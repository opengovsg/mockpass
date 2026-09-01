const ExpiryMap = require('expiry-map')
const crypto = require('crypto')

const AUTH_CODE_TIMEOUT = 5 * 60 * 1000
const profileAndNonceStore = new ExpiryMap(AUTH_CODE_TIMEOUT)

const FAPI_ACCESS_TOKEN_EXPIRY_SECONDS = 30 * 60
const fapiAccessTokenStore = new ExpiryMap(
  FAPI_ACCESS_TOKEN_EXPIRY_SECONDS * 1000,
)

const generateAuthCode = (
  { profile, scopes, nonce, clientId = '' },
  { isStateless = false },
) => {
  const authCode = isStateless
    ? Buffer.from(
        JSON.stringify({ profile, scopes, nonce, clientId }),
      ).toString('base64url')
    : crypto.randomBytes(45).toString('base64')

  profileAndNonceStore.set(authCode, { profile, scopes, nonce, clientId })
  return authCode
}

const generateAuthCodeForFapi = ({ profile, clientId = '', authRequest }) => {
  const authCode = crypto.randomBytes(45).toString('base64url')

  profileAndNonceStore.set(authCode, { profile, clientId, authRequest })
  return authCode
}

const lookUpByAuthCode = (authCode, { isStateless = false }) => {
  return isStateless
    ? JSON.parse(Buffer.from(authCode, 'base64url').toString('utf-8'))
    : profileAndNonceStore.get(authCode)
}

const generateAccessTokenForFapi = ({ profile, authRequest, dpopJkt }) => {
  const accessToken = crypto.randomBytes(64).toString('base64url')

  fapiAccessTokenStore.set(accessToken, { profile, authRequest, dpopJkt })
  return accessToken
}

const lookUpByAccessToken = (accessToken) =>
  fapiAccessTokenStore.get(accessToken)

module.exports = {
  FAPI_ACCESS_TOKEN_EXPIRY_SECONDS,
  generateAccessTokenForFapi,
  generateAuthCode,
  generateAuthCodeForFapi,
  lookUpByAccessToken,
  lookUpByAuthCode,
}
