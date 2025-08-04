const ExpiryMap = require('expiry-map')
const crypto = require('crypto')

const AUTH_CODE_TIMEOUT = 5 * 60 * 1000
const profileAndNonceStore = new ExpiryMap(AUTH_CODE_TIMEOUT)

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

const lookUpByAuthCode = (authCode, { isStateless = false }) => {
  return isStateless
    ? JSON.parse(Buffer.from(authCode, 'base64url').toString('utf-8'))
    : profileAndNonceStore.get(authCode)
}

module.exports = { generateAuthCode, lookUpByAuthCode }
