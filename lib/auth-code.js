const ExpiryMap = require('expiry-map')
const crypto = require('crypto')

const AUTH_CODE_TIMEOUT = 5 * 60 * 1000
const profileAndNonceStore = new ExpiryMap(AUTH_CODE_TIMEOUT)

const generateAuthCode = ({ profile, scopes, nonce }) => {
  const authCode = crypto.randomBytes(45).toString('base64')
  profileAndNonceStore.set(authCode, { profile, scopes, nonce })
  return authCode
}

const lookUpByAuthCode = (authCode) => {
  return profileAndNonceStore.get(authCode)
}

module.exports = { generateAuthCode, lookUpByAuthCode }
