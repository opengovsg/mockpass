// Unlike the other FAPI endpoints, /userinfo answers with the OAuth error shape.
class UserInfoError extends Error {
  constructor(error, description, status) {
    super(description)
    this.error = error
    this.status = status
  }
}

const invalidToken = (description) =>
  new UserInfoError('invalid_token', description, 401)

const invalidDpopProof = (description) =>
  new UserInfoError('invalid_dpop_proof', description, 401)

const invalidRequest = (description) =>
  new UserInfoError('invalid_request', description, 400)

function sendUserInfoError(res, caught) {
  const known = caught instanceof UserInfoError
  const status = known ? caught.status : 500
  const error = known ? caught.error : 'server_error'
  const error_description = caught.message

  if (status === 401) {
    res.set(
      'WWW-Authenticate',
      `DPoP error="${error}", error_description="${error_description}"`,
    )
  }
  return res.status(status).send({ error, error_description })
}

module.exports = {
  invalidDpopProof,
  invalidRequest,
  invalidToken,
  sendUserInfoError,
}
