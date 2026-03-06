module.exports = {
  ...require('./oidc'),
  configMyInfo: require('./myinfo'),
  configSGID: require('./sgid'),
  configSignV3: require('./signv3'),
  configFapi: require('./fapi/fapi.controller'),
}
