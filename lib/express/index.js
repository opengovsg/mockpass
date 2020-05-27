module.exports = {
  configSPCP: require('./spcp'),
  configOIDC: require('./oidc'),
  configMyInfo: {
    consent: require('./myinfo/consent').config,
    v2: require('./myinfo/v2'),
    v3: require('./myinfo/v3'),
  },
}
