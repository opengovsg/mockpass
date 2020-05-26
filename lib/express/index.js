module.exports = {
  configSpcp: require('./spcp'),
  configMyInfo: {
    consent: require('./myinfo/consent').config,
    v2: require('./myinfo/v2'),
    v3: require('./myinfo/v3'),
  },
}
