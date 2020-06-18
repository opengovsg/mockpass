const { config: consent } = require('./consent')
const controllers = require('./controllers')

const { pki, apex } = require('../../crypto/myinfo-signature')

module.exports = {
  consent,
  v2: controllers('v2', apex),
  v3: controllers('v3', pki),
}
