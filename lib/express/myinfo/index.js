const { config: consent } = require('./consent')
const controllers = require('./controllers')

const { pki } = require('../../crypto/myinfo-signature')

module.exports = {
  consent,
  v3: controllers('v3', pki),
}
