const fs = require('fs')
const { render } = require('mustache')

const TEMPLATE = fs.readFileSync('./static/saml/unsigned-assertion.xml', 'utf8')

module.exports = {
  singPass: render(TEMPLATE, { name: 'UserName', value: 'S1234567A' }),
  corpPass: render(TEMPLATE, { name: '123456789A', value: 'invalid' }),
}
