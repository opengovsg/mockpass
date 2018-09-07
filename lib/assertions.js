const base64 = require('base-64')
const fs = require('fs')
const { render } = require('mustache')
const path = require('path')

const TEMPLATE = fs.readFileSync(path.resolve(__dirname, '../static/saml/unsigned-assertion.xml'), 'utf8')

const CORPPASS = base64.encode(fs.readFileSync(path.resolve(__dirname, '../static/saml/corppass.xml'), 'utf8'))

module.exports = {
  singPass: render(TEMPLATE, { name: 'UserName', value: 'S1234567A' }),
  corpPass: render(TEMPLATE, { name: '123456789A', value: CORPPASS }),
}
