const base64 = require('base-64')
const fs = require('fs')
const { render } = require('mustache')
const path = require('path')

const readFrom = p => fs.readFileSync(path.resolve(__dirname, p), 'utf8')

const TEMPLATE = readFrom('../static/saml/unsigned-assertion.xml')
const corpPassTemplate = readFrom('../static/saml/corppass.xml')

const NRIC = process.env.MOCKPASS_NRIC || 'S8979373D'
const UEN = process.env.MOCKPASS_UEN || '123456789A'

const CORPPASS = base64.encode(render(corpPassTemplate, { NRIC, UEN }))

module.exports = {
  singPass: render(TEMPLATE, { name: 'UserName', value: NRIC }),
  corpPass: render(TEMPLATE, { name: UEN, value: CORPPASS }),
}
