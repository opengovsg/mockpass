const base64 = require('base-64')
const fs = require('fs')
const { render } = require('mustache')
const path = require('path')

const readFrom = p => fs.readFileSync(path.resolve(__dirname, p), 'utf8')

const TEMPLATE = readFrom('../static/saml/unsigned-assertion.xml')
const corpPassTemplate = readFrom('../static/saml/corppass.xml')

const identities = {
  singPass: ['S8979373D', 'S1234567A'],
  corpPass: [
    { NRIC: 'S8979373D', UEN: '123456789A' },
  ],
}

const makeCorpPass = ({ NRIC, UEN }) => render(
  TEMPLATE,
  {
    name: UEN,
    value: base64.encode(render(corpPassTemplate, { NRIC, UEN })),
  }
)

const makeSingPass = NRIC => render(TEMPLATE, { name: 'UserName', value: NRIC })

const NRIC = process.env.MOCKPASS_NRIC || identities.singPass[0]
const CORPPASS_NRIC = process.env.MOCKPASS_NRIC || identities.corpPass[0].NRIC
const UEN = process.env.MOCKPASS_UEN || identities.corpPass[0].UEN

module.exports = {
  singPass: {
    default: makeSingPass(NRIC),
    create: makeSingPass,
  },
  corpPass: {
    default: makeCorpPass({ NRIC: CORPPASS_NRIC, UEN }),
    create: makeCorpPass,
  },
  identities,
}
