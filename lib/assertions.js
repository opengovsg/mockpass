const base64 = require('base-64')
const fs = require('fs')
const { render } = require('mustache')
const path = require('path')

const readFrom = p => fs.readFileSync(path.resolve(__dirname, p), 'utf8')

const TEMPLATE = readFrom('../static/saml/unsigned-assertion.xml')
const corpPassTemplate = readFrom('../static/saml/corppass.xml')

const myinfo = JSON.parse(readFrom('../static/myinfo.json'))

const identities = {
  singPass: [
    'S8979373D',
    'S8116474F',
    'S8723211E',
    'S5062854Z',
    'T0066846F',
    'F9477325W',
    'S3000024B',
    'S6005040F',
    'S6005041D',
    'S6005042B',
    'S6005043J',
    'S6005044I',
    'S6005045G',
    'S6005046E',
    'S6005047C',
    'S6005064C',
    'S6005065A',
    'S6005066Z',
    'S6005037F',
    'S6005038D',
    'S6005039B',
    'G1612357P',
    'G1612358M',
    'F1612359P',
    'F1612360U',
    'F1612361R',
    'F1612362P',
    'F1612363M',
    'F1612364K',
    'F1612365W',
    'F1612366T',
    'F1612367Q',
    'F1612358R',
    'F1612354N',
    'F1612357U',
    ...Object.keys(myinfo.personas),
  ],
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
  myinfo,
}
