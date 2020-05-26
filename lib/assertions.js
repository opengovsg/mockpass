const base64 = require('base-64')
const fs = require('fs')
const { render } = require('mustache')
const path = require('path')
const moment = require('moment')

const readFrom = p => fs.readFileSync(path.resolve(__dirname, p), 'utf8')

const TEMPLATE = readFrom('../static/saml/unsigned-assertion.xml')
const corpPassTemplate = readFrom('../static/saml/corppass.xml')

const myinfo = {
  v2: JSON.parse(readFrom('../static/myinfo/v2.json')),
  v3: JSON.parse(readFrom('../static/myinfo/v3.json')),
}

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
    ...Object.keys(myinfo.v3.personas),
  ],
  corpPass: [
    { NRIC: 'S8979373D', UEN: '123456789A' },
    { NRIC: 'S8116474F', UEN: '123456789A' },
    { NRIC: 'S8723211E', UEN: '123456789A' },
    { NRIC: 'S5062854Z', UEN: '123456789B' },
    { NRIC: 'T0066846F', UEN: '123456789B' },
    { NRIC: 'F9477325W', UEN: '123456789B' },
    { NRIC: 'S3000024B', UEN: '123456789C' },
    { NRIC: 'S6005040F', UEN: '123456789C' },
  ],
}

const corpPassNric = process.env.MOCKPASS_NRIC || identities.corpPass[0].NRIC
const uen = process.env.MOCKPASS_UEN || identities.corpPass[0].UEN

const defaultAudience = process.env.SERVICE_PROVIDER_ENTITY_ID || 'http://sp.example.com/demo1/metadata.php'

const makeCorpPass = (source = { NRIC: corpPassNric, UEN: uen }, issuer, recipient, inResponseTo, audience = defaultAudience) => render(
  TEMPLATE,
  {
    issueInstant: moment.utc().format(),
    name: source.UEN,
    value: base64.encode(render(corpPassTemplate, source)),
    recipient,
    issuer,
    inResponseTo,
    audience,
  }
)

const singPassNric = process.env.MOCKPASS_NRIC || identities.singPass[0]

const makeSingPass = (nric = singPassNric, issuer, recipient, inResponseTo, audience = defaultAudience) => render(
  TEMPLATE,
  {
    name: 'UserName',
    value: nric,
    issueInstant: moment.utc().format(),
    recipient,
    issuer,
    inResponseTo,
    audience,
  })

module.exports = {
  singPass: {
    create: makeSingPass,
  },
  corpPass: {
    create: makeCorpPass,
  },
  identities,
  myinfo,
  singPassNric,
  corpPassNric,
  uen,
}
