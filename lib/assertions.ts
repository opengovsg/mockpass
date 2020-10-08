import base64 from 'base-64'
import crypto from 'crypto'
import fs from 'fs'
import { render } from 'mustache'
import moment from 'moment'
import jose from 'node-jose'
import path from 'path'
import { IMyInfoSpec } from './types/myinfo'
import { ISamlAssertion, IOidcAssertion } from './types/core'

const readFrom = (p: string) =>
  fs.readFileSync(path.resolve(__dirname, p), 'utf8')

const TEMPLATE = readFrom('../static/saml/unsigned-assertion.xml')
const corpPassTemplate = readFrom('../static/saml/corppass.xml')

const defaultAudience =
  process.env.SERVICE_PROVIDER_ENTITY_ID ||
  'http://sp.example.com/demo1/metadata.php'

const hashAccessToken = (accessToken: string): string => {
  const fullHash = crypto.createHash('sha256')
  fullHash.update(accessToken, 'utf8')
  const fullDigest = fullHash.digest()
  return fullDigest.slice(0, fullDigest.length / 2).toString('base64')
}

export const myinfo: { v2: IMyInfoSpec; v3: IMyInfoSpec } = {
  v2: JSON.parse(readFrom('../static/myinfo/v2.json')),
  v3: JSON.parse(readFrom('../static/myinfo/v3.json')),
}

export const saml: ISamlAssertion = {
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
    ...Object.keys(myinfo.v2.personas),
  ],
  corpPass: [
    { nric: 'S8979373D', uen: '123456789A' },
    { nric: 'S8116474F', uen: '123456789A' },
    { nric: 'S8723211E', uen: '123456789A' },
    { nric: 'S5062854Z', uen: '123456789B' },
    { nric: 'T0066846F', uen: '123456789B' },
    { nric: 'F9477325W', uen: '123456789B' },
    { nric: 'S3000024B', uen: '123456789C' },
    { nric: 'S6005040F', uen: '123456789C' },
  ],
  create: {
    singPass: (
      nric,
      issuer,
      recipient,
      inResponseTo,
      audience = defaultAudience,
    ) =>
      render(TEMPLATE, {
        name: 'UserName',
        value: nric,
        issueInstant: moment.utc().format(),
        recipient,
        issuer,
        inResponseTo,
        audience,
      }),
    corpPass: (
      source,
      issuer,
      recipient,
      inResponseTo,
      audience = defaultAudience,
    ) =>
      render(TEMPLATE, {
        issueInstant: moment.utc().format(),
        name: source.uen,
        value: base64.encode(render(corpPassTemplate, source)),
        recipient,
        issuer,
        inResponseTo,
        audience,
      }),
  },
}

export const oidc: IOidcAssertion = {
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
    {
      nric: 'S8979373D',
      name: 'Name of S8979373D',
      isSingPassHolder: true,
      uen: '123456789A',
    },
    {
      nric: 'S8116474F',
      name: 'Name of S8116474F',
      isSingPassHolder: true,
      uen: '123456789A',
    },
    {
      nric: 'S8723211E',
      name: 'Name of S8723211E',
      isSingPassHolder: true,
      uen: '123456789A',
    },
    {
      nric: 'S5062854Z',
      name: 'Name of S5062854Z',
      isSingPassHolder: true,
      uen: '123456789B',
    },
    {
      nric: 'T0066846F',
      name: 'Name of T0066846F',
      isSingPassHolder: true,
      uen: '123456789B',
    },
    {
      nric: 'F9477325W',
      name: 'Name of F9477325W',
      isSingPassHolder: false,
      uen: '123456789B',
    },
    {
      nric: 'S3000024B',
      name: 'Name of S3000024B',
      isSingPassHolder: true,
      uen: '123456789C',
    },
    {
      nric: 'S6005040F',
      name: 'Name of S6005040F',
      isSingPassHolder: true,
      uen: '123456789C',
    },
  ],
  create: {
    singPass: (uuid, iss, aud, nonce) => {
      const nric = oidc.singPass[uuid]
      const sub = `s=${nric},u=${uuid}`

      const accessToken = crypto.randomBytes(15).toString('hex')
      const accessTokenHash = hashAccessToken(accessToken)

      return {
        accessToken,
        idTokenClaims: {
          rt_hash: '',
          at_hash: accessTokenHash,
          iat: Date.now(),
          exp: Date.now() + 24 * 60 * 60 * 1000,
          iss,
          amr: ['pwd'],
          aud,
          sub,
          ...(nonce ? { nonce } : {}),
        },
      }
    },
    corpPass: async (uuid, iss, aud, nonce) => {
      const baseClaims = {
        iat: Date.now(),
        exp: Date.now() + 24 * 60 * 60 * 1000,
        iss,
        aud,
      }

      const profile = oidc.corpPass[uuid]
      const sub = `s=${profile.nric},u=${uuid},c=SG`

      const accessTokenClaims = {
        ...baseClaims,
        authorization: {
          EntityInfo: {},
          AccessInfo: {},
          TPAccessInfo: {},
        },
      }

      const signingPem = fs.readFileSync(
        path.resolve(__dirname, '../static/certs/spcp-key.pem'),
      )
      const signingKey = await jose.JWK.asKey(signingPem, 'pem')
      const accessTokenResult = await jose.JWS.createSign(
        { format: 'compact' },
        signingKey,
      )
        .update(JSON.stringify(accessTokenClaims))
        .final()
      // TODO: is this change okay?
      const accessToken = JSON.stringify(accessTokenResult)

      const accessTokenHash = hashAccessToken(accessToken)

      return {
        accessToken,
        idTokenClaims: {
          ...baseClaims,
          rt_hash: '',
          at_hash: accessTokenHash,
          amr: ['pwd'],
          sub,
          ...(nonce ? { nonce } : {}),
          userInfo: {
            CPAccType: 'User',
            CPUID_FullName: profile.name,
            ISSPHOLDER: profile.isSingPassHolder ? 'YES' : 'NO',
          },
        },
      }
    },
  },
}

export const singPassNric = process.env.MOCKPASS_NRIC || saml.singPass[0]
export const corpPassNric = process.env.MOCKPASS_NRIC || saml.corpPass[0].nric
export const uen = process.env.MOCKPASS_UEN || saml.corpPass[0].uen
