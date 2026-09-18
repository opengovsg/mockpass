const crypto = require('crypto')
const fs = require('fs')
const jose = require('node-jose')
const path = require('path')

const readFrom = (p) => fs.readFileSync(path.resolve(__dirname, p), 'utf8')

const signingPem = fs.readFileSync(
  path.resolve(__dirname, '../static/certs/spcp-key.pem'),
)

const hashToken = (token) => {
  const fullHash = crypto.createHash('sha256')
  fullHash.update(token, 'utf8')
  const fullDigest = fullHash.digest()
  const digestBuffer = fullDigest.slice(0, fullDigest.length / 2)
  if (Buffer.isEncoding('base64url')) {
    return digestBuffer.toString('base64url')
  } else {
    const fromBase64 = (base64String) =>
      base64String.replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_')
    return fromBase64(digestBuffer.toString('base64'))
  }
}

const myinfo = {
  v3: JSON.parse(
    readFrom(process.env.MYINFO_V3_USERS_PATH || '../static/myinfo/v3.json'),
  ),
}

const singPassUsers = JSON.parse(
  readFrom(process.env.SINGPASS_USERS_PATH || '../static/singpass/users.json'),
)
const corpPassUsers = JSON.parse(
  readFrom(process.env.CORPPASS_USERS_PATH || '../static/corppass/users.json'),
)

const oidc = {
  singPass: [
    ...singPassUsers,
    ...Object.keys(myinfo.v3.personas).map((nric) => ({
      nric,
      uuid: myinfo.v3.personas[nric].uuid.value,
      claims: myinfo.v3.personas[nric],
    })),
  ],
  corpPass: corpPassUsers,
  create: {
    singPass: (
      { nric, uuid, sfa },
      iss,
      aud,
      nonce,
      accessToken = crypto.randomBytes(15).toString('hex'),
    ) => {
      let sub
      if (nric.startsWith('Y')) {
        const sfaAccount = sfa || {
          fid: 'G730Z-H5P96',
          coi: 'DE',
          RP: 'CORPPASS',
        }
        sub = `s=${nric},fid=${sfaAccount.fid},coi=${sfaAccount.coi},u=${uuid}`
      } else {
        sub = `s=${nric},u=${uuid}`
      }
      const accessTokenHash = hashToken(accessToken)

      const refreshToken = crypto.randomBytes(20).toString('hex')
      const refreshTokenHash = hashToken(refreshToken)

      return {
        accessToken,
        refreshToken,
        idTokenClaims: {
          rt_hash: refreshTokenHash,
          at_hash: accessTokenHash,
          iat: Math.floor(Date.now() / 1000),
          exp: Math.floor(Date.now() / 1000) + 24 * 60 * 60,
          iss,
          amr: ['pwd'],
          aud,
          sub,
          ...(nonce ? { nonce } : {}),
        },
      }
    },
    corpPass: async (
      { nric, uuid, name, isSingPassHolder, uen },
      iss,
      aud,
      nonce,
    ) => {
      const baseClaims = {
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 24 * 60 * 60,
        iss,
        aud,
      }

      const sub = `s=${nric},uuid=${uuid},u=${uen}${nric},c=SG`

      const accessTokenClaims = {
        ...baseClaims,
        authorization: {
          EntityInfo: {},
          AccessInfo: {},
          TPAccessInfo: {},
        },
      }

      const signingKey = await jose.JWK.asKey(signingPem, 'pem')
      const accessToken = await jose.JWS.createSign(
        { format: 'compact' },
        signingKey,
      )
        .update(JSON.stringify(accessTokenClaims))
        .final()

      const accessTokenHash = hashToken(accessToken)

      const refreshToken = crypto.randomBytes(20).toString('hex')
      const refreshTokenHash = hashToken(refreshToken)

      return {
        accessToken,
        refreshToken,
        idTokenClaims: {
          ...baseClaims,
          rt_hash: refreshTokenHash,
          at_hash: accessTokenHash,
          amr: ['pwd'],
          sub,
          ...(nonce ? { nonce } : {}),
          userInfo: {
            CPAccType: 'User',
            CPUID_FullName: name,
            ISSPHOLDER: isSingPassHolder ? 'YES' : 'NO',
          },
          entityInfo: {
            CPEntID: uen,
            CPEnt_TYPE: 'UEN',
            CPEnt_Status: 'Registered',
            CPNonUEN_Country: '',
            CPNonUEN_RegNo: '',
            CPNonUEN_Name: '',
          },
        },
      }
    },
  },
}

module.exports = {
  oidc,
  myinfo,
}
