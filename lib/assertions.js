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
  v3: JSON.parse(readFrom('../static/myinfo/v3.json')),
}

const oidc = {
  singPass: [
    { nric: 'S8979373D', uuid: 'a9865837-7bd7-46ac-bef4-42a76a946424' },
    { nric: 'S8116474F', uuid: 'f4b70aea-d639-4b79-b8d9-8ace5875f6b1' },
    { nric: 'S8723211E', uuid: '178478de-fed7-4c03-a75e-e68c44d0d5f0' },
    { nric: 'S5062854Z', uuid: '1bd2e743-8681-4079-a557-6a66a8d16386' },
    { nric: 'T0066846F', uuid: '14f7ee8f-9e64-4170-a529-e55ca7578e2b' },
    { nric: 'F9477325W', uuid: '2135fe5c-d07b-49d3-b960-aabb0ff2e05a' },
    { nric: 'S3000024B', uuid: 'b5630beb-e3ee-4a31-aec5-534cdc087fd8' },
    { nric: 'S6005040F', uuid: '6c6745d9-e6c5-40ee-8c96-5d737ddbc5e4' },
    { nric: 'S6005041D', uuid: 'bd3fd1e0-c807-4b07-bbe4-b567cab54b8c' },
    { nric: 'S6005042B', uuid: '2dd788c0-d11f-4d5b-99af-b89d2389b474' },
    { nric: 'S6005043J', uuid: 'eb196477-36b3-4c0f-ae5e-2172e2f6a6d8' },
    { nric: 'S6005044I', uuid: '843ebc6b-1de1-4d46-b1dd-9ad4aeac3a27' },
    { nric: 'S6005045G', uuid: 'caafaedc-f369-498a-9e35-27e9cb7f0de2' },
    { nric: 'S6005046E', uuid: 'f9b37d06-de3f-4c4f-8331-37a3b2ee6cb4' },
    { nric: 'S6005047C', uuid: '57620e0f-fdf9-4f3e-a8f6-f6088e151395' },
    { nric: 'S6005064C', uuid: '80952b2f-3455-4b59-b50f-39afbc418271' },
    { nric: 'S6005065A', uuid: '3af48e26-69a1-43e3-b5f2-303098ef3210' },
    { nric: 'S6005066Z', uuid: '8b2f8213-2fe9-493a-ac95-0b55e319e689' },
    { nric: 'S6005037F', uuid: 'ae3d1d8c-6d14-449e-8ed1-9ce3d5e67607' },
    { nric: 'S6005038D', uuid: '23d3bb45-a324-46d6-b0d9-2e94194ed9ae' },
    { nric: 'S6005039B', uuid: '9ac807a2-5217-417a-a8d1-d7018b002b3f' },
    { nric: 'G1612357P', uuid: 'eb125a02-3137-486f-9262-eab3e0c57a5f' },
    { nric: 'G1612358M', uuid: 'd821900c-663d-4552-a753-a2e1cf8d124f' },
    { nric: 'F1612359P', uuid: '08df8d35-600c-45fd-a812-b37a27b7856a' },
    { nric: 'F1612360U', uuid: '1e90b698-23af-4acb-9fb4-eb5a80f444b6' },
    { nric: 'F1612361R', uuid: 'bc134ee1-f104-4b26-9839-32047fecb963' },
    { nric: 'F1612362P', uuid: '285e8366-f3bd-48b4-8153-b47260fc9f56' },
    { nric: 'F1612363M', uuid: '379bc106-d3db-492c-a38e-fd27642ef47f' },
    { nric: 'F1612364K', uuid: '108fa3ff-c85c-461e-ba1f-8edef62b68e2' },
    { nric: 'F1612365W', uuid: '1275ae4e-02d2-4b09-9573-36ac610ede89' },
    { nric: 'F1612366T', uuid: '23c6a3a4-d9d8-445f-a588-9d91831980a6' },
    { nric: 'F1612367Q', uuid: '0c400961-eb00-425a-8df4-6656b0b9245a' },
    { nric: 'F1612358R', uuid: '45669f5c-e9ac-43c6-bcd2-9c3757f1fa1c' },
    { nric: 'F1612354N', uuid: 'c38ddb2d-9e5d-45c2-bb70-8ccb54fc8320' },
    { nric: 'F1612357U', uuid: 'f904a2b1-4b61-47e2-bdad-e2d606325e20' },
    ...Object.keys(myinfo.v3.personas).map((nric) => ({
      nric,
      uuid: myinfo.v3.personas[nric].uuid.value,
    })),
  ],
  corpPass: [
    {
      nric: 'S8979373D',
      uuid: 'a9865837-7bd7-46ac-bef4-42a76a946424',
      name: 'Name of S8979373D',
      isSingPassHolder: true,
      uen: '123456789A',
    },
    {
      nric: 'S8116474F',
      uuid: 'f4b70aea-d639-4b79-b8d9-8ace5875f6b1',
      name: 'Name of S8116474F',
      isSingPassHolder: true,
      uen: '123456789A',
    },
    {
      nric: 'S8723211E',
      uuid: '178478de-fed7-4c03-a75e-e68c44d0d5f0',
      name: 'Name of S8723211E',
      isSingPassHolder: true,
      uen: '123456789A',
    },
    {
      nric: 'S5062854Z',
      uuid: '1bd2e743-8681-4079-a557-6a66a8d16386',
      name: 'Name of S5062854Z',
      isSingPassHolder: true,
      uen: '123456789B',
    },
    {
      nric: 'T0066846F',
      uuid: '14f7ee8f-9e64-4170-a529-e55ca7578e2b',
      name: 'Name of T0066846F',
      isSingPassHolder: true,
      uen: '123456789B',
    },
    {
      nric: 'F9477325W',
      uuid: '2135fe5c-d07b-49d3-b960-aabb0ff2e05a',
      name: 'Name of F9477325W',
      isSingPassHolder: false,
      uen: '123456789B',
    },
    {
      nric: 'S3000024B',
      uuid: 'b5630beb-e3ee-4a31-aec5-534cdc087fd8',
      name: 'Name of S3000024B',
      isSingPassHolder: true,
      uen: '123456789C',
    },
    {
      nric: 'S6005040F',
      uuid: '6c6745d9-e6c5-40ee-8c96-5d737ddbc5e4',
      name: 'Name of S6005040F',
      isSingPassHolder: true,
      uen: '123456789C',
    },
  ],
  create: {
    singPass: (
      { nric, uuid },
      iss,
      aud,
      nonce,
      accessToken = crypto.randomBytes(15).toString('hex'),
    ) => {
      const sub = `s=${nric},u=${uuid}`

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

      const sub = `s=${nric},u=${uuid},c=SG`

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
