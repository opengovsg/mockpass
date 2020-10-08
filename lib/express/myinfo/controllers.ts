import crypto from 'crypto'
import fs from 'fs'
import path from 'path'

import bodyParser from 'body-parser'
import { pick, partition } from 'lodash'

import jose from 'node-jose'
import jwt from 'jsonwebtoken'
import { Express, RequestHandler } from 'express'

import * as assertions from '../../assertions'
import * as consent from './consent'
import {
  MyInfoVersion,
  MyInfoSignatureFn,
  IConfigOptions,
} from '../../types/core'

const MOCKPASS_PRIVATE_KEY = fs.readFileSync(
  path.resolve(__dirname, '../../../static/certs/spcp-key.pem'),
)
const MOCKPASS_PUBLIC_KEY = fs.readFileSync(
  path.resolve(__dirname, '../../../static/certs/spcp.crt'),
)

const MYINFO_SECRET = process.env.SERVICE_PROVIDER_MYINFO_SECRET

export default (version: MyInfoVersion, myInfoSignature: MyInfoSignatureFn) => (
  app: Express,
  { serviceProvider, encryptMyInfo }: IConfigOptions,
): Express => {
  const verify = (signature: string, baseString: string): boolean => {
    const verifier = crypto.createVerify('RSA-SHA256')
    verifier.update(baseString)
    verifier.end()
    return verifier.verify(serviceProvider.pubKey, signature, 'base64')
  }

  // eslint-disable-next-line @typescript-eslint/ban-types
  const encryptPersona = async (persona: object): Promise<string> => {
    const signedPersona =
      version === 'v3'
        ? jwt.sign(persona, MOCKPASS_PRIVATE_KEY, {
            algorithm: 'RS256',
          })
        : persona
    const serviceCertAsKey = await jose.JWK.asKey(serviceProvider.cert, 'pem')
    const encryptedAndSignedPersona = await jose.JWE.createEncrypt(
      { format: 'compact' },
      serviceCertAsKey,
    )
      .update(JSON.stringify(signedPersona))
      .final()
    return encryptedAndSignedPersona
  }

  const lookupPerson = (
    allowedAttributes: string[],
  ): RequestHandler<
    { uinfin: string },
    unknown,
    unknown,
    { attributes: string }
  > => async (req, res) => {
    const requestedAttributes = (req.query.attributes || '').split(',')

    const [attributes, disallowedAttributes] = partition(
      requestedAttributes,
      (v) => allowedAttributes.includes(v),
    )

    if (disallowedAttributes.length > 0) {
      res.status(401).send({
        code: 401,
        message: 'Disallowed',
        fields: disallowedAttributes.join(','),
      })
    } else {
      const transformPersona = encryptMyInfo
        ? encryptPersona
        : (person: unknown) => person
      const persona = assertions.myinfo[version].personas[req.params.uinfin]
      res.status(persona ? 200 : 404).send(
        persona
          ? await transformPersona(pick(persona, attributes))
          : {
              code: 404,
              message: 'UIN/FIN does not exist in MyInfo.',
              fields: '',
            },
      )
    }
  }

  const allowedAttributes = assertions.myinfo[version].attributes

  app.get(
    `/myinfo/${version}/person-basic/:uinfin/`,
    (req, res, next) => {
      // sp_esvcId and txnNo needed as query params
      const [, authHeader] = req.get('Authorization')!.split(' ')

      const { signature, baseString } = myInfoSignature(authHeader, req)
      if (verify(signature, baseString)) {
        next()
      } else {
        res.status(403).send({
          code: 403,
          message: `Signature verification failed, ${baseString} does not result in ${signature}`,
          fields: '',
        })
      }
    },
    lookupPerson(allowedAttributes.basic),
  )
  app.get(`/myinfo/${version}/person/:uinfin/`, (req, res) => {
    const authz = req.get('Authorization')!.split(' ')
    const token = authz.pop()!

    const authHeader = (authz[1] || '').replace(',Bearer', '')
    const signatureResult = encryptMyInfo
      ? myInfoSignature(authHeader, req)
      : undefined
    const signature = signatureResult?.signature
    const baseString = signatureResult?.baseString

    const { sub, scope } = jwt.verify(token, MOCKPASS_PUBLIC_KEY, {
      algorithms: ['RS256'],
    })
    if (encryptMyInfo && !verify(signature, baseString)) {
      res.status(401).send({
        code: 401,
        message: `Signature verification failed, ${baseString} does not result in ${signature}`,
      })
    } else if (sub !== req.params.uinfin) {
      res.status(401).send({
        code: 401,
        message: 'UIN requested does not match logged in user',
      })
    } else {
      lookupPerson(scope)(req, res)
    }
  })

  app.get(
    `/myinfo/${version}/authorise`,
    version === 'v3' ? consent.authorizeViaOIDC : consent.authorizeViaSAML,
  )

  app.post(
    `/myinfo/${version}/token`,
    bodyParser.urlencoded({
      extended: false,
      type: 'application/x-www-form-urlencoded',
    }),
    (req, res) => {
      const [tokenTemplate, redirectURI] = consent.authorizations[req.body.code]
      const [, authHeader] = (req.get('Authorization') || '').split(' ')

      const { signature, baseString } = MYINFO_SECRET
        ? myInfoSignature(authHeader, req, {
            clientSecret: MYINFO_SECRET,
            redirectURI,
          })
        : {}

      if (!tokenTemplate) {
        res.status(400).send({
          code: 400,
          message: 'No such authorization given',
          fields: '',
        })
      } else if (MYINFO_SECRET && !verify(signature, baseString)) {
        res.status(403).send({
          code: 403,
          message: `Signature verification failed, ${baseString} does not result in ${signature}`,
        })
      } else {
        const token = jwt.sign(
          { ...tokenTemplate, auth_time: Date.now() },
          MOCKPASS_PRIVATE_KEY,
          { expiresIn: '1800 seconds', algorithm: 'RS256' },
        )
        res.send({
          access_token: token,
          token_type: 'Bearer',
          expires_in: 1798,
        })
      }
    },
  )

  return app
}
