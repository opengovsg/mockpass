const crypto = require('crypto')
const fs = require('fs')
const path = require('path')

const express = require('express')
const { pick, partition } = require('lodash')

const jose = require('jose')
const jwt = require('jsonwebtoken')

const assertions = require('../../assertions')
const consent = require('./consent')

const MOCKPASS_PRIVATE_KEY = fs.readFileSync(
  path.resolve(__dirname, '../../../static/certs/spcp-key.pem'),
)
const MOCKPASS_PUBLIC_KEY = fs.readFileSync(
  path.resolve(__dirname, '../../../static/certs/spcp.crt'),
)

const MYINFO_SECRET = process.env.SERVICE_PROVIDER_MYINFO_SECRET

module.exports =
  (version, myInfoSignature) =>
  (app, { serviceProvider, encryptMyInfo }) => {
    const verify = (signature, baseString) => {
      const verifier = crypto.createVerify('RSA-SHA256')
      verifier.update(baseString)
      verifier.end()
      return verifier.verify(serviceProvider.pubKey, signature, 'base64')
    }

    const encryptPersona = async (persona) => {
      /*
       * We sign and encrypt the persona. It's important to note that although a signature is
       * usually derived from the payload hash and is thus much smaller than the payload itself,
       * we're specifically contructeding a JWT, which contains the original payload.
       *
       * We then construct a JWE and provide two headers specifying the encryption algorithms used.
       * You can read about them here: https://www.rfc-editor.org/rfc/inline-errata/rfc7518.html
       *
       * These values weren't picked arbitrarily; they were the defaults used by a library we
       * formerly used: node-jose. We opted to continue using them for backwards compatibility.
       */
      const privateKey = await jose.importPKCS8(MOCKPASS_PRIVATE_KEY.toString())
      const sign = await new jose.SignJWT(persona)
        .setProtectedHeader({ alg: 'RS256' })
        .sign(privateKey)
      const publicKey = await jose.importX509(serviceProvider.cert.toString())
      const encryptedAndSignedPersona = await new jose.CompactEncrypt(
        Buffer.from(sign),
      )
        .setProtectedHeader({ alg: 'RSA-OAEP', enc: 'A128CBC-HS256' })
        .encrypt(publicKey)
      return encryptedAndSignedPersona
    }

    const lookupPerson = (allowedAttributes) => async (req, res) => {
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
          : (person) => person
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
        const [, authHeader] = req.get('Authorization').split(' ')

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
      const authz = req.get('Authorization').split(' ')
      const token = authz.pop()

      const authHeader = (authz[1] || '').replace(',Bearer', '')
      const { signature, baseString } = encryptMyInfo
        ? myInfoSignature(authHeader, req)
        : {}

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

    app.get(`/myinfo/${version}/authorise`, consent.authorizeViaOIDC)

    app.post(
      `/myinfo/${version}/token`,
      express.urlencoded({
        extended: false,
        type: 'application/x-www-form-urlencoded',
      }),
      (req, res) => {
        const [tokenTemplate, redirect_uri] =
          consent.authorizations[req.body.code]
        const [, authHeader] = (req.get('Authorization') || '').split(' ')

        const { signature, baseString } = MYINFO_SECRET
          ? myInfoSignature(authHeader, req, {
              client_secret: MYINFO_SECRET,
              redirect_uri,
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
