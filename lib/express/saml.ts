import bodyParser from 'body-parser'
import fs from 'fs'
import { render } from 'mustache'
import path from 'path'
import { DOMParser } from 'xmldom'
import xpath from 'xpath'
import moment from 'moment'
import { Express } from 'express'

import * as assertions from '../assertions'
import crypto from '../crypto'
import samlArtifact from '../saml-artifact'
import { IConfigOptions, ISamlAssertion, Idp } from '../types/core'

const domParser = new DOMParser()
const dom = (xmlString: string) => domParser.parseFromString(xmlString)

const TEMPLATE = fs.readFileSync(
  path.resolve(__dirname, '../../static/saml/unsigned-response.xml'),
  'utf8',
)
const LOGIN_TEMPLATE = fs.readFileSync(
  path.resolve(__dirname, '../../static/html/login-page.html'),
  'utf8',
)

const MYINFO_ASSERT_ENDPOINT = '/consent/myinfo-com'

const idGenerator = {
  singPass: (rawId: string) =>
    assertions.myinfo.v2.personas[rawId] ? `${rawId} [MyInfo]` : rawId,
  corpPass: (rawId: ISamlAssertion['corpPass'][number]) =>
    `${rawId.nric} / UEN: ${rawId.uen}`,
}

function config(
  app: Express,
  { showLoginPage, serviceProvider, idpConfig, cryptoConfig }: IConfigOptions,
) {
  const { verifySignature, sign, promiseToEncryptAssertion } = crypto(
    serviceProvider,
  )

  for (const idp of Object.values(Idp)) {
    app.get(`/${idp.toLowerCase()}/logininitial`, (req, res) => {
      const assertEndpoint =
        req.query.esrvcID === 'MYINFO-CONSENTPLATFORM' && idp === 'singPass'
          ? MYINFO_ASSERT_ENDPOINT
          : idpConfig[idp].assertEndpoint || req.query.PartnerId
      const relayState = req.query.Target
      if (showLoginPage) {
        const saml = assertions.saml[idp]
        const values = saml.map((rawId, index) => {
          const samlArt = encodeURIComponent(
            samlArtifact(idpConfig[idp].id, index),
          )
          let assertURL = `${assertEndpoint}?SAMLart=${samlArt}`
          if (relayState !== undefined) {
            assertURL += `&RelayState=${encodeURIComponent(relayState)}`
          }
          const id = idGenerator[idp](rawId)
          return { id, assertURL }
        })
        const response = render(LOGIN_TEMPLATE, values)
        res.send(response)
      } else {
        const samlArt = encodeURIComponent(samlArtifact(idpConfig[idp].id))
        let assertURL = `${assertEndpoint}?SAMLart=${samlArt}`
        if (relayState !== undefined) {
          assertURL += `&RelayState=${encodeURIComponent(relayState)}`
        }
        console.warn(
          `Redirecting login from ${req.query.PartnerId} to ${assertURL}`,
        )
        res.redirect(assertURL)
      }
    })

    app.post(
      `/${idp.toLowerCase()}/soap`,
      bodyParser.text({ type: 'text/xml' }),
      (req, res) => {
        // Extract the body of the SOAP request
        const { body } = req
        const xml = dom(body)

        if (
          cryptoConfig.resolveArtifactRequestSigned &&
          !verifySignature(xml)
        ) {
          res.status(400).send('Request has bad signature')
        } else {
          // Grab the SAML artifact
          // TODO: verify the SAML artifact is something we sent
          // TODO: do something about the partner entity id
          const samlArtifact = xpath.select(
            "string(//*[local-name(.)='Artifact'])",
            xml,
          )
          console.warn(`Received SAML Artifact ${samlArtifact}`)
          // Take the template and plug in the typical SingPass/CorpPass response
          // Sign and encrypt the assertion
          const samlArtifactBuffer = Buffer.from(samlArtifact, 'base64')
          const index = samlArtifactBuffer.readInt8(
            samlArtifactBuffer.length - 1,
          )

          const samlArtifactResolveId = xpath.select(
            "string(//*[local-name(.)='ArtifactResolve']/@ID)",
            xml,
          )

          let result = assertions.saml.create[idp](
            assertions.saml[idp][index],
            idpConfig[idp].id,
            idpConfig[idp].assertEndpoint,
            samlArtifactResolveId,
          )

          if (cryptoConfig.signAssertion) {
            result = sign(result, "//*[local-name(.)='Assertion']")
          }
          const assertionPromise = cryptoConfig.encryptAssertion
            ? promiseToEncryptAssertion(result)
            : Promise.resolve(result)

          assertionPromise.then((assertion) => {
            let response = render(TEMPLATE, {
              assertion,
              issueInstant: moment.utc().format(),
              issuer: idpConfig[idp].id,
              destination: idpConfig[idp].assertEndpoint,
              inResponseTo: samlArtifactResolveId,
            })
            if (cryptoConfig.signResponse) {
              response = sign(
                sign(response, "//*[local-name(.)='Response']"),
                "//*[local-name(.)='ArtifactResponse']",
              )
            }
            res.send(response)
          })
        }
      },
    )
  }

  return app
}

module.exports = config
