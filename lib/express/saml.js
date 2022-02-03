const express = require('express')
const fs = require('fs')
const { render } = require('mustache')
const path = require('path')
const { DOMParser } = require('@xmldom/xmldom')
const xpath = require('xpath')
const moment = require('moment')

const assertions = require('../assertions')
const crypto = require('../crypto')
const { samlArtifact, hashPartnerId } = require('../saml-artifact')

const domParser = new DOMParser()
const dom = (xmlString) => domParser.parseFromString(xmlString)

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
  singPass: (rawId) =>
    assertions.myinfo.v2.personas[rawId] ? `${rawId} [MyInfo]` : rawId,
  corpPass: (rawId) => `${rawId.nric} / UEN: ${rawId.uen}`,
}

function config(
  app,
  { showLoginPage, serviceProvider, idpConfig, cryptoConfig },
) {
  const { verifySignature, sign, promiseToEncryptAssertion } =
    crypto(serviceProvider)

  for (const idp of ['singPass', 'corpPass']) {
    app.get(`/${idp.toLowerCase()}/logininitial`, (req, res) => {
      const assertEndpoint =
        req.query.esrvcID === 'MYINFO-CONSENTPLATFORM' && idp === 'singPass'
          ? MYINFO_ASSERT_ENDPOINT
          : idpConfig[idp].assertEndpoint || req.query.PartnerId
      const relayState = req.query.Target
      const partnerId = idpConfig[idp].id
      if (showLoginPage(req)) {
        const saml = assertions.saml[idp]
        const values = saml.map((rawId, index) => {
          const samlArt = encodeURIComponent(samlArtifact(partnerId, index))
          let assertURL = `${assertEndpoint}?SAMLart=${samlArt}`
          if (relayState !== undefined) {
            assertURL += `&RelayState=${encodeURIComponent(relayState)}`
          }
          const id = idGenerator[idp](rawId)
          return { id, assertURL }
        })
        const hashedPartnerId = hashPartnerId(partnerId)
        const response = render(LOGIN_TEMPLATE, {
          values,
          assertEndpoint,
          relayState,
          hashedPartnerId,
        })
        res.send(response)
      } else {
        const samlArt = encodeURIComponent(samlArtifact(partnerId))
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
      express.text({ type: 'text/xml' }),
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
          // Handle encoded base64 Artifact
          // Take the template and plug in the typical SingPass/CorpPass response
          // Sign and encrypt the assertion
          const samlArtifactBuffer = Buffer.from(samlArtifact, 'base64')
          const samlArtifactMessage = samlArtifactBuffer.toString('utf8', 24)

          let nric
          if (samlArtifactMessage.startsWith('customNric:')) {
            nric = samlArtifactMessage.slice('customNric:'.length)
          } else {
            let index = samlArtifactBuffer.readInt8(
              samlArtifactBuffer.length - 1,
            )
            // use env NRIC when SHOW_LOGIN_PAGE is false
            if (index === -1) {
              index =
                idp === 'singPass'
                  ? assertions.saml.singPass.indexOf(assertions.singPassNric)
                  : assertions.saml.corpPass.findIndex(
                      (c) => c.nric === assertions.corpPassNric,
                    )
            }

            nric = assertions.saml[idp][index]
          }

          const samlArtifactResolveId = xpath.select(
            "string(//*[local-name(.)='ArtifactResolve']/@ID)",
            xml,
          )

          let result = assertions.saml.create[idp](
            nric,
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
