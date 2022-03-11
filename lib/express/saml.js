const express = require('express')
const fs = require('fs')
const { render } = require('mustache')
const path = require('path')
const { DOMParser } = require('@xmldom/xmldom')
const xpath = require('xpath')
const moment = require('moment')

const assertions = require('../assertions')
const crypto = require('../crypto')
const {
  generateSamlArtifact,
  lookUpBySamlArtifact,
} = require('../saml-artifact')

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

const buildAssertURL = (assertEndpoint, samlArt, relayState) => {
  let assertURL = `${assertEndpoint}?SAMLart=${encodeURIComponent(samlArt)}`
  if (relayState !== undefined) {
    assertURL += `&RelayState=${encodeURIComponent(relayState)}`
  }
  return assertURL
}

const idGenerator = {
  singPass: ({ nric }) =>
    assertions.myinfo.v2.personas[nric] ? `${nric} [MyInfo]` : nric,
  corpPass: ({ nric, uen }) => `${nric} / UEN: ${uen}`,
}

const customProfileFromHeaders = {
  singPass: (req) => {
    const customNricHeader = req.header('X-Custom-NRIC')
    if (!customNricHeader) {
      return false
    }
    return { nric: customNricHeader }
  },
  corpPass: (req) => {
    const customNricHeader = req.header('X-Custom-NRIC')
    const customUenHeader = req.header('X-Custom-UEN')
    if (!customNricHeader || !customUenHeader) {
      return false
    }
    return { nric: customNricHeader, uen: customUenHeader }
  },
}

function config(
  app,
  { showLoginPage, serviceProvider, idpConfig, cryptoConfig },
) {
  const { verifySignature, sign, promiseToEncryptAssertion } =
    crypto(serviceProvider)

  for (const idp of ['singPass', 'corpPass']) {
    const partnerId = idpConfig[idp].id
    const partnerAssertEndpoint = idpConfig[idp].assertEndpoint

    const profiles = assertions.saml[idp]
    const defaultProfile =
      profiles.find((p) => p.nric === process.env.MOCKPASS_NRIC) || profiles[0]

    app.get(`/${idp.toLowerCase()}/logininitial`, (req, res) => {
      const assertEndpoint =
        req.query.esrvcID === 'MYINFO-CONSENTPLATFORM' && idp === 'singPass'
          ? MYINFO_ASSERT_ENDPOINT
          : partnerAssertEndpoint || req.query.PartnerId
      const relayState = req.query.Target
      if (showLoginPage(req)) {
        const values = profiles.map((profile) => {
          const samlArt = generateSamlArtifact(partnerId, profile)
          const assertURL = buildAssertURL(assertEndpoint, samlArt, relayState)
          const id = idGenerator[idp](profile)
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
        const profile = customProfileFromHeaders[idp](req) || defaultProfile
        const samlArt = generateSamlArtifact(partnerId, profile)
        const assertURL = buildAssertURL(assertEndpoint, samlArt, relayState)
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
          const profile = lookUpBySamlArtifact(samlArtifact)

          const samlArtifactResolveId = xpath.select(
            "string(//*[local-name(.)='ArtifactResolve']/@ID)",
            xml,
          )

          let result = assertions.saml.create[idp](
            profile,
            partnerId,
            partnerAssertEndpoint,
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
              issuer: partnerId,
              destination: partnerAssertEndpoint,
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
