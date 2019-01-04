const bodyParser = require('body-parser')
const fs = require('fs')
const morgan = require('morgan')
const { render } = require('mustache')
const path = require('path')
const { DOMParser } = require('xmldom')
const xpath = require('xpath')

const assertions = require('./assertions')
const crypto = require('./crypto')
const samlArtifact = require('./saml-artifact')

const domParser = new DOMParser()
const dom = xmlString => domParser.parseFromString(xmlString)

const TEMPLATE = fs.readFileSync(path.resolve(__dirname, '../static/saml/unsigned-response.xml'), 'utf8')
const LOGIN_TEMPLATE = fs.readFileSync(path.resolve(__dirname, '../static/html/login-page.html'), 'utf8')

function config (app, { showLoginPage, serviceProvider, idpConfig }) {
  const { verifySignature, sign, promiseToEncryptAssertion } = crypto(serviceProvider)
  app.use(morgan('combined'))

  for (const idp of ['singPass', 'corpPass']) {
    app.get(`/${idp.toLowerCase()}/logininitial`, (req, res) => {
      const relayState = encodeURIComponent(req.query.Target)
      if (showLoginPage) {
        const identities = assertions.identities[idp]
        const someValues = identities
          .map((id, index) => {
            const samlArt = samlArtifact(idpConfig[idp].id, index)
            const assertURL =
              `${idpConfig[idp].assertEndpoint}?SAMLart=${samlArt}&RelayState=${relayState}`
            return { id, assertURL }
          })
        const response = render(LOGIN_TEMPLATE, someValues)
        res.send(response)
      } else {
        const samlArt = samlArtifact(idpConfig[idp].id)
        const assertURL =
          `${idpConfig[idp].assertEndpoint}?SAMLart=${samlArt}&RelayState=${relayState}`
        console.warn(`Redirecting login from ${req.query.PartnerId} to ${assertURL}`)
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

        if (!verifySignature(xml)) {
          res.status(400).send('Request has bad signature')
        } else {
          // Grab the SAML artifact
          // TODO: verify the SAML artifact is something we sent
          // TODO: do something about the partner entity id
          const samlArtifact = xpath.select("string(//*[local-name(.)='Artifact'])", xml)
          console.warn(`Received SAML Artifact ${samlArtifact}`)
          // Take the template and plug in the typical SingPass/CorpPass response
          // Sign and encrypt the assertion
          const samlArtifactBuffer = Buffer.from(samlArtifact, 'base64')
          const index = samlArtifactBuffer.readInt8(samlArtifactBuffer.length - 1)
          const assertion = assertions.identities[idp][index]
            ? assertions[idp].create(assertions.identities[idp][index])
            : assertions[idp].default
          const signedAssertion = sign(assertion, "//*[local-name(.)='Assertion']")
          promiseToEncryptAssertion(signedAssertion)
            .then(assertion => {
              const response = render(TEMPLATE, { assertion })
              const signedResponse = sign(
                sign(response, "//*[local-name(.)='Response']"),
                "//*[local-name(.)='ArtifactResponse']"
              )
              res.send(signedResponse)
            })
        }
      }
    )
  }
  return app
}

module.exports = { config }
