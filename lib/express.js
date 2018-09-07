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

function config (app, { showLoginPage, serviceProvider, idpConfig }) {
  const { verifySignature, sign, promiseToEncryptAssertion } = crypto(serviceProvider)

  app.use(morgan('combined'))

  for (const idp of ['singPass', 'corpPass']) {
    app.get(`/${idp.toLowerCase()}/logininitial`, (req, res) => {
      const relayState = encodeURIComponent(req.query.Target)
      const samlArt = samlArtifact(idpConfig[idp].id)
      const assertURL =
        `${idpConfig[idp].assertEndpoint}?SAMLart=${samlArt}&RelayState=${relayState}`
      console.warn(`Redirecting login from ${req.query.PartnerId} to ${assertURL}`)
      if (showLoginPage) {
        res.send(`
          <html><body>Click to login <a href="${assertURL}">here</a></body></html>
        `)
      } else {
        res.redirect(assertURL)
      }
    })

    app.post(
      `/${idp.toLowerCase()}/soap`,
      bodyParser.text({ type: 'text/xml' }),
      async (req, res) => {
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
          const assertion = await promiseToEncryptAssertion(
            sign(assertions[idp], "//*[local-name(.)='Assertion']")
          )
          // TODO: sign at Response and ArtifactResponse
          const response = render(TEMPLATE, { assertion })
          const signedResponse = sign(
            sign(response, "//*[local-name(.)='Response']"),
            "//*[local-name(.)='ArtifactResponse']"
          )
          res.send(signedResponse)
        }
      }
    )
  }
  return app
}

module.exports = { config }
