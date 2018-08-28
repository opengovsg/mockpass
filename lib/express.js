const morgan = require('morgan')

const samlArtifact = require('./lib/saml-artifact')

function config (app, { assertEndpoint, showLoginPage }) {
  app.use(morgan('combined'))

  app.get('/logininitial', (req, res) => {
    const relayState = encodeURIComponent(req.query.Target)
    const samlArt = samlArtifact(req.query.PartnerId)
    const assertURL =
      `${assertEndpoint}?SAMLart=${samlArt}&RelayState=${relayState}`
    if (showLoginPage) {
      res.send(`
        <html><body>Click to login <a href="${assertURL}">here</a></body></html>
      `)
    } else {
      res.redirect(assertURL)
    }
  })

  return app
}

module.exports = { config }
