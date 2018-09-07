const fs = require('fs')
const { promisify } = require('util')
const { SignedXml } = require('xml-crypto')
const { encrypt } = require('xml-encryption')
const xpath = require('xpath')

const promiseToEncrypt = promisify(encrypt)

module.exports = (serviceProviderPaths) => {
  // NOTE - the typo in keyEncryptionAlgorighm is deliberate
  const ENCRYPT_OPTIONS = {
    rsa_pub: fs.readFileSync(serviceProviderPaths.pubKey || './static/certs/key.pub'),
    pem: fs.readFileSync(serviceProviderPaths.cert || './static/certs/server.crt'),
    encryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#aes256-cbc',
    keyEncryptionAlgorighm: 'http://www.w3.org/2001/04/xmlenc#rsa-1_5',
  }

  return {
    verifySignature (xml, serviceProviderCertPath) {
      const [ signature ] =
        xpath.select("//*[local-name(.)='Signature']", xml) || []
      const [ artifactResolvePayload ] =
        xpath.select("//*[local-name(.)='ArtifactResolve']", xml) || []
      const verifier = new SignedXml()
      verifier.keyInfoProvider = { getKey: () => ENCRYPT_OPTIONS.pem }
      verifier.loadSignature(signature.toString())
      return verifier.checkSignature(artifactResolvePayload.toString())
    },

    sign (payload, xpath) {
      const sig = new SignedXml()
      const transforms = [
        'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
        'http://www.w3.org/2001/10/xml-exc-c14n#',
      ]
      const digestAlgorithm = 'http://www.w3.org/2001/04/xmlenc#sha256'
      sig.addReference(xpath, transforms, digestAlgorithm)

      sig.signingKey = fs.readFileSync('./static/certs/spcp-key.pem')
      sig.signatureAlgorithm = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'
      sig.computeSignature(payload, { prefix: 'ds', location: { action: 'prepend' } })
      return sig.getSignedXml()
    },

    promiseToEncryptAssertion: async assertion => {
      const encryptedAssertion = await promiseToEncrypt(assertion, ENCRYPT_OPTIONS)
      return `<saml:EncryptedAssertion>${encryptedAssertion}</saml:EncryptedAssertion>`
    },
  }
}
