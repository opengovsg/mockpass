const crypto = require('crypto')
const fs = require('fs')
const path = require('path')
const { SignedXml } = require('xml-crypto')
const { encrypt } = require('xml-encryption')
const xpath = require('xpath')

module.exports = (serviceProvider) => {
  // NOTE - the typo in keyEncryptionAlgorighm is deliberate
  const ENCRYPT_OPTIONS = {
    rsa_pub: serviceProvider.pubKey,
    pem: serviceProvider.cert,
    encryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#aes256-cbc',
    keyEncryptionAlgorighm: 'http://www.w3.org/2001/04/xmlenc#rsa-1_5',
  }

  const apexBaseString = function apexBaseString ({
    httpMethod,
    url,
    appId,
    clientId,
    singpassEserviceId,
    nonce,
    requestedAttributes,
    timestamp,
  }) {
    return httpMethod.toUpperCase() +
      // url string replacement was dictated by MyInfo docs - no explanation
      // was provided for why this is necessary
      '&' + url.replace('.api.gov.sg', '.e.api.gov.sg') +
      '&apex_l2_eg_app_id=' + appId +
      '&apex_l2_eg_nonce=' + nonce +
      '&apex_l2_eg_signature_method=SHA256withRSA' +
      '&apex_l2_eg_timestamp=' + timestamp +
      '&apex_l2_eg_version=1.0' +
      '&attributes=' + requestedAttributes +
      '&client_id=' + clientId +
      '&singpassEserviceId=' + singpassEserviceId
  }

  const pkiBaseString = function pkiBaseString ({
    httpMethod,
    appId,
    nonce,
    timestamp,
  }) {
    return httpMethod.toUpperCase() +
      '&app_id=' + appId +
      '&nonce=' + nonce +
      '&signature_method=RS256' +
      '&timestamp=' + timestamp
  }

  return {
    verifySignature (xml) {
      const [signature] =
        xpath.select("//*[local-name(.)='Signature']", xml) || []
      const [artifactResolvePayload] =
        xpath.select("//*[local-name(.)='ArtifactResolve']", xml) || []
      const verifier = new SignedXml()
      verifier.keyInfoProvider = { getKey: () => ENCRYPT_OPTIONS.pem }
      verifier.loadSignature(signature.toString())
      return verifier.checkSignature(artifactResolvePayload.toString())
    },

    sign (payload, reference) {
      const sig = new SignedXml()
      const transforms = [
        'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
        'http://www.w3.org/2001/10/xml-exc-c14n#',
      ]
      const digestAlgorithm = 'http://www.w3.org/2001/04/xmlenc#sha256'
      sig.addReference(reference, transforms, digestAlgorithm)

      sig.signingKey = fs.readFileSync(path.resolve(__dirname, '../static/certs/spcp-key.pem'))
      sig.signatureAlgorithm = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'
      const options = {
        prefix: 'ds',
        location: { reference, action: 'prepend' },
      }
      sig.computeSignature(payload, options)
      return sig.getSignedXml()
    },

    promiseToEncryptAssertion: assertion => new Promise((resolve, reject) => {
      encrypt(
        assertion,
        ENCRYPT_OPTIONS,
        (err, data) => err
          ? reject(err)
          : resolve(`<saml:EncryptedAssertion>${data}</saml:EncryptedAssertion>`)
      )
    }),

    verifyMyInfoSignature (signature, baseStringFields, baseString = apexBaseString) {
      const verifier = crypto.createVerify('RSA-SHA256')
      verifier.update(baseString(baseStringFields))
      verifier.end()
      return verifier.verify(serviceProvider.pubKey, signature, 'base64')
    },

    apexBaseString,
    pkiBaseString,
  }
}
