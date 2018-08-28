const crypto = require('crypto')

/**
 * Construct a SingPass/CorpPass SAML artifact, a base64
 * encoding of a byte sequence consisting of the following:
 *  - a two-byte type code, always 0x0004, per SAML 2.0;
 *  - a two-byte endpoint index, currently always 0x0000;
 *  - a 20-byte sha1 hash of the partner id, and;
 *  - a 20-byte random sequence that is effectively the message id
 * @param {string} partnerId - the partner id
 * @return {string} the SAML artifact, a base64 string
 * containing the type code, the endpoint index,
 * the hash of the partner id, followed by 20 random bytes
 */
function samlArtifact (partnerId) {
  let hashedPartnerId = crypto.createHash('sha1')
    .update(partnerId, 'utf8')
    .digest('hex')
  const randomBytes = crypto.randomBytes(20).toString('hex')
  return Buffer.from(`00040000${hashedPartnerId}${randomBytes}`, 'hex')
    .toString('base64')
}

module.exports = samlArtifact
