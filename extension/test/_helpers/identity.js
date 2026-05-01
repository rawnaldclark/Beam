/**
 * @file identity.js
 * @description Generate test device identities (Ed25519 keypair + deviceId)
 * in the same shape that `popup/pairing.js` stores in chrome.storage.local.
 *
 * The Ed25519 private key is exported as PKCS8 (matching what Web Crypto
 * gives the popup), and the public key is exported as a raw 32-byte
 * Uint8Array. The deviceId is the base64url of SHA-256(pubKey)[0:16],
 * matching the relay's gateway derivation.
 *
 * @returns {Promise<{
 *   deviceId: string,
 *   ed25519Sk: number[],   // PKCS8 bytes as plain array (chrome.storage shape)
 *   ed25519Pk: number[],   // raw 32 bytes as plain array
 * }>}
 */
export async function generateTestIdentity() {
  const key = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']);
  const skPkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', key.privateKey));
  const pkRaw   = new Uint8Array(await crypto.subtle.exportKey('raw', key.publicKey));

  const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', pkRaw));
  const idBytes = hash.slice(0, 16);
  const deviceId = Buffer.from(idBytes).toString('base64url');

  return {
    deviceId,
    ed25519Sk: Array.from(skPkcs8),
    ed25519Pk: Array.from(pkRaw),
  };
}
