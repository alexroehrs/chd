// Envelope encryption used by CHD.
//
// * Each record is encrypted with a fresh 256-bit data-encryption key (DEK) using
//   AES-256-GCM; the record identifier is bound as additional authenticated data (AAD).
// * The DEK is wrapped separately for every authorised reader with an ECIES-style scheme:
//   ephemeral X25519 key agreement -> HKDF-SHA256 -> AES-256-GCM.
// * Only public keys ever leave the client. The gateway and the chain never see a DEK
//   or a private key, so a compromise of either does not disclose clinical content.
import crypto from 'node:crypto';

const AES = 'aes-256-gcm';
const IV_LEN = 12;
const WRAP_INFO = Buffer.from('CHD-key-wrap-v1');

const b64 = (buf) => Buffer.from(buf).toString('base64');
const unb64 = (s) => Buffer.from(s, 'base64');

/** Generates an X25519 key pair; the public key is returned as 32 raw bytes (hex). */
export function generateEncryptionKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519');
  const raw = publicKey.export({ format: 'jwk' }).x; // base64url, 32 bytes
  return {
    publicKeyHex: '0x' + Buffer.from(raw, 'base64url').toString('hex'),
    privateKey,
  };
}

function publicKeyFromHex(hex) {
  const x = Buffer.from(hex.replace(/^0x/, ''), 'hex').toString('base64url');
  return crypto.createPublicKey({ key: { kty: 'OKP', crv: 'X25519', x }, format: 'jwk' });
}

/** Canonical bytes of an encrypted envelope, used for the on-chain SHA-256 digest. */
export function envelopeBytes(env) {
  return Buffer.concat([
    Buffer.from(`CHD-env-v1|${env.recordId}|`),
    unb64(env.iv),
    unb64(env.tag),
    unb64(env.ciphertext),
  ]);
}

export function sha256Hex(buf) {
  return '0x' + crypto.createHash('sha256').update(buf).digest('hex');
}

/** Encrypts a plaintext buffer for record `recordId`; returns { envelope, dek }. */
export function encryptRecord(recordId, plaintext) {
  const dek = crypto.randomBytes(32);
  const iv = crypto.randomBytes(IV_LEN);
  const cipher = crypto.createCipheriv(AES, dek, iv);
  cipher.setAAD(Buffer.from(recordId));
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const envelope = {
    version: 1,
    recordId,
    iv: b64(iv),
    tag: b64(cipher.getAuthTag()),
    ciphertext: b64(ciphertext),
  };
  return { envelope, dek };
}

export function decryptRecord(envelope, dek) {
  const decipher = crypto.createDecipheriv(AES, dek, unb64(envelope.iv));
  decipher.setAAD(Buffer.from(envelope.recordId));
  decipher.setAuthTag(unb64(envelope.tag));
  return Buffer.concat([decipher.update(unb64(envelope.ciphertext)), decipher.final()]);
}

function kek(shared, salt, recordId, recipientHex) {
  const info = Buffer.concat([WRAP_INFO, Buffer.from(`|${recordId}|${recipientHex.toLowerCase()}`)]);
  return Buffer.from(crypto.hkdfSync('sha256', shared, salt, info, 32));
}

/** Wraps a DEK for the holder of the X25519 public key `recipientHex`. */
export function wrapKey(dek, recipientHex, recordId) {
  const eph = crypto.generateKeyPairSync('x25519');
  const shared = crypto.diffieHellman({ privateKey: eph.privateKey, publicKey: publicKeyFromHex(recipientHex) });
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(IV_LEN);
  const cipher = crypto.createCipheriv(AES, kek(shared, salt, recordId, recipientHex), iv);
  const ct = Buffer.concat([cipher.update(dek), cipher.final()]);
  const epk = Buffer.from(eph.publicKey.export({ format: 'jwk' }).x, 'base64url');
  return { epk: b64(epk), salt: b64(salt), iv: b64(iv), tag: b64(cipher.getAuthTag()), ct: b64(ct) };
}

export function unwrapKey(wrapped, privateKey, recipientHex, recordId) {
  const epk = crypto.createPublicKey({
    key: { kty: 'OKP', crv: 'X25519', x: unb64(wrapped.epk).toString('base64url') },
    format: 'jwk',
  });
  const shared = crypto.diffieHellman({ privateKey, publicKey: epk });
  const decipher = crypto.createDecipheriv(AES, kek(shared, unb64(wrapped.salt), recordId, recipientHex), unb64(wrapped.iv));
  decipher.setAuthTag(unb64(wrapped.tag));
  return Buffer.concat([decipher.update(unb64(wrapped.ct)), decipher.final()]);
}

/** Random 32-byte record identifier (no personal information is derivable from it). */
export function newRecordId() {
  return '0x' + crypto.randomBytes(32).toString('hex');
}
