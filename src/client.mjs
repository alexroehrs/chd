// Client SDK used by patients and healthcare institutions (and by the benchmarks).
// All cryptographic secrets stay inside this module; the gateway and the chain only
// receive ciphertext, digests, wrapped keys and signed transactions.
import { ethers } from 'ethers';
import { Sender, registryInterface, registryReader } from './chain.mjs';
import { signRequest } from './auth.mjs';
import {
  decryptRecord, encryptRecord, envelopeBytes, generateEncryptionKeyPair,
  newRecordId, sha256Hex, unwrapKey, wrapKey,
} from './crypto.mjs';
import { validateFhir } from './fhir.mjs';

const iface = registryInterface();
const now = () => performance.now();
const KEY_CACHE_MS = 60_000;
const REGISTER_ATTEMPTS = 3;

export class Actor {
  constructor({ privateKey, prov, registryAddress, gatewayUrl }) {
    this.sender = new Sender(privateKey ?? ethers.Wallet.createRandom().privateKey, prov);
    this.address = this.sender.address;
    this.prov = prov;
    this.registryAddress = registryAddress;
    this.reader = registryReader(registryAddress, prov);
    this.gateway = gatewayUrl;
    this.enc = generateEncryptionKeyPair();
    this.deks = new Map(); // recordId -> DEK (patient side cache)
    this.keyDirectory = new Map(); // address -> { key, fetchedAt }
  }

  async init() {
    await this.sender.init();
    return this;
  }

  tx(fn, args, gasLimit) {
    return this.sender.send(this.registryAddress, iface.encodeFunctionData(fn, args), gasLimit);
  }

  async publishEncryptionKey() {
    return this.tx('setEncryptionKey', [this.enc.publicKeyHex]);
  }

  async http(method, path, body) {
    const raw = body === undefined ? '' : JSON.stringify(body);
    const headers = await signRequest(this.sender.wallet, method, path, raw);
    const res = await fetch(this.gateway + path, {
      method,
      headers: { ...headers, 'content-type': 'application/json' },
      body: method === 'GET' || method === 'DELETE' ? undefined : raw,
    });
    const json = await res.json().catch(() => ({}));
    if (!res.ok) throw Object.assign(new Error(`${method} ${path}: ${res.status} ${json.error ?? ''}`), { status: res.status });
    // the signed request is attached per call (non-enumerable) so audit events bind to it
    return Object.defineProperty(json, '_signedRequest', { value: headers._signed, enumerable: false });
  }

  /** Reads a participant's X25519 key from the on-chain directory (cached for one minute). */
  async encryptionKeyOf(address) {
    const cached = this.keyDirectory.get(address);
    if (cached && now() - cached.fetchedAt < KEY_CACHE_MS) return cached.key;
    const key = await this.reader.encryptionKey(address);
    if (key === ethers.ZeroHash) throw new Error(`no encryption key published for ${address}`);
    this.keyDirectory.set(address, { key, fetchedAt: now() });
    return key;
  }

  // ---------------------------------------------------------------- patient side

  /** Validates, encrypts, anchors and uploads a FHIR document. */
  async createRecord(fhirDoc) {
    const t = { start: now() };
    const { valid, errors } = validateFhir(fhirDoc);
    if (!valid) throw new Error(`invalid FHIR content: ${errors.join('; ')}`);
    t.validated = now();
    const plaintext = Buffer.from(JSON.stringify(fhirDoc));
    let recordId, envelope, dek, gasUsed, txMs;
    // A registration reverts if the (random) identifier is already taken, for instance
    // when a mempool observer front-runs it; the client then retries with a fresh one.
    for (let attempt = 1; ; attempt++) {
      recordId = newRecordId();
      ({ envelope, dek } = encryptRecord(recordId, plaintext));
      t.encrypted ??= now();
      try {
        ({ gasUsed, latencyMs: txMs } = await this.tx('registerRecord', [recordId, sha256Hex(envelopeBytes(envelope))], 200_000n));
        break;
      } catch (e) {
        if (attempt >= REGISTER_ATTEMPTS || !/reverted/.test(e.message)) throw e;
      }
    }
    const ownWrapped = wrapKey(dek, this.enc.publicKeyHex, recordId);
    t.anchored = now();
    await this.http('PUT', `/records/${recordId}`, { envelope, wrappedKeys: { [this.address]: ownWrapped } });
    t.uploaded = now();
    this.deks.set(recordId, dek);
    return {
      recordId,
      gasUsed,
      bytes: Buffer.byteLength(envelope.ciphertext, 'base64'),
      timings: {
        validateMs: t.validated - t.start,
        encryptMs: t.encrypted - t.validated,
        txMs,
        uploadMs: t.uploaded - t.anchored,
        totalMs: t.uploaded - t.start,
      },
    };
  }

  async ownDek(recordId) {
    if (!this.deks.has(recordId)) {
      const { wrappedKey } = await this.http('GET', `/records/${recordId}`);
      this.deks.set(recordId, unwrapKey(wrappedKey, this.enc.privateKey, this.enc.publicKeyHex, recordId));
    }
    return this.deks.get(recordId);
  }

  /** Grants `institution` access for `ttlSeconds` and shares a wrapped data key with it. */
  async grant(recordId, institution, ttlSeconds = 3600) {
    const t0 = now();
    const expiresAt = BigInt(Math.floor(Date.now() / 1000) + ttlSeconds);
    const { gasUsed, latencyMs: txMs } = await this.tx('grantAccess', [recordId, institution, expiresAt], 200_000n);
    const t1 = now();
    const wrapped = wrapKey(await this.ownDek(recordId), await this.encryptionKeyOf(institution), recordId);
    await this.http('PUT', `/records/${recordId}/keys/${institution}`, wrapped);
    return { gasUsed, timings: { txMs, keyShareMs: now() - t1, totalMs: now() - t0 } };
  }

  async revoke(recordId, institution) {
    const { gasUsed, latencyMs } = await this.tx('revokeAccess', [recordId, institution], 200_000n);
    return { gasUsed, timings: { txMs: latencyMs, totalMs: latencyMs } };
  }

  /** On-chain erasure followed by deletion of ciphertext and wrapped keys. */
  async erase(recordId) {
    const t0 = now();
    const { gasUsed, latencyMs: txMs } = await this.tx('eraseRecord', [recordId], 200_000n);
    await this.http('DELETE', `/records/${recordId}`);
    this.deks.delete(recordId);
    return { gasUsed, timings: { txMs, totalMs: now() - t0 } };
  }

  // ---------------------------------------------------------------- institution side

  /** Retrieves, decrypts and verifies a record; returns the FHIR document. */
  async read(recordId) {
    const t = { start: now() };
    const resp = await this.http('GET', `/records/${recordId}`);
    const { envelope, wrappedKey } = resp;
    const signedRequest = resp._signedRequest;
    t.fetched = now();
    const [, contentHash] = await this.reader.getRecord(recordId);
    t.verifiedChain = now();
    if (sha256Hex(envelopeBytes(envelope)) !== contentHash) throw new Error('integrity check failed');
    const dek = unwrapKey(wrappedKey, this.enc.privateKey, this.enc.publicKeyHex, recordId);
    const doc = JSON.parse(decryptRecord(envelope, dek).toString('utf8'));
    t.decrypted = now();
    return {
      doc,
      requestHash: sha256Hex(Buffer.from(signedRequest)),
      timings: {
        fetchMs: t.fetched - t.start,
        chainCheckMs: t.verifiedChain - t.fetched,
        decryptMs: t.decrypted - t.verifiedChain,
        totalMs: t.decrypted - t.start,
      },
    };
  }

  async logAccess(recordId, requestHash) {
    const { gasUsed, latencyMs } = await this.tx('logAccess', [recordId, requestHash], 200_000n);
    return { gasUsed, timings: { txMs: latencyMs, totalMs: latencyMs } };
  }
}
