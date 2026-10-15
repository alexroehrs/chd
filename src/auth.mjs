// Signed-request authentication between CHD clients and the gateway.
// Every request carries an EIP-191 signature over a canonical string that binds the
// HTTP method, the request path (which names the record and, for key uploads, the
// grantee), the SHA-256 digest of the body, a timestamp and a random nonce.
// The gateway accepts a request only inside a freshness window and only once.
import crypto from 'node:crypto';
import { ethers } from 'ethers';

export const FRESHNESS_MS = 60_000;
const MAX_CACHE = 100_000;

export function bodyDigest(body) {
  const data = body === undefined || body === null ? '' : typeof body === 'string' ? body : JSON.stringify(body);
  return '0x' + crypto.createHash('sha256').update(data).digest('hex');
}

export function canonical(method, path, digest, timestamp, nonce) {
  return `CHD-REQ-v1|${method.toUpperCase()}|${path.toLowerCase()}|${digest}|${timestamp}|${nonce}`;
}

/** Produces the authentication headers for a request signed by `wallet`. */
export async function signRequest(wallet, method, path, bodyString) {
  const timestamp = Date.now().toString();
  const nonce = crypto.randomBytes(16).toString('hex');
  const digest = bodyDigest(bodyString);
  const message = canonical(method, path, digest, timestamp, nonce);
  const signature = await wallet.signMessage(message);
  // non-enumerable copy of the signed message, used by clients to bind audit events to it
  return Object.defineProperty({
    'x-chd-address': wallet.address,
    'x-chd-timestamp': timestamp,
    'x-chd-nonce': nonce,
    'x-chd-signature': signature,
  }, '_signed', { value: `${message}|${signature}`, enumerable: false });
}

/** SHA-256 of the signed request (canonical string and signature) as seen by the gateway. */
export function signedRequestHash(headers, method, path, rawBody) {
  const h = headers;
  if (!h['x-chd-signature'] || !h['x-chd-timestamp'] || !h['x-chd-nonce']) return null;
  const msg = canonical(method, path, bodyDigest(rawBody), h['x-chd-timestamp'], h['x-chd-nonce']);
  return '0x' + crypto.createHash('sha256').update(`${msg}|${h['x-chd-signature']}`).digest('hex');
}

export class ReplayGuard {
  constructor(windowMs = FRESHNESS_MS) {
    this.windowMs = windowMs;
    this.seen = new Map();
  }

  /** Returns the authenticated address, or throws with an HTTP status. */
  verify(headers, method, path, rawBody) {
    const address = headers['x-chd-address'];
    const timestamp = headers['x-chd-timestamp'];
    const nonce = headers['x-chd-nonce'];
    const signature = headers['x-chd-signature'];
    if (!address || !timestamp || !nonce || !signature) throw Object.assign(new Error('missing authentication headers'), { status: 401 });
    const ts = Number(timestamp);
    const now = Date.now();
    if (!Number.isFinite(ts) || Math.abs(now - ts) > this.windowMs) throw Object.assign(new Error('stale request'), { status: 401 });
    const key = `${address.toLowerCase()}|${nonce}`;
    if (this.seen.has(key)) throw Object.assign(new Error('replayed request'), { status: 401 });
    let signer;
    try {
      signer = ethers.verifyMessage(canonical(method, path, bodyDigest(rawBody), timestamp, nonce), signature);
    } catch {
      throw Object.assign(new Error('malformed signature'), { status: 401 });
    }
    if (signer.toLowerCase() !== address.toLowerCase()) throw Object.assign(new Error('invalid signature'), { status: 401 });
    this.#gc(now);
    if (this.seen.size >= MAX_CACHE) throw Object.assign(new Error('too many requests'), { status: 429 });
    // the entry lives until the request itself would be stale, even for future-dated timestamps
    this.seen.set(key, Math.max(now, ts) + this.windowMs);
    return signer;
  }

  #gc(now) {
    if (this.seen.size < 10_000 && now - (this.lastGc ?? 0) < this.windowMs) return;
    this.lastGc = now;
    for (const [k, exp] of this.seen) if (exp < now) this.seen.delete(k);
  }
}
