// CHD gateway: an honest-but-curious off-chain service that stores encrypted envelopes
// and wrapped keys, and releases them only when the on-chain registry says so.
// It serves plain HTTP and has no rate limiting; a deployment needs TLS termination and
// rate limiting in front of it.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';
import { provider, readDeployment, registryReader } from './chain.mjs';
import { ADDR, EnvelopeStore, HEX32 } from './store.mjs';
import { ReplayGuard, signedRequestHash } from './auth.mjs';
import { envelopeBytes, sha256Hex } from './crypto.mjs';

const B64 = /^[A-Za-z0-9+/]+={0,2}$/;
const b64len = (s) => (typeof s === 'string' && B64.test(s) ? Buffer.from(s, 'base64').length : -1);
const ZERO = '0x0000000000000000000000000000000000000000';

function isEnvelope(e) {
  return e && typeof e === 'object' && e.version === 1 && typeof e.recordId === 'string'
    && b64len(e.iv) === 12 && b64len(e.tag) === 16 && b64len(e.ciphertext) > 0;
}

function isWrappedKey(w) {
  return w && typeof w === 'object' && b64len(w.epk) === 32 && b64len(w.salt) === 16
    && b64len(w.iv) === 12 && b64len(w.tag) === 16 && b64len(w.ct) === 32;
}

export function createGateway({ registryAddress, rpcUrl, dataDir }) {
  const prov = provider(rpcUrl);
  const registry = registryReader(registryAddress, prov);
  const store = new EnvelopeStore(dataDir);
  const guard = new ReplayGuard();
  const app = express();
  app.disable('x-powered-by');
  app.use(express.text({ type: '*/*', limit: '25mb' }));

  // Request log kept by the gateway operator. Each line holds the hash of the signed
  // request, which is the value institutions reference in on-chain logAccess events.
  // The entry is written synchronously before any response is sent; if it cannot be
  // written, the response is withheld (503).
  fs.mkdirSync(dataDir, { recursive: true });
  const logFile = path.join(dataDir, 'requests.log');
  const logRequest = (req, status) => {
    fs.appendFileSync(logFile, JSON.stringify({
      at: new Date().toISOString(), method: req.method, path: req.path,
      address: req.headers['x-chd-address'] ?? null, status,
      requestHash: signedRequestHash(req.headers, req.method, req.path, req.body || ''),
    }) + '\n');
  };

  const fail = (status, message) => Object.assign(new Error(message), { status });

  // Handlers return { status, body }; every request is logged before anything is sent.
  const handle = (fn) => async (req, res) => {
    let status, body;
    try {
      ({ status, body } = await fn(req));
    } catch (e) {
      status = e.status ?? 500;
      body = { error: e.status ? e.message : 'internal error' };
      if (!e.status) console.error(e);
    }
    try {
      logRequest(req, status);
    } catch (e) {
      console.error('request log unavailable', e);
      return res.status(503).json({ error: 'audit log unavailable' });
    }
    res.status(status).json(body);
  };

  const auth = (req) => {
    if (!HEX32.test(req.params.id)) throw fail(400, 'invalid record id');
    if (req.params.grantee !== undefined && !ADDR.test(req.params.grantee)) throw fail(400, 'invalid grantee address');
    return guard.verify(req.headers, req.method, req.path, req.body || '');
  };

  const parseJson = (raw) => {
    try {
      return JSON.parse(raw);
    } catch {
      throw fail(400, 'malformed JSON body');
    }
  };

  async function requireOwner(recordId, address) {
    const [owner, contentHash, , , erased] = await registry.getRecord(recordId);
    if (owner === ZERO) throw fail(404, 'unknown record');
    if (owner.toLowerCase() !== address.toLowerCase()) throw fail(403, 'not the record owner');
    return { contentHash, erased };
  }

  app.get('/health', (_req, res) => res.json({ ok: true, registry: registryAddress }));

  // Upload of the encrypted envelope (after registerRecord was mined).
  app.put('/records/:id', handle(async (req) => {
    const signer = auth(req);
    const { envelope, wrappedKeys } = parseJson(req.body) ?? {};
    if (!isEnvelope(envelope) || envelope.recordId.toLowerCase() !== req.params.id.toLowerCase()) throw fail(400, 'malformed envelope or record mismatch');
    const keys = Object.entries(wrappedKeys ?? {});
    for (const [addr, wrapped] of keys) {
      if (!ADDR.test(addr) || addr.toLowerCase() !== signer.toLowerCase()) throw fail(400, 'only the owner key can be uploaded here');
      if (!isWrappedKey(wrapped)) throw fail(400, 'malformed wrapped key');
    }
    const { contentHash, erased } = await requireOwner(req.params.id, signer);
    if (erased) throw fail(410, 'record erased');
    if (sha256Hex(envelopeBytes(envelope)) !== contentHash) throw fail(409, 'digest does not match on-chain hash');
    await store.putEnvelope(req.params.id, envelope);
    for (const [addr, wrapped] of keys) await store.putKey(req.params.id, addr, wrapped);
    return { status: 201, body: { stored: true } };
  }));

  // Upload of a data key wrapped for a grantee (after grantAccess was mined).
  app.put('/records/:id/keys/:grantee', handle(async (req) => {
    const signer = auth(req);
    const wrapped = parseJson(req.body);
    if (!isWrappedKey(wrapped)) throw fail(400, 'malformed wrapped key');
    await requireOwner(req.params.id, signer);
    if (!(await registry.hasAccess(req.params.id, req.params.grantee))) throw fail(403, 'no active grant for grantee');
    await store.putKey(req.params.id, req.params.grantee, wrapped);
    return { status: 201, body: { stored: true } };
  }));

  // Retrieval: authorized by the on-chain registry at the time of the request.
  app.get('/records/:id', handle(async (req) => {
    const signer = auth(req);
    if (!(await registry.hasAccess(req.params.id, signer))) {
      // Crypto-shredding is also enforced here: content of a record erased on-chain is
      // deleted on the next access, even if the owner never sent the DELETE request.
      const [, , , , erased] = await registry.getRecord(req.params.id);
      if (erased) {
        await store.erase(req.params.id);
        throw fail(410, 'record erased');
      }
      throw fail(403, 'access denied by registry');
    }
    const [envelope, wrappedKey] = await Promise.all([
      store.getEnvelope(req.params.id),
      store.getKey(req.params.id, signer),
    ]);
    if (!envelope || !wrappedKey) throw fail(404, 'content not available');
    return { status: 200, body: { envelope, wrappedKey } };
  }));

  // Crypto-shredding after eraseRecord was mined (idempotent).
  app.delete('/records/:id', handle(async (req) => {
    const signer = auth(req);
    const { erased } = await requireOwner(req.params.id, signer);
    if (!erased) throw fail(409, 'record must be erased on-chain first');
    await store.erase(req.params.id);
    return { status: 200, body: { erased: true } };
  }));

  // Errors raised before a handler runs (oversized or unreadable bodies) are logged too.
  app.use((err, req, res, _next) => {
    const status = err.status ?? err.statusCode ?? 500;
    try {
      logRequest(req, status);
    } catch (e) {
      console.error('request log unavailable', e);
      return res.status(503).json({ error: 'audit log unavailable' });
    }
    res.status(status).json({ error: status === 500 ? 'internal error' : err.message });
  });

  return app;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  const dep = readDeployment();
  const port = Number(process.env.PORT ?? 8080);
  const app = createGateway({
    registryAddress: dep.CHDRegistry,
    rpcUrl: process.env.RPC_URL ?? dep.rpcUrl,
    dataDir: process.env.DATA_DIR ?? path.resolve('gateway-data'),
  });
  app.listen(port, () => console.log(`CHD gateway on :${port} (registry ${dep.CHDRegistry})`));
}
