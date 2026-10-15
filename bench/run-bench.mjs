// CHD experimental harness. Requires a running network (network/start.sh).
//
//   node bench/run-bench.mjs <experiment> [options]
//
// experiments and their options (defaults in brackets):
//   crypto   client-side validation/encryption cost vs. record size (no network)
//            --reps N [50]
//   gas      gas per operation and on-chain baseline vs. payload size
//   latency  sequential end-to-end latency of every operation
//            --reps N [30]  --size KiB [16]
//   load     closed-loop load at increasing concurrency
//            --levels 1,4,16,64  --duration s [60]  --warmup s [10]  --size KiB [16]
//            --workloads read,readAudit,write  --name FILE [load]
// common:    --label L [default]   (results go to results/<L>/<name>.json)
//
// Results are written as JSON together with host and network metadata; the first error
// messages of each load level are kept in `errorSamples`.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import { ethers } from 'ethers';
import { Sender, loadArtifact, provider, registryInterface } from '../src/chain.mjs';
import { Actor } from '../src/client.mjs';
import {
  decryptRecord, encryptRecord, envelopeBytes, generateEncryptionKeyPair,
  newRecordId, sha256Hex, unwrapKey, wrapKey,
} from '../src/crypto.mjs';
import { validateFhir } from '../src/fhir.mjs';
import { syntheticBundle } from './fhir-gen.mjs';
import { summarize } from './stats.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const args = process.argv.slice(2);
const exp = args[0];
const opt = (k, d) => {
  const i = args.indexOf(`--${k}`);
  return i >= 0 ? args[i + 1] : d;
};
const label = opt('label', 'default');
const rpcUrl = process.env.RPC_URL ?? 'http://127.0.0.1:8545';
const outDir = path.join(root, 'results', label);
fs.mkdirSync(outDir, { recursive: true });
const KB = 1024;

function save(name, data) {
  const meta = {
    experiment: name,
    label,
    date: new Date().toISOString(),
    host: { cpus: os.cpus().length, cpuModel: os.cpus()[0]?.model, memGB: Math.round(os.totalmem() / 2 ** 30), node: process.version, platform: `${os.platform()} ${os.release()}` },
    rpcUrl,
  };
  fs.writeFileSync(path.join(outDir, `${name}.json`), JSON.stringify({ meta, data }, (_, v) => (typeof v === 'bigint' ? v.toString() : v), 2));
  console.log(`saved results/${label}/${name}.json`);
}

async function networkInfo(prov) {
  const qbft = await prov.send('qbft_getValidatorsByBlockNumber', ['latest']).catch(() => []);
  const b1 = await prov.getBlock('latest');
  const b0 = await prov.getBlock(Math.max(0, b1.number - 10));
  return {
    validators: qbft.length,
    blockPeriodObservedS: (b1.timestamp - b0.timestamp) / Math.max(1, b1.number - b0.number),
    clientVersion: await prov.send('web3_clientVersion', []),
    peers: Number(await prov.send('net_peerCount', [])),
  };
}

async function startGateway(registryAddress) {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'chd-bench-gw-'));
  const port = 18080 + Math.floor(Math.random() * 1000);
  const child = spawn(process.execPath, ['-e', `
    import(${JSON.stringify(path.join(root, 'src', 'gateway.mjs'))}).then(({ createGateway }) => {
      createGateway({ registryAddress: '${registryAddress}', rpcUrl: '${rpcUrl}', dataDir: ${JSON.stringify(path.join(dataDir, 'store'))} })
        .listen(${port}, () => console.log('ready'));
    });`], { stdio: ['ignore', 'pipe', 'inherit'] });
  await new Promise((resolve, reject) => {
    child.stdout.on('data', (d) => d.toString().includes('ready') && resolve());
    child.on('exit', (code) => reject(new Error(`gateway exited with code ${code}`)));
    setTimeout(() => reject(new Error('gateway did not start')), 30_000);
  });
  const stop = () => child.kill();
  process.on('exit', stop);
  return { url: `http://127.0.0.1:${port}`, stop };
}

async function fixture({ patients, institutions }) {
  const prov = provider(rpcUrl);
  const admin = await new Sender(ethers.Wallet.createRandom().privateKey, prov).init();
  const reg = await admin.deploy(loadArtifact('CHDRegistry'));
  const gw = await startGateway(reg.address);
  const mk = () => new Actor({ prov, registryAddress: reg.address, gatewayUrl: gw.url }).init();
  const pats = await Promise.all(Array.from({ length: patients }, mk));
  const insts = await Promise.all(Array.from({ length: institutions }, mk));
  const iface = registryInterface();
  // institution registration is batched: the admin sends all transactions, then waits.
  await Promise.all(insts.map((i) => admin.send(reg.address, iface.encodeFunctionData('setInstitution', [i.address, true]))));
  await Promise.all([...pats, ...insts].map((a) => a.publishEncryptionKey()));
  return { prov, admin, registry: reg.address, gw, patients: pats, institutions: insts, deployGas: reg.receipt.gasUsed };
}

// ----------------------------------------------------------------------------- crypto
async function runCrypto() {
  const sizes = [1, 4, 16, 64, 256, 1024].map((k) => k * KB);
  const reps = Number(opt('reps', 50));
  const kp = generateEncryptionKeyPair();
  const rows = [];
  for (const size of sizes) {
    const doc = syntheticBundle(size, size);
    const validate = [], seal = [], open = [];
    for (let i = 0; i < reps + 5; i++) {
      let t = performance.now();
      validateFhir(doc);
      const plain = Buffer.from(JSON.stringify(doc));
      const tv = performance.now() - t;
      t = performance.now();
      const id = newRecordId();
      const { envelope, dek } = encryptRecord(id, plain);
      const digest = sha256Hex(envelopeBytes(envelope));
      const w = wrapKey(dek, kp.publicKeyHex, id);
      const ts = performance.now() - t;
      t = performance.now();
      if (sha256Hex(envelopeBytes(envelope)) !== digest) throw new Error('digest');
      const back = decryptRecord(envelope, unwrapKey(w, kp.privateKey, kp.publicKeyHex, id));
      JSON.parse(back.toString());
      const to = performance.now() - t;
      if (i >= 5) { validate.push(tv); seal.push(ts); open.push(to); }
    }
    rows.push({
      targetBytes: size,
      plaintextBytes: Buffer.byteLength(JSON.stringify(doc)),
      resources: doc.entry.length,
      validateSerializeMs: summarize(validate),
      sealMs: summarize(seal),
      openMs: summarize(open),
    });
    console.log(`crypto ${size / KB} KiB: seal p50 ${rows.at(-1).sealMs.p50} ms, open p50 ${rows.at(-1).openMs.p50} ms`);
  }
  save('crypto', { reps, rows });
}

// ----------------------------------------------------------------------------- gas
async function runGas() {
  const f = await fixture({ patients: 1, institutions: 1 });
  const [p] = f.patients;
  const [h] = f.institutions;
  const ops = {};
  const add = (k, r) => (ops[k] ??= []).push({ gas: Number(r.gasUsed), ms: r.timings?.txMs ?? r.latencyMs });
  for (let i = 0; i < 10; i++) {
    const rec = await p.createRecord(syntheticBundle(16 * KB, 1000 + i));
    add('registerRecord', { gasUsed: rec.gasUsed, latencyMs: rec.timings.txMs });
    add('grantAccess', await p.grant(rec.recordId, h.address, 3600));
    const { requestHash } = await h.read(rec.recordId);
    add('logAccess', await h.logAccess(rec.recordId, requestHash));
    add('revokeAccess', await p.revoke(rec.recordId, h.address));
    add('updateRecord', await p.tx('updateRecord', [rec.recordId, sha256Hex(Buffer.from(`new-${i}`))], 200_000n));
    add('eraseRecord', await p.erase(rec.recordId));
  }
  const pk = await new Actor({ prov: f.prov, registryAddress: f.registry, gatewayUrl: f.gw.url }).init();
  add('setEncryptionKey', await pk.publishEncryptionKey());
  const iface = registryInterface();
  add('setInstitution', await f.admin.send(f.registry, iface.encodeFunctionData('setInstitution', [ethers.Wallet.createRandom().address, true])));

  // Baseline: the encrypted envelope written to contract storage (records kept on-chain).
  const base = await f.admin.deploy(loadArtifact('OnChainBaseline'));
  const bIface = new ethers.Interface(loadArtifact('OnChainBaseline').abi);
  const baseline = [];
  for (const size of [1, 4, 16, 64].map((k) => k * KB)) {
    const samples = [];
    for (let i = 0; i < 5; i++) {
      const sender = await new Sender(ethers.Wallet.createRandom().privateKey, f.prov).init();
      const { envelope } = encryptRecord(newRecordId(), Buffer.from(JSON.stringify(syntheticBundle(size, size + i))));
      const payload = JSON.stringify(envelope);
      const r = await sender.send(base.address, bIface.encodeFunctionData('saveJSON', [payload]), 400_000_000n);
      samples.push({ gas: Number(r.gasUsed), ms: r.latencyMs, payloadBytes: payload.length });
    }
    baseline.push({ targetBytes: size, payloadBytes: summarize(samples.map((s) => s.payloadBytes)), gas: summarize(samples.map((s) => s.gas)), latencyMs: summarize(samples.map((s) => s.ms)) });
    console.log(`baseline ${size / KB} KiB: gas ${baseline.at(-1).gas.mean}`);
  }
  const summary = Object.fromEntries(Object.entries(ops).map(([k, v]) => [k, { gas: summarize(v.map((x) => x.gas)), txLatencyMs: summarize(v.map((x) => x.ms)) }]));
  f.gw.stop();
  save('gas', { network: await networkInfo(f.prov), deployGas: { CHDRegistry: Number(f.deployGas), OnChainBaseline: Number(base.receipt.gasUsed) }, operations: summary, baseline });
}

// ----------------------------------------------------------------------------- latency
async function runLatency() {
  const n = Number(opt('reps', 30));
  const size = Number(opt('size', 16)) * KB;
  const f = await fixture({ patients: 1, institutions: 1 });
  const [p] = f.patients;
  const [h] = f.institutions;
  const res = { create: [], grant: [], read: [], logAccess: [], revoke: [], erase: [] };
  for (let i = 0; i < n; i++) {
    const c = await p.createRecord(syntheticBundle(size, 5000 + i));
    res.create.push(c.timings);
    res.grant.push((await p.grant(c.recordId, h.address, 3600)).timings);
    const r = await h.read(c.recordId);
    res.read.push(r.timings);
    res.logAccess.push((await h.logAccess(c.recordId, r.requestHash)).timings);
    res.revoke.push((await p.revoke(c.recordId, h.address)).timings);
    res.erase.push((await p.erase(c.recordId)).timings);
    process.stdout.write('.');
  }
  console.log();
  const out = {};
  for (const [op, list] of Object.entries(res)) {
    out[op] = Object.fromEntries(Object.keys(list[0]).map((k) => [k, summarize(list.map((x) => x[k]))]));
  }
  f.gw.stop();
  save('latency', { network: await networkInfo(f.prov), reps: n, recordBytes: size, operations: out });
}

// ----------------------------------------------------------------------------- load
async function closedLoop(vus, durationS, warmupS, op) {
  const lat = [];
  const errorSamples = [];
  let errors = 0, done = 0;
  const tStart = performance.now();
  const tEnd = tStart + (warmupS + durationS) * 1000;
  const tMeasure = tStart + warmupS * 1000;
  await Promise.all(vus.map(async (vu, idx) => {
    let k = 0;
    while (performance.now() < tEnd) {
      const t0 = performance.now();
      try {
        await op(vu, idx, k++);
        const t1 = performance.now();
        if (t0 >= tMeasure && t1 <= tEnd) { lat.push(t1 - t0); done++; }
      } catch (e) {
        if (t0 >= tMeasure) errors++;
        if (errorSamples.length < 5) {
          errorSamples.push(e.message.slice(0, 300));
          console.error(`  error: ${e.message}`);
        }
      }
    }
  }));
  return { vus: vus.length, durationS, completed: done, errors, errorSamples, throughputOpsPerS: Math.round((done / durationS) * 100) / 100, latencyMs: summarize(lat) };
}

async function runLoad() {
  const levels = (opt('levels', '1,4,16,64')).split(',').map(Number);
  const durationS = Number(opt('duration', 60));
  const warmupS = Number(opt('warmup', 10));
  const size = Number(opt('size', 16)) * KB;
  const maxVu = Math.max(...levels);
  const workloads = opt('workloads', 'read,readAudit,write').split(',');
  const nRecords = 32;
  const needInst = workloads.some((w) => w !== 'write');
  const f = await fixture({ patients: maxVu, institutions: needInst ? maxVu : 1 });
  console.log(`fixture ready: ${maxVu} patients, ${maxVu} institutions`);

  // Read workload: each institution holds grants for two of the 32 pre-loaded records.
  const owners = f.patients.slice(0, 8);
  const records = [];
  if (needInst) {
    for (let i = 0; i < nRecords; i++) {
      const owner = owners[i % owners.length];
      records.push({ owner, id: (await owner.createRecord(syntheticBundle(size, 9000 + i))).recordId });
    }
    await Promise.all(f.institutions.map(async (inst, i) => {
      for (const r of [records[i % nRecords], records[(i + 1) % nRecords]]) await r.owner.grant(r.id, inst.address, 86_400);
    }));
    console.log('records loaded and granted');
  }

  const read = [], write = [], readAudit = [];
  for (const c of workloads.includes('read') ? levels : []) {
    const vus = f.institutions.slice(0, c);
    read.push(await closedLoop(vus, durationS, warmupS, (inst, i, k) => inst.read(records[(i + (k % 2)) % nRecords].id)));
    console.log(`read  c=${c}: ${read.at(-1).throughputOpsPerS} ops/s p50 ${read.at(-1).latencyMs.p50} ms p99 ${read.at(-1).latencyMs.p99} ms err ${read.at(-1).errors}`);
  }
  for (const c of workloads.includes('readAudit') ? levels : []) {
    const vus = f.institutions.slice(0, c);
    readAudit.push(await closedLoop(vus, durationS, warmupS, async (inst, i, k) => {
      const id = records[(i + (k % 2)) % nRecords].id;
      const r = await inst.read(id);
      await inst.logAccess(id, r.requestHash);
    }));
    console.log(`read+audit c=${c}: ${readAudit.at(-1).throughputOpsPerS} ops/s p50 ${readAudit.at(-1).latencyMs.p50} ms err ${readAudit.at(-1).errors}`);
  }
  for (const c of workloads.includes('write') ? levels : []) {
    const vus = f.patients.slice(0, c);
    write.push(await closedLoop(vus, durationS, warmupS, (pat, i, k) => pat.createRecord(syntheticBundle(size, 100_000 + i * 10_000 + k))));
    console.log(`write c=${c}: ${write.at(-1).throughputOpsPerS} ops/s p50 ${write.at(-1).latencyMs.p50} ms p99 ${write.at(-1).latencyMs.p99} ms err ${write.at(-1).errors}`);
  }
  f.gw.stop();
  save(opt('name', 'load'), { network: await networkInfo(f.prov), recordBytes: size, durationS, warmupS, read, readAudit, write });
}

const runners = { crypto: runCrypto, gas: runGas, latency: runLatency, load: runLoad };
if (!runners[exp]) {
  console.error(`usage: node bench/run-bench.mjs <${Object.keys(runners).join('|')}> [options]`);
  process.exit(1);
}
try {
  await runners[exp]();
  process.exit(0);
} catch (e) {
  console.error(e);
  process.exit(1);
}
