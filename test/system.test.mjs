// End-to-end tests against a running Besu network (RPC_URL, default node1).
// Each test maps to a threat or requirement listed in the article (Table "threat model").
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { ethers } from 'ethers';
import { signRequest } from '../src/auth.mjs';
import { syntheticBundle } from '../bench/fhir-gen.mjs';
import { listFiles, revertName, setup } from './helpers.mjs';

let env, patient, hospital, outsider, rec, doc;

before(async () => {
  env = await setup({ institutions: 1, patients: 1 });
  [patient] = env.patients;
  [hospital] = env.institutions;
  outsider = env.outsider;
  doc = syntheticBundle(4096, 42);
  rec = await patient.createRecord(doc);
});

after(async () => env.close());

test('F1 owner can store and read back its own record', async () => {
  const { doc: back } = await patient.read(rec.recordId);
  assert.deepEqual(back, doc);
});

test('T1 institution without a grant is denied by the gateway', async () => {
  await assert.rejects(hospital.read(rec.recordId), { status: 403 });
});

test('T2 non-institution account cannot receive a grant', async () => {
  const exp = BigInt(Math.floor(Date.now() / 1000) + 3600);
  assert.equal(await revertName(patient, 'grantAccess', [rec.recordId, outsider.address, exp]), 'NotInstitution');
});

test('T3 only the owner can grant, update or erase', async () => {
  const exp = BigInt(Math.floor(Date.now() / 1000) + 3600);
  assert.equal(await revertName(hospital, 'grantAccess', [rec.recordId, hospital.address, exp]), 'NotOwner');
  assert.equal(await revertName(outsider, 'eraseRecord', [rec.recordId]), 'NotOwner');
  assert.equal(await revertName(outsider, 'updateRecord', [rec.recordId, ethers.id('x')]), 'NotOwner');
});

test('F2 granted institution retrieves, decrypts and verifies the record', async () => {
  await patient.grant(rec.recordId, hospital.address, 3600);
  const { doc: got, requestHash } = await hospital.read(rec.recordId);
  assert.deepEqual(got, doc);
  const { gasUsed } = await hospital.logAccess(rec.recordId, requestHash);
  assert.ok(gasUsed > 0n);
  // the on-chain audit hash matches the gateway's log entry of the signed request
  const log = fs.readFileSync(`${env.dataDir}/requests.log`, 'utf8').trim().split('\n').map((l) => JSON.parse(l));
  const entry = log.find((e) => e.requestHash === requestHash);
  assert.ok(entry && entry.status === 200 && entry.address.toLowerCase() === hospital.address.toLowerCase());
});

test('T4 audit entries cannot be written without access', async () => {
  assert.equal(await revertName(outsider, 'logAccess', [rec.recordId, ethers.ZeroHash]), 'AccessDenied');
});

test('T5 replayed, stale and forged requests are rejected', async () => {
  const id = rec.recordId;
  const headers = await signRequest(hospital.sender.wallet, 'GET', `/records/${id}`, '');
  const ok = await fetch(`${env.gatewayUrl}/records/${id}`, { headers });
  assert.equal(ok.status, 200);
  const replay = await fetch(`${env.gatewayUrl}/records/${id}`, { headers });
  assert.equal(replay.status, 401);
  const stale = { ...(await signRequest(hospital.sender.wallet, 'GET', `/records/${id}`, '')), 'x-chd-timestamp': String(Date.now() - 120_000) };
  assert.equal((await fetch(`${env.gatewayUrl}/records/${id}`, { headers: stale })).status, 401);
  const forged = { ...(await signRequest(outsider.sender.wallet, 'GET', `/records/${id}`, '')), 'x-chd-address': hospital.address };
  assert.equal((await fetch(`${env.gatewayUrl}/records/${id}`, { headers: forged })).status, 401);
});

test('T6 upload whose digest differs from the on-chain hash is refused', async () => {
  const r2 = await patient.createRecord(syntheticBundle(2048, 43));
  const { envelope } = await (async () => {
    const h = await signRequest(patient.sender.wallet, 'GET', `/records/${r2.recordId}`, '');
    return (await fetch(`${env.gatewayUrl}/records/${r2.recordId}`, { headers: h })).json();
  })();
  const tampered = { ...envelope, ciphertext: Buffer.from('tampered').toString('base64') };
  await assert.rejects(patient.http('PUT', `/records/${r2.recordId}`, { envelope: tampered, wrappedKeys: {} }), { status: 409 });
  await assert.rejects(outsider.http('PUT', `/records/${r2.recordId}`, { envelope, wrappedKeys: {} }), { status: 403 });
});

test('T7 revocation takes effect at the next request', async () => {
  const r3 = await patient.createRecord(syntheticBundle(2048, 44));
  await patient.grant(r3.recordId, hospital.address, 3600);
  await hospital.read(r3.recordId);
  await patient.revoke(r3.recordId, hospital.address);
  await assert.rejects(hospital.read(r3.recordId), { status: 403 });
});

test('T8 expired grants are no longer honoured', async () => {
  const r4 = await patient.createRecord(syntheticBundle(2048, 45));
  await patient.grant(r4.recordId, hospital.address, 6);
  await hospital.read(r4.recordId);
  // hasAccess compares the expiry with the latest block timestamp, which may lag the
  // wall clock by up to one block period; wait for the grant to expire on-chain.
  const latest = await env.prov.getBlock('latest');
  const previous = await env.prov.getBlock(latest.number - 1);
  const blockPeriodMs = Math.max(1, latest.timestamp - previous.timestamp) * 1000;
  await new Promise((r) => setTimeout(r, 6_000 + 2 * blockPeriodMs));
  await assert.rejects(hospital.read(r4.recordId), { status: 403 });
});

test('T9 patient identifier and name never appear in clear on the gateway or the ledger', async () => {
  const family = doc.entry[0].resource.name[0].family;
  const marker = doc.entry[0].resource.identifier[0].value;
  for (const f of listFiles(env.dataDir).filter((f) => !f.endsWith('requests.log'))) {
    const content = fs.readFileSync(f, 'utf8');
    assert.ok(!content.includes(marker) && !content.includes(`"family":"${family}"`), `clear text found in ${f}`);
  }
  const head = await env.prov.getBlockNumber();
  const markerHex = Buffer.from(marker).toString('hex');
  const familyHex = Buffer.from(family).toString('hex');
  for (let b = Math.max(1, head - 59); b <= head; b++) {
    const block = await env.prov.getBlock(b, true);
    for (const tx of block.prefetchedTransactions) {
      assert.ok(!tx.data.includes(markerHex), 'identifier found on-chain');
      assert.ok(!tx.data.includes(familyHex), 'patient name found on-chain');
    }
  }
});

test('F3 erasure removes ciphertext and keys and blocks every reader', async () => {
  const r5 = await patient.createRecord(syntheticBundle(2048, 46));
  await patient.grant(r5.recordId, hospital.address, 3600);
  await assert.rejects(patient.http('DELETE', `/records/${r5.recordId}`), { status: 409 });
  await patient.erase(r5.recordId);
  await assert.rejects(hospital.read(r5.recordId), { status: 410 });
  await assert.rejects(patient.read(r5.recordId), { status: 410 });
  assert.ok(!listFiles(env.dataDir).some((f) => f.includes(r5.recordId.toLowerCase())));
  assert.equal(await revertName(patient, 'grantAccess', [r5.recordId, hospital.address, 9_999_999_999n]), 'RecordIsErased');
  // the gateway also shreds a record erased on-chain whose owner never sent the DELETE request
  const r6 = await patient.createRecord(syntheticBundle(2048, 47));
  await patient.grant(r6.recordId, hospital.address, 3600);
  await patient.tx('eraseRecord', [r6.recordId], 200_000n);
  await assert.rejects(hospital.read(r6.recordId), { status: 410 });
  assert.ok(!listFiles(env.dataDir).some((f) => f.includes(r6.recordId.toLowerCase())));
});

test('F4 duplicate identifiers and empty digests are rejected', async () => {
  assert.equal(await revertName(patient, 'registerRecord', [rec.recordId, ethers.id('y')]), 'RecordExists');
  assert.equal(await revertName(patient, 'registerRecord', [ethers.id('new'), ethers.ZeroHash]), 'InvalidHash');
});

test('F5 invalid FHIR content never leaves the client', async () => {
  await assert.rejects(patient.createRecord({ resourceType: 'Patient', gender: 'robot' }), /invalid FHIR/);
});
