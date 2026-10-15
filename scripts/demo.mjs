// End-to-end demonstration: patient stores a FHIR Bundle, grants a hospital access,
// the hospital reads and audits it, the patient revokes and finally erases the record.
import { ethers } from 'ethers';
import { Sender, loadArtifact, provider, registryInterface } from '../src/chain.mjs';
import { createGateway } from '../src/gateway.mjs';
import { Actor } from '../src/client.mjs';
import { syntheticBundle } from '../bench/fhir-gen.mjs';
import os from 'node:os';
import fs from 'node:fs';
import path from 'node:path';

const rpcUrl = process.env.RPC_URL ?? 'http://127.0.0.1:8545';
const prov = provider(rpcUrl);
const admin = await new Sender(ethers.Wallet.createRandom().privateKey, prov).init();
const { address: registry } = await admin.deploy(loadArtifact('CHDRegistry'));
console.log(`registry deployed at ${registry}`);
const app = createGateway({ registryAddress: registry, rpcUrl, dataDir: fs.mkdtempSync(path.join(os.tmpdir(), 'chd-demo-')) });
const server = app.listen(0);
const gatewayUrl = `http://127.0.0.1:${server.address().port}`;

const patient = await new Actor({ prov, registryAddress: registry, gatewayUrl }).init();
const hospital = await new Actor({ prov, registryAddress: registry, gatewayUrl }).init();
await admin.send(registry, registryInterface().encodeFunctionData('setInstitution', [hospital.address, true]));
await Promise.all([patient.publishEncryptionKey(), hospital.publishEncryptionKey()]);

const bundle = syntheticBundle(8 * 1024, 1);
const rec = await patient.createRecord(bundle);
console.log(`record ${rec.recordId.slice(0, 12)}... stored (${rec.bytes} B ciphertext, ${rec.gasUsed} gas, ${rec.timings.totalMs.toFixed(0)} ms)`);
await hospital.read(rec.recordId).catch((e) => console.log(`hospital before grant: ${e.message}`));
await patient.grant(rec.recordId, hospital.address, 600);
const r = await hospital.read(rec.recordId);
console.log(`hospital read ${r.doc.entry.length} FHIR resources in ${r.timings.totalMs.toFixed(0)} ms`);
await hospital.logAccess(rec.recordId, r.requestHash);
console.log('access logged on-chain');
await patient.revoke(rec.recordId, hospital.address);
await hospital.read(rec.recordId).catch((e) => console.log(`hospital after revoke: ${e.message}`));
await patient.erase(rec.recordId);
console.log('record erased (on-chain flag + ciphertext and keys deleted)');
server.close();
process.exit(0);
