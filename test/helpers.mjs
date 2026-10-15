import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { ethers } from 'ethers';
import { Sender, loadArtifact, provider, registryInterface } from '../src/chain.mjs';
import { createGateway } from '../src/gateway.mjs';
import { Actor } from '../src/client.mjs';

/** Deploys a fresh registry, starts an in-process gateway and creates actors. */
export async function setup({ institutions = 1, patients = 1 } = {}) {
  const rpcUrl = process.env.RPC_URL ?? 'http://127.0.0.1:8545';
  const prov = provider(rpcUrl);
  const admin = await new Sender(ethers.Wallet.createRandom().privateKey, prov).init();
  const { address: registryAddress } = await admin.deploy(loadArtifact('CHDRegistry'));
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'chd-gw-'));
  const app = createGateway({ registryAddress, rpcUrl, dataDir });
  const server = await new Promise((resolve) => {
    const s = app.listen(0, () => resolve(s));
  });
  const gatewayUrl = `http://127.0.0.1:${server.address().port}`;
  const mk = () => new Actor({ prov, registryAddress, gatewayUrl }).init();
  const pats = await Promise.all(Array.from({ length: patients }, mk));
  const insts = await Promise.all(Array.from({ length: institutions }, mk));
  const outsider = await mk();
  const iface = registryInterface();
  for (const i of insts) await admin.send(registryAddress, iface.encodeFunctionData('setInstitution', [i.address, true]));
  await Promise.all([...pats, ...insts, outsider].map((a) => a.publishEncryptionKey()));
  return {
    prov, admin, registryAddress, dataDir, gatewayUrl, patients: pats, institutions: insts, outsider,
    close: () => new Promise((r) => server.close(r)),
  };
}

/** Simulates a call from `actor` and returns the custom error name it reverts with. */
export async function revertName(actor, fn, args) {
  const c = new ethers.Contract(actor.registryAddress, loadArtifact('CHDRegistry').abi, actor.sender.wallet);
  try {
    await c[fn].staticCall(...args);
    return null;
  } catch (e) {
    return e.revert?.name ?? e.shortMessage ?? e.message;
  }
}

export function listFiles(dir) {
  return fs.readdirSync(dir, { recursive: true, withFileTypes: true })
    .filter((d) => d.isFile())
    .map((d) => path.join(d.parentPath ?? d.path, d.name));
}
