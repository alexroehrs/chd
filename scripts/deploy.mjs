// Deploys CHDRegistry and the on-chain baseline; writes deployment.json, which contains the
// development admin private key and is therefore gitignored (local use only).
import fs from 'node:fs';
import { ethers } from 'ethers';
import { Sender, deploymentFile, loadArtifact, provider } from '../src/chain.mjs';

const rpcUrl = process.env.RPC_URL ?? 'http://127.0.0.1:8545';
const prov = provider(rpcUrl);
// Development-only administrator key; production deployments use a consortium multisig.
const adminKey = process.env.ADMIN_KEY ?? ethers.Wallet.createRandom().privateKey;
const admin = await new Sender(adminKey, prov).init();

const reg = await admin.deploy(loadArtifact('CHDRegistry'));
const base = await admin.deploy(loadArtifact('OnChainBaseline'));
const dep = {
  rpcUrl,
  chainId: Number(admin.chainId),
  CHDRegistry: reg.address,
  OnChainBaseline: base.address,
  deployGas: { CHDRegistry: reg.receipt.gasUsed.toString(), OnChainBaseline: base.receipt.gasUsed.toString() },
  adminKey,
  deployedAt: new Date().toISOString(),
};
fs.writeFileSync(deploymentFile(), JSON.stringify(dep, null, 2));
console.log(`CHDRegistry ${reg.address} (gas ${dep.deployGas.CHDRegistry})`);
console.log(`OnChainBaseline ${base.address} (gas ${dep.deployGas.OnChainBaseline})`);
