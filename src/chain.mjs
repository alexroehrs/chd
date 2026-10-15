// Thin helpers around ethers v6 for the CHD contracts on a zero-gas-price Besu network.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ethers } from 'ethers';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

export function loadArtifact(name) {
  return JSON.parse(fs.readFileSync(path.join(root, 'artifacts', `${name}.json`), 'utf8'));
}

export function provider(url = process.env.RPC_URL ?? 'http://127.0.0.1:8545') {
  const p = new ethers.JsonRpcProvider(url, undefined, { staticNetwork: true, batchMaxCount: 1 });
  p.pollingInterval = 100;
  return p;
}

/** Polls for a receipt every `intervalMs`; returns { receipt, latencyMs }. */
export async function waitReceipt(prov, txHash, t0, intervalMs = 50, timeoutMs = 120_000) {
  for (;;) {
    const receipt = await prov.getTransactionReceipt(txHash);
    if (receipt) {
      if (receipt.status !== 1) throw new Error(`transaction ${txHash} reverted`);
      return { receipt, latencyMs: performance.now() - t0 };
    }
    if (performance.now() - t0 > timeoutMs) throw new Error(`timeout waiting for ${txHash}`);
    await new Promise((r) => setTimeout(r, intervalMs));
  }
}

/**
 * A wallet that manages its own nonce and sends zero-price legacy transactions with a
 * fixed gas limit, so that latency measurements exclude extra estimation round trips.
 */
export class Sender {
  constructor(privateKey, prov) {
    this.prov = prov;
    this.wallet = new ethers.Wallet(privateKey, prov);
    this.address = this.wallet.address;
    this.nonce = null;
    this.chainId = null;
  }

  async init() {
    this.nonce = await this.prov.getTransactionCount(this.address, 'pending');
    this.chainId = (await this.prov.getNetwork()).chainId;
    return this;
  }

  /**
   * Submits a signed transaction. The nonce is reserved synchronously, before the first
   * await, so that concurrent calls never share one; on rejection by the node the local
   * counter is resynchronized with the pool.
   */
  async #submit(tx) {
    tx.nonce = this.nonce++;
    const signed = await this.wallet.signTransaction(tx);
    const t0 = performance.now();
    let hash;
    try {
      hash = await this.prov.send('eth_sendRawTransaction', [signed]);
    } catch (e) {
      this.nonce = await this.prov.getTransactionCount(this.address, 'pending');
      throw e;
    }
    return waitReceipt(this.prov, hash, t0);
  }

  /** Sends `data` to `to`; returns { receipt, latencyMs, gasUsed }. */
  async send(to, data, gasLimit = 500_000n) {
    const { receipt, latencyMs } = await this.#submit({ to, data, gasLimit, gasPrice: 0n, chainId: this.chainId, type: 0 });
    return { receipt, latencyMs, gasUsed: receipt.gasUsed };
  }

  async deploy(artifact, gasLimit = 6_000_000n) {
    const { receipt, latencyMs } = await this.#submit({ data: artifact.bytecode, gasLimit, gasPrice: 0n, chainId: this.chainId, type: 0 });
    return { address: receipt.contractAddress, receipt, latencyMs };
  }
}

export function registryInterface() {
  return new ethers.Interface(loadArtifact('CHDRegistry').abi);
}

export function registryReader(address, prov) {
  return new ethers.Contract(address, loadArtifact('CHDRegistry').abi, prov);
}

export function deploymentFile() {
  return path.join(root, 'deployment.json');
}

export function readDeployment() {
  return JSON.parse(fs.readFileSync(deploymentFile(), 'utf8'));
}
