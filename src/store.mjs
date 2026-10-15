// Off-chain storage of encrypted envelopes and wrapped keys (filesystem backend).
// The store only ever holds ciphertext; it can be replaced by an object store or IPFS
// without changing the protocol, because integrity is checked against the on-chain digest.
import fs from 'node:fs/promises';
import path from 'node:path';

export const HEX32 = /^0x[0-9a-fA-F]{64}$/;
export const ADDR = /^0x[0-9a-fA-F]{40}$/;

/** Writes atomically (temporary file and rename) so readers never see a partial file. */
async function writeAtomic(file, data) {
  const tmp = `${file}.${process.pid}.${Date.now()}.tmp`;
  await fs.writeFile(tmp, data);
  await fs.rename(tmp, file);
}

export class EnvelopeStore {
  constructor(dir) {
    this.dir = dir;
  }

  #recDir(recordId) {
    const id = recordId.toLowerCase();
    if (!/^0x[0-9a-f]{64}$/.test(id)) throw new Error('invalid record id');
    return path.join(this.dir, id);
  }

  async putEnvelope(recordId, envelope) {
    const d = this.#recDir(recordId);
    await fs.mkdir(path.join(d, 'keys'), { recursive: true });
    await writeAtomic(path.join(d, 'envelope.json'), JSON.stringify(envelope));
  }

  async getEnvelope(recordId) {
    try {
      return JSON.parse(await fs.readFile(path.join(this.#recDir(recordId), 'envelope.json'), 'utf8'));
    } catch {
      return null;
    }
  }

  async putKey(recordId, address, wrapped) {
    const a = address.toLowerCase();
    if (!/^0x[0-9a-f]{40}$/.test(a)) throw new Error('invalid address');
    const d = path.join(this.#recDir(recordId), 'keys');
    await fs.mkdir(d, { recursive: true });
    await writeAtomic(path.join(d, `${a}.json`), JSON.stringify(wrapped));
  }

  async getKey(recordId, address) {
    try {
      const a = address.toLowerCase();
      return JSON.parse(await fs.readFile(path.join(this.#recDir(recordId), 'keys', `${a}.json`), 'utf8'));
    } catch {
      return null;
    }
  }

  /** Crypto-shredding: removes ciphertext and every wrapped data key of the record. */
  async erase(recordId) {
    await fs.rm(this.#recDir(recordId), { recursive: true, force: true });
  }
}
