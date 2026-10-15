// Compiles the Solidity contracts with the solc-js (WebAssembly) compiler pinned in
// package.json, so no native compiler download is needed.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import solc from 'solc';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const contractsDir = path.join(root, 'contracts');
const outDir = path.join(root, 'artifacts');

const sources = {};
for (const f of fs.readdirSync(contractsDir).filter((f) => f.endsWith('.sol'))) {
  sources[f] = { content: fs.readFileSync(path.join(contractsDir, f), 'utf8') };
}

const input = {
  language: 'Solidity',
  sources,
  settings: {
    optimizer: { enabled: true, runs: 200 },
    evmVersion: 'london',
    outputSelection: { '*': { '*': ['abi', 'evm.bytecode.object', 'evm.deployedBytecode.object'] } },
  },
};

const output = JSON.parse(solc.compile(JSON.stringify(input)));
const errors = (output.errors || []).filter((e) => e.severity === 'error');
for (const e of output.errors || []) console.error(e.formattedMessage);
if (errors.length) process.exit(1);

fs.mkdirSync(outDir, { recursive: true });
for (const [file, contracts] of Object.entries(output.contracts)) {
  for (const [name, c] of Object.entries(contracts)) {
    const artifact = {
      contractName: name,
      sourceName: file,
      compiler: solc.version(),
      abi: c.abi,
      bytecode: '0x' + c.evm.bytecode.object,
      deployedBytecodeSize: c.evm.deployedBytecode.object.length / 2,
    };
    fs.writeFileSync(path.join(outDir, `${name}.json`), JSON.stringify(artifact, null, 2));
    console.log(`compiled ${name} (${artifact.deployedBytecodeSize} bytes deployed) with solc ${solc.version()}`);
  }
}
