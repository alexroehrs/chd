// Offline tests: envelope encryption and FHIR validation.
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  decryptRecord, encryptRecord, envelopeBytes, generateEncryptionKeyPair,
  newRecordId, sha256Hex, unwrapKey, wrapKey,
} from '../src/crypto.mjs';
import { validateFhir } from '../src/fhir.mjs';
import { syntheticBundle } from '../bench/fhir-gen.mjs';

test('encrypt/decrypt round trip with wrapped key', () => {
  const id = newRecordId();
  const kp = generateEncryptionKeyPair();
  const plain = Buffer.from(JSON.stringify(syntheticBundle(8192, 7)));
  const { envelope, dek } = encryptRecord(id, plain);
  const wrapped = wrapKey(dek, kp.publicKeyHex, id);
  const dek2 = unwrapKey(wrapped, kp.privateKey, kp.publicKeyHex, id);
  assert.deepEqual(decryptRecord(envelope, dek2), plain);
});

test('tampered ciphertext is rejected by GCM authentication', () => {
  const id = newRecordId();
  const { envelope, dek } = encryptRecord(id, Buffer.from('{"resourceType":"Patient"}'));
  const ct = Buffer.from(envelope.ciphertext, 'base64');
  ct[0] ^= 0xff;
  assert.throws(() => decryptRecord({ ...envelope, ciphertext: ct.toString('base64') }, dek));
});

test('envelope cannot be replayed under another record id (AAD binding)', () => {
  const { envelope, dek } = encryptRecord(newRecordId(), Buffer.from('x'));
  assert.throws(() => decryptRecord({ ...envelope, recordId: newRecordId() }, dek));
});

test('a different recipient cannot unwrap the data key', () => {
  const id = newRecordId();
  const alice = generateEncryptionKeyPair();
  const mallory = generateEncryptionKeyPair();
  const { dek } = encryptRecord(id, Buffer.from('x'));
  const wrapped = wrapKey(dek, alice.publicKeyHex, id);
  assert.throws(() => unwrapKey(wrapped, mallory.privateKey, alice.publicKeyHex, id));
  assert.throws(() => unwrapKey(wrapped, mallory.privateKey, mallory.publicKeyHex, id));
});

test('digest changes with any envelope change', () => {
  const id = newRecordId();
  const { envelope } = encryptRecord(id, Buffer.from('abc'));
  const h1 = sha256Hex(envelopeBytes(envelope));
  const h2 = sha256Hex(envelopeBytes({ ...envelope, tag: Buffer.alloc(16).toString('base64') }));
  assert.notEqual(h1, h2);
});

test('synthetic bundles are valid FHIR; malformed content is rejected', () => {
  for (const size of [1024, 16384, 262144]) assert.equal(validateFhir(syntheticBundle(size, size)).valid, true);
  assert.equal(validateFhir({ resourceType: 'Patient', gender: 'robot' }).valid, false);
  assert.equal(validateFhir({ resourceType: 'Bundle', type: 'collection', entry: [] }).valid, false);
  assert.equal(validateFhir({ foo: 'bar' }).valid, false);
  const noSubject = { resourceType: 'Observation', status: 'final', code: { text: 'x' } };
  assert.equal(validateFhir(noSubject).valid, false);
  // R5 shapes: Condition requires clinicalStatus; MedicationStatement uses a CodeableReference
  const subject = { reference: 'Patient/p1' };
  assert.equal(validateFhir({ resourceType: 'Condition', code: { text: 'x' }, subject }).valid, false);
  const r4Medication = { resourceType: 'MedicationStatement', status: 'active', medicationCodeableConcept: { text: 'x' }, subject };
  assert.equal(validateFhir(r4Medication).valid, false);
  const r5Medication = { resourceType: 'MedicationStatement', status: 'recorded', medication: { concept: { text: 'x' } }, subject };
  assert.equal(validateFhir(r5Medication).valid, true);
});
