// Deterministic generator of synthetic HL7 FHIR R5 Bundles (no real patient data).
// Each Bundle has one Patient plus Observations, Conditions and MedicationStatements
// added until the serialised size reaches the requested number of bytes.
import crypto from 'node:crypto';

const GIVEN = ['Ana', 'Bruno', 'Carla', 'Diego', 'Elisa', 'Felipe', 'Gabriela', 'Heitor', 'Iara', 'Joao'];
const FAMILY = ['Silva', 'Souza', 'Oliveira', 'Pereira', 'Costa', 'Rodrigues', 'Almeida', 'Lima'];
const LOINC = [
  ['8867-4', 'Heart rate', '/min', 55, 110],
  ['8480-6', 'Systolic blood pressure', 'mm[Hg]', 95, 170],
  ['8462-4', 'Diastolic blood pressure', 'mm[Hg]', 55, 105],
  ['2339-0', 'Glucose [Mass/volume] in Blood', 'mg/dL', 65, 220],
  ['29463-7', 'Body weight', 'kg', 45, 120],
  ['8310-5', 'Body temperature', 'Cel', 35.5, 39.5],
];
const SNOMED = [
  ['38341003', 'Hypertensive disorder'],
  ['44054006', 'Diabetes mellitus type 2'],
  ['195967001', 'Asthma'],
  ['35489007', 'Depressive disorder'],
];
const RXNORM = [
  ['197361', 'Amlodipine 5 MG Oral Tablet'],
  ['860975', 'Metformin hydrochloride 500 MG Oral Tablet'],
  ['745679', 'Albuterol 0.09 MG/ACTUAT Inhaler'],
];

function rng(seed) {
  let s = crypto.createHash('sha256').update(String(seed)).digest().readUInt32LE(0) || 1;
  return () => ((s = (s * 1664525 + 1013904223) >>> 0) / 2 ** 32);
}

export function syntheticBundle(targetBytes = 4096, seed = 1) {
  const r = rng(seed);
  const pick = (a) => a[Math.floor(r() * a.length)];
  const pid = `p${seed}`;
  const patient = {
    resourceType: 'Patient',
    id: pid,
    identifier: [{ system: 'urn:chd:synthetic', value: crypto.createHash('sha1').update(String(seed)).digest('hex') }],
    name: [{ use: 'official', family: pick(FAMILY), given: [pick(GIVEN)] }],
    gender: pick(['male', 'female', 'other', 'unknown']),
    birthDate: `${1940 + Math.floor(r() * 70)}-0${1 + Math.floor(r() * 9)}-1${Math.floor(r() * 9)}`,
    address: [{ city: 'Springfield', state: 'XX', country: 'BR' }],
  };
  const bundle = { resourceType: 'Bundle', type: 'collection', entry: [{ fullUrl: `urn:uuid:${pid}`, resource: patient }] };
  const subject = { reference: `Patient/${pid}` };
  let i = 0;
  while (JSON.stringify(bundle).length < targetBytes) {
    i++;
    const kind = i % 10;
    let res;
    if (kind < 8) {
      const [code, display, unit, lo, hi] = pick(LOINC);
      res = {
        resourceType: 'Observation', id: `o${i}`, status: 'final',
        code: { coding: [{ system: 'http://loinc.org', code, display }] },
        subject,
        effectiveDateTime: `2025-${String(1 + (i % 12)).padStart(2, '0')}-${String(1 + (i % 28)).padStart(2, '0')}T10:00:00Z`,
        valueQuantity: { value: Math.round((lo + r() * (hi - lo)) * 10) / 10, unit, system: 'http://unitsofmeasure.org' },
      };
    } else if (kind === 8) {
      const [code, display] = pick(SNOMED);
      res = {
        resourceType: 'Condition', id: `c${i}`,
        clinicalStatus: { coding: [{ system: 'http://terminology.hl7.org/CodeSystem/condition-clinical', code: 'active' }] },
        code: { coding: [{ system: 'http://snomed.info/sct', code, display }] },
        subject,
      };
    } else {
      const [code, display] = pick(RXNORM);
      res = {
        resourceType: 'MedicationStatement', id: `m${i}`, status: 'recorded',
        medication: { concept: { coding: [{ system: 'http://www.nlm.nih.gov/research/umls/rxnorm', code, display }] } },
        subject,
      };
    }
    bundle.entry.push({ fullUrl: `urn:uuid:${res.id}-${pid}`, resource: res });
  }
  return bundle;
}
