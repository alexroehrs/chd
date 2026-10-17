// Structural validation of HL7 FHIR R5 (v5.0.0) content accepted by CHD clients.
// Validation happens on the client, before encryption, because the gateway only ever
// sees ciphertext. This is a structural check of the subset used by CHD (Bundle,
// Patient, Observation, Condition, MedicationStatement, AllergyIntolerance,
// Encounter). It checks resource types, required elements, identifier syntax, code
// systems and the overall date format; profile validation and calendar validity of dates
// are outside its scope.

const ID_RE = /^[A-Za-z0-9\-.]{1,64}$/;
const DATE_RE = /^\d{4}(-\d{2}(-\d{2})?)?$/;
const DATETIME_RE = /^\d{4}(-\d{2}(-\d{2}(T\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}:\d{2})?)?)?)?$/;
const GENDERS = new Set(['male', 'female', 'other', 'unknown']);
const BUNDLE_TYPES = new Set([
  'document', 'message', 'transaction', 'transaction-response', 'batch', 'batch-response', 'history',
  'searchset', 'collection', 'subscription-notification',
]);
const OBSERVATION_STATUS = new Set([
  'registered', 'preliminary', 'final', 'amended', 'corrected', 'cancelled', 'entered-in-error', 'unknown',
]);
const MEDICATION_STATEMENT_STATUS = new Set(['recorded', 'entered-in-error', 'draft']);
const SUPPORTED = new Set([
  'Patient', 'Observation', 'Condition', 'MedicationStatement', 'AllergyIntolerance', 'Encounter',
]);

function checkCodeableConcept(cc, where, errors) {
  if (!cc || typeof cc !== 'object') return errors.push(`${where}: CodeableConcept required`);
  if (cc.coding !== undefined) {
    if (!Array.isArray(cc.coding)) return errors.push(`${where}.coding must be an array`);
    cc.coding.forEach((c, i) => {
      if (!c || typeof c !== 'object' || typeof c.system !== 'string' || typeof c.code !== 'string') {
        errors.push(`${where}.coding[${i}] requires system and code`);
      }
    });
  } else if (typeof cc.text !== 'string') {
    errors.push(`${where}: coding or text required`);
  }
}

// R5 CodeableReference: a concept, a reference, or both.
function checkCodeableReference(cr, where, errors) {
  if (!cr || typeof cr !== 'object' || (cr.concept === undefined && cr.reference === undefined)) {
    return errors.push(`${where}: CodeableReference requires concept or reference`);
  }
  if (cr.concept !== undefined) checkCodeableConcept(cr.concept, `${where}.concept`, errors);
  if (cr.reference !== undefined) checkReference(cr.reference, `${where}.reference`, errors);
}

function checkReference(ref, where, errors) {
  if (!ref || typeof ref.reference !== 'string' || !/^(urn:uuid:|[A-Za-z]+\/)/.test(ref.reference)) {
    errors.push(`${where}: invalid Reference`);
  }
}

function validateResource(r, where, errors) {
  if (!r || typeof r !== 'object') return errors.push(`${where}: resource must be an object`);
  if (!SUPPORTED.has(r.resourceType)) return errors.push(`${where}: unsupported resourceType ${r.resourceType}`);
  if (r.id !== undefined && (typeof r.id !== 'string' || !ID_RE.test(r.id))) errors.push(`${where}.id is not a valid FHIR id`);
  switch (r.resourceType) {
    case 'Patient':
      if (r.gender !== undefined && !GENDERS.has(r.gender)) errors.push(`${where}.gender invalid`);
      if (r.birthDate !== undefined && !DATE_RE.test(r.birthDate)) errors.push(`${where}.birthDate invalid`);
      if (r.name !== undefined && !Array.isArray(r.name)) errors.push(`${where}.name must be an array`);
      break;
    case 'Observation':
      if (!OBSERVATION_STATUS.has(r.status)) errors.push(`${where}.status invalid`);
      checkCodeableConcept(r.code, `${where}.code`, errors);
      checkReference(r.subject, `${where}.subject`, errors);
      if (r.effectiveDateTime !== undefined && !DATETIME_RE.test(r.effectiveDateTime)) {
        errors.push(`${where}.effectiveDateTime invalid`);
      }
      break;
    case 'Condition':
      checkCodeableConcept(r.clinicalStatus, `${where}.clinicalStatus`, errors);
      if (r.code !== undefined) checkCodeableConcept(r.code, `${where}.code`, errors);
      checkReference(r.subject, `${where}.subject`, errors);
      break;
    case 'AllergyIntolerance':
      if (r.code !== undefined) checkCodeableConcept(r.code, `${where}.code`, errors);
      checkReference(r.patient, `${where}.patient`, errors);
      break;
    case 'MedicationStatement':
      if (!MEDICATION_STATEMENT_STATUS.has(r.status)) errors.push(`${where}.status invalid`);
      checkCodeableReference(r.medication, `${where}.medication`, errors);
      checkReference(r.subject, `${where}.subject`, errors);
      break;
    case 'Encounter':
      if (typeof r.status !== 'string') errors.push(`${where}.status required`);
      checkReference(r.subject, `${where}.subject`, errors);
      break;
  }
}

/** Returns { valid, errors } for a FHIR R5 Bundle or a single supported resource. */
export function validateFhir(doc) {
  const errors = [];
  if (doc?.resourceType === 'Bundle') {
    if (!BUNDLE_TYPES.has(doc.type)) errors.push('Bundle.type invalid');
    if (!Array.isArray(doc.entry) || doc.entry.length === 0) {
      errors.push('Bundle.entry must be a non-empty array');
    } else {
      doc.entry.forEach((e, i) => validateResource(e?.resource, `Bundle.entry[${i}].resource`, errors));
      if (!doc.entry.some((e) => e?.resource?.resourceType === 'Patient')) errors.push('Bundle must contain a Patient');
    }
  } else {
    validateResource(doc, doc?.resourceType ?? 'resource', errors);
  }
  return { valid: errors.length === 0, errors };
}
