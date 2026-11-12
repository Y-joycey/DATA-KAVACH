import { DomainType, InternalFinding } from '../types.ts';
import { NormalizedView, mapNormSpanToOrig } from '../pipeline/normalize.ts';

export const DICTIONARY_VERSION = 'minearena-abbr-dict-v2.1';

const MONTHS_RE =
  '(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:t(?:ember)?)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)';

// Covers:
// - Named-month with day & year ("Nov 10 2026", "November 10th, 2026", "10 Nov 2026", "1st January 2025", "10-Nov-26")
// - ISO / Year-first ("2026-11-10", "2026/11/10", "2026.11.10")
// - Numeric DMY/MDY ("10/11/2026", "10-11-2026", "10.11.2026", "10/11/26", "10.11.26") — guarded against IP octets
// - Month-Year ("Nov 2026", "January 1995", "08/1994", "11-2026")
const DATE_PATTERN_RE = new RegExp(
  `(?<!\\d)(?<!\\d\\.)(?:` +
    `${MONTHS_RE}\\s+\\d{1,2}(?:st|nd|rd|th)?,?\\s+\\d{2,4}` +
    `|\\d{1,2}(?:st|nd|rd|th)?[\\s-]${MONTHS_RE},?[\\s-]\\d{2,4}` +
    `|(?:19|20)\\d{2}[\\/\\-.](?:0?[1-9]|1[0-2])[\\/\\-.](?:0?[1-9]|[12]\\d|3[01])` +
    `|(?:0?[1-9]|[12]\\d|3[01])[\\/\\-.](?:0?[1-9]|[12]\\d|3[01])[\\/\\-.]\\d{2,4}` +
    `|${MONTHS_RE}[\\s-]+(?:19|20)\\d{2}` +
    `|(?:0?[1-9]|1[0-2])[\\/\\-](?:19|20)\\d{2}` +
  `)(?!\\d)(?!\\.\\d)`,
  'gi'
);

export function detectDatesAndContext(
  view: NormalizedView,
  domain: DomainType
): InternalFinding[] {
  const findings: InternalFinding[] = [];
  const text = view.normalized;
  let m: RegExpExecArray | null;

  // 1. Contextual Date & DOB Parser
  while ((m = DATE_PATTERN_RE.exec(text)) !== null) {
    const rawDate = m[0];
    const windowBefore = text.slice(Math.max(0, m.index - 40), m.index);
    const mapped = mapNormSpanToOrig(view, m.index, m.index + rawDate.length);

    const isDob = /\b(?:DOB|D\.O\.B|Date\s+of\s+Birth|Birth\s+Date|Born|Janam\s*Dinank|जन्म\s*तिथि|ಜನ್ಮ\s*ದಿನಾಂಕ)\s*[:\-–=]?\s*$/i.test(
      windowBefore
    );
    const isAdmissionOrTxn = /\b(?:ADM_DT|Admission\s+Date|Admitted\s+on|TXN_DT|Transaction\s+Date|Discharged\s+on|Joining\s+Date|Dated)\s*[:\-–=]?\s*$/i.test(
      windowBefore
    );

    const ambiguity: string[] = [];
    const numericMatch = rawDate.match(/^(\d{1,2})[\/\-.](\d{1,2})[\/\-.](\d{2,4})$/);
    if (numericMatch) {
      const p1 = parseInt(numericMatch[1], 10);
      const p2 = parseInt(numericMatch[2], 10);
      if (p1 <= 12 && p2 <= 12 && p1 !== p2) {
        ambiguity.push('ambiguous_dd_mm_vs_mm_dd');
      }
    }

    if (isDob) {
      findings.push({
        id: `f_dob_${mapped.start}`,
        entity_type: 'DATE_OF_BIRTH',
        start: mapped.start,
        end: mapped.end,
        raw_value: mapped.raw,
        detector: 'context+date_parser',
        detectors_provenance: ['context_engine', 'date_parser'],
        confidence: ambiguity.length > 0 ? 0.84 : 0.96,
        confidence_band: 'HIGH',
        classification: ['PERSONAL_DATA'],
        domain,
        context_label: 'DOB',
        ambiguity,
      });
    } else if (isAdmissionOrTxn) {
      findings.push({
        id: `f_ctx_date_${mapped.start}`,
        entity_type: 'CONTEXTUAL_DATE',
        start: mapped.start,
        end: mapped.end,
        raw_value: mapped.raw,
        detector: 'context+date_parser',
        detectors_provenance: ['context_engine', 'date_parser'],
        confidence: 0.92,
        confidence_band: 'HIGH',
        classification: ['PERSONAL_DATA'],
        domain,
        context_label: 'Admission/Transaction/Event Date',
        ambiguity,
      });
    } else {
      findings.push({
        id: `f_event_date_${mapped.start}`,
        entity_type: 'CONTEXTUAL_DATE',
        start: mapped.start,
        end: mapped.end,
        raw_value: mapped.raw,
        detector: 'date_parser',
        detectors_provenance: ['date_parser'],
        confidence: 0.88,
        confidence_band: 'HIGH',
        classification: ['PERSONAL_DATA'],
        domain,
        context_label: 'Date expression (hidden by policy)',
        ambiguity,
      });
    }
  }

  // 2. Domain-Scoped Abbreviations & Ambiguous Short Forms (CIF, UTR, CID, DM)
  const cifRe = /\b(?:CIF|CIF\s*No\.?)\s*[:#\-]?\s*([A-Z0-9]{6,14})\b/gi;
  while ((m = cifRe.exec(text)) !== null) {
    const val = m[1];
    const valStart = m.index + m[0].lastIndexOf(val);
    const mapped = mapNormSpanToOrig(view, valStart, valStart + val.length);
    findings.push({
      id: `f_cif_${mapped.start}`,
      entity_type: 'BANK_ACCOUNT',
      start: mapped.start,
      end: mapped.end,
      raw_value: mapped.raw,
      detector: 'abbreviation_dictionary',
      detectors_provenance: ['abbreviation_dictionary_v2.1'],
      confidence: domain === 'loan' || domain === 'kyc' ? 0.91 : 0.78,
      confidence_band: 'MEDIUM',
      classification: ['PERSONAL_DATA'],
      domain,
      context_label: 'CIF abbreviation',
      ambiguity: domain === 'general' ? ['domain_unconfirmed_abbreviation'] : [],
    });
  }

  const utrRe = /\b(?:UTR|UTR\s*(?:No\.?|Ref|Code))\s*[:#\-]?\s*([A-Z0-9]{10,24})\b/gi;
  while ((m = utrRe.exec(text)) !== null) {
    const val = m[1];
    const valStart = m.index + m[0].lastIndexOf(val);
    const mapped = mapNormSpanToOrig(view, valStart, valStart + val.length);
    findings.push({
      id: `f_utr_${mapped.start}`,
      entity_type: 'TRANSACTION_REFERENCE',
      start: mapped.start,
      end: mapped.end,
      raw_value: mapped.raw,
      detector: 'abbreviation_dictionary',
      detectors_provenance: ['abbreviation_dictionary_v2.1'],
      confidence: 0.94,
      confidence_band: 'HIGH',
      classification: ['PERSONAL_DATA'],
      domain,
      context_label: 'UTR transaction reference',
      ambiguity: [],
    });
  }

  // Ambiguous short forms: CID / DM with weak value shape -> retain ambiguity & route to REVIEW
  const ambigAbbrRe = /\b(CID|DM)\s*[:#\-]?\s*([A-Z0-9\-]{4,14})\b/g;
  while ((m = ambigAbbrRe.exec(text)) !== null) {
    const label = m[1];
    const val = m[2];
    const valStart = m.index + m[0].lastIndexOf(val);
    const mapped = mapNormSpanToOrig(view, valStart, valStart + val.length);
    findings.push({
      id: `f_abbr_ambig_${mapped.start}`,
      entity_type: 'UNKNOWN_IDENTIFIER',
      start: mapped.start,
      end: mapped.end,
      raw_value: mapped.raw,
      detector: 'abbreviation_dictionary',
      detectors_provenance: ['abbreviation_dictionary_v2.1'],
      confidence: 0.58,
      confidence_band: 'LOW',
      classification: ['PERSONAL_DATA'],
      domain,
      context_label: `Ambiguous abbreviation (${label})`,
      ambiguity: [`ambiguous_abbreviation_${label}`],
    });
  }

  // 3. Indic / Code-Mixed Patterns (Tested Hindi Devanagari, Hinglish, and Kannada)
  // Devanagari person after मेरा नाम / नाम:
  const hiNameRe = /(?:मेरा\s+नाम|नाम)\s*[:\-–]?\s*([\u0900-\u097F]+(?:\s+[\u0900-\u097F]+){0,2})/g;
  while ((m = hiNameRe.exec(text)) !== null) {
    const val = m[1].replace(/\s+(?:है|हूँ)$/u, '').trim();
    if (!val) continue;
    const valStart = m.index + m[0].indexOf(val);
    const mapped = mapNormSpanToOrig(view, valStart, valStart + val.length);
    findings.push({
      id: `f_hi_name_${mapped.start}`,
      entity_type: 'PERSON',
      start: mapped.start,
      end: mapped.end,
      raw_value: mapped.raw,
      detector: 'indic_hindi_codemix_ner',
      detectors_provenance: ['indic_hindi_codemix_ner'],
      confidence: 0.9,
      confidence_band: 'HIGH',
      classification: ['PERSONAL_DATA'],
      domain,
      context_label: 'Hindi name cue',
      ambiguity: [],
    });
  }

  // Hinglish "Mera naam Rahul Sharma hai" or "naam Priya Verma"
  const hinglishNameRe = /\b(?:mera\s+naam|naam)\s+([A-Z][a-z]{2,20}(?:\s+[A-Z][a-z]{2,20}){0,2})(?=\s+(?:hai|h|aur|ka|ki|ke)\b|[.,;\n]|$)/gi;
  while ((m = hinglishNameRe.exec(text)) !== null) {
    const val = m[1].trim();
    const valStart = m.index + m[0].indexOf(val);
    const mapped = mapNormSpanToOrig(view, valStart, valStart + val.length);
    findings.push({
      id: `f_hinglish_name_${mapped.start}`,
      entity_type: 'PERSON',
      start: mapped.start,
      end: mapped.end,
      raw_value: mapped.raw,
      detector: 'indic_hinglish_ner',
      detectors_provenance: ['indic_hinglish_ner'],
      confidence: 0.91,
      confidence_band: 'HIGH',
      classification: ['PERSONAL_DATA'],
      domain,
      context_label: 'Hinglish name cue',
      ambiguity: [],
    });
  }

  // Kannada name/address cues: ಹೆಸರು: / ನನ್ನ ಹೆಸರು ... / ವಿಳಾಸ:
  const knNameRe = /(?:ನನ್ನ\s+ಹೆಸರು|ಹೆಸರು)\s*[:\-–]?\s*([\u0C80-\u0CFF]+(?:\s+[\u0C80-\u0CFF]+){0,2}|[A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,2})/g;
  while ((m = knNameRe.exec(text)) !== null) {
    const val = m[1].trim();
    const valStart = m.index + m[0].indexOf(val);
    const mapped = mapNormSpanToOrig(view, valStart, valStart + val.length);
    findings.push({
      id: `f_kn_name_${mapped.start}`,
      entity_type: 'PERSON',
      start: mapped.start,
      end: mapped.end,
      raw_value: mapped.raw,
      detector: 'indic_kannada_ner',
      detectors_provenance: ['indic_kannada_ner'],
      confidence: 0.9,
      confidence_band: 'HIGH',
      classification: ['PERSONAL_DATA'],
      domain,
      context_label: 'Kannada name cue',
      ambiguity: [],
    });
  }

  const knAddrRe = /(?:ವಿಳಾಸ|ಪೂರ್ಣ\s+ವಿಳಾಸ)\s*[:\-–]\s*([^\n;]{10,160})/g;
  while ((m = knAddrRe.exec(text)) !== null) {
    const val = m[1].trim();
    const valStart = m.index + m[0].indexOf(val);
    const mapped = mapNormSpanToOrig(view, valStart, valStart + val.length);
    findings.push({
      id: `f_kn_addr_${mapped.start}`,
      entity_type: 'ADDRESS',
      start: mapped.start,
      end: mapped.end,
      raw_value: mapped.raw,
      detector: 'indic_kannada_ner',
      detectors_provenance: ['indic_kannada_ner'],
      confidence: 0.9,
      confidence_band: 'HIGH',
      classification: ['PERSONAL_DATA'],
      domain,
      context_label: 'Kannada address cue',
      ambiguity: [],
    });
  }

  return findings;
}

/**
 * Unknown-risk candidate detector: catches unseen identifier-like strings
 * adjacent to sensitive labels without treating every number as PII.
 */
export function detectUnknownRiskCandidates(
  view: NormalizedView,
  domain: DomainType,
  existingFindings: InternalFinding[]
): InternalFinding[] {
  const candidates: InternalFinding[] = [];
  const text = view.normalized;

  const unknownLabelRe =
    /\b(?:Member\s*(?:ID|No\.?)|Beneficiary\s*Ref|National\s*ID|Passport\s*Ref|Gov\s*ID|Token\s*ID|Cust(?:omer)?\s*Ref|Secret\s*Code|Auth\s*Code|PIN)\s*[:#\-=]\s*([A-Z0-9][A-Z0-9\-_]{5,22})\b/gi;

  let m: RegExpExecArray | null;
  while ((m = unknownLabelRe.exec(text)) !== null) {
    const val = m[1];
    const valStart = m.index + m[0].lastIndexOf(val);
    const mapped = mapNormSpanToOrig(view, valStart, valStart + val.length);

    // Skip if already covered by a specific recognizer
    const alreadyCovered = existingFindings.some(
      (f) => !(mapped.end <= f.start || mapped.start >= f.end)
    );
    if (alreadyCovered) continue;

    // Require at least some digits to avoid matching plain English prose words
    if (!/\d/.test(val)) continue;

    candidates.push({
      id: `f_unk_${mapped.start}`,
      entity_type: 'UNKNOWN_IDENTIFIER',
      start: mapped.start,
      end: mapped.end,
      raw_value: mapped.raw,
      detector: 'unknown_risk_heuristic',
      detectors_provenance: ['unknown_risk_heuristic'],
      confidence: 0.64,
      confidence_band: 'LOW',
      classification: ['PERSONAL_DATA'],
      domain,
      context_label: 'Unrecognized identifier-like token near sensitive label',
      ambiguity: ['unseen_identifier_pattern_requires_review'],
    });
  }

  return candidates;
}
