import { DomainType, InternalFinding } from '../types.ts';
import { NormalizedView, mapNormSpanToOrig } from '../pipeline/normalize.ts';

// Verhoeff checksum tables for 12-digit Aadhaar validation
const VERHOEFF_D = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
  [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
  [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
  [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
  [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
  [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
  [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
  [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
  [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
  [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
];

const VERHOEFF_P = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
  [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
  [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
  [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
  [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
  [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
  [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
  [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
];

export function verifyVerhoeff(numStr: string): boolean {
  if (!/^\d+$/.test(numStr)) return false;
  let c = 0;
  const digits = numStr.split('').reverse().map(Number);
  for (let i = 0; i < digits.length; i++) {
    c = VERHOEFF_D[c][VERHOEFF_P[i % 8][digits[i]]];
  }
  return c === 0;
}

/** Generate a valid synthetic Aadhaar check digit for test fixtures */
export function computeVerhoeffCheckDigit(elevenDigits: string): string {
  const inv = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9];
  let c = 0;
  const digits = elevenDigits.split('').reverse().map(Number);
  for (let i = 0; i < digits.length; i++) {
    c = VERHOEFF_D[c][VERHOEFF_P[(i + 1) % 8][digits[i]]];
  }
  return String(inv[c]);
}

const GSTIN_CHARSET = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ';
export function verifyGstinChecksum(gstin: string): boolean {
  if (!/^[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z][1-9A-Z]Z[0-9A-Z]$/.test(gstin)) {
    return false;
  }
  const stateCode = parseInt(gstin.slice(0, 2), 10);
  if (stateCode < 1 || stateCode > 38) return false;

  let factor = 2;
  let sum = 0;
  const mod = GSTIN_CHARSET.length;
  for (let i = gstin.length - 2; i >= 0; i--) {
    const codePoint = GSTIN_CHARSET.indexOf(gstin[i]);
    if (codePoint === -1) return false;
    let digit = factor * codePoint;
    factor = factor === 2 ? 1 : 2;
    digit = Math.floor(digit / mod) + (digit % mod);
    sum += digit;
  }
  const checkCode = (mod - (sum % mod)) % mod;
  return GSTIN_CHARSET[checkCode] === gstin[gstin.length - 1];
}

const PAN_ENTITY_CODES = new Set(['P', 'C', 'H', 'A', 'B', 'G', 'J', 'L', 'F', 'T']);

function hasContextNearby(text: string, idx: number, keywords: RegExp): boolean {
  const windowStart = Math.max(0, idx - 48);
  const windowEnd = Math.min(text.length, idx + 48);
  return keywords.test(text.slice(windowStart, windowEnd));
}

export function detectIndianIdentifiers(
  view: NormalizedView,
  domain: DomainType
): InternalFinding[] {
  const findings: InternalFinding[] = [];
  const text = view.normalized;

  // 1. AADHAAR (12-digit starting 2-9, allowing spaces/hyphens; must not be a slice of 14/16-digit IDs)
  const aadhaarRe = /(?<![\d-])([2-9]\d{3}[\s-]?\d{4}[\s-]?\d{4})(?![\d-])/g;
  let m: RegExpExecArray | null;
  while ((m = aadhaarRe.exec(text)) !== null) {
    const candidate = m[1];
    const digits = candidate.replace(/[\s-]/g, '');
    const context = hasContextNearby(
      text,
      m.index,
      /\b(aadhaar|aadhar|uid|uidai|आधार|ಆಧಾರ್)\b/i
    );
    const financialRefContext = hasContextNearby(
      text,
      m.index,
      /\b(utr|rrn|txn|transaction|upi\s*ref|imps|neft|rtgs|payment\s*ref|a\/c|acc|acct|account|savings|current)\b/i
    );
    if (financialRefContext && !context) continue;

    const validVerhoeff = verifyVerhoeff(digits);
    const mapped = mapNormSpanToOrig(view, m.index, m.index + candidate.length);

    if (validVerhoeff || context) {
      findings.push({
        id: `f_aadhaar_${mapped.start}`,
        entity_type: 'AADHAAR',
        start: mapped.start,
        end: mapped.end,
        raw_value: mapped.raw,
        detector: validVerhoeff ? 'presidio_india+verhoeff' : 'presidio_india_regex',
        detectors_provenance: validVerhoeff
          ? ['presidio_india_aadhaar', 'verhoeff_checksum']
          : ['presidio_india_aadhaar'],
        confidence: validVerhoeff && context ? 0.99 : validVerhoeff ? 0.92 : 0.72,
        confidence_band: validVerhoeff ? 'HIGH' : 'MEDIUM',
        classification: ['PERSONAL_DATA'],
        domain,
        context_label: context ? 'Aadhaar context label' : undefined,
        ambiguity: validVerhoeff ? [] : ['checksum_mismatch_requires_review'],
      });
    }
  }

  // 2. GSTIN (15 chars, embeds PAN at chars 2..12)
  const gstinRe = /\b([0-9]{2}[A-Z]{5}[0-9]{4}[A-Z][1-9A-Z]Z[0-9A-Z])\b/g;
  const gstinSpans: Array<{ start: number; end: number }> = [];
  while ((m = gstinRe.exec(text)) !== null) {
    const candidate = m[1];
    const checksumOk = verifyGstinChecksum(candidate);
    const context = hasContextNearby(text, m.index, /\b(gstin|gst|tax|invoice|vendor)\b/i);
    const mapped = mapNormSpanToOrig(view, m.index, m.index + candidate.length);
    gstinSpans.push({ start: m.index, end: m.index + candidate.length });

    findings.push({
      id: `f_gstin_${mapped.start}`,
      entity_type: 'GSTIN',
      start: mapped.start,
      end: mapped.end,
      raw_value: mapped.raw,
      detector: checksumOk ? 'presidio_india+gstin_mod36' : 'presidio_india_gstin',
      detectors_provenance: checksumOk
        ? ['presidio_india_gstin', 'gstin_checksum']
        : ['presidio_india_gstin'],
      confidence: checksumOk ? 0.98 : context ? 0.84 : 0.74,
      confidence_band: checksumOk ? 'HIGH' : 'MEDIUM',
      classification: ['PERSONAL_DATA', 'ENTERPRISE_CONFIDENTIAL'],
      domain,
      context_label: context ? 'GSTIN/Tax context' : undefined,
      ambiguity: checksumOk ? [] : ['gstin_checksum_unverified'],
    });
  }

  // 3. PAN (AAAAA9999A), skip slices inside already matched GSTINs
  const panRe = /\b([A-Z]{5}[0-9]{4}[A-Z])\b/g;
  while ((m = panRe.exec(text)) !== null) {
    const overlapsGstin = gstinSpans.some(
      (g) => m!.index >= g.start && m!.index + m![1].length <= g.end
    );
    if (overlapsGstin) continue;

    const candidate = m[1];
    const entityCodeOk = PAN_ENTITY_CODES.has(candidate[3]);
    const context = hasContextNearby(text, m.index, /\b(pan|permanent account|tax|kyc|पैन|ಪ್ಯಾನ್)\b/i);
    const mapped = mapNormSpanToOrig(view, m.index, m.index + candidate.length);

    findings.push({
      id: `f_pan_${mapped.start}`,
      entity_type: 'PAN',
      start: mapped.start,
      end: mapped.end,
      raw_value: mapped.raw,
      detector: entityCodeOk ? 'presidio_india+pan_schema' : 'presidio_india_pan',
      detectors_provenance: entityCodeOk
        ? ['presidio_india_pan', 'pan_entity_code_check']
        : ['presidio_india_pan'],
      confidence: entityCodeOk && context ? 0.98 : entityCodeOk ? 0.9 : 0.68,
      confidence_band: entityCodeOk ? 'HIGH' : 'MEDIUM',
      classification: ['PERSONAL_DATA'],
      domain,
      context_label: context ? 'PAN context label' : undefined,
      ambiguity: entityCodeOk ? [] : ['unusual_pan_4th_char'],
    });
  }

  // 4. VOTER ID / EPIC ([A-Z]{3}[0-9]{7})
  const voterRe = /\b([A-Z]{3}[0-9]{7})\b/g;
  while ((m = voterRe.exec(text)) !== null) {
    const candidate = m[1];
    const context = hasContextNearby(
      text,
      m.index,
      /\b(voter|epic|election|elector|voter[\s_-]?id)\b/i
    );
    const mapped = mapNormSpanToOrig(view, m.index, m.index + candidate.length);

    findings.push({
      id: `f_voter_${mapped.start}`,
      entity_type: 'VOTER_ID',
      start: mapped.start,
      end: mapped.end,
      raw_value: mapped.raw,
      detector: 'presidio_india_voter_id',
      detectors_provenance: ['presidio_india_voter_id'],
      confidence: context ? 0.95 : 0.78,
      confidence_band: context ? 'HIGH' : 'MEDIUM',
      classification: ['PERSONAL_DATA'],
      domain,
      context_label: context ? 'Voter ID/EPIC context' : undefined,
      ambiguity: context ? [] : ['alphanumeric_3_7_without_voter_label'],
    });
  }

  // 5. INDIAN PASSPORT ([A-PR-WY][0-9]{7} — excludes Q, X, Z first letters)
  const passportRe = /\b([A-PR-WY][0-9]{7})\b/g;
  while ((m = passportRe.exec(text)) !== null) {
    const candidate = m[1];
    const context = hasContextNearby(
      text,
      m.index,
      /\b(passport|ppt|travel|visa|पासपोर्ट|ಪಾಸ್‌ಪೋರ್ಟ್)\b/i
    );
    const mapped = mapNormSpanToOrig(view, m.index, m.index + candidate.length);

    if (context) {
      findings.push({
        id: `f_passport_${mapped.start}`,
        entity_type: 'PASSPORT',
        start: mapped.start,
        end: mapped.end,
        raw_value: mapped.raw,
        detector: 'presidio_india_passport',
        detectors_provenance: ['presidio_india_passport', 'context_engine'],
        confidence: 0.95,
        confidence_band: 'HIGH',
        classification: ['PERSONAL_DATA'],
        domain,
        context_label: 'Passport context label',
        ambiguity: [],
      });
    } else {
      // Without explicit passport context, flag as ambiguous candidate rather than silent pass or blind certainty
      findings.push({
        id: `f_passport_cand_${mapped.start}`,
        entity_type: 'PASSPORT',
        start: mapped.start,
        end: mapped.end,
        raw_value: mapped.raw,
        detector: 'presidio_india_passport',
        detectors_provenance: ['presidio_india_passport'],
        confidence: 0.62,
        confidence_band: 'LOW',
        classification: ['PERSONAL_DATA'],
        domain,
        ambiguity: ['letter_plus_7_digits_without_passport_context'],
      });
    }
  }

  return findings;
}
