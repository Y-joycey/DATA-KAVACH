import { DomainType, InternalFinding } from '../types.ts';
import { NormalizedView, mapNormSpanToOrig } from '../pipeline/normalize.ts';

function verifyLuhn(numStr: string): boolean {
  let sum = 0;
  let alt = false;
  for (let i = numStr.length - 1; i >= 0; i--) {
    let n = parseInt(numStr[i], 10);
    if (alt) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    alt = !alt;
  }
  return sum % 10 === 0;
}

const KNOWN_UPI_HANDLES = new Set([
  'oksbi', 'okicici', 'okaxis', 'okhdfcbank', 'okhdfc',
  'ybl', 'ibl', 'axl', 'paytm', 'upi', 'apl', 'fbl', 'yapl',
  'sbi', 'icici', 'hdfcbank', 'hdfc', 'axisbank', 'kotak', 'pnb',
  'bob', 'barodampay', 'indus', 'federal', 'yesbank', 'idbi',
  'aubank', 'bandhan', 'rbl', 'citi', 'hsbc', 'sc', 'jupiteraxis',
  'slice', 'ikwik', 'waaxis', 'wahdfcbank', 'waicici', 'wasbi',
  'pingpay', 'kbl', 'kvb', 'sib', 'tmb', 'uco', 'unionbank',
  'indianbank', 'canara', 'centralbank', 'mahb', 'postbank',
  'airtel', 'jio', 'freecharge', 'amazonpay', 'naviaxis',
  'ptyes', 'ptaxis', 'pthdfc', 'ptsbi', 'tapicici', 'timecosmos',
]);

// Curated local NER gazetteer & honorific/label heuristics for Indian English + code-mixed text
const PERSON_LABEL_RE =
  /(?:^|[\n,;:|])[\s]*(?:Applicant Name|Full Name|Customer Name|Patient Name|Employee Name|Claimant|Beneficiary|Policyholder|Cardholder|Account Holder|Name|Guardian|Father(?:'s)? Name|Spouse|Patient|Customer|Applicant|Mera naam|Naam|नाम|मेरा नाम|ಹೆಸರು)\s*[:\-–=]\s*([A-Z][a-zA-Z.'-]{1,24}(?:\s+[A-Z][a-zA-Z.'-]{1,24}){0,3})/gi;

const HONORIFIC_NAME_RE =
  /\b(?:Shri|Smt|Sri|Kumari|Mr|Mrs|Ms|Dr|Prof)\.?\s+([A-Z][a-z]{1,20}(?:\s+[A-Z][a-z]{1,20}){1,2})\b/g;

const RELATION_NAME_RE =
  /\b(?:S\/o|D\/o|W\/o|C\/o)\s+([A-Z][a-z]{1,20}(?:\s+[A-Z][a-z]{1,20}){1,2})\b/g;

const INDIAN_FIRST_NAMES = new Set([
  'aarav', 'aditi', 'aditya', 'akash', 'amit', 'ananya', 'anil', 'anjali', 'ankit',
  'anurag', 'arjun', 'arun', 'ashok', 'bhavna', 'chetan', 'deepak', 'deepika',
  'dev', 'divya', 'ganesh', 'gaurav', 'geeta', 'harish', 'isha', 'karan', 'kavita',
  'kiran', 'krishna', 'lakshmi', 'mahesh', 'manish', 'meera', 'mohan', 'mukesh',
  'nandini', 'naveen', 'neha', 'nikhil', 'nisha', 'nitin', 'pooja', 'prakash',
  'pranav', 'prashant', 'preeti', 'priya', 'rahul', 'rajesh', 'rakesh', 'ramesh',
  'rashmi', 'ravi', 'rekha', 'rohan', 'rohit', 'sachin', 'sandeep', 'sanjay',
  'santosh', 'sharma', 'shivam', 'shreya', 'siddharth', 'sneha', 'sonia', 'suresh',
  'swati', 'tanvi', 'tarun', 'varun', 'vijay', 'vikas', 'vikram', 'vinod', 'vivek',
  'yash', 'zoya', 'fatima', 'imran', 'salman', 'irfan', 'naveed', 'abhishek',
]);

const INDIAN_LAST_NAMES = new Set([
  'sharma', 'verma', 'gupta', 'patel', 'reddy', 'nair', 'iyer', 'iyengar', 'rao',
  'kulkarni', 'deshmukh', 'joshi', 'bhat', 'hegde', 'shetty', 'gowda', 'kamath',
  'menon', 'pillai', 'das', 'bose', 'chatterjee', 'mukherjee', 'banerjee', 'sen',
  'singh', 'kaur', 'kumar', 'mishra', 'tiwari', 'pandey', 'dubey', 'shukla',
  'agarwal', 'bansal', 'mittal', 'jain', 'mehta', 'shah', 'desai', 'choudhary',
  'khan', 'ali', 'ahmed', 'shaikh', 'kapoor', 'malhotra', 'khanna', 'chopra',
  'subramanian', 'krishnan', 'venkatesh', 'prasad', 'murthy', 'swamy', 'patil',
]);

const ADDRESS_LABEL_RE =
  /(?:^|[\n;])[\s]*(?:Residential Address|Permanent Address|Current Address|Communication Address|Delivery Address|Address|Residence|Pata|पता|ವಿಳಾಸ)\s*[:\-–=]\s*([^\n;]{12,180})/gi;

const STRUCTURED_ADDRESS_RE =
  /\b(?:Flat|Plot|House|Door|H\.?\s?No\.?|#)\s*[A-Za-z0-9\-\/]+,\s*[^\n]{10,140}?\b[1-9]\d{5}\b/gi;

export function detectCommonAndDomainEntities(
  view: NormalizedView,
  domain: DomainType
): { findings: InternalFinding[]; promptInjectionDetected: boolean } {
  const findings: InternalFinding[] = [];
  const text = view.normalized;
  let m: RegExpExecArray | null;

  // 1. EMAIL
  const emailRe = /\b([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b/g;
  while ((m = emailRe.exec(text)) !== null) {
    const mapped = mapNormSpanToOrig(view, m.index, m.index + m[1].length);
    findings.push({
      id: `f_email_${mapped.start}`,
      entity_type: 'EMAIL',
      start: mapped.start,
      end: mapped.end,
      raw_value: mapped.raw,
      detector: 'presidio_email',
      detectors_provenance: ['presidio_email'],
      confidence: 0.98,
      confidence_band: 'HIGH',
      classification: ['PERSONAL_DATA'],
      domain,
      ambiguity: [],
    });
  }

  // 2. UPI ID (VPA handles like user@oksbi, 9876543210@ybl, or labeled UPI/VPA handle)
  const upiRe = /\b([a-zA-Z0-9._-]{2,}@[a-zA-Z0-9]{2,24})\b/g;
  while ((m = upiRe.exec(text)) !== null) {
    const handle = m[1].split('@')[1]?.toLowerCase() ?? '';
    const isKnownHandle = KNOWN_UPI_HANDLES.has(handle);
    const hasUpiContext = /\b(?:upi(?:\s*id)?|vpa|virtual\s+payment\s+address|bhim|gpay|phonepe|paytm|यूपीआई)\b/i.test(
      text.slice(Math.max(0, m.index - 40), m.index + m[1].length + 24)
    );
    if (!isKnownHandle && !hasUpiContext) continue;
    const mapped = mapNormSpanToOrig(view, m.index, m.index + m[1].length);
    findings.push({
      id: `f_upi_${mapped.start}`,
      entity_type: 'UPI_ID',
      start: mapped.start,
      end: mapped.end,
      raw_value: mapped.raw,
      detector: isKnownHandle ? 'india_upi_recognizer' : 'context+upi_recognizer',
      detectors_provenance: isKnownHandle
        ? ['india_upi_recognizer']
        : ['india_upi_recognizer', 'context_engine'],
      confidence: isKnownHandle ? 0.96 : 0.91,
      confidence_band: 'HIGH',
      classification: ['PERSONAL_DATA'],
      domain,
      context_label: hasUpiContext ? 'UPI/VPA context' : undefined,
      ambiguity: [],
    });
  }

  // 2b. TRANSACTION REFERENCE CODES (Txn ID/Ref, RRN, UPI/IMPS/NEFT/RTGS Ref, Payment Ref)
  const txnRefRe =
    /\b(?:Transaction\s*(?:Reference|Ref|ID|Code|No\.?)|Txn\s*(?:Ref|ID|No\.?|Code)|Trans(?:action)?\s*Ref(?:erence)?|RRN|UPI\s*Ref(?:erence)?(?:\s*No\.?)?|IMPS\s*Ref(?:\s*No\.?)?|NEFT\s*Ref(?:\s*No\.?)?|RTGS\s*Ref(?:\s*No\.?)?|Payment\s*(?:Ref(?:erence)?|ID|Code)|Ref(?:erence)?\s*(?:No\.?|Code))\s*[:#\-=]?\s*([A-Z0-9][A-Z0-9\-\/_]{5,28})\b/gi;
  while ((m = txnRefRe.exec(text)) !== null) {
    const val = m[1];
    if (!/\d/.test(val)) continue;
    const valStart = m.index + m[0].lastIndexOf(val);
    const mapped = mapNormSpanToOrig(view, valStart, valStart + val.length);
    findings.push({
      id: `f_txnref_${mapped.start}`,
      entity_type: 'TRANSACTION_REFERENCE',
      start: mapped.start,
      end: mapped.end,
      raw_value: mapped.raw,
      detector: 'financial_txn_ref_recognizer',
      detectors_provenance: ['context_engine', 'financial_txn_ref_recognizer'],
      confidence: 0.93,
      confidence_band: 'HIGH',
      classification: ['PERSONAL_DATA'],
      domain,
      context_label: 'Transaction reference label',
      ambiguity: [],
    });
  }

  // 3. PHONE (Indian +91 / 0 / 10-digit [6-9]XXXXXXXXX)
  const phoneRe = /(?<!\d)(?:(?:\+91[\s-]?)|(?:\b0))?([6-9]\d{4}[\s-]?\d{5})\b/g;
  while ((m = phoneRe.exec(text)) !== null) {
    const full = m[0];
    const mapped = mapNormSpanToOrig(view, m.index, m.index + full.length);
    const hasPrefix = full.startsWith('+91') || full.startsWith('0');
    const context = /\b(phone|mob|mobile|contact|tel|call|cell|whatsapp|फ़ोन|ಮೊಬೈಲ್)\b/i.test(
      text.slice(Math.max(0, m.index - 32), m.index + full.length + 16)
    );
    findings.push({
      id: `f_phone_${mapped.start}`,
      entity_type: 'PHONE',
      start: mapped.start,
      end: mapped.end,
      raw_value: mapped.raw,
      detector: 'presidio_india_phone',
      detectors_provenance: ['presidio_india_phone'],
      confidence: hasPrefix || context ? 0.96 : 0.84,
      confidence_band: hasPrefix || context ? 'HIGH' : 'MEDIUM',
      classification: ['PERSONAL_DATA'],
      domain,
      context_label: context ? 'Phone/Mobile context' : undefined,
      ambiguity: hasPrefix || context ? [] : ['unprefixed_10_digit_number'],
    });
  }

  // 4. IFSC ([A-Z]{4}0[A-Z0-9]{6})
  const ifscRe = /\b([A-Z]{4}0[A-Z0-9]{6})\b/g;
  while ((m = ifscRe.exec(text)) !== null) {
    const mapped = mapNormSpanToOrig(view, m.index, m.index + m[1].length);
    findings.push({
      id: `f_ifsc_${mapped.start}`,
      entity_type: 'IFSC',
      start: mapped.start,
      end: mapped.end,
      raw_value: mapped.raw,
      detector: 'india_ifsc_recognizer',
      detectors_provenance: ['india_ifsc_recognizer'],
      confidence: 0.95,
      confidence_band: 'HIGH',
      classification: ['PERSONAL_DATA'],
      domain,
      ambiguity: [],
    });
  }

  // 5. BANK ACCOUNT (any length/order: 4 to 28+ digits, spaced/hyphenated, or alphanumeric with digits)
  const bankRe =
    /\b(?:Bank\s+)?(?:A\/[Cc]|Acc(?:ount)?|Acct|Savings(?:\s+Account)?|Current(?:\s+Account)?|Loan\s+Account|Order\s+Account|Customer\s+Account|Merchant\s+Account)(?:\s*(?:No\.?|Number|ID|Code|#))?\s*(?:[:#\-=]|is)?\s*((?:\d{2,6}\s){1,6}\d{2,6}|[A-Z0-9]{1,8}[\-\/]?[A-Z0-9\-\/]*\d[A-Z0-9\-\/]{1,28})\b/gi;
  while ((m = bankRe.exec(text)) !== null) {
    const val = m[1].trim();
    if (!/\d/.test(val) || val.replace(/\D/g, '').length < 3) continue;
    const valStart = m.index + m[0].lastIndexOf(val);
    const mapped = mapNormSpanToOrig(view, valStart, valStart + val.length);
    findings.push({
      id: `f_bank_${mapped.start}`,
      entity_type: 'BANK_ACCOUNT',
      start: mapped.start,
      end: mapped.end,
      raw_value: mapped.raw,
      detector: 'context+bank_account',
      detectors_provenance: ['context_engine', 'bank_account_recognizer'],
      confidence: 0.94,
      confidence_band: 'HIGH',
      classification: ['PERSONAL_DATA'],
      domain,
      context_label: 'Account number',
      ambiguity: [],
    });
  }

  // 6. CARD NUMBER (16 digits with Luhn)
  const cardRe = /\b(\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4})\b/g;
  while ((m = cardRe.exec(text)) !== null) {
    const digits = m[1].replace(/[\s-]/g, '');
    if (!verifyLuhn(digits)) continue;
    const mapped = mapNormSpanToOrig(view, m.index, m.index + m[1].length);
    findings.push({
      id: `f_card_${mapped.start}`,
      entity_type: 'CARD_NUMBER',
      start: mapped.start,
      end: mapped.end,
      raw_value: mapped.raw,
      detector: 'presidio_credit_card+luhn',
      detectors_provenance: ['presidio_credit_card', 'luhn_checksum'],
      confidence: 0.97,
      confidence_band: 'HIGH',
      classification: ['PERSONAL_DATA'],
      domain,
      ambiguity: [],
    });
  }

  // 7. ABHA (14-digit health ID XX-XXXX-XXXX-XXXX)
  const abhaRe = /\b(\d{2}-\d{4}-\d{4}-\d{4})\b/g;
  while ((m = abhaRe.exec(text)) !== null) {
    const mapped = mapNormSpanToOrig(view, m.index, m.index + m[1].length);
    findings.push({
      id: `f_abha_${mapped.start}`,
      entity_type: 'ABHA',
      start: mapped.start,
      end: mapped.end,
      raw_value: mapped.raw,
      detector: 'india_abha_recognizer',
      detectors_provenance: ['india_abha_recognizer'],
      confidence: 0.95,
      confidence_band: 'HIGH',
      classification: ['PERSONAL_DATA'],
      domain,
      ambiguity: [],
    });
  }

  // 8. Healthcare UHID / MRN, Loan / Policy / Claim / Emp IDs
  const domainIdSpecs: Array<{
    re: RegExp;
    type: InternalFinding['entity_type'];
    label: string;
  }> = [
    { re: /\b(?:UHID)\s*[:#\-]?\s*([A-Z]{2,5}[-\/]?\d{5,10})\b/gi, type: 'UHID', label: 'UHID' },
    { re: /\b(?:MRN)\s*[:#\-]?\s*([A-Z]{1,4}[-\/]?\d{5,10})\b/gi, type: 'MRN', label: 'MRN' },
    { re: /\b(?:Loan\s*(?:ID|No\.?|Ref))\s*[:#\-]?\s*([A-Z]{2,4}[-\/]?\d{4,10})\b/gi, type: 'LOAN_ID', label: 'Loan ID' },
    { re: /\b(LN[-\/]\d{4,10})\b/g, type: 'LOAN_ID', label: 'Loan ID' },
    { re: /\b(?:Policy\s*(?:No\.?|ID)|POL)\s*[:#\-]?\s*([A-Z]{2,5}[-\/]?\d{5,10})\b/gi, type: 'POLICY_NO', label: 'Policy No' },
    { re: /\b(?:Claim\s*(?:ID|No\.?|Ref)|CLM)\s*[:#\-]?\s*([A-Z]{2,5}[-\/]?\d{4,10})\b/gi, type: 'CLAIM_ID', label: 'Claim ID' },
    { re: /\b(?:Emp(?:loyee)?\s*(?:ID|Code|No\.?)|EMP)\s*[:#\-]?\s*([A-Z]{2,5}[-\/]?\d{3,8})\b/gi, type: 'EMP_ID', label: 'Employee ID' },
  ];

  for (const spec of domainIdSpecs) {
    while ((m = spec.re.exec(text)) !== null) {
      const val = m[1];
      const valStart = m.index + m[0].lastIndexOf(val);
      const mapped = mapNormSpanToOrig(view, valStart, valStart + val.length);
      findings.push({
        id: `f_${spec.type.toLowerCase()}_${mapped.start}`,
        entity_type: spec.type,
        start: mapped.start,
        end: mapped.end,
        raw_value: mapped.raw,
        detector: 'domain_pack_recognizer',
        detectors_provenance: ['context_engine', 'domain_pack_recognizer'],
        confidence: 0.93,
        confidence_band: 'HIGH',
        classification: ['PERSONAL_DATA'],
        domain,
        context_label: spec.label,
        ambiguity: [],
      });
    }
  }

  // 9. VEHICLE REGISTRATION & IP ADDRESS
  const vehRe = /\b([A-Z]{2}\s?\d{2}\s?[A-Z]{1,2}\s?\d{4})\b/g;
  while ((m = vehRe.exec(text)) !== null) {
    const context = /\b(vehicle|reg|rc|car|bike|dl|rto)\b/i.test(
      text.slice(Math.max(0, m.index - 32), m.index + m[1].length + 24)
    );
    if (!context) continue;
    const mapped = mapNormSpanToOrig(view, m.index, m.index + m[1].length);
    findings.push({
      id: `f_veh_${mapped.start}`,
      entity_type: 'VEHICLE_REG',
      start: mapped.start,
      end: mapped.end,
      raw_value: mapped.raw,
      detector: 'india_rto_recognizer',
      detectors_provenance: ['india_rto_recognizer'],
      confidence: 0.9,
      confidence_band: 'HIGH',
      classification: ['PERSONAL_DATA'],
      domain,
      ambiguity: [],
    });
  }

  const ipRe = /\b((?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?))\b/g;
  while ((m = ipRe.exec(text)) !== null) {
    const mapped = mapNormSpanToOrig(view, m.index, m.index + m[1].length);
    findings.push({
      id: `f_ip_${mapped.start}`,
      entity_type: 'IP_ADDRESS',
      start: mapped.start,
      end: mapped.end,
      raw_value: mapped.raw,
      detector: 'presidio_ip_address',
      detectors_provenance: ['presidio_ip_address'],
      confidence: 0.91,
      confidence_band: 'HIGH',
      classification: ['PERSONAL_DATA'],
      domain,
      ambiguity: [],
    });
  }

  // 10. PERSON (Local Rule + Gazetteer NER)
  while ((m = PERSON_LABEL_RE.exec(text)) !== null) {
    const nameVal = m[1].trim();
    const valStart = m.index + m[0].lastIndexOf(nameVal);
    const mapped = mapNormSpanToOrig(view, valStart, valStart + nameVal.length);
    findings.push({
      id: `f_person_lbl_${mapped.start}`,
      entity_type: 'PERSON',
      start: mapped.start,
      end: mapped.end,
      raw_value: mapped.raw,
      detector: 'local_ner+label',
      detectors_provenance: ['local_ner_indian', 'context_label'],
      confidence: 0.95,
      confidence_band: 'HIGH',
      classification: ['PERSONAL_DATA'],
      domain,
      context_label: 'Labeled person field',
      ambiguity: [],
    });
  }

  for (const re of [HONORIFIC_NAME_RE, RELATION_NAME_RE]) {
    while ((m = re.exec(text)) !== null) {
      const nameVal = m[1].trim();
      const valStart = m.index + m[0].lastIndexOf(nameVal);
      const mapped = mapNormSpanToOrig(view, valStart, valStart + nameVal.length);
      findings.push({
        id: `f_person_hon_${mapped.start}`,
        entity_type: 'PERSON',
        start: mapped.start,
        end: mapped.end,
        raw_value: mapped.raw,
        detector: 'local_ner_honorific',
        detectors_provenance: ['local_ner_indian'],
        confidence: 0.93,
        confidence_band: 'HIGH',
        classification: ['PERSONAL_DATA'],
        domain,
        ambiguity: [],
      });
    }
  }

  // Sliding-window Gazetteer NER for unlabeled two-word capitalized Indian names (e.g. "User Nikhil Bose")
  const capWordMatches = Array.from(text.matchAll(/\b([A-Z][a-z]{2,18})\b/g));
  for (let idx = 0; idx < capWordMatches.length - 1; idx++) {
    const first = capWordMatches[idx];
    const second = capWordMatches[idx + 1];
    const gap = text.slice((first.index ?? 0) + first[0].length, second.index ?? 0);
    if (!/^\s+$/.test(gap)) continue;

    const w1 = first[1].toLowerCase();
    const w2 = second[1].toLowerCase();
    if (INDIAN_FIRST_NAMES.has(w1) || INDIAN_LAST_NAMES.has(w2)) {
      const startNorm = first.index ?? 0;
      const endNorm = (second.index ?? 0) + second[0].length;
      const mapped = mapNormSpanToOrig(view, startNorm, endNorm);
      findings.push({
        id: `f_person_gaz_${mapped.start}`,
        entity_type: 'PERSON',
        start: mapped.start,
        end: mapped.end,
        raw_value: mapped.raw,
        detector: 'local_ner_gazetteer',
        detectors_provenance: ['local_ner_indian', 'indian_name_gazetteer'],
        confidence: INDIAN_FIRST_NAMES.has(w1) && INDIAN_LAST_NAMES.has(w2) ? 0.92 : 0.84,
        confidence_band: 'HIGH',
        classification: ['PERSONAL_DATA'],
        domain,
        ambiguity: [],
      });
    }
  }

  // 11. ADDRESS (Labeled & structured Indian addresses with PIN code)
  while ((m = ADDRESS_LABEL_RE.exec(text)) !== null) {
    const addr = m[1].trim().replace(/[.;]+$/, '');
    const valStart = m.index + m[0].indexOf(addr);
    const mapped = mapNormSpanToOrig(view, valStart, valStart + addr.length);
    findings.push({
      id: `f_addr_lbl_${mapped.start}`,
      entity_type: 'ADDRESS',
      start: mapped.start,
      end: mapped.end,
      raw_value: mapped.raw,
      detector: 'local_ner_address',
      detectors_provenance: ['local_ner_address', 'context_label'],
      confidence: 0.93,
      confidence_band: 'HIGH',
      classification: ['PERSONAL_DATA'],
      domain,
      context_label: 'Address field',
      ambiguity: [],
    });
  }

  while ((m = STRUCTURED_ADDRESS_RE.exec(text)) !== null) {
    const addr = m[0].trim();
    const mapped = mapNormSpanToOrig(view, m.index, m.index + addr.length);
    findings.push({
      id: `f_addr_pin_${mapped.start}`,
      entity_type: 'ADDRESS',
      start: mapped.start,
      end: mapped.end,
      raw_value: mapped.raw,
      detector: 'india_address_pin_ner',
      detectors_provenance: ['local_ner_address', 'india_pin_code'],
      confidence: 0.91,
      confidence_band: 'HIGH',
      classification: ['PERSONAL_DATA'],
      domain,
      ambiguity: [],
    });
  }

  // 12. CLINICAL DIAGNOSIS / PRESCRIPTION (only in healthcare or medical context)
  if (domain === 'healthcare' || /\b(patient|uhid|mrn|abha|diagnosis|rx|prescribed)\b/i.test(text)) {
    const diagRe = /\b(?:Diagnosis|Diagnosed with|Condition|Prescription|Rx)\s*[:\-–]\s*([^\n.;]{4,80})/gi;
    while ((m = diagRe.exec(text)) !== null) {
      const val = m[1].trim();
      const valStart = m.index + m[0].indexOf(val);
      const mapped = mapNormSpanToOrig(view, valStart, valStart + val.length);
      findings.push({
        id: `f_med_${mapped.start}`,
        entity_type: 'MEDICAL_CONDITION',
        start: mapped.start,
        end: mapped.end,
        raw_value: mapped.raw,
        detector: 'clinical_domain_pack',
        detectors_provenance: ['clinical_domain_pack'],
        confidence: 0.89,
        confidence_band: 'HIGH',
        classification: ['PERSONAL_DATA'],
        domain,
        context_label: 'Clinical record',
        ambiguity: [],
      });
    }
  }

  // 13. ENTERPRISE CONFIDENTIALITY LAYER (Strictly separated from DPDP personal data)
  const apiKeyRe = /\b(AIza[0-9A-Za-z\-_]{20,}|sk-(?:live|test|proj)?[0-9A-Za-z\-_]{16,}|ghp_[0-9A-Za-z]{20,}|AKIA[0-9A-Z]{16})\b/g;
  while ((m = apiKeyRe.exec(text)) !== null) {
    const mapped = mapNormSpanToOrig(view, m.index, m.index + m[1].length);
    findings.push({
      id: `f_apikey_${mapped.start}`,
      entity_type: 'API_KEY',
      start: mapped.start,
      end: mapped.end,
      raw_value: mapped.raw,
      detector: 'enterprise_secret_scanner',
      detectors_provenance: ['enterprise_secret_scanner'],
      confidence: 0.99,
      confidence_band: 'HIGH',
      classification: ['ENTERPRISE_CONFIDENTIAL'],
      domain,
      ambiguity: [],
    });
  }

  const credRe = /\b(?:password|passwd|secret_key|api_secret|client_secret|bearer)\s*[:=]\s*([^\s,;]{6,64})/gi;
  while ((m = credRe.exec(text)) !== null) {
    const val = m[1];
    const valStart = m.index + m[0].lastIndexOf(val);
    const mapped = mapNormSpanToOrig(view, valStart, valStart + val.length);
    findings.push({
      id: `f_cred_${mapped.start}`,
      entity_type: 'CREDENTIAL',
      start: mapped.start,
      end: mapped.end,
      raw_value: mapped.raw,
      detector: 'enterprise_secret_scanner',
      detectors_provenance: ['enterprise_secret_scanner'],
      confidence: 0.97,
      confidence_band: 'HIGH',
      classification: ['ENTERPRISE_CONFIDENTIAL'],
      domain,
      context_label: 'Credential assignment',
      ambiguity: [],
    });
  }

  const secretBlockRe = /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]{10,400}?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g;
  while ((m = secretBlockRe.exec(text)) !== null) {
    const mapped = mapNormSpanToOrig(view, m.index, m.index + m[0].length);
    findings.push({
      id: `f_privkey_${mapped.start}`,
      entity_type: 'CREDENTIAL',
      start: mapped.start,
      end: mapped.end,
      raw_value: mapped.raw,
      detector: 'enterprise_secret_scanner',
      detectors_provenance: ['enterprise_secret_scanner'],
      confidence: 1.0,
      confidence_band: 'HIGH',
      classification: ['ENTERPRISE_CONFIDENTIAL'],
      domain,
      ambiguity: [],
    });
  }

  const entConfidentialRe =
    /\b(?:INTERNAL ONLY|STRICTLY CONFIDENTIAL|TRADE SECRET|UNANNOUNCED M&A|PROPRIETARY PRICING|Q[1-4]\s+GROSS\s+MARGIN)\s*[:\-–]\s*([^\n.;|]{4,120})/gi;
  while ((m = entConfidentialRe.exec(text)) !== null) {
    const val = m[1].trim();
    const valStart = m.index + m[0].indexOf(val);
    const mapped = mapNormSpanToOrig(view, valStart, valStart + val.length);
    findings.push({
      id: `f_ent_${mapped.start}`,
      entity_type: 'ENTERPRISE_SECRET',
      start: mapped.start,
      end: mapped.end,
      raw_value: mapped.raw,
      detector: 'enterprise_confidential_pack',
      detectors_provenance: ['enterprise_confidential_pack'],
      confidence: 0.91,
      confidence_band: 'HIGH',
      classification: ['ENTERPRISE_CONFIDENTIAL'],
      domain,
      context_label: 'Confidential business clause',
      ambiguity: [],
    });
  }

  // 14. PROMPT INJECTION DETECTION (untrusted document content attempting to override gateway policy)
  const promptInjectionDetected =
    /\b(ignore\s+(?:all\s+)?previous\s+instructions|disable\s+(?:privacy\s+)?firewall|bypass\s+policy|do\s+not\s+mask|send\s+raw\s+(?:aadhaar|pan|pii)|system\s+override)\b/i.test(
      text
    );

  return { findings, promptInjectionDetected };
}
