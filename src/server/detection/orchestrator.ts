import { DomainType, EntityType, InternalFinding } from '../types.ts';
import { NormalizedView } from '../pipeline/normalize.ts';
import { detectIndianIdentifiers } from './indiaRecognizers.ts';
import { detectCommonAndDomainEntities } from './commonAndDomainRecognizers.ts';
import { detectDatesAndContext, detectUnknownRiskCandidates } from './contextDateIndic.ts';

const ENTITY_SPECIFICITY_RANK: Record<EntityType, number> = {
  API_KEY: 100,
  CREDENTIAL: 99,
  AADHAAR: 95,
  GSTIN: 94,
  PAN: 93,
  PASSPORT: 92,
  VOTER_ID: 91,
  ABHA: 90,
  CARD_NUMBER: 89,
  IFSC: 88,
  BANK_ACCOUNT: 86,
  UPI_ID: 85,
  EMAIL: 84,
  PHONE: 83,
  DATE_OF_BIRTH: 82,
  TRANSACTION_REFERENCE: 81,
  UHID: 80,
  MRN: 79,
  LOAN_ID: 78,
  POLICY_NO: 77,
  CLAIM_ID: 76,
  EMP_ID: 75,
  VEHICLE_REG: 74,
  IP_ADDRESS: 73,
  ADDRESS: 72,
  PERSON: 71,
  MEDICAL_CONDITION: 68,
  ENTERPRISE_SECRET: 67,
  CONTEXTUAL_DATE: 60,
  UNKNOWN_IDENTIFIER: 40,
};

function spansOverlap(a: InternalFinding, b: InternalFinding): boolean {
  return a.start < b.end && b.start < a.end;
}

/**
 * Deterministic overlap resolution & provenance merging.
 * Also assigns approximate person_group_id so cross-person substitution checks
 * can detect if Person 1's identifier gets attached to Person 2 in LLM output.
 */
export function mergeFindingsDeterministically(
  rawFindings: InternalFinding[]
): InternalFinding[] {
  // Sort by unambiguous vs ambiguous, then specificity desc, then confidence desc, then span length desc, then start asc
  const sorted = [...rawFindings].sort((a, b) => {
    const ambigA = a.ambiguity.length === 0 ? 1 : 0;
    const ambigB = b.ambiguity.length === 0 ? 1 : 0;
    if (ambigB !== ambigA) return ambigB - ambigA;
    const specDiff =
      (ENTITY_SPECIFICITY_RANK[b.entity_type] ?? 0) -
      (ENTITY_SPECIFICITY_RANK[a.entity_type] ?? 0);
    if (specDiff !== 0) return specDiff;
    if (b.confidence !== a.confidence) return b.confidence - a.confidence;
    const lenDiff = b.end - b.start - (a.end - a.start);
    if (lenDiff !== 0) return lenDiff;
    return a.start - b.start;
  });

  const kept: InternalFinding[] = [];
  for (const candidate of sorted) {
    if (candidate.start >= candidate.end || !candidate.raw_value.trim()) continue;
    const overlapping = kept.find((k) => spansOverlap(k, candidate));
    if (overlapping) {
      // Preserve multi-detector provenance if it's the same entity type or enclosed
      for (const p of candidate.detectors_provenance) {
        if (!overlapping.detectors_provenance.includes(p)) {
          overlapping.detectors_provenance.push(p);
        }
      }
      continue;
    }
    kept.push({ ...candidate });
  }

  // Sort final kept findings strictly by document order
  kept.sort((a, b) => a.start - b.start);

  // Assign person_group_id based on nearest preceding PERSON finding
  let currentGroup = 'group_0';
  let personCount = 0;
  for (const f of kept) {
    if (f.entity_type === 'PERSON') {
      personCount++;
      currentGroup = `person_${personCount}`;
    }
    f.person_group_id = currentGroup;
  }

  return kept;
}

export function runDetectionEnsemble(
  view: NormalizedView,
  domain: DomainType,
  simulateOutage = false
): {
  findings: InternalFinding[];
  promptInjectionDetected: boolean;
  detectorError: string | null;
} {
  if (simulateOutage) {
    // Fail-closed simulation: detector failure MUST NEVER be interpreted as "no PII found"
    return {
      findings: [],
      promptInjectionDetected: false,
      detectorError: 'Local NER/Presidio detector engine unavailable (simulated outage)',
    };
  }

  const india = detectIndianIdentifiers(view, domain);
  const common = detectCommonAndDomainEntities(view, domain);
  const contextDates = detectDatesAndContext(view, domain);

  const prelim = [...india, ...common.findings, ...contextDates];
  const unknownCandidates = detectUnknownRiskCandidates(view, domain, prelim);

  const merged = mergeFindingsDeterministically([...prelim, ...unknownCandidates]);

  return {
    findings: merged,
    promptInjectionDetected: common.promptInjectionDetected,
    detectorError: null,
  };
}
