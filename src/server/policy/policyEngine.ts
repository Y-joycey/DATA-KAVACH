import {
  DomainType,
  InternalFinding,
  PolicyAction,
  PolicyDecision,
} from '../types.ts';

export const POLICY_VERSION = 'minearena-policy-v2.1';

function generalizeDob(raw: string): string {
  const yearMatch = raw.match(/\b(19\d{2}|20\d{2})\b/);
  if (yearMatch) {
    const year = parseInt(yearMatch[1], 10);
    const decade = Math.floor(year / 10) * 10;
    return `[BIRTH_DECADE_${decade}s]`;
  }
  return '[GENERALIZED_DOB]';
}

/**
 * Pure deterministic policy evaluation engine.
 * Keeps DPDP personal-data classification separate from enterprise-confidentiality.
 */
export function evaluatePolicy(
  finding: InternalFinding,
  purpose: string,
  domain: DomainType,
  provider: string,
  approvedOverrides?: Record<string, PolicyAction>
): PolicyDecision {
  // Check explicit authorized reviewer override first
  if (approvedOverrides && approvedOverrides[finding.id]) {
    return {
      action: approvedOverrides[finding.id],
      reason: `Reviewer-approved override for ${finding.entity_type}`,
      policy_id: `review-override-${finding.id}`,
      policy_version: POLICY_VERSION,
      requires_review: false,
    };
  }

  const isEnterprise = finding.classification.includes('ENTERPRISE_CONFIDENTIAL');
  const isPersonal = finding.classification.includes('PERSONAL_DATA');

  // 1. Enterprise Confidentiality Layer (API keys & credentials are always BLOCK or MASK)
  if (isEnterprise) {
    if (finding.entity_type === 'API_KEY' || finding.entity_type === 'CREDENTIAL') {
      return {
        action: 'MASK',
        reason: `Enterprise secret (${finding.entity_type}) irreversibly masked before external boundary`,
        policy_id: 'ent-secret-mask-v2',
        policy_version: POLICY_VERSION,
        requires_review: false,
      };
    }
    if (finding.entity_type === 'ENTERPRISE_SECRET') {
      return {
        action: 'RESTRICT',
        reason: 'Confidential business information restricted from external LLM payload',
        policy_id: 'ent-confidential-restrict-v2',
        policy_version: POLICY_VERSION,
        requires_review: false,
      };
    }
  }

  // 2. High-risk uncertainty / ambiguity -> route to REVIEW (fail-closed, no external call while pending)
  if (
    finding.entity_type === 'UNKNOWN_IDENTIFIER' ||
    finding.ambiguity.includes('checksum_mismatch_requires_review') ||
    finding.ambiguity.some((a) => a.startsWith('ambiguous_abbreviation_')) ||
    finding.ambiguity.includes('letter_plus_7_digits_without_passport_context')
  ) {
    return {
      action: 'REVIEW',
      reason: `High-risk uncertainty (${finding.ambiguity.join(', ') || finding.entity_type}) requires authorized review`,
      policy_id: 'risk-uncertainty-review-v2',
      policy_version: POLICY_VERSION,
      requires_review: true,
    };
  }

  // 3. Dates: hide dates of any format (DOB tokenized/generalized; all other dates tokenized)
  if (finding.entity_type === 'CONTEXTUAL_DATE') {
    return {
      action: 'TOKENIZE',
      reason: 'Date of any format tokenized before external provider boundary',
      policy_id: `${domain}-date-tokenize-v2`,
      policy_version: POLICY_VERSION,
      requires_review: false,
    };
  }

  if (finding.entity_type === 'DATE_OF_BIRTH') {
    if (purpose === 'analytics_cohort' || purpose === 'underwriting_aggregate') {
      return {
        action: 'GENERALIZE',
        reason: 'DOB generalized to birth decade for aggregate underwriting/analytics utility',
        policy_id: `${domain}-dob-generalize-v2`,
        policy_version: POLICY_VERSION,
        requires_review: false,
        generalized_value: generalizeDob(finding.raw_value),
      };
    }
    return {
      action: 'TOKENIZE',
      reason: 'DOB linked to identifiable individual tokenized with request-scoped placeholder',
      policy_id: `${domain}-dob-tokenize-v2`,
      policy_version: POLICY_VERSION,
      requires_review: false,
    };
  }

  // 4. Irreversible MASK for payment card numbers
  if (finding.entity_type === 'CARD_NUMBER') {
    return {
      action: 'MASK',
      reason: 'Payment card number irreversibly masked (PCI/DPDP safeguard)',
      policy_id: 'fin-card-mask-v2',
      policy_version: POLICY_VERSION,
      requires_review: false,
    };
  }

  // 5. Standard DPDP Personal Data -> TOKENIZE for utility-preserving local reinsertion
  if (isPersonal) {
    return {
      action: 'TOKENIZE',
      reason: `${finding.entity_type} linked to ${domain} (${purpose}) tokenized before ${provider} boundary`,
      policy_id: `${domain}-${finding.entity_type.toLowerCase()}-tokenize-v2`,
      policy_version: POLICY_VERSION,
      requires_review: false,
    };
  }

  return {
    action: 'ALLOW',
    reason: 'No restriction rule triggered',
    policy_id: 'default-allow-v2',
    policy_version: POLICY_VERSION,
    requires_review: false,
  };
}
