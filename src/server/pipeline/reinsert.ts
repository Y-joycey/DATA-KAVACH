import { DomainType, TokenIntegrityReport } from '../types.ts';
import {
  getTokenPersonGroups,
  listAllowedTokensForRequest,
  resolveTokenFromVault,
} from '../vault/tokenVault.ts';
import { buildNormalizedView } from './normalize.ts';
import { detectIndianIdentifiers } from '../detection/indiaRecognizers.ts';
import { detectCommonAndDomainEntities } from '../detection/commonAndDomainRecognizers.ts';

const PLACEHOLDER_RE = /<([A-Z0-9_]+)_(\d+)>/g;

export interface ReinsertionResult {
  restoredResponse: string;
  integrity: TokenIntegrityReport;
  warnings: string[];
}

/**
 * Validates provider response tokens against current-request allowlist,
 * guards against cross-person substitution, never reconstructs missing tokens,
 * never fuzzy-matches fabricated tokens, and scans restored output before return.
 */
export function validateAndReinsertLocally(params: {
  requestId: string;
  rawProviderResponse: string;
  domain: DomainType;
}): ReinsertionResult {
  const { requestId, rawProviderResponse, domain } = params;
  const issuedTokens = listAllowedTokensForRequest(requestId);
  const personGroups = getTokenPersonGroups(requestId);

  const warnings: string[] = [];
  const restoredSet = new Set<string>();
  const fabricatedSet = new Set<string>();
  const crossPersonWarnings: string[] = [];
  const blockedCrossPersonTokens = new Set<string>();

  // 1. Cross-person association check per line/clause
  const uniquePersonGroups = new Set(
    Array.from(personGroups.values()).filter((g) => g.startsWith('person_'))
  );
  if (uniquePersonGroups.size >= 2) {
    const clauses = rawProviderResponse.split(/[\n.;]+/);
    for (const clause of clauses) {
      const tokensInClause = clause.match(/<[A-Z0-9_]+_\d+>/g) ?? [];
      const personsInClause = tokensInClause.filter((t) => t.startsWith('<PERSON_'));
      const idsInClause = tokensInClause.filter((t) => !t.startsWith('<PERSON_'));

      if (personsInClause.length === 1 && idsInClause.length >= 1) {
        const personGroup = personGroups.get(personsInClause[0]);
        for (const idTok of idsInClause) {
          const idGroup = personGroups.get(idTok);
          if (
            personGroup &&
            idGroup &&
            idGroup.startsWith('person_') &&
            personGroup !== idGroup
          ) {
            const msg = `Cross-person substitution blocked: response associated ${personsInClause[0]} (${personGroup}) with ${idTok} (${idGroup})`;
            if (!crossPersonWarnings.includes(msg)) {
              crossPersonWarnings.push(msg);
              warnings.push(msg);
            }
            blockedCrossPersonTokens.add(idTok);
          }
        }
      }
    }
  }

  // 2. Check token ordering in response vs issued order
  const responseOccurrences: string[] = [];
  let m: RegExpExecArray | null;
  PLACEHOLDER_RE.lastIndex = 0;
  while ((m = PLACEHOLDER_RE.exec(rawProviderResponse)) !== null) {
    responseOccurrences.push(m[0]);
  }

  const knownOccurrences = responseOccurrences.filter((t) => issuedTokens.includes(t));
  let reorderedDetected = false;
  for (let i = 1; i < knownOccurrences.length; i++) {
    const prevIdx = issuedTokens.indexOf(knownOccurrences[i - 1]);
    const currIdx = issuedTokens.indexOf(knownOccurrences[i]);
    if (currIdx < prevIdx) {
      reorderedDetected = true;
      break;
    }
  }

  // 3. Replace ONLY valid current-request tokens that passed cross-person checks
  const restoredResponse = rawProviderResponse.replace(PLACEHOLDER_RE, (fullToken) => {
    if (!issuedTokens.includes(fullToken)) {
      fabricatedSet.add(fullToken);
      return fullToken; // Leave unknown/fabricated token literal
    }
    if (blockedCrossPersonTokens.has(fullToken)) {
      return `[BLOCKED_CROSS_PERSON_${fullToken.slice(1, -1)}]`;
    }
    const resolved = resolveTokenFromVault(requestId, fullToken);
    if (!resolved) {
      fabricatedSet.add(fullToken);
      warnings.push(`Token ${fullToken} missing or expired in local vault; left literal`);
      return fullToken;
    }
    restoredSet.add(fullToken);
    return resolved.value;
  });

  // 4. Missing/dropped tokens remain absent; record warning
  const missingTokens = issuedTokens.filter((t) => !restoredSet.has(t) && !blockedCrossPersonTokens.has(t));
  if (missingTokens.length > 0) {
    warnings.push(
      `Dropped placeholder(s) omitted by model (not reconstructed): ${missingTokens.join(', ')}`
    );
  }
  if (fabricatedSet.size > 0) {
    warnings.push(
      `Unknown/fabricated placeholder(s) left literal: ${Array.from(fabricatedSet).join(', ')}`
    );
  }

  // 5. Response-side safety check (ensure provider didn't hallucinate an unrequested secret or unexpected raw ID)
  const responseSafetyViolations: string[] = [];
  const respView = buildNormalizedView(rawProviderResponse);
  const respIndia = detectIndianIdentifiers(respView, domain);
  const respCommon = detectCommonAndDomainEntities(respView, domain);
  for (const f of [...respIndia, ...respCommon.findings]) {
    if (f.entity_type === 'API_KEY' || f.entity_type === 'CREDENTIAL') {
      responseSafetyViolations.push(`Response contained unexpected ${f.entity_type}`);
    }
  }
  if (responseSafetyViolations.length > 0) {
    warnings.push(...responseSafetyViolations);
  }

  return {
    restoredResponse,
    integrity: {
      restored_tokens: Array.from(restoredSet),
      missing_tokens: missingTokens,
      fabricated_tokens: Array.from(fabricatedSet),
      reordered_detected: reorderedDetected,
      cross_person_warnings: crossPersonWarnings,
      response_safety_passed: responseSafetyViolations.length === 0,
      response_safety_violations: responseSafetyViolations,
    },
    warnings,
  };
}
