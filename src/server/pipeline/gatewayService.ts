import crypto from 'node:crypto';
import {
  AuditRecord,
  GatewayRequest,
  GatewayResponse,
  PolicyAction,
  ReviewItem,
  StageLatency,
} from '../types.ts';
import { buildNormalizedView } from './normalize.ts';
import { runDetectionEnsemble } from '../detection/orchestrator.ts';
import { DICTIONARY_VERSION } from '../detection/contextDateIndic.ts';
import { POLICY_VERSION, evaluatePolicy } from '../policy/policyEngine.ts';
import { createRequestVault } from '../vault/tokenVault.ts';
import {
  buildOutboundBody,
  sanitizeBySpans,
  validateAndSealOutboundPayload,
} from './sanitizeAndFirewall.ts';
import { invokeExternalProvider } from '../providers/llmProvider.ts';
import { validateAndReinsertLocally } from './reinsert.ts';
import {
  getReviewItem,
  saveAuditRecord,
  saveReviewItem,
} from '../store/localStore.ts';

// Protected transient memory for pending review items only (never written to audit logs)
const pendingReviewRawPayloads = new Map<
  string,
  { request: GatewayRequest; expiresAt: number }
>();

const MAX_REQUEST_BYTES = Number(process.env.MAX_REQUEST_BYTES ?? 1_000_000);
const TOKEN_TTL_SECONDS = Number(process.env.TOKEN_TTL_SECONDS ?? 1800);

function roundMs(n: number): number {
  return Math.round(n * 100) / 100;
}

export async function analyzeLocallyOnly(req: GatewayRequest): Promise<{
  detected_language: string;
  language_supported: boolean;
  sanitized_payload: string;
  findings: GatewayResponse['findings'];
  prompt_injection_detected: boolean;
  normalization_notes: string[];
}> {
  const requestId = `local_${crypto.randomUUID()}`;
  const view = buildNormalizedView(req.text);
  const { findings, promptInjectionDetected } = runDetectionEnsemble(
    view,
    req.domain,
    Boolean(req.simulate_scanner_outage)
  );

  const enriched = findings.map((f) => {
    const decision = evaluatePolicy(
      f,
      req.purpose,
      req.domain,
      req.provider,
      req.approved_review_overrides
    );
    return {
      ...f,
      policy_action: decision.action,
      policy_id: decision.policy_id,
      policy_reason: decision.reason,
      generalized_value: decision.generalized_value,
    };
  });

  const vault = createRequestVault(requestId);
  const sanitized = sanitizeBySpans(req.text, enriched, vault, TOKEN_TTL_SECONDS);

  return {
    detected_language: view.detectedLanguage,
    language_supported: view.languageSupported,
    sanitized_payload: sanitized.sanitizedText,
    findings: sanitized.findingViews,
    prompt_injection_detected: promptInjectionDetected,
    normalization_notes: view.normalizationNotes,
  };
}

export async function processGatewayRequest(
  req: GatewayRequest,
  options?: { skipAudit?: boolean }
): Promise<GatewayResponse> {
  const tStart = performance.now();
  const createdAt = new Date().toISOString();
  const requestId = `req_${crypto.randomUUID()}`;

  if (!req.text || typeof req.text !== 'string') {
    throw new Error('Request text is required');
  }
  if (Buffer.byteLength(req.text, 'utf8') > MAX_REQUEST_BYTES) {
    throw new Error(`Input exceeds MAX_REQUEST_BYTES (${MAX_REQUEST_BYTES})`);
  }

  const warnings: string[] = [];

  // 1. Normalize with bidirectional offset map
  const tNorm0 = performance.now();
  const view = buildNormalizedView(req.text);
  const normalizeMs = performance.now() - tNorm0;

  if (!view.languageSupported) {
    warnings.push(
      `Script detected (${view.detectedLanguage}) is an experimental hook; verify findings carefully.`
    );
  }
  if (view.normalizationNotes.length > 0) {
    warnings.push(...view.normalizationNotes);
  }

  // 2. Local Detection Ensemble
  const tDet0 = performance.now();
  const { findings, promptInjectionDetected, detectorError } = runDetectionEnsemble(
    view,
    req.domain,
    Boolean(req.simulate_scanner_outage)
  );
  const detectMs = performance.now() - tDet0;

  if (promptInjectionDetected) {
    warnings.push(
      'Untrusted document contained prompt-injection pattern; policy engine enforced deterministic safeguards.'
    );
  }

  // 3. Deterministic Policy Engine
  const tPol0 = performance.now();
  const enriched = findings.map((f) => {
    const decision = evaluatePolicy(
      f,
      req.purpose,
      req.domain,
      req.provider,
      req.approved_review_overrides
    );
    return {
      ...f,
      policy_action: decision.action,
      policy_id: decision.policy_id,
      policy_reason: decision.reason,
      generalized_value: decision.generalized_value,
    };
  });
  const policyMs = performance.now() - tPol0;

  // 4. Token Vault + Span-based Sanitizer
  const tSan0 = performance.now();
  const vault = createRequestVault(requestId);
  const sanitized = sanitizeBySpans(req.text, enriched, vault, TOKEN_TTL_SECONDS);
  const targetModel =
    req.provider === 'gemini' ? 'gemini-3.8-flash' : 'minearena-mock-v2.1';
  const outbound = buildOutboundBody({
    task: req.task,
    domain: req.domain,
    purpose: req.purpose,
    sanitizedText: sanitized.sanitizedText,
    provider: req.provider,
    model: targetModel,
  });
  const sanitizeMs = performance.now() - tSan0;

  // 5. Independent Outbound Privacy Firewall (fail-closed)
  const tFw0 = performance.now();
  const { validation, sealedPayload } = validateAndSealOutboundPayload({
    requestId,
    serializedBody: outbound.serializedBody,
    sanitizedText: sanitized.sanitizedText,
    systemPrompt: outbound.systemPrompt,
    protectedOriginalSpans: enriched.map((e) => ({
      entity_type: e.entity_type,
      raw_value: e.raw_value,
      policy_action: e.policy_action,
    })),
    hasBlockingOrReview: sanitized.hasBlockingOrReview,
    detectorError,
    simulateScannerOutage: req.simulate_scanner_outage,
    domain: req.domain,
    provider: req.provider,
    model: targetModel,
    policyVersion: POLICY_VERSION,
  });
  const firewallMs = performance.now() - tFw0;

  let status: GatewayResponse['status'] = 'completed';
  let providerCalled = false;
  let providerName: string | null = null;
  let modelName: string | null = null;
  let rawProviderResponse: string | null = null;
  let restoredResponse: string | null = null;
  let tokenIntegrity: GatewayResponse['token_integrity'] = null;
  let reviewItemId: string | undefined;
  let providerMs = 0;
  let reinsertMs = 0;

  if (!validation.passed || !sealedPayload) {
    // Fail-closed gate: external LLM is NEVER called
    if (sanitized.hasBlockingOrReview && !req.simulate_scanner_outage && !detectorError) {
      status = 'pending_review';
      const revId = `rev_${crypto.randomUUID().slice(0, 8)}`;
      reviewItemId = revId;
      const reviewItem: ReviewItem = {
        id: revId,
        request_id: requestId,
        created_at: createdAt,
        status: 'pending',
        domain: req.domain,
        purpose: req.purpose,
        task: req.task,
        provider: req.provider,
        sanitized_context: sanitized.sanitizedText,
        candidates: sanitized.reviewCandidates.map((c) => ({
          finding_id: c.id,
          entity_type: c.entity_type,
          confidence: c.confidence,
          confidence_band: c.confidence_band,
          ambiguity: c.ambiguity,
          context_label: c.context_label,
          detector: c.detector,
          recommended_action: c.policy_action,
        })),
        policy_version: POLICY_VERSION,
      };
      if (!options?.skipAudit) {
        saveReviewItem(reviewItem);
        pendingReviewRawPayloads.set(revId, {
          request: req,
          expiresAt: Date.now() + TOKEN_TTL_SECONDS * 1000,
        });
      }
      warnings.push(
        `Request held for human review (${revId}). No external LLM call was made.`
      );
    } else {
      status = 'blocked';
      warnings.push(
        'Outbound privacy firewall blocked this request. No external LLM call was made.'
      );
    }
  } else {
    // 6. Invoke External LLM Adapter ONLY with ValidatedSanitizedPayload
    const tProv0 = performance.now();
    const provResult = await invokeExternalProvider(
      sealedPayload,
      req.task,
      req.simulation_mode ?? 'normal'
    );
    providerMs = performance.now() - tProv0;
    providerCalled = true;
    providerName = provResult.provider;
    modelName = provResult.model;
    rawProviderResponse = provResult.responseText;
    if (provResult.providerNote) {
      warnings.push(provResult.providerNote);
    }

    // 7. Response Validation & Local Reinsertion
    const tRein0 = performance.now();
    const reinserted = validateAndReinsertLocally({
      requestId,
      rawProviderResponse,
      domain: req.domain,
    });
    reinsertMs = performance.now() - tRein0;

    restoredResponse = reinserted.restoredResponse;
    tokenIntegrity = reinserted.integrity;
    warnings.push(...reinserted.warnings);

    if (!reinserted.integrity.response_safety_passed) {
      status = 'blocked';
      restoredResponse =
        '[RESPONSE BLOCKED BY RESPONSE-SIDE SAFETY SCANNER — SEE WARNINGS]';
    }
  }

  const totalMs = performance.now() - tStart;
  const latency_ms: StageLatency = {
    normalize_ms: roundMs(normalizeMs),
    detect_ms: roundMs(detectMs),
    policy_ms: roundMs(policyMs),
    sanitize_ms: roundMs(sanitizeMs),
    firewall_ms: roundMs(firewallMs),
    provider_ms: roundMs(providerMs),
    reinsert_ms: roundMs(reinsertMs),
    total_ms: roundMs(totalMs),
  };

  const unverifiedOrBlocked =
    Boolean(detectorError) ||
    Boolean(req.simulate_scanner_outage) ||
    validation.violations.some((v) => v.includes('LEAK') || v.includes('RESCAN'));

  const safeSanitizedPreview = unverifiedOrBlocked
    ? '[FAIL-CLOSED: SCANNER/DETECTOR BLOCKED — PAYLOAD WITHHELD]'
    : sanitized.sanitizedText;

  const safeOutboundRecord = unverifiedOrBlocked
    ? '[BLOCKED BEFORE TRANSMISSION — UNVERIFIED PAYLOAD WITHHELD FROM AUDIT LOG]'
    : outbound.serializedBody;

  const response: GatewayResponse = {
    request_id: requestId,
    status,
    input_format: req.input_format ?? 'plain_text',
    detected_language: view.detectedLanguage,
    language_supported: view.languageSupported,
    domain: req.domain,
    purpose: req.purpose,
    task: req.task,
    policy_version: POLICY_VERSION,
    dictionary_version: DICTIONARY_VERSION,
    sanitized_payload: safeSanitizedPreview,
    exact_outbound_body: safeOutboundRecord,
    findings: sanitized.findingViews,
    outbound_validation: validation,
    provider_called: providerCalled,
    provider: providerName,
    model: modelName,
    raw_provider_response: rawProviderResponse,
    restored_response: restoredResponse,
    token_integrity: tokenIntegrity,
    warnings,
    prompt_injection_detected: promptInjectionDetected,
    review_item_id: reviewItemId,
    latency_ms,
    created_at: createdAt,
  };

  // Persist strictly sanitized audit record (NO raw PII, NO token mappings)
  if (!options?.skipAudit) {
    const auditRecord: AuditRecord = {
      request_id: requestId,
      created_at: createdAt,
      completed_at: new Date().toISOString(),
      domain: req.domain,
      purpose: req.purpose,
      task: req.task,
      detected_language: view.detectedLanguage,
      status,
      policy_version: POLICY_VERSION,
      dictionary_version: DICTIONARY_VERSION,
      entity_types: Array.from(new Set(sanitized.findingViews.map((f) => f.entity_type))),
      finding_count: sanitized.findingViews.length,
      findings_summary: sanitized.findingViews,
      exact_sanitized_outbound_payload: safeOutboundRecord,
      outbound_validation: validation,
      provider_called: providerCalled,
      provider: providerName,
      model: modelName,
      warnings,
      latency_ms,
      prompt_injection_detected: promptInjectionDetected,
    };
    saveAuditRecord(auditRecord);
  }

  return response;
}

export async function decideReviewItem(params: {
  itemId: string;
  decision: 'approved' | 'rejected';
  reviewer: string;
  reason: string;
  overrideAction?: PolicyAction;
}): Promise<{ reviewItem: ReviewItem; reprocessed?: GatewayResponse }> {
  const item = getReviewItem(params.itemId);
  if (!item) {
    throw new Error(`Review item ${params.itemId} not found`);
  }

  item.status = params.decision;
  item.reviewer = params.reviewer;
  item.decision_reason = params.reason;
  item.decided_at = new Date().toISOString();
  saveReviewItem(item);

  const cached = pendingReviewRawPayloads.get(item.id);
  if (params.decision === 'rejected' || !cached || Date.now() > cached.expiresAt) {
    pendingReviewRawPayloads.delete(item.id);
    return { reviewItem: item };
  }

  const overrides: Record<string, PolicyAction> = {};
  const actionToApply: PolicyAction = params.overrideAction ?? 'TOKENIZE';
  for (const cand of item.candidates) {
    overrides[cand.finding_id] = actionToApply;
  }

  pendingReviewRawPayloads.delete(item.id);
  const reprocessed = await processGatewayRequest({
    ...cached.request,
    approved_review_overrides: overrides,
  });

  return { reviewItem: item, reprocessed };
}
