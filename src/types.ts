export type DomainType =
  | 'kyc'
  | 'loan'
  | 'support'
  | 'insurance'
  | 'healthcare'
  | 'hr'
  | 'enterprise'
  | 'general';

export type TaskType = 'summarize' | 'extract' | 'classify' | 'qa';
export type ProviderMode = 'mock' | 'gemini';
export type SimulationMode =
  | 'normal'
  | 'reorder_tokens'
  | 'drop_token'
  | 'fabricate_token'
  | 'cross_person_swap';

export type PolicyAction =
  | 'ALLOW'
  | 'MASK'
  | 'TOKENIZE'
  | 'GENERALIZE'
  | 'RESTRICT'
  | 'BLOCK'
  | 'REVIEW';

export interface SanitizedFindingView {
  id: string;
  entity_type: string;
  start: number;
  end: number;
  length: number;
  detector: string;
  detectors_provenance: string[];
  confidence: number;
  confidence_band: 'HIGH' | 'MEDIUM' | 'LOW';
  classification: Array<'PERSONAL_DATA' | 'ENTERPRISE_CONFIDENTIAL'>;
  domain: DomainType;
  context_label?: string;
  ambiguity: string[];
  policy_action: PolicyAction;
  policy_id: string;
  policy_reason: string;
  token?: string;
}

export interface OutboundValidationResult {
  passed: boolean;
  status: 'PASS' | 'BLOCK';
  violations: string[];
  checks_run: string[];
  firewall_version: string;
  content_hash: string;
  scanned_at: string;
}

export interface TokenIntegrityReport {
  restored_tokens: string[];
  missing_tokens: string[];
  fabricated_tokens: string[];
  reordered_detected: boolean;
  cross_person_warnings: string[];
  response_safety_passed: boolean;
  response_safety_violations: string[];
}

export interface StageLatency {
  normalize_ms: number;
  detect_ms: number;
  policy_ms: number;
  sanitize_ms: number;
  firewall_ms: number;
  provider_ms: number;
  reinsert_ms: number;
  total_ms: number;
}

export interface GatewayResponse {
  request_id: string;
  status: 'completed' | 'blocked' | 'pending_review' | 'failed';
  input_format: string;
  detected_language: string;
  language_supported: boolean;
  domain: DomainType;
  purpose: string;
  task: TaskType;
  policy_version: string;
  dictionary_version: string;
  sanitized_payload: string;
  exact_outbound_body: string;
  findings: SanitizedFindingView[];
  outbound_validation: OutboundValidationResult;
  provider_called: boolean;
  provider: string | null;
  model: string | null;
  raw_provider_response: string | null;
  restored_response: string | null;
  token_integrity: TokenIntegrityReport | null;
  warnings: string[];
  prompt_injection_detected: boolean;
  review_item_id?: string;
  latency_ms: StageLatency;
  created_at: string;
}

export interface AuditRecord {
  request_id: string;
  created_at: string;
  completed_at: string;
  domain: DomainType;
  purpose: string;
  task: TaskType;
  detected_language: string;
  status: GatewayResponse['status'];
  policy_version: string;
  dictionary_version: string;
  entity_types: string[];
  finding_count: number;
  findings_summary: SanitizedFindingView[];
  exact_sanitized_outbound_payload: string;
  outbound_validation: OutboundValidationResult;
  provider_called: boolean;
  provider: string | null;
  model: string | null;
  warnings: string[];
  latency_ms: StageLatency;
  prompt_injection_detected: boolean;
}

export interface ReviewItem {
  id: string;
  request_id: string;
  created_at: string;
  status: 'pending' | 'approved' | 'rejected';
  domain: DomainType;
  purpose: string;
  task: TaskType;
  provider: ProviderMode;
  sanitized_context: string;
  candidates: Array<{
    finding_id: string;
    entity_type: string;
    confidence: number;
    confidence_band: 'HIGH' | 'MEDIUM' | 'LOW';
    ambiguity: string[];
    context_label?: string;
    detector: string;
    recommended_action: PolicyAction;
  }>;
  reviewer?: string;
  decision_reason?: string;
  decided_at?: string;
  policy_version: string;
}

export interface PresetDocument {
  id: string;
  title: string;
  category: string;
  domain: DomainType;
  purpose: string;
  task: TaskType;
  language: string;
  text: string;
  notes?: string;
}

export interface EvaluationReport {
  run_at: string;
  dataset_size: number;
  dataset_composition: Record<string, number>;
  tested_languages: string[];
  policy_version: string;
  overall: {
    tp: number;
    fp: number;
    fn: number;
    precision: number;
    recall: number;
    f1: number;
    false_positive_rate: number;
    outbound_leakage_count: number;
    outbound_leakage_rate: number;
    review_rate: number;
    reinsertion_accuracy: number;
    wrong_person_substitution_count: number;
    p50_latency_ms: number;
    p95_latency_ms: number;
    mean_stage_latency_ms: StageLatency;
  };
  per_entity: Array<{
    entity_type: string;
    tp: number;
    fp: number;
    fn: number;
    precision: number;
    recall: number;
    f1: number;
  }>;
  security_suite: Array<{
    name: string;
    passed: boolean;
    detail: string;
  }>;
  limitations: string[];
  sample_failures: Array<{
    doc_id: string;
    title: string;
    issue: string;
  }>;
}
