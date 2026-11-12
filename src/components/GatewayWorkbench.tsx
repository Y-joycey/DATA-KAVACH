import React, { useMemo, useRef, useState } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  Clock,
  FileUp,
  Lock,
  Play,
  ShieldAlert,
  ShieldCheck,
} from 'lucide-react';
import {
  DomainType,
  GatewayResponse,
  PresetDocument,
  ProviderMode,
  SanitizedFindingView,
  SimulationMode,
  TaskType,
} from '../types';

interface GatewayWorkbenchProps {
  presets: PresetDocument[];
  text: string;
  setText: (v: string) => void;
  domain: DomainType;
  setDomain: (v: DomainType) => void;
  purpose: string;
  setPurpose: (v: string) => void;
  task: TaskType;
  setTask: (v: TaskType) => void;
  provider: ProviderMode;
  setProvider: (v: ProviderMode) => void;
  simulationMode: SimulationMode;
  setSimulationMode: (v: SimulationMode) => void;
  simulateOutage: boolean;
  setSimulateOutage: (v: boolean) => void;
  inputFormat: 'plain_text' | 'json' | 'csv';
  setInputFormat: (v: 'plain_text' | 'json' | 'csv') => void;
  result: GatewayResponse | null;
  localPreview: {
    detected_language: string;
    language_supported: boolean;
    sanitized_payload: string;
    findings: SanitizedFindingView[];
    prompt_injection_detected: boolean;
  } | null;
  loading: boolean;
  error: string | null;
  onProcess: () => void;
  onAnalyzeLocal: () => void;
  onOpenReviewQueue: () => void;
}

function renderHighlightedOriginal(
  original: string,
  findings: SanitizedFindingView[]
): React.ReactNode {
  if (!findings || findings.length === 0) {
    return <span>{original}</span>;
  }
  const sorted = [...findings].sort((a, b) => a.start - b.start);
  const parts: React.ReactNode[] = [];
  let cursor = 0;

  for (const f of sorted) {
    if (f.start < cursor || f.start >= original.length) continue;
    if (f.start > cursor) {
      parts.push(<span key={`t_${cursor}`}>{original.slice(cursor, f.start)}</span>);
    }
    const snippet = original.slice(f.start, f.end);
    const isEnterprise = f.classification.includes('ENTERPRISE_CONFIDENTIAL');
    const style =
      f.policy_action === 'REVIEW' || f.policy_action === 'BLOCK'
        ? 'bg-amber-100 text-amber-950 border-b-2 border-amber-600'
        : f.policy_action === 'ALLOW'
        ? 'bg-slate-100 text-slate-800 border-b border-slate-400'
        : isEnterprise
        ? 'bg-red-50 text-red-950 border-b-2 border-red-600'
        : 'bg-teal-50 text-teal-950 border-b-2 border-teal-700';

    parts.push(
      <mark
        key={f.id}
        title={`${f.entity_type} · ${f.policy_action} · ${f.detector}`}
        className={`rounded-sm px-0.5 ${style}`}
      >
        {snippet}
      </mark>
    );
    cursor = f.end;
  }
  if (cursor < original.length) {
    parts.push(<span key={`t_end`}>{original.slice(cursor)}</span>);
  }
  return parts;
}

export const GatewayWorkbench: React.FC<GatewayWorkbenchProps> = ({
  presets,
  text,
  setText,
  domain,
  setDomain,
  purpose,
  setPurpose,
  task,
  setTask,
  provider,
  setProvider,
  simulationMode,
  setSimulationMode,
  simulateOutage,
  setSimulateOutage,
  inputFormat,
  setInputFormat,
  result,
  localPreview,
  loading,
  error,
  onProcess,
  onAnalyzeLocal,
  onOpenReviewQueue,
}) => {
  const [inputMode, setInputMode] = useState<'edit' | 'spans'>('edit');
  const [outboundTab, setOutboundTab] = useState<'text' | 'json'>('text');
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  const activeFindings = result?.findings ?? localPreview?.findings ?? [];
  const activeLanguage = result?.detected_language ?? localPreview?.detected_language ?? 'Indian English';

  const handlePresetChange = (presetId: string) => {
    const found = presets.find((p) => p.id === presetId);
    if (!found) return;
    setText(found.text);
    setDomain(found.domain);
    setPurpose(found.purpose);
    setTask(found.task);
    setInputFormat('plain_text');
    setInputMode('edit');
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      const content = typeof reader.result === 'string' ? reader.result : '';
      setText(content);
      if (file.name.endsWith('.json')) setInputFormat('json');
      else if (file.name.endsWith('.csv')) setInputFormat('csv');
      else setInputFormat('plain_text');
    };
    reader.readAsText(file);
    e.target.value = '';
  };

  const firewallStatus = result?.outbound_validation.status;

  const groupedIntegrity = useMemo(() => {
    if (!result?.token_integrity) return null;
    return result.token_integrity;
  }, [result]);

  return (
    <div className="space-y-5">
      {/* Workspace Controls Toolbar */}
      <div className="rounded-lg border border-slate-200 bg-white p-4">
        <div className="grid grid-cols-1 gap-3 md:grid-cols-2 lg:grid-cols-6">
          <div className="lg:col-span-2">
            <label htmlFor="preset-select" className="block text-xs font-medium text-slate-600">
              Synthetic Scenario Preset
            </label>
            <select
              id="preset-select"
              defaultValue=""
              onChange={(e) => handlePresetChange(e.target.value)}
              className="mt-1 w-full rounded-md border border-slate-200 bg-white px-3 py-2 text-xs text-slate-900 focus:border-teal-700 focus:outline-none"
            >
              <option value="" disabled>
                Load a labeled synthetic scenario...
              </option>
              {presets.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.title} ({p.category})
                </option>
              ))}
            </select>
          </div>

          <div>
            <label htmlFor="domain-select" className="block text-xs font-medium text-slate-600">
              Domain Pack
            </label>
            <select
              id="domain-select"
              value={domain}
              onChange={(e) => setDomain(e.target.value as DomainType)}
              className="mt-1 w-full rounded-md border border-slate-200 bg-white px-3 py-2 text-xs text-slate-900 focus:border-teal-700 focus:outline-none"
            >
              <option value="kyc">KYC / Onboarding</option>
              <option value="loan">Banking / Loan</option>
              <option value="healthcare">Healthcare / Clinical</option>
              <option value="insurance">Insurance Claims</option>
              <option value="support">Customer Support</option>
              <option value="hr">Human Resources</option>
              <option value="enterprise">Enterprise Confidential</option>
              <option value="general">General</option>
            </select>
          </div>

          <div>
            <label htmlFor="purpose-select" className="block text-xs font-medium text-slate-600">
              Trusted Purpose
            </label>
            <select
              id="purpose-select"
              value={purpose}
              onChange={(e) => setPurpose(e.target.value)}
              className="mt-1 w-full rounded-md border border-slate-200 bg-white px-3 py-2 text-xs text-slate-900 focus:border-teal-700 focus:outline-none"
            >
              <option value="kyc_verification">kyc_verification</option>
              <option value="credit_underwriting">credit_underwriting</option>
              <option value="underwriting_aggregate">underwriting_aggregate (generalize DOB)</option>
              <option value="clinical_summary">clinical_summary</option>
              <option value="claims_adjudication">claims_adjudication</option>
              <option value="ticket_triage">ticket_triage</option>
              <option value="incident_summary">incident_summary</option>
              <option value="analytics_cohort">analytics_cohort</option>
            </select>
          </div>

          <div>
            <label htmlFor="task-select" className="block text-xs font-medium text-slate-600">
              LLM Task
            </label>
            <select
              id="task-select"
              value={task}
              onChange={(e) => setTask(e.target.value as TaskType)}
              className="mt-1 w-full rounded-md border border-slate-200 bg-white px-3 py-2 text-xs text-slate-900 focus:border-teal-700 focus:outline-none"
            >
              <option value="summarize">Summarize</option>
              <option value="extract">Extract Structured Fields</option>
              <option value="classify">Classify</option>
              <option value="qa">Question Answering</option>
            </select>
          </div>

          <div>
            <label htmlFor="provider-select" className="block text-xs font-medium text-slate-600">
              External Provider
            </label>
            <select
              id="provider-select"
              value={provider}
              onChange={(e) => setProvider(e.target.value as ProviderMode)}
              className="mt-1 w-full rounded-md border border-slate-200 bg-white px-3 py-2 text-xs text-slate-900 focus:border-teal-700 focus:outline-none"
            >
              <option value="mock">Mock Provider (Offline)</option>
              <option value="gemini">Gemini 3.8 Flash (External)</option>
            </select>
          </div>
        </div>

        <div className="mt-3 flex flex-wrap items-center justify-between gap-3 border-t border-slate-100 pt-3">
          <div className="flex flex-wrap items-center gap-4">
            <div className="flex items-center gap-2">
              <label htmlFor="sim-mode" className="text-xs text-slate-600 whitespace-nowrap">
                Response Edge-Case Test:
              </label>
              <select
                id="sim-mode"
                value={simulationMode}
                onChange={(e) => setSimulationMode(e.target.value as SimulationMode)}
                className="rounded-md border border-slate-200 bg-white px-2.5 py-1.5 text-xs text-slate-800 focus:border-teal-700 focus:outline-none"
              >
                <option value="normal">Normal Response</option>
                <option value="reorder_tokens">Simulate Reordered Tokens</option>
                <option value="drop_token">Simulate Dropped Token</option>
                <option value="fabricate_token">Simulate Fabricated &lt;PERSON_99&gt;</option>
                <option value="cross_person_swap">Simulate Cross-Person Swap</option>
              </select>
            </div>

            <label className="inline-flex cursor-pointer items-center gap-2 text-xs text-slate-700">
              <input
                type="checkbox"
                checked={simulateOutage}
                onChange={(e) => setSimulateOutage(e.target.checked)}
                className="h-3.5 w-3.5 rounded border-slate-300 text-teal-700 focus:ring-teal-700"
              />
              <span>Simulate Scanner Outage (Fail-Closed Test)</span>
            </label>
          </div>

          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={onAnalyzeLocal}
              disabled={loading || !text.trim()}
              className="rounded-md border border-slate-300 bg-white px-4 py-2 text-xs font-medium text-slate-800 hover:bg-slate-50 disabled:opacity-50 whitespace-nowrap shrink-0"
            >
              Local Analyze Only
            </button>
            <button
              type="button"
              onClick={onProcess}
              disabled={loading || !text.trim()}
              className="inline-flex items-center gap-1.5 rounded-md bg-teal-700 px-4 py-2 text-xs font-medium text-white hover:bg-teal-800 disabled:opacity-50 whitespace-nowrap shrink-0"
            >
              <Play className="h-3.5 w-3.5" />
              {loading ? 'Processing...' : 'Process Through Gateway'}
            </button>
          </div>
        </div>
      </div>

      {error && (
        <div className="flex items-center gap-2 rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">
          <ShieldAlert className="h-4 w-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Primary Three-Panel View */}
      <div className="grid grid-cols-1 items-stretch gap-5 xl:grid-cols-3">
        {/* PANEL A: ORIGINAL INPUT */}
        <section className="flex flex-col rounded-lg border border-slate-200 bg-white p-5">
          <div className="flex items-center justify-between gap-2 border-b border-slate-100 pb-3">
            <div>
              <h2 className="text-base font-semibold text-slate-900">
                1. Original Input
              </h2>
              <p className="mt-0.5 flex items-center gap-1.5 text-xs text-slate-500">
                <Lock className="h-3 w-3 text-teal-700" />
                Handled strictly locally · Never transmitted raw
              </p>
            </div>
            <div className="flex items-center gap-1 rounded-md bg-slate-100 p-0.5">
              <button
                type="button"
                onClick={() => setInputMode('edit')}
                className={`rounded px-2.5 py-1 text-xs font-medium whitespace-nowrap ${
                  inputMode === 'edit' ? 'bg-white text-slate-900 shadow-sm' : 'text-slate-600'
                }`}
              >
                Edit
              </button>
              <button
                type="button"
                onClick={() => setInputMode('spans')}
                className={`rounded px-2.5 py-1 text-xs font-medium whitespace-nowrap ${
                  inputMode === 'spans' ? 'bg-white text-slate-900 shadow-sm' : 'text-slate-600'
                }`}
              >
                Spans ({activeFindings.length})
              </button>
            </div>
          </div>

          <div className="mt-3 flex flex-wrap items-center justify-between gap-2 text-xs text-slate-500">
            <div>
              <span>Format: {inputFormat}</span>
              <span className="mx-1.5" aria-hidden="true">·</span>
              <span>Language: {activeLanguage}</span>
              <span className="mx-1.5" aria-hidden="true">·</span>
              <span className="font-mono tabular-nums">{text.length} chars</span>
            </div>
            <div>
              <input
                ref={fileInputRef}
                type="file"
                accept=".txt,.json,.csv"
                onChange={handleFileUpload}
                className="hidden"
              />
              <button
                type="button"
                onClick={() => fileInputRef.current?.click()}
                className="inline-flex items-center gap-1 text-xs font-medium text-teal-700 hover:underline whitespace-nowrap"
              >
                <FileUp className="h-3.5 w-3.5" />
                Load TXT/JSON/CSV
              </button>
            </div>
          </div>

          <div className="mt-3 flex-1">
            {inputMode === 'edit' ? (
              <textarea
                aria-label="Original local input text"
                value={text}
                onChange={(e) => setText(e.target.value)}
                rows={13}
                placeholder="Enter synthetic Indian KYC, loan, healthcare, or enterprise text..."
                className="h-full min-h-[280px] w-full resize-y rounded-md border border-slate-200 bg-slate-50/50 p-3 font-mono text-xs leading-relaxed text-slate-900 focus:border-teal-700 focus:bg-white focus:outline-none"
              />
            ) : (
              <div className="min-h-[280px] whitespace-pre-wrap rounded-md border border-slate-200 bg-slate-50 p-3 font-mono text-xs leading-relaxed text-slate-900">
                {renderHighlightedOriginal(text, activeFindings)}
              </div>
            )}
          </div>

          <div className="mt-3 border-t border-slate-100 pt-2.5 text-[11px] text-slate-500">
            <span>Domain: {domain}</span>
            <span className="mx-1.5" aria-hidden="true">·</span>
            <span>Purpose: {purpose}</span>
            <span className="mx-1.5" aria-hidden="true">·</span>
            <span>Task: {task}</span>
          </div>
        </section>

        {/* PANEL B: OUTBOUND SANITIZED PAYLOAD & FIREWALL */}
        <section className="flex flex-col rounded-lg border border-slate-200 bg-white p-5">
          <div className="flex items-center justify-between gap-2 border-b border-slate-100 pb-3">
            <div>
              <h2 className="text-base font-semibold text-slate-900">
                2. Outbound Sanitized Payload
              </h2>
              <p className="mt-0.5 text-xs text-slate-500">
                Exact serialized boundary inspected by independent firewall
              </p>
            </div>
            <div className="flex items-center gap-1 rounded-md bg-slate-100 p-0.5">
              <button
                type="button"
                onClick={() => setOutboundTab('text')}
                className={`rounded px-2.5 py-1 text-xs font-medium whitespace-nowrap ${
                  outboundTab === 'text' ? 'bg-white text-slate-900 shadow-sm' : 'text-slate-600'
                }`}
              >
                Sanitized
              </button>
              <button
                type="button"
                onClick={() => setOutboundTab('json')}
                className={`rounded px-2.5 py-1 text-xs font-medium whitespace-nowrap ${
                  outboundTab === 'json' ? 'bg-white text-slate-900 shadow-sm' : 'text-slate-600'
                }`}
              >
                Exact JSON
              </button>
            </div>
          </div>

          {result ? (
            <div className="mt-3 flex flex-1 flex-col space-y-3">
              {/* Firewall Verdict */}
              <div
                className={`rounded-md border px-3 py-2.5 text-xs ${
                  result.status === 'completed' && firewallStatus === 'PASS'
                    ? 'border-emerald-200 bg-emerald-50 text-emerald-900'
                    : result.status === 'pending_review'
                    ? 'border-amber-200 bg-amber-50 text-amber-900'
                    : 'border-red-200 bg-red-50 text-red-900'
                }`}
              >
                <div className="flex items-center justify-between gap-2 font-medium">
                  <span className="inline-flex items-center gap-1.5">
                    {result.status === 'completed' && firewallStatus === 'PASS' ? (
                      <ShieldCheck className="h-4 w-4 text-emerald-700" />
                    ) : result.status === 'pending_review' ? (
                      <Clock className="h-4 w-4 text-amber-700" />
                    ) : (
                      <ShieldAlert className="h-4 w-4 text-red-700" />
                    )}
                    Firewall: {firewallStatus}
                  </span>
                  <span className="font-mono text-[11px] opacity-80">
                    SHA-256: {result.outbound_validation.content_hash.slice(0, 12)}
                  </span>
                </div>
                <div className="mt-1 text-[11px]">
                  {result.provider_called
                    ? `Provider invoked: ${result.provider} (${result.model})`
                    : 'No external provider call was made (fail-closed boundary enforced).'}
                </div>
                {result.outbound_validation.violations.length > 0 && (
                  <ul className="mt-1.5 list-disc space-y-0.5 pl-4 text-[11px]">
                    {result.outbound_validation.violations.map((v, idx) => (
                      <li key={idx}>{v}</li>
                    ))}
                  </ul>
                )}
              </div>

              <pre className="min-h-[200px] flex-1 overflow-auto whitespace-pre-wrap rounded-md border border-slate-200 bg-slate-50 p-3 font-mono text-xs leading-relaxed text-slate-800">
                {outboundTab === 'text'
                  ? result.sanitized_payload
                  : result.exact_outbound_body}
              </pre>
            </div>
          ) : localPreview ? (
            <div className="mt-3 flex flex-1 flex-col space-y-3">
              <div className="rounded-md border border-slate-200 bg-slate-50 px-3 py-2 text-xs text-slate-700">
                Local-only analysis preview · External LLM was not invoked
              </div>
              <pre className="min-h-[240px] flex-1 overflow-auto whitespace-pre-wrap rounded-md border border-slate-200 bg-slate-50 p-3 font-mono text-xs leading-relaxed text-slate-800">
                {localPreview.sanitized_payload}
              </pre>
            </div>
          ) : (
            <div className="mt-3 flex flex-1 items-center justify-center rounded-md border border-dashed border-slate-200 bg-slate-50/50 p-8 text-center">
              <div>
                <p className="text-xs font-medium text-slate-700">
                  Sanitized payload awaits processing
                </p>
                <p className="mt-1 text-xs text-slate-500">
                  Run Local Analyze Only or Process Through Gateway to inspect exact outbound bytes.
                </p>
              </div>
            </div>
          )}
        </section>

        {/* PANEL C: FINAL RESTORED RESPONSE */}
        <section className="flex flex-col rounded-lg border border-slate-200 bg-white p-5">
          <div className="border-b border-slate-100 pb-3">
            <h2 className="text-base font-semibold text-slate-900">
              3. Final Restored Response
            </h2>
            <p className="mt-0.5 text-xs text-slate-500">
              Validated locally with request-scoped token allowlist
            </p>
          </div>

          {result ? (
            <div className="mt-3 flex flex-1 flex-col space-y-3">
              {result.status === 'pending_review' ? (
                <div className="rounded-md border border-amber-200 bg-amber-50 p-4 text-xs text-amber-900">
                  <div className="font-semibold">Held for Authorized Human Review</div>
                  <p className="mt-1 leading-relaxed">
                    Ambiguous or unseen high-risk candidates prevented automatic external forwarding. Review ID:{' '}
                    <span className="font-mono font-medium">{result.review_item_id}</span>.
                  </p>
                  <button
                    type="button"
                    onClick={onOpenReviewQueue}
                    className="mt-3 rounded-md bg-amber-700 px-3 py-1.5 text-xs font-medium text-white hover:bg-amber-800"
                  >
                    Open Review Queue
                  </button>
                </div>
              ) : result.status === 'blocked' ? (
                <div className="rounded-md border border-red-200 bg-red-50 p-4 text-xs text-red-900">
                  <div className="font-semibold">Request Blocked (Fail-Closed)</div>
                  <p className="mt-1 leading-relaxed">
                    No response was generated because the privacy firewall or response safety check blocked transmission.
                  </p>
                </div>
              ) : (
                <pre className="min-h-[160px] flex-1 overflow-auto whitespace-pre-wrap rounded-md border border-slate-200 bg-slate-50 p-3 font-sans text-xs leading-relaxed text-slate-900">
                  {result.restored_response}
                </pre>
              )}

              {groupedIntegrity && (
                <div className="rounded-md border border-slate-200 bg-white p-3 text-xs">
                  <div className="font-semibold text-slate-900">
                    Token Integrity & Reinsertion Audit
                  </div>
                  <dl className="mt-2 grid grid-cols-2 gap-x-3 gap-y-1.5 text-[11px]">
                    <div>
                      <dt className="text-slate-500">Restored Tokens</dt>
                      <dd className="font-mono text-slate-900">
                        {groupedIntegrity.restored_tokens.length > 0
                          ? groupedIntegrity.restored_tokens.join(', ')
                          : 'None'}
                      </dd>
                    </div>
                    <div>
                      <dt className="text-slate-500">Dropped (Not Reconstructed)</dt>
                      <dd className="font-mono text-slate-900">
                        {groupedIntegrity.missing_tokens.length > 0
                          ? groupedIntegrity.missing_tokens.join(', ')
                          : '0'}
                      </dd>
                    </div>
                    <div>
                      <dt className="text-slate-500">Fabricated / Unknown</dt>
                      <dd className="font-mono text-slate-900">
                        {groupedIntegrity.fabricated_tokens.length > 0
                          ? groupedIntegrity.fabricated_tokens.join(', ')
                          : '0'}
                      </dd>
                    </div>
                    <div>
                      <dt className="text-slate-500">Response Safety Scan</dt>
                      <dd
                        className={`inline-flex items-center gap-1 font-medium ${
                          groupedIntegrity.response_safety_passed
                            ? 'text-emerald-700'
                            : 'text-red-700'
                        }`}
                      >
                        {groupedIntegrity.response_safety_passed ? (
                          <>
                            <CheckCircle2 className="h-3 w-3" /> Passed
                          </>
                        ) : (
                          'Blocked'
                        )}
                      </dd>
                    </div>
                  </dl>
                </div>
              )}

              {result.warnings.length > 0 && (
                <div className="rounded-md border border-amber-200 bg-amber-50/70 p-3 text-[11px] text-amber-900">
                  <div className="flex items-center gap-1.5 font-semibold">
                    <AlertTriangle className="h-3.5 w-3.5 text-amber-700" />
                    Gateway Notices
                  </div>
                  <ul className="mt-1 list-disc space-y-0.5 pl-4">
                    {result.warnings.map((w, i) => (
                      <li key={i}>{w}</li>
                    ))}
                  </ul>
                </div>
              )}

              <div className="border-t border-slate-100 pt-2.5 text-[11px] font-mono tabular-nums text-slate-500">
                <span>Audit ID: {result.request_id.slice(0, 14)}</span>
                <span className="mx-1.5" aria-hidden="true">·</span>
                <span>Total: {result.latency_ms.total_ms} ms</span>
                <span className="mx-1.5" aria-hidden="true">·</span>
                <span>Firewall: {result.latency_ms.firewall_ms} ms</span>
              </div>
            </div>
          ) : (
            <div className="mt-3 flex flex-1 items-center justify-center rounded-md border border-dashed border-slate-200 bg-slate-50/50 p-8 text-center">
              <div>
                <p className="text-xs font-medium text-slate-700">
                  Final restored output appears here
                </p>
                <p className="mt-1 text-xs text-slate-500">
                  Valid placeholders are restored locally while fabricated or cross-person swaps are blocked.
                </p>
              </div>
            </div>
          )}
        </section>
      </div>

      {/* Findings & Policy Explainability Matrix */}
      <section className="rounded-lg border border-slate-200 bg-white p-5">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-100 pb-3">
          <div>
            <h3 className="text-sm font-semibold text-slate-900">
              Detected Entities, Provenance & Policy Decisions
            </h3>
            <p className="mt-0.5 text-xs text-slate-500">
              Raw values are never persisted in audit logs or returned in finding metadata.
            </p>
          </div>
          {result && (
            <div className="font-mono text-xs text-slate-500">
              {result.policy_version} · {result.dictionary_version}
            </div>
          )}
        </div>

        {activeFindings.length === 0 ? (
          <p className="py-6 text-center text-xs text-slate-500">
            No protected entities detected yet. Submit a document or choose a preset above.
          </p>
        ) : (
          <div className="mt-3 overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="border-b border-slate-200 bg-slate-50 text-slate-600">
                <tr>
                  <th className="px-3 py-2 font-medium">Entity Type</th>
                  <th className="px-3 py-2 font-medium">Offsets</th>
                  <th className="px-3 py-2 font-medium">Classification Layer</th>
                  <th className="px-3 py-2 font-medium">Detector Provenance</th>
                  <th className="px-3 py-2 text-right font-medium">Confidence</th>
                  <th className="px-3 py-2 font-medium">Policy Action</th>
                  <th className="px-3 py-2 font-medium">Token</th>
                  <th className="px-3 py-2 font-medium">Explainability Reason</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {activeFindings.map((f) => (
                  <tr key={f.id} className="hover:bg-slate-50">
                    <td className="px-3 py-2 font-mono font-medium text-slate-900">
                      {f.entity_type}
                    </td>
                    <td className="px-3 py-2 font-mono tabular-nums text-slate-600">
                      [{f.start}, {f.end}]
                    </td>
                    <td className="px-3 py-2 text-slate-700">
                      {f.classification.join(' + ')}
                    </td>
                    <td className="px-3 py-2 font-mono text-[11px] text-slate-600">
                      {f.detectors_provenance.join(', ')}
                    </td>
                    <td className="px-3 py-2 text-right font-mono tabular-nums text-slate-800">
                      {f.confidence.toFixed(2)} ({f.confidence_band})
                    </td>
                    <td className="px-3 py-2 font-mono font-medium">
                      <span
                        className={
                          f.policy_action === 'REVIEW' || f.policy_action === 'BLOCK'
                            ? 'text-amber-700'
                            : f.policy_action === 'MASK' || f.policy_action === 'RESTRICT'
                            ? 'text-red-700'
                            : f.policy_action === 'ALLOW'
                            ? 'text-slate-600'
                            : 'text-teal-700'
                        }
                      >
                        {f.policy_action}
                      </span>
                    </td>
                    <td className="px-3 py-2 font-mono text-slate-800">
                      {f.token ?? '—'}
                    </td>
                    <td className="px-3 py-2 text-slate-600">{f.policy_reason}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
};
