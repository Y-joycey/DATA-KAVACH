import { useCallback, useEffect, useState } from 'react';
import { GatewayWorkbench } from './components/GatewayWorkbench';
import { ReviewQueueView } from './components/ReviewQueueView';
import { AuditLogView } from './components/AuditLogView';
import { EvaluationView } from './components/EvaluationView';
import {
  AuditRecord,
  DomainType,
  EvaluationReport,
  GatewayResponse,
  PolicyAction,
  PresetDocument,
  ProviderMode,
  ReviewItem,
  SanitizedFindingView,
  SimulationMode,
  TaskType,
} from './types';

type ActiveTab = 'gateway' | 'review' | 'audit' | 'evaluation';

const INITIAL_TEXT = `Applicant Name: Aarav Kulkarni
DOB: 14 Nov 1994
Aadhaar: 2345 6789 0124
PAN: ABCDE1234F
GSTIN: 27AAPFU0939F1ZV
Address: Flat 402, Shanti Nagar, Pune 411001
Please summarize this KYC file for onboarding verification.`;

export default function App() {
  const [activeTab, setActiveTab] = useState<ActiveTab>('gateway');
  const [presets, setPresets] = useState<PresetDocument[]>([]);
  const [text, setText] = useState(INITIAL_TEXT);
  const [domain, setDomain] = useState<DomainType>('kyc');
  const [purpose, setPurpose] = useState('kyc_verification');
  const [task, setTask] = useState<TaskType>('summarize');
  const [provider, setProvider] = useState<ProviderMode>('mock');
  const [simulationMode, setSimulationMode] = useState<SimulationMode>('normal');
  const [simulateOutage, setSimulateOutage] = useState(false);
  const [inputFormat, setInputFormat] = useState<'plain_text' | 'json' | 'csv'>('plain_text');

  const [gatewayResult, setGatewayResult] = useState<GatewayResponse | null>(null);
  const [localPreview, setLocalPreview] = useState<{
    detected_language: string;
    language_supported: boolean;
    sanitized_payload: string;
    findings: SanitizedFindingView[];
    prompt_injection_detected: boolean;
  } | null>(null);
  const [gatewayLoading, setGatewayLoading] = useState(false);
  const [gatewayError, setGatewayError] = useState<string | null>(null);

  const [reviewItems, setReviewItems] = useState<ReviewItem[]>([]);
  const [reviewLoading, setReviewLoading] = useState(false);

  const [auditRecords, setAuditRecords] = useState<AuditRecord[]>([]);
  const [auditLoading, setAuditLoading] = useState(false);

  const [evaluationReport, setEvaluationReport] = useState<EvaluationReport | null>(null);
  const [evalLoading, setEvalLoading] = useState(false);

  const fetchPresets = useCallback(async () => {
    try {
      const res = await fetch('/api/v1/presets');
      if (res.ok) {
        const data = await res.json();
        setPresets(data.presets ?? []);
      }
    } catch {
      // non-fatal
    }
  }, []);

  const fetchReviews = useCallback(async () => {
    setReviewLoading(true);
    try {
      const res = await fetch('/api/v1/review');
      if (res.ok) {
        const data = await res.json();
        setReviewItems(data.items ?? []);
      }
    } finally {
      setReviewLoading(false);
    }
  }, []);

  const fetchAudits = useCallback(async () => {
    setAuditLoading(true);
    try {
      const res = await fetch('/api/v1/requests');
      if (res.ok) {
        const data = await res.json();
        setAuditRecords(data.requests ?? []);
      }
    } finally {
      setAuditLoading(false);
    }
  }, []);

  const fetchMetrics = useCallback(async () => {
    setEvalLoading(true);
    try {
      const res = await fetch('/api/v1/metrics');
      if (res.ok) {
        const data = await res.json();
        setEvaluationReport(data);
      }
    } finally {
      setEvalLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchPresets();
    fetchReviews();
    fetchAudits();
  }, [fetchPresets, fetchReviews, fetchAudits]);

  useEffect(() => {
    if (activeTab === 'evaluation' && !evaluationReport && !evalLoading) {
      fetchMetrics();
    }
  }, [activeTab, evaluationReport, evalLoading, fetchMetrics]);

  const handleAnalyzeLocal = async () => {
    setGatewayLoading(true);
    setGatewayError(null);
    setGatewayResult(null);
    try {
      const res = await fetch('/api/v1/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          text,
          purpose,
          domain,
          task,
          provider,
          input_format: inputFormat,
          simulate_scanner_outage: simulateOutage,
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Local analysis failed');
      setLocalPreview(data);
    } catch (err) {
      setGatewayError(err instanceof Error ? err.message : 'Local analysis failed');
    } finally {
      setGatewayLoading(false);
    }
  };

  const handleProcessGateway = async () => {
    setGatewayLoading(true);
    setGatewayError(null);
    setLocalPreview(null);
    try {
      const res = await fetch('/api/v1/gateway/process', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          text,
          purpose,
          domain,
          task,
          provider,
          input_format: inputFormat,
          simulate_scanner_outage: simulateOutage,
          simulation_mode: simulationMode,
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Gateway processing failed');
      setGatewayResult(data);
      fetchReviews();
      fetchAudits();
    } catch (err) {
      setGatewayError(err instanceof Error ? err.message : 'Gateway processing failed');
    } finally {
      setGatewayLoading(false);
    }
  };

  const handleRunEvaluation = async () => {
    setActiveTab('evaluation');
    setEvalLoading(true);
    try {
      const res = await fetch('/api/v1/evaluate', { method: 'POST' });
      if (res.ok) {
        const data = await res.json();
        setEvaluationReport(data);
      }
    } finally {
      setEvalLoading(false);
    }
  };

  const handleDecideReview = async (
    itemId: string,
    decision: 'approved' | 'rejected',
    reviewer: string,
    reason: string,
    overrideAction: PolicyAction
  ) => {
    const res = await fetch(`/api/v1/review/${itemId}/decision`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ decision, reviewer, reason, overrideAction }),
    });
    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.error || 'Review decision failed');
    }
    await fetchReviews();
    await fetchAudits();
    return data.reprocessed as GatewayResponse | undefined;
  };

  const pendingCount = reviewItems.filter((r) => r.status === 'pending').length;

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900">
      {/* Strict 3-Zone Top Bar */}
      <header className="border-b border-slate-200 bg-white">
        <div className="mx-auto flex max-w-[1440px] items-center justify-between gap-8 px-6 py-3.5">
          {/* Zone 1: Single text element wordmark */}
          <button
            type="button"
            onClick={() => setActiveTab('gateway')}
            className="font-display text-lg font-bold tracking-tight text-slate-900 whitespace-nowrap shrink-0 focus:outline-none"
          >
            DATA KAVACH
          </button>

          {/* Zone 2: Concise single-line nav links */}
          <nav className="flex items-center gap-6 text-sm font-medium">
            <button
              type="button"
              onClick={() => setActiveTab('gateway')}
              className={`border-b-2 py-1 transition-colors whitespace-nowrap shrink-0 ${
                activeTab === 'gateway'
                  ? 'border-teal-700 text-slate-900'
                  : 'border-transparent text-slate-600 hover:text-slate-900'
              }`}
            >
              Gateway
            </button>
            <button
              type="button"
              onClick={() => setActiveTab('review')}
              className={`border-b-2 py-1 transition-colors whitespace-nowrap shrink-0 ${
                activeTab === 'review'
                  ? 'border-teal-700 text-slate-900'
                  : 'border-transparent text-slate-600 hover:text-slate-900'
              }`}
            >
              {pendingCount > 0 ? `Review Queue (${pendingCount})` : 'Review Queue'}
            </button>
            <button
              type="button"
              onClick={() => setActiveTab('audit')}
              className={`border-b-2 py-1 transition-colors whitespace-nowrap shrink-0 ${
                activeTab === 'audit'
                  ? 'border-teal-700 text-slate-900'
                  : 'border-transparent text-slate-600 hover:text-slate-900'
              }`}
            >
              Audit Log
            </button>
            <button
              type="button"
              onClick={() => setActiveTab('evaluation')}
              className={`border-b-2 py-1 transition-colors whitespace-nowrap shrink-0 ${
                activeTab === 'evaluation'
                  ? 'border-teal-700 text-slate-900'
                  : 'border-transparent text-slate-600 hover:text-slate-900'
              }`}
            >
              Evaluation
            </button>
          </nav>

          {/* Zone 3: Single primary action */}
          <div className="flex items-center shrink-0">
            <button
              type="button"
              onClick={handleRunEvaluation}
              disabled={evalLoading}
              className="rounded-md bg-teal-700 px-4 py-2 text-xs font-medium text-white hover:bg-teal-800 disabled:opacity-50 whitespace-nowrap shrink-0"
            >
              {evalLoading ? 'Evaluating...' : 'Run Benchmark'}
            </button>
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-[1440px] px-6 py-6">
        {activeTab === 'gateway' && (
          <GatewayWorkbench
            presets={presets}
            text={text}
            setText={setText}
            domain={domain}
            setDomain={setDomain}
            purpose={purpose}
            setPurpose={setPurpose}
            task={task}
            setTask={setTask}
            provider={provider}
            setProvider={setProvider}
            simulationMode={simulationMode}
            setSimulationMode={setSimulationMode}
            simulateOutage={simulateOutage}
            setSimulateOutage={setSimulateOutage}
            inputFormat={inputFormat}
            setInputFormat={setInputFormat}
            result={gatewayResult}
            localPreview={localPreview}
            loading={gatewayLoading}
            error={gatewayError}
            onProcess={handleProcessGateway}
            onAnalyzeLocal={handleAnalyzeLocal}
            onOpenReviewQueue={() => setActiveTab('review')}
          />
        )}

        {activeTab === 'review' && (
          <ReviewQueueView
            items={reviewItems}
            loading={reviewLoading}
            onDecide={handleDecideReview}
            onOpenReprocessed={(res) => {
              setGatewayResult(res);
              setActiveTab('gateway');
            }}
          />
        )}

        {activeTab === 'audit' && (
          <AuditLogView records={auditRecords} loading={auditLoading} />
        )}

        {activeTab === 'evaluation' && (
          <EvaluationView
            report={evaluationReport}
            loading={evalLoading}
            onRunEvaluation={handleRunEvaluation}
          />
        )}
      </main>
    </div>
  );
}
