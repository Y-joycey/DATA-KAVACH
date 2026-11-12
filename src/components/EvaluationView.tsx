import React from 'react';
import { CheckCircle2, AlertTriangle, XCircle, Play } from 'lucide-react';
import { EvaluationReport } from '../types';

interface EvaluationViewProps {
  report: EvaluationReport | null;
  loading: boolean;
  onRunEvaluation: () => void;
}

export const EvaluationView: React.FC<EvaluationViewProps> = ({
  report,
  loading,
  onRunEvaluation,
}) => {
  if (loading && !report) {
    return (
      <div className="space-y-4">
        <div className="h-24 animate-pulse rounded-lg border border-slate-200 bg-white" />
        <div className="h-80 animate-pulse rounded-lg border border-slate-200 bg-white" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-200 pb-4">
        <div>
          <h1 className="text-xl font-semibold text-slate-900">
            Synthetic Benchmark & Security Evaluation
          </h1>
          <p className="mt-1 text-sm text-slate-600">
            Measures per-entity detection precision/recall/F1, outbound leakage, reinsertion integrity, and fail-closed security invariants across {report?.dataset_size ?? 54} synthetic Indian documents.
          </p>
        </div>
        <button
          onClick={onRunEvaluation}
          disabled={loading}
          className="inline-flex items-center gap-2 rounded-md bg-teal-700 px-4 py-2 text-xs font-medium text-white hover:bg-teal-800 disabled:opacity-50 whitespace-nowrap shrink-0"
        >
          <Play className="h-3.5 w-3.5" />
          {loading ? 'Running Evaluation...' : 'Re-Run 54-Doc Benchmark'}
        </button>
      </div>

      {report && (
        <>
          {/* KPI Strip */}
          <div className="grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-6">
            <div className="rounded-lg border border-slate-200 bg-white p-4">
              <div className="text-xs text-slate-500">Outbound Leakage</div>
              <div className="mt-1 flex items-baseline gap-2 font-mono text-2xl font-semibold tabular-nums text-emerald-700">
                {report.overall.outbound_leakage_count}
                <span className="text-xs font-normal text-slate-500">
                  / {report.dataset_size} docs
                </span>
              </div>
            </div>
            <div className="rounded-lg border border-slate-200 bg-white p-4">
              <div className="text-xs text-slate-500">Precision / Recall</div>
              <div className="mt-1 font-mono text-2xl font-semibold tabular-nums text-slate-900">
                {(report.overall.precision * 100).toFixed(1)}%
                <span className="ml-1.5 text-sm font-normal text-slate-500">
                  / {(report.overall.recall * 100).toFixed(1)}%
                </span>
              </div>
            </div>
            <div className="rounded-lg border border-slate-200 bg-white p-4">
              <div className="text-xs text-slate-500">Macro F1 Score</div>
              <div className="mt-1 font-mono text-2xl font-semibold tabular-nums text-slate-900">
                {(report.overall.f1 * 100).toFixed(1)}%
              </div>
            </div>
            <div className="rounded-lg border border-slate-200 bg-white p-4">
              <div className="text-xs text-slate-500">Reinsertion Accuracy</div>
              <div className="mt-1 font-mono text-2xl font-semibold tabular-nums text-slate-900">
                {(report.overall.reinsertion_accuracy * 100).toFixed(1)}%
              </div>
            </div>
            <div className="rounded-lg border border-slate-200 bg-white p-4">
              <div className="text-xs text-slate-500">Review / Hold Rate</div>
              <div className="mt-1 font-mono text-2xl font-semibold tabular-nums text-slate-900">
                {(report.overall.review_rate * 100).toFixed(1)}%
              </div>
            </div>
            <div className="rounded-lg border border-slate-200 bg-white p-4">
              <div className="text-xs text-slate-500">Added Latency (p50 / p95)</div>
              <div className="mt-1 font-mono text-xl font-semibold tabular-nums text-slate-900">
                {report.overall.p50_latency_ms}ms
                <span className="ml-1 text-xs font-normal text-slate-500">
                  / {report.overall.p95_latency_ms}ms
                </span>
              </div>
            </div>
          </div>

          <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
            {/* Per-Entity Table */}
            <div className="rounded-lg border border-slate-200 bg-white p-5 lg:col-span-7">
              <div className="flex items-center justify-between border-b border-slate-100 pb-3">
                <h2 className="text-sm font-semibold text-slate-900">
                  Per-Entity Detection Performance
                </h2>
                <span className="text-xs text-slate-500">
                  TP: {report.overall.tp} · FP: {report.overall.fp} · FN: {report.overall.fn}
                </span>
              </div>
              <div className="mt-3 overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead className="border-b border-slate-200 bg-slate-50 text-slate-600">
                    <tr>
                      <th className="px-3 py-2 font-medium">Entity Type</th>
                      <th className="px-3 py-2 text-right font-medium">TP</th>
                      <th className="px-3 py-2 text-right font-medium">FP</th>
                      <th className="px-3 py-2 text-right font-medium">FN</th>
                      <th className="px-3 py-2 text-right font-medium">Precision</th>
                      <th className="px-3 py-2 text-right font-medium">Recall</th>
                      <th className="px-3 py-2 text-right font-medium">F1</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100 font-mono tabular-nums">
                    {report.per_entity.map((row) => (
                      <tr key={row.entity_type} className="hover:bg-slate-50">
                        <td className="px-3 py-2 font-medium text-slate-900">{row.entity_type}</td>
                        <td className="px-3 py-2 text-right text-slate-700">{row.tp}</td>
                        <td className="px-3 py-2 text-right text-slate-700">{row.fp}</td>
                        <td className="px-3 py-2 text-right text-slate-700">{row.fn}</td>
                        <td className="px-3 py-2 text-right text-slate-900">
                          {(row.precision * 100).toFixed(1)}%
                        </td>
                        <td className="px-3 py-2 text-right text-slate-900">
                          {(row.recall * 100).toFixed(1)}%
                        </td>
                        <td className="px-3 py-2 text-right font-semibold text-slate-900">
                          {(row.f1 * 100).toFixed(1)}%
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Security Suite & Stage Latency */}
            <div className="space-y-5 lg:col-span-5">
              <div className="rounded-lg border border-slate-200 bg-white p-5">
                <h2 className="border-b border-slate-100 pb-3 text-sm font-semibold text-slate-900">
                  Security & Reinsertion Invariant Suite
                </h2>
                <div className="mt-3 space-y-3">
                  {report.security_suite.map((item) => (
                    <div
                      key={item.name}
                      className="flex items-start gap-2.5 border-b border-slate-100 pb-2.5 last:border-b-0 last:pb-0"
                    >
                      {item.passed ? (
                        <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-emerald-600" />
                      ) : (
                        <XCircle className="mt-0.5 h-4 w-4 shrink-0 text-red-600" />
                      )}
                      <div>
                        <div className="text-xs font-medium text-slate-900">{item.name}</div>
                        <div className="mt-0.5 font-mono text-[11px] text-slate-500">
                          {item.detail}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              <div className="rounded-lg border border-slate-200 bg-white p-5">
                <h2 className="border-b border-slate-100 pb-3 text-sm font-semibold text-slate-900">
                  Dataset Composition & Mean Stage Latency
                </h2>
                <div className="mt-3 flex flex-wrap gap-x-4 gap-y-1.5 text-xs text-slate-700">
                  {Object.entries(report.dataset_composition).map(([cat, count]) => (
                    <span key={cat} className="font-mono">
                      {cat}: {count}
                    </span>
                  ))}
                </div>
                <div className="mt-4 grid grid-cols-2 gap-2 border-t border-slate-100 pt-3 font-mono text-xs tabular-nums text-slate-700">
                  <div>Normalize: {report.overall.mean_stage_latency_ms.normalize_ms} ms</div>
                  <div>Detect: {report.overall.mean_stage_latency_ms.detect_ms} ms</div>
                  <div>Policy: {report.overall.mean_stage_latency_ms.policy_ms} ms</div>
                  <div>Sanitize: {report.overall.mean_stage_latency_ms.sanitize_ms} ms</div>
                  <div>Firewall: {report.overall.mean_stage_latency_ms.firewall_ms} ms</div>
                  <div>Reinsert: {report.overall.mean_stage_latency_ms.reinsert_ms} ms</div>
                </div>
              </div>
            </div>
          </div>

          {/* Honest Tested Coverage & Known Limitations */}
          <div className="rounded-lg border border-slate-200 bg-white p-5">
            <div className="flex items-center gap-2 border-b border-slate-100 pb-3">
              <AlertTriangle className="h-4 w-4 text-amber-600" />
              <h2 className="text-sm font-semibold text-slate-900">
                Tested Language Coverage & Known Limitations
              </h2>
            </div>
            <div className="mt-3 grid grid-cols-1 gap-5 md:grid-cols-2">
              <div>
                <div className="text-xs font-medium text-slate-600">
                  Explicitly Tested Languages & Scripts
                </div>
                <ul className="mt-2 list-disc space-y-1 pl-4 text-xs text-slate-700">
                  {report.tested_languages.map((lang) => (
                    <li key={lang}>{lang}</li>
                  ))}
                </ul>
              </div>
              <div>
                <div className="text-xs font-medium text-slate-600">
                  Honest Scope & Legal Boundaries
                </div>
                <ul className="mt-2 list-disc space-y-1 pl-4 text-xs text-slate-700">
                  {report.limitations.map((lim, idx) => (
                    <li key={idx}>{lim}</li>
                  ))}
                </ul>
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );
};
