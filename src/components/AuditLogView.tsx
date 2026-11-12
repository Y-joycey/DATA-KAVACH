import React, { useState } from 'react';
import { CheckCircle2, Clock, Search, ShieldAlert } from 'lucide-react';
import { AuditRecord } from '../types';

interface AuditLogViewProps {
  records: AuditRecord[];
  loading: boolean;
}

export const AuditLogView: React.FC<AuditLogViewProps> = ({ records, loading }) => {
  const [query, setQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [selected, setSelected] = useState<AuditRecord | null>(null);

  const filtered = records.filter((r) => {
    if (statusFilter !== 'all' && r.status !== statusFilter) return false;
    if (!query.trim()) return true;
    const q = query.toLowerCase();
    return (
      r.request_id.toLowerCase().includes(q) ||
      r.domain.toLowerCase().includes(q) ||
      r.purpose.toLowerCase().includes(q) ||
      r.entity_types.some((e) => e.toLowerCase().includes(q))
    );
  });

  const activeRecord = selected ?? filtered[0] ?? null;

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-200 pb-4">
        <div>
          <h1 className="text-xl font-semibold text-slate-900">Gateway Audit Trail</h1>
          <p className="mt-1 text-sm text-slate-600">
            Request-level provenance, policy versions, and exact sanitized outbound payloads. Raw PII and token mappings are strictly excluded.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <div className="relative">
            <Search className="pointer-events-none absolute top-2.5 left-3 h-3.5 w-3.5 text-slate-400" />
            <input
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Filter by request ID, domain, entity..."
              className="w-64 rounded-md border border-slate-200 bg-white py-1.5 pr-3 pl-8 text-xs text-slate-900 focus:border-teal-700 focus:outline-none"
            />
          </div>
          <div className="flex items-center gap-1 rounded-lg bg-slate-100 p-1">
            {(['all', 'completed', 'pending_review', 'blocked'] as const).map((s) => (
              <button
                key={s}
                onClick={() => setStatusFilter(s)}
                className={`rounded-md px-2.5 py-1 text-xs font-medium transition-colors whitespace-nowrap shrink-0 ${
                  statusFilter === s
                    ? 'bg-white text-slate-900 shadow-sm'
                    : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                {s === 'all'
                  ? 'All'
                  : s === 'pending_review'
                  ? 'Review'
                  : s === 'completed'
                  ? 'Completed'
                  : 'Blocked'}
              </button>
            ))}
          </div>
        </div>
      </div>

      {loading ? (
        <div className="h-64 animate-pulse rounded-lg border border-slate-200 bg-white" />
      ) : filtered.length === 0 ? (
        <div className="rounded-lg border border-slate-200 bg-white p-10 text-center">
          <p className="text-sm font-medium text-slate-900">No audit records recorded yet</p>
          <p className="mt-1 text-xs text-slate-500">
            Process a request in the Gateway tab to generate a sanitized audit record.
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-5 lg:grid-cols-12">
          <div className="overflow-x-auto rounded-lg border border-slate-200 bg-white lg:col-span-7">
            <table className="w-full text-left text-xs">
              <thead className="border-b border-slate-200 bg-slate-50 text-slate-600">
                <tr>
                  <th className="px-3 py-2.5 font-medium">Request ID</th>
                  <th className="px-3 py-2.5 font-medium">Domain / Purpose</th>
                  <th className="px-3 py-2.5 font-medium">Firewall</th>
                  <th className="px-3 py-2.5 font-medium">Provider</th>
                  <th className="px-3 py-2.5 text-right font-medium">Latency</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {filtered.map((rec) => {
                  const isActive = activeRecord?.request_id === rec.request_id;
                  return (
                    <tr
                      key={rec.request_id}
                      onClick={() => setSelected(rec)}
                      className={`cursor-pointer transition-colors ${
                        isActive ? 'bg-teal-50/60' : 'hover:bg-slate-50'
                      }`}
                    >
                      <td className="px-3 py-2.5 font-mono text-slate-900">
                        {rec.request_id.slice(0, 14)}
                      </td>
                      <td className="px-3 py-2.5 text-slate-700">
                        <div>{rec.domain} · {rec.purpose}</div>
                        <div className="mt-0.5 text-[11px] text-slate-500">
                          {rec.entity_types.join(', ') || 'No protected entities'}
                        </div>
                      </td>
                      <td className="px-3 py-2.5">
                        {rec.status === 'completed' ? (
                          <span className="inline-flex items-center gap-1 font-medium text-emerald-700">
                            <CheckCircle2 className="h-3.5 w-3.5" />
                            PASS
                          </span>
                        ) : rec.status === 'pending_review' ? (
                          <span className="inline-flex items-center gap-1 font-medium text-amber-700">
                            <Clock className="h-3.5 w-3.5" />
                            REVIEW
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 font-medium text-red-700">
                            <ShieldAlert className="h-3.5 w-3.5" />
                            BLOCK
                          </span>
                        )}
                      </td>
                      <td className="px-3 py-2.5 text-slate-700">
                        {rec.provider_called ? rec.model : 'Not invoked'}
                      </td>
                      <td className="px-3 py-2.5 text-right font-mono tabular-nums text-slate-700">
                        {rec.latency_ms.total_ms.toFixed(2)} ms
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          <div className="rounded-lg border border-slate-200 bg-white p-5 lg:col-span-5">
            {activeRecord && (
              <div className="space-y-4">
                <div className="border-b border-slate-100 pb-3">
                  <h2 className="text-sm font-semibold text-slate-900">
                    Audit Record Detail
                  </h2>
                  <div className="mt-1 font-mono text-xs text-slate-600">
                    {activeRecord.request_id}
                  </div>
                </div>

                <dl className="grid grid-cols-2 gap-x-4 gap-y-2 text-xs">
                  <div>
                    <dt className="text-slate-500">Policy Version</dt>
                    <dd className="font-mono text-slate-900">{activeRecord.policy_version}</dd>
                  </div>
                  <div>
                    <dt className="text-slate-500">Dictionary Version</dt>
                    <dd className="font-mono text-slate-900">{activeRecord.dictionary_version}</dd>
                  </div>
                  <div>
                    <dt className="text-slate-500">Language</dt>
                    <dd className="text-slate-900">{activeRecord.detected_language}</dd>
                  </div>
                  <div>
                    <dt className="text-slate-500">Provider Invoked</dt>
                    <dd className="text-slate-900">
                      {activeRecord.provider_called
                        ? `${activeRecord.provider} (${activeRecord.model})`
                        : 'No (fail-closed)'}
                    </dd>
                  </div>
                </dl>

                <div>
                  <div className="text-xs font-medium text-slate-600">
                    Outbound Firewall SHA-256 Hash
                  </div>
                  <div className="mt-1 truncate rounded border border-slate-200 bg-slate-50 px-2.5 py-1.5 font-mono text-[11px] text-slate-700">
                    {activeRecord.outbound_validation.content_hash}
                  </div>
                </div>

                <div>
                  <div className="text-xs font-medium text-slate-600">
                    Exact Sanitized Outbound Payload (Audit Copy)
                  </div>
                  <pre className="mt-1.5 max-h-56 overflow-auto whitespace-pre-wrap rounded-md border border-slate-200 bg-slate-50 p-3 font-mono text-xs text-slate-800">
                    {activeRecord.exact_sanitized_outbound_payload}
                  </pre>
                </div>

                <div>
                  <div className="text-xs font-medium text-slate-600">
                    Per-Stage Latency (ms)
                  </div>
                  <div className="mt-1.5 grid grid-cols-4 gap-2 text-xs font-mono tabular-nums text-slate-700">
                    <div>Norm: {activeRecord.latency_ms.normalize_ms}</div>
                    <div>Detect: {activeRecord.latency_ms.detect_ms}</div>
                    <div>Policy: {activeRecord.latency_ms.policy_ms}</div>
                    <div>Sanitize: {activeRecord.latency_ms.sanitize_ms}</div>
                    <div>Firewall: {activeRecord.latency_ms.firewall_ms}</div>
                    <div>Provider: {activeRecord.latency_ms.provider_ms}</div>
                    <div>Reinsert: {activeRecord.latency_ms.reinsert_ms}</div>
                    <div className="font-semibold text-slate-900">
                      Total: {activeRecord.latency_ms.total_ms}
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
