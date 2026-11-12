import React, { useState } from 'react';
import { CheckCircle2, Clock, ShieldAlert, XCircle } from 'lucide-react';
import { GatewayResponse, PolicyAction, ReviewItem } from '../types';

interface ReviewQueueViewProps {
  items: ReviewItem[];
  loading: boolean;
  onDecide: (
    itemId: string,
    decision: 'approved' | 'rejected',
    reviewer: string,
    reason: string,
    overrideAction: PolicyAction
  ) => Promise<GatewayResponse | undefined>;
  onOpenReprocessed: (res: GatewayResponse) => void;
}

export const ReviewQueueView: React.FC<ReviewQueueViewProps> = ({
  items,
  loading,
  onDecide,
  onOpenReprocessed,
}) => {
  const [filter, setFilter] = useState<'all' | 'pending' | 'decided'>('all');
  const [reviewer, setReviewer] = useState('privacy-officer@enterprise.in');
  const [reasons, setReasons] = useState<Record<string, string>>({});
  const [overrides, setOverrides] = useState<Record<string, PolicyAction>>({});
  const [busyId, setBusyId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const filtered = items.filter((it) => {
    if (filter === 'pending') return it.status === 'pending';
    if (filter === 'decided') return it.status !== 'pending';
    return true;
  });

  const handleAction = async (item: ReviewItem, decision: 'approved' | 'rejected') => {
    setBusyId(item.id);
    setError(null);
    try {
      const reason =
        reasons[item.id] ||
        (decision === 'approved'
          ? 'Verified candidate context; approved for tokenized processing'
          : 'Rejected due to unverified high-risk identifier ambiguity');
      const overrideAction = overrides[item.id] ?? 'TOKENIZE';
      const reprocessed = await onDecide(item.id, decision, reviewer, reason, overrideAction);
      if (reprocessed) {
        onOpenReprocessed(reprocessed);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to process review decision');
    } finally {
      setBusyId(null);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-200 pb-4">
        <div>
          <h1 className="text-xl font-semibold text-slate-900">Human Review Queue</h1>
          <p className="mt-1 text-sm text-slate-600">
            Uncertain or ambiguous high-risk candidates are held locally without invoking any external provider until reviewed.
          </p>
        </div>
        <div className="flex items-center gap-1 rounded-lg bg-slate-100 p-1">
          {(['all', 'pending', 'decided'] as const).map((tab) => (
            <button
              key={tab}
              onClick={() => setFilter(tab)}
              className={`rounded-md px-3 py-1.5 text-xs font-medium capitalize transition-colors whitespace-nowrap shrink-0 ${
                filter === tab
                  ? 'bg-white text-slate-900 shadow-sm'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              {tab}
            </button>
          ))}
        </div>
      </div>

      {error && (
        <div className="flex items-center gap-2 rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">
          <XCircle className="h-4 w-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      <div className="flex flex-wrap items-center gap-3 rounded-lg border border-slate-200 bg-white px-4 py-3">
        <label htmlFor="reviewer-id" className="text-xs font-medium text-slate-600">
          Authorized Reviewer Identity
        </label>
        <input
          id="reviewer-id"
          type="text"
          value={reviewer}
          onChange={(e) => setReviewer(e.target.value)}
          className="w-72 rounded-md border border-slate-200 px-3 py-1.5 text-sm text-slate-900 focus:border-teal-700 focus:outline-none"
        />
        <span className="text-xs text-slate-500">
          Minimized sanitized context only · Raw protected values remain in local memory
        </span>
      </div>

      {loading ? (
        <div className="space-y-3">
          {[1, 2].map((i) => (
            <div key={i} className="h-36 animate-pulse rounded-lg border border-slate-200 bg-white" />
          ))}
        </div>
      ) : filtered.length === 0 ? (
        <div className="rounded-lg border border-slate-200 bg-white p-10 text-center">
          <p className="text-sm font-medium text-slate-900">No review items match this filter</p>
          <p className="mt-1 text-xs text-slate-500">
            Submit an ambiguous document (such as an invalid Aadhaar checksum or unknown Member ID) in the Gateway tab to trigger a fail-closed review hold.
          </p>
        </div>
      ) : (
        <div className="space-y-4">
          {filtered.map((item) => (
            <div key={item.id} className="rounded-lg border border-slate-200 bg-white p-5">
              <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-100 pb-3">
                <div className="flex flex-wrap items-center gap-2 text-xs text-slate-500">
                  <span className="font-mono font-semibold text-slate-900">{item.id}</span>
                  <span aria-hidden="true">·</span>
                  <span className="font-mono">{item.request_id.slice(0, 14)}</span>
                  <span aria-hidden="true">·</span>
                  <span>Domain: {item.domain}</span>
                  <span aria-hidden="true">·</span>
                  <span>Purpose: {item.purpose}</span>
                  <span aria-hidden="true">·</span>
                  <span>{new Date(item.created_at).toLocaleTimeString()}</span>
                </div>
                <div className="flex items-center gap-1.5 text-xs font-medium">
                  {item.status === 'pending' ? (
                    <span className="inline-flex items-center gap-1.5 text-amber-700">
                      <Clock className="h-3.5 w-3.5" />
                      Pending Human Decision (Provider Not Called)
                    </span>
                  ) : item.status === 'approved' ? (
                    <span className="inline-flex items-center gap-1.5 text-emerald-700">
                      <CheckCircle2 className="h-3.5 w-3.5" />
                      Approved & Reprocessed
                    </span>
                  ) : (
                    <span className="inline-flex items-center gap-1.5 text-red-700">
                      <ShieldAlert className="h-3.5 w-3.5" />
                      Rejected (Blocked)
                    </span>
                  )}
                </div>
              </div>

              <div className="mt-4 grid grid-cols-1 gap-5 lg:grid-cols-2">
                <div>
                  <div className="text-xs font-medium text-slate-600">
                    Minimized Sanitized Context
                  </div>
                  <pre className="mt-1.5 max-h-44 overflow-auto whitespace-pre-wrap rounded-md border border-slate-200 bg-slate-50 p-3 font-mono text-xs text-slate-800">
                    {item.sanitized_context}
                  </pre>
                </div>
                <div>
                  <div className="text-xs font-medium text-slate-600">
                    Uncertain High-Risk Candidates
                  </div>
                  <div className="mt-1.5 overflow-x-auto rounded-md border border-slate-200">
                    <table className="w-full text-left text-xs">
                      <thead className="border-b border-slate-200 bg-slate-50 text-slate-600">
                        <tr>
                          <th className="px-3 py-2 font-medium">Entity</th>
                          <th className="px-3 py-2 font-medium">Confidence</th>
                          <th className="px-3 py-2 font-medium">Ambiguity / Evidence</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-100">
                        {item.candidates.map((c) => (
                          <tr key={c.finding_id}>
                            <td className="px-3 py-2 font-mono font-medium text-slate-900">
                              {c.entity_type}
                            </td>
                            <td className="px-3 py-2 font-mono tabular-nums text-slate-700">
                              {c.confidence.toFixed(2)} ({c.confidence_band})
                            </td>
                            <td className="px-3 py-2 text-slate-600">
                              {c.ambiguity.join(', ') || c.context_label || c.detector}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              </div>

              {item.status === 'pending' ? (
                <div className="mt-4 flex flex-wrap items-center justify-between gap-3 border-t border-slate-100 pt-4">
                  <div className="flex flex-1 flex-wrap items-center gap-3">
                    <select
                      aria-label="Override policy action"
                      value={overrides[item.id] ?? 'TOKENIZE'}
                      onChange={(e) =>
                        setOverrides((prev) => ({
                          ...prev,
                          [item.id]: e.target.value as PolicyAction,
                        }))
                      }
                      className="rounded-md border border-slate-200 bg-white px-3 py-2 text-xs font-medium text-slate-800 focus:border-teal-700 focus:outline-none"
                    >
                      <option value="TOKENIZE">Approve as TOKENIZE</option>
                      <option value="MASK">Approve as MASK (Irreversible)</option>
                      <option value="ALLOW">Approve as ALLOW (Non-PII)</option>
                    </select>
                    <input
                      type="text"
                      placeholder="Decision rationale for audit trail..."
                      value={reasons[item.id] ?? ''}
                      onChange={(e) =>
                        setReasons((prev) => ({ ...prev, [item.id]: e.target.value }))
                      }
                      className="min-w-[240px] flex-1 rounded-md border border-slate-200 px-3 py-2 text-xs text-slate-900 focus:border-teal-700 focus:outline-none"
                    />
                  </div>
                  <div className="flex items-center gap-2">
                    <button
                      disabled={busyId === item.id}
                      onClick={() => handleAction(item, 'rejected')}
                      className="rounded-md border border-red-200 bg-white px-4 py-2 text-xs font-medium text-red-700 hover:bg-red-50 disabled:opacity-50 whitespace-nowrap shrink-0"
                    >
                      Reject Request
                    </button>
                    <button
                      disabled={busyId === item.id}
                      onClick={() => handleAction(item, 'approved')}
                      className="rounded-md bg-teal-700 px-4 py-2 text-xs font-medium text-white hover:bg-teal-800 disabled:opacity-50 whitespace-nowrap shrink-0"
                    >
                      {busyId === item.id ? 'Reprocessing...' : 'Approve & Reprocess'}
                    </button>
                  </div>
                </div>
              ) : (
                <div className="mt-3 border-t border-slate-100 pt-3 text-xs text-slate-600">
                  <span>Reviewer: {item.reviewer}</span>
                  <span className="mx-2" aria-hidden="true">·</span>
                  <span>Reason: {item.decision_reason}</span>
                  <span className="mx-2" aria-hidden="true">·</span>
                  <span>Policy: {item.policy_version}</span>
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
