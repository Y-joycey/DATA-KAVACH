import fs from 'node:fs';
import path from 'node:path';
import { AuditRecord, EvaluationReport, ReviewItem } from '../types.ts';

const DATA_DIR = path.resolve(process.cwd(), '.minearena-data');
const AUDIT_FILE = path.join(DATA_DIR, 'audit_logs.json');
const REVIEW_FILE = path.join(DATA_DIR, 'review_queue.json');

// Keep an in-memory store mirrored to local disk (unless disabled for isolated tests)
let auditRecords: AuditRecord[] = [];
let reviewItems: ReviewItem[] = [];
let latestEvaluation: EvaluationReport | null = null;
let persistenceEnabled = true;

function ensureLoaded(): void {
  if (!persistenceEnabled) return;
  try {
    if (!fs.existsSync(DATA_DIR)) {
      fs.mkdirSync(DATA_DIR, { recursive: true });
    }
    if (auditRecords.length === 0 && fs.existsSync(AUDIT_FILE)) {
      const raw = fs.readFileSync(AUDIT_FILE, 'utf8');
      auditRecords = JSON.parse(raw) as AuditRecord[];
    }
    if (reviewItems.length === 0 && fs.existsSync(REVIEW_FILE)) {
      const raw = fs.readFileSync(REVIEW_FILE, 'utf8');
      reviewItems = JSON.parse(raw) as ReviewItem[];
    }
  } catch {
    // Non-fatal fallback to in-memory storage
  }
}

function flushAudit(): void {
  if (!persistenceEnabled) return;
  try {
    if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
    fs.writeFileSync(AUDIT_FILE, JSON.stringify(auditRecords.slice(0, 200), null, 2), 'utf8');
  } catch {
    // ignore disk errors
  }
}

function flushReviews(): void {
  if (!persistenceEnabled) return;
  try {
    if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
    fs.writeFileSync(REVIEW_FILE, JSON.stringify(reviewItems.slice(0, 200), null, 2), 'utf8');
  } catch {
    // ignore disk errors
  }
}

export function setPersistenceEnabled(enabled: boolean): void {
  persistenceEnabled = enabled;
}

export function saveAuditRecord(record: AuditRecord): void {
  ensureLoaded();
  const idx = auditRecords.findIndex((r) => r.request_id === record.request_id);
  if (idx >= 0) {
    auditRecords[idx] = record;
  } else {
    auditRecords.unshift(record);
  }
  flushAudit();
}

export function listAuditRecords(): AuditRecord[] {
  ensureLoaded();
  return auditRecords;
}

export function getAuditRecord(requestId: string): AuditRecord | null {
  ensureLoaded();
  return auditRecords.find((r) => r.request_id === requestId) ?? null;
}

export function saveReviewItem(item: ReviewItem): void {
  ensureLoaded();
  const idx = reviewItems.findIndex((r) => r.id === item.id);
  if (idx >= 0) {
    reviewItems[idx] = item;
  } else {
    reviewItems.unshift(item);
  }
  flushReviews();
}

export function listReviewItems(): ReviewItem[] {
  ensureLoaded();
  return reviewItems;
}

export function getReviewItem(id: string): ReviewItem | null {
  ensureLoaded();
  return reviewItems.find((r) => r.id === id) ?? null;
}

export function saveLatestEvaluation(report: EvaluationReport): void {
  latestEvaluation = report;
}

export function getLatestEvaluation(): EvaluationReport | null {
  return latestEvaluation;
}
