import 'dotenv/config';
import express from 'express';
import path from 'node:path';
import { createServer as createViteServer } from 'vite';
import {
  analyzeLocallyOnly,
  decideReviewItem,
  processGatewayRequest,
} from './src/server/pipeline/gatewayService.ts';
import {
  getAuditRecord,
  getLatestEvaluation,
  listAuditRecords,
  listReviewItems,
  saveLatestEvaluation,
} from './src/server/store/localStore.ts';
import { runFullEvaluation } from './src/server/evaluation/evaluator.ts';
import { SYNTHETIC_DATASET } from './src/server/evaluation/syntheticDataset.ts';

async function startServer() {
  const app = express();
  app.use(express.json({ limit: '1mb' }));

  // Health endpoint — strictly no secrets or sensitive configuration
  app.get('/health', (_req, res) => {
    res.json({
      status: 'ok',
      service: 'minearena-privacy-gateway',
      fail_closed: true,
    });
  });

  // Curated synthetic presets for quick demonstration
  app.get('/api/v1/presets', (_req, res) => {
    const pickIds = [
      'syn-kyc-01',
      'syn-kyc-05',
      'syn-loan-01',
      'syn-hlth-01',
      'syn-cm-01',
      'syn-cm-03',
      'syn-ent-04',
      'syn-adv-01',
      'syn-adv-02',
      'syn-adv-03',
      'syn-adv-04',
      'syn-neg-01',
    ];
    const presets = pickIds
      .map((id) => SYNTHETIC_DATASET.find((d) => d.id === id))
      .filter(Boolean);
    res.json({ presets, total_dataset_size: SYNTHETIC_DATASET.length });
  });

  // Local-only analysis (never invokes external LLM)
  app.post('/api/v1/analyze', async (req, res) => {
    try {
      const result = await analyzeLocallyOnly(req.body);
      res.json(result);
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Local analysis failed';
      res.status(400).json({ error: msg });
    }
  });

  // Full local-first pipeline + firewall + provider + local reinsertion
  app.post('/api/v1/gateway/process', async (req, res) => {
    try {
      const result = await processGatewayRequest(req.body);
      res.json(result);
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Gateway processing failed';
      res.status(400).json({ error: msg });
    }
  });

  // Audit records (strictly sanitized — zero raw PII, zero token mappings)
  app.get('/api/v1/requests', (_req, res) => {
    res.json({ requests: listAuditRecords() });
  });

  app.get('/api/v1/requests/:requestId', (req, res) => {
    const rec = getAuditRecord(req.params.requestId);
    if (!rec) {
      res.status(404).json({ error: 'Request audit record not found' });
      return;
    }
    res.json(rec);
  });

  // Human review queue
  app.get('/api/v1/review', (_req, res) => {
    res.json({ items: listReviewItems() });
  });

  app.post('/api/v1/review/:itemId/decision', async (req, res) => {
    try {
      const { decision, reviewer, reason, overrideAction } = req.body;
      if (decision !== 'approved' && decision !== 'rejected') {
        res.status(400).json({ error: 'Decision must be approved or rejected' });
        return;
      }
      const outcome = await decideReviewItem({
        itemId: req.params.itemId,
        decision,
        reviewer: reviewer || 'compliance-reviewer',
        reason: reason || 'Reviewed via MINEARENA console',
        overrideAction,
      });
      res.json(outcome);
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to record review decision';
      res.status(400).json({ error: msg });
    }
  });

  // Evaluation & metrics
  app.get('/api/v1/metrics', async (_req, res) => {
    let report = getLatestEvaluation();
    if (!report) {
      report = await runFullEvaluation();
      saveLatestEvaluation(report);
    }
    res.json(report);
  });

  app.post('/api/v1/evaluate', async (_req, res) => {
    try {
      const report = await runFullEvaluation();
      saveLatestEvaluation(report);
      res.json(report);
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Evaluation failed';
      res.status(500).json({ error: msg });
    }
  });

  // Mount Vite middleware in development or serve built dist in production
  const isProd = process.env.NODE_ENV === 'production';
  if (!isProd) {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.resolve(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  const port = Number(process.env.PORT ?? 3000);
  app.listen(port, '0.0.0.0', () => {
    console.log(`MINEARENA 2.0 gateway listening on http://0.0.0.0:${port}`);
  });
}

startServer();
