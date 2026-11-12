import assert from 'node:assert/strict';
import { buildNormalizedView } from '../pipeline/normalize.ts';
import { verifyVerhoeff, verifyGstinChecksum } from '../detection/indiaRecognizers.ts';
import { processGatewayRequest } from '../pipeline/gatewayService.ts';
import { invokeExternalProvider } from '../providers/llmProvider.ts';
import { validateAndReinsertLocally } from '../pipeline/reinsert.ts';
import { createRequestVault, issueRequestScopedToken } from '../vault/tokenVault.ts';
import { runFullEvaluation } from '../evaluation/evaluator.ts';
import { setPersistenceEnabled, listAuditRecords } from '../store/localStore.ts';

async function run() {
  setPersistenceEnabled(false);
  let passed = 0;
  const test = async (name: string, fn: () => void | Promise<void>) => {
    await fn();
    passed++;
    console.log(`PASS: ${name}`);
  };

  await test('Verhoeff Aadhaar & GSTIN mod-36 checksum validators', () => {
    assert.equal(verifyVerhoeff('234567890124'), true);
    assert.equal(verifyVerhoeff('234567890129'), false);
    assert.equal(verifyGstinChecksum('27AAPFU0939F1ZV'), true);
    assert.equal(verifyGstinChecksum('27AAPFU0939F1Z0'), false);
  });

  await test('Non-destructive normalization maps homoglyph + zero-width PAN back to exact original offsets', async () => {
    const raw = 'Applicant: Rohit Gupta | PAN: \u0410BC\u200BDE1234F';
    const view = buildNormalizedView(raw);
    assert.ok(view.normalized.includes('ABCDE1234F'));
    const res = await processGatewayRequest({
      text: raw,
      purpose: 'kyc_verification',
      domain: 'kyc',
      task: 'extract',
      provider: 'mock',
    });
    assert.equal(res.status, 'completed');
    assert.equal(res.outbound_validation.passed, true);
    assert.ok(!res.exact_outbound_body.includes('DE1234F'));
    assert.ok(res.restored_response?.includes('\u0410BC\u200BDE1234F'));
  });

  await test('Mandatory 5 Indian identifiers tokenized consistently and restored locally', async () => {
    const raw = [
      'Applicant Name: Aarav Kulkarni',
      'Aadhaar: 2345 6789 0124 (repeat: 234567890124)',
      'PAN: ABCDE1234F',
      'GSTIN: 27AAPFU0939F1ZV',
      'Voter ID: KRN1234567',
      'Passport: K1234567',
    ].join('\n');
    const res = await processGatewayRequest({
      text: raw,
      purpose: 'kyc_verification',
      domain: 'kyc',
      task: 'summarize',
      provider: 'mock',
    });
    assert.equal(res.status, 'completed');
    assert.equal(res.provider_called, true);
    const aadhaarTokens = res.findings
      .filter((f) => f.entity_type === 'AADHAAR')
      .map((f) => f.token);
    assert.equal(aadhaarTokens.length, 2);
    assert.equal(aadhaarTokens[0], aadhaarTokens[1]); // Consistent request-scoped token
    for (const secret of ['Aarav Kulkarni', '2345 6789 0124', '234567890124', 'ABCDE1234F', '27AAPFU0939F1ZV', 'KRN1234567', 'K1234567']) {
      assert.equal(res.exact_outbound_body.includes(secret), false, `Leaked ${secret}`);
    }
    assert.ok(res.restored_response?.includes('Aarav Kulkarni'));
  });

  await test('Fail-closed: simulated scanner outage blocks provider call', async () => {
    const res = await processGatewayRequest({
      text: 'Name: Priya Nair, PAN: ABCDE1234F',
      purpose: 'kyc',
      domain: 'kyc',
      task: 'summarize',
      provider: 'mock',
      simulate_scanner_outage: true,
    });
    assert.equal(res.status, 'blocked');
    assert.equal(res.outbound_validation.status, 'BLOCK');
    assert.equal(res.provider_called, false);
    assert.equal(res.raw_provider_response, null);
  });

  await test('Security boundary: provider adapter rejects unsealed objects', async () => {
    await assert.rejects(async () => {
      await invokeExternalProvider({ sanitized_text: 'test' } as never, 'summarize');
    }, /SECURITY_BOUNDARY_VIOLATION/);
  });

  await test('Reinsertion: reordered restored, dropped absent, fabricated literal, cross-person blocked', () => {
    const reqId = 'unit_rein_1';
    const vault = createRequestVault(reqId);
    const p1 = issueRequestScopedToken(vault, 'PERSON', 'Vikram Mehta', 'person_1');
    const pan1 = issueRequestScopedToken(vault, 'PAN', 'BGHPM4321K', 'person_1');
    const p2 = issueRequestScopedToken(vault, 'PERSON', 'Ananya Mehta', 'person_2');
    const pan2 = issueRequestScopedToken(vault, 'PAN', 'CFHPA8765M', 'person_2');

    // Reordered + fabricated
    const r1 = validateAndReinsertLocally({
      requestId: reqId,
      rawProviderResponse: `Check ${pan1} then ${p1} and unknown <PERSON_99>.`,
      domain: 'kyc',
    });
    assert.equal(r1.integrity.reordered_detected, true);
    assert.ok(r1.restoredResponse.includes('Vikram Mehta'));
    assert.ok(r1.restoredResponse.includes('BGHPM4321K'));
    assert.ok(r1.restoredResponse.includes('<PERSON_99>'));
    assert.equal(r1.integrity.missing_tokens.includes(p2), true);

    // Cross-person swap
    const r2 = validateAndReinsertLocally({
      requestId: reqId,
      rawProviderResponse: `${p1} owns ${pan2}. ${p2} owns ${pan1}.`,
      domain: 'kyc',
    });
    assert.equal(r2.integrity.cross_person_warnings.length, 2);
    assert.equal(r2.restoredResponse.includes('CFHPA8765M'), false);
    assert.equal(r2.restoredResponse.includes('BGHPM4321K'), false);
  });

  await test('Audit logs contain zero raw PII and zero token mappings', async () => {
    const audits = listAuditRecords();
    const serialized = JSON.stringify(audits);
    for (const secret of ['Aarav Kulkarni', '2345 6789 0124', 'ABCDE1234F', '27AAPFU0939F1ZV', 'KRN1234567']) {
      assert.equal(serialized.includes(secret), false, `Audit log leaked ${secret}`);
    }
  });

  await test('UPI IDs and Transaction Reference codes receive typed placeholders and restore safely', async () => {
    const raw = [
      'Customer: Priya Nair',
      'UPI ID: priya.nair@kotak (backup VPA: shop99@custompsp)',
      'UTR: HDFCR5202611109988',
      'Transaction Reference: TXN-2026-998120',
      'RRN: 431298765432',
    ].join('\n');
    const res = await processGatewayRequest({
      text: raw,
      purpose: 'ticket_triage',
      domain: 'support',
      task: 'summarize',
      provider: 'mock',
    });
    assert.equal(res.status, 'completed');
    assert.equal(res.provider_called, true);
    const upiTokens = res.findings.filter((f) => f.entity_type === 'UPI_ID').map((f) => f.token);
    const txnTokens = res.findings
      .filter((f) => f.entity_type === 'TRANSACTION_REFERENCE')
      .map((f) => f.token);
    assert.equal(upiTokens.length, 2);
    assert.equal(upiTokens[0], '<UPI_ID_1>');
    assert.equal(upiTokens[1], '<UPI_ID_2>');
    assert.equal(txnTokens.length, 3);
    assert.equal(txnTokens[0], '<TRANSACTION_REFERENCE_1>');
    assert.equal(txnTokens[1], '<TRANSACTION_REFERENCE_2>');
    assert.equal(txnTokens[2], '<TRANSACTION_REFERENCE_3>');
    for (const secret of [
      'priya.nair@kotak',
      'shop99@custompsp',
      'HDFCR5202611109988',
      'TXN-2026-998120',
      '431298765432',
    ]) {
      assert.equal(res.exact_outbound_body.includes(secret), false, `Leaked ${secret}`);
    }
    assert.ok(res.restored_response?.includes('priya.nair@kotak'));
    assert.ok(res.restored_response?.includes('TXN-2026-998120'));
  });

  await test('Dates of any format are hidden with placeholders and restored locally', async () => {
    const raw = [
      'DOB: 14 Nov 1994',
      'Joining: 1st January 2025',
      'Review on November 10th, 2026',
      'ISO: 2026-11-10 and Slash ISO: 2026/11/10',
      'Dot: 10.11.2026 and Short: 10/11/26',
      'Month-Year: Nov 2026 and Numeric Month-Year: 08/1994',
    ].join('\n');
    const res = await processGatewayRequest({
      text: raw,
      purpose: 'hr_onboarding',
      domain: 'hr',
      task: 'summarize',
      provider: 'mock',
    });
    assert.equal(res.status, 'completed');
    assert.equal(res.provider_called, true);
    const dateFindings = res.findings.filter(
      (f) => f.entity_type === 'DATE_OF_BIRTH' || f.entity_type === 'CONTEXTUAL_DATE'
    );
    assert.equal(dateFindings.length, 9);
    for (const d of [
      '14 Nov 1994',
      '1st January 2025',
      'November 10th, 2026',
      '2026-11-10',
      '2026/11/10',
      '10.11.2026',
      '10/11/26',
      'Nov 2026',
      '08/1994',
    ]) {
      assert.equal(res.exact_outbound_body.includes(d), false, `Leaked date ${d}`);
    }
    assert.ok(res.restored_response?.includes('14 Nov 1994'));
  });

  await test('Account numbers of any length/order are hidden with placeholders and restored locally', async () => {
    const raw = [
      'A/C: 4412',
      'Order Account # 884210',
      'Account Number: 0041 9928 1102',
      'Bank Account is 1234-5678-9012-3456-7890',
      'Acct No: SAV-00981234',
    ].join('\n');
    const res = await processGatewayRequest({
      text: raw,
      purpose: 'loan_servicing',
      domain: 'loan',
      task: 'summarize',
      provider: 'mock',
    });
    assert.equal(res.status, 'completed');
    assert.equal(res.provider_called, true);
    const acctTokens = res.findings
      .filter((f) => f.entity_type === 'BANK_ACCOUNT')
      .map((f) => f.token);
    assert.equal(acctTokens.length, 5);
    assert.deepEqual(acctTokens, [
      '<BANK_ACCOUNT_1>',
      '<BANK_ACCOUNT_2>',
      '<BANK_ACCOUNT_3>',
      '<BANK_ACCOUNT_4>',
      '<BANK_ACCOUNT_5>',
    ]);
    for (const secret of [
      '4412',
      '884210',
      '0041 9928 1102',
      '1234-5678-9012-3456-7890',
      'SAV-00981234',
    ]) {
      assert.equal(res.exact_outbound_body.includes(secret), false, `Leaked account ${secret}`);
    }
    assert.ok(res.restored_response?.includes('1234-5678-9012-3456-7890'));
  });

  await test('Full 54-document synthetic evaluation runs with 0 outbound leakage', async () => {
    const report = await runFullEvaluation();
    console.log('Evaluation summary:', JSON.stringify(report.overall));
    if (report.sample_failures.length > 0) {
      console.log('Sample failures:', JSON.stringify(report.sample_failures));
    }
    assert.equal(report.dataset_size, 54);
    assert.equal(report.overall.outbound_leakage_count, 0);
    assert.ok(report.overall.precision >= 0.85, `Precision too low: ${report.overall.precision}`);
    assert.ok(report.overall.recall >= 0.85, `Recall too low: ${report.overall.recall}`);
    assert.ok(report.security_suite.every((s) => s.passed));
  });

  console.log(`\nAll ${passed} tests passed!`);
}

run().catch((err) => {
  console.error(err);
  process.exit(1);
});
