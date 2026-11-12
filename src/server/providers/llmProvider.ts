import { GoogleGenAI } from '@google/genai';
import { SimulationMode, TaskType } from '../types.ts';
import {
  ValidatedSanitizedPayload,
  assertValidatedSanitizedPayload,
} from '../pipeline/sanitizeAndFirewall.ts';

export interface ProviderCallResult {
  provider: string;
  model: string;
  responseText: string;
  usedFallbackMock: boolean;
  providerNote?: string;
}

function extractPlaceholders(text: string): string[] {
  return text.match(/<[A-Z0-9_]+_\d+>/g) ?? [];
}

function runMockProvider(
  payload: ValidatedSanitizedPayload,
  task: TaskType,
  simulationMode: SimulationMode = 'normal'
): ProviderCallResult {
  const sanitized = payload.sanitized_text;
  const tokens = Array.from(new Set(extractPlaceholders(sanitized)));
  const personTokens = tokens.filter((t) => t.startsWith('<PERSON_'));
  const nonPersonTokens = tokens.filter((t) => !t.startsWith('<PERSON_'));

  if (simulationMode === 'reorder_tokens' && tokens.length >= 2) {
    const reversed = [...tokens].reverse();
    return {
      provider: 'mock-offline',
      model: 'minearena-mock-v2.1',
      responseText: `Summary (reordered references): Verified record linking ${reversed.join(', ')} for ${task} review. All contextual clauses preserved.`,
      usedFallbackMock: false,
    };
  }

  if (simulationMode === 'drop_token' && tokens.length >= 2) {
    const kept = tokens.slice(0, tokens.length - 1);
    return {
      provider: 'mock-offline',
      model: 'minearena-mock-v2.1',
      responseText: `Partial summary: Processed identifiers ${kept.join(', ')}. Additional secondary fields were omitted by the model.`,
      usedFallbackMock: false,
    };
  }

  if (simulationMode === 'fabricate_token') {
    return {
      provider: 'mock-offline',
      model: 'minearena-mock-v2.1',
      responseText: `Summary: Reviewed ${tokens.join(', ') || 'document'}. Cross-check also referenced <PERSON_99> and <AADHAAR_99> from unverified context.`,
      usedFallbackMock: false,
    };
  }

  if (
    simulationMode === 'cross_person_swap' &&
    personTokens.length >= 2 &&
    nonPersonTokens.length >= 2
  ) {
    // Deliberately pair PERSON_1 with the second person's identifier and vice versa
    const idForP2 = nonPersonTokens[0];
    const idForP1 = nonPersonTokens[nonPersonTokens.length - 1];
    return {
      provider: 'mock-offline',
      model: 'minearena-mock-v2.1',
      responseText: `Extracted Associations:\n- Primary Subject ${personTokens[0]} is linked to identifier ${idForP1}.\n- Secondary Subject ${personTokens[1]} is linked to identifier ${idForP2}.`,
      usedFallbackMock: false,
    };
  }

  // Normal utility-preserving response operating ONLY on sanitized placeholders
  const lines = sanitized
    .split(/\n+/)
    .map((l) => l.trim())
    .filter(Boolean);

  let responseText = '';
  if (task === 'extract') {
    responseText = [
      `Structured Extraction Summary:`,
      `- Entities referenced: ${tokens.length > 0 ? tokens.join(', ') : 'None (no protected tokens required)'}`,
      `- Key lines preserved: ${lines.slice(0, 3).join(' | ')}`,
    ].join('\n');
  } else if (task === 'classify') {
    responseText = `Classification Result: Document processed for ${tokens.length} protected placeholder(s) (${tokens.join(', ') || 'none'}). Ready for downstream workflow.`;
  } else if (task === 'qa') {
    responseText = `Q&A Response: Based on the sanitized submission, the relevant record references ${tokens.join(', ') || 'no personal identifiers'} and satisfies standard context verification.`;
  } else {
    responseText = `Executive Summary: Processed submission containing ${lines.length} clause(s). Key subjects and identifiers: ${tokens.join(', ') || 'No sensitive identifiers present'}. Context summary: ${lines.slice(0, 2).join(' ')}`;
  }

  return {
    provider: 'mock-offline',
    model: 'minearena-mock-v2.1',
    responseText,
    usedFallbackMock: false,
  };
}

/**
 * External LLM Adapter.
 * Strictly requires a ValidatedSanitizedPayload sealed by the outbound firewall.
 */
export async function invokeExternalProvider(
  payload: ValidatedSanitizedPayload,
  task: TaskType,
  simulationMode: SimulationMode = 'normal'
): Promise<ProviderCallResult> {
  // Runtime boundary enforcement: throw immediately if payload is unsealed or tampered
  assertValidatedSanitizedPayload(payload);

  if (payload.provider === 'mock' || simulationMode !== 'normal') {
    return runMockProvider(payload, task, simulationMode);
  }

  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey || apiKey === 'MY_GEMINI_API_KEY') {
    const fallback = runMockProvider(payload, task, 'normal');
    return {
      ...fallback,
      usedFallbackMock: true,
      providerNote:
        'GEMINI_API_KEY is not configured in Secrets; executed safe offline mock provider on the validated sanitized payload.',
    };
  }

  const ai = new GoogleGenAI({
    apiKey,
    httpOptions: {
      headers: {
        'User-Agent': 'aistudio-build',
      },
    },
  });

  const modelName = payload.model || 'gemini-3.8-flash';
  const prompt = `Task: ${task}\n\nSanitized Document:\n${payload.sanitized_text}`;

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 15000);

  try {
    const response = await ai.models.generateContent({
      model: modelName,
      contents: prompt,
      config: {
        systemInstruction: payload.system_prompt,
        abortSignal: controller.signal,
      },
    });
    const text = (response.text ?? '').trim();
    return {
      provider: 'gemini',
      model: modelName,
      responseText: text || 'Provider returned an empty response.',
      usedFallbackMock: false,
    };
  } catch (err) {
    const message = err instanceof Error ? err.message : 'External Gemini call failed';
    const fallback = runMockProvider(payload, task, 'normal');
    return {
      ...fallback,
      usedFallbackMock: true,
      providerNote: `Gemini call unavailable (${message}); fell back to safe offline local provider.`,
    };
  } finally {
    clearTimeout(timeout);
  }
}
