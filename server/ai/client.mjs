import { randomUUID } from 'node:crypto';
import { extractJsonObject } from './schema.mjs';

export class AiProviderError extends Error {
  constructor(message, { kind = 'provider', status = null } = {}) {
    super(message);
    this.name = 'AiProviderError';
    this.kind = kind;
    this.status = status;
  }
}

/**
 * Call an OpenAI-compatible chat completion endpoint and return parsed JSON.
 * The API key is only ever placed in the Authorization header.
 */
export async function requestJsonCompletion({
  aiConfig,
  systemPrompt,
  userPayload,
  fetchImpl = globalThis.fetch,
  logger = null
}) {
  if (!aiConfig?.available || !aiConfig.apiKey) {
    throw new AiProviderError('AI review is not configured', { kind: 'disabled' });
  }
  if (typeof fetchImpl !== 'function') {
    throw new AiProviderError('No fetch implementation available', { kind: 'internal' });
  }

  const url = `${aiConfig.baseUrl}/chat/completions`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), aiConfig.timeoutMs);
  const startedAt = Date.now();

  const body = {
    model: aiConfig.model,
    temperature: 0.1,
    max_tokens: aiConfig.maxOutputTokens,
    messages: [
      { role: 'system', content: systemPrompt },
      { role: 'user', content: JSON.stringify(userPayload) }
    ]
  };
  if (aiConfig.jsonMode) body.response_format = { type: 'json_object' };
  const headers = {
    'content-type': 'application/json',
    authorization: `Bearer ${aiConfig.apiKey}`
  };
  if (new URL(aiConfig.baseUrl).hostname === 'opencode.ai') {
    headers['user-agent'] = 'ares/1.0.0';
    headers['x-opencode-session'] = randomUUID();
  }

  try {
    const response = await fetchImpl(url, {
      method: 'POST',
      headers,
      body: JSON.stringify(body),
      signal: controller.signal,
      redirect: 'error'
    });

    if (!response.ok) {
      let detail = '';
      try {
        detail = (await response.text()).slice(0, 240);
      } catch {
        detail = '';
      }
      logger?.warn('ai provider rejected request', { status: response.status, detail });
      throw new AiProviderError(`AI provider returned HTTP ${response.status}`, {
        kind: 'provider',
        status: response.status
      });
    }

    const rawText = await response.text();
    if (rawText.length > 2_000_000) {
      throw new AiProviderError('AI provider response was too large', { kind: 'provider' });
    }
    let data;
    try {
      data = JSON.parse(rawText);
    } catch {
      throw new AiProviderError('AI provider returned a non-JSON envelope', { kind: 'provider' });
    }
    const content = data?.choices?.[0]?.message?.content;
    if (typeof content !== 'string' || !content.trim()) {
      throw new AiProviderError('AI provider returned an empty response', { kind: 'provider' });
    }
    const parsed = extractJsonObject(content);
    if (!parsed) {
      throw new AiProviderError('AI provider response was not valid JSON', { kind: 'schema' });
    }
    logger?.info('ai provider call completed', {
      model: data?.model ?? aiConfig.model,
      durationMs: Date.now() - startedAt,
      promptTokens: data?.usage?.prompt_tokens ?? null,
      completionTokens: data?.usage?.completion_tokens ?? null
    });
    return {
      parsed,
      model: data?.model ?? aiConfig.model,
      usage: data?.usage ?? null,
      durationMs: Date.now() - startedAt
    };
  } catch (error) {
    if (error instanceof AiProviderError) throw error;
    if (error?.name === 'AbortError') {
      throw new AiProviderError(`AI provider timed out after ${Math.round(aiConfig.timeoutMs / 1000)}s`, { kind: 'timeout' });
    }
    throw new AiProviderError(`AI provider request failed: ${String(error?.message ?? error).slice(0, 200)}`, {
      kind: 'network'
    });
  } finally {
    clearTimeout(timer);
  }
}
