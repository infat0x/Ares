import { existsSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { DEFAULT_AI_BASE_URL, DEFAULT_AI_MODEL, readSavedAiKey } from './ai/settings.mjs';

export const APP_VERSION = '1.0.0';
export const APP_NAME = 'Ares';

const LOOPBACK_HOSTS = new Set(['127.0.0.1', '::1', 'localhost']);

export class ConfigError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ConfigError';
  }
}

/**
 * Minimal .env parser. Supports KEY=VALUE, # comments, optional quotes and
 * "export " prefixes. Values are not interpolated.
 */
export function parseEnvFile(text) {
  const result = {};
  for (const rawLine of String(text).split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const match = /^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/.exec(line);
    if (!match) continue;
    let value = match[2].trim();
    if (
      (value.startsWith('"') && value.endsWith('"') && value.length >= 2) ||
      (value.startsWith("'") && value.endsWith("'") && value.length >= 2)
    ) {
      value = value.slice(1, -1);
    }
    result[match[1]] = value;
  }
  return result;
}

function applyEnvFile(env, filePath) {
  if (!existsSync(filePath)) return false;
  let parsed;
  try {
    parsed = parseEnvFile(readFileSync(filePath, 'utf8'));
  } catch {
    return false;
  }
  for (const [key, value] of Object.entries(parsed)) {
    if (!(key in env) || env[key] === '') {
      env[key] = value;
    }
  }
  return true;
}

function toInt(value, fallback, { min, max, name }) {
  if (value === undefined || value === null || value === '') return fallback;
  const parsed = Number.parseInt(String(value), 10);
  if (!Number.isFinite(parsed) || parsed < min || parsed > max) {
    throw new ConfigError(`${name} must be an integer between ${min} and ${max}`);
  }
  return parsed;
}

function toBool(value, fallback = false) {
  if (value === undefined || value === null || value === '') return fallback;
  const normalized = String(value).trim().toLowerCase();
  return normalized === '1' || normalized === 'true' || normalized === 'yes' || normalized === 'on';
}

export function loadConfig({ env = process.env, cwd = process.cwd(), loadEnvFile = true } = {}) {
  if (loadEnvFile) {
    applyEnvFile(env, join(cwd, '.env'));
  }

  const host = (env.ARES_HOST || '127.0.0.1').trim();
  if (!LOOPBACK_HOSTS.has(host)) {
    throw new ConfigError(
      `ARES_HOST must be a loopback address (127.0.0.1, ::1 or localhost). Refusing "${host}".`
    );
  }

  const port = toInt(env.ARES_PORT, 4517, { min: 1, max: 65535, name: 'ARES_PORT' });
  const collectorTimeoutMs = toInt(env.ARES_COLLECTOR_TIMEOUT_MS, 25000, {
    min: 500,
    max: 300000,
    name: 'ARES_COLLECTOR_TIMEOUT_MS'
  });
  const aiTimeoutMs = toInt(env.ARES_AI_TIMEOUT_MS, 60000, {
    min: 1000,
    max: 300000,
    name: 'ARES_AI_TIMEOUT_MS'
  });

  const dataDir = resolve(cwd, env.ARES_DATA_DIR || 'data');
  const aiSettingsFile = join(dataDir, 'ai-settings.json');
  const savedAiKey = readSavedAiKey(aiSettingsFile);
  const aiKey = savedAiKey ?? (env.ARES_AI_API_KEY || '').trim();
  const aiEnabledFlag = savedAiKey !== null || toBool(env.ARES_AI_ENABLED, false);
  const aiBaseUrl = (savedAiKey !== null ? DEFAULT_AI_BASE_URL : env.ARES_AI_BASE_URL || DEFAULT_AI_BASE_URL).trim().replace(/\/+$/, '');
  let parsedBase;
  try {
    parsedBase = new URL(aiBaseUrl);
  } catch {
    throw new ConfigError('ARES_AI_BASE_URL must be a valid absolute URL');
  }
  if (parsedBase.protocol !== 'https:' && !['127.0.0.1', 'localhost'].includes(parsedBase.hostname)) {
    throw new ConfigError('ARES_AI_BASE_URL must use HTTPS (plain HTTP is allowed only for loopback test providers)');
  }

  const ai = {
    enabled: aiEnabledFlag,
    apiKey: aiKey,
    available: aiEnabledFlag && aiKey.length > 0,
    baseUrl: aiBaseUrl,
    model: (savedAiKey !== null ? DEFAULT_AI_MODEL : env.ARES_AI_MODEL || DEFAULT_AI_MODEL).trim(),
    timeoutMs: aiTimeoutMs,
    jsonMode: savedAiKey === null && toBool(env.ARES_AI_JSON_MODE, false),
    maxOutputTokens: toInt(env.ARES_AI_MAX_TOKENS, 1400, { min: 200, max: 8000, name: 'ARES_AI_MAX_TOKENS' })
  };

  const debugSlowCollector = (env.ARES_DEBUG_SLOW_COLLECTOR || '').trim().toLowerCase() || null;

  return {
    appName: APP_NAME,
    version: APP_VERSION,
    host,
    port,
    cwd,
    publicDir: join(cwd, 'public'),
    collectorScriptDir: join(cwd, 'server', 'collectors', 'ps'),
    advisoryFile: join(cwd, 'server', 'advisories.json'),
    dataDir,
    aiSettingsFile,
    snapshotDir: join(dataDir, 'assessments'),
    logFile: join(dataDir, 'ares.log'),
    collectorTimeoutMs,
    maxAssessmentRetention: 30,
    maxConcurrentAssessments: 3,
    debugSlowCollector,
    ai,
    secrets: [aiKey].filter((value) => value.length >= 8),
    // Keep this out of the browser: only booleans/derived values cross the API.
    exposeAiAvailability: true
  };
}

export function aiStatusForClient(config) {
  return {
    enabled: Boolean(config.ai.enabled),
    available: Boolean(config.ai.available),
    model: config.ai.model,
    provider: new URL(config.ai.baseUrl).hostname === 'opencode.ai' ? 'OpenCode' : 'Custom'
  };
}
