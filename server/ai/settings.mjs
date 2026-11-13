import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { mkdir, rename, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';

export const DEFAULT_AI_BASE_URL = 'https://opencode.ai/inference/go/openai/v1';
export const DEFAULT_AI_MODEL = 'deepseek-v4.1-flash';

export class AiSettingsError extends Error {}

export function validateApiKey(apiKey) {
  if (typeof apiKey !== 'string' || apiKey.length < 8 || apiKey.length > 2048 || !/^[A-Za-z0-9._~+\/-]+=*$/.test(apiKey)) {
    throw new AiSettingsError('API key must contain 8 to 2048 characters without whitespace.');
  }
  return apiKey;
}

export function readSavedAiKey(file) {
  let text;
  try {
    text = readFileSync(file, 'utf8');
  } catch (error) {
    if (error.code === 'ENOENT') return null;
    throw new AiSettingsError('Could not read saved AI settings. Check the data directory permissions.');
  }
  try {
    return validateApiKey(JSON.parse(text).apiKey);
  } catch {
    throw new AiSettingsError('Saved AI settings are invalid.');
  }
}

export function createAiSettingsWriter(config) {
  let pending = Promise.resolve();
  return (value) => {
    const apiKey = validateApiKey(value);
    const save = async () => {
      await mkdir(dirname(config.aiSettingsFile), { recursive: true });
      const temporaryFile = `${config.aiSettingsFile}.${randomUUID()}.tmp`;
      await writeFile(temporaryFile, JSON.stringify({ apiKey }), { encoding: 'utf8', mode: 0o600, flag: 'wx' });
      await rename(temporaryFile, config.aiSettingsFile);
      config.secrets.push(apiKey);
      config.ai = {
        ...config.ai,
        enabled: true,
        available: true,
        apiKey,
        baseUrl: DEFAULT_AI_BASE_URL,
        model: DEFAULT_AI_MODEL,
        jsonMode: false
      };
    };
    const result = pending.then(save);
    pending = result.catch(() => {});
    return result;
  };
}
