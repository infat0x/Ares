import { appendFile, mkdir } from 'node:fs/promises';
import { dirname } from 'node:path';
import { redactSecrets } from './util/secrets.mjs';

const LEVELS = { debug: 10, info: 20, warn: 30, error: 40 };

export class Logger {
  constructor({ level = 'info', file = null, secrets = [], bufferSize = 500 } = {}) {
    this.level = LEVELS[level] ?? LEVELS.info;
    this.file = file;
    this.secrets = secrets;
    this.buffer = [];
    this.bufferSize = bufferSize;
    this.fileReady = false;
  }

  debug(message, meta) { this.#write('debug', message, meta); }
  info(message, meta) { this.#write('info', message, meta); }
  warn(message, meta) { this.#write('warn', message, meta); }
  error(message, meta) { this.#write('error', message, meta); }

  #write(level, message, meta) {
    if ((LEVELS[level] ?? 20) < this.level) return;
    const entry = {
      at: new Date().toISOString(),
      level,
      message: redactSecrets(sanitizeMeta(message), this.secrets),
      ...(meta === undefined ? {} : { meta: sanitizeMeta(meta) })
    };
    const line = redactSecrets(JSON.stringify(entry), this.secrets);
    this.buffer.push(JSON.parse(line));
    if (this.buffer.length > this.bufferSize) this.buffer.shift();
    const stream = level === 'error' || level === 'warn' ? process.stderr : process.stdout;
    stream.write(`${line}\n`);
    if (this.file) this.#append(line);
  }

  async #append(line) {
    try {
      if (!this.fileReady) {
        await mkdir(dirname(this.file), { recursive: true });
        this.fileReady = true;
      }
      await appendFile(this.file, `${line}\n`, 'utf8');
    } catch {
      /* logging must never break the app */
    }
  }
}

function sanitizeMeta(value, depth = 0) {
  if (depth > 6) return '[depth-limit]';
  if (value instanceof Error) {
    return { name: value.name, message: value.message };
  }
  if (typeof value === 'string') {
    return value.length > 4000 ? `${value.slice(0, 4000)}…` : value;
  }
  if (Array.isArray(value)) {
    return value.slice(0, 50).map((item) => sanitizeMeta(item, depth + 1));
  }
  if (value && typeof value === 'object') {
    const result = {};
    for (const [key, item] of Object.entries(value)) {
      if (key === 'apiKey' || key === 'authorization' || key === 'password') {
        result[key] = '[redacted]';
      } else {
        result[key] = sanitizeMeta(item, depth + 1);
      }
    }
    return result;
  }
  return value;
}
