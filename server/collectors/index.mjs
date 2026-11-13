import { spawn } from 'node:child_process';
import { join } from 'node:path';
import { readFile } from 'node:fs/promises';
import { sshArgs } from '../target.mjs';
import { sshPasswordEnvironment } from '../util/ssh.mjs';
import { runCommand } from '../util/exec.mjs';
import { asArray } from '../machine.mjs';

export const RESULT_MARKER = '@@ARES@@';

export class CollectorError extends Error {
  constructor(message, { kind = 'collector', detail = null } = {}) {
    super(message);
    this.name = 'CollectorError';
    this.kind = kind;
    this.detail = detail;
  }
}

function cleanString(value, maxLength = 512) {
  if (value === null || value === undefined) return null;
  const text = String(value).replace(/\0/g, '').trim();
  if (!text) return null;
  return text.length > maxLength ? text.slice(0, maxLength) : text;
}

function cleanInteger(value, { min = 0, max = Number.MAX_SAFE_INTEGER } = {}) {
  const number = Number(value);
  if (!Number.isFinite(number)) return null;
  const rounded = Math.round(number);
  if (rounded < min || rounded > max) return null;
  return rounded;
}

function readableError(message) {
  const text = String(message ?? '').trim();
  if (/access is denied|requires elevation|privileged|privilege|unauthorized|denied/i.test(text)) {
    return `Permission denied: ${text || 'the current user cannot read this data'}`;
  }
  return text || 'Collector failed without a message';
}

export function parseCollectorOutput(stdout, label) {
  const index = stdout.lastIndexOf(RESULT_MARKER);
  if (index === -1) {
    throw new CollectorError(`${label} returned no result payload`, { kind: 'parse' });
  }
  const jsonText = stdout.slice(index + RESULT_MARKER.length).trim();
  let parsed;
  try {
    parsed = JSON.parse(jsonText);
  } catch (error) {
    throw new CollectorError(`${label} returned malformed JSON`, {
      kind: 'parse',
      detail: String(error?.message ?? error)
    });
  }
  if (parsed && typeof parsed === 'object' && parsed.__collectorError) {
    throw new CollectorError(readableError(parsed.__collectorError), { kind: 'collector' });
  }
  return parsed ?? {};
}

export function normalizeHost(raw) {
  const addresses = asArray(raw.addresses)
    .map((item) => ({
      address: cleanString(item?.address, 128),
      family: cleanString(item?.family, 16),
      interface: cleanString(item?.interface, 128),
      prefixLength: cleanInteger(item?.prefixLength, { min: 0, max: 128 }),
      prefixOrigin: cleanString(item?.prefixOrigin, 32)
    }))
    .filter((item) => item.address);

  return {
    platform: cleanString(raw.platform, 20) ?? 'windows',
    hostname: cleanString(raw.hostname, 128),
    distributionId: cleanString(raw.distributionId, 40),
    distributionVersion: cleanString(raw.distributionVersion, 40),
    caption: cleanString(raw.caption, 160),
    productName: cleanString(raw.productName, 160),
    editionId: cleanString(raw.editionId, 80),
    displayVersion: cleanString(raw.displayVersion, 40),
    releaseId: cleanString(raw.releaseId, 40),
    version: cleanString(raw.version, 40),
    buildNumber: cleanString(raw.buildNumber, 20),
    ubr: cleanInteger(raw.ubr, { min: 0, max: 1000000 }),
    build: cleanString(raw.build, 40),
    architecture: cleanString(raw.architecture, 40),
    language: cleanString(raw.language, 40),
    manufacturer: cleanString(raw.manufacturer, 120),
    model: cleanString(raw.model, 120),
    pcSystemType: cleanInteger(raw.pcSystemType, { min: 0, max: 100 }),
    chassisTypes: asArray(raw.chassisTypes)
      .map((value) => cleanInteger(value, { min: 0, max: 1000 }))
      .filter((value) => value !== null),
    totalMemoryGb: Number.isFinite(Number(raw.totalMemoryGb)) ? Number(raw.totalMemoryGb) : null,
    bootTime: cleanString(raw.bootTime, 64),
    collectedAt: cleanString(raw.collectedAt, 64),
    timeZone: cleanString(raw.timeZone, 80),
    addresses
  };
}

export function normalizePorts(raw) {
  const seen = new Set();
  const endpoints = [];
  for (const item of asArray(raw.endpoints)) {
    const protocol = String(item?.protocol ?? '').toLowerCase();
    if (protocol !== 'tcp' && protocol !== 'udp') continue;
    const port = cleanInteger(item?.port, { min: 0, max: 65535 });
    const address = cleanString(item?.address, 128);
    if (port === null || !address) continue;
    const pid = cleanInteger(item?.pid, { min: 0, max: 4294967295 });
    const key = `${protocol}|${address}|${port}|${pid ?? ''}`;
    if (seen.has(key)) continue;
    seen.add(key);
    endpoints.push({
      protocol,
      address,
      port,
      state: cleanString(item?.state, 32) ?? (protocol === 'tcp' ? 'Listen' : 'bound'),
      pid,
      process: cleanString(item?.process, 120),
      service: cleanString(item?.service, 120),
      loopbackOnly: Boolean(item?.loopbackOnly),
      anyAddress: Boolean(item?.anyAddress)
    });
    if (endpoints.length >= 3000) break;
  }
  endpoints.sort((a, b) => a.protocol.localeCompare(b.protocol) || a.port - b.port || a.address.localeCompare(b.address));
  return {
    source: cleanString(raw.source, 80),
    collectedAt: cleanString(raw.collectedAt, 64),
    endpoints,
    counts: {
      tcp: endpoints.filter((item) => item.protocol === 'tcp').length,
      udp: endpoints.filter((item) => item.protocol === 'udp').length
    },
    processLookupAvailable: raw.processLookupAvailable !== false
  };
}

export function normalizeSoftware(raw) {
  const seen = new Set();
  const software = [];
  for (const item of asArray(raw.software)) {
    const name = cleanString(item?.name, 200);
    if (!name) continue;
    const version = cleanString(item?.version, 80);
    const key = `${name.toLowerCase()}|${version ?? ''}`;
    if (seen.has(key)) continue;
    seen.add(key);
    software.push({
      name,
      version,
      sourceName: cleanString(item?.sourceName, 200),
      sourceVersion: cleanString(item?.sourceVersion, 80),
      publisher: cleanString(item?.publisher, 160),
      scope: cleanString(item?.scope, 20) ?? 'machine',
      installDate: cleanString(item?.installDate, 40)
    });
    if (software.length >= 1500) break;
  }
  software.sort((a, b) => a.name.localeCompare(b.name, undefined, { sensitivity: 'base' }));
  return {
    collectedAt: cleanString(raw.collectedAt, 64),
    source: cleanString(raw.source, 160),
    truncated: Boolean(raw.truncated),
    ecosystem: cleanString(raw.ecosystem, 80),
    totalFound: cleanInteger(raw.totalFound, { min: 0, max: 100000 }) ?? software.length,
    software
  };
}

export function normalizeUpdates(raw) {
  const hotfixes = asArray(raw.hotfixes)
    .map((item) => ({
      id: cleanString(item?.id, 40),
      description: cleanString(item?.description, 80),
      installedOn: cleanString(item?.installedOn, 64),
      source: cleanString(item?.source, 40)
    }))
    .filter((item) => item.id);

  return {
    platform: cleanString(raw.platform, 20) ?? 'windows',
    collectedAt: cleanString(raw.collectedAt, 64),
    source: cleanString(raw.source, 160),
    hotfixSource: cleanString(raw.hotfixSource, 80),
    hotfixes,
    hotfixCount: hotfixes.length,
    updateService: {
      name: cleanString(raw.updateService?.name, 40) ?? 'wuauserv',
      status: cleanString(raw.updateService?.status, 40)
    },
    policy: {
      noAutoUpdate: cleanInteger(raw.policy?.noAutoUpdate, { min: 0, max: 10 }),
      auOptions: cleanInteger(raw.policy?.auOptions, { min: 0, max: 10 }),
      wsusServer: cleanString(raw.policy?.wsusServer, 200)
    },
    lastSearchSuccess: cleanString(raw.lastSearchSuccess, 64),
    lastInstallSuccess: cleanString(raw.lastInstallSuccess, 64),
    pendingReboot: Boolean(raw.pendingReboot),
    errors: asArray(raw.errors).map((value) => cleanString(value, 400)).filter(Boolean)
  };
}

const CHECK_STATUSES = new Set(['ok', 'weak', 'info', 'unknown']);

export function normalizeConfig(raw) {
  const checks = [];
  const seen = new Set();
  for (const item of asArray(raw.checks)) {
    const id = cleanString(item?.id, 60);
    if (!id || seen.has(id)) continue;
    seen.add(id);
    const status = String(item?.status ?? '').toLowerCase();
    const observed = item?.observed && typeof item.observed === 'object' ? item.observed : { value: item?.observed ?? null };
    checks.push({
      id,
      category: cleanString(item?.category, 40) ?? 'security',
      status: CHECK_STATUSES.has(status) ? status : 'unknown',
      observed,
      detail: cleanString(item?.detail, 300)
    });
  }
  return {
    collectedAt: cleanString(raw.collectedAt, 64),
    checks
  };
}

export const COLLECTORS = [
  {
    id: 'host',
    label: 'Host & network identity',
    description: 'Hostname, Windows edition/build and local IP addresses',
    script: 'host.ps1',
    parse: normalizeHost,
    timeoutMs: 15000,
    empty: () => null
  },
  {
    id: 'ports',
    label: 'Listening endpoints',
    description: 'Listening TCP ports, bound UDP endpoints and owning processes',
    script: 'ports.ps1',
    parse: normalizePorts,
    timeoutMs: 20000,
    empty: () => ({ endpoints: [], counts: { tcp: 0, udp: 0 } })
  },
  {
    id: 'software',
    label: 'Installed software',
    description: 'Installed application names and versions from the uninstall registry',
    script: 'software.ps1',
    parse: normalizeSoftware,
    timeoutMs: 15000,
    empty: () => ({ software: [], truncated: false, totalFound: 0 })
  },
  {
    id: 'updates',
    label: 'Windows updates',
    description: 'Installed hotfixes and update configuration visible to the current user',
    script: 'updates.ps1',
    parse: normalizeUpdates,
    timeoutMs: 20000,
    empty: () => ({ hotfixes: [], hotfixCount: 0, errors: [] })
  },
  {
    id: 'config',
    label: 'Security configuration',
    description: 'Firewall, Defender, SMB, RDP, UAC and other local security settings',
    script: 'config.ps1',
    parse: normalizeConfig,
    timeoutMs: 25000,
    empty: () => ({ checks: [] })
  }
];

export const COLLECTOR_IDS = COLLECTORS.map((collector) => collector.id);

export async function runCollector(collector, { scriptDir, timeoutMs, logger, target = { mode: 'local' } }) {
  const scriptPath = join(scriptDir, collector.script);
  const effectiveTimeout = Math.min(timeoutMs, collector.timeoutMs ?? timeoutMs);
  const startedAt = Date.now();

  const args = [
    '-NoLogo',
    '-NoProfile',
    '-NonInteractive',
    '-ExecutionPolicy',
    'Bypass',
    '-File',
    scriptPath
  ];

  const linux = target.mode === 'ssh' || process.platform === 'linux';
  const result = await runCommand({
    file: target.mode === 'ssh' ? 'ssh' : linux ? 'python3' : 'powershell.exe',
    args: target.mode === 'ssh' ? sshArgs(target, collector.id) : linux ? ['-', collector.id] : args,
    env: target.mode === 'ssh' ? await sshPasswordEnvironment(target.password) : undefined,
    input: linux ? await readFile(new URL('./linux.py', import.meta.url), 'utf8') : undefined,
    timeoutMs: effectiveTimeout,
    maxOutputBytes: 6 * 1024 * 1024
  });
  if (target.password) result.stderr = result.stderr.split(target.password).join('[redacted]');

  if (result.timedOut) {
    logger?.warn('collector timed out', { collector: collector.id, timeoutMs: effectiveTimeout });
    return {
      status: 'error',
      kind: 'timeout',
      error: `Collector timed out after ${Math.round(effectiveTimeout / 1000)}s. Other collectors continued.`,
      durationMs: Date.now() - startedAt
    };
  }
  if (result.spawnError) {
    return {
      status: 'error',
      kind: 'spawn',
      error: `Could not start ${target.mode === 'ssh' ? 'SSH' : linux ? 'Python 3' : 'PowerShell'}: ${readableError(result.stderr)}`,
      durationMs: Date.now() - startedAt
    };
  }
  if (result.code !== 0 && !result.stdout.includes(RESULT_MARKER)) {
    return {
      status: 'error',
      kind: 'exit',
      error: readableError(result.stderr) || `Collector exited with code ${result.code}`,
      durationMs: Date.now() - startedAt
    };
  }

  try {
    const parsed = parseCollectorOutput(result.stdout, collector.label);
    return {
      status: 'ok',
      data: collector.parse(parsed),
      durationMs: Date.now() - startedAt,
      truncated: result.truncated
    };
  } catch (error) {
    return {
      status: 'error',
      kind: error instanceof CollectorError ? error.kind : 'parse',
      error: readableError(error.message),
      detail: error.detail ?? null,
      durationMs: Date.now() - startedAt
    };
  }
}
