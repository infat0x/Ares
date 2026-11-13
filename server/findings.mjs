import { createHash } from 'node:crypto';
import { deriveConfigFindings, severityRank, SEVERITY_ORDER } from './config-rules.mjs';

export { severityRank, SEVERITY_ORDER };

const VIRTUAL_PRODUCT_NOISE = /\b(x64|x86|amd64|arm64|32-bit|64-bit|win64|windows|for|the|edition|release|version)\b/g;

export function normalizeProductName(name) {
  return String(name ?? '')
    .toLowerCase()
    .replace(/\([^)]*\)/g, ' ')
    .replace(VIRTUAL_PRODUCT_NOISE, ' ')
    .replace(/\b\d+(?:\.\d+)+\b/g, ' ')
    .replace(/[^a-z0-9+# ]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

export function parseVersion(input) {
  const raw = String(input ?? '').trim();
  if (!raw) return { ok: false, numbers: [], suffix: '', raw };
  const match = /(\d+(?:[._-]\d+)+|\d+)([a-z])?/i.exec(raw);
  if (!match) return { ok: false, numbers: [], suffix: '', raw };
  const numbers = match[1].split(/[._-]/).map((part) => Number.parseInt(part, 10));
  if (numbers.some((value) => !Number.isFinite(value))) {
    return { ok: false, numbers: [], suffix: '', raw };
  }
  return {
    ok: true,
    numbers,
    suffix: match[2] ? match[2].toLowerCase() : '',
    raw
  };
}

/**
 * Numeric-aware comparison with a trailing letter suffix (1.0.1f < 1.0.1g).
 * Returns confident=false when either side cannot be parsed reliably.
 */
export function compareVersions(left, right) {
  const a = typeof left === 'string' ? parseVersion(left) : left;
  const b = typeof right === 'string' ? parseVersion(right) : right;
  if (!a?.ok || !b?.ok) return { result: 0, confident: false };
  const length = Math.max(a.numbers.length, b.numbers.length);
  for (let index = 0; index < length; index += 1) {
    const x = a.numbers[index] ?? 0;
    const y = b.numbers[index] ?? 0;
    if (x !== y) return { result: x < y ? -1 : 1, confident: true };
  }
  if (a.suffix === b.suffix) return { result: 0, confident: true };
  if (!a.suffix) return { result: -1, confident: true };
  if (!b.suffix) return { result: 1, confident: true };
  return { result: a.suffix < b.suffix ? -1 : 1, confident: true };
}

export function formatAffectedRange(range = {}) {
  const parts = [];
  if (range.gte) parts.push(`>= ${range.gte}`);
  if (range.lt) parts.push(`< ${range.lt}`);
  return parts.length > 0 ? parts.join(' and ') : 'unknown';
}

function hashId(kind, key) {
  return `f_${createHash('sha256').update(`${kind}|${key}`).digest('hex').slice(0, 12)}`;
}

export function buildFinding(input) {
  const id = hashId(input.kind, input.key);
  return {
    id,
    kind: input.kind,
    category: input.category ?? input.kind,
    severity: SEVERITY_ORDER.includes(input.severity) ? input.severity : 'info',
    title: input.title,
    summary: input.summary,
    source: input.source,
    observed: input.observed,
    affectedRange: input.affectedRange ?? null,
    fix: input.fix,
    confidence: input.confidence === 'confirmed' ? 'confirmed' : 'possible',
    confidenceReasons: input.confidenceReasons ?? [],
    evidenceLabel: input.evidenceLabel ?? null,
    evidenceRefs: [id],
    aiEvidence: input.aiEvidence ?? null,
    ai: null
  };
}

function extractVersionFromName(name) {
  const match = /(?:^|[\s(])(\d+(?:\.\d+)+[a-z]?)(?:[\s)]|$)/i.exec(String(name ?? ''));
  return match ? match[1] : null;
}

function compareRange(version, range = {}) {
  const parsed = parseVersion(version);
  if (!parsed.ok) return { affected: false, confident: false, reason: 'version could not be parsed' };
  let confident = true;
  if (range.gte) {
    const comparison = compareVersions(parsed, range.gte);
    if (!comparison.confident) confident = false;
    else if (comparison.result < 0) return { affected: false, confident: true };
  }
  if (range.lt) {
    const comparison = compareVersions(parsed, range.lt);
    if (!comparison.confident) confident = false;
    else if (comparison.result >= 0) return { affected: false, confident: true };
  }
  return { affected: true, confident };
}

export function matchSoftwareFindings({ software = [], advisories } = {}) {
  const findings = [];
  const entries = advisories?.software ?? [];
  const applications = software.filter((app) => app?.name).map((app, index) => {
    const normalized = normalizeProductName(app.name);
    return { app, index, normalized, compact: normalized.replace(/\s+/g, '') };
  });
  const byName = new Map();
  for (const application of applications) {
    if (!application.normalized) continue;
    const words = application.normalized.split(' ');
    const keys = [`compact:${application.compact}`];
    for (let length = 1; length <= words.length; length += 1) {
      keys.push(`prefix:${words.slice(0, length).join(' ')}`);
    }
    for (const key of keys) {
      if (!byName.has(key)) byName.set(key, []);
      byName.get(key).push(application);
    }
  }
  for (const entry of entries) {
    const aliases = [entry.product, ...(entry.aliases ?? [])]
      .map((alias) => normalizeProductName(alias))
      .filter(Boolean);
    if (aliases.length === 0) continue;
    const candidates = new Set();
    for (const alias of aliases) {
      for (const key of [`prefix:${alias}`, `compact:${alias.replace(/\s+/g, '')}`]) {
        for (const application of byName.get(key) ?? []) candidates.add(application);
      }
    }
    const ordered = [...candidates].sort((a, b) => a.index - b.index);
    for (const { app, normalized, compact } of ordered) {
      const matchedAlias = aliases.find(
        (alias) =>
          normalized === alias ||
          normalized.startsWith(`${alias} `) ||
          compact === alias.replace(/\s+/g, '')
      );
      if (!matchedAlias) continue;

      const confidenceReasons = [];
      let version = app.version ?? null;
      let versionSource = 'uninstall registry DisplayVersion';
      if (!version) {
        version = extractVersionFromName(app.name);
        if (version) {
          versionSource = 'parsed from the application display name';
          confidenceReasons.push('Installed version was not reported separately; it was parsed from the display name.');
        }
      }
      if (normalized !== matchedAlias) {
        confidenceReasons.push('Product matched on a name prefix, not an exact product name.');
      }

      const base = {
        kind: 'software',
        severity: entry.severity,
        title: `${entry.product}: ${entry.title}`,
        summary: entry.notes ?? entry.title,
        source: { name: entry.source?.name ?? 'Advisory', id: entry.cve ?? entry.id, url: entry.source?.url ?? null },
        affectedRange: formatAffectedRange(entry.range),
        fix: entry.fix,
        affectedProduct: entry.product,
        observedVersion: version,
        evidenceLabel: `${app.name}${app.version ? ` ${app.version}` : ''}`,
        aiEvidence: {
          kind: 'software',
          product: entry.product,
          installedApplication: app.name,
          observedVersion: version ?? 'not reported',
          advisoryId: entry.cve ?? entry.id,
          advisoryTitle: entry.title,
          advisorySeverity: entry.severity,
          advisorySource: entry.source?.name ?? null,
          affectedRange: formatAffectedRange(entry.range),
          fixedVersion: entry.fixedVersion ?? null
        }
      };

      if (!version) {
        findings.push(
          buildFinding({
            ...base,
            key: `${entry.id}|${app.name}|noversion`,
            observed: `${app.name} (version not reported)`,
            confidence: 'possible',
            confidenceReasons: ['The installed version is unknown, so the affected range cannot be evaluated.']
          })
        );
        continue;
      }

      const comparison = compareRange(version, entry.range);
      if (!comparison.affected) {
        if (comparison.confident) continue;
        findings.push(
          buildFinding({
            ...base,
            key: `${entry.id}|${app.name}|${version}|unparsed`,
            observed: `${app.name} ${version}`,
            confidence: 'possible',
            confidenceReasons: [
              ...confidenceReasons,
              comparison.reason ?? 'The version string could not be compared reliably with the advisory range.'
            ]
          })
        );
        continue;
      }

      findings.push(
        buildFinding({
          ...base,
          key: `${entry.id}|${app.name}|${version}`,
          observed: `${app.name}${app.version ? ` ${app.version}` : ` ${version}`}`,
          confidence: comparison.confident && confidenceReasons.length === 0 ? 'confirmed' : 'possible',
          confidenceReasons:
            confidenceReasons.length > 0
              ? confidenceReasons
              : comparison.confident
                ? []
                : ['The advisory range could not be evaluated with full confidence.']
        })
      );
    }
  }
  return findings;
}

export function evaluateLifecycle({ host, lifecycle = [], now = new Date() } = {}) {
  if (!host) return [];
  const build = Number.parseInt(String(host.buildNumber ?? host.build ?? ''), 10);
  if (!Number.isFinite(build)) return [];
  const caption = String(host.caption ?? '');
  const identity = `${host.editionId ?? ''} ${caption}`;
  const editionClass = /enterprise|education|iot|ltsc/i.test(identity) ? 'enterprise' : 'consumer';
  const findings = [];

  for (const entry of lifecycle) {
    if (!entry?.captionMatch) continue;
    if (!caption.toLowerCase().includes(String(entry.captionMatch).toLowerCase())) continue;
    if (build < entry.buildMin || build > entry.buildMax) continue;

    let supportEnd = entry.supportEnd;
    if (supportEnd && typeof supportEnd === 'object') {
      supportEnd = supportEnd[editionClass] ?? supportEnd.consumer;
    }
    if (!supportEnd) continue;
    const endDate = new Date(`${supportEnd}T23:59:59Z`);
    if (Number.isNaN(endDate.getTime()) || now <= endDate) continue;

    const exactBuild = build === entry.buildMax;
    const confidence = exactBuild ? 'confirmed' : 'possible';
    const reasons = exactBuild
      ? []
      : ['The build is inside a lifecycle family range but is not the latest servicing baseline; verify the exact update level.'];

    findings.push(
      buildFinding({
        kind: 'os-lifecycle',
        category: 'operating-system',
        key: `${entry.id}|${build}`,
        severity: entry.severity,
        title: `${entry.family} is outside Microsoft support`,
        summary: `${entry.notes ?? 'The operating system no longer receives security updates.'} Support ended ${supportEnd}.`,
        source: {
          name: entry.source?.name ?? 'Microsoft Lifecycle Policy',
          id: entry.id,
          url: entry.source?.url ?? null
        },
        observed: `${caption || entry.family} build ${build}${host.ubr ? `.${host.ubr}` : ''}`,
        affectedRange: `Support ended ${supportEnd}`,
        fix: entry.fix,
        confidence,
        confidenceReasons: reasons,
        evidenceLabel: `${entry.family} build ${build}`,
        aiEvidence: {
          kind: 'os-lifecycle',
          family: entry.family,
          build,
          supportEnd,
          editionClass,
          severity: entry.severity,
          source: entry.source?.name ?? 'Microsoft Lifecycle Policy'
        }
      })
    );
  }
  return findings;
}

export function mapConfigFindings(candidates = []) {
  return candidates.map((candidate) =>
    buildFinding({
      kind: 'configuration',
      category: candidate.category ?? 'configuration',
      key: `${candidate.ruleId}|${candidate.observed}`,
      severity: candidate.severity,
      title: candidate.title,
      summary: candidate.summary,
      source: candidate.source,
      observed: candidate.observed,
      affectedRange: 'Configuration setting (no version range)',
      fix: candidate.fix,
      confidence: candidate.confidence ?? 'confirmed',
      confidenceReasons: candidate.confidenceReasons ?? [],
      evidenceLabel: `Configuration check: ${candidate.ruleId}`,
      aiEvidence: {
        kind: 'configuration',
        checkId: candidate.ruleId,
        category: candidate.category,
        observed: candidate.evidence ?? null
      }
    })
  );
}

export function sortFindings(findings = []) {
  return [...findings].sort((a, b) => {
    const severity = severityRank(a.severity) - severityRank(b.severity);
    if (severity !== 0) return severity;
    const confidence = (a.confidence === 'confirmed' ? 0 : 1) - (b.confidence === 'confirmed' ? 0 : 1);
    if (confidence !== 0) return confidence;
    return String(a.title).localeCompare(String(b.title));
  });
}

export function summarizeFindings(findings = []) {
  const counts = Object.fromEntries(SEVERITY_ORDER.map((severity) => [severity, 0]));
  let possible = 0;
  for (const finding of findings) {
    if (counts[finding.severity] !== undefined) counts[finding.severity] += 1;
    if (finding.confidence === 'possible') possible += 1;
  }
  return { total: findings.length, bySeverity: counts, possible };
}

export function computeMachineTotals(machine = {}) {
  const endpoints = Array.isArray(machine.endpoints) ? machine.endpoints : [];
  const software = Array.isArray(machine.software) ? machine.software : [];
  const findings = Array.isArray(machine.findings) ? machine.findings : [];
  return {
    endpoints: endpoints.length,
    tcp: endpoints.filter((endpoint) => endpoint.protocol === 'tcp').length,
    udp: endpoints.filter((endpoint) => endpoint.protocol === 'udp').length,
    software: software.length,
    findings: findings.length,
    possible: findings.filter((finding) => finding.confidence === 'possible').length,
    bySeverity: Object.fromEntries(
      SEVERITY_ORDER.map((severity) => [severity, findings.filter((finding) => finding.severity === severity).length])
    )
  };
}

/** Local, deterministic evaluation. AI never influences this result. */
export function evaluateFindings(machine, { advisories, now = new Date() } = {}) {
  const softwareFindings = matchSoftwareFindings({
    software: machine.host?.platform === 'linux' || machine.target?.mode === 'ssh' || machine.platform === 'linux' ? [] : machine.software ?? [],
    advisories
  });
  const lifecycleFindings = evaluateLifecycle({ host: machine.host, lifecycle: advisories?.lifecycle ?? [], now });
  const configCandidates = deriveConfigFindings({
    checks: machine.configChecks ?? [],
    endpoints: machine.endpoints ?? []
  });
  const configFindings = mapConfigFindings(configCandidates);
  if (machine.host?.platform === 'linux' || machine.target?.mode === 'ssh') {
    for (const finding of configFindings) {
      finding.fix = finding.fix.replace(/Windows Firewall/g, 'the host firewall');
    }
  }

  const seen = new Set();
  const deduped = [];
  for (const finding of [...softwareFindings, ...lifecycleFindings, ...configFindings, ...(machine.vulnerabilityFindings ?? [])]) {
    if (seen.has(finding.id)) continue;
    seen.add(finding.id);
    deduped.push(finding);
  }
  return sortFindings(deduped);
}
