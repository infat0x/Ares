import { requestJsonCompletion, AiProviderError } from './client.mjs';
import { validateReviewPayload, SYSTEM_PROMPT } from './schema.mjs';
import { collectIdentifiers, sanitizeDeep, containsIdentifiers } from '../util/redact.mjs';
import { userInfo } from 'node:os';

const CONFIDENCE_RANK = { high: 0, medium: 1, low: 2 };

export const AI_JOBS = [
  {
    id: 'software',
    label: 'Software & OS advisory review',
    task: 'Explain the real-world risk of these software and operating-system advisories. For each item, state what an attacker could achieve and give the single most effective remediation. Flag weak local matches explicitly.',
    kinds: ['software', 'os-lifecycle']
  },
  {
    id: 'configuration',
    label: 'Security configuration review',
    task: 'Explain the risk of these configuration weaknesses. For each item, state the realistic attack path and give the single most effective remediation. Do not assume an operating system, domain or cloud context that is not supplied.',
    kinds: ['configuration']
  },
  {
    id: 'validation',
    label: 'Evidence validation and attack-path analysis',
    task: 'Independently challenge the supplied observations. Identify unsupported assumptions and false-positive risks. Explain plausible attack paths only when supported by cited evidence and state the additional verification needed. Give prioritized remediations. With no findings, explain that coverage is insufficient to establish safety. Never invent a vulnerability.',
    kinds: ['software', 'os-lifecycle', 'configuration']
  }
];

export function buildSoftwareEvidence(findings = []) {
  return findings
    .filter((finding) => finding.kind === 'software' || finding.kind === 'os-lifecycle')
    .map((finding) => {
      const evidence = finding.aiEvidence ?? {};
      return {
        id: finding.id,
        localSeverity: finding.severity,
        localConfidence: finding.confidence,
        title: finding.title,
        product: evidence.product ?? evidence.family ?? null,
        installedVersion: evidence.observedVersion ?? (evidence.build ? `build ${evidence.build}` : null),
        advisoryId: evidence.advisoryId ?? null,
        advisoryTitle: evidence.advisoryTitle ?? null,
        affectedRange: evidence.affectedRange ?? finding.affectedRange ?? null,
        fixedVersion: evidence.fixedVersion ?? null,
        source: evidence.advisorySource ?? finding.source?.name ?? null
      };
    });
}

export function buildConfigurationEvidence(findings = []) {
  return findings
    .filter((finding) => finding.kind === 'configuration')
    .map((finding) => {
      const evidence = finding.aiEvidence ?? {};
      return {
        id: finding.id,
        localSeverity: finding.severity,
        localConfidence: finding.confidence,
        title: finding.title,
        checkId: evidence.checkId ?? null,
        category: evidence.category ?? finding.category ?? null,
        observed: evidence.observed ?? null
      };
    });
}

/** Build the exact payload for one job. Only allowlisted fields are included. */
export function buildJobPayload(job, evidence) {
  return {
    task: job.task,
    evidence
  };
}

async function runJob({ job, findings, aiConfig, identifiers, logger, fetchImpl }) {
  const startedAt = Date.now();
  const evidence = job.id === 'validation'
    ? [...buildSoftwareEvidence(findings), ...buildConfigurationEvidence(findings)]
    : job.id === 'software' ? buildSoftwareEvidence(findings) : buildConfigurationEvidence(findings);

  if (evidence.length === 0 && job.id !== 'validation') {
    return {
      id: job.id,
      label: job.label,
      status: 'skipped',
      reason: 'No local findings in this group, so no evidence was sent.',
      evidenceCount: 0,
      items: [],
      durationMs: 0
    };
  }

  const payload = sanitizeDeep(buildJobPayload(job, evidence), identifiers);
  const serialized = JSON.stringify(payload);
  if (containsIdentifiers(serialized, identifiers)) {
    return {
      id: job.id,
      label: job.label,
      status: 'error',
      error: 'Refused to send: the prepared payload still contained a host identifier.',
      evidenceCount: evidence.length,
      items: [],
      durationMs: Date.now() - startedAt
    };
  }

  try {
    const response = await requestJsonCompletion({
      aiConfig,
      systemPrompt: SYSTEM_PROMPT,
      userPayload: payload,
      fetchImpl,
      logger
    });
    const validation = validateReviewPayload(response.parsed, {
      allowedEvidenceRefs: evidence.map((item) => item.id)
    });
    const items = (validation.value?.findings ?? []).map((item) => ({ ...item, job: job.id }));
    const status = items.length > 0 || (validation.ok && validation.value) ? 'complete' : 'error';
    return {
      id: job.id,
      label: job.label,
      status,
      summary: validation.value?.summary ?? null,
      items,
      evidenceCount: evidence.length,
      model: response.model,
      usage: response.usage,
      validationErrors: validation.errors,
      droppedItems: validation.dropped,
      durationMs: Date.now() - startedAt
    };
  } catch (error) {
    return {
      id: job.id,
      label: job.label,
      status: 'error',
      error:
        error instanceof AiProviderError
          ? error.message
          : `AI review job failed: ${String(error?.message ?? error).slice(0, 200)}`,
      errorKind: error instanceof AiProviderError ? error.kind : 'internal',
      evidenceCount: evidence.length,
      items: [],
      durationMs: Date.now() - startedAt
    };
  }
}

function normalizeTitle(title) {
  return String(title ?? '')
    .toLowerCase()
    .replace(/[^a-z0-9 ]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

/**
 * Merge agent output across jobs, remove duplicates, and attach each accepted
 * item to the local finding(s) it cites. AI text never changes local severity
 * or confidence; it is stored separately for display.
 */
export function mergeAiFindings(jobs, findings) {
  const byId = new Map(findings.map((finding) => [finding.id, finding]));
  const merged = new Map();

  for (const job of jobs) {
    for (const item of job.items ?? []) {
      const refs = Array.isArray(item.evidenceRefs) ? [...new Set(item.evidenceRefs)] : [];
      if (refs.length === 0) continue;
      const key = `${normalizeTitle(item.title)}|${[...refs].sort().join(',')}`;
      const existing = merged.get(key);
      if (existing) {
        existing.refs = [...new Set([...existing.refs, ...refs])];
        existing.mergedFrom += 1;
        if ((CONFIDENCE_RANK[item.confidence] ?? 9) < (CONFIDENCE_RANK[existing.confidence] ?? 9)) {
          existing.confidence = item.confidence;
          existing.risk = item.risk;
          existing.remediation = item.remediation;
        }
        continue;
      }
      merged.set(key, {
        title: item.title,
        risk: item.risk,
        severity: item.severity,
        remediation: item.remediation,
        confidence: item.confidence,
        refs,
        job: job.id,
        jobSummary: job.summary ?? null,
        model: job.model ?? null,
        mergedFrom: 1
      });
    }
  }

  let attached = 0;
  const result = [];
  for (const item of merged.values()) {
    let attachedAny = false;
    for (const ref of item.refs) {
      const finding = byId.get(ref);
      if (!finding) continue;
      const candidate = {
        job: item.job,
        title: item.title,
        risk: item.risk,
        severity: item.severity,
        remediation: item.remediation,
        confidence: item.confidence,
        summary: item.jobSummary,
        model: item.model,
        mergedFrom: item.mergedFrom
      };
      if (!finding.ai) {
        finding.ai = candidate;
      } else if ((CONFIDENCE_RANK[candidate.confidence] ?? 9) < (CONFIDENCE_RANK[finding.ai.confidence] ?? 9)) {
        finding.ai = candidate;
      }
      attachedAny = true;
      attached += 1;
    }
    result.push({ ...item, attached: attachedAny });
  }

  return { items: result, attached };
}

/**
 * Run independent review jobs concurrently. Provider failures are
 * returned as per-job errors so the Windows assessment keeps its local result.
 */
export async function runAiReview({ aiConfig, machine, findings, logger, fetchImpl = globalThis.fetch, onJob = () => {} }) {
  const startedAt = Date.now();
  if (!aiConfig?.available) {
    return {
      status: 'disabled',
      jobs: [],
      merged: [],
      attached: 0,
      reason: 'AI review is disabled or no API key is configured.',
      durationMs: 0
    };
  }

  const identifiers = [
    ...collectIdentifiers(machine),
    userInfo().username,
    process.env.USERNAME,
    process.env.USER
  ].filter((value) => typeof value === 'string' && value.trim().length >= 3);
  const jobs = await Promise.all(
    AI_JOBS.map(async (job) => {
      onJob({ id: job.id, label: job.label, status: 'running' });
      const result = await runJob({ job, findings, aiConfig, identifiers, logger, fetchImpl });
      onJob(result);
      return result;
    })
  );
  const merge = mergeAiFindings(jobs, findings);

  const anyItems = jobs.some((job) => (job.items ?? []).length > 0);
  const allSkipped = jobs.every((job) => job.status === 'skipped');
  const allComplete = jobs.every((job) => job.status === 'complete' || job.status === 'skipped');
  const status = allSkipped ? 'skipped' : allComplete ? 'complete' : anyItems ? 'partial' : 'error';

  return {
    status,
    jobs,
    merged: merge.items,
    attached: merge.attached,
    durationMs: Date.now() - startedAt
  };
}
