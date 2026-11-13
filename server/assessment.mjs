import { randomUUID } from 'node:crypto';
import { mkdir, readdir, stat, unlink, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { COLLECTORS, runCollector } from './collectors/index.mjs';
import { classifyMachine, selectPrimaryIp, uniqueIps } from './machine.mjs';
import { evaluateFindings, computeMachineTotals, summarizeFindings } from './findings.mjs';
import { runAiReview, AI_JOBS } from './ai/review.mjs';
import { validateTarget } from './target.mjs';
import { OsvClient, runVulnerabilityAgent } from './vulnerability-agent.mjs';
import { runWebAssessment } from './web-assessment.mjs';

export class AssessmentLimitError extends Error {
  constructor(message) {
    super(message);
    this.name = 'AssessmentLimitError';
  }
}

export class AssessmentNotFoundError extends Error {
  constructor(id) {
    super(`Assessment ${id} not found`);
    this.name = 'AssessmentNotFoundError';
  }
}

const DEBUG_HANG_MS = 60000;

function initialMachine(id, startedAt) {
  return {
    id: `local-${id.slice(0, 8)}`,
    sample: false,
    hostname: null,
    machineType: 'Unknown',
    ips: [],
    primaryIp: null,
    status: 'collecting',
    host: null,
    endpoints: [],
    software: [],
    configChecks: [],
    updates: null,
    findings: [],
    errors: [],
    warnings: [],
    timestamps: { startedAt, completedAt: null, collectors: {} },
    totals: computeMachineTotals({})
  };
}

function applyCollectorData(machine, collectorId, data) {
  switch (collectorId) {
    case 'host': {
      machine.host = data;
      machine.hostname = data.hostname ?? null;
      machine.machineType = classifyMachine(data);
      machine.ips = uniqueIps(data.addresses);
      machine.primaryIp = selectPrimaryIp(data.addresses);
      break;
    }
    case 'ports': {
      machine.endpoints = data.endpoints ?? [];
      break;
    }
    case 'software': {
      machine.software = data.software ?? [];
      machine.packageInventory = { ecosystem: data.ecosystem, source: data.source, truncated: data.truncated, totalFound: data.totalFound };
      break;
    }
    case 'updates': {
      machine.updates = data;
      for (const message of data.errors ?? []) {
        machine.warnings.push({ source: 'Updates', message });
      }
      break;
    }
    case 'config': {
      machine.configChecks = data.checks ?? [];
      break;
    }
    default:
      break;
  }
}

export class AssessmentManager {
  constructor({ config, advisories, logger, now = () => new Date() }) {
    this.config = config;
    this.advisories = advisories;
    this.logger = logger;
    this.now = now;
    this.records = new Map();
    this.active = 0;
    this.vulnerabilityClient = new OsvClient({ cacheDir: join(config.dataDir, 'cve-cache') });
  }

  create({ aiReview = false, vulnerabilityLookup = true, client = 'dashboard', target } = {}) {
    target = validateTarget(target);
    if (target.mode === 'web') vulnerabilityLookup = false;
    if (this.active >= this.config.maxConcurrentAssessments) {
      throw new AssessmentLimitError('Too many assessments are already running. Wait for one to finish.');
    }
    const id = randomUUID();
    const startedAt = this.now().toISOString();
    const record = {
      id,
      createdAt: startedAt,
      client,
      status: 'running',
      options: { aiReview: Boolean(aiReview), vulnerabilityLookup: Boolean(vulnerabilityLookup), target },
      machine: initialMachine(id, startedAt),
      agent: { status: vulnerabilityLookup ? 'pending' : 'not-requested', phase: 'planning', requests: 0, reusedResponses: 0, warnings: [] },
      collectors: COLLECTORS.map((collector) => ({
        id: collector.id,
        label: collector.label,
        status: 'pending',
        durationMs: null,
        error: null
      })),
      ai: {
        requested: Boolean(aiReview),
        available: this.config.ai.available,
        status: aiReview ? 'pending' : 'not-requested',
        jobs: [],
        merged: [],
        attached: 0,
        reason: null
      },
      events: [],
      eventSeq: 0,
      subscribers: new Set(),
      finished: false,
      startedAt,
      completedAt: null
    };
    record.machine.target = target;
    record.machine.platform = target.mode === 'ssh' || process.platform === 'linux' ? 'linux' : 'windows';
    if (target.mode === 'web') {
      record.machine.platform = 'web';
      record.machine.id = `web-${id.slice(0, 8)}`;
      record.machine.hostname = new URL(target.url).hostname;
      record.machine.machineType = 'Web application';
      record.collectors = [{ id: 'web', label: 'Web security assessment', status: 'pending', durationMs: null, error: null }];
    }
    if (target.mode === 'ssh') record.machine.id = `ssh-${id.slice(0, 8)}`;
    if (target.mode === 'ssh' || process.platform === 'linux') {
      for (const collector of record.collectors) {
        if (collector.id === 'updates') collector.label = 'Linux updates';
      }
    }
    this.records.set(id, record);
    this.active += 1;

    record.run = this.#run(record)
      .catch((error) => {
        this.logger.error('assessment run failed', { assessmentId: id, error });
        this.emit(record, 'error', { message: 'The assessment stopped unexpectedly.', detail: String(error?.message ?? error) });
        record.status = 'failed';
        record.machine.status = 'failed';
        record.finished = true;
        this.emit(record, 'done', { status: 'failed', totals: record.machine.totals, durationMs: 0 });
      })
      .finally(() => {
        this.active = Math.max(0, this.active - 1);
      });

    return this.publicSnapshot(record);
  }

  get(id) {
    const record = this.records.get(id);
    if (!record) throw new AssessmentNotFoundError(id);
    return record;
  }

  publicSnapshot(record) {
    return {
      id: record.id,
      createdAt: record.createdAt,
      status: record.status,
      options: record.options,
      collectors: record.collectors,
      machine: record.machine,
      ai: record.ai,
      agent: record.agent,
      finished: record.finished
    };
  }

  getEvents(record, afterId = 0) {
    return record.events.filter((event) => event.id > afterId);
  }

  subscribe(record, listener) {
    record.subscribers.add(listener);
    return () => record.subscribers.delete(listener);
  }

  emit(record, type, data) {
    record.eventSeq += 1;
    const event = { id: record.eventSeq, type, at: this.now().toISOString(), data };
    record.events.push(event);
    if (record.events.length > 4000) {
      record.events.splice(0, record.events.length - 4000);
    }
    for (const listener of [...record.subscribers]) {
      try {
        listener(event);
      } catch (error) {
        this.logger.warn('sse subscriber failed', { assessmentId: record.id, error });
        record.subscribers.delete(listener);
      }
    }
    return event;
  }

  async runAi(id) {
    const record = this.get(id);
    if (!this.config.ai.available) {
      return { ok: false, status: 409, body: { error: 'AI review is not configured on this backend.' } };
    }
    if (!record.finished) {
      return { ok: false, status: 409, body: { error: 'Wait for the assessment to finish before requesting AI review.' } };
    }
    if (record.ai.running) {
      return { ok: false, status: 409, body: { error: 'An AI review is already running for this assessment.' } };
    }

    record.ai = {
      ...record.ai,
      requested: true,
      running: true,
      status: 'running',
      jobs: AI_JOBS.map((job) => ({ id: job.id, label: job.label, status: 'running' })),
      merged: [],
      attached: 0,
      reason: null
    };
    this.emit(record, 'ai', { ...record.ai, machineId: record.machine.id });

    try {
      const result = await runAiReview({
        aiConfig: this.config.ai,
        machine: record.machine,
        findings: record.machine.findings,
        logger: this.logger
      });
      record.ai = { ...result, requested: true, available: true, running: false };
      this.emit(record, 'ai', { ...record.ai, machineId: record.machine.id });
      this.emit(record, 'findings', {
        machineId: record.machine.id,
        findings: record.machine.findings,
        summary: summarizeFindings(record.machine.findings)
      });
      this.logger.info('ai review finished', { assessmentId: record.id, status: result.status, jobs: result.jobs.map((job) => job.status) });
      await this.persist(record);
      return { ok: true, status: 200, body: record.ai };
    } catch (error) {
      const reason = `AI review failed: ${String(error?.message ?? error)}`;
      record.ai = {
        ...record.ai,
        running: false,
        status: 'error',
        jobs: (record.ai.jobs ?? []).map((job) =>
          job.status === 'running' ? { ...job, status: 'error', error: reason } : job
        ),
        reason
      };
      this.emit(record, 'ai', { ...record.ai, machineId: record.machine.id });
      return { ok: false, status: 502, body: { error: record.ai.reason } };
    }
  }

  async #run(record) {
    const machine = record.machine;
    this.emit(record, 'machine', { machine });
    this.emit(record, 'progress', {
      phase: 'collecting',
      completed: 0,
      total: record.collectors.length,
      running: record.collectors.map((collector) => collector.id)
    });

    const completedIds = new Set();
    const collectors = record.options.target.mode === 'web' ? [] : COLLECTORS;
    if (record.options.target.mode === 'web') await this.#runWeb(record);

    await Promise.all(
      collectors.map(async (collector) => {
        const label = record.collectors.find((item) => item.id === collector.id).label;
        this.emit(record, 'collector', {
          collector: collector.id,
          label,
          status: 'running'
        });

        let result;
        try {
          result = await this.#runCollectorWithTimeout(collector, record.options.target);
        } catch (error) {
          result = {
            status: 'error',
            kind: 'internal',
            error: `Collector failed: ${String(error?.message ?? error)}`,
            durationMs: 0
          };
        }

        if (result.status === 'ok') {
          applyCollectorData(machine, collector.id, result.data);
        } else {
          const message = result.error || 'Collector failed without a message';
          machine.errors.push({
            collector: collector.id,
            label,
            kind: result.kind ?? 'error',
            message
          });
          this.logger.warn('collector error', {
            assessmentId: record.id,
            collector: collector.id,
            kind: result.kind,
            message
          });
        }

        const entry = record.collectors.find((item) => item.id === collector.id);
        if (entry) {
          entry.status = result.status;
          entry.durationMs = result.durationMs ?? null;
          entry.error = result.status === 'ok' ? null : result.error;
        }
        machine.timestamps.collectors[collector.id] = {
          status: result.status,
          durationMs: result.durationMs ?? null,
          at: this.now().toISOString()
        };
        completedIds.add(collector.id);

        this.emit(record, 'collector', {
          collector: collector.id,
          label,
          status: result.status,
          kind: result.kind ?? null,
          durationMs: result.durationMs ?? null,
          error: result.status === 'ok' ? null : result.error,
          data: result.status === 'ok' ? result.data : null,
          truncated: Boolean(result.truncated),
          machineSummary: {
            hostname: machine.hostname,
            machineType: machine.machineType,
            ips: machine.ips,
            primaryIp: machine.primaryIp
          }
        });
        if (result.status === 'ok') this.#refreshFindings(record);
        this.emit(record, 'progress', {
          phase: 'collecting',
          completed: completedIds.size,
          total: COLLECTORS.length,
          running: COLLECTORS.filter((item) => !completedIds.has(item.id)).map((item) => item.id)
        });
      })
    );

    if (record.options.vulnerabilityLookup) {
      await runVulnerabilityAgent({
        machine,
        client: this.vulnerabilityClient,
        onUpdate: ({ findings, ...agent }) => {
          record.agent = agent;
          machine.vulnerabilityFindings = findings;
          this.emit(record, 'agent', agent);
          this.#refreshFindings(record);
        }
      });
    }

    const failedCount = machine.errors.length;
    machine.status = failedCount === 0 ? 'complete' : failedCount >= record.collectors.length ? 'failed' : 'partial';
    if (machine.status === 'complete' && machine.web?.status === 'partial') machine.status = 'partial';
    if (machine.status === 'complete' && ['partial', 'error'].includes(record.agent.status)) machine.status = 'partial';
    machine.timestamps.completedAt = this.now().toISOString();
    record.status = machine.status;
    this.#refreshFindings(record);

    if (record.options.aiReview) {
      if (!this.config.ai.available) {
        record.ai = {
          ...record.ai,
          status: 'disabled',
          reason: 'AI review was requested but the backend has no AI provider configured. Local results are complete.'
        };
        this.emit(record, 'ai', { ...record.ai, machineId: machine.id });
      } else {
        record.ai = { ...record.ai, status: 'running', jobs: AI_JOBS.map((job) => ({ id: job.id, label: job.label, status: 'running' })) };
        this.emit(record, 'ai', { ...record.ai, machineId: machine.id });
        const result = await runAiReview({
          aiConfig: this.config.ai,
          machine,
          findings: machine.findings,
          logger: this.logger
        });
        record.ai = { ...result, requested: true, available: true };
        this.emit(record, 'ai', { ...record.ai, machineId: machine.id });
        this.emit(record, 'findings', {
          machineId: machine.id,
          findings: machine.findings,
          summary: summarizeFindings(machine.findings)
        });
      }
    }

    record.completedAt = this.now().toISOString();
    record.finished = true;
    record.status = machine.status;
    this.emit(record, 'done', {
      machineId: machine.id,
      status: machine.status,
      totals: machine.totals,
      partial: failedCount > 0,
      collectors: record.collectors,
      aiStatus: record.ai.status,
      agentStatus: record.agent.status,
      startedAt: record.startedAt,
      completedAt: record.completedAt,
      durationMs: new Date(record.completedAt).getTime() - new Date(record.startedAt).getTime()
    });

    this.logger.info('assessment finished', {
      assessmentId: record.id,
      status: machine.status,
      durationMs: new Date(record.completedAt).getTime() - new Date(record.startedAt).getTime(),
      findings: machine.findings.length,
      endpoints: machine.endpoints.length,
      software: machine.software.length,
      collectorErrors: failedCount
    });

    await this.persist(record);
  }

  async #runWeb(record) {
    const entry = record.collectors[0];
    const started = Date.now();
    entry.status = 'running';
    this.emit(record, 'collector', { collector: 'web', label: entry.label, status: 'running' });
    const result = await runWebAssessment({
      target: record.options.target,
      onUpdate: ({ checks, findings, ...web }) => {
        record.machine.web = web;
        record.machine.configChecks = checks;
        record.machine.vulnerabilityFindings = findings;
        this.emit(record, 'web', { ...web, checks });
        this.#refreshFindings(record);
      }
    });
    entry.status = result.status === 'error' ? 'error' : 'ok';
    entry.durationMs = Date.now() - started;
    entry.error = result.status === 'error' ? result.warnings.join(' ') : null;
    if (entry.error) record.machine.errors.push({ collector: 'web', label: entry.label, kind: 'web', message: entry.error });
    record.machine.timestamps.collectors.web = { status: entry.status, durationMs: entry.durationMs, at: this.now().toISOString() };
    this.emit(record, 'collector', { collector: 'web', label: entry.label, status: entry.status, durationMs: entry.durationMs, error: entry.error });
    this.emit(record, 'progress', { phase: 'web', completed: 1, total: 1, running: [] });
  }

  #refreshFindings(record) {
    const machine = record.machine;
    machine.findings = evaluateFindings(machine, { advisories: this.advisories, now: this.now() });
    machine.totals = computeMachineTotals(machine);
    this.emit(record, 'findings', {
      machineId: machine.id,
      findings: machine.findings,
      summary: summarizeFindings(machine.findings),
      totals: machine.totals
    });
  }

  async #runCollectorWithTimeout(collector, target) {
    const timeoutMs = Math.min(this.config.collectorTimeoutMs, collector.timeoutMs ?? this.config.collectorTimeoutMs);
    let timer = null;
    const timeoutPromise = new Promise((resolve) => {
      timer = setTimeout(() => {
        resolve({
          status: 'error',
          kind: 'timeout',
          error: `Collector timed out after ${Math.round(timeoutMs / 1000)}s. Partial results from the other collectors were kept.`,
          durationMs: timeoutMs
        });
      }, timeoutMs);
    });

    const simulateHang = this.config.debugSlowCollector === collector.id;
    const work = simulateHang
      ? new Promise((resolve) => {
          this.logger.warn('debug hang simulation active', { collector: collector.id, timeoutMs });
          const timer = setTimeout(() => resolve({ status: 'ok', data: collector.empty(), durationMs: DEBUG_HANG_MS }), DEBUG_HANG_MS);
          timer.unref?.();
        })
      : runCollector(collector, {
          scriptDir: this.config.collectorScriptDir,
          target,
          timeoutMs,
          logger: this.logger
        });

    try {
      return await Promise.race([work, timeoutPromise]);
    } finally {
      if (timer) clearTimeout(timer);
    }
  }

  async persist(record) {
    try {
      await mkdir(this.config.snapshotDir, { recursive: true });
      const snapshot = {
        id: record.id,
        createdAt: record.createdAt,
        completedAt: record.completedAt,
        status: record.status,
        options: record.options,
        collectors: record.collectors,
        ai: record.ai,
        agent: record.agent,
        machine: record.machine
      };
      await writeFile(join(this.config.snapshotDir, `${record.id}.json`), JSON.stringify(snapshot, null, 2), 'utf8');
      await this.#pruneSnapshots();
    } catch (error) {
      this.logger.warn('could not persist assessment snapshot', { assessmentId: record.id, error });
    }
  }

  async #pruneSnapshots() {
    try {
      const entries = await readdir(this.config.snapshotDir);
      const files = entries.filter((name) => name.endsWith('.json'));
      if (files.length <= this.config.maxAssessmentRetention) return;
      const withTimes = await Promise.all(
        files.map(async (name) => {
          const info = await stat(join(this.config.snapshotDir, name));
          return { name, mtime: info.mtimeMs };
        })
      );
      withTimes.sort((a, b) => a.mtime - b.mtime);
      const remove = withTimes.slice(0, withTimes.length - this.config.maxAssessmentRetention);
      await Promise.all(remove.map((item) => unlink(join(this.config.snapshotDir, item.name))));
    } catch {
      /* retention is best effort */
    }
  }
}
