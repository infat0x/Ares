import {
  SEVERITY_LEVELS,
  normalizeFilters,
  machineMatches,
  countSeverities,
  machineStatusLabel
} from './filter.mjs';

const $ = (id) => document.getElementById(id);

async function apiFetch(url, options) {
  const response = await fetch(url, options);
  if (response.status === 401) {
    window.location.replace('/');
    throw new Error('Your session has expired. Sign in again.');
  }
  return response;
}

const state = {
  meta: null,
  samples: null,
  live: null,
  busy: false,
  filters: normalizeFilters({}),
  open: new Set(),
  notices: [],
  assessment: {
    id: null,
    status: 'idle',
    collectors: [],
    progress: null,
    ai: null,
    agent: null,
    aiRequested: false,
    done: false,
    source: null,
    startedAt: null
  }
};

function el(tag, props = {}, children = []) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (value === undefined || value === null) continue;
    if (key === 'class') node.className = value;
    else if (key === 'text') node.textContent = String(value);
    else if (key === 'dataset') Object.assign(node.dataset, value);
    else if (key === 'attrs') {
      for (const [name, attrValue] of Object.entries(value)) node.setAttribute(name, String(attrValue));
    } else if (key === 'on') {
      for (const [eventName, handler] of Object.entries(value)) node.addEventListener(eventName, handler);
    } else {
      node[key] = value;
    }
  }
  for (const child of [].concat(children)) {
    if (child === null || child === undefined || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

function formatDate(value) {
  if (!value) return '—';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit'
  });
}

function formatDuration(ms) {
  if (ms === null || ms === undefined || !Number.isFinite(Number(ms))) return '—';
  const value = Number(ms);
  if (value < 1000) return `${Math.round(value)} ms`;
  return `${(value / 1000).toFixed(1)} s`;
}

function severityLabel(value) {
  const text = String(value ?? 'info');
  return text.charAt(0).toUpperCase() + text.slice(1);
}

function statusTone(machine) {
  if (!machine) return 'idle';
  if (machine.sample) return 'sample';
  if (machine.status === 'complete') return 'ok';
  if (machine.status === 'partial') return 'warn';
  if (machine.status === 'failed') return 'bad';
  return 'running';
}

function safeLink(url, text) {
  const href = typeof url === 'string' && /^https:\/\//i.test(url) ? url : null;
  if (!href) return el('span', { text });
  return el('a', { href, text, target: '_blank', rel: 'noopener noreferrer' });
}

function setStatus(message, tone = 'neutral') {
  const node = $('assessment-status');
  node.textContent = message;
  node.dataset.tone = tone;
}

function addNotice(tone, title, message, key = null) {
  const id = key ?? `${tone}:${title}:${message}`;
  if (state.notices.some((notice) => notice.id === id)) return;
  state.notices.push({ id, tone, title, message });
  renderNotices();
}

function clearNotices() {
  state.notices = [];
  renderNotices();
}

async function init() {
  wireEvents();
  try {
    const [metaResponse, samplesResponse] = await Promise.all([apiFetch('/api/meta'), apiFetch('/api/samples')]);
    if (!metaResponse.ok) throw new Error(`Metadata request failed (HTTP ${metaResponse.status})`);
    if (!samplesResponse.ok) throw new Error(`Sample data request failed (HTTP ${samplesResponse.status})`);
    state.meta = await metaResponse.json();
    state.samples = await samplesResponse.json();
    applyMeta();
    renderAll();
    setStatus('Ready. Start an assessment to inspect this machine.');
  } catch (error) {
    setStatus('Backend metadata could not be loaded.', 'bad');
    addNotice('error', 'Dashboard initialisation failed', String(error?.message ?? error), 'init-failed');
  }
}

function applyMeta() {
  const ai = state.meta?.ai ?? { available: false, enabled: false };
  const chip = $('ai-chip');
  if (ai.available) {
    chip.textContent = `AI review: available${ai.model ? ` (${ai.model})` : ''}`;
    chip.className = 'chip chip-ok';
  } else {
    chip.textContent = 'AI review: off (no backend key)';
    chip.className = 'chip chip-muted';
  }

  const toggle = $('ai-toggle');
  toggle.disabled = true;
  toggle.checked = Boolean(ai.available);
  $('web-input-checks').checked = Boolean(ai.available) || $('web-input-checks').checked;
  $('web-input-checks').disabled = Boolean(ai.available);

  $('ai-hint').textContent = ai.available
    ? 'Sends software/version facts and configuration observations. With web input probes enabled, AI chooses the next check from previous results. Target URLs, parameter names and response bodies stay local.'
    : 'No backend AI provider is configured. The local Windows assessment still runs normally.';
  $('ai-note').textContent = ai.available
    ? 'AI starts automatically with each assessment. Web input checks and three parallel analysis agents appear in the pipeline.'
    : 'Open AI settings below and save your OpenCode API key to enable AI review.';

  const sampleInfo = state.meta?.samples;
  const banner = $('sample-banner');
  if (sampleInfo && state.samples) {
    banner.hidden = false;
    banner.replaceChildren(
      el('strong', { text: 'SAMPLE DATA' }),
      ` — ${state.samples.count} synthetic machines for scale and filter testing. They are not real hosts and are never scanned.`
    );
  }

  const advisory = state.meta?.advisory;
  $('meta-line').textContent = [
    `Ares ${state.meta?.version ?? ''}`,
    advisory?.snapshot ? `advisory snapshot ${advisory.snapshot}` : null,
    advisory ? `${advisory.softwareEntries} software advisories` : null,
    advisory ? `${advisory.lifecycleEntries} lifecycle entries` : null,
    state.samples ? `${state.samples.count} sample machines` : null
  ]
    .filter(Boolean)
    .join(' · ');
}

function wireEvents() {
  $('logout-btn').addEventListener('click', async () => {
    $('logout-btn').disabled = true;
    try {
      const response = await apiFetch('/api/logout', {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'x-ares-request': 'dashboard' },
        body: '{}'
      });
      if (!response.ok) throw new Error('Sign out failed. Try again.');
      state.assessment.source?.close();
      window.location.replace('/');
    } catch (error) {
      $('logout-btn').disabled = false;
      addNotice('error', 'Sign out failed', String(error?.message ?? error));
    }
  });
  $('ai-settings-form').addEventListener('submit', saveAiKey);
  $('target-mode').addEventListener('change', () => {
    $('ssh-fields').hidden = $('target-mode').value !== 'ssh';
    $('web-fields').hidden = $('target-mode').value !== 'web';
    $('vulnerability-option').hidden = $('target-mode').value === 'web';
  });
  $('start-btn').addEventListener('click', startAssessment);
  $('ai-run-btn').addEventListener('click', runAiReview);

  const scheduleRender = debounce(() => {
    updateFiltersFromControls();
    renderStats();
    renderMachineList();
  }, 150);

  $('filter-ip').addEventListener('input', scheduleRender);
  $('filter-port').addEventListener('input', scheduleRender);
  $('filter-process').addEventListener('input', scheduleRender);

  for (const checkbox of document.querySelectorAll('[data-severity]')) {
    checkbox.addEventListener('change', () => {
      updateFiltersFromControls();
      renderStats();
      renderMachineList();
    });
  }

  $('show-samples').addEventListener('change', () => {
    updateFiltersFromControls();
    renderStats();
    renderMachineList();
  });

  $('clear-filters').addEventListener('click', () => {
    $('filter-ip').value = '';
    $('filter-port').value = '';
    $('filter-process').value = '';
    $('show-samples').checked = true;
    for (const checkbox of document.querySelectorAll('[data-severity]')) checkbox.checked = true;
    updateFiltersFromControls();
    renderStats();
    renderMachineList();
  });
}

function debounce(fn, delay) {
  let timer = null;
  return (...args) => {
    if (timer) clearTimeout(timer);
    timer = setTimeout(() => fn(...args), delay);
  };
}

function updateFiltersFromControls() {
  const severities = [...document.querySelectorAll('[data-severity]')]
    .filter((checkbox) => checkbox.checked)
    .map((checkbox) => checkbox.dataset.severity);
  state.filters = normalizeFilters({
    ip: $('filter-ip').value,
    port: $('filter-port').value,
    process: $('filter-process').value,
    severities,
    showSamples: $('show-samples').checked
  });
}

function visibleMachines() {
  const machines = [];
  if (state.live) machines.push(state.live);
  if (state.samples && state.filters.showSamples) machines.push(...state.samples.machines);
  return machines;
}

function filteredMachines() {
  return visibleMachines().filter((machine) => machineMatches(machine, state.filters));
}

function renderAll() {
  renderStats();
  renderMachineList();
  renderProgress();
  renderNotices();
}

function renderStats() {
  const machines = filteredMachines();
  const counts = countSeverities(machines);
  const endpoints = machines.reduce((total, machine) => total + (machine.endpoints?.length ?? 0), 0);
  const software = machines.reduce((total, machine) => total + (machine.software?.length ?? 0), 0);

  const stats = $('stats');
  stats.replaceChildren(
    ...SEVERITY_LEVELS.map((severity) =>
      el('span', { class: `stat sev-${severity}`, title: `${counts[severity]} ${severity} findings in visible machines` }, [
        el('span', { class: 'stat-dot' }),
        el('strong', { text: String(counts[severity]) }),
        el('span', { class: 'stat-label', text: severity })
      ])
    ),
    el('span', { class: 'stat stat-plain' }, [el('strong', { text: String(endpoints) }), el('span', { class: 'stat-label', text: 'endpoints visible' })]),
    el('span', { class: 'stat stat-plain' }, [el('strong', { text: String(software) }), el('span', { class: 'stat-label', text: 'applications visible' })])
  );
}

function renderMachineList() {
  const container = $('machines');
  const machines = filteredMachines();
  const total = visibleMachines().length;

  const banner = $('sample-banner');
  if (state.samples) banner.hidden = !state.filters.showSamples;

  $('count').textContent = `· showing ${machines.length} of ${total}`;
  $('empty').hidden = machines.length > 0 || total === 0;

  const sorted = [...machines].sort((a, b) => {
    const liveDelta = (a.sample ? 1 : 0) - (b.sample ? 1 : 0);
    if (liveDelta !== 0) return liveDelta;
    return String(a.hostname ?? '').localeCompare(String(b.hostname ?? ''), undefined, { numeric: true });
  });

  container.replaceChildren(...sorted.map((machine) => buildMachineRow(machine)));
}

function buildMachineRow(machine) {
  const key = machine.id ?? machine.hostname ?? 'unknown';
  const details = el('details', { class: 'machine' });
  details.dataset.id = key;

  const title = machine.hostname ?? (machine.sample ? 'Sample host' : 'Local host (collecting)');
  const extraIps = Math.max(0, (machine.ips?.length ?? 0) - 1);
  const tone = statusTone(machine);

  const summary = el('summary', { class: 'machine-summary' }, [
    el('span', { class: 'chevron', attrs: { 'aria-hidden': 'true' } }),
    el('span', { class: 'm-name' }, [
      el('strong', { text: title }),
      machine.sample
        ? el('span', { class: 'badge badge-sample', text: 'SAMPLE' })
        : el('span', { class: 'badge badge-live', text: 'LIVE' })
    ]),
    el('span', { class: 'm-ip mono', attrs: { title: (machine.ips ?? []).join(', ') || 'No IP collected' } }, [
      machine.primaryIp ?? 'No IP',
      extraIps > 0 ? el('span', { class: 'muted', text: ` +${extraIps}` }) : null
    ]),
    el('span', { class: 'm-type', text: machine.machineType ?? 'Unknown' }),
    el('span', { class: `status status-${tone}`, text: machineStatusLabel(machine) }),
    el('span', { class: 'm-mini' }, [
      el('span', { class: 'mini', title: 'Listening endpoints', text: `${machine.endpoints?.length ?? 0} ports` }),
      el('span', { class: 'mini', title: 'Installed applications', text: `${machine.software?.length ?? 0} apps` }),
      ...severityDots(machine)
    ])
  ]);

  const body = el('div', { class: 'machine-body' });
  const populate = () => {
    if (body.dataset.ready === '1') return;
    body.dataset.ready = '1';
    body.replaceChildren(...buildMachineDetail(machine));
  };

  details.addEventListener('toggle', () => {
    if (details.open) {
      state.open.add(key);
      populate();
    } else {
      state.open.delete(key);
    }
  });

  if (state.open.has(key)) {
    details.open = true;
    populate();
  }

  details.append(summary, body);
  return details;
}

function severityDots(machine) {
  const findings = machine.findings ?? [];
  if (findings.length === 0) return [];
  return SEVERITY_LEVELS.filter((severity) => findings.some((finding) => finding.severity === severity)).map((severity) => {
    const count = findings.filter((finding) => finding.severity === severity).length;
    return el('span', {
      class: `dot sev-${severity}`,
      title: `${count} ${severity}`,
      text: String(count)
    });
  });
}

function section(title, count, content, subtitle = null) {
  return el('section', { class: 'detail-section' }, [
    el('div', { class: 'section-head' }, [
      el('h3', { text: count === null ? title : `${title} (${count})` }),
      subtitle ? el('span', { class: 'muted small', text: subtitle }) : null
    ]),
    content
  ]);
}

function buildMachineDetail(machine) {
  const sections = [];
  const host = machine.host;
  const collectorEntries = Object.entries(machine.timestamps?.collectors ?? {});
  const addresses = machine.ips ?? [];
  const addressNode =
    addresses.length > 0
      ? el(
          'div',
          { class: 'ip-list' },
          addresses.map((address) => el('span', { class: 'ip-line mono', text: address, attrs: { title: address } }))
        )
      : 'Unknown';

  sections.push(
    section(
      'Overview',
      null,
      el('div', { class: 'overview' }, machine.platform === 'web' ? [
        infoPair('Target', machine.web?.endpoint ?? 'Collecting...'),
        infoPair('HTTP status', machine.web?.statusCode ?? 'Collecting...'),
        infoPair('Requests', `${machine.web?.requests ?? 0}/${machine.web?.maxRequests ?? 10}`),
        infoPair('Assessment started', formatDate(machine.timestamps?.startedAt)),
        infoPair('Assessment finished', formatDate(machine.timestamps?.completedAt)),
        infoPair('Status', machineStatusLabel(machine))
      ] : [
        infoPair('Hostname', machine.hostname ?? 'Unknown'),
        infoPair('IP addresses', addressNode),
        infoPair('Machine type', machine.machineType ?? 'Unknown'),
        infoPair(
          'Operating system',
          host ? `${host.caption ?? 'Windows'}${host.displayVersion ? ` · ${host.displayVersion}` : ''}` : 'Not collected'
        ),
        infoPair('Build', host?.build ? `${host.build}${host.architecture ? ` · ${host.architecture}` : ''}` : 'Not collected'),
        infoPair('Hardware', [host?.manufacturer, host?.model].filter(Boolean).join(' ') || 'Unknown'),
        infoPair('Memory', host?.totalMemoryGb ? `${host.totalMemoryGb} GB` : 'Unknown'),
        infoPair('Time zone', host?.timeZone ?? 'Unknown'),
        infoPair('Boot time', formatDate(host?.bootTime)),
        infoPair('Assessment started', formatDate(machine.timestamps?.startedAt)),
        infoPair('Assessment finished', formatDate(machine.timestamps?.completedAt)),
        infoPair('Status', machineStatusLabel(machine))
      ])
    )
  );

  if (machine.errors?.length || machine.warnings?.length) {
    const items = [
      ...(machine.errors ?? []).map((error) =>
        el('li', { class: 'notice notice-error' }, [
          el('strong', { text: `${error.label ?? error.collector} failed` }),
          el('span', { text: error.message })
        ])
      ),
      ...(machine.warnings ?? []).map((warning) =>
        el('li', { class: 'notice notice-warn' }, [
          el('strong', { text: warning.source }),
          el('span', { text: warning.message })
        ])
      )
    ];
    sections.push(section('Collector issues', items.length, el('ul', { class: 'notice-list' }, items)));
  }

  if (collectorEntries.length > 0) {
    const rows = collectorEntries.map(([id, timing]) =>
      el('tr', {}, [
        el('td', { text: id }),
        el('td', {}, [statusBadge(timing.status === 'ok' ? 'ok' : 'error', timing.status === 'ok' ? 'Completed' : 'Failed')]),
        el('td', { class: 'mono', text: formatDuration(timing.durationMs) }),
        el('td', { class: 'muted small', text: formatDate(timing.at) })
      ])
    );
    sections.push(
      section(
        'Collector timings',
        null,
        el('div', { class: 'table-wrap' }, [
          el('table', { class: 'table compact' }, [
            el('thead', {}, [el('tr', {}, ['Collector', 'Result', 'Duration', 'Finished'].map((label) => el('th', { text: label })))]),
            el('tbody', {}, rows)
          ])
        ]),
        'Concurrent, each with an independent timeout'
      )
    );
  }

  sections.push(
    section(
      'Findings',
      machine.findings?.length ?? 0,
      (machine.findings?.length ?? 0) === 0
        ? el('p', { class: 'muted small' }, [
            machine.status === 'collecting'
              ? 'Waiting for collectors to finish…'
              : machine.platform === 'web'
                ? 'No findings in the tested web checks. Review the coverage notices.'
                : `No findings matched the bundled advisory snapshot (${state.meta?.advisory?.softwareEntries ?? '?'} software advisories, ${state.meta?.advisory?.lifecycleEntries ?? '?'} lifecycle entries). An empty list does not prove the machine is clean.`
          ])
        : el('div', { class: 'findings' }, machine.findings.map((finding) => buildFinding(finding))),
      'Local matches are deterministic; possible matches mark incomplete evidence'
    )
  );

  if (machine.platform !== 'web') sections.push(
    section(
      'Listening endpoints',
      machine.endpoints?.length ?? 0,
      (machine.endpoints?.length ?? 0) === 0
        ? el('p', { class: 'muted small', text: machine.status === 'collecting' ? 'Collecting…' : 'No listening endpoints were collected.' })
        : el('div', { class: 'table-wrap tall' }, [
            el('table', { class: 'table' }, [
              el('thead', {}, [
                el('tr', {}, ['Proto', 'Local address', 'Port', 'State', 'Process', 'PID', 'Service'].map((label) => el('th', { text: label })))
              ]),
              el(
                'tbody',
                {},
                [...(machine.endpoints ?? [])]
                  .sort((a, b) => a.protocol.localeCompare(b.protocol) || a.port - b.port)
                  .map((endpoint) =>
                    el('tr', {}, [
                      el('td', { class: 'mono', text: String(endpoint.protocol).toUpperCase() }),
                      el('td', { class: 'mono', text: endpoint.address }),
                      el('td', { class: 'mono', text: String(endpoint.port) }),
                      el('td', { text: endpoint.state ?? '—' }),
                      el('td', { text: endpoint.process ?? 'Unknown' }),
                      el('td', { class: 'mono', text: endpoint.pid === null || endpoint.pid === undefined ? '—' : String(endpoint.pid) }),
                      el('td', { text: endpoint.service ?? '—' })
                    ])
                  )
              )
            ])
          ])
    )
  );

  if (machine.platform !== 'web') sections.push(
    section(
      'Installed software',
      machine.software?.length ?? 0,
      (machine.software?.length ?? 0) === 0
        ? el('p', { class: 'muted small', text: machine.status === 'collecting' ? 'Collecting…' : 'No installed applications were reported.' })
        : el('div', { class: 'table-wrap tall' }, [
            el('table', { class: 'table' }, [
              el('thead', {}, [el('tr', {}, ['Application', 'Version', 'Publisher', 'Scope'].map((label) => el('th', { text: label })))]),
              el(
                'tbody',
                {},
                (machine.software ?? []).map((app) =>
                  el('tr', {}, [
                    el('td', { text: app.name }),
                    el('td', { class: 'mono', text: app.version ?? 'Not reported' }),
                    el('td', { text: app.publisher ?? '—' }),
                    el('td', { text: app.scope ?? '—' })
                  ])
                )
              )
            ])
          ]),
      machine.sample ? 'Synthetic values' : 'From the uninstall registry'
    )
  );

  const checks = machine.configChecks ?? [];
  sections.push(
    section(
      'Security configuration',
      checks.length,
      checks.length === 0
        ? el('p', { class: 'muted small', text: machine.status === 'collecting' ? 'Collecting…' : 'No configuration checks were collected.' })
        : el('div', { class: 'table-wrap' }, [
            el('table', { class: 'table compact' }, [
              el('thead', {}, [el('tr', {}, ['Check', 'Category', 'Result', 'Observed'].map((label) => el('th', { text: label })))]),
              el(
                'tbody',
                {},
                checks.map((check) =>
                  el('tr', {}, [
                    el('td', { class: 'mono', text: check.id }),
                    el('td', { text: check.category }),
                    el('td', {}, [statusBadge(check.status, check.status)]),
                    el('td', { class: 'mono small wrap', text: summarizeObserved(check) })
                  ])
                )
              )
            ])
          ]),
      'Unknown means the current user could not read the setting'
    )
  );

  if (machine.updates) {
    const updates = machine.updates;
    sections.push(
      section(
        updates.platform === 'linux' ? 'Linux updates' : 'Windows updates',
        updates.hotfixCount ?? updates.hotfixes?.length ?? 0,
        el('div', {}, [
          el('div', { class: 'chip-row' }, [
            el('span', { class: 'chip chip-muted', text: `${updates.updateService?.name ?? 'wuauserv'}: ${updates.updateService?.status ?? 'unknown'}` }),
            el('span', { class: `chip ${updates.pendingReboot ? 'chip-warn' : 'chip-muted'}`, text: `reboot pending: ${updates.pendingReboot ? 'yes' : 'no'}` }),
            el('span', { class: 'chip chip-muted', text: `last search: ${formatDate(updates.lastSearchSuccess)}` }),
            el('span', { class: 'chip chip-muted', text: `last install: ${formatDate(updates.lastInstallSuccess)}` })
          ]),
          (updates.hotfixes?.length ?? 0) === 0
            ? el('p', { class: 'muted small', text: 'No hotfixes were reported for the current user.' })
            : el('div', { class: 'table-wrap' }, [
                el('table', { class: 'table compact' }, [
                  el('thead', {}, [el('tr', {}, ['Hotfix', 'Description', 'Installed'].map((label) => el('th', { text: label })))]),
                  el(
                    'tbody',
                    {},
                    (updates.hotfixes ?? []).slice(0, 12).map((hotfix) =>
                      el('tr', {}, [
                        el('td', { class: 'mono', text: hotfix.id }),
                        el('td', { text: hotfix.description ?? '—' }),
                        el('td', { text: formatDate(hotfix.installedOn) })
                      ])
                    )
                  )
                ]),
                (updates.hotfixes?.length ?? 0) > 12
                  ? el('p', { class: 'muted small', text: `…and ${(updates.hotfixes?.length ?? 0) - 12} more hotfixes.` })
                  : null
              ])
        ]),
        'What the current user can read; some queries need elevation'
      )
    );
  }

  return sections;
}

function infoPair(label, value) {
  const valueNode = el('div', { class: 'info-value' });
  if (value instanceof Node) valueNode.append(value);
  else valueNode.textContent = value ?? '—';
  return el('div', { class: 'info-pair' }, [el('span', { class: 'info-label', text: label }), valueNode]);
}

function statusBadge(status, label) {
  const normalized = String(status ?? 'unknown').toLowerCase();
  const tone = normalized === 'ok' || normalized === 'complete' ? 'ok' : normalized === 'weak' || normalized === 'error' ? 'bad' : normalized === 'info' ? 'info' : 'warn';
  return el('span', { class: `status status-${tone}`, text: label ?? normalized });
}

function summarizeObserved(check) {
  const observed = check.observed ?? {};
  if (observed.unknownReason) return `Unknown: ${observed.unknownReason}`;
  let text;
  try {
    text = JSON.stringify(observed);
  } catch {
    text = String(observed);
  }
  if (!text) return '—';
  return text.length > 220 ? `${text.slice(0, 220)}…` : text;
}

function buildFinding(finding) {
  const details = el('article', { class: `finding sev-${finding.severity}` });
  const reasons = finding.confidenceReasons ?? [];

  const head = el('div', { class: 'finding-head' }, [
    el('span', { class: `sev-badge sev-${finding.severity}`, text: severityLabel(finding.severity) }),
    el('h4', { text: finding.title }),
    el('span', {
      class: `badge ${finding.confidence === 'confirmed' ? 'badge-confirmed' : 'badge-possible'}`,
      text: finding.confidence === 'confirmed' ? 'Confirmed match' : 'Possible match',
      attrs: reasons.length ? { title: reasons.join(' ') } : undefined
    })
  ]);

  const fields = el('dl', { class: 'finding-fields' }, [
    el('dt', { text: 'Source' }),
    el('dd', {}, [
      safeLink(finding.source?.url, `${finding.source?.name ?? 'Advisory'}${finding.source?.id ? ` · ${finding.source.id}` : ''}`)
    ]),
    el('dt', { text: 'Observed' }),
    el('dd', { class: 'mono', text: finding.observed ?? '—' }),
    el('dt', { text: 'Affected range' }),
    el('dd', { class: 'mono', text: finding.affectedRange ?? '—' }),
    el('dt', { text: 'Fix' }),
    el('dd', { text: finding.fix ?? '—' })
  ]);

  const blocks = [head, el('p', { class: 'finding-summary', text: finding.summary ?? '' }), fields];

  if (reasons.length > 0) {
    blocks.push(
      el('div', { class: 'confidence-reasons' }, [
        el('strong', { text: 'Why this is only a possible match: ' }),
        reasons.join(' ')
      ])
    );
  }

  if (finding.ai) {
    blocks.push(
      el('div', { class: 'ai-block' }, [
        el('div', { class: 'ai-head' }, [
          el('span', { class: 'badge badge-ai', text: 'AI-assisted · unverified' }),
          el('span', { class: 'muted small', text: `${finding.ai.job} review · agent confidence ${finding.ai.confidence} · agent severity ${finding.ai.severity}` })
        ]),
        el('p', { text: finding.ai.risk }),
        el('p', { class: 'ai-fix' }, [el('strong', { text: 'Suggested remediation: ' }), finding.ai.remediation])
      ])
    );
  }

  details.append(...blocks);
  return details;
}

function upsertCollector(data) {
  const list = state.assessment.collectors;
  const existing = list.find((collector) => collector.id === data.collector);
  const next = {
    id: data.collector,
    label: data.label,
    status: data.status,
    durationMs: data.durationMs ?? existing?.durationMs ?? null,
    error: data.error ?? existing?.error ?? null
  };
  if (existing) Object.assign(existing, next);
  else list.push(next);
}

function renderProgress() {
  const panel = $('progress');
  if (state.assessment.status === 'idle' && !state.assessment.id) {
    panel.hidden = true;
    panel.replaceChildren();
    return;
  }
  panel.hidden = false;
  const collectors = [ ...(
    state.assessment.collectors.length > 0
      ? state.assessment.collectors
      : (state.meta?.collectors ?? []).map((collector) => ({ id: collector.id, label: collector.label, status: 'pending' }))) ];
  const addStage = (stage) => {
    const status = stage.status ?? 'pending';
    collectors.push({ ...stage, note: status,
      status: ['complete', 'stopped', 'skipped', 'ok'].includes(status) ? 'ok'
        : ['error', 'partial', 'limit-reached', 'failed'].includes(status) ? 'error'
          : status === 'running' ? 'running' : 'pending' });
  };
  const planner = state.live?.web?.planner;
  if (planner && planner.status !== 'not-requested') {
    addStage({ id: 'web-planner', label: 'Adaptive web agent', status: planner.status });
  }
  if (state.assessment.aiRequested || state.assessment.ai?.requested) {
    const jobs = state.assessment.ai?.jobs;
    for (const stage of jobs?.length ? jobs : [
      { id: 'software', label: 'Software & OS advisory review' },
      { id: 'configuration', label: 'Security configuration review' },
      { id: 'validation', label: 'Evidence validation and attack-path analysis' }
    ]) addStage(stage);
  }

  const finished = collectors.filter((collector) => collector.status === 'ok' || collector.status === 'error').length;
  const percent = collectors.length === 0 ? 0 : Math.round((finished / collectors.length) * 100);

  const bar = el('progress', {
    class: 'bar',
    max: Math.max(1, collectors.length),
    value: finished,
    attrs: { 'aria-label': 'Collector progress' }
  });
  const tiles = collectors.map((collector) => {
    const tone =
      collector.status === 'ok'
        ? 'ok'
        : collector.status === 'error'
          ? 'bad'
          : collector.status === 'running'
            ? 'running'
            : 'idle';
    return el('div', { class: `collector-tile tile-${tone}` }, [
      el('span', { class: `tile-dot dot-${tone}` }),
      el('span', { class: 'tile-label', text: collector.label ?? collector.id }),
      el('span', {
        class: 'tile-meta',
        text: collector.note ?? (
          collector.status === 'running'
            ? 'running…'
            : collector.status === 'pending'
              ? 'queued'
              : `${collector.status === 'ok' ? 'done' : 'failed'} · ${formatDuration(collector.durationMs)}`)
      }),
      collector.error ? el('span', { class: 'tile-error', text: collector.error, attrs: { title: collector.error } }) : null
    ]);
  });

  panel.replaceChildren(
    el('div', { class: 'progress-head' }, [
      el('span', { class: 'muted small', text: `${finished} of ${collectors.length} pipeline stages finished` }),
      el('span', { class: 'mono small', text: `${percent}%` })
    ]),
    bar,
    el('div', { class: 'collector-grid' }, tiles)
  );
}

function renderNotices() {
  const container = $('notices');
  const items = [];
  const web = state.live?.web;
  if (web) {
    items.push({ id: 'web-progress', tone: ['partial', 'error'].includes(web.status) ? 'warn' : 'info', title: `Web assessment - ${web.status}`, message: `${web.requests ?? 0}/${web.maxRequests ?? 10} requests. ${web.endpoint ?? ''}` });
    if (web.planner && web.planner.status !== 'not-requested') {
      items.push({ id: 'web-planner', tone: web.planner.status === 'error' ? 'warn' : 'info', title: `AI web agent - ${web.planner.status}`,
        message: (web.planner.decisions ?? []).map((step) => `${step.action} (${step.selectedBy})`).join(', ') || 'Waiting for input checks.' });
    }
    for (const warning of web.warnings ?? []) items.push({ id: `web:${warning}`, tone: 'warn', title: 'Web coverage', message: warning });
  }

  for (const error of state.live?.errors ?? []) {
    items.push({ id: `collector:${error.collector}`, tone: 'error', title: `${error.label ?? error.collector} failed`, message: error.message });
  }
  for (const warning of state.live?.warnings ?? []) {
    items.push({ id: `warning:${warning.source}:${warning.message}`, tone: 'warn', title: warning.source, message: warning.message });
  }
  for (const notice of state.notices) items.push(notice);

  const ai = state.assessment.ai;
  const agent = state.assessment.agent;
  if (agent && !['pending', 'not-requested'].includes(agent.status)) {
    items.push({
      id: 'cve-agent', tone: ['partial', 'error', 'skipped'].includes(agent.status) ? 'warn' : 'info',
      title: `CVE agent - ${agent.status === 'running' ? agent.phase : agent.status}`,
      message: `${agent.queried ?? 0}/${agent.packages ?? 0} source packages queried, ${agent.verifiedAdvisories ?? 0}/${agent.matchedAdvisories ?? 0} advisories checked, ${agent.requests ?? 0}/24 requests, ${agent.reusedResponses ?? 0} reused responses.`
    });
    for (const warning of agent.warnings ?? []) {
      items.push({ id: `agent:${warning}`, tone: 'warn', title: 'CVE coverage', message: warning });
    }
  }
  if (ai?.status === 'disabled' && ai.reason) {
    items.push({ id: 'ai-disabled', tone: 'info', title: 'AI review skipped', message: ai.reason });
  }
  if (ai?.status === 'error' && ai.reason) {
    items.push({ id: 'ai-error', tone: 'error', title: 'AI review failed', message: ai.reason });
  }
  for (const job of ai?.jobs ?? []) {
    if (job.status === 'error') {
      items.push({ id: `ai-job:${job.id}:${job.error}`, tone: 'warn', title: `${job.label} failed`, message: job.error ?? 'Unknown AI error' });
    }
  }

  if (items.length === 0) {
    container.hidden = true;
    container.replaceChildren();
    return;
  }

  container.hidden = false;
  container.replaceChildren(
    ...items.map((item) =>
      el('div', { class: `notice notice-${item.tone}` }, [
        el('strong', { text: item.title }),
        el('span', { text: item.message })
      ])
    )
  );
}

function connectStream(assessmentId) {
  if (state.assessment.source) state.assessment.source.close();
  const source = new EventSource(`/api/assessments/${assessmentId}/events`);
  state.assessment.source = source;
  source.addEventListener('web', (event) => {
    try {
      const { checks, ...web } = JSON.parse(event.data);
      if (state.live) {
        state.live.web = web;
        state.live.configChecks = checks;
      }
      if (web.status === 'running') setStatus('Web security checks are running...', 'running');
      renderProgress();
      renderNotices();
    } catch {
      addNotice('warn', 'Stream warning', 'A web assessment event could not be parsed.', 'stream-web');
    }
  });
  source.addEventListener('agent', (event) => {
    try {
      state.assessment.agent = JSON.parse(event.data);
      if (state.assessment.agent.status === 'running') setStatus(`CVE agent is ${state.assessment.agent.phase} advisories...`, 'running');
      renderNotices();
    } catch {
      addNotice('warn', 'Stream warning', 'A CVE agent event could not be parsed.', 'stream-agent');
    }
  });

  source.addEventListener('machine', (event) => {
    try {
      const data = JSON.parse(event.data);
      state.live = data.machine;
      renderAll();
    } catch {
      addNotice('warn', 'Stream warning', 'A machine event could not be parsed.', 'stream-machine');
    }
  });

  source.addEventListener('collector', (event) => {
    try {
      applyCollectorEvent(JSON.parse(event.data));
      renderAll();
    } catch {
      addNotice('warn', 'Stream warning', 'A collector event could not be parsed.', 'stream-collector');
    }
  });

  source.addEventListener('progress', (event) => {
    try {
      state.assessment.progress = JSON.parse(event.data);
      renderProgress();
    } catch {
      /* progress display is advisory */
    }
  });

  source.addEventListener('findings', (event) => {
    try {
      const data = JSON.parse(event.data);
      if (state.live) {
        state.live.findings = data.findings ?? [];
        if (data.totals) state.live.totals = data.totals;
      }
      renderAll();
    } catch {
      addNotice('warn', 'Stream warning', 'A findings event could not be parsed.', 'stream-findings');
    }
  });

  source.addEventListener('ai', (event) => {
    try {
      state.assessment.ai = JSON.parse(event.data);
      renderProgress();
      if (state.assessment.ai.status === 'running') {
        setStatus('AI review jobs are running concurrently…', 'running');
      }
      renderNotices();
      maybeShowAiButton();
    } catch {
      addNotice('warn', 'Stream warning', 'An AI event could not be parsed.', 'stream-ai');
    }
  });

  source.addEventListener('error', async (event) => {
    if (event?.data) {
      try {
        const data = JSON.parse(event.data);
        addNotice('error', 'Assessment error', data.message ?? 'The assessment stopped unexpectedly.', 'assessment-error');
      } catch {
        /* ignore malformed fatal event */
      }
      return;
    }
    if (!state.assessment.done) {
      try {
        await apiFetch('/api/health');
      } catch {
        return;
      }
      setStatus('Result stream interrupted — reconnecting…', 'warn');
    }
  });

  source.addEventListener('done', async (event) => {
    try {
      const data = JSON.parse(event.data);
      state.assessment.done = true;
      state.assessment.status = data.status;
      source.close();
      state.assessment.source = null;
      state.busy = false;
      $('start-btn').disabled = false;

      if (data.status === 'complete' && state.live?.platform === 'web') {
        setStatus(`Web assessment complete. ${data.totals?.findings ?? 0} findings, ${state.live.web?.requests ?? 0} requests.`, 'ok');
      } else if (data.status === 'complete') {
        setStatus(
          `Assessment complete — ${data.totals?.endpoints ?? 0} endpoints, ${data.totals?.software ?? 0} applications, ${data.totals?.findings ?? 0} findings (${data.totals?.possible ?? 0} possible).`,
          'ok'
        );
      } else if (data.status === 'partial') {
        setStatus(
          `Assessment finished with partial coverage. ${(state.live?.errors ?? []).length} collector errors. Check the coverage notices below.`,
          'warn'
        );
      } else {
        setStatus('Assessment failed — no collector completed. See the errors below.', 'bad');
      }
      $('assessment-time').textContent = data.completedAt ? `Finished ${formatDate(data.completedAt)}` : '';

      await refreshSnapshot();
      state.notices = state.notices.filter((notice) => !notice.id.startsWith('stream-'));
      renderAll();
      maybeShowAiButton();
    } catch (error) {
      setStatus('Assessment finished, but the final snapshot could not be loaded.', 'warn');
      addNotice('warn', 'Snapshot refresh failed', String(error?.message ?? error), 'snapshot-refresh');
      state.busy = false;
      $('start-btn').disabled = false;
    }
  });
}

function applyCollectorEvent(data) {
  if (!state.live) return;
  const machine = state.live;
  const summary = data.machineSummary ?? {};

  if (data.status === 'ok' && data.data) {
    switch (data.collector) {
      case 'host': {
        machine.host = data.data;
        machine.hostname = data.data.hostname ?? machine.hostname;
        machine.ips = (data.data.addresses ?? []).map((address) => address.address).filter(Boolean);
        break;
      }
      case 'ports':
        machine.endpoints = data.data.endpoints ?? [];
        break;
      case 'software':
        machine.software = data.data.software ?? [];
        break;
      case 'updates':
        machine.updates = data.data;
        break;
      case 'config':
        machine.configChecks = data.data.checks ?? [];
        break;
      default:
        break;
    }
  }

  if (summary.machineType) machine.machineType = summary.machineType;
  if (summary.primaryIp !== undefined) machine.primaryIp = summary.primaryIp;
  if (Array.isArray(summary.ips)) machine.ips = summary.ips;

  if (data.status === 'error') {
    machine.errors = [...(machine.errors ?? []), { collector: data.collector, label: data.label, kind: data.kind, message: data.error }];
  }

  machine.timestamps = machine.timestamps ?? { collectors: {} };
  machine.timestamps.collectors = machine.timestamps.collectors ?? {};
  machine.timestamps.collectors[data.collector] = {
    status: data.status,
    durationMs: data.durationMs ?? null,
    at: new Date().toISOString()
  };

  upsertCollector(data);
}

async function refreshSnapshot() {
  if (!state.assessment.id) return;
  const response = await apiFetch(`/api/assessments/${state.assessment.id}`);
  if (!response.ok) throw new Error(`Snapshot request failed (HTTP ${response.status})`);
  const snapshot = await response.json();
  state.live = snapshot.machine;
  state.assessment.ai = snapshot.ai;
  state.assessment.agent = snapshot.agent;
  state.assessment.collectors = snapshot.collectors ?? state.assessment.collectors;
}

async function saveAiKey(event) {
  event.preventDefault();
  const button = $('ai-save-btn');
  const status = $('ai-settings-status');
  button.disabled = true;
  status.textContent = 'Saving...';
  try {
    const response = await apiFetch('/api/settings/ai', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-ares-request': 'dashboard' },
      body: JSON.stringify({ apiKey: $('ai-api-key').value.trim() })
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(body.error || `Could not save settings (HTTP ${response.status})`);
    state.meta = { ...state.meta, ai: body.ai };
    $('ai-api-key').value = '';
    applyMeta();
    maybeShowAiButton();
    status.textContent = 'Saved. OpenCode DeepSeek V4.1 Flash is configured.';
  } catch (error) {
    status.textContent = String(error?.message ?? error);
  } finally {
    button.disabled = false;
  }
}

async function startAssessment() {
  if (state.busy) return;
  state.busy = true;
  $('start-btn').disabled = true;
  $('ai-run-btn').hidden = true;
  state.open.clear();
  state.live = null;
  state.notices = [];
  state.assessment = {
    id: null,
    status: 'running',
    collectors: [],
    progress: null,
    ai: null,
    agent: null,
    aiRequested: Boolean(state.meta?.ai?.available),
    done: false,
    source: null,
    startedAt: new Date().toISOString()
  };
  $('assessment-time').textContent = '';
  renderAll();
  setStatus('Starting assessment…', 'running');

  if ($('ai-toggle').checked && !state.meta?.ai?.available) {
    addNotice('warn', 'AI review unavailable', 'No backend AI provider is configured. The local assessment runs normally.', 'ai-unavailable');
  }

  try {
    let target = $('target-mode').value === 'ssh'
      ? { mode: 'ssh', host: $('ssh-host').value.trim(), port: Number($('ssh-port').value), username: $('ssh-username').value.trim() }
      : { mode: 'local' };
    if ($('target-mode').value === 'web') {
      target = { mode: 'web', url: $('web-url').value.trim(), activeChecks: $('web-input-checks').checked };
    }
    const response = await apiFetch('/api/assessments', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-ares-request': 'dashboard' },
      body: JSON.stringify({ aiReview: $('ai-toggle').checked, vulnerabilityLookup: $('vulnerability-toggle').checked, target })
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(body.error || `Backend returned HTTP ${response.status}`);
    state.assessment.id = body.assessmentId;
    setStatus('Collectors are running concurrently…', 'running');
    connectStream(body.assessmentId);
  } catch (error) {
    state.busy = false;
    $('start-btn').disabled = false;
    setStatus('Assessment could not be started.', 'bad');
    addNotice('error', 'Start failed', String(error?.message ?? error), 'start-failed');
    renderAll();
  }
}

function maybeShowAiButton() {
  const ai = state.assessment.ai;
  const available = Boolean(state.meta?.ai?.available);
  const finished = state.assessment.done;
  const alreadyRunning = ai?.status === 'running';
  const hasItems = (ai?.jobs ?? []).some((job) => (job.items ?? []).length > 0);
  const canRun = available && finished && !alreadyRunning && !hasItems && (!ai || ['not-requested', 'pending', 'error'].includes(ai.status));
  $('ai-run-btn').hidden = !canRun;
  $('ai-run-btn').disabled = alreadyRunning;
}

async function runAiReview() {
  if (!state.assessment.id) return;
  $('ai-run-btn').disabled = true;
  setStatus('AI review jobs are running concurrently…', 'running');
  try {
    const response = await apiFetch(`/api/assessments/${state.assessment.id}/ai-review`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-ares-request': 'dashboard' },
      body: JSON.stringify({ consent: true })
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(body.error || `HTTP ${response.status}`);
    state.assessment.ai = body;
    await refreshSnapshot();
    renderAll();
    if (body.status === 'complete' || body.status === 'partial') {
      const accepted = (body.merged ?? []).length;
      setStatus(`AI review finished — ${accepted} analysis item${accepted === 1 ? '' : 's'} attached to local findings.`, 'ok');
      addNotice('info', 'AI review finished', `${accepted} validated item(s) were merged into the findings below. AI text is advisory and does not change local severity.`, 'ai-finished');
    } else {
      setStatus('AI review did not produce usable output. Local findings are unchanged.', 'warn');
      addNotice('warn', 'AI review produced no usable output', 'The provider response failed schema validation or all review jobs failed.', 'ai-empty');
    }
  } catch (error) {
    addNotice('error', 'AI review failed', String(error?.message ?? error), 'ai-failed');
    setStatus('AI review failed. Local findings are unchanged.', 'warn');
  } finally {
    $('ai-run-btn').disabled = false;
    maybeShowAiButton();
    renderNotices();
  }
}

init();
