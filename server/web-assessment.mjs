import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { randomBytes } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { buildFinding, sortFindings } from './findings.mjs';
import { chooseWebAction } from './ai/planner.mjs';

const SOURCE = { name: 'OWASP Web Security Testing Guide', url: 'https://wstg.owasp.org/v4.2/' };
const MAX_REQUESTS = 10;
const SQL_ERRORS = [
  ['mysql', /you have an error in your sql syntax/i],
  ['sqlstate', /SQLSTATE\[[0-9A-Z]{5}\]/i],
  ['postgresql', /(?:PostgreSQL[^\n]{0,80}ERROR|pg_query\(\)[^\n]{0,80}(?:error|failed))/i],
  ['mssql', /Unclosed quotation mark after the character string/i],
  ['oracle', /ORA-\d{5}/],
  ['sqlite', /sqlite(?:3)?\.(?:Operational|Database)Error|SQLite(?:Exception| error)|SQLITE_ERROR|unrecognized token:\s*["']/i]
];

function safeUrl(value) {
  const url = new URL(value);
  for (const key of [...url.searchParams.keys()]) url.searchParams.set(key, '[value]');
  return url.href;
}

function sameScope(initial, destination) {
  return destination.origin === initial.origin ||
    (initial.protocol === 'http:' && !initial.port && destination.protocol === 'https:' && !destination.port && destination.hostname === initial.hostname);
}

function comparableBody(response, values) {
  let body = response.body;
  const variants = values.filter(Boolean).flatMap((value) => [
    value, encodeURIComponent(value),
    value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;')
  ]).sort((a, b) => b.length - a.length);
  for (const value of new Set(variants)) body = body.replaceAll(value, '');
  return body.replace(/\s+/g, ' ').trim();
}

export function compareBooleanSqlResponses(baseline, repeated, whenTrue, whenFalse, values) {
  const baselineBody = comparableBody(baseline, values);
  const sameStatus = [repeated, whenTrue, whenFalse].every((response) => response.status === baseline.status);
  const contentType = String(baseline.headers['content-type'] ?? '').split(';')[0].trim().toLowerCase();
  const sameType = [repeated, whenTrue, whenFalse].every((response) =>
    String(response.headers['content-type'] ?? '').split(';')[0].trim().toLowerCase() === contentType);
  const baselineStable = repeated.status === baseline.status && comparableBody(repeated, values) === baselineBody;
  const trueMatchesBaseline = comparableBody(whenTrue, values) === baselineBody;
  const falseDiffersFromBaseline = comparableBody(whenFalse, values) !== baselineBody;
  return { baselineStable, trueMatchesBaseline, falseDiffersFromBaseline, sameStatus, sameType,
    detected: baseline.status >= 200 && baseline.status < 300 && sameStatus && sameType && baselineStable && trueMatchesBaseline && falseDiffersFromBaseline };
}

export function requestWebPage(url, { headers = {}, timeoutMs = 10000 } = {}) {
  return new Promise((resolve, reject) => {
    const request = (url.protocol === 'https:' ? httpsRequest : httpRequest)(url, {
      method: 'GET',
      headers: { 'user-agent': 'Ares-Web-Assessment/1.0', accept: 'text/html,application/json;q=0.8,*/*;q=0.1', 'accept-encoding': 'identity', ...headers },
      signal: AbortSignal.timeout(timeoutMs),
      maxHeaderSize: 16 * 1024
    }, (response) => {
      const chunks = [];
      let bytes = 0;
      const certificate = response.socket.getPeerCertificate?.();
      const tls = url.protocol === 'https:' ? { protocol: response.socket.getProtocol?.(), validTo: certificate?.valid_to } : null;
      response.on('data', (chunk) => {
        bytes += chunk.length;
        if (bytes > 1024 * 1024) {
          response.destroy(new Error('Response exceeded the 1 MiB limit.'));
          return;
        }
        chunks.push(chunk);
      });
      response.on('error', reject);
      response.on('end', () => resolve({ status: response.statusCode, headers: response.headers, body: Buffer.concat(chunks).toString('utf8'), bytes, tls }));
    });
    request.on('error', reject);
    request.end();
  });
}

export function inspectWebResponse(response, url) {
  const checks = [];
  const add = (id, status, observed, detail) => checks.push({ id: `web-${id}`, category: 'web', status, observed, detail });
  const headers = response.headers;
  const html = /(?:text\/html|application\/xhtml\+xml)/i.test(String(headers['content-type'] ?? ''));
  add('transport', url.protocol === 'https:' ? 'ok' : 'weak', { encrypted: url.protocol === 'https:' }, 'Observed transport for the selected endpoint');
  if (url.protocol === 'https:') {
    const hsts = String(headers['strict-transport-security'] ?? '');
    const hstsEnabled = /(?:^|;)\s*max-age\s*=\s*"?[1-9]\d*"?\s*(?:;|$)/i.test(hsts);
    add('hsts', hstsEnabled ? 'ok' : 'weak', { enabled: hstsEnabled }, 'HSTS must have a positive max-age');
    if (response.tls?.validTo) {
      const daysRemaining = Math.floor((Date.parse(response.tls.validTo) - Date.now()) / 86400000);
      add('certificate', daysRemaining < 30 ? 'weak' : 'ok', { daysRemaining }, 'Certificate expiry for the current verified TLS connection');
    }
  }
  if (html) {
    const csp = String(headers['content-security-policy'] ?? '');
    add('csp', csp.trim() ? 'ok' : 'weak', { present: Boolean(csp.trim()) }, 'An enforced CSP helps constrain content execution');
    const framing = String(headers['x-frame-options'] ?? '').trim();
    const ancestors = /(?:^|;)\s*frame-ancestors\s+([^;]+)/i.exec(csp)?.[1]?.trim();
    const frameRestricted = /^(DENY|SAMEORIGIN)$/i.test(framing) || Boolean(ancestors && !ancestors.split(/\s+/).includes('*'));
    add('framing', frameRestricted ? 'ok' : 'weak', { restricted: frameRestricted }, 'Observed framing policy needs application context to assess clickjacking impact');
    add('nosniff', String(headers['x-content-type-options'] ?? '').toLowerCase().trim() === 'nosniff' ? 'ok' : 'weak',
      { enabled: String(headers['x-content-type-options'] ?? '').toLowerCase().trim() === 'nosniff' }, 'MIME sniffing protection');
    const directory = /<title>\s*Index of\s/i.test(response.body) && /<a\s[^>]*href=["'][^"']*["']/i.test(response.body);
    add('directory-listing', directory ? 'weak' : 'ok', { detected: directory }, 'Directory index signature in the selected response');
    const debug = /Traceback \(most recent call last\)|Exception in thread|Stack trace:|Microsoft ASP\.NET Version|Werkzeug Debugger/i.test(response.body);
    add('debug-output', debug ? 'weak' : 'ok', { detected: debug }, 'Framework diagnostic signature in the selected response');
  }
  const sessionCookies = [].concat(headers['set-cookie'] ?? []).filter((cookie) => /^(?:[^=;]*session[^=;]*|[^=;]*auth[^=;]*|[^=;]*token[^=;]*|sid|PHPSESSID|JSESSIONID)=/i.test(cookie));
  for (const [attribute, pattern] of [['secure', /;\s*Secure\s*(?:;|$)/i], ['httponly', /;\s*HttpOnly\s*(?:;|$)/i], ['samesite', /;\s*SameSite\s*=\s*(?:Strict|Lax|None)\s*(?:;|$)/i]]) {
    if (!sessionCookies.length) continue;
    const missing = sessionCookies.filter((cookie) => !pattern.test(cookie)).length;
    add(`cookie-${attribute}`, missing ? 'weak' : 'ok', { sessionCookies: sessionCookies.length, missing }, `Session-like cookie ${attribute} attribute check`);
  }
  return checks;
}

const RULES = {
  'web-tls-validation': ['medium', 'TLS certificate validation failed', 'Check the certificate hostname, expiry and chain against the client trust configuration.', 'possible'],
  'web-transport': ['medium', 'The selected endpoint uses cleartext HTTP', 'Serve the application over HTTPS and redirect HTTP traffic to HTTPS.', 'confirmed'],
  'web-hsts': ['low', 'HSTS is absent or disabled', 'Set Strict-Transport-Security with a positive max-age after validating HTTPS deployment.', 'confirmed'],
  'web-certificate': ['low', 'TLS certificate renewal is due soon', 'Renew the certificate and verify automated renewal before expiry.', 'confirmed'],
  'web-csp': ['low', 'An enforced Content Security Policy is absent', 'Deploy and test an application-specific Content-Security-Policy.', 'possible'],
  'web-framing': ['low', 'The response has no restrictive framing policy', "Use CSP frame-ancestors 'none' or an explicit trusted origin policy where framing is unnecessary.", 'possible'],
  'web-nosniff': ['low', 'MIME sniffing protection is absent', 'Serve correct Content-Type values and set X-Content-Type-Options: nosniff.', 'possible'],
  'web-directory-listing': ['medium', 'A directory index is visible', 'Disable automatic directory indexes for application directories.', 'possible'],
  'web-debug-output': ['medium', 'Framework diagnostic output is visible', 'Disable public debug output and return generic error pages while retaining server-side diagnostics.', 'possible'],
  'web-cookie-secure': ['medium', 'Session-like cookies lack Secure', 'Set Secure on session cookies and serve authentication over HTTPS.', 'possible'],
  'web-cookie-httponly': ['medium', 'Session-like cookies lack HttpOnly', 'Use HttpOnly for session cookies that client-side JavaScript does not need to read.', 'possible'],
  'web-cookie-samesite': ['low', 'Session-like cookies lack an explicit SameSite policy', 'Set an appropriate SameSite policy and verify cross-site authentication flows.', 'possible'],
  'web-cors': ['medium', 'CORS reflects multiple arbitrary origins with credentials enabled', 'Allow only explicit trusted origins and enable credentialed CORS solely for endpoints that require it.', 'possible'],
  'web-reflection': ['medium', 'A query parameter reflects unescaped HTML markup', 'Apply output encoding for the rendering context and validate the value server-side.', 'possible'],
  'web-sql-error': ['medium', 'A quoted parameter triggers a database error signature', 'Use parameterized queries, validate inputs and return generic errors. Verify the suspected injection with an authorized contextual test.', 'possible'],
  'web-sql-boolean': ['high', 'Boolean-based SQL injection behavior observed', 'Replace SQL string concatenation with parameterized queries and enforce server-side input validation. Recheck the paired true/false behavior after patching.', 'possible']
};

export function webFindings(checks) {
  return sortFindings(checks.filter((check) => check.status === 'weak' && RULES[check.id]).map((check) => {
    const [severity, title, fix, confidence] = RULES[check.id];
    return buildFinding({
      kind: 'configuration', category: 'web', key: `${check.id}|${JSON.stringify(check.observed)}`,
      severity, title, fix, confidence, source: SOURCE,
      summary: check.detail, observed: JSON.stringify(check.observed), affectedRange: 'Observed web response',
      confidenceReasons: confidence === 'possible' ? ['The response provides a signal. Exploitability and application impact require contextual validation.'] : [],
      evidenceLabel: check.id,
      aiEvidence: { kind: 'configuration', checkId: check.id, category: 'web', observed: Object.fromEntries(Object.entries(check.observed).filter(([key]) => key !== 'parameter')) }
    });
  }));
}

export async function runWebAssessment({ target, aiConfig = null, onUpdate = () => {}, requestPage = requestWebPage, intervalMs = 1000, chooseAction = chooseWebAction }) {
  const initial = new URL(target.url);
  let current = initial;
  const state = { status: 'running', phase: 'web', requests: 0, maxRequests: MAX_REQUESTS, warnings: [], checks: [], findings: [], endpoint: safeUrl(initial), statusCode: null,
    planner: { status: aiConfig ? 'pending' : 'not-requested', decisions: [] } };
  let deadline = Date.now() + 30000;
  let lastRequest = 0;
  const publish = () => {
    state.findings = webFindings(state.checks);
    onUpdate({ ...state, checks: [...state.checks], findings: [...state.findings], warnings: [...state.warnings] });
  };
  const request = async (url, headers) => {
    if (state.requests >= MAX_REQUESTS || Date.now() >= deadline) throw new Error('Web assessment request or time budget reached.');
    if (url.username || url.password || !sameScope(initial, url)) throw new Error('Redirect destination requires its own web target assessment.');
    const pause = Math.max(0, lastRequest + intervalMs - Date.now());
    if (Date.now() + pause >= deadline) throw new Error('Web assessment time budget reached.');
    if (pause) await delay(pause);
    lastRequest = Date.now();
    state.requests++;
    const response = await requestPage(url, { headers, timeoutMs: Math.max(1, Math.min(10000, deadline - Date.now())) });
    if (response.status === 429) throw new Error('The target returned HTTP 429. The request limit for this target was reached.');
    return response;
  };
  publish();
  try {
    let response;
    for (let redirects = 0; redirects < 3; redirects++) {
      response = await request(current);
      if (![301, 302, 303, 307, 308].includes(response.status)) break;
      const location = response.headers.location;
      if (!location) throw new Error('Redirect response has no Location header.');
      current = new URL(location, current);
      if (redirects === 2) throw new Error('The redirect limit was reached.');
    }
    state.endpoint = safeUrl(current);
    state.statusCode = response.status;
    state.checks = inspectWebResponse(response, current);
    publish();
    if (response.status >= 500) throw new Error('The initial endpoint returned a server error. Coverage is limited to that response.');
    if (response.status >= 200 && response.status < 300) {
      const origins = ['https://ares-probe-a.invalid', 'https://ares-probe-b.invalid'];
      let reflected = 0;
      for (const origin of origins) {
        const cors = await request(current, { origin });
        if (cors.status >= 500) throw new Error('The endpoint returned a server error during the CORS check.');
        if (cors.status === response.status && cors.headers['access-control-allow-origin'] === origin && String(cors.headers['access-control-allow-credentials']).toLowerCase() === 'true') reflected++;
      }
      state.checks.push({ id: 'web-cors', category: 'web', status: reflected === 2 ? 'weak' : 'ok', observed: { reflectedOriginsWithCredentials: reflected }, detail: 'Two synthetic Origin values were reflected with credentials enabled. Sensitive authenticated response access requires contextual validation.' });
      publish();
      if (target.activeChecks) {
        const parameters = [...new Set(current.searchParams.keys())].filter((name) =>
          current.searchParams.getAll(name).length === 1 && !/pass|token|key|auth|secret|csrf/i.test(name)).slice(0, 2);
        if (!parameters.length) state.warnings.push('Input probes need an existing non-credential query parameter in the selected URL.');
        const actions = parameters.flatMap((parameter, index) => {
          const numeric = /^\d+$/.test(current.searchParams.get(parameter));
          return [
            { id: `sql-${index}`, kind: 'sql', parameter, numeric, cost: 4 },
            ...(!numeric ? [{ id: `reflection-${index}`, kind: 'reflection', parameter, numeric, cost: 1 }] : [])
          ];
        });
        let planning = Boolean(aiConfig);
        let plannerCalls = 0;
        while (actions.length && state.requests < MAX_REQUESTS) {
          const available = actions.filter((action) => action.cost <= MAX_REQUESTS - state.requests);
          if (!available.length) {
            state.warnings.push('Remaining request budget cannot fit another input check.');
            break;
          }
          let action = available[0];
          if (planning) {
            if (plannerCalls >= 4) {
              state.planner.status = 'limit-reached';
              break;
            }
            state.planner.status = 'running';
            publish();
            const started = Date.now();
            plannerCalls++;
            try {
              action = await chooseAction({ aiConfig, actions: available, checks: state.checks, decisions: state.planner.decisions, remainingRequests: MAX_REQUESTS - state.requests });
              if (action && !available.includes(action)) throw new Error('AI planner returned an unavailable action.');
            } catch {
              state.warnings.push('AI planning failed. Remaining checks use the standard sequence.');
              state.planner.status = 'error';
              planning = false;
              action = available[0];
            } finally {
              deadline += Date.now() - started;
            }
            if (!action) {
              state.planner.status = 'stopped';
              break;
            }
          }
          actions.splice(actions.indexOf(action), 1);
          state.planner.decisions.push({ action: action.id, selectedBy: planning ? 'ai' : 'standard', requestsBefore: state.requests });
          const parameter = action.parameter;
          const probe = new URL(current);
          const original = current.searchParams.get(parameter);
          const numeric = /^\d+$/.test(original);
          if (action.kind === 'sql') {
            probe.searchParams.set(parameter, `${original}'`);
            const sqlPage = await request(probe);
            const family = SQL_ERRORS.find(([, pattern]) => pattern.test(sqlPage.body) && !pattern.test(response.body))?.[0] ?? null;
            state.checks.push({ id: 'web-sql-error', category: 'web', status: family ? 'weak' : 'ok', observed: { parameter, databaseErrorFamily: family }, detail: 'Adding one quote produced a database error signature absent from the baseline response. This is a suspected injection signal.' });
            publish();
            if (sqlPage.status >= 500 && !family) throw new Error('An input probe returned an unexpected server error. Existing observations were retained.');
            if (MAX_REQUESTS - state.requests >= 3) {
              const repeated = await request(current);
              if (repeated.status !== response.status || repeated.status >= 500) throw new Error('The endpoint baseline changed after the input probe. Coverage is partial.');
              if (comparableBody(response, [original]) !== comparableBody(repeated, [original])) {
                state.checks.push({ id: 'web-sql-boolean', category: 'web', status: 'unknown', observed: { parameter, baselineStable: false }, detail: 'The repeated baseline changed before boolean SQL verification.' });
                state.warnings.push('The response baseline was unstable. Boolean SQLi comparison is inconclusive.');
                publish();
                break;
              }
              const whenTrue = numeric ? `${original} AND 1=1` : `${original}' AND '1'='1'-- `;
              const whenFalse = numeric ? `${original} AND 1=2` : `${original}' AND '1'='2'-- `;
              probe.searchParams.set(parameter, whenTrue);
              const truePage = await request(probe);
              if (truePage.status >= 500) throw new Error('The boolean SQL probe returned an unexpected server error. Existing observations were retained.');
              probe.searchParams.set(parameter, whenFalse);
              const falsePage = await request(probe);
              const comparison = compareBooleanSqlResponses(response, repeated, truePage, falsePage, [original, whenTrue, whenFalse]);
              state.checks.push({ id: 'web-sql-boolean', category: 'web', status: comparison.detected ? 'weak' : comparison.baselineStable ? 'info' : 'unknown',
                observed: { parameter, syntax: numeric ? 'numeric' : 'quoted', ...comparison },
                detail: 'A repeated baseline and paired true/false SQL predicates were compared after normalizing reflected input. The true response matched the stable baseline while the false response differed only when detected=true. This behavior requires application-context validation.' });
              publish();
              if (falsePage.status >= 500) throw new Error('The boolean SQL probe returned a server error. Existing observations were retained.');
              if (!comparison.baselineStable) state.warnings.push('The response baseline was unstable. Boolean SQLi comparison is inconclusive.');
            } else if (sqlPage.status >= 500) {
              throw new Error('The database error signal was preserved. The remaining request budget cannot verify endpoint recovery.');
            } else {
              state.warnings.push('The remaining request budget could not fit boolean SQLi verification.');
            }
            continue;
          }
          const marker = `<ares-probe-${randomBytes(8).toString('hex')}>`;
          probe.searchParams.set(parameter, marker);
          const reflectedPage = await request(probe);
          const reflectedHtml = /text\/html/i.test(String(reflectedPage.headers['content-type'] ?? '')) && reflectedPage.body.includes(marker) && !response.body.includes(marker);
          state.checks.push({ id: 'web-reflection', category: 'web', status: reflectedHtml ? 'weak' : 'ok', observed: { parameter, unescapedHtml: reflectedHtml }, detail: 'A unique inert HTML marker was reflected in an HTML response. Browser execution and a usable XSS context require validation.' });
          publish();
          if (reflectedPage.status >= 500) throw new Error('The HTML probe returned a server error. Existing observations were retained.');
        }
        if (state.planner.status === 'running') state.planner.status = 'complete';
      }
    }
    if (response.status < 200 || response.status >= 300) state.warnings.push(`The endpoint returned HTTP ${response.status}. Coverage is limited to that response.`);
    state.status = state.warnings.length ? 'partial' : 'complete';
  } catch (error) {
    if (['CERT_HAS_EXPIRED', 'DEPTH_ZERO_SELF_SIGNED_CERT', 'ERR_TLS_CERT_ALTNAME_INVALID', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'SELF_SIGNED_CERT_IN_CHAIN'].includes(error.code)) {
      state.checks.push({ id: 'web-tls-validation', category: 'web', status: 'weak', observed: { trusted: false, reasonCode: error.code }, detail: 'The current TLS connection failed certificate validation.' });
    }
    state.status = state.checks.length ? 'partial' : 'error';
    state.warnings.push(String(error.message).slice(0, 240));
  }
  if (state.planner.status === 'pending') state.planner.status = 'skipped';
  if (state.planner.status === 'running') state.planner.status = 'partial';
  state.phase = 'done';
  publish();
  return state;
}
