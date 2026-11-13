import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { APP_NAME, aiStatusForClient } from './config.mjs';
import { COLLECTORS } from './collectors/index.mjs';
import { TargetError } from './target.mjs';
import { AiSettingsError, createAiSettingsWriter } from './ai/settings.mjs';
import { AssessmentLimitError, AssessmentNotFoundError } from './assessment.mjs';
import { createAuth, LoginLimitError, SESSION_COOKIE, SESSION_TTL_MS, sessionToken } from './auth.mjs';

const MAX_BODY_BYTES = 4096;
const ASSESSMENT_ID = /^[0-9a-fA-F-]{8,64}$/;

const SECURITY_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Resource-Policy': 'same-origin',
  'Permissions-Policy': 'geolocation=(), camera=(), microphone=(), usb=()',
  'Content-Security-Policy':
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
};

const STATIC_FILES = new Map([
  ['/', { path: 'index.html', type: 'text/html; charset=utf-8' }],
  ['/index.html', { path: 'index.html', type: 'text/html; charset=utf-8' }],
  ['/login', { path: 'login.html', type: 'text/html; charset=utf-8' }],
  ['/login.js', { path: 'login.js', type: 'text/javascript; charset=utf-8' }],
  ['/app.js', { path: 'app.js', type: 'text/javascript; charset=utf-8' }],
  ['/filter.mjs', { path: 'filter.mjs', type: 'text/javascript; charset=utf-8' }],
  ['/styles.css', { path: 'styles.css', type: 'text/css; charset=utf-8' }],
  ['/favicon.svg', { path: 'favicon.svg', type: 'image/svg+xml' }]
]);

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

function sendJson(res, status, body) {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    ...SECURITY_HEADERS,
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(payload),
    'Cache-Control': 'no-store'
  });
  res.end(payload);
}

function sendText(res, status, text) {
  res.writeHead(status, {
    ...SECURITY_HEADERS,
    'Content-Type': 'text/plain; charset=utf-8',
    'Content-Length': Buffer.byteLength(text),
    'Cache-Control': 'no-store'
  });
  res.end(text);
}

function hostnameOf(hostHeader) {
  if (!hostHeader) return '';
  const value = String(hostHeader).trim().toLowerCase();
  if (value.startsWith('[')) {
    const end = value.indexOf(']');
    return end === -1 ? value : value.slice(1, end);
  }
  const colon = value.lastIndexOf(':');
  return colon === -1 ? value : value.slice(0, colon);
}

function isLoopbackHostname(hostname) {
  return hostname === '127.0.0.1' || hostname === 'localhost' || hostname === '::1';
}

function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    const timer = setTimeout(() => {
      reject(new HttpError(408, 'Request body timed out'));
      req.destroy();
    }, 5000);

    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        clearTimeout(timer);
        reject(new HttpError(413, 'Request body is too large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      clearTimeout(timer);
      const raw = Buffer.concat(chunks).toString('utf8').trim();
      if (!raw) {
        resolve({});
        return;
      }
      try {
        const parsed = JSON.parse(raw);
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
          reject(new HttpError(400, 'Request body must be a JSON object'));
          return;
        }
        resolve(parsed);
      } catch {
        reject(new HttpError(400, 'Request body must be valid JSON'));
      }
    });
    req.on('error', (error) => {
      clearTimeout(timer);
      reject(new HttpError(400, `Request stream error: ${error.message}`));
    });
  });
}

function assertAllowedKeys(body, allowed) {
  for (const key of Object.keys(body)) {
    if (!allowed.includes(key)) {
      throw new HttpError(400, `Unknown field "${key}". Only predefined operations are accepted.`);
    }
  }
}

function sseWrite(res, event) {
  res.write(`id: ${event.id}\n`);
  res.write(`event: ${event.type}\n`);
  res.write(`data: ${JSON.stringify(event.data)}\n\n`);
}

export function createAresServer({ config, logger, advisories, manager, samples, startedAt = Date.now(), auth = createAuth() }) {
  const recentAssessments = [];
  const saveAiSettings = createAiSettingsWriter(config);

  const server = createServer(async (req, res) => {
    const method = req.method ?? 'GET';
    const url = new URL(req.url ?? '/', 'http://127.0.0.1');
    const pathname = url.pathname;

    try {
      if (!isLoopbackHostname(hostnameOf(req.headers.host))) {
        sendJson(res, 421, { error: 'Invalid Host header. Ares only answers on the loopback interface.' });
        return;
      }

      if (method === 'POST') {
        if (req.headers['x-ares-request'] !== 'dashboard') {
          sendJson(res, 403, { error: 'Missing X-Ares-Request header.' });
          return;
        }
        if (req.headers.origin) {
          let originHost = '';
          try {
            originHost = new URL(req.headers.origin).host.toLowerCase();
          } catch {
            originHost = '';
          }
          if (originHost !== String(req.headers.host ?? '').toLowerCase()) {
            sendJson(res, 403, { error: 'Cross-origin requests are not allowed.' });
            return;
          }
        }
        const contentType = String(req.headers['content-type'] ?? '');
        if (!contentType.toLowerCase().startsWith('application/json')) {
          sendJson(res, 415, { error: 'Content-Type must be application/json.' });
          return;
        }
      }

      if (method === 'POST' && pathname === '/api/login') {
        const body = await readJsonBody(req);
        assertAllowedKeys(body, ['password']);
        const token = await auth.login(body.password);
        if (!token) {
          sendJson(res, 401, { error: 'Incorrect password.' });
          return;
        }
        auth.logout(sessionToken(req));
        res.setHeader('Set-Cookie', `${SESSION_COOKIE}=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${SESSION_TTL_MS / 1000}`);
        sendJson(res, 200, { authenticated: true });
        return;
      }

      const token = sessionToken(req);
      const authenticated = auth.isAuthenticated(token);
      const entryPage = ['/', '/index.html', '/login'].includes(pathname);
      const loginAsset = ['/login.js', '/styles.css', '/favicon.svg'].includes(pathname);
      if (!authenticated && !(method === 'GET' && (entryPage || loginAsset))) {
        sendJson(res, 401, { error: 'Sign in to continue.', code: 'authentication-required' });
        return;
      }

      if (method === 'POST' && pathname === '/api/logout') {
        auth.logout(token);
        res.setHeader('Set-Cookie', `${SESSION_COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0`);
        sendJson(res, 200, { authenticated: false });
        return;
      }

      // ---------------- static dashboard ----------------
      if (method === 'GET' && STATIC_FILES.has(pathname)) {
        const entry = entryPage ? { path: authenticated ? 'index.html' : 'login.html', type: 'text/html; charset=utf-8' } : STATIC_FILES.get(pathname);
        let body;
        try {
          body = await readFile(join(config.publicDir, entry.path));
        } catch {
          sendText(res, 500, 'Dashboard asset is missing.');
          return;
        }
        res.writeHead(200, {
          ...SECURITY_HEADERS,
          'Content-Type': entry.type,
          'Content-Length': body.length,
          'Cache-Control': 'no-store'
        });
        res.end(body);
        return;
      }

      // ---------------- API ----------------
      if (method === 'GET' && pathname === '/api/health') {
        sendJson(res, 200, {
          status: 'ok',
          app: APP_NAME,
          version: config.version,
          uptimeSeconds: Math.round((Date.now() - startedAt) / 1000)
        });
        return;
      }

      if (method === 'GET' && pathname === '/api/meta') {
        sendJson(res, 200, {
          app: APP_NAME,
          version: config.version,
          loopbackOnly: true,
          ai: aiStatusForClient(config),
          aiPolicy: {
            optIn: true,
            sentFields: ['software product/version', 'advisory metadata', 'configuration check id and categorical value'],
            neverSent: ['hostname', 'IP addresses', 'usernames', 'raw PowerShell output', 'file paths']
          },
          collectors: COLLECTORS.map((collector) => ({
            id: collector.id,
            label: collector.label,
            description: collector.description
          })),
          advisory: {
            snapshot: advisories.provenance?.snapshot ?? null,
            softwareEntries: advisories.software?.length ?? 0,
            lifecycleEntries: advisories.lifecycle?.length ?? 0,
            sources: (advisories.provenance?.sources ?? []).map((source) => source.name)
          },
          samples: {
            label: samples.label,
            count: samples.count,
            notice: samples.notice
          }
        });
        return;
      }

      if (method === 'GET' && pathname === '/api/samples') {
        sendJson(res, 200, samples);
        return;
      }

      if (method === 'GET' && pathname === '/api/advisories') {
        sendJson(res, 200, {
          provenance: advisories.provenance,
          software: (advisories.software ?? []).map((entry) => ({
            id: entry.id,
            cve: entry.cve,
            title: entry.title,
            product: entry.product,
            severity: entry.severity,
            range: entry.range,
            fixedVersion: entry.fixedVersion,
            source: entry.source
          })),
          lifecycle: advisories.lifecycle ?? []
        });
        return;
      }

      if (method === 'POST' && pathname === '/api/settings/ai') {
        const body = await readJsonBody(req);
        assertAllowedKeys(body, ['apiKey']);
        await saveAiSettings(body.apiKey);
        sendJson(res, 200, { ai: aiStatusForClient(config) });
        return;
      }

      if (method === 'POST' && pathname === '/api/assessments') {
        const cutoff = Date.now() - 60000;
        while (recentAssessments.length > 0 && recentAssessments[0] < cutoff) recentAssessments.shift();
        if (recentAssessments.length >= 12) {
          sendJson(res, 429, { error: 'Too many assessments started in the last minute. Wait a moment.' });
          return;
        }
        const body = await readJsonBody(req);
        assertAllowedKeys(body, ['aiReview', 'target', 'vulnerabilityLookup']);
        if (body.aiReview !== undefined && typeof body.aiReview !== 'boolean') {
          throw new HttpError(400, 'aiReview must be a boolean');
        }
        if (body.vulnerabilityLookup !== undefined && typeof body.vulnerabilityLookup !== 'boolean') {
          throw new HttpError(400, 'vulnerabilityLookup must be a boolean');
        }
        const snapshot = manager.create({ aiReview: Boolean(body.aiReview), vulnerabilityLookup: body.vulnerabilityLookup, client: 'dashboard', target: body.target });
        recentAssessments.push(Date.now());
        logger.info('assessment started', {
          assessmentId: snapshot.id,
          aiReview: Boolean(body.aiReview),
          aiAvailable: config.ai.available
        });
        sendJson(res, 201, {
          assessmentId: snapshot.id,
          eventsUrl: `/api/assessments/${snapshot.id}/events`,
          aiRequested: Boolean(body.aiReview),
          aiAvailable: config.ai.available
        });
        return;
      }

      const eventsMatch = /^\/api\/assessments\/([^/]+)\/events$/.exec(pathname);
      if (method === 'GET' && eventsMatch) {
        const record = manager.get(eventsMatch[1]);
        const lastEventId = req.headers['last-event-id'];
        const afterParam = Number.parseInt(String(lastEventId ?? url.searchParams.get('after') ?? '0'), 10);
        const after = Number.isFinite(afterParam) ? afterParam : 0;

        res.writeHead(200, {
          ...SECURITY_HEADERS,
          'Content-Type': 'text/event-stream; charset=utf-8',
          'Cache-Control': 'no-cache, no-transform',
          Connection: 'keep-alive',
          'X-Accel-Buffering': 'no'
        });
        res.write('retry: 1500\n\n');
        auth.attachStream(token, res);

        for (const event of manager.getEvents(record, after)) {
          sseWrite(res, event);
        }

        const listener = (event) => {
          try {
            sseWrite(res, event);
          } catch {
            unsubscribe();
          }
        };
        const unsubscribe = manager.subscribe(record, listener);
        const keepAlive = setInterval(() => {
          if (!auth.isAuthenticated(token)) {
            clearInterval(keepAlive);
            res.end();
            return;
          }
          try {
            res.write(': keep-alive\n\n');
          } catch {
            clearInterval(keepAlive);
          }
        }, 15000);

        req.on('close', () => {
          clearInterval(keepAlive);
          unsubscribe();
        });
        return;
      }

      const aiMatch = /^\/api\/assessments\/([^/]+)\/ai-review$/.exec(pathname);
      if (method === 'POST' && aiMatch) {
        const record = manager.get(aiMatch[1]);
        if (!ASSESSMENT_ID.test(aiMatch[1])) throw new HttpError(400, 'Invalid assessment id');
        const body = await readJsonBody(req);
        assertAllowedKeys(body, ['consent']);
        if (body.consent !== true) {
          throw new HttpError(400, 'External AI review requires explicit consent: {"consent": true}');
        }
        const result = await manager.runAi(record.id);
        sendJson(res, result.status, result.body);
        return;
      }

      const snapshotMatch = /^\/api\/assessments\/([^/]+)$/.exec(pathname);
      if (method === 'GET' && snapshotMatch) {
        sendJson(res, 200, manager.publicSnapshot(manager.get(snapshotMatch[1])));
        return;
      }

      if (pathname.startsWith('/api/')) {
        sendJson(res, 404, { error: 'Unknown API operation. Ares only exposes predefined endpoints.' });
        return;
      }

      if (method === 'GET') {
        sendText(res, 404, 'Not found');
        return;
      }
      sendJson(res, 405, { error: 'Method not allowed' });
    } catch (error) {
      if (error instanceof LoginLimitError) {
        res.setHeader('Retry-After', '60');
        sendJson(res, 429, { error: error.message });
        return;
      }
      if (error instanceof AiSettingsError) {
        sendJson(res, 400, { error: error.message });
        return;
      }
      if (error instanceof TargetError) {
        sendJson(res, 400, { error: error.message });
        return;
      }
      if (error instanceof HttpError) {
        sendJson(res, error.status, { error: error.message });
        return;
      }
      if (error instanceof AssessmentNotFoundError) {
        sendJson(res, 404, { error: 'Assessment not found or expired.' });
        return;
      }
      if (error instanceof AssessmentLimitError) {
        sendJson(res, 429, { error: error.message });
        return;
      }
      logger.error('request failed', { method, path: pathname, error });
      sendJson(res, 500, { error: 'Internal error while handling the request.' });
    }
  });

  server.on('clientError', (error, socket) => {
    if (socket.writable) socket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
  });

  return server;
}
