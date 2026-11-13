import { readFile, mkdir } from 'node:fs/promises';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { loadConfig } from './config.mjs';
import { Logger } from './logger.mjs';
import { createAresServer } from './http.mjs';
import { AssessmentManager } from './assessment.mjs';
import { sampleDataset } from './samples.mjs';
import { openDashboard } from './util/browser.mjs';

export async function startAres({ env = process.env, cwd = process.cwd(), port, loadEnvFile = true, auth } = {}) {
  const config = loadConfig({ env, cwd, loadEnvFile });
  if (port !== undefined) config.port = port;

  await mkdir(config.snapshotDir, { recursive: true });

  const logger = new Logger({
    level: env.ARES_LOG_LEVEL || 'info',
    file: config.logFile,
    secrets: config.secrets
  });

  let advisories;
  try {
    advisories = JSON.parse(await readFile(config.advisoryFile, 'utf8'));
  } catch (error) {
    throw new Error(`Could not load advisory snapshot at ${config.advisoryFile}: ${error.message}`);
  }
  if (!Array.isArray(advisories.software) || !Array.isArray(advisories.lifecycle)) {
    throw new Error('Advisory snapshot is malformed: "software" and "lifecycle" arrays are required.');
  }

  const samples = sampleDataset(advisories, new Date());
  const manager = new AssessmentManager({ config, advisories, logger });
  const server = createAresServer({ config, logger, advisories, manager, samples, auth });

  await new Promise((resolve, reject) => {
    const onError = (error) => reject(error);
    server.once('error', onError);
    server.listen(config.port, config.host, () => {
      server.removeListener('error', onError);
      resolve();
    });
  });

  const address = server.address();
  const shownHost = address.family === 'IPv6' && address.address === '::1' ? '[::1]' : address.address;
  const url = `http://${shownHost}:${address.port}`;

  logger.info('ares listening', {
    url,
    loopbackOnly: true,
    aiAvailable: config.ai.available,
    advisorySnapshot: advisories.provenance?.snapshot ?? null
  });

  const close = async () => {
    await new Promise((resolve) => server.close(() => resolve()));
  };

  return { config, logger, advisories, samples, manager, server, url, close };
}

const isMain = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;

export async function runAres({ cwd = fileURLToPath(new URL('../', import.meta.url)), openBrowser = false, fallbackPort = false, port, env = process.env, loadEnvFile = true } = {}) {
  let app;
  try {
    app = await startAres({ cwd, port, env, loadEnvFile });
  } catch (error) {
    if (!fallbackPort || error.code !== 'EADDRINUSE') throw error;
    app = await startAres({ cwd, port: 0, env, loadEnvFile });
    process.stdout.write(`The configured port was busy. Using ${app.url}\n`);
  }
  const aiLine = app.config.ai.available
    ? `AI review available (model: ${app.config.ai.model}); external review is opt-in per assessment.`
    : 'AI review disabled (no ARES_AI_API_KEY / ARES_AI_ENABLED). Local assessment works normally.';
  process.stdout.write(
    [
      '',
      `  ${app.config.appName} ${app.config.version} - assessment dashboard`,
      `  Dashboard: ${app.url}`,
      `  ${aiLine}`,
      '  Bound to loopback only. Press Ctrl+C to stop.',
      ''
    ].join('\n')
  );

  let shuttingDown = false;
  const shutdown = async () => {
    if (shuttingDown) return;
    shuttingDown = true;
    process.stdout.write('\n  Stopping Ares…\n');
    const timer = setTimeout(() => process.exit(0), 2000);
    timer.unref();
    try {
      await app.close();
    } catch {
      /* ignore */
    }
    process.exit(0);
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
  if (openBrowser) await openDashboard(app.url);
  return app;
}

if (isMain) {
  try {
    await runAres();
  } catch (error) {
    if (error?.code === 'EADDRINUSE') {
      process.stderr.write(`Ares could not start: port ${error.port ?? ''} is already in use. Set ARES_PORT to another value.\n`);
    } else if (error?.code === 'EACCES') {
      process.stderr.write('Ares could not start: permission denied while binding the local port.\n');
    } else {
      process.stderr.write(`Ares could not start: ${error?.message ?? error}\n`);
    }
    process.exit(1);
  }
}
