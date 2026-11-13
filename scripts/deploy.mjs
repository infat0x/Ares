import { readdir, mkdir, access } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { spawnSync } from 'node:child_process';

const ROOT = fileURLToPath(new URL('../', import.meta.url));

export function checkNodeVersion(version = process.versions.node) {
  const [major, minor] = version.split('.').map(Number);
  if (!Number.isInteger(major) || !Number.isInteger(minor) || major < 20 || (major === 20 && minor < 11)) {
    throw new Error(`Node.js 20.11 or later is required. Found ${version}.`);
  }
}

export function parseDeployArgs(args) {
  const options = { checkOnly: false, openBrowser: true, port: undefined };
  for (let index = 0; index < args.length; index++) {
    const argument = args[index];
    if (argument === '--check') options.checkOnly = true;
    else if (argument === '--no-open') options.openBrowser = false;
    else if (argument === '--port') {
      const value = args[++index];
      if (!/^\d+$/.test(value ?? '') || Number(value) < 1 || Number(value) > 65535) {
        throw new Error('--port requires an integer from 1 to 65535.');
      }
      options.port = Number(value);
    } else throw new Error(`Unknown deploy option: ${argument}`);
  }
  return options;
}

export async function checkProject(root = ROOT) {
  checkNodeVersion();
  for (const file of ['package.json', 'server/index.mjs', 'server/advisories.json', 'public/index.html', 'public/login.html', 'public/app.js', 'public/login.js', 'public/styles.css']) {
    await access(join(root, file));
  }
  for (const folder of ['server', 'public', 'scripts']) {
    const entries = await readdir(join(root, folder), { recursive: true, withFileTypes: true });
    for (const entry of entries) {
      if (!entry.isFile() || !/\.(?:mjs|js)$/.test(entry.name)) continue;
      const directory = entry.parentPath ?? entry.path;
      const result = spawnSync(process.execPath, ['--check', join(directory, entry.name)], { windowsHide: true, encoding: 'utf8' });
      if (result.error) throw result.error;
      if (result.status !== 0) throw new Error(result.stderr.trim() || `Syntax check failed for ${entry.name}`);
    }
  }
  await mkdir(join(root, 'data', 'assessments'), { recursive: true });
  process.stdout.write(`Ares preflight passed on ${process.platform} (${process.arch}), Node.js ${process.versions.node}.\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const options = parseDeployArgs(process.argv.slice(2));
    await checkProject();
    if (!options.checkOnly) {
      const { runAres } = await import('../server/index.mjs');
      await runAres({ cwd: ROOT, openBrowser: options.openBrowser, port: options.port, fallbackPort: options.port === undefined });
    }
  } catch (error) {
    process.stderr.write(`Ares could not deploy: ${error.message}\n`);
    process.exitCode = 1;
  }
}
