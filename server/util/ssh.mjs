import { access, chmod, mkdir } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import { runCommand } from './exec.mjs';

const ROOT = fileURLToPath(new URL('../../', import.meta.url));
let helperReady;

async function prepareHelper() {
  if (process.platform !== 'win32') {
    const file = join(ROOT, 'scripts', 'ssh-askpass.sh');
    await chmod(file, 0o700);
    return file;
  }
  const directory = join(ROOT, 'data', 'ssh-support');
  await mkdir(directory, { recursive: true });
  const file = join(directory, 'askpass-v1.exe');
  try {
    await access(file);
  } catch {
    const result = await runCommand({ file: 'powershell.exe', args: [
      '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File',
      join(ROOT, 'scripts', 'ssh-askpass.ps1'), '-OutputPath', file
    ], timeoutMs: 15000 });
    if (result.code !== 0) throw new Error('Could not prepare the SSH password helper.');
  }
  return file;
}

export async function sshPasswordEnvironment(password) {
  if (!password) return undefined;
  helperReady ??= prepareHelper().catch((error) => { helperReady = undefined; throw error; });
  return { ...process.env, SSH_ASKPASS: await helperReady, SSH_ASKPASS_REQUIRE: 'force',
    DISPLAY: process.env.DISPLAY || 'ares:0', ARES_SSH_PASSWORD: password };
}
