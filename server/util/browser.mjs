import { spawn } from 'node:child_process';

export function browserCommand(url, { platform = process.platform, env = process.env } = {}) {
  const parsed = new URL(url);
  if (!['http:', 'https:'].includes(parsed.protocol) || !['127.0.0.1', '[::1]', 'localhost'].includes(parsed.hostname) || parsed.username || parsed.password) {
    throw new Error('The dashboard browser URL must use a loopback HTTP(S) address.');
  }
  if (env.SSH_CONNECTION || env.SSH_TTY) return null;
  if (platform === 'win32') {
    return { file: 'powershell.exe', args: ['-NoProfile', '-NonInteractive', '-Command', `Start-Process -FilePath '${parsed.href.replace(/'/g, "''")}'`] };
  }
  if (platform === 'linux' && (env.DISPLAY || env.WAYLAND_DISPLAY)) return { file: 'xdg-open', args: [parsed.href] };
  return null;
}

export async function openDashboard(url) {
  const command = browserCommand(url);
  if (!command) return;
  await new Promise((resolve) => {
    const child = spawn(command.file, command.args, { windowsHide: true, stdio: 'ignore' });
    child.once('error', () => {
      process.stderr.write(`Open the dashboard in your browser at ${url}\n`);
      resolve();
    });
    child.once('exit', (code) => {
      if (code !== 0) process.stderr.write(`Open the dashboard in your browser at ${url}\n`);
      resolve();
    });
  });
}
