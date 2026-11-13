import { spawn } from 'node:child_process';

/**
 * Run a command with a hard timeout. On Windows the process tree is killed
 * with taskkill so a stuck PowerShell child cannot keep the assessment alive.
 */
export function runCommand({ file, args = [], timeoutMs = 30000, maxOutputBytes = 4 * 1024 * 1024, env, cwd, input }) {
  return new Promise((resolve) => {
    const startedAt = Date.now();
    let stdout = '';
    let stderr = '';
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let truncated = false;
    let timedOut = false;
    let settled = false;
    let timer = null;

    const finish = (extra) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      resolve({
        code: null,
        signal: null,
        stdout,
        stderr,
        timedOut,
        truncated,
        durationMs: Date.now() - startedAt,
        ...extra
      });
    };

    let child;
    try {
      child = spawn(file, args, {
        cwd,
        env: env ?? process.env,
        windowsHide: true,
        stdio: [input === undefined ? 'ignore' : 'pipe', 'pipe', 'pipe']
      });
    } catch (error) {
      finish({ spawnError: true, stderr: String(error?.message ?? error) });
      return;
    }

    child.stdout?.on('data', (chunk) => {
      if (stdoutBytes < maxOutputBytes) {
        stdout += chunk.toString('utf8');
        stdoutBytes += chunk.length;
      } else {
        truncated = true;
      }
    });
    child.stderr?.on('data', (chunk) => {
      if (stderrBytes < 64 * 1024) {
        stderr += chunk.toString('utf8');
        stderrBytes += chunk.length;
      }
    });

    child.on('error', (error) => {
      finish({ spawnError: true, stderr: `${stderr}${String(error?.message ?? error)}` });
    });
    if (input !== undefined) {
      child.stdin.on('error', (error) => {
        if (error.code !== 'EPIPE') stderr += String(error.message);
      });
      child.stdin.end(input);
    }
    child.on('close', (code, signal) => {
      finish({ code, signal });
    });

    timer = setTimeout(() => {
      timedOut = true;
      killTree(child.pid);
      // Give the kill a moment to land; resolve anyway so a collector can
      // never hold the whole assessment open.
      setTimeout(() => {
        finish({ killed: true });
      }, 2500).unref?.();
    }, timeoutMs);
  });
}

function killTree(pid) {
  if (!pid) return;
  if (process.platform === 'win32') {
    try {
      spawn('taskkill', ['/pid', String(pid), '/T', '/F'], {
        windowsHide: true,
        stdio: 'ignore'
      }).unref?.();
    } catch {
      /* best effort */
    }
    return;
  }
  try {
    process.kill(pid, 'SIGKILL');
  } catch {
    /* best effort */
  }
}
