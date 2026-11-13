import { isIP } from 'node:net';

export class TargetError extends Error {}

export function validateTarget(value = { mode: 'local' }) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new TargetError('target must be an object');
  if (Object.keys(value).some((key) => !['mode', 'host', 'port', 'username', 'password', 'url', 'activeChecks'].includes(key))) {
    throw new TargetError('Unknown target field');
  }
  if (value.mode === 'local') {
    if (Object.keys(value).some((key) => key !== 'mode')) throw new TargetError('Local target only accepts mode');
    if (!['win32', 'linux'].includes(process.platform)) throw new TargetError('Local assessment supports Windows and Linux. Select a web or SSH target on this platform.');
    return { mode: 'local' };
  }
  if (value.mode === 'web') {
    if (Object.keys(value).some((key) => !['mode', 'url', 'activeChecks'].includes(key))) throw new TargetError('Web targets accept only url and activeChecks');
    if (typeof value.url !== 'string' || value.url.length > 2048) throw new TargetError('Enter a valid HTTP or HTTPS URL');
    let url;
    try {
      url = new URL(value.url);
    } catch {
      throw new TargetError('Enter a valid HTTP or HTTPS URL');
    }
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) throw new TargetError('Web URL must use HTTP or HTTPS without embedded credentials');
    if (value.activeChecks !== undefined && typeof value.activeChecks !== 'boolean') throw new TargetError('activeChecks must be a boolean');
    url.hash = '';
    return { mode: 'web', url: url.href, activeChecks: value.activeChecks ?? false };
  }
  if (value.mode === 'ip') {
    if (Object.keys(value).some((key) => !['mode', 'host'].includes(key)) || typeof value.host !== 'string' || !isIP(value.host)) {
      throw new TargetError('IP target requires a single IPv4 or IPv6 address');
    }
    return { mode: 'ip', host: value.host };
  }
  if (value.mode !== 'ssh') throw new TargetError('target.mode must be local, ssh, web or ip');
  if (Object.keys(value).some((key) => !['mode', 'host', 'port', 'username', 'password'].includes(key))) throw new TargetError('Unknown SSH target field');
  const { host, username, port = 22 } = value;
  if (typeof host !== 'string' || host.length > 253 ||
      !(isIP(host) || /^(?=.{1,253}$)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/i.test(host))) {
    throw new TargetError('SSH host must be an IP address or hostname');
  }
  if (typeof username !== 'string' || !/^[a-z_][a-z0-9_.-]{0,63}$/i.test(username)) {
    throw new TargetError('Invalid SSH username');
  }
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new TargetError('SSH port must be between 1 and 65535');
  const password = value.password ?? '';
  if (typeof password !== 'string' || password.length > 1024 || /[\r\n\0]/.test(password)) throw new TargetError('Invalid SSH password');
  const target = { mode: 'ssh', host, port, username };
  Object.defineProperty(target, 'password', { value: password || undefined, writable: true });
  return target;
}

export function sshArgs(target, collectorId) {
  return ['-T', '-o', `BatchMode=${target.password ? 'no' : 'yes'}`, '-o', 'StrictHostKeyChecking=yes',
    ...(target.password ? ['-o', 'PreferredAuthentications=password', '-o', 'NumberOfPasswordPrompts=1'] : []),
    '-o', 'ConnectTimeout=10', '-o', 'ForwardAgent=no', '-o', 'ClearAllForwardings=yes',
    '-p', String(target.port), '-l', target.username, '--', target.host, `python3 - ${collectorId}`];
}
