import { createConnection, isIP } from 'node:net';
import { setTimeout as delay } from 'node:timers/promises';

export const IP_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 389, 443, 445, 465, 587, 636, 993, 995, 1433, 1521, 2375, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 9200, 11211, 27017];

export function probeTcpPort(host, port, timeoutMs = 1200) {
  return new Promise((resolve) => {
    const socket = createConnection({ host, port });
    let settled = false;
    const finish = (status) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve({ port, status });
    };
    socket.setTimeout(timeoutMs, () => finish('unknown'));
    socket.once('connect', () => finish('open'));
    socket.once('error', (error) => finish(error.code === 'ECONNREFUSED' ? 'closed' : 'unknown'));
  });
}

export async function runIpAssessment({ host, onUpdate = () => {}, probe = probeTcpPort, intervalMs = 500 }) {
  if (!isIP(host)) throw new Error('A single IPv4 or IPv6 address is required.');
  const results = [];
  const pending = new Set();
  for (const port of IP_PORTS) {
    const task = probe(host, port).then((result) => {
      results.push(result);
      onUpdate({ completed: results.length, total: IP_PORTS.length });
    });
    pending.add(task);
    void task.then(() => pending.delete(task), () => pending.delete(task));
    if (pending.size >= 2) await Promise.race(pending);
    await delay(intervalMs);
  }
  await Promise.all(pending);
  const unknown = results.filter((result) => result.status === 'unknown').length;
  return {
    status: unknown ? 'partial' : 'complete',
    testedPorts: [...IP_PORTS], unknown,
    endpoints: results.filter((result) => result.status === 'open').map(({ port }) => ({
      protocol: 'tcp', address: host, port, state: 'Open', pid: null,
      process: null, service: null, loopbackOnly: false, anyAddress: false, remote: true
    })).sort((a, b) => a.port - b.port)
  };
}
