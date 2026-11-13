export const SEVERITY_LEVELS = ['critical', 'high', 'medium', 'low', 'info'];

/**
 * Filter logic shared by the dashboard and the automated verification script.
 * Machines may be live assessment results or clearly-labelled sample rows.
 */
export function normalizeFilters(input = {}) {
  const severities = Array.isArray(input.severities)
    ? SEVERITY_LEVELS.filter((level) => input.severities.includes(level))
    : [...SEVERITY_LEVELS];
  return {
    ip: String(input.ip ?? '').trim().toLowerCase(),
    port: String(input.port ?? '').trim(),
    process: String(input.process ?? '').trim().toLowerCase(),
    severities,
    showSamples: input.showSamples !== false
  };
}

function machineIps(machine) {
  const ips = Array.isArray(machine?.ips) ? machine.ips : [];
  if (ips.length > 0) return ips.map((ip) => String(ip).toLowerCase());
  return machine?.primaryIp ? [String(machine.primaryIp).toLowerCase()] : [];
}

export function machineMatches(machine, filters) {
  const normalized = normalizeFilters(filters);
  if (!machine) return false;
  if (machine.sample && !normalized.showSamples) return false;

  if (normalized.ip) {
    if (!machineIps(machine).some((ip) => ip.includes(normalized.ip))) return false;
  }

  if (normalized.port && Number.isFinite(Number(normalized.port))) {
    const port = Number(normalized.port);
    const endpoints = Array.isArray(machine.endpoints) ? machine.endpoints : [];
    if (!endpoints.some((endpoint) => Number(endpoint.port) === port)) return false;
  }

  if (normalized.process) {
    const endpoints = Array.isArray(machine.endpoints) ? machine.endpoints : [];
    const matched = endpoints.some((endpoint) => {
      const process = String(endpoint.process ?? '').toLowerCase();
      const service = String(endpoint.service ?? '').toLowerCase();
      return process.includes(normalized.process) || service.includes(normalized.process);
    });
    if (!matched) return false;
  }

  if (normalized.severities.length === 0) return false;
  if (normalized.severities.length < SEVERITY_LEVELS.length) {
    const findings = Array.isArray(machine.findings) ? machine.findings : [];
    if (!findings.some((finding) => normalized.severities.includes(finding.severity))) return false;
  }

  return true;
}

export function filterMachines(machines = [], filters) {
  return machines.filter((machine) => machineMatches(machine, filters));
}

export function countSeverities(machines = []) {
  const counts = Object.fromEntries(SEVERITY_LEVELS.map((level) => [level, 0]));
  for (const machine of machines) {
    for (const finding of machine?.findings ?? []) {
      if (counts[finding.severity] !== undefined) counts[finding.severity] += 1;
    }
  }
  return counts;
}

export function machineStatusLabel(machine) {
  if (!machine) return 'Unknown';
  if (machine.sample) return 'Sample';
  if (machine.status === 'collecting') return 'Collecting';
  if (machine.status === 'complete') return 'Complete';
  if (machine.status === 'partial') return 'Partial';
  if (machine.status === 'failed') return 'Failed';
  return 'Unknown';
}
