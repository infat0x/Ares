const IPV4 = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
const WINDOWS_USER_PATH = /[A-Za-z]:\\Users\\[^\\/"'\s]+/g;
const EMAIL = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g;
const UNC_USER_PATH = /\\\\[A-Za-z0-9._-]+\\Users\\[^\\/"'\s]+/g;

function escapeRegExp(text) {
  return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Remove host identifiers from free text. Used as a defence-in-depth pass on
 * every payload that leaves the machine for an external AI provider.
 */
export function sanitizeText(value, identifiers = []) {
  let output = String(value ?? '');
  for (const identifier of identifiers) {
    if (typeof identifier !== 'string') continue;
    const trimmed = identifier.trim();
    if (trimmed.length < 3) continue;
    output = output.replace(new RegExp(escapeRegExp(trimmed), 'gi'), '[redacted]');
  }
  output = output.replace(UNC_USER_PATH, '\\\\[redacted]\\Users\\[redacted]');
  output = output.replace(WINDOWS_USER_PATH, '[redacted-path]');
  output = output.replace(EMAIL, '[redacted-email]');
  output = output.replace(IPV4, '[redacted-ip]');
  return output;
}

/** Deep sanitise strings inside a JSON-like structure. */
export function sanitizeDeep(value, identifiers = [], depth = 0) {
  if (depth > 8) return '[depth-limit]';
  if (typeof value === 'string') return sanitizeText(value, identifiers);
  if (Array.isArray(value)) return value.map((item) => sanitizeDeep(item, identifiers, depth + 1));
  if (value && typeof value === 'object') {
    const result = {};
    for (const [key, item] of Object.entries(value)) {
      result[key] = sanitizeDeep(item, identifiers, depth + 1);
    }
    return result;
  }
  return value;
}

export function collectIdentifiers(machine) {
  const identifiers = new Set();
  const add = (value) => {
    if (typeof value === 'string' && value.trim().length >= 3) identifiers.add(value.trim());
  };
  add(machine?.hostname);
  add(machine?.target?.host);
  add(machine?.target?.username);
  for (const ip of machine?.ips ?? []) add(ip);
  for (const address of machine?.host?.addresses ?? []) add(address?.address);
  add(machine?.host?.hostname);
  return [...identifiers];
}

export function containsIdentifiers(text, identifiers = []) {
  const haystack = String(text ?? '').toLowerCase();
  return identifiers.some((identifier) => identifier && haystack.includes(String(identifier).toLowerCase()));
}
