const SECRET_PATTERNS = [
  /sk-[A-Za-z0-9_-]{12,}/g,
  /Bearer\s+[A-Za-z0-9._~+/=-]{8,}/gi,
  /(?<=authorization["':\s]{1,6})[A-Za-z0-9._~+/=-]{16,}/gi
];

/** Replace secrets and credential-looking strings before anything is logged. */
export function redactSecrets(text, secrets = []) {
  let output = String(text ?? '');
  for (const secret of secrets) {
    if (typeof secret === 'string' && secret.length >= 4) {
      output = output.split(secret).join('[redacted-key]');
    }
  }
  for (const pattern of SECRET_PATTERNS) {
    output = output.replace(pattern, '[redacted-key]');
  }
  return output;
}
