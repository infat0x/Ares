import { randomBytes, scrypt, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';

const deriveKey = promisify(scrypt);
const DEFAULT_PASSWORD_HASH = {
  salt: 'd69d30ac63449190c933e2f1ffbd88b4',
  hash: '01a7fb8d7ef243a510ca6b6f9bb77c6a76cdc11364db3f254bce5fb7b64192790167ce3a76da9bba3990bd4ef02aaf733d18363759a8fa5da3d89a13ab719420'
};

export const SESSION_COOKIE = 'ares_session';
export const SESSION_TTL_MS = 8 * 60 * 60 * 1000;

export class LoginLimitError extends Error {}

export function sessionToken(req) {
  const values = String(req.headers.cookie ?? '').split(';')
    .map((part) => part.trim()).filter((part) => part.startsWith(`${SESSION_COOKIE}=`));
  if (values.length !== 1) return null;
  const token = values[0].slice(SESSION_COOKIE.length + 1);
  return /^[a-f0-9]{64}$/.test(token) ? token : null;
}

export function createAuth({ passwordHash = DEFAULT_PASSWORD_HASH, now = Date.now } = {}) {
  const sessions = new Map();
  const attempts = [];
  const expected = Buffer.from(passwordHash.hash, 'hex');

  function logout(token) {
    const session = sessions.get(token);
    sessions.delete(token);
    for (const response of session?.streams ?? []) response.end();
  }

  function isAuthenticated(token) {
    const session = sessions.get(token);
    if (!session) return false;
    if (session.expiresAt <= now()) {
      logout(token);
      return false;
    }
    return true;
  }

  return {
    async login(password) {
      while (attempts.length && attempts[0] <= now() - 60000) attempts.shift();
      if (attempts.length >= 10) throw new LoginLimitError('Too many login attempts. Try again in one minute.');
      attempts.push(now());
      if (typeof password !== 'string' || password.length === 0 || password.length > 1024) return null;
      const actual = await deriveKey(password, passwordHash.salt, expected.length);
      if (!timingSafeEqual(actual, expected)) return null;
      for (const [token, session] of sessions) {
        if (session.expiresAt <= now()) logout(token);
      }
      if (sessions.size >= 100) logout(sessions.keys().next().value);
      const token = randomBytes(32).toString('hex');
      sessions.set(token, { expiresAt: now() + SESSION_TTL_MS, streams: new Set() });
      return token;
    },
    isAuthenticated,
    logout,
    attachStream(token, response) {
      if (!isAuthenticated(token)) {
        response.end();
        return;
      }
      const streams = sessions.get(token).streams;
      streams.add(response);
      response.on('close', () => streams.delete(response));
    }
  };
}
