import { deriveLinuxFindings } from './linux-rules.mjs';

export const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

export function severityRank(severity) {
  const index = SEVERITY_ORDER.indexOf(String(severity).toLowerCase());
  return index === -1 ? SEVERITY_ORDER.length : index;
}

const MS_LEARN = (path) => ({
  name: 'Microsoft Learn',
  url: `https://learn.microsoft.com/${path}`
});

const MSRC_MS17_010 = {
  name: 'Microsoft Security Bulletin MS17-010',
  url: 'https://learn.microsoft.com/security-updates/securitybulletins/2017/ms17-010'
};

const NIST_CM6 = {
  name: 'NIST SP 800-123 (server security)',
  url: 'https://csrc.nist.gov/pubs/sp/800/123/final'
};

function checkById(checks, id) {
  return checks.find((check) => check.id === id) ?? null;
}

function observedBoolean(check, key) {
  const value = check?.observed?.[key];
  return typeof value === 'boolean' ? value : null;
}

const CHECK_RULES = [
  {
    id: 'cfg-firewall',
    checkId: 'firewall',
    evaluate(check) {
      const disabled = Array.isArray(check.observed?.disabledProfiles) ? check.observed.disabledProfiles : [];
      if (disabled.length === 0) return null;
      return {
        severity: 'high',
        title: 'Windows Firewall is disabled for one or more profiles',
        summary: 'Inbound filtering is off for at least one network profile, so services that listen on all interfaces are reachable from that network.',
        observed: `Disabled profiles: ${disabled.join(', ')}`,
        fix: 'Enable Windows Defender Firewall for every profile (Domain, Private, Public) and keep only explicitly required inbound rules.',
        source: MS_LEARN('windows/security/threat-protection/windows-firewall/windows-firewall-with-advanced-security'),
        evidence: { checkId: 'firewall', disabledProfiles: disabled }
      };
    }
  },
  {
    id: 'cfg-defender-realtime',
    checkId: 'defender',
    evaluate(check) {
      if (observedBoolean(check, 'realTimeProtection') !== false) return null;
      return {
        severity: 'high',
        title: 'Microsoft Defender real-time protection is off',
        summary: 'Real-time antivirus protection is disabled, so known malware can execute and persist without an on-access block.',
        observed: 'RealTimeProtectionEnabled = false',
        fix: 'Re-enable real-time protection in Windows Security and check for a conflicting third-party antivirus product or a disabling policy.',
        source: MS_LEARN('defender-endpoint/configure-real-time-protection-defender-antivirus'),
        evidence: { checkId: 'defender', realTimeProtection: false }
      };
    }
  },
  {
    id: 'cfg-smb1',
    checkId: 'smb1',
    evaluate(check) {
      if (observedBoolean(check, 'enabled') !== true) return null;
      return {
        severity: 'high',
        title: 'SMBv1 server protocol is enabled',
        summary: 'SMBv1 is a deprecated protocol with well-known remote code execution history (for example MS17-010) and no modern hardening.',
        observed: 'EnableSMB1Protocol = true',
        fix: 'Disable SMBv1 with "Set-SmbServerConfiguration -EnableSMB1Protocol $false" and audit remaining legacy clients.',
        source: MSRC_MS17_010,
        evidence: { checkId: 'smb1', enabled: true }
      };
    }
  },
  {
    id: 'cfg-rdp-nla',
    checkId: 'rdp',
    evaluate(check) {
      if (observedBoolean(check, 'enabled') !== true) return null;
      if (observedBoolean(check, 'nlaRequired') !== false) return null;
      return {
        severity: 'high',
        title: 'Remote Desktop is enabled without Network Level Authentication',
        summary: 'RDP accepts connections before authentication, which exposes the login stack to pre-auth attacks and credential guessing.',
        observed: 'fDenyTSConnections = 0, UserAuthentication = 0',
        fix: 'Require Network Level Authentication for RDP, restrict port 3389 to a management network or VPN, and enforce account lockout.',
        source: MS_LEARN('windows-server/remote/remote-desktop-services/clients/remote-desktop-allow-access'),
        evidence: { checkId: 'rdp', enabled: true, nlaRequired: false }
      };
    }
  },
  {
    id: 'cfg-rdp-enabled',
    checkId: 'rdp',
    evaluate(check) {
      if (observedBoolean(check, 'enabled') !== true) return null;
      if (observedBoolean(check, 'nlaRequired') === false) return null;
      return {
        severity: 'low',
        title: 'Remote Desktop is enabled',
        summary: 'The Remote Desktop listener is active. Each extra remote-access surface increases credential-attack exposure.',
        observed: 'fDenyTSConnections = 0',
        fix: 'Disable RDP if it is not required, or restrict it to a VPN/management network and require NLA.',
        source: MS_LEARN('windows-server/remote/remote-desktop-services/clients/remote-desktop-allow-access'),
        evidence: { checkId: 'rdp', enabled: true }
      };
    }
  },
  {
    id: 'cfg-guest-account',
    checkId: 'guestAccount',
    evaluate(check) {
      if (observedBoolean(check, 'enabled') !== true) return null;
      return {
        severity: 'medium',
        title: 'The built-in Guest account is enabled',
        summary: 'A passwordless, low-privilege account is available for interactive and network logon.',
        observed: 'Guest account enabled = true',
        fix: 'Disable the Guest account unless a documented, isolated use case requires it.',
        source: MS_LEARN('windows-server/identity/ad-ds/manage/understand-security-groups'),
        evidence: { checkId: 'guestAccount', enabled: true }
      };
    }
  },
  {
    id: 'cfg-llmnr',
    checkId: 'llmnr',
    evaluate(check) {
      if (observedBoolean(check, 'enabled') !== true) return null;
      return {
        severity: 'low',
        title: 'LLMNR name resolution is enabled',
        summary: 'Link-Local Multicast Name Resolution accepts unsigned local answers, which enables spoofing and NTLM hash capture on the local network.',
        observed: 'EnableMulticast is not disabled (effective state: enabled)',
        fix: 'Disable LLMNR through the "Turn off multicast name resolution" policy (EnableMulticast = 0).',
        source: MS_LEARN('windows-server/security/windows-security-baselines'),
        evidence: { checkId: 'llmnr', enabled: true }
      };
    }
  },
  {
    id: 'cfg-winrm-http',
    checkId: 'winrm',
    evaluate(check) {
      const httpListeners = Number(check.observed?.httpListeners ?? 0);
      if (!Number.isFinite(httpListeners) || httpListeners <= 0) return null;
      return {
        severity: 'medium',
        title: 'WinRM is listening over plain HTTP',
        summary: 'Remote PowerShell transport without TLS can be intercepted or modified on the network.',
        observed: `HTTP listeners = ${httpListeners}`,
        fix: 'Disable the HTTP WinRM listener and use HTTPS with a trusted certificate, or restrict WinRM to a management network.',
        source: MS_LEARN('windows/win32/winrm/installation-and-configuration-for-windows-remote-management'),
        evidence: { checkId: 'winrm', httpListeners }
      };
    }
  },
  {
    id: 'cfg-uac-disabled',
    checkId: 'uac',
    evaluate(check) {
      if (observedBoolean(check, 'enabled') !== false) return null;
      return {
        severity: 'high',
        title: 'User Account Control is disabled',
        summary: 'Administrators run with a full elevated token and no consent prompt, removing a key defence against silent privilege use.',
        observed: 'EnableLUA = 0',
        fix: 'Re-enable UAC (EnableLUA = 1) and require consent or credentials for elevation.',
        source: MS_LEARN('windows/security/identity-protection/user-account-control/how-user-account-control-works'),
        evidence: { checkId: 'uac', enabled: false }
      };
    }
  },
  {
    id: 'cfg-uac-token-filter',
    checkId: 'uac',
    evaluate(check) {
      if (observedBoolean(check, 'localAccountTokenFilter') !== true) return null;
      return {
        severity: 'medium',
        title: 'UAC remote restrictions are disabled for local accounts',
        summary: 'LocalAccountTokenFilterPolicy = 1 lets local accounts obtain full administrative tokens over the network, enabling pass-the-hash style lateral movement.',
        observed: 'LocalAccountTokenFilterPolicy = 1',
        fix: 'Remove LocalAccountTokenFilterPolicy or set it to 0, and use dedicated administrative accounts for remote management.',
        source: MS_LEARN('windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings'),
        evidence: { checkId: 'uac', localAccountTokenFilter: true }
      };
    }
  },
  {
    id: 'cfg-powershell-v2',
    checkId: 'powershellV2',
    evaluate(check) {
      if (observedBoolean(check, 'installed') !== true) return null;
      return {
        severity: 'medium',
        title: 'Windows PowerShell 2.0 engine is installed',
        summary: 'The legacy engine lacks modern logging and security controls and can be used to downgrade attacker detection.',
        observed: 'MicrosoftWindowsPowerShellV2 feature state = Enabled',
        fix: 'Remove the Windows PowerShell 2.0 Engine optional feature unless a documented legacy dependency exists.',
        source: MS_LEARN('powershell/scripting/windows-powershell/install/windows-powershell-system-requirements'),
        evidence: { checkId: 'powershellV2', installed: true }
      };
    }
  },
  {
    id: 'cfg-secureboot',
    checkId: 'secureBoot',
    evaluate(check) {
      if (observedBoolean(check, 'enabled') !== false) return null;
      return {
        severity: 'medium',
        title: 'Secure Boot is disabled',
        summary: 'Boot-time integrity checks are off, so unsigned boot components and rootkits are not blocked.',
        observed: 'Secure Boot enabled = false',
        fix: 'Enable Secure Boot in UEFI firmware after confirming the installed OS and drivers are signed.',
        source: MS_LEARN('windows-hardware/design/device-experiences/oem-secure-boot'),
        evidence: { checkId: 'secureBoot', enabled: false }
      };
    }
  },
  {
    id: 'cfg-bitlocker',
    checkId: 'bitlocker',
    evaluate(check) {
      const status = String(check.observed?.protectionStatus ?? '').toLowerCase();
      if (!status || status === 'on' || status === 'unknown') return null;
      return {
        severity: 'medium',
        title: 'System drive is not protected by BitLocker',
        summary: 'Data at rest can be read if the disk or device is lost, stolen or booted from removable media.',
        observed: `ProtectionStatus = ${check.observed?.protectionStatus ?? 'unknown'}`,
        fix: 'Enable BitLocker on the system drive and store recovery keys in an approved location.',
        source: MS_LEARN('windows/security/operating-system-security/data-protection/bitlocker/'),
        evidence: { checkId: 'bitlocker', protectionStatus: status }
      };
    }
  },
  {
    id: 'cfg-unquoted-service',
    checkId: 'unquotedServices',
    evaluate(check) {
      const count = Number(check.observed?.count ?? 0);
      if (!Number.isFinite(count) || count <= 0) return null;
      const samples = Array.isArray(check.observed?.samples) ? check.observed.samples : [];
      return {
        severity: 'medium',
        title: 'Unquoted service paths allow executable planting',
        summary: 'A service path containing spaces but no quotes can be resolved to an attacker-controlled executable in a writable directory.',
        observed: `${count} unquoted service path(s)${samples.length ? `: ${samples.map((item) => item.name).slice(0, 5).join(', ')}` : ''}`,
        fix: 'Quote the full executable path for each affected service, and remove write access to the service directories for non-administrators.',
        source: NIST_CM6,
        evidence: { checkId: 'unquotedServices', count, serviceNames: samples.map((item) => item.name).slice(0, 5) }
      };
    }
  },
  {
    id: 'cfg-autologon',
    checkId: 'autologon',
    evaluate(check) {
      if (observedBoolean(check, 'enabled') !== true) return null;
      const stored = observedBoolean(check, 'credentialStored') === true;
      return {
        severity: stored ? 'high' : 'medium',
        title: 'Automatic logon is configured',
        summary: stored
          ? 'Credentials are stored for automatic logon, which exposes them to anyone who can read the registry.'
          : 'The machine can log on without interactive credentials, which weakens physical access control.',
        observed: `Autologon enabled = true, stored credential = ${stored}`,
        fix: 'Disable automatic logon, remove stored credentials, and use a managed device logon mechanism instead.',
        source: MS_LEARN('windows-server/security/windows-authentication/credentials-processes-in-windows-authentication'),
        evidence: { checkId: 'autologon', enabled: true, credentialStored: stored }
      };
    }
  }
];

const EXPOSED_SERVICES = [
  {
    ports: [23],
    severity: 'high',
    title: 'Telnet service is listening',
    summary: 'Telnet sends credentials and session data in cleartext.',
    fix: 'Disable Telnet and use SSH or another encrypted management protocol.',
    source: NIST_CM6
  },
  {
    ports: [5900, 5901, 5902, 5903],
    severity: 'high',
    title: 'VNC service is listening',
    summary: 'VNC commonly provides unauthenticated or weakly authenticated remote desktop access.',
    fix: 'Disable VNC or bind it to localhost behind a VPN, and enforce a strong password with TLS tunnelling.',
    source: NIST_CM6
  },
  {
    ports: [1433, 3306, 5432, 6379, 9200, 27017, 11211],
    severity: 'medium',
    title: 'Database or cache service is reachable on all interfaces',
    summary: 'A data store is bound to a non-loopback address. Many default configurations have weak or no authentication.',
    fix: 'Bind the service to localhost or a management network, require authentication, and restrict the port with Windows Firewall.',
    source: NIST_CM6
  },
  {
    ports: [21],
    severity: 'low',
    title: 'FTP service is listening',
    summary: 'FTP transmits credentials and files in cleartext.',
    fix: 'Replace FTP with SFTP or FTPS, or disable the service if unused.',
    source: NIST_CM6
  }
];

function exposedAnyAddress(endpoint) {
  if (!endpoint) return false;
  if (endpoint.anyAddress) return true;
  return !endpoint.loopbackOnly && !String(endpoint.address).startsWith('127.') && endpoint.address !== '::1';
}

/**
 * Deterministic local configuration findings. These never depend on AI.
 */
export function deriveConfigFindings({ checks = [], endpoints = [] } = {}) {
  const results = deriveLinuxFindings(checks);
  for (const rule of CHECK_RULES) {
    const check = checkById(checks, rule.checkId);
    if (!check || check.status === 'unknown') continue;
    let candidate = null;
    try {
      candidate = rule.evaluate(check);
    } catch {
      candidate = null;
    }
    if (!candidate) continue;
    results.push({ ...candidate, ruleId: rule.id, category: check.category, checkStatus: check.status });
  }

  for (const service of EXPOSED_SERVICES) {
    const matches = endpoints.filter(
      (endpoint) => service.ports.includes(Number(endpoint.port)) && exposedAnyAddress(endpoint)
    );
    if (matches.length === 0) continue;
    const processes = [...new Set(matches.map((item) => item.process || item.service).filter(Boolean))];
    results.push({
      ruleId: `cfg-exposure-${service.ports[0]}`,
      category: 'network-exposure',
      severity: service.severity,
      title: service.title,
      summary: service.summary,
      observed: `${matches.length} endpoint(s): ${matches
        .slice(0, 6)
        .map((item) => `${item.protocol}/${item.port}${item.process ? ` (${item.process})` : ''}`)
        .join(', ')}`,
      fix: service.fix,
      source: service.source,
      evidence: {
        ports: [...new Set(matches.map((item) => Number(item.port)))],
        processes: processes.slice(0, 6)
      }
    });
  }

  return results;
}
