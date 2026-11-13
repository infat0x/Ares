const SSH_SOURCE = { name: 'OpenSSH sshd_config', url: 'https://man.openbsd.org/sshd_config' };
const KERNEL_SOURCE = { name: 'Linux kernel sysctl documentation', url: 'https://docs.kernel.org/admin-guide/sysctl/kernel.html' };
const FS_SOURCE = { name: 'Linux filesystem sysctl documentation', url: 'https://docs.kernel.org/admin-guide/sysctl/fs.html' };

const LINUX_RULES = [
  {
    checkId: 'linux-ssh-permitrootlogin', weakValues: ['yes'], severity: 'medium',
    title: 'SSH permits direct root login',
    summary: 'The base SSH configuration permits root login, increasing exposure of the administrative account. Authentication methods and per-user rules still determine whether access succeeds.',
    fix: 'Use a named administrative account with sudo and set PermitRootLogin no after verifying that administrative access works.',
    source: SSH_SOURCE
  },
  {
    checkId: 'linux-ssh-passwordauthentication', weakValues: ['yes'], severity: 'low',
    title: 'SSH password authentication is enabled',
    summary: 'Password authentication is enabled in the base configuration. Password strength, additional authentication requirements and access restrictions determine the practical risk.',
    fix: 'Configure SSH keys and test access before setting PasswordAuthentication no. Review keyboard-interactive authentication and MFA requirements as well.',
    source: SSH_SOURCE
  },
  {
    checkId: 'linux-ssh-permitemptypasswords', weakValues: ['yes'], severity: 'high',
    title: 'SSH permits authentication with empty passwords',
    summary: 'The base SSH configuration allows empty-password authentication. A usable passwordless account and applicable authentication rules are additional prerequisites for access.',
    fix: 'Set PermitEmptyPasswords no in the effective SSH configuration, validate the configuration and reload the SSH service.',
    source: SSH_SOURCE
  },
  {
    checkId: 'linux-sysctl-kernel.randomize_va_space', weakValues: [0, 1], severity: 'medium',
    title: 'Full process address space randomization is disabled',
    summary: 'The kernel is configured with reduced or disabled address space randomization, which can make memory corruption exploitation more predictable.',
    fix: 'Set kernel.randomize_va_space=2 using sysctl and persist the setting after checking application compatibility.',
    source: KERNEL_SOURCE
  },
  {
    checkId: 'linux-sysctl-kernel.kptr_restrict', weakValues: [0], severity: 'low',
    title: 'Kernel pointer access restrictions are relaxed',
    summary: 'The sysctl setting does not enforce the privileged-reader restriction for %pK kernel pointer output. Actual disclosure also depends on pointer hashing and interface permissions.',
    fix: 'Set kernel.kptr_restrict to 1 or 2 according to the operational requirements and persist the setting.',
    source: KERNEL_SOURCE
  },
  {
    checkId: 'linux-sysctl-kernel.dmesg_restrict', weakValues: [0], severity: 'low',
    title: 'Unprivileged access to the kernel log is enabled',
    summary: 'Unprivileged users can access the kernel log buffer, which may contain diagnostic information useful to a local attacker.',
    fix: 'Set kernel.dmesg_restrict=1 and persist the setting. Provide diagnostic access through an authorized administrative role.',
    source: KERNEL_SOURCE
  },
  {
    checkId: 'linux-sysctl-fs.protected_hardlinks', weakValues: [0], severity: 'medium',
    title: 'Kernel hardlink protection is disabled',
    summary: 'Ownership restrictions on hardlink creation are disabled, increasing exposure to file-link attacks against privileged applications.',
    fix: 'Set fs.protected_hardlinks=1 and persist the setting.',
    source: FS_SOURCE
  },
  {
    checkId: 'linux-sysctl-fs.protected_symlinks', weakValues: [0], severity: 'medium',
    title: 'Kernel symlink protection is disabled',
    summary: 'Restrictions on following symlinks in sticky world-writable directories are disabled, increasing exposure to file-link races in privileged applications.',
    fix: 'Set fs.protected_symlinks=1 and persist the setting.',
    source: FS_SOURCE
  }
];

export function deriveLinuxFindings(checks = []) {
  const byId = new Map(checks.map((check) => [check.id, check]));
  const findings = [];
  for (const rule of LINUX_RULES) {
    const check = byId.get(rule.checkId);
    if (!check || check.status === 'unknown' || !rule.weakValues.includes(check.observed?.value)) continue;
    const baseSshConfig = rule.checkId.startsWith('linux-ssh-');
    findings.push({
      ruleId: rule.checkId, category: check.category, severity: rule.severity,
      title: rule.title, summary: rule.summary, fix: rule.fix, source: rule.source,
      observed: `${rule.checkId.replace(/^linux-(ssh-|sysctl-)/, '')} = ${check.observed.value}`,
      evidence: { checkId: rule.checkId, value: check.observed.value },
      confidence: baseSshConfig ? 'possible' : 'confirmed',
      confidenceReasons: baseSshConfig ? ['Base SSH configuration was evaluated. Match blocks and additional authentication requirements can restrict access.'] : []
    });
  }
  return findings;
}
