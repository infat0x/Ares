import { classifyMachine, selectPrimaryIp, uniqueIps } from './machine.mjs';
import { evaluateFindings, computeMachineTotals } from './findings.mjs';

/**
 * Deterministic synthetic machines used to exercise the expandable list,
 * filters and severity display at scale. They are clearly labelled as sample
 * data in the API response and in the dashboard.
 */

function mulberry32(seed) {
  let state = seed >>> 0;
  return function random() {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const SOFTWARE_POOL = [
  { name: '7-Zip 25.01 (x64)', version: '25.01', publisher: 'Igor Pavlov', vulnerable: false },
  { name: '7-Zip 23.01 (x64)', version: '23.01', publisher: 'Igor Pavlov', vulnerable: true },
  { name: 'WinRAR 6.24 (64-bit)', version: '6.24', publisher: 'win.rar GmbH', vulnerable: false },
  { name: 'WinRAR 6.11 (64-bit)', version: '6.11', publisher: 'win.rar GmbH', vulnerable: true },
  { name: 'Git version 2.45.2', version: '2.45.2', publisher: 'The Git Development Community', vulnerable: false },
  { name: 'Git version 2.40.1', version: '2.40.1', publisher: 'The Git Development Community', vulnerable: true },
  { name: 'PuTTY 0.81', version: '0.81', publisher: 'Simon Tatham', vulnerable: false },
  { name: 'PuTTY 0.78', version: '0.78', publisher: 'Simon Tatham', vulnerable: true },
  { name: 'curl 8.4.0', version: '8.4.0', publisher: 'curl project', vulnerable: false },
  { name: 'curl 8.3.0', version: '8.3.0', publisher: 'curl project', vulnerable: true },
  { name: 'OpenSSL 3.0.13', version: '3.0.13', publisher: 'OpenSSL Software Foundation', vulnerable: false },
  { name: 'OpenSSL 1.0.1c', version: '1.0.1c', publisher: 'OpenSSL Software Foundation', vulnerable: true },
  { name: 'Apache Log4j 2.17.1', version: '2.17.1', publisher: 'Apache Software Foundation', vulnerable: false },
  { name: 'Apache Log4j 2.14.1', version: '2.14.1', publisher: 'Apache Software Foundation', vulnerable: true },
  { name: 'Microsoft Edge 131.0.2903.86', version: '131.0.2903.86', publisher: 'Microsoft Corporation', vulnerable: false },
  { name: 'Mozilla Firefox 121.0', version: '121.0', publisher: 'Mozilla', vulnerable: false },
  { name: 'Python 3.12.4', version: '3.12.4', publisher: 'Python Software Foundation', vulnerable: false },
  { name: 'Node.js 22.11.0', version: '22.11.0', publisher: 'OpenJS Foundation', vulnerable: false },
  { name: 'Visual Studio Code 1.95.3', version: '1.95.3', publisher: 'Microsoft Corporation', vulnerable: false },
  { name: 'Docker Desktop 4.34.2', version: '4.34.2', publisher: 'Docker Inc.', vulnerable: false },
  { name: 'Wireshark 4.4.1', version: '4.4.1', publisher: 'The Wireshark developers', vulnerable: false },
  { name: 'Notepad++ 8.7.1', version: '8.7.1', publisher: 'Notepad++ Team', vulnerable: false },
  { name: 'VLC media player 3.0.21', version: '3.0.21', publisher: 'VideoLAN', vulnerable: false },
  { name: 'Adobe Acrobat Reader DC 24.003.20112', version: '24.003.20112', publisher: 'Adobe Inc.', vulnerable: false },
  { name: 'Microsoft Office LTSC 2021', version: '16.0.14332.20481', publisher: 'Microsoft Corporation', vulnerable: false },
  { name: 'Microsoft Visual C++ 2015-2022 Redistributable (x64)', version: '14.42.34433', publisher: 'Microsoft Corporation', vulnerable: false },
  { name: 'Mullvad VPN 2025.13.0', version: '2025.13.0', publisher: 'Mullvad VPN', vulnerable: false },
  { name: 'ShareX 22.4.0', version: '22.4.0', publisher: 'ShareX Team', vulnerable: false }
];

const OS_PROFILES = [
  { caption: 'Microsoft Windows 11 Pro', editionId: 'Professional', displayVersion: '25H2', buildNumber: '26200', ubr: 9445, version: '10.0.26200' },
  { caption: 'Microsoft Windows 11 Enterprise', editionId: 'Enterprise', displayVersion: '24H2', buildNumber: '26100', ubr: 2314, version: '10.0.26100' },
  { caption: 'Microsoft Windows 11 Pro', editionId: 'Professional', displayVersion: '23H2', buildNumber: '22631', ubr: 4890, version: '10.0.22631' },
  { caption: 'Microsoft Windows 11 Pro', editionId: 'Professional', displayVersion: '22H2', buildNumber: '22621', ubr: 4317, version: '10.0.22621' },
  { caption: 'Microsoft Windows 10 Pro', editionId: 'Professional', displayVersion: '22H2', buildNumber: '19045', ubr: 5384, version: '10.0.19045' },
  { caption: 'Microsoft Windows 10 Enterprise', editionId: 'Enterprise', displayVersion: '21H2', buildNumber: '19044', ubr: 3803, version: '10.0.19044' },
  { caption: 'Microsoft Windows Server 2022 Standard', editionId: 'ServerStandard', displayVersion: '21H2', buildNumber: '20348', ubr: 2402, version: '10.0.20348' },
  { caption: 'Microsoft Windows Server 2019 Standard', editionId: 'ServerStandard', displayVersion: '1809', buildNumber: '17763', ubr: 6167, version: '10.0.17763' },
  { caption: 'Microsoft Windows 8.1 Pro', editionId: 'Professional', displayVersion: '6.3', buildNumber: '9600', ubr: 22882, version: '6.3.9600' },
  { caption: 'Microsoft Windows 7 Professional', editionId: 'Professional', displayVersion: 'SP1', buildNumber: '7601', ubr: 26764, version: '6.1.7601' }
];

const INTERFACES = ['Ethernet', 'WiFi', 'Ethernet 2', 'vEthernet (Default Switch)', 'VMware Network Adapter VMnet8'];

const PORT_POOL = [
  { protocol: 'tcp', port: 135, process: 'svchost', service: 'RpcSs', likelihood: 0.9 },
  { protocol: 'tcp', port: 139, process: 'System', service: 'LanmanServer', likelihood: 0.6 },
  { protocol: 'tcp', port: 445, process: 'System', service: 'LanmanServer', likelihood: 0.9 },
  { protocol: 'tcp', port: 3389, process: 'svchost', service: 'TermService', likelihood: 0.2 },
  { protocol: 'tcp', port: 5985, process: 'svchost', service: 'WinRM', likelihood: 0.15 },
  { protocol: 'tcp', port: 5900, process: 'vncserver', service: null, likelihood: 0.12 },
  { protocol: 'tcp', port: 8080, process: 'node', service: null, likelihood: 0.25 },
  { protocol: 'tcp', port: 3000, process: 'node', service: null, likelihood: 0.2 },
  { protocol: 'tcp', port: 5432, process: 'postgres', service: null, likelihood: 0.12 },
  { protocol: 'tcp', port: 1433, process: 'sqlservr', service: 'MSSQLSERVER', likelihood: 0.1 },
  { protocol: 'tcp', port: 3306, process: 'mysqld', service: null, likelihood: 0.1 },
  { protocol: 'tcp', port: 6379, process: 'redis-server', service: null, likelihood: 0.08 },
  { protocol: 'tcp', port: 9200, process: 'java', service: null, likelihood: 0.07 },
  { protocol: 'tcp', port: 80, process: 'httpd', service: null, likelihood: 0.08 },
  { protocol: 'tcp', port: 443, process: 'httpd', service: null, likelihood: 0.08 },
  { protocol: 'tcp', port: 49669, process: 'svchost', service: null, likelihood: 0.7 },
  { protocol: 'tcp', port: 49670, process: 'spoolsv', service: 'Spooler', likelihood: 0.4 },
  { protocol: 'udp', port: 5353, process: 'svchost', service: 'Dnscache', likelihood: 0.6 },
  { protocol: 'udp', port: 5355, process: 'svchost', service: 'Dnscache', likelihood: 0.7 },
  { protocol: 'udp', port: 1900, process: 'svchost', service: 'SSDPSRV', likelihood: 0.5 },
  { protocol: 'udp', port: 5000, process: 'svchost', service: 'FDResPub', likelihood: 0.3 },
  { protocol: 'udp', port: 7680, process: 'svchost', service: 'DoSvc', likelihood: 0.4 }
];

const HOSTNAME_PREFIX = { Desktop: 'CW-WS', Laptop: 'CW-LT', Server: 'CW-SRV', 'Virtual machine': 'CW-VM', Unknown: 'CW-EDGE' };
const TYPE_CHOICE = ['Desktop', 'Desktop', 'Desktop', 'Laptop', 'Laptop', 'Server', 'Virtual machine', 'Unknown'];

const CHASSIS_BY_TYPE = {
  Desktop: [3],
  Laptop: [9],
  Server: [23],
  'Virtual machine': [3],
  Unknown: []
};

function isoDaysAgo(days, hourOffset = 0) {
  const base = new Date('2026-11-12T08:00:00Z');
  return new Date(base.getTime() - days * 86400000 + hourOffset * 60000).toISOString();
}

function buildEndpoints(random, machineType, primaryIp) {
  const endpoints = [];
  for (const item of PORT_POOL) {
    let probability = item.likelihood;
    if (machineType === 'Server') probability = Math.min(0.95, probability + 0.25);
    if (machineType === 'Laptop') probability *= 0.65;
    if (item.port === 3389 && machineType === 'Server') probability = 0.55;
    if (random() > probability) continue;
    const loopbackOnly = item.port >= 49000 && random() < 0.7;
    const address = loopbackOnly ? '127.0.0.1' : random() < 0.55 ? '0.0.0.0' : primaryIp;
    endpoints.push({
      protocol: item.protocol,
      address,
      port: item.port,
      state: item.protocol === 'tcp' ? 'Listen' : 'bound',
      pid: 1000 + Math.floor(random() * 8000),
      process: item.process,
      service: item.service,
      loopbackOnly,
      anyAddress: address === '0.0.0.0'
    });
  }
  if (endpoints.length === 0) {
    endpoints.push({
      protocol: 'tcp',
      address: '0.0.0.0',
      port: 445,
      state: 'Listen',
      pid: 4,
      process: 'System',
      service: 'LanmanServer',
      loopbackOnly: false,
      anyAddress: true
    });
  }
  return endpoints;
}

function buildSoftware(random) {
  const chosen = [];
  const pool = [...SOFTWARE_POOL];
  const count = 6 + Math.floor(random() * 7);
  for (let index = 0; index < count && pool.length > 0; index += 1) {
    const position = Math.floor(random() * pool.length);
    const [item] = pool.splice(position, 1);
    chosen.push({
      name: item.name,
      version: item.version,
      publisher: item.publisher,
      scope: random() < 0.9 ? 'machine' : 'user',
      installDate: null
    });
  }
  return chosen;
}

function buildConfigChecks(random) {
  const weak = (probability) => random() < probability;
  const checks = [];

  const firewallDisabled = weak(0.12);
  checks.push({
    id: 'firewall',
    category: 'network',
    status: firewallDisabled ? 'weak' : 'ok',
    observed: {
      profiles: [
        { name: 'Domain', enabled: true },
        { name: 'Private', enabled: !firewallDisabled || random() < 0.5 },
        { name: 'Public', enabled: !firewallDisabled }
      ],
      disabledProfiles: firewallDisabled ? ['Private', 'Public'] : []
    },
    detail: ''
  });

  const defenderOff = weak(0.16);
  checks.push({
    id: 'defender',
    category: 'endpoint',
    status: defenderOff ? 'weak' : 'ok',
    observed: {
      available: true,
      realTimeProtection: !defenderOff,
      antivirusEnabled: !defenderOff,
      tamperProtection: random() < 0.5,
      signatureAgeDays: Math.floor(random() * 6)
    },
    detail: ''
  });

  const smb1 = weak(0.1);
  checks.push({
    id: 'smb1',
    category: 'network',
    status: smb1 ? 'weak' : 'ok',
    observed: { enabled: smb1, signingRequired: random() < 0.4, smb2Enabled: true },
    detail: ''
  });

  const rdpEnabled = weak(0.28);
  const nla = random() < 0.55;
  checks.push({
    id: 'rdp',
    category: 'remote-access',
    status: 'info',
    observed: { enabled: rdpEnabled, nlaRequired: rdpEnabled ? nla : null },
    detail: ''
  });

  const guestEnabled = weak(0.08);
  checks.push({
    id: 'guestAccount',
    category: 'accounts',
    status: guestEnabled ? 'weak' : 'ok',
    observed: { enabled: guestEnabled },
    detail: ''
  });

  const llmnrEnabled = weak(0.55) && random() < 0.85;
  checks.push({
    id: 'llmnr',
    category: 'network',
    status: llmnrEnabled ? 'weak' : 'ok',
    observed: { enabled: llmnrEnabled, source: random() < 0.5 ? 'default' : 'policy' },
    detail: ''
  });

  const winrmHttp = weak(0.12);
  checks.push({
    id: 'winrm',
    category: 'remote-access',
    status: 'info',
    observed: {
      listenerCount: winrmHttp ? 1 : 0,
      listeners: winrmHttp ? [{ transport: 'HTTP', port: '5985' }] : [],
      httpListeners: winrmHttp ? 1 : 0
    },
    detail: ''
  });

  const uacDisabled = weak(0.08);
  const tokenFilter = weak(0.05);
  checks.push({
    id: 'uac',
    category: 'accounts',
    status: uacDisabled ? 'weak' : 'ok',
    observed: {
      enabled: !uacDisabled,
      adminConsentPrompt: 5,
      localAccountTokenFilter: tokenFilter ? true : null
    },
    detail: ''
  });

  const psV2 = weak(0.2);
  const psV2Unknown = !psV2 && random() < 0.15;
  checks.push({
    id: 'powershellV2',
    category: 'hardening',
    status: psV2 ? 'weak' : psV2Unknown ? 'unknown' : 'ok',
    observed: psV2
      ? { installed: true }
      : psV2Unknown
        ? { unknownReason: 'The requested operation requires elevation.' }
        : { installed: false },
    detail: psV2Unknown ? 'Get-WindowsOptionalFeature requires elevation' : ''
  });

  const secureBootUnknown = random() < 0.25;
  checks.push({
    id: 'secureBoot',
    category: 'hardening',
    status: secureBootUnknown ? 'unknown' : 'ok',
    observed: secureBootUnknown ? { unknownReason: 'Access denied' } : { enabled: true },
    detail: secureBootUnknown ? 'Confirm-SecureBootUEFI requires elevation and UEFI firmware' : ''
  });

  const bitlockerOff = weak(0.3);
  const bitlockerUnknown = !bitlockerOff && random() < 0.2;
  checks.push({
    id: 'bitlocker',
    category: 'data-protection',
    status: bitlockerOff ? 'weak' : bitlockerUnknown ? 'unknown' : 'ok',
    observed: bitlockerOff
      ? { mountPoint: 'C:', protectionStatus: 'Off', encryptionPercentage: 0 }
      : bitlockerUnknown
        ? { unknownReason: 'Access denied ' }
        : { mountPoint: 'C:', protectionStatus: 'On', encryptionPercentage: 100 },
    detail: bitlockerUnknown ? 'Get-BitLockerVolume requires elevation' : ''
  });

  const unquoted = weak(0.18);
  checks.push({
    id: 'unquotedServices',
    category: 'hardening',
    status: unquoted ? 'weak' : 'ok',
    observed: unquoted ? { count: 1 + Math.floor(random() * 3), samples: [{ name: 'VendorAgentSvc', startMode: 'Auto' }] } : { count: 0, samples: [] },
    detail: ''
  });

  const autologonEnabled = weak(0.06);
  checks.push({
    id: 'autologon',
    category: 'accounts',
    status: autologonEnabled ? 'weak' : 'ok',
    observed: { enabled: autologonEnabled, credentialStored: autologonEnabled && random() < 0.5 },
    detail: 'No usernames or passwords are read into the report'
  });

  return checks;
}

function buildUpdates(random) {
  const count = 2 + Math.floor(random() * 12);
  const hotfixes = [];
  for (let index = 0; index < count; index += 1) {
    hotfixes.push({
      id: `KB50${String(10000 + Math.floor(random() * 89999)).slice(0, 5)}`,
      description: random() < 0.5 ? 'Security Update' : 'Update',
      installedOn: isoDaysAgo(Math.floor(random() * 160) + 5),
      source: 'Win32_QuickFixEngineering'
    });
  }
  return {
    collectedAt: isoDaysAgo(0, Math.floor(random() * 600)),
    source: 'Win32_QuickFixEngineering via CIM',
    hotfixSource: 'Win32_QuickFixEngineering',
    hotfixes,
    hotfixCount: hotfixes.length,
    updateService: { name: 'wuauserv', status: random() < 0.7 ? 'Running' : 'Stopped' },
    policy: { noAutoUpdate: null, auOptions: 4, wsusServer: null },
    lastSearchSuccess: random() < 0.5 ? isoDaysAgo(Math.floor(random() * 10)) : null,
    lastInstallSuccess: random() < 0.5 ? isoDaysAgo(Math.floor(random() * 20)) : null,
    pendingReboot: random() < 0.15,
    errors: []
  };
}

export function generateSampleMachines({ advisories, count = 60, now = new Date() } = {}) {
  const random = mulberry32(0xa4e5c0de);
  const machines = [];

  for (let index = 0; index < count; index += 1) {
    const machineType = TYPE_CHOICE[index % TYPE_CHOICE.length];
    const profile = OS_PROFILES[(index * 3) % OS_PROFILES.length];
    const hostname = `${HOSTNAME_PREFIX[machineType]}-${String(index + 1).padStart(3, '0')}`;
    const addressOctet = 10 + (index % 200);
    const addresses = [
      {
        address: `10.42.${Math.floor(index / 200)}.${addressOctet}`,
        family: 'IPv4',
        interface: INTERFACES[index % INTERFACES.length],
        prefixLength: 24,
        prefixOrigin: 'Dhcp'
      }
    ];
    if (index % 7 === 0) {
      addresses.push({
        address: '10.42.200.15',
        family: 'IPv4',
        interface: 'Radmin VPN',
        prefixLength: 8,
        prefixOrigin: 'Manual'
      });
    }
    if (index % 4 === 0) {
      addresses.push({
        address: `fe80::${(0x1000 + index).toString(16)}:${(0x2000 + index).toString(16)}`,
        family: 'IPv6',
        interface: INTERFACES[index % INTERFACES.length],
        prefixLength: 64,
        prefixOrigin: 'WellKnown'
      });
    }

    const model =
      machineType === 'Virtual machine'
        ? 'VMware Virtual Platform'
        : machineType === 'Server'
          ? 'PowerEdge R650'
          : machineType === 'Laptop'
            ? 'ThinkPad T14 Gen 4'
            : machineType === 'Unknown'
              ? 'OEM System'
              : 'OptiPlex 7010';

    const host = {
      hostname,
      caption: profile.caption,
      productName: profile.caption.replace('Microsoft ', ''),
      editionId: profile.editionId,
      displayVersion: profile.displayVersion,
      releaseId: '2009',
      version: profile.version,
      buildNumber: profile.buildNumber,
      ubr: profile.ubr,
      build: `${profile.buildNumber}.${profile.ubr}`,
      architecture: '64-bit',
      language: '1033',
      manufacturer: machineType === 'Virtual machine' ? 'VMware, Inc.' : machineType === 'Unknown' ? null : 'Dell Inc.',
      model,
      pcSystemType: machineType === 'Unknown' ? null : machineType === 'Laptop' ? 2 : machineType === 'Server' ? 3 : 1,
      chassisTypes: CHASSIS_BY_TYPE[machineType] ?? [],
      totalMemoryGb: [8, 16, 16, 32, 32, 64][index % 6],
      bootTime: isoDaysAgo(Math.floor(random() * 6)),
      collectedAt: isoDaysAgo(0, -Math.floor(random() * 120)),
      timeZone: 'Azerbaijan Standard Time',
      addresses
    };

    const primaryIp = selectPrimaryIp(addresses);
    const ips = uniqueIps(addresses);

    const machine = {
      id: `sample-${String(index + 1).padStart(2, '0')}`,
      sample: true,
      hostname,
      machineType: classifyMachine(host),
      ips,
      primaryIp,
      status: 'sample',
      host,
      endpoints: buildEndpoints(random, machineType, primaryIp),
      software: buildSoftware(random),
      configChecks: buildConfigChecks(random),
      updates: buildUpdates(random),
      errors: [],
      timestamps: {
        startedAt: isoDaysAgo(0, -180 - index),
        completedAt: isoDaysAgo(0, -170 - index),
        collectors: {}
      }
    };

    machine.findings = evaluateFindings(machine, { advisories, now });
    machine.totals = computeMachineTotals(machine);
    machines.push(machine);
  }

  return machines;
}

export function sampleDataset(advisories, now = new Date()) {
  const machines = generateSampleMachines({ advisories, count: 60, now });
  return {
    label: 'SAMPLE DATA',
    notice:
      'Synthetic machines generated locally for list, expansion and filter testing. They are not real hosts and are never scanned.',
    generatedAt: now.toISOString(),
    count: machines.length,
    machines
  };
}
