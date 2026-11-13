const VIRTUAL_MODEL = /virtual|vmware|virtualbox|hyper-?v|qemu|parallels|xen|bochs|kvm|bhyve/i;

const CHASSIS = {
  LAPTOP: new Set([8, 9, 10, 14, 30, 31, 32]),
  DESKTOP: new Set([3, 4, 5, 6, 7, 13, 15, 16, 24, 35, 36]),
  SERVER: new Set([17, 23, 25, 28, 29]),
  APPLIANCE: new Set([33, 34])
};

const VIRTUAL_INTERFACE = /vEthernet|vmware|virtualbox|vethernet|hyper-v|wsl|loopback|npcap|radmin|tap-|tun|bluetooth|teredo|isatap/i;
const VIRTUAL_ADDRESS = /^(26\.|172\.1[7-9]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168\.56\.|169\.254\.)/;

function addressScore(item) {
  const address = String(item?.address ?? '');
  const iface = String(item?.interface ?? '');
  let score = 0;
  if (address.includes('.')) score += 100;
  if (String(item?.prefixOrigin).toLowerCase() === 'dhcp') score += 25;
  if (!VIRTUAL_INTERFACE.test(iface)) score += 20;
  if (VIRTUAL_ADDRESS.test(address)) score -= 45;
  if (address.startsWith('fe80:') || address.startsWith('::')) score -= 60;
  return score;
}

export function asArray(value) {
  if (Array.isArray(value)) return value;
  if (value === null || value === undefined) return [];
  return [value];
}

/** Best-effort machine classification. Returns "Unknown" when evidence is absent. */
export function classifyMachine(host) {
  if (!host || typeof host !== 'object') return 'Unknown';
  const model = `${host.manufacturer ?? ''} ${host.model ?? ''}`.trim();
  if (model && VIRTUAL_MODEL.test(model)) return 'Virtual machine';

  const chassis = asArray(host.chassisTypes)
    .map((value) => Number(value))
    .filter((value) => Number.isInteger(value) && value > 0);

  const has = (set) => chassis.some((value) => set.has(value));
  if (has(CHASSIS.SERVER)) return 'Server';
  if (has(CHASSIS.LAPTOP)) return 'Laptop';
  if (has(CHASSIS.DESKTOP)) return 'Desktop';
  if (has(CHASSIS.APPLIANCE)) return 'Appliance';

  const pcSystemType = Number(host.pcSystemType);
  if (pcSystemType === 2) return 'Laptop';
  if (pcSystemType === 1) return 'Desktop';
  if ([3, 4, 5, 7].includes(pcSystemType)) return 'Server';
  if (pcSystemType === 6) return 'Appliance';
  return 'Unknown';
}

export function selectPrimaryIp(addresses = []) {
  const list = asArray(addresses).filter((item) => item && item.address);
  if (list.length === 0) return null;
  const ranked = [...list].sort((a, b) => addressScore(b) - addressScore(a));
  const best = ranked[0];
  if (addressScore(best) > -60) return best.address;
  return list[0].address;
}

export function uniqueIps(addresses = []) {
  const seen = new Set();
  const result = [];
  for (const item of asArray(addresses)) {
    const address = typeof item === 'string' ? item : item?.address;
    if (!address || seen.has(address)) continue;
    seen.add(address);
    result.push(address);
  }
  return result;
}
