import datetime
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys


def command(args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=12)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or 'Command failed: ' + args[0])
    return result.stdout


def host():
    release = platform.freedesktop_os_release()
    addresses = []
    for interface in json.loads(command(['ip', '-j', 'address', 'show'])):
        for item in interface.get('addr_info', []):
            address = ipaddress.ip_address(item['local'])
            if not address.is_loopback and not address.is_link_local:
                addresses.append(dict(address=str(address), family='IPv4' if address.version == 4 else 'IPv6',
                                      interface=interface['ifname'], prefixLength=item['prefixlen']))
    return dict(hostname=platform.node(), platform='linux', caption=release.get('PRETTY_NAME', 'Linux'),
                distributionId=release.get('ID'), distributionVersion=release.get('VERSION_ID'),
                version=platform.release(), displayVersion=release.get('VERSION_ID'),
                architecture=platform.machine(), addresses=addresses)


def ports():
    endpoints = []
    output = command(['ss', '-H', '-lntuap'])
    for line in output.splitlines():
        fields = line.split()
        if len(fields) < 5 or fields[0] not in ('tcp', 'udp'):
            continue
        protocol, state = fields[:2]
        if protocol == 'tcp' and state != 'LISTEN':
            continue
        address, port = fields[4].rsplit(':', 1)
        address = address.strip('[]')
        if not port.isdigit():
            continue
        process = re.search(r'users:\(\("([^"]+)",pid=(\d+)', line)
        endpoints.append(dict(protocol=protocol, address=address, port=int(port), state=state,
                              process=process[1] if process else None, pid=int(process[2]) if process else None,
                              loopbackOnly=address == '::1' or address.startswith('127.'),
                              anyAddress=address in ('*', '0.0.0.0', '::')))
    return dict(source='ss', endpoints=endpoints, processLookupAvailable=os.geteuid() == 0)


def software():
    release = platform.freedesktop_os_release()
    distribution = release.get('ID')
    version = release.get('VERSION_ID', '')
    ecosystem = None
    if distribution == 'debian' and re.fullmatch(r'\d+(?:\.\d+)*', version):
        ecosystem = 'Debian:' + version.split('.')[0]
    elif distribution == 'ubuntu' and re.fullmatch(r'\d+\.\d+', version):
        lts = 'LTS' in release.get('VERSION', '') or 'LTS' in release.get('PRETTY_NAME', '')
        ecosystem = 'Ubuntu:' + version + (':LTS' if lts else '')
    elif distribution == 'alpine' and re.fullmatch(r'\d+\.\d+(?:\.\d+)?', version):
        ecosystem = 'Alpine:v' + '.'.join(version.split('.')[:2])
    if shutil.which('dpkg-query'):
        output = command(['dpkg-query', '-W', '-f=${binary:Package}\t${Version}\t${db:Status-Status}\t${source:Package}\t${source:Version}\n'])
        rows = [line.split('\t') for line in output.splitlines()]
        packages = [dict(name=row[0], version=row[1], sourceName=row[3], sourceVersion=row[4])
                    for row in rows if len(row) == 5 and row[2] == 'installed']
        source = 'dpkg-query'
    elif shutil.which('rpm'):
        output = command(['rpm', '-qa', '--qf', '%{NAME}\t%{VERSION}-%{RELEASE}\n'])
        packages = [dict(name=row[0], version=row[1]) for row in (line.split('\t') for line in output.splitlines()) if len(row) == 2]
        source = 'rpm'
    elif shutil.which('apk'):
        packages = []
        for block in Path('/lib/apk/db/installed').read_text().split('\n\n'):
            fields = dict(line.split(':', 1) for line in block.splitlines() if ':' in line)
            if fields.get('P') and fields.get('V') and fields.get('o'):
                packages.append(dict(name=fields['P'], version=fields['V'],
                                     sourceName=fields['o'], sourceVersion=fields['V']))
        source = 'apk'
    else:
        raise RuntimeError('Supported package manager required: dpkg, rpm or apk')
    return dict(source=source, ecosystem=ecosystem, software=packages[:1500], totalFound=len(packages), truncated=len(packages) > 1500)


def updates():
    return dict(source='Linux reboot marker', platform='linux', hotfixes=[],
                updateService=dict(name='Linux package manager', status='unknown'),
                pendingReboot=os.path.exists('/var/run/reboot-required'),
                errors=['Available security updates were not queried. Use the distribution package manager to verify patch status.'])


def config():
    checks = []
    for name, minimum in [('kernel.randomize_va_space', 2), ('kernel.kptr_restrict', 1),
                          ('kernel.dmesg_restrict', 1), ('fs.protected_hardlinks', 1),
                          ('fs.protected_symlinks', 1)]:
        check = dict(id='linux-sysctl-' + name, category='kernel', observed={})
        try:
            value = int(Path('/proc/sys', name.replace('.', '/')).read_text().strip())
            check.update(status='weak' if value < minimum else 'ok', observed=dict(value=value))
        except (OSError, ValueError) as error:
            check.update(status='unknown', detail=str(error))
        checks.append(check)

    # -T reads base settings and Include files. Match blocks need connection context.
    try:
        sshd = shutil.which('sshd') or '/usr/sbin/sshd'
        output = command([sshd, '-T'])
        settings = dict(line.split(None, 1) for line in output.splitlines() if ' ' in line)
        for name in ['permitrootlogin', 'passwordauthentication', 'permitemptypasswords']:
            value = settings.get(name)
            checks.append(dict(id='linux-ssh-' + name, category='ssh',
                               status='unknown' if value is None else 'weak' if value == 'yes' else 'ok',
                               observed=dict(value=value, scope='base'),
                               detail='Base SSH daemon setting. Per-user Match blocks can override this value.'))
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        checks.append(dict(id='linux-ssh', category='ssh', status='unknown',
                           detail=str(error), observed={}))
    return dict(checks=checks)


if __name__ == '__main__':
    try:
        collectors = dict(host=host, ports=ports, software=software, updates=updates, config=config)
        result = collectors[sys.argv[1]]()
        result['collectedAt'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    except Exception as error:
        result = dict(__collectorError=str(error))
    print('@@ARES@@' + json.dumps(result))
