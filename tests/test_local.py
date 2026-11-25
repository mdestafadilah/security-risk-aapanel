#!/usr/bin/env python
# coding: utf-8
"""
Local test-suite for the aaPanel "Security Risk" plugin.

The rule engine is path-agnostic: set SECRISK_SYSROOT to a throw-away directory
and every /etc lookup resolves inside it. That lets the whole detect -> fix ->
verify -> restore cycle run on a developer machine without touching the host.

    python tests/test_local.py
"""

import io
import os
import re
import sys
import json
import shutil
import tempfile
import importlib.util

HERE = os.path.dirname(os.path.abspath(__file__))
PLUGIN = os.path.join(os.path.dirname(HERE), 'securityrisk')
MAIN = os.path.join(PLUGIN, 'securityrisk_main.py')

PASSED = []
FAILED = []


def check(label, condition, extra=''):
    if condition:
        PASSED.append(label)
        print('  PASS  %s' % label)
    else:
        FAILED.append(label)
        print('  FAIL  %s %s' % (label, extra))


def write(root, rel, body, mode=0o644):
    path = os.path.join(root, rel.replace('/', os.sep))
    parent = os.path.dirname(path)
    if not os.path.isdir(parent):
        os.makedirs(parent)
    with io.open(path, 'w', encoding='utf-8', newline='\n') as f:
        f.write(body)
    try:
        os.chmod(path, mode)
    except OSError:
        pass
    return path


def read(root, rel):
    path = os.path.join(root, rel.replace('/', os.sep))
    with io.open(path, 'r', encoding='utf-8', errors='replace') as f:
        return f.read()


def build_fixture(root):
    write(root, 'etc/os-release', (
        'NAME="Ubuntu"\n'
        'VERSION="22.04.4 LTS (Jammy Jellyfish)"\n'
        'ID=ubuntu\n'
        'ID_LIKE=debian\n'
        'PRETTY_NAME="Ubuntu 22.04.4 LTS"\n'
        'VERSION_ID="22.04"\n'
    ))
    write(root, 'www/server/panel/data/port.pl', '8888')
    write(root, 'etc/profile', (
        '# /etc/profile\n'
        'export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin\n'
        'umask 022\n'
    ))
    write(root, 'etc/sudoers', (
        'Defaults\tenv_reset\n'
        'Defaults\tmail_badpass\n'
        'root\tALL=(ALL:ALL) ALL\n'
        '%sudo\tALL=(ALL:ALL) NOPASSWD: ALL\n'
        'bob\tALL=(ALL) NOPASSWD: ALL, \\\n'
        '\tPASSWD: /bin/ls\n'
        '#includedir /etc/sudoers.d\n'
    ), 0o440)
    write(root, 'etc/sudoers.d/90-cloud-init-users',
          'cloud-init ALL=(ALL) NOPASSWD: ALL\n', 0o440)
    write(root, 'etc/passwd', (
        'root:x:0:0:root:/root:/bin/bash\n'
        'testuser:x:1000:1000::/home/testuser:/bin/bash\n'
    ))
    write(root, 'etc/group', 'root:x:0:\ntestuser:x:1000:\n')
    write(root, 'etc/gshadow', 'root:*::\n')
    write(root, 'etc/shadow', (
        'root:$6$abcdefgh$hash:19000:0:99999:7:::\n'
        'testuser::19000:0:99999:7:::\n'
    ), 0o600)
    write(root, 'etc/ssh/sshd_config', (
        '# sshd_config\n'
        'Port 22\n'
        'PermitRootLogin yes\n'
        'PasswordAuthentication yes\n'
        'UsePAM yes\n'
    ), 0o600)


def build_rhel_fixture(root):
    write(root, 'etc/os-release', (
        'NAME="Rocky Linux"\n'
        'VERSION="9.4 (Blue Onyx)"\n'
        'ID="rocky"\n'
        'ID_LIKE="rhel centos fedora"\n'
        'PRETTY_NAME="Rocky Linux 9.4 (Blue Onyx)"\n'
        'VERSION_ID="9.4"\n'
    ))
    write(root, 'www/server/panel/data/port.pl', '12345')
    write(root, 'etc/profile', 'export PATH=/usr/local/sbin:/usr/bin\n')
    write(root, 'etc/sudoers', (
        'Defaults\tenv_reset\n'
        'root\tALL=(ALL:ALL) ALL\n'
        '%wheel\tALL=(ALL) ALL\n'
        '#includedir /etc/sudoers.d\n'
    ), 0o440)
    write(root, 'etc/passwd', 'root:x:0:0:root:/root:/bin/bash\n')
    write(root, 'etc/group', 'root:x:0:\nwheel:x:10:\n')
    write(root, 'etc/shadow', 'root:$6$xyz$hash:19000:0:99999:7:::\n', 0o600)
    write(root, 'etc/ssh/sshd_config', (
        'Port 22\n'
        'PermitRootLogin no\n'
        'PasswordAuthentication no\n'
    ), 0o600)
    write(root, 'etc/selinux/config', 'SELINUX=enforcing\nSELINUXTYPE=targeted\n')
    write(root, 'sys/fs/selinux/enforce', '1')


def load_module(root, data_dir):
    os.environ['SECRISK_SYSROOT'] = root
    os.environ['SECRISK_DATA'] = data_dir
    spec = importlib.util.spec_from_file_location('securityrisk_main', MAIN)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def main():
    root = tempfile.mkdtemp(prefix='secrisk-root-')
    data = tempfile.mkdtemp(prefix='secrisk-data-')
    print('fixture root : %s' % root)
    print('plugin data  : %s\n' % data)

    build_fixture(root)
    mod = load_module(root, data)
    real_perm_rules = mod.PERM_RULES
    mod.PERM_RULES = []  # Windows cannot represent unix modes; tested separately
    app = mod.securityrisk_main()

    original_profile = read(root, 'etc/profile')
    original_sudoers = read(root, 'etc/sudoers')

    print('1. scan')
    res = app.get_index({})
    items = {i['id']: i for i in res['items']}
    check('cli_timeout reported as risk', items['cli_timeout']['status'] == 'risk')
    check('sudo_nopasswd reported as risk', items['sudo_nopasswd']['status'] == 'risk')
    check('both sudoers files listed',
          '/etc/sudoers' in items['sudo_nopasswd']['title']
          and '90-cloud-init-users' in items['sudo_nopasswd']['title'])
    check('ssh_root_login reported as risk', items['ssh_root_login']['status'] == 'risk')
    check('ssh_password_auth reported as risk', items['ssh_password_auth']['status'] == 'risk')
    check('empty_password found testuser', items['empty_password'].get('users') == ['testuser'])
    check('panel_ssl reported as risk', items['panel_ssl']['status'] == 'risk')
    check('summary counts risks', res['summary']['risk'] >= 6,
          json.dumps(res['summary']))
    check('scan_time present', isinstance(res.get('scan_time'), int))

    print('\n2. fix cli_timeout')
    out = app.fix({'id': 'cli_timeout'})
    check('fix returned success', out.get('status') is True, json.dumps(out)[:200])
    profile = read(root, 'etc/profile')
    check('TMOUT=300 appended', 'TMOUT=300' in profile)
    check('TMOUT is readonly', 'readonly TMOUT' in profile)
    check('TMOUT is exported', 'export TMOUT' in profile)
    check('check now passes', out['item']['status'] == 'ok')
    bid_timeout = out.get('backup')
    check('backup id returned', bool(bid_timeout))
    backup_file = os.path.join(data, 'backup', bid_timeout, 'etc', 'profile')
    check('backup contains original profile',
          os.path.isfile(backup_file) and io.open(backup_file, encoding='utf-8').read() == original_profile)

    print('\n3. fix sudo_nopasswd')
    out = app.fix({'id': 'sudo_nopasswd'})
    check('fix returned success', out.get('status') is True, json.dumps(out)[:300])
    sudoers = read(root, 'etc/sudoers')
    dropin = read(root, 'etc/sudoers.d/90-cloud-init-users')
    active = [l for l in sudoers.splitlines()
              if 'NOPASSWD' in l and not l.lstrip().startswith('#')]
    check('no active NOPASSWD left in /etc/sudoers', not active, str(active))
    check('continuation line commented too',
          all(l.lstrip().startswith('#') for l in sudoers.splitlines()
              if 'NOPASSWD' in l or 'PASSWD: /bin/ls' in l))
    check('drop-in NOPASSWD commented',
          all(l.lstrip().startswith('#') for l in dropin.splitlines() if 'NOPASSWD' in l))
    check('other sudoers rules untouched', 'root\tALL=(ALL:ALL) ALL' in sudoers)
    check('check now passes', out['item']['status'] == 'ok')
    check('backup keeps original sudoers',
          io.open(os.path.join(data, 'backup', out.get('backup', ''), 'etc', 'sudoers'),
                  encoding='utf-8').read() == original_sudoers)

    print('\n4. fix empty_password')
    out = app.fix({'id': 'empty_password'})
    check('fix returned success', out.get('status') is True, json.dumps(out)[:200])
    check('shadow entry locked',
          re.search(r'^testuser:!', read(root, 'etc/shadow'), re.M) is not None)
    check('root hash untouched', 'root:$6$' in read(root, 'etc/shadow'))
    check('check now passes', out['item']['status'] == 'ok')

    print('\n5. fix ssh keys')
    out = app.fix({'id': 'ssh_root_login'})
    check('PermitRootLogin rewritten',
          'PermitRootLogin prohibit-password' in read(root, 'etc/ssh/sshd_config'))
    check('ssh_root_login now ok', out['item']['status'] == 'ok')
    out = app.fix({'id': 'ssh_password_auth'})
    check('PasswordAuthentication rewritten',
          'PasswordAuthentication no' in read(root, 'etc/ssh/sshd_config'))
    check('ssh_password_auth now ok', out['item']['status'] == 'ok')
    check('sshd_config mode preserved', mod._mode('/etc/ssh/sshd_config') in (None, 0o600, 0o666, 0o444))

    print('\n5b. drop-in overrides the main config')
    write(root, 'etc/ssh/sshd_config.d/50-cloud-init.conf', 'PasswordAuthentication yes\n', 0o600)
    items = {i['id']: i for i in app.get_index({})['items']}
    check('drop-in value wins over sshd_config', items['ssh_password_auth']['status'] == 'risk',
          items['ssh_password_auth']['detail'])
    out = app.fix({'id': 'ssh_password_auth'})
    check('drop-in was the file edited',
          'PasswordAuthentication no' in read(root, 'etc/ssh/sshd_config.d/50-cloud-init.conf'))
    check('main config left alone',
          'PasswordAuthentication no' in read(root, 'etc/ssh/sshd_config'))
    check('check now passes again', out['item']['status'] == 'ok')

    print('\n6. permission rule (pure)')
    mod.PERM_RULES = real_perm_rules
    issues = mod._perm_issues([('/etc/passwd', 0o644), ('/etc/shadow', 0o644),
                               ('/etc/sudoers', 0o440), ('/etc/group', 0o000)])
    flagged = sorted(i['path'] for i in issues)
    check('only the too-permissive file is flagged', flagged == ['/etc/shadow'], str(flagged))
    check('stricter-than-needed mode is accepted',
          mod._perm_issues([('/etc/shadow', 0o000)]) == [])
    mod.PERM_RULES = []

    print('\n7. history + restore')
    hist = app.get_history({})
    check('history has entries', len(hist['items']) >= 4, str(len(hist['items'])))
    check('history newest first', hist['items'][0]['id'] == 'ssh_password_auth',
          hist['items'][0]['id'])
    out = app.restore({'backup': bid_timeout})
    check('restore succeeded', out.get('status') is True, json.dumps(out)[:200])
    check('profile restored byte for byte', read(root, 'etc/profile') == original_profile)
    check('restore rejects path traversal',
          app.restore({'backup': '../../etc'}).get('status') is False)
    check('fix rejects unknown id', app.fix({'id': 'nope'}).get('status') is False)

    print('\n8. rescan after fixes')
    res = app.get_index({})
    items = {i['id']: i for i in res['items']}
    check('cli_timeout still ok after restore? no - risk again',
          items['cli_timeout']['status'] == 'risk')
    check('sudo_nopasswd stays ok', items['sudo_nopasswd']['status'] == 'ok')
    check('empty_password stays ok', items['empty_password']['status'] == 'ok')
    check('summary is consistent',
          res['summary']['total'] == len(res['items'])
          and res['summary']['risk'] + res['summary']['ok']
          + res['summary']['unknown'] == res['summary']['total'])

    print('\n9. plugin contract')
    check('dynamic route refuses anonymous call', app._check({}) is False)
    html = app.index({})
    check('index() serves the UI', '<!DOCTYPE html>' in html and 'Security Risk' in html)
    check('class name matches file name', type(app).__name__ == 'securityrisk_main')

    print('\n10. distribution profile - Ubuntu')
    sysinfo = res['system']
    check('family detected as debian', sysinfo['family'] == 'debian', sysinfo['family'])
    check('pretty name shown', sysinfo['os'] == 'Ubuntu 22.04.4 LTS', sysinfo['os'])
    check('version parsed', sysinfo['os_version'] == '22.04')
    check('apt chosen as package manager', sysinfo['pkg'] == 'apt-get', sysinfo['pkg'])
    check('ufw chosen as firewall', sysinfo['firewall'] == 'ufw')
    check('ssh unit is "ssh"', sysinfo['ssh_service'] == 'ssh')
    check('admin group is sudo', sysinfo['sudo_group'] == 'sudo')
    check('panel port read from port.pl', sysinfo['panel_port'] == '8888')
    check('apparmor check present on debian family', 'apparmor' in items)
    check('selinux check skipped on debian family', 'selinux' not in items)
    check('firewall commands are ufw specific',
          any(c.startswith('ufw ') for c in items['firewall']['commands']),
          str(items['firewall']['commands']))
    check('firewall commands use the real panel port',
          any('8888' in c for c in items['firewall']['commands']))
    check('fail2ban install uses apt',
          any(c.startswith('apt-get') for c in items['fail2ban']['commands']))
    # a fresh NOPASSWD rule so the risk branch (not the "no action" branch) is inspected
    write(root, 'etc/sudoers.d/91-test', 'tester ALL=(ALL) NOPASSWD: ALL\n', 0o440)
    items_os = {i['id']: i for i in app.get_index({})['items']}
    check('sudo risk returns for the new rule', items_os['sudo_nopasswd']['status'] == 'risk')
    check('sudo advice names the %sudo group',
          '%sudo' in items_os['sudo_nopasswd']['solution'],
          items_os['sudo_nopasswd']['solution'][:120])

    print('\n11. distribution profile - Rocky Linux')
    root2 = tempfile.mkdtemp(prefix='secrisk-rhel-')
    data2 = tempfile.mkdtemp(prefix='secrisk-data2-')
    build_rhel_fixture(root2)
    mod2 = load_module(root2, data2)
    mod2.PERM_RULES = []
    app2 = mod2.securityrisk_main()
    res2 = app2.get_index({})
    sys2 = res2['system']
    items2 = {i['id']: i for i in res2['items']}
    check('family detected as rhel', sys2['family'] == 'rhel', sys2['family'])
    check('rocky name/version parsed',
          sys2['os_name'] == 'Rocky Linux' and sys2['os_version'] == '9.4',
          '%s %s' % (sys2['os_name'], sys2['os_version']))
    check('dnf chosen as package manager', sys2['pkg'] == 'dnf', sys2['pkg'])
    check('firewalld chosen as firewall', sys2['firewall'] == 'firewalld')
    check('ssh unit is sshd', sys2['ssh_service'] == 'sshd')
    check('admin group is wheel', sys2['sudo_group'] == 'wheel')
    check('selinux check present on rhel family', 'selinux' in items2)
    check('selinux enforcing reported ok', items2['selinux']['status'] == 'ok',
          items2['selinux']['detail'])
    check('apparmor check skipped on rhel family', 'apparmor' not in items2)
    check('firewall commands are firewalld specific',
          any('firewall-cmd' in c for c in items2['firewall']['commands']),
          str(items2['firewall']['commands']))
    check('firewall commands use port 12345',
          any('12345' in c for c in items2['firewall']['commands']))
    check('fail2ban install pulls epel first',
          any('epel-release' in c for c in items2['fail2ban']['commands']),
          str(items2['fail2ban']['commands']))
    check('rocky scan is clean on ssh', items2['ssh_root_login']['status'] == 'ok'
          and items2['ssh_password_auth']['status'] == 'ok')
    check('no sudo risk when no NOPASSWD', items2['sudo_nopasswd']['status'] == 'ok')

    print('\n12. unknown distribution falls back safely')
    root3 = tempfile.mkdtemp(prefix='secrisk-other-')
    data3 = tempfile.mkdtemp(prefix='secrisk-data3-')
    write(root3, 'etc/profile', 'export PATH=/usr/bin\n')
    mod3 = load_module(root3, data3)
    mod3.PERM_RULES = []
    app3 = mod3.securityrisk_main()
    res3 = app3.get_index({})
    sys3 = res3['system']
    check('falls back to generic linux', sys3['family'] == 'unknown', sys3['family'])
    check('generic label used', sys3['family_label'] == 'Generic Linux')
    check('no apparmor/selinux check without a known family',
          not any(i['id'] in ('selinux', 'apparmor') for i in res3['items']))
    check('generic firewall advice still given',
          any('iptables' in c for i in res3['items'] if i['id'] == 'firewall'
              for c in i['commands']))

    print('\n%d passed, %d failed' % (len(PASSED), len(FAILED)))
    shutil.rmtree(root, ignore_errors=True)
    shutil.rmtree(data, ignore_errors=True)
    return 0 if not FAILED else 1


if __name__ == '__main__':
    sys.exit(main())
