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


def leftovers(root):
    out = []
    for base, _dirs, files in os.walk(root):
        out += [os.path.join(base, f) for f in files if '.secrisk-' in f]
    return out


class FakeRunner(object):
    """Stands in for subprocess: rules map a binary name to (out, ok) or a callable."""

    def __init__(self, **rules):
        self.rules = rules
        self.calls = []

    def __call__(self, args):
        self.calls.append(list(args))
        rule = self.rules.get(os.path.basename(args[0]).replace('-', '_'))
        if rule is None:
            return '', False  # binary not installed
        return rule(args) if callable(rule) else rule


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
    # cloud images: the admin user has no password, only NOPASSWD sudo
    write(root, 'etc/sudoers.d/90-cloud-init-users',
          'ubuntu ALL=(ALL) NOPASSWD: ALL\n', 0o440)
    write(root, 'etc/passwd', (
        'root:x:0:0:root:/root:/bin/bash\n'
        'testuser:x:1000:1000::/home/testuser:/bin/bash\n'
        'bob:x:1001:1001::/home/bob:/bin/bash\n'
        'ubuntu:x:1002:1002::/home/ubuntu:/bin/bash\n'
    ))
    write(root, 'etc/group', (
        'root:x:0:\nshadow:x:42:\nsudo:x:27:bob\n'
        'testuser:x:1000:\nbob:x:1001:\nubuntu:x:1002:\n'
    ))
    write(root, 'etc/gshadow', 'root:*::\n')
    write(root, 'etc/shadow', (
        'root:$6$abcdefgh$hash:19000:0:99999:7:::\n'
        'testuser::19000:0:99999:7:::\n'
        'bob:$6$bobsalt$hash:19000:0:99999:7:::\n'
        'ubuntu:!:19000:0:99999:7:::\n'
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


def validators_and_exit_codes():
    """The validators must decide on the real exit code (the panel's ExecShell
    never reports one, which used to make every check look successful)."""
    print('\n13. validators, exit codes and rollback')
    root = tempfile.mkdtemp(prefix='secrisk-run-')
    data = tempfile.mkdtemp(prefix='secrisk-rundata-')
    build_fixture(root)
    mod = load_module(root, data)
    mod.PERM_RULES = []
    app = mod.securityrisk_main()
    main_sudoers = mod._path('/etc/sudoers')

    # sshd -t rejects the staged file: the real config is never touched
    ssh_before = read(root, 'etc/ssh/sshd_config')
    mod._RUNNER = FakeRunner(sshd=lambda a: ('line 3: Bad configuration option', False))
    out = app.fix({'id': 'ssh_root_login'})
    check('sshd -t failure is a failure', out.get('status') is False, json.dumps(out)[:200])
    check('message says nothing changed', 'nothing was changed' in out.get('msg', ''),
          out.get('msg'))
    check('sshd_config byte for byte unchanged', read(root, 'etc/ssh/sshd_config') == ssh_before)
    check('no temp file left after rejection', not leftovers(root), str(leftovers(root)))

    # validation passes: staged file checked first, full config next, reload last
    runner = FakeRunner(sshd=lambda a: ('', '-T' not in a), systemctl=('', True))
    mod._RUNNER = runner
    out = app.fix({'id': 'ssh_root_login'})
    check('valid sshd change applied', out.get('status') is True, json.dumps(out)[:200])
    order = [' '.join(c[:2]) for c in runner.calls if c[0] in ('sshd', 'systemctl')]
    check('order: sshd -t -f tmp, sshd -t, reload',
          order.index('sshd -t') < order.index('systemctl reload')
          and any(c[:3] == ['sshd', '-t', '-f'] and '.secrisk-' in c[3] for c in runner.calls),
          str(order))
    check('reload reported', 'Reloaded ssh' in out.get('changes', []), str(out.get('changes')))

    # sudoers: staged file rejected -> nothing written
    sudo_before = read(root, 'etc/sudoers')
    mod._RUNNER = FakeRunner(visudo=('>>> sudoers.tmp: syntax error near line 4 <<<', False))
    out = app.fix({'id': 'sudo_nopasswd'})
    check('visudo failure is a failure', out.get('status') is False)
    check('sudoers unchanged after staged rejection', read(root, 'etc/sudoers') == sudo_before)

    # staged file fine, full policy rejected -> rolled back
    mod._RUNNER = FakeRunner(visudo=lambda a: ('', a[-1] != main_sudoers))
    out = app.fix({'id': 'sudo_nopasswd'})
    check('full policy failure rolls back', out.get('status') is False
          and 'Rolled back' in out.get('msg', ''), out.get('msg'))
    check('sudoers restored after rollback', read(root, 'etc/sudoers') == sudo_before)
    check('no temp file left after rollback', not leftovers(root), str(leftovers(root)))

    # passwd -l: a failing exit code and a "success" that changed nothing both fail
    mod._RUNNER = FakeRunner(passwd=('passwd: Authentication token manipulation error', False))
    out = app.fix({'id': 'empty_password'})
    check('passwd -l failure reported', out.get('status') is False
          and 'testuser' in out.get('msg', ''), out.get('msg'))
    mod._RUNNER = FakeRunner(passwd=('', True))
    out = app.fix({'id': 'empty_password'})
    check('passwd -l without effect is not trusted', out.get('status') is False
          and 'Still without a password' in out.get('msg', ''), out.get('msg'))

    def really_lock(args):
        path = os.path.join(root, 'etc', 'shadow')
        body = io.open(path, encoding='utf-8').read()
        io.open(path, 'w', encoding='utf-8', newline='\n').write(
            body.replace('%s::' % args[-1], '%s:!:' % args[-1]))
        return 'passwd: password expiry information changed.', True
    mod._RUNNER = FakeRunner(passwd=really_lock)
    out = app.fix({'id': 'empty_password'})
    check('passwd -l that locks succeeds', out.get('status') is True, out.get('msg'))

    # status checks read the exit code / the exact answer
    mod._RUNNER = FakeRunner(aa_status=('', False))
    check('aa-status failure is not "enabled"', mod.check_apparmor()['status'] == 'risk')
    mod._RUNNER = FakeRunner()
    check('missing aa-status is not "enabled"', mod.check_apparmor()['status'] == 'risk')
    mod._RUNNER = FakeRunner(aa_status=('', True))
    check('aa-status exit 0 is enabled', mod.check_apparmor()['status'] == 'ok')
    mod._RUNNER = FakeRunner(firewall_cmd=('not running', False))
    check('"not running" firewalld is not active', mod.check_firewall()['status'] == 'risk')
    mod._RUNNER = FakeRunner(firewall_cmd=('running', True))
    check('running firewalld is active', mod.check_firewall()['status'] == 'ok')

    # the real runner: exit status and timeout
    mod._RUNNER, saved_root = None, mod.SYSROOT
    mod.SYSROOT = ''
    try:
        _o, ok = mod._run([sys.executable, '-c', 'import sys; sys.exit(3)'])
        check('real exit code 3 -> ok False', ok is False)
        o, ok = mod._run([sys.executable, '-c', 'print("hi")'])
        check('real exit code 0 -> ok True', ok is True and 'hi' in o)
        o, ok = mod._run([sys.executable, '-c', 'import time; time.sleep(5)'], timeout=1)
        check('hanging command times out', ok is False and 'timed out' in o, o)
        o, ok = mod._run(['/nonexistent/secrisk-binary'])
        check('missing binary -> ok False', ok is False)
    finally:
        mod.SYSROOT = saved_root

    shutil.rmtree(root, ignore_errors=True)
    shutil.rmtree(data, ignore_errors=True)


def restore_safety():
    print('\n14. restore safety and access guards')
    root = tempfile.mkdtemp(prefix='secrisk-rst-')
    data = tempfile.mkdtemp(prefix='secrisk-rstdata-')
    build_fixture(root)
    mod = load_module(root, data)
    mod.PERM_RULES = []
    app = mod.securityrisk_main()

    original = read(root, 'etc/profile')
    bid = app.fix({'id': 'cli_timeout'})['backup']
    write(root, 'etc/profile', read(root, 'etc/profile') + 'alias ll="ls -l"\n')
    out = app.restore({'backup': bid})
    check('restore refuses to undo a later edit', out.get('status') is False
          and out.get('drift') == ['/etc/profile'], json.dumps(out)[:200])
    check('later edit still there', 'alias ll' in read(root, 'etc/profile'))
    out = app.restore({'backup': bid, 'force': '1'})
    check('force=1 restores anyway', out.get('status') is True
          and read(root, 'etc/profile') == original, json.dumps(out)[:200])

    mod._RUNNER = FakeRunner(visudo=('', True))
    sbid = app.fix({'id': 'sudo_nopasswd'})['backup']
    after_fix = read(root, 'etc/sudoers')
    mod._RUNNER = FakeRunner(visudo=('syntax error', False))
    out = app.restore({'backup': sbid})
    check('restore validates sudoers first', out.get('status') is False
          and 'Nothing was restored' in out.get('msg', ''), out.get('msg'))
    check('sudoers untouched by rejected restore', read(root, 'etc/sudoers') == after_fix)
    mod._RUNNER = FakeRunner(visudo=('', True))
    out = app.restore({'backup': sbid})
    check('validated sudoers restore works', out.get('status') is True
          and 'NOPASSWD' in read(root, 'etc/sudoers'), json.dumps(out)[:200])
    mod._RUNNER = None

    # backups made by v1.1 held a full copy of /etc/shadow
    legacy = os.path.join(data, 'backup', '20200101-000000-empty_password')
    write(legacy, 'etc/shadow', 'root:$6$old$hash:::::::\n', 0o600)
    write(legacy, 'manifest.json', json.dumps({
        'id': '20200101-000000-empty_password', 'risk': 'empty_password',
        'files': [{'path': '/etc/shadow', 'file': os.path.join('etc', 'shadow'), 'mode': 384}],
        'modes': []}))
    app.get_index({})
    check('legacy shadow copy deleted', not os.path.exists(os.path.join(legacy, 'etc', 'shadow')))
    check('legacy manifest cleaned',
          json.load(io.open(os.path.join(legacy, 'manifest.json'))).get('files') == [])

    evil = os.path.join(data, 'backup', '20200101-000001-cli_timeout')
    write(evil, 'manifest.json', json.dumps({
        'id': '20200101-000001-cli_timeout', 'risk': 'cli_timeout',
        'files': [{'path': '/root/.ssh/authorized_keys', 'file': '../../../x'},
                  {'path': '/etc/../root/x', 'file': 'x'}], 'modes': []}))
    out = app.restore({'backup': '20200101-000001-cli_timeout', 'force': '1'})
    check('tampered manifest writes nothing', out.get('status') is False, json.dumps(out))

    os.environ['SECRISK_ALLOW_ANON'] = '1'
    try:
        check('debug anon switch works in a test sysroot', app._check({}) is True)
        saved_root, mod.SYSROOT = mod.SYSROOT, ''
        check('debug anon switch ignored on a real host', app._check({}) is False)
        mod.SYSROOT = saved_root
    finally:
        os.environ.pop('SECRISK_ALLOW_ANON', None)

    shutil.rmtree(root, ignore_errors=True)
    shutil.rmtree(data, ignore_errors=True)


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
    plan = '\n'.join(items['sudo_nopasswd']['plan'])
    check('plan says the ubuntu rule is skipped',
          'skip' in plan and 'no usable password for ubuntu' in plan, plan)
    original_dropin = read(root, 'etc/sudoers.d/90-cloud-init-users')
    out = app.fix({'id': 'sudo_nopasswd'})
    check('fix returned success', out.get('status') is True, json.dumps(out)[:300])
    sudoers = read(root, 'etc/sudoers')
    dropin = read(root, 'etc/sudoers.d/90-cloud-init-users')
    check('no NOPASSWD left in /etc/sudoers', 'NOPASSWD' not in sudoers, sudoers)
    check('group rule kept, only the tag removed', '%sudo\tALL=(ALL:ALL) ALL\n' in sudoers)
    check('continuation rule kept active',
          'bob\tALL=(ALL) ALL, \\\n\tPASSWD: /bin/ls\n' in sudoers, repr(sudoers))
    check('nothing commented out', sudoers.count('#') == original_sudoers.count('#'))
    check('rule of a user without password left alone', dropin == original_dropin)
    check('skip reported in changes',
          any(c.startswith('Skipped /etc/sudoers.d/90-cloud-init-users') for c in out['changes']),
          str(out['changes']))
    check('item stays risk but is no longer auto-fixable',
          out['item']['status'] == 'risk' and out['item']['fixable'] is False)
    check('other sudoers rules untouched', 'root\tALL=(ALL:ALL) ALL' in sudoers)
    check('backup keeps original sudoers',
          io.open(os.path.join(data, 'backup', out.get('backup', ''), 'etc', 'sudoers'),
                  encoding='utf-8').read() == original_sudoers)
    again = app.fix({'id': 'sudo_nopasswd'})
    check('second run refuses instead of locking ubuntu out',
          again.get('status') is False and 'lock its users out' in again.get('msg', ''),
          again.get('msg'))
    check('no temp file left behind', not leftovers(root), str(leftovers(root)))

    print('\n4. fix empty_password')
    out = app.fix({'id': 'empty_password'})
    check('fix returned success', out.get('status') is True, json.dumps(out)[:200])
    bdir = os.path.join(data, 'backup', out.get('backup', ''))
    check('no copy of /etc/shadow in the backup',
          not os.path.exists(os.path.join(bdir, 'etc', 'shadow')))
    check('locked accounts recorded by name',
          json.load(io.open(os.path.join(bdir, 'manifest.json'))).get('accounts') == ['testuser'])
    out_r = app.restore({'backup': out.get('backup')})
    check('restore never unlocks an empty password account',
          out_r.get('status') is False and 'not unlocked' in out_r.get('msg', ''),
          out_r.get('msg'))
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
    check('lockout-risk fix needs confirm=1 in the API',
          out.get('status') is False and out.get('need_confirm') is True)
    check('sshd_config untouched without confirm',
          'PasswordAuthentication yes' in read(root, 'etc/ssh/sshd_config'))
    out = app.fix({'id': 'ssh_password_auth', 'confirm': '1'})
    check('PasswordAuthentication rewritten',
          'PasswordAuthentication no' in read(root, 'etc/ssh/sshd_config'))
    check('ssh_password_auth now ok', out['item']['status'] == 'ok')
    check('sshd_config mode preserved', mod._mode('/etc/ssh/sshd_config') in (None, 0o600, 0o666, 0o444))

    print('\n5b. drop-in overrides the main config')
    write(root, 'etc/ssh/sshd_config.d/50-cloud-init.conf', 'PasswordAuthentication yes\n', 0o600)
    items = {i['id']: i for i in app.get_index({})['items']}
    check('drop-in value wins over sshd_config', items['ssh_password_auth']['status'] == 'risk',
          items['ssh_password_auth']['detail'])
    out = app.fix({'id': 'ssh_password_auth', 'confirm': '1'})
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
    check('debian 0640 root:shadow is accepted',
          mod._perm_issues([('/etc/shadow', 0o640, 0, 42),
                            ('/etc/gshadow', 0o640, 0, 42)]) == [])
    grp = mod._perm_issues([('/etc/shadow', 0o640, 0, 0)])
    check('0640 with group root is flagged, only the extra bit removed',
          len(grp) == 1 and grp[0]['target'] == oct(0o600), str(grp))
    own = mod._perm_issues([('/etc/passwd', 0o644, 1000, 0)])
    check('non-root owner is flagged', len(own) == 1 and own[0]['bad_owner']
          and not own[0]['bad_mode'], str(own))
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
    check('sudo_nopasswd keeps only the protected rule',
          items['sudo_nopasswd']['status'] == 'risk'
          and [r['file'] for r in items['sudo_nopasswd']['rules']]
          == ['/etc/sudoers.d/90-cloud-init-users'])
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

    validators_and_exit_codes()
    restore_safety()

    print('\n%d passed, %d failed' % (len(PASSED), len(FAILED)))
    shutil.rmtree(root, ignore_errors=True)
    shutil.rmtree(data, ignore_errors=True)
    return 0 if not FAILED else 1


if __name__ == '__main__':
    sys.exit(main())
