#!/usr/bin/python
# coding: utf-8
"""
Security Risk - aaPanel third-party plugin.

Audits a Linux server for common hardening gaps (idle shell timeout, passwordless
sudo, SSH exposure, file permissions, empty passwords, firewall, fail2ban, panel
SSL) and can fix the auto-fixable ones in place.

Safety model for every fix:
    1. every touched file is copied to data/backup/<id>/ first
    2. the change is validated (visudo -c / sshd -t) when a validator exists
    3. an invalid change is rolled back from the backup immediately
    4. the check is re-run so the UI shows the real state, not an assumption

The class name must match the file name (aaPanel plugin contract).
"""

import io
import os
import re
import sys
import json
import stat
import time
import glob
import shutil
import subprocess

try:
    import public  # provided by the panel at runtime
except Exception:  # allows the rule engine to be tested outside the panel
    public = None


# ---------------------------------------------------------------------------
# paths
# ---------------------------------------------------------------------------

PLUGIN_PATH = os.path.dirname(os.path.abspath(__file__))

# SECRISK_SYSROOT lets the test-suite point every /etc lookup at a fake root.
SYSROOT = (os.environ.get('SECRISK_SYSROOT') or '').rstrip('/')
DATA_PATH = os.environ.get('SECRISK_DATA') or os.path.join(PLUGIN_PATH, 'data')
BACKUP_PATH = os.path.join(DATA_PATH, 'backup')
LOG_FILE = os.path.join(DATA_PATH, 'fix.log')

TMOUT_TARGET = 300
TMOUT_MAX = 600
BACKUP_KEEP = 40

RE_TMOUT = re.compile(r'^\s*(?:export\s+|readonly\s+)*TMOUT\s*=\s*["\']?(\d+)')
RE_TMOUT_VALUE = re.compile(r'^(\s*(?:export\s+|readonly\s+)*TMOUT\s*=\s*["\']?)(\d+)')
RE_NOPASSWD = re.compile(r'NOPASSWD\s*:', re.I)
RE_SSH_KEY = re.compile(r'^\s*([A-Za-z][A-Za-z0-9]*)\s+(.+?)\s*$')
RE_BACKUP_ID = re.compile(r'^[0-9]{8}-[0-9]{6}-[a-z0-9_]+$')


class FixError(Exception):
    """Raised by a fixer when the change cannot be applied safely."""


# ---------------------------------------------------------------------------
# low level helpers
# ---------------------------------------------------------------------------

def _path(p):
    return SYSROOT + p if SYSROOT else p


def _strip(p):
    if SYSROOT and p.startswith(SYSROOT):
        p = p[len(SYSROOT):]
    return p.replace(os.sep, '/')


def _read(path, default=None):
    try:
        with io.open(_path(path), 'r', encoding='utf-8', errors='replace') as f:
            return f.read()
    except (IOError, OSError):
        return default


def _exists(path):
    return os.path.exists(_path(path))


def _mode(path):
    try:
        return stat.S_IMODE(os.stat(_path(path)).st_mode)
    except OSError:
        return None


def _write(path, content, mode=None):
    """Rewrite a file in place, keeping inode (SELinux context) and file mode."""
    real = _path(path)
    if mode is None:
        mode = _mode(path)
    try:
        with io.open(real, 'w', encoding='utf-8', newline='\n') as f:
            f.write(content)
    except (IOError, OSError) as exc:
        # a 0440 sudoers is not writable by the owner bit; root can still write,
        # but be explicit so the plugin also works under a restricted user
        if getattr(exc, 'errno', None) not in (13, 1):
            raise
        os.chmod(real, 0o600)
        with io.open(real, 'w', encoding='utf-8', newline='\n') as f:
            f.write(content)
    if mode is not None:
        try:
            os.chmod(real, mode)
        except OSError:
            pass


def _shell(cmd, timeout=20):
    """Run a shell command, return (output, ok). Disabled inside a test sysroot."""
    if SYSROOT:
        return '', False
    if public is not None:
        try:
            res = public.ExecShell(cmd)
            if isinstance(res, (list, tuple)):
                return '%s%s' % (res[0] or '', res[1] or ''), True
            return res or '', True
        except Exception:
            pass
    try:
        proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT)
        out = proc.communicate()[0]
        if not isinstance(out, str):
            out = out.decode('utf-8', 'replace')
        return out, proc.returncode == 0
    except Exception as exc:  # pragma: no cover - environment dependent
        return str(exc), False


def _glob(pattern):
    return [_strip(p) for p in sorted(glob.glob(_path(pattern)))]


# ---------------------------------------------------------------------------
# operating system profile
#
# Every check that has a distro-specific answer (package manager, firewall
# backend, sshd unit name, admin group, mandatory access control) asks this
# profile instead of hard coding one distribution's defaults.
# ---------------------------------------------------------------------------

FAMILIES = {
    'debian': {
        'label': 'Debian / Ubuntu',
        'pkg': 'apt-get',
        'firewall': 'ufw',
        'ssh_service': 'ssh',
        'sudo_group': 'sudo',
        'mac': 'AppArmor',
    },
    'rhel': {
        'label': 'RHEL / Rocky / Alma',
        'pkg': 'dnf',
        'firewall': 'firewalld',
        'ssh_service': 'sshd',
        'sudo_group': 'wheel',
        'mac': 'SELinux',
    },
    'suse': {
        'label': 'SUSE / openSUSE',
        'pkg': 'zypper',
        'firewall': 'firewalld',
        'ssh_service': 'sshd',
        'sudo_group': 'wheel',
        'mac': 'AppArmor',
    },
    'alpine': {
        'label': 'Alpine',
        'pkg': 'apk',
        'firewall': 'awall',
        'ssh_service': 'sshd',
        'sudo_group': 'wheel',
        'mac': 'None',
    },
    'arch': {
        'label': 'Arch',
        'pkg': 'pacman',
        'firewall': 'nftables',
        'ssh_service': 'sshd',
        'sudo_group': 'wheel',
        'mac': 'AppArmor',
    },
    'unknown': {
        'label': 'Generic Linux',
        'pkg': '',
        'firewall': '',
        'ssh_service': 'sshd',
        'sudo_group': 'wheel',
        'mac': '',
    },
}

ID_FAMILY = {
    'debian': 'debian', 'ubuntu': 'debian', 'linuxmint': 'debian', 'kali': 'debian',
    'raspbian': 'debian', 'devuan': 'debian', 'pop': 'debian', 'elementary': 'debian',
    'zorin': 'debian', 'neon': 'debian', 'mx': 'debian', 'deepin': 'debian',
    'rhel': 'rhel', 'centos': 'rhel', 'rocky': 'rhel', 'almalinux': 'rhel',
    'alma': 'rhel', 'fedora': 'rhel', 'ol': 'rhel', 'oracle': 'rhel',
    'amzn': 'rhel', 'cloudlinux': 'rhel', 'scientific': 'rhel', 'virtuozzo': 'rhel',
    'opensuse': 'suse', 'opensuse-leap': 'suse', 'opensuse-tumbleweed': 'suse',
    'sles': 'suse', 'suse': 'suse',
    'alpine': 'alpine', 'arch': 'arch', 'manjaro': 'arch', 'endeavouros': 'arch',
}

_OS_CACHE = {'root': None, 'profile': None}


def _read_os_release():
    for path in ('/etc/os-release', '/usr/lib/os-release'):
        body = _read(path)
        if not body:
            continue
        data = {}
        for line in body.splitlines():
            line = line.strip()
            if not line or line.startswith('#') or '=' not in line:
                continue
            key, val = line.split('=', 1)
            data[key.strip()] = val.strip().strip('"').strip("'")
        if data.get('ID') or data.get('NAME'):
            return data
    return {}


def _family_from_ids(os_id, id_like):
    for token in [os_id] + (id_like or '').split():
        token = (token or '').strip().lower()
        if token in ID_FAMILY:
            return ID_FAMILY[token]
    return ''


def _has_bin(name):
    if SYSROOT:
        return False
    out, ok = _shell('command -v %s >/dev/null 2>&1 && echo yes' % name)
    return ok and 'yes' in out


def detect_os():
    """Return a cached profile describing the distribution this plugin runs on."""
    if _OS_CACHE['root'] == SYSROOT and _OS_CACHE['profile']:
        return _OS_CACHE['profile']

    data = _read_os_release()
    os_id = (data.get('ID') or '').lower()
    id_like = (data.get('ID_LIKE') or '').lower()
    name = data.get('NAME') or ''
    version = data.get('VERSION_ID') or ''
    pretty = data.get('PRETTY_NAME') or ('%s %s' % (name, version)).strip()

    if not os_id:
        # fall back to the release files older distributions still ship
        for path, guess in (('/etc/redhat-release', 'rhel'),
                            ('/etc/rocky-release', 'rocky'),
                            ('/etc/almalinux-release', 'almalinux'),
                            ('/etc/centos-release', 'centos'),
                            ('/etc/debian_version', 'debian'),
                            ('/etc/SuSE-release', 'suse')):
            body = _read(path)
            if body:
                os_id = guess
                name = name or body.strip().splitlines()[0]
                pretty = pretty or body.strip().splitlines()[0]
                break

    family = _family_from_ids(os_id, id_like) or 'unknown'
    base = FAMILIES.get(family, FAMILIES['unknown'])
    profile = {
        'id': os_id or 'linux',
        'name': name or base['label'],
        'version': version,
        'pretty': pretty or base['label'],
        'family': family,
        'label': base['label'],
        'pkg': base['pkg'],
        'firewall': base['firewall'],
        'ssh_service': base['ssh_service'],
        'sudo_group': base['sudo_group'],
        'mac': base['mac'],
        'panel_port': _panel_port(),
    }

    # refine with what is actually installed when we are on a real machine
    if not SYSROOT:
        if family == 'rhel' and profile['pkg'] == 'dnf' and not _has_bin('dnf'):
            profile['pkg'] = 'yum'
        if family == 'debian' and not _has_bin('apt-get'):
            profile['pkg'] = 'apt'

    _OS_CACHE['root'] = SYSROOT
    _OS_CACHE['profile'] = profile
    return profile


def _panel_port():
    body = _read('/www/server/panel/data/port.pl')
    m = re.search(r'\d{2,5}', body or '')
    return m.group(0) if m else '8888'


def _pkg_install(profile, *packages):
    """Build the install command for the detected package manager."""
    pkgs = ' '.join(packages)
    pkg = profile['pkg']
    if pkg == 'apt-get':
        return 'apt-get update && apt-get install -y %s' % pkgs
    if pkg == 'dnf':
        return 'dnf install -y %s' % pkgs
    if pkg == 'yum':
        return 'yum install -y %s' % pkgs
    if pkg == 'zypper':
        return 'zypper install -y %s' % pkgs
    if pkg == 'apk':
        return 'apk add %s' % pkgs
    if pkg == 'pacman':
        return 'pacman -S --noconfirm %s' % pkgs
    return 'install %s with the package manager of this distribution' % pkgs


def _logical_lines(body):
    """Yield (first_index, last_index, joined_text) joining backslash continuations."""
    lines = body.splitlines()
    i = 0
    while i < len(lines):
        start = i
        parts = [lines[i]]
        while parts[-1].rstrip().endswith('\\') and i + 1 < len(lines):
            i += 1
            parts.append(lines[i])
        yield start, i, ' '.join(x.rstrip().rstrip('\\').strip() for x in parts)
        i += 1


def _ensure_dirs():
    for d in (DATA_PATH, BACKUP_PATH):
        if not os.path.isdir(d):
            os.makedirs(d)
    try:
        os.chmod(DATA_PATH, 0o700)
    except OSError:
        pass


def _backup(paths, risk_id, modes=None):
    """Copy files into a timestamped backup dir, return (backup_id, saved list)."""
    _ensure_dirs()
    stamp = time.strftime('%Y%m%d-%H%M%S')
    bid = '%s-%s' % (stamp, risk_id)
    root = os.path.join(BACKUP_PATH, bid)
    saved = []
    for p in paths:
        real = _path(p)
        if not os.path.isfile(real):
            continue
        rel = p.lstrip('/').replace('/', os.sep)
        dst = os.path.join(root, rel)
        parent = os.path.dirname(dst)
        if parent and not os.path.isdir(parent):
            os.makedirs(parent)
        shutil.copy2(real, dst)
        saved.append({'path': p, 'file': rel, 'mode': _mode(p)})
    if not os.path.isdir(root):
        os.makedirs(root)
    with io.open(os.path.join(root, 'manifest.json'), 'w', encoding='utf-8') as f:
        f.write(json.dumps({'id': bid, 'risk': risk_id, 'time': int(time.time()),
                            'files': saved, 'modes': modes or []},
                           ensure_ascii=False, indent=2))
    _prune_backups()
    return bid, saved


def _prune_backups():
    try:
        dirs = sorted([d for d in os.listdir(BACKUP_PATH)
                       if os.path.isdir(os.path.join(BACKUP_PATH, d))])
        for old in dirs[:-BACKUP_KEEP]:
            shutil.rmtree(os.path.join(BACKUP_PATH, old), ignore_errors=True)
    except OSError:
        pass


def _log(entry):
    _ensure_dirs()
    entry = dict(entry)
    entry.setdefault('time', int(time.time()))
    with io.open(LOG_FILE, 'a', encoding='utf-8') as f:
        f.write(json.dumps(entry, ensure_ascii=False) + '\n')


def _read_log(limit=40):
    if not os.path.isfile(LOG_FILE):
        return []
    out = []
    with io.open(LOG_FILE, 'r', encoding='utf-8', errors='replace') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except ValueError:
                continue
    return out[-limit:][::-1]


def _item(rid, title, level, status, detail, solution,
          fixable=False, danger=False, plan=None, commands=None, extra=None):
    data = {
        'id': rid,
        'title': title,
        'level': level,
        'status': status,
        'detail': detail,
        'solution': solution,
        'fixable': bool(fixable),
        'danger': bool(danger),
        'plan': plan or [],
        'commands': commands or [],
    }
    if extra:
        data.update(extra)
    return data


# ---------------------------------------------------------------------------
# check 1 - idle shell timeout (TMOUT)
# ---------------------------------------------------------------------------

def _tmout_files():
    files = ['/etc/profile']
    for p in _glob('/etc/profile.d/*.sh'):
        files.append(p)
    files.append('/etc/bash.bashrc')
    return files


def _tmout_hits():
    hits = []
    for path in _tmout_files():
        body = _read(path)
        if body is None:
            continue
        for idx, line in enumerate(body.splitlines(), 1):
            if line.lstrip().startswith('#'):
                continue
            m = RE_TMOUT.match(line)
            if m:
                hits.append({'file': path, 'line': idx, 'value': int(m.group(1))})
    return hits


def check_cli_timeout():
    hits = _tmout_hits()
    if not hits:
        return _item(
            'cli_timeout',
            'No command line timeout is configured for exit',
            'medium', 'risk',
            'TMOUT is not defined in /etc/profile, /etc/profile.d/*.sh or '
            '/etc/bash.bashrc, so an idle root shell never expires.',
            'Add TMOUT=300 (readonly, exported) to /etc/profile, then re-login '
            'or run "source /etc/profile". Keep the value at 600 seconds or less.',
            fixable=True,
            plan=['Append "TMOUT=300" + "readonly TMOUT" + "export TMOUT" to /etc/profile',
                  'Back up /etc/profile before writing',
                  'Re-run this check to confirm the value is picked up'],
        )

    effective = hits[-1]['value']
    where = ', '.join('%s:%d' % (h['file'], h['line']) for h in hits)
    if effective > TMOUT_MAX:
        return _item(
            'cli_timeout',
            'Command line timeout is longer than 600 seconds',
            'low', 'risk',
            'TMOUT=%d is set at %s; anything above %d seconds leaves an idle '
            'root shell open for too long.' % (effective, where, TMOUT_MAX),
            'Lower the value to 300 seconds in the file that defines it.',
            fixable=True,
            plan=['Rewrite the existing TMOUT assignment(s) to TMOUT=300',
                  'Back up the file(s) first', 'Re-run this check'],
            extra={'value': effective, 'sources': where},
        )

    return _item(
        'cli_timeout',
        'Command line timeout is configured',
        'low', 'ok',
        'TMOUT=%d (at %s).' % (effective, where),
        'No action needed.',
        extra={'value': effective, 'sources': where},
    )


def _fix_cli_timeout():
    hits = _tmout_hits()
    if hits:
        files = sorted(set(h['file'] for h in hits))
        bid, _ = _backup(files, 'cli_timeout')
        changes = []
        for path in files:
            body = _read(path, '')
            lines = body.splitlines(True)
            touched = 0
            for idx, raw in enumerate(lines):
                m = RE_TMOUT_VALUE.match(raw)
                if m:
                    lines[idx] = RE_TMOUT_VALUE.sub(r'\g<1>%d' % TMOUT_TARGET, raw)
                    touched += 1
            if touched:
                _write(path, ''.join(lines))
                changes.append('Set TMOUT=%d in %s (%d line)' % (TMOUT_TARGET, path, touched))
        return {'changes': changes, 'backup': bid, 'reload': ''}

    path = '/etc/profile'
    body = _read(path, '')
    bid, _ = _backup([path], 'cli_timeout')
    if body and not body.endswith('\n'):
        body += '\n'
    block = (
        '\n# --- idle shell timeout (added by aaPanel Security Risk) ---\n'
        'TMOUT=%d\n'
        'readonly TMOUT\n'
        'export TMOUT\n' % TMOUT_TARGET
    )
    _write(path, body + block)
    return {
        'changes': ['Appended TMOUT=%d block to %s' % (TMOUT_TARGET, path)],
        'backup': bid,
        'reload': '',
    }


# ---------------------------------------------------------------------------
# check 2 - passwordless sudo
# ---------------------------------------------------------------------------

def _sudoers_files():
    files = ['/etc/sudoers']
    for p in _glob('/etc/sudoers.d/*'):
        base = os.path.basename(p)
        if os.path.isdir(_path(p)) or base.endswith('~') or base.startswith('.'):
            continue
        files.append(p)
    return files


def _nopasswd_hits():
    hits = []
    for path in _sudoers_files():
        body = _read(path)
        if body is None:
            continue
        for start, end, text in _logical_lines(body):
            if text.lstrip().startswith('#'):
                continue
            if RE_NOPASSWD.search(text):
                hits.append({'file': path, 'line': start + 1,
                             'lines': end - start + 1, 'text': text.strip()})
    return hits


def check_sudo_nopasswd():
    hits = _nopasswd_hits()
    if not hits:
        return _item(
            'sudo_nopasswd',
            'No sudo rule allows an empty password',
            'medium', 'ok',
            'No active NOPASSWD entry was found in /etc/sudoers or /etc/sudoers.d.',
            'No action needed.',
        )

    files = sorted(set(h['file'] for h in hits))
    detail = 'Passwordless sudo is allowed by %d rule(s): %s' % (
        len(hits), ', '.join(files))
    group = detect_os()['sudo_group']
    return _item(
        'sudo_nopasswd',
        'The following sudo files contain the NOPASSWD flag: %s' % ', '.join(files),
        'medium', 'risk',
        detail,
        'Comment out or remove the NOPASSWD marker in the listed files. Sudo '
        'will then ask for the user password again. Validate with "visudo -c". '
        'On this distribution the admin group is "%' + group + '", so keep the '
        'group rule and drop only the NOPASSWD part.',
        fixable=True,
        plan=['Back up %s' % ', '.join(files),
              'Comment out every line that contains NOPASSWD:',
              'Validate the result with "visudo -c" and roll back if it fails']
             + ['  %s:%d  %s' % (h['file'], h['line'], h['text'][:110]) for h in hits[:6]],
        extra={'files': files,
               'rules': [{'file': h['file'], 'line': h['line'],
                          'text': h['text'][:200]} for h in hits]},
    )


def _comment_nopasswd(body):
    """Comment every physical line of a logical line containing NOPASSWD."""
    target = set()
    for start, end, text in _logical_lines(body):
        if text.lstrip().startswith('#'):
            continue
        if RE_NOPASSWD.search(text):
            for k in range(start, end + 1):
                target.add(k)
    if not target:
        return body, 0
    lines = body.splitlines(True)
    out = []
    for idx, raw in enumerate(lines):
        if idx in target:
            stripped = raw.rstrip('\r\n')
            indent = re.match(r'^[ \t]*', stripped).group(0)
            rest = stripped[len(indent):]
            if not rest.startswith('#'):
                stripped = indent + '# ' + rest
            out.append(stripped + '\n')
        else:
            out.append(raw)
    return ''.join(out), len(target)


def _fix_sudo_nopasswd():
    hits = _nopasswd_hits()
    if not hits:
        raise FixError('No NOPASSWD rule is left to fix.')
    files = sorted(set(h['file'] for h in hits))
    bid, _ = _backup(files, 'sudo_nopasswd')

    changes = []
    originals = {}
    for path in files:
        body = _read(path, '')
        originals[path] = body
        new_body, count = _comment_nopasswd(body)
        if not count:
            continue
        _write(path, new_body)
        changes.append('Commented out %d line(s) in %s' % (count, path))

    # sudo refuses to work with a broken config: validate and roll back.
    if not SYSROOT:
        broken = []
        for path in files:
            if path not in originals or originals[path] == _read(path):
                continue
            out, ok = _shell('visudo -cf %s' % path)
            parsed = 'parsed ok' in out.lower()
            if not ok or not parsed:
                broken.append((path, (out.strip() or 'visudo rejected the file')[:300]))
        if broken:
            for path in originals:
                _write(path, originals[path])
            raise FixError('Rolled back, sudoers validation failed: %s'
                           % '; '.join('%s: %s' % (p, m) for p, m in broken))

    return {'changes': changes, 'backup': bid, 'reload': ''}


# ---------------------------------------------------------------------------
# check 3/4 - SSH hardening
# ---------------------------------------------------------------------------

def _ssh_files():
    files = []
    for p in _glob('/etc/ssh/sshd_config.d/*.conf'):
        files.append(p)
    files.append('/etc/ssh/sshd_config')
    return [p for p in files if _exists(p)]


def _ssh_effective(key):
    """Return (value, source) using sshd -T when possible, else config parsing."""
    if not SYSROOT:
        out, ok = _shell('sshd -T 2>/dev/null | grep -i "^%s " ' % key.lower())
        if ok and out.strip():
            return out.strip().split(None, 1)[1].strip().lower(), 'sshd -T'
    for path in _ssh_files():
        body = _read(path, '')
        for line in body.splitlines():
            if line.lstrip().startswith('#'):
                continue
            m = RE_SSH_KEY.match(line)
            if m and m.group(1).lower() == key.lower():
                return m.group(2).strip().lower(), path
    return None, None


def check_ssh_root_login():
    value, source = _ssh_effective('PermitRootLogin')
    if value is None:
        return _item(
            'ssh_root_login',
            'SSH root login setting could not be read',
            'low', 'unknown',
            'sshd_config was not found or the panel could not query sshd.',
            'Check /etc/ssh/sshd_config manually.',
        )
    if value in ('yes', 'true'):
        return _item(
            'ssh_root_login',
            'SSH allows direct root login',
            'medium', 'risk',
            'PermitRootLogin %s (from %s).' % (value, source),
            'Set "PermitRootLogin prohibit-password" so root can only log in '
            'with a key, then run "sshd -t" and reload sshd.',
            fixable=True,
            plan=['Back up %s' % source,
                  'Set PermitRootLogin prohibit-password',
                  'Validate with "sshd -t", reload sshd, roll back on failure'],
            extra={'value': value, 'source': source},
        )
    return _item(
        'ssh_root_login',
        'SSH root login is restricted',
        'low', 'ok',
        'PermitRootLogin %s (from %s).' % (value, source),
        'No action needed.',
        extra={'value': value, 'source': source},
    )


def check_ssh_password_auth():
    value, source = _ssh_effective('PasswordAuthentication')
    if value is None:
        return _item(
            'ssh_password_auth',
            'SSH password authentication setting could not be read',
            'low', 'unknown',
            'PasswordAuthentication is not declared in sshd_config.',
            'Check /etc/ssh/sshd_config manually.',
        )
    if value == 'yes':
        return _item(
            'ssh_password_auth',
            'SSH accepts password authentication',
            'medium', 'risk',
            'PasswordAuthentication yes (from %s). Brute-force attacks against '
            'passwords are the most common way servers get compromised.' % source,
            'Disable password login once every admin uses a key: '
            '"PasswordAuthentication no", then reload sshd.',
            fixable=True,
            danger=True,
            plan=['Back up %s' % source,
                  'Set PasswordAuthentication no',
                  'Validate with "sshd -t", reload sshd, roll back on failure',
                  'Make sure you have a working SSH key before confirming'],
            extra={'value': value, 'source': source},
        )
    return _item(
        'ssh_password_auth',
        'SSH password authentication is disabled',
        'low', 'ok',
        'PasswordAuthentication %s (from %s).' % (value, source),
        'No action needed.',
        extra={'value': value, 'source': source},
    )


def _ssh_declared_file(key):
    """First file that actively declares `key` (drop-ins are read before the main file)."""
    for path in _ssh_files():
        body = _read(path, '')
        for line in body.splitlines():
            if line.lstrip().startswith('#'):
                continue
            m = RE_SSH_KEY.match(line)
            if m and m.group(1).lower() == key.lower():
                return path
    return None


def _set_ssh_key(key, value):
    files = _ssh_files()
    if not files:
        raise FixError('sshd_config not found.')
    # edit the file that actually carries the directive, otherwise sshd keeps
    # using the value from an earlier Include
    path = _ssh_declared_file(key) or '/etc/ssh/sshd_config'
    body = _read(path, '')
    bid, _ = _backup([path], 'ssh_%s' % key.lower())

    lines = body.splitlines(True)
    hit = False
    for idx, raw in enumerate(lines):
        if raw.lstrip().startswith('#'):
            continue
        m = RE_SSH_KEY.match(raw)
        if m and m.group(1).lower() == key.lower():
            lines[idx] = '%s %s\n' % (key, value)
            hit = True
            break
    if not hit:
        if lines and not lines[-1].endswith('\n'):
            lines[-1] += '\n'
        lines.append('%s %s\n' % (key, value))
    _write(path, ''.join(lines))

    changes = ['Set %s %s in %s' % (key, value, path)]
    if not SYSROOT:
        out, ok = _shell('sshd -t')
        if not ok:
            _write(path, body)
            raise FixError('Rolled back, "sshd -t" rejected the change: %s'
                           % (out.strip()[:300] or 'unknown error'))

        # Debian/Ubuntu call the unit "ssh", RHEL family calls it "sshd"
        svc = detect_os()['ssh_service']
        other = 'ssh' if svc == 'sshd' else 'sshd'
        reload_out, reload_ok = _shell(
            'systemctl reload %(a)s 2>/dev/null || systemctl reload %(b)s 2>/dev/null '
            '|| service %(a)s reload 2>/dev/null || service %(b)s reload 2>/dev/null'
            % {'a': svc, 'b': other})
        if reload_ok:
            changes.append('Reloaded %s' % svc)
        else:
            changes.append('Config saved but reload failed - run '
                           '"systemctl reload %s" manually' % svc)

    # confirm the new value is really the effective one, otherwise another file wins
    now, now_src = _ssh_effective(key)
    if now is not None and now != value:
        _write(path, body)
        raise FixError('Rolled back: %s still resolves to "%s" (from %s), the value '
                       'is overridden by another config file.'
                       % (key, now, now_src))
    return {'changes': changes, 'backup': bid, 'reload': ''}


def _fix_ssh_root_login():
    return _set_ssh_key('PermitRootLogin', 'prohibit-password')


def _fix_ssh_password_auth():
    return _set_ssh_key('PasswordAuthentication', 'no')


# ---------------------------------------------------------------------------
# check 5 - sensitive file permissions
# ---------------------------------------------------------------------------

PERM_RULES = [
    ('/etc/passwd', 0o644),
    ('/etc/shadow', 0o600),
    ('/etc/group', 0o644),
    ('/etc/gshadow', 0o600),
    ('/etc/sudoers', 0o440),
    ('/etc/ssh/sshd_config', 0o600),
]


def _perm_issues(entries=None):
    """Return files whose mode has bits outside the allowed mask.

    `entries` is a list of (path, mode) pairs; when omitted the live files are read.
    Kept separable so the rule can be unit-tested without touching the filesystem.
    """
    wants = dict(PERM_RULES)
    if entries is None:
        entries = []
        for path, _want in PERM_RULES:
            if _exists(path):
                cur = _mode(path)
                if cur is not None:
                    entries.append((path, cur))
    issues = []
    for path, cur in entries:
        want = wants.get(path)
        if want is None:
            continue
        if cur & ~want:  # any bit outside the allowed mask = too permissive
            issues.append({'path': path, 'current': oct(cur), 'want': oct(want)})
    return issues


def check_file_permissions():
    issues = _perm_issues()
    if not issues:
        return _item(
            'file_permissions',
            'Sensitive system files have safe permissions',
            'low', 'ok',
            'All checked files are at or below their maximum allowed mode.',
            'No action needed.',
        )
    detail = '; '.join('%s is %s (max %s)' % (i['path'], i['current'], i['want'])
                       for i in issues)
    critical = any(i['path'] in ('/etc/shadow', '/etc/sudoers') for i in issues)
    return _item(
        'file_permissions',
        'Sensitive system files are readable by more users than needed',
        'high' if critical else 'medium', 'risk',
        detail,
        'Restore the standard modes: 644 /etc/passwd, 644 /etc/group, '
        '600 /etc/shadow, 600 /etc/gshadow, 440 /etc/sudoers, 600 sshd_config.',
        fixable=True,
        plan=['chmod %s %s' % (i['want'], i['path']) for i in issues],
        extra={'files': issues},
    )


def _fix_file_permissions():
    issues = _perm_issues()
    if not issues:
        raise FixError('Permissions already correct.')
    previous = [{'path': i['path'], 'mode': int(i['current'], 8)} for i in issues]
    bid, _ = _backup([], 'file_permissions', previous)
    changes = []
    for i in issues:
        try:
            os.chmod(_path(i['path']), int(i['want'], 8))
            changes.append('%s: %s -> %s' % (i['path'], i['current'], i['want']))
        except OSError as exc:
            raise FixError('chmod failed on %s: %s' % (i['path'], exc))
    return {'changes': changes, 'backup': bid, 'reload': ''}


# ---------------------------------------------------------------------------
# check 6 - accounts with an empty password
# ---------------------------------------------------------------------------

def _empty_password_users():
    body = _read('/etc/shadow')
    if body is None:
        return None
    users = []
    for line in body.splitlines():
        if not line.strip() or line.startswith('#'):
            continue
        parts = line.split(':')
        if len(parts) < 2:
            continue
        if parts[1] == '':
            users.append(parts[0])
    return users


def check_empty_password():
    users = _empty_password_users()
    if users is None:
        return _item(
            'empty_password',
            'Password hashes could not be read',
            'low', 'unknown',
            '/etc/shadow is not readable by the panel.',
            'Run the panel as root and scan again.',
        )
    if not users:
        return _item(
            'empty_password',
            'No account has an empty password',
            'low', 'ok',
            'Every entry in /etc/shadow has a password hash or a lock marker.',
            'No action needed.',
        )
    return _item(
        'empty_password',
        'Accounts with an empty password: %s' % ', '.join(users),
        'high', 'risk',
        'These accounts can be used to log in without any password.',
        'Lock the accounts ("passwd -l <user>") or set a strong password. '
        'Never leave a login account without a hash.',
        fixable=True,
        plan=['Lock the account(s) with "passwd -l %s"' % '", "'.join(users),
              'Back up /etc/shadow first'],
        extra={'users': users},
    )


def _fix_empty_password():
    users = _empty_password_users() or []
    if not users:
        raise FixError('No empty password account is left.')
    bid, _ = _backup(['/etc/shadow'], 'empty_password')
    changes = []
    for user in users:
        if not SYSROOT:
            out, ok = _shell('passwd -l %s' % user)
            if not ok:
                raise FixError('passwd -l %s failed: %s' % (user, out.strip()[:200]))
        changes.append('Locked account %s' % user)
    if SYSROOT:
        # simulate the lock so the test-suite can verify the flow end to end
        body = _read('/etc/shadow', '')
        out_lines = []
        for line in body.splitlines():
            parts = line.split(':')
            if len(parts) > 1 and parts[1] == '':
                parts[1] = '!'
                line = ':'.join(parts)
            out_lines.append(line)
        _write('/etc/shadow', '\n'.join(out_lines) + '\n')
    return {'changes': changes, 'backup': bid, 'reload': ''}


# ---------------------------------------------------------------------------
# check 7 - firewall (backend depends on the distribution)
# ---------------------------------------------------------------------------

def _firewall_commands(profile):
    port = profile['panel_port']
    fam = profile['family']
    if fam == 'debian':
        return [
            'ufw allow 22/tcp',
            'ufw allow %s/tcp' % port,
            'ufw --force enable',
            'ufw status verbose',
        ]
    if fam in ('rhel', 'suse'):
        return [
            'firewall-cmd --permanent --add-service=ssh',
            'firewall-cmd --permanent --add-port=%s/tcp' % port,
            'firewall-cmd --reload',
            'firewall-cmd --state',
        ]
    if fam == 'alpine':
        return [
            'apk add awall',
            'awall enable',
            'awall activate',
        ]
    return [
        'iptables -A INPUT -p tcp --dport 22 -j ACCEPT',
        'iptables -A INPUT -p tcp --dport %s -j ACCEPT' % port,
        'iptables -P INPUT DROP',
    ]


def check_firewall():
    profile = detect_os()
    evidence = []
    active = False

    body = _read('/etc/ufw/ufw.conf')
    if body and re.search(r'^\s*ENABLED\s*=\s*"?yes', body, re.M | re.I):
        active = True
        evidence.append('ufw enabled in /etc/ufw/ufw.conf')

    if not SYSROOT:
        out, ok = _shell('firewall-cmd --state 2>/dev/null')
        if ok and 'running' in out.lower():
            active = True
            evidence.append('firewalld is running')
        out, ok = _shell('ufw status 2>/dev/null | head -1')
        if ok and 'status: active' in out.lower():
            active = True
            evidence.append('ufw status: active')
        out, ok = _shell('iptables -S 2>/dev/null | grep -c "^-A"')
        if ok and out.strip().isdigit() and int(out.strip()) > 0:
            evidence.append('iptables has %s rule(s)' % out.strip())

    if active:
        return _item(
            'firewall',
            'A host firewall is active',
            'low', 'ok',
            '; '.join(evidence) or 'Firewall detected.',
            'No action needed.',
            extra={'platform': profile['label']},
        )

    backend = profile['firewall'] or 'iptables'
    return _item(
        'firewall',
        'No host firewall is enabled',
        'medium', 'risk',
        'Neither %s nor any other packet filter was found active on %s.'
        % (backend, profile['pretty'] or profile['label']),
        'Enable %s (the firewall %s ships with) and allow only the ports you '
        'actually use: SSH, the panel port %s, and HTTP/HTTPS if you serve sites.'
        % (backend, profile['label'], profile['panel_port']),
        commands=_firewall_commands(profile),
        extra={'platform': profile['label']},
    )


# ---------------------------------------------------------------------------
# check 8 - fail2ban
# ---------------------------------------------------------------------------

def check_fail2ban():
    profile = detect_os()
    installed = _exists('/etc/fail2ban') or _exists('/etc/fail2ban/jail.conf')
    running = False
    if not SYSROOT:
        out, ok = _shell('fail2ban-client status 2>/dev/null')
        running = ok and 'jail list' in out.lower()
    if installed and (running or SYSROOT):
        return _item(
            'fail2ban',
            'Fail2ban is installed',
            'low', 'ok',
            'Fail2ban configuration found at /etc/fail2ban.',
            'No action needed. Make sure the sshd jail is enabled.',
            extra={'platform': profile['label']},
        )

    if profile['family'] == 'rhel':
        cmds = ['dnf install -y epel-release', _pkg_install(profile, 'fail2ban'),
                'systemctl enable --now fail2ban', 'fail2ban-client status sshd']
    else:
        cmds = [_pkg_install(profile, 'fail2ban'),
                'systemctl enable --now fail2ban', 'fail2ban-client status sshd']

    return _item(
        'fail2ban',
        'Fail2ban is not protecting the server',
        'medium', 'risk',
        'No fail2ban jail was detected, so repeated login failures are never '
        'blocked at the IP level.',
        'Install fail2ban and enable the sshd jail. aaPanel also ships an SSH '
        'brute-force protection module you can use instead.',
        commands=cmds,
        extra={'platform': profile['label']},
    )


# ---------------------------------------------------------------------------
# check 9 - panel SSL
# ---------------------------------------------------------------------------

def check_panel_ssl():
    if _exists('/www/server/panel/data/ssl.pl'):
        return _item(
            'panel_ssl',
            'The panel is served over HTTPS',
            'low', 'ok',
            'Panel SSL marker /www/server/panel/data/ssl.pl is present.',
            'No action needed.',
        )
    return _item(
        'panel_ssl',
        'The panel is served over plain HTTP',
        'low', 'risk',
        'Panel traffic (including the login form) is not encrypted.',
        'Open Panel Settings -> Panel SSL and enable it, or put the panel '
        'behind a reverse proxy with a certificate.',
        commands=['Panel Settings -> Security -> Panel SSL -> Enable'],
    )


# ---------------------------------------------------------------------------
# check 9/10 - mandatory access control (only on the families that ship one)
# ---------------------------------------------------------------------------

def check_selinux():
    profile = detect_os()
    if profile['family'] != 'rhel':
        return None

    mode = None
    body = _read('/etc/selinux/config')
    if body:
        m = re.search(r'^\s*SELINUX\s*=\s*(\w+)', body, re.M)
        if m:
            mode = m.group(1).lower()
    enforce = _read('/sys/fs/selinux/enforce')
    if enforce is not None and enforce.strip() in ('0', '1'):
        mode = 'enforcing' if enforce.strip() == '1' else 'permissive'

    if mode is None:
        return _item(
            'selinux',
            'SELinux state could not be read',
            'low', 'unknown',
            'Neither /etc/selinux/config nor /sys/fs/selinux could be read.',
            'Run "sestatus" on the server to check it manually.',
            extra={'platform': profile['label']},
        )
    if mode == 'enforcing':
        return _item(
            'selinux',
            'SELinux is enforcing',
            'low', 'ok',
            'SELINUX=%s on %s.' % (mode, profile['pretty'] or profile['label']),
            'No action needed.',
            extra={'platform': profile['label']},
        )
    if mode == 'permissive':
        return _item(
            'selinux',
            'SELinux is permissive (only logs, never blocks)',
            'medium', 'risk',
            'SELINUX=permissive on %s: violations are logged but not denied, so a '
            'compromised service is not contained.' % (profile['pretty'] or profile['label']),
            'Switch to enforcing after checking "ausearch -m AVC -ts recent" for '
            'denials, so the change does not break a running service.',
            commands=['setenforce 1',
                      "sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config",
                      'sestatus'],
            extra={'platform': profile['label']},
        )
    return _item(
        'selinux',
        'SELinux is disabled',
        'medium', 'risk',
        'SELINUX=%s: the kernel provides no mandatory access control on %s.'
        % (mode, profile['pretty'] or profile['label']),
        'Enabling SELinux on an already installed system needs a reboot and a full '
        'relabel ("touch /.autorelabel"), which can take a long time. Plan it in a '
        'maintenance window, not during business hours.',
        commands=["sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config",
                  'touch /.autorelabel',
                  'reboot'],
        extra={'platform': profile['label']},
    )


def check_apparmor():
    profile = detect_os()
    if profile['family'] not in ('debian', 'suse'):
        return None

    enabled = False
    body = _read('/sys/module/apparmor/parameters/enabled')
    if body and body.strip().lower().startswith('y'):
        enabled = True
    if not SYSROOT:
        out, ok = _shell('aa-status --enabled 2>/dev/null')
        if ok and not out.strip():
            enabled = True

    if enabled:
        return _item(
            'apparmor',
            'AppArmor is enabled',
            'low', 'ok',
            'The kernel AppArmor module is active on %s.' % (profile['pretty'] or profile['label']),
            'No action needed.',
            extra={'platform': profile['label']},
        )
    return _item(
        'apparmor',
        'AppArmor is not active',
        'low', 'risk',
        'No AppArmor profiles are enforced, so services are not confined if they '
        'are compromised. Debian installs it only when asked.',
        'Install AppArmor and enable it; Ubuntu ships it enabled by default.',
        commands=[_pkg_install(profile, 'apparmor', 'apparmor-utils'),
                  'systemctl enable --now apparmor',
                  'aa-status'],
        extra={'platform': profile['label']},
    )


# ---------------------------------------------------------------------------
# engine
# ---------------------------------------------------------------------------

CHECKS = [
    check_cli_timeout,
    check_sudo_nopasswd,
    check_ssh_root_login,
    check_ssh_password_auth,
    check_file_permissions,
    check_empty_password,
    check_firewall,
    check_fail2ban,
    check_selinux,
    check_apparmor,
    check_panel_ssl,
]

FIXERS = {
    'cli_timeout': _fix_cli_timeout,
    'sudo_nopasswd': _fix_sudo_nopasswd,
    'ssh_root_login': _fix_ssh_root_login,
    'ssh_password_auth': _fix_ssh_password_auth,
    'file_permissions': _fix_file_permissions,
    'empty_password': _fix_empty_password,
}

LEVEL_WEIGHT = {'high': 0, 'medium': 1, 'low': 2}
STATUS_WEIGHT = {'risk': 0, 'unknown': 1, 'ok': 2}


def run_checks():
    items = []
    for fn in CHECKS:
        try:
            item = fn()
        except Exception as exc:  # a broken check must not kill the scan
            item = _item(fn.__name__, 'Check failed to run', 'low', 'unknown',
                         str(exc), 'Report this to the plugin author.')
        if item:  # checks that do not apply to this distribution return None
            items.append(item)
    items.sort(key=lambda i: (STATUS_WEIGHT.get(i['status'], 3),
                              LEVEL_WEIGHT.get(i['level'], 3)))
    summary = {
        'total': len(items),
        'risk': sum(1 for i in items if i['status'] == 'risk'),
        'ok': sum(1 for i in items if i['status'] == 'ok'),
        'unknown': sum(1 for i in items if i['status'] == 'unknown'),
        'fixable': sum(1 for i in items if i['status'] == 'risk' and i['fixable']),
        'high': sum(1 for i in items if i['status'] == 'risk' and i['level'] == 'high'),
        'medium': sum(1 for i in items if i['status'] == 'risk' and i['level'] == 'medium'),
        'low': sum(1 for i in items if i['status'] == 'risk' and i['level'] == 'low'),
    }
    return items, summary


def _system_info():
    profile = detect_os()
    info = {
        'hostname': '',
        'os': profile['pretty'],
        'os_id': profile['id'],
        'os_name': profile['name'],
        'os_version': profile['version'],
        'family': profile['family'],
        'family_label': profile['label'],
        'pkg': profile['pkg'],
        'firewall': profile['firewall'],
        'ssh_service': profile['ssh_service'],
        'sudo_group': profile['sudo_group'],
        'mac': profile['mac'],
        'panel_port': profile['panel_port'],
        'kernel': '',
        'panel': '',
    }
    try:
        info['hostname'] = os.uname()[1] if hasattr(os, 'uname') else os.environ.get('COMPUTERNAME', '')
    except Exception:
        pass
    if not SYSROOT:
        out, ok = _shell('uname -r')
        if ok:
            info['kernel'] = out.strip()
        if _exists('/www/server/panel/class/common.py'):
            info['panel'] = 'aaPanel'
    return info


def _find(risk_id):
    for fn in CHECKS:
        try:
            item = fn()
        except Exception:
            continue
        if item and item['id'] == risk_id:
            return item
    return None


# ---------------------------------------------------------------------------
# plugin class - methods here are callable from index.html
# ---------------------------------------------------------------------------

class securityrisk_main:

    def _check(self, args=None):
        """Access guard for the session-less dynamic routes (/{plugin}/{method}).

        The documented /plugin?action=a&name=...&s=... router inherits the panel
        session; the shortcut route does not. Because fix() and restore() write
        to /etc, an anonymous request must never reach them. Returning False
        here disables that shortcut entirely while the authenticated router keeps
        working.
        """
        if os.environ.get('SECRISK_ALLOW_ANON') == '1':
            return True
        try:
            from flask import session
        except Exception:
            return False
        if len(session) == 0:
            return False
        for key in ('login', 'uid', 'user', 'username'):
            if session.get(key):
                return True
        return False

    def index(self, args):
        """Serve the UI for panels that route the plugin entry point to a method."""
        try:
            with io.open(os.path.join(PLUGIN_PATH, 'index.html'), 'r',
                         encoding='utf-8') as f:
                return f.read()
        except (IOError, OSError):
            return '<h1>Security Risk</h1><p>index.html is missing from the plugin directory.</p>'

    def get_index(self, args):
        _ensure_dirs()
        items, summary = run_checks()
        last = _read_log(1)
        return {
            'status': True,
            'items': items,
            'summary': summary,
            'system': _system_info(),
            'scan_time': int(time.time()),
            'last_fix': last[0] if last else None,
            'backup_dir': BACKUP_PATH,
        }

    def rescan_one(self, args):
        rid = (args or {}).get('id', '')
        item = _find(rid)
        if not item:
            return {'status': False, 'msg': 'Unknown check: %s' % rid}
        return {'status': True, 'item': item}

    def fix(self, args):
        rid = (args or {}).get('id', '')
        fixer = FIXERS.get(rid)
        if not fixer:
            return {'status': False, 'msg': 'This risk has no automatic fix.'}
        try:
            result = fixer()
        except FixError as exc:
            _log({'id': rid, 'ok': False, 'msg': str(exc), 'changes': []})
            return {'status': False, 'msg': str(exc), 'item': _find(rid)}
        except Exception as exc:
            _log({'id': rid, 'ok': False, 'msg': 'Unexpected error: %s' % exc,
                  'changes': []})
            return {'status': False, 'msg': 'Unexpected error: %s' % exc,
                    'item': _find(rid)}

        item = _find(rid)
        entry = {
            'id': rid,
            'title': item['title'] if item else rid,
            'ok': True,
            'changes': result.get('changes', []),
            'backup': result.get('backup', ''),
        }
        _log(entry)
        return {
            'status': True,
            'msg': 'Applied %d change(s).' % len(entry['changes']),
            'changes': entry['changes'],
            'backup': entry['backup'],
            'item': item,
        }

    def get_history(self, args):
        return {'status': True, 'items': _read_log(30)}

    def list_backups(self, args):
        if not os.path.isdir(BACKUP_PATH):
            return {'status': True, 'items': []}
        items = []
        for name in sorted(os.listdir(BACKUP_PATH), reverse=True):
            root = os.path.join(BACKUP_PATH, name)
            manifest = os.path.join(root, 'manifest.json')
            if not os.path.isfile(manifest):
                continue
            try:
                with io.open(manifest, 'r', encoding='utf-8') as f:
                    data = json.load(f)
            except Exception:
                continue
            data['id'] = name
            items.append(data)
        return {'status': True, 'items': items[:30]}

    def restore(self, args):
        bid = (args or {}).get('backup', '')
        if not RE_BACKUP_ID.match(bid or ''):
            return {'status': False, 'msg': 'Invalid backup id.'}
        root = os.path.join(BACKUP_PATH, bid)
        manifest = os.path.join(root, 'manifest.json')
        if not os.path.isfile(manifest):
            return {'status': False, 'msg': 'Backup not found.'}
        try:
            with io.open(manifest, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except Exception as exc:
            return {'status': False, 'msg': 'Cannot read manifest: %s' % exc}

        restored = []
        for entry in data.get('files', []):
            src = os.path.join(root, entry.get('file', ''))
            dst = _path(entry.get('path', ''))
            if not os.path.isfile(src) or not dst:
                continue
            parent = os.path.dirname(dst)
            if parent and not os.path.isdir(parent):
                continue
            try:
                shutil.copy2(src, dst)
                if entry.get('mode') is not None:
                    os.chmod(dst, entry['mode'])
                restored.append(entry['path'])
            except (OSError, IOError) as exc:
                return {'status': False, 'msg': 'Restore failed on %s: %s'
                        % (entry.get('path'), exc)}

        for entry in data.get('modes', []):
            dst = _path(entry.get('path', ''))
            if not dst or not os.path.isfile(dst):
                continue
            try:
                os.chmod(dst, entry['mode'])
                restored.append('%s (mode)' % entry['path'])
            except (OSError, IOError) as exc:
                return {'status': False, 'msg': 'chmod failed on %s: %s'
                        % (entry.get('path'), exc)}

        if not restored:
            return {'status': False, 'msg': 'Nothing to restore in this backup.'}
        _log({'id': data.get('risk', ''), 'title': 'Restore %s' % bid, 'ok': True,
              'changes': ['Restored ' + ', '.join(restored)], 'backup': bid})
        return {'status': True, 'msg': 'Restored %d file(s).' % len(restored),
                'changes': ['Restored ' + ', '.join(restored)]}


# CLI entry point: `python securityrisk_main.py scan` for quick server checks
if __name__ == '__main__':
    cmd = sys.argv[1] if len(sys.argv) > 1 else 'scan'
    if cmd == 'scan':
        _items, _summary = run_checks()
        print(json.dumps({'summary': _summary, 'items': _items},
                         ensure_ascii=False, indent=2))
    elif cmd == 'fix' and len(sys.argv) > 2:
        print(json.dumps(FIXERS[sys.argv[2]](), ensure_ascii=False, indent=2))
    else:
        print('usage: securityrisk_main.py [scan|fix <risk_id>]')
