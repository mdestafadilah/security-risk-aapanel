#!/usr/bin/python
# coding: utf-8
"""
Security Risk - aaPanel third-party plugin.

Audits a Linux server for common hardening gaps (idle shell timeout, passwordless
sudo, SSH exposure, file permissions, empty passwords, firewall, fail2ban, panel
SSL) and can fix the auto-fixable ones in place.

Safety model for every fix:
    1. every touched file is copied to data/backup/<id>/ first
    2. the new content is written to a temp file next to the target and
       validated there (visudo -cf / sshd -t -f) before the target is touched
    3. the temp file atomically replaces the target, then the full config is
       validated again; a rejection rolls every file back immediately
    4. the check is re-run so the UI shows the real state, not an assumption

Commands are always run through subprocess with an argument list (no shell)
and their real exit status. The panel's public.ExecShell is deliberately not
used: it returns (stdout, stderr) without the exit code, which would make
every validator look successful.

The class name must match the file name (aaPanel plugin contract).

DISCLAIMER: provided "as is", without warranty of any kind. It modifies system
files as root; use it at your own risk. The repository owner and contributors
are not liable for any lockout, downtime, data loss or other damage arising
from its use. See README.md ("Disclaimer & risiko penggunaan").
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
import hashlib
import subprocess

try:
    from urllib.parse import urlparse
except ImportError:  # pragma: no cover - python 2
    from urlparse import urlparse

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
RE_NOPASSWD = re.compile(r'\bNOPASSWD\s*:')
RE_NOPASSWD_TAG = re.compile(r'\bNOPASSWD\s*:\s*')
RE_SSH_KEY = re.compile(r'^\s*([A-Za-z][A-Za-z0-9]*)\s+(.+?)\s*$')
RE_SSH_MATCH = re.compile(r'^\s*Match\s', re.I)
RE_BACKUP_ID = re.compile(r'^[0-9]{8}-[0-9]{6}-[a-z0-9_]+$')
RE_USERNAME = re.compile(r'^[A-Za-z_][A-Za-z0-9_.-]*\$?$')

# files whose copies must never sit in a backup: they hold every password hash
NO_BACKUP = ('/etc/shadow', '/etc/gshadow')

# fixes that can lock the administrator out; the API demands confirm=1
DANGEROUS = ('ssh_password_auth',)

# test hook: a callable(args) -> (output, ok) that replaces real execution
_RUNNER = None


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


def _read_bytes(path):
    try:
        with open(_path(path), 'rb') as f:
            return f.read()
    except (IOError, OSError):
        return None


def _exists(path):
    return os.path.exists(_path(path))


def _mode(path):
    try:
        return stat.S_IMODE(os.stat(_path(path)).st_mode)
    except OSError:
        return None


def _sha256(path):
    try:
        with open(_path(path), 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()
    except (IOError, OSError):
        return None


def _copy_meta(src, dst):
    """Give `dst` the owner, mode and SELinux label of `src` (best effort)."""
    st = os.stat(src)
    if hasattr(os, 'chown'):
        try:
            os.chown(dst, st.st_uid, st.st_gid)
        except OSError:
            pass
    if hasattr(os, 'getxattr'):
        try:
            os.setxattr(dst, 'security.selinux', os.getxattr(src, 'security.selinux'))
        except (OSError, IOError):
            pass
    os.chmod(dst, stat.S_IMODE(st.st_mode))


def _tmp_name(real):
    # a leading dot keeps the temp file out of sudoers.d (sudo skips names with
    # a dot) and out of sshd_config.d/*.conf
    return os.path.join(os.path.dirname(real),
                        '.%s.secrisk-%d.tmp' % (os.path.basename(real), os.getpid()))


def _stage(path, content):
    """Write `content` to a temp file beside `path` with the same metadata.

    Returns the temp path; the target itself is untouched, so a full disk or a
    crash here can never leave /etc/sudoers or sshd_config truncated.
    """
    real = os.path.realpath(_path(path))
    tmp = _tmp_name(real)
    try:
        if isinstance(content, bytes):
            f = io.open(tmp, 'wb')
        else:
            f = io.open(tmp, 'w', encoding='utf-8', newline='\n')
        with f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        if os.path.exists(real):
            _copy_meta(real, tmp)
    except (IOError, OSError):
        _discard(tmp)
        raise
    return tmp


def _discard(tmp):
    try:
        if os.path.exists(tmp):
            os.chmod(tmp, 0o600)
            os.remove(tmp)
    except OSError:
        pass


def _commit(tmp, path):
    """Atomically move a staged temp file over its target."""
    real = os.path.realpath(_path(path))
    try:
        os.replace(tmp, real)
    except OSError:
        if os.name != 'nt' or not os.path.exists(real):
            _discard(tmp)
            raise
        # Windows refuses to replace a read-only file (test fixtures only)
        os.chmod(real, 0o600)
        os.replace(tmp, real)


def _write(path, content):
    """Replace a file atomically, keeping its owner, mode and SELinux label."""
    _commit(_stage(path, content), path)


def _live():
    """True when external commands may run (real host, or a test runner)."""
    return _RUNNER is not None or not SYSROOT


def _bin(name):
    """Absolute path of a system binary, or None. sbin is searched explicitly
    because the panel process does not always have it in PATH."""
    if _RUNNER is not None:
        return name
    if SYSROOT:
        return None
    search = os.pathsep.join([os.environ.get('PATH', ''), '/usr/sbin', '/sbin',
                              '/usr/local/sbin', '/usr/bin', '/bin'])
    return shutil.which(name, path=search)


def _run(args, timeout=20):
    """Run a command without a shell, return (output, ok) from the real exit code."""
    args = [str(a) for a in args]
    if _RUNNER is not None:
        return _RUNNER(args)
    if SYSROOT:
        return '', False
    env = dict(os.environ, LC_ALL='C', LANG='C')  # validators are parsed in English
    try:
        proc = subprocess.Popen(args, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, env=env)
    except OSError as exc:
        return str(exc), False
    try:
        out = proc.communicate(timeout=timeout)[0]
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        return 'timed out after %ds: %s' % (timeout, ' '.join(args)), False
    if not isinstance(out, str):
        out = out.decode('utf-8', 'replace')
    return out, proc.returncode == 0


def _run_bin(name, *args, **kw):
    exe = _bin(name)
    if not exe:
        return '%s not found' % name, False
    return _run([exe] + list(args), **kw)


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
    return _bin(name) is not None


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


def _backup(paths, risk_id, modes=None, extra=None):
    """Copy files into a timestamped backup dir, return (backup_id, saved list)."""
    _ensure_dirs()
    stamp = time.strftime('%Y%m%d-%H%M%S')
    bid = '%s-%s' % (stamp, risk_id)
    n = 1
    while os.path.exists(os.path.join(BACKUP_PATH, bid)):
        # two fixes in the same second must not overwrite each other's backup
        n += 1
        bid = '%s-%s_%d' % (stamp, risk_id, n)
    root = os.path.join(BACKUP_PATH, bid)
    saved = []
    for p in paths:
        if p in NO_BACKUP:
            raise FixError('Refusing to copy %s into a backup.' % p)
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
    manifest = {'id': bid, 'risk': risk_id, 'time': int(time.time()),
                'files': saved, 'modes': modes or []}
    manifest.update(extra or {})
    _save_manifest(bid, manifest)
    _prune_backups()
    return bid, saved


def _manifest_path(bid):
    return os.path.join(BACKUP_PATH, bid, 'manifest.json')


def _load_manifest(bid):
    with io.open(_manifest_path(bid), 'r', encoding='utf-8') as f:
        return json.load(f)


def _save_manifest(bid, data):
    with io.open(_manifest_path(bid), 'w', encoding='utf-8') as f:
        f.write(json.dumps(data, ensure_ascii=False, indent=2))


def _seal_backup(bid):
    """Record the state right after a fix, so restore can tell whether the file
    was edited again since then (restoring would silently undo that edit)."""
    try:
        data = _load_manifest(bid)
    except (IOError, OSError, ValueError):
        return
    data['after'] = dict((e['path'], _sha256(e['path'])) for e in data.get('files', []))
    for entry in data.get('modes', []):
        entry['after'] = _mode(entry['path'])
    _save_manifest(bid, data)


def _purge_sensitive_backups():
    """Remove password-hash copies left by plugin versions before 1.2."""
    if not os.path.isdir(BACKUP_PATH):
        return
    for name in os.listdir(BACKUP_PATH):
        if not RE_BACKUP_ID.match(name):
            continue
        try:
            data = _load_manifest(name)
        except (IOError, OSError, ValueError):
            continue
        keep = []
        for entry in data.get('files', []):
            if entry.get('path') in NO_BACKUP:
                src = os.path.join(BACKUP_PATH, name, entry.get('file', ''))
                try:
                    os.remove(src)
                except OSError:
                    pass
            else:
                keep.append(entry)
        if len(keep) != len(data.get('files', [])):
            data['files'] = keep
            data['note'] = 'Password hash copy removed for safety.'
            _save_manifest(name, data)


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
# accounts (shared by the sudo, permission and empty password checks)
# ---------------------------------------------------------------------------

def _shadow_map():
    """{user: hash field} from /etc/shadow, or None when it is not readable."""
    body = _read('/etc/shadow')
    if body is None:
        return None
    out = {}
    for line in body.splitlines():
        if not line.strip() or line.startswith('#'):
            continue
        parts = line.split(':')
        if len(parts) >= 2 and parts[0]:
            out[parts[0]] = parts[1]
    return out


def _usable_hash(value):
    """A hash a user can actually type a password against (not empty, not locked)."""
    return bool(value) and value[0] not in '!*'


def _group_name(gid):
    for line in (_read('/etc/group') or '').splitlines():
        parts = line.split(':')
        if len(parts) >= 3 and parts[2] == str(gid):
            return parts[0]
    return None


def _group_members(name):
    """Users covered by %name: listed members plus users with it as primary group."""
    gid, members = None, set()
    for line in (_read('/etc/group') or '').splitlines():
        parts = line.split(':')
        if len(parts) >= 4 and parts[0] == name:
            gid = parts[2]
            members.update(m.strip() for m in parts[3].split(',') if m.strip())
    if gid is not None:
        for line in (_read('/etc/passwd') or '').splitlines():
            parts = line.split(':')
            if len(parts) >= 4 and parts[3] == gid:
                members.add(parts[0])
    return members


# ---------------------------------------------------------------------------
# check 2 - passwordless sudo
# ---------------------------------------------------------------------------

def _sudoers_files():
    files = ['/etc/sudoers']
    for p in _glob('/etc/sudoers.d/*'):
        base = os.path.basename(p)
        # sudo itself skips names with a dot or a trailing ~
        if os.path.isdir(_path(p)) or base.endswith('~') or '.' in base:
            continue
        files.append(p)
    return files


def _rule_principals(text):
    """User list of a sudoers rule ("alice, %adm  ALL=(ALL) ..." -> [alice, %adm])."""
    tokens = text.split('=', 1)[0].split()
    if len(tokens) < 2:
        return None
    return [u.strip() for u in ' '.join(tokens[:-1]).split(',') if u.strip()]


def _password_gap(text, shadow):
    """Why dropping NOPASSWD from this rule would leave someone unable to sudo.

    Without NOPASSWD sudo asks for the user's own password. Cloud images create
    the admin user (ubuntu, ec2-user, rocky ...) with a locked password, so
    removing the tag there removes the only route to root. Returns '' when every
    covered user has a usable password.
    """
    if shadow is None:
        return '/etc/shadow is not readable, the users cannot be verified'
    principals = _rule_principals(text)
    if not principals:
        return 'rule format not recognised'
    users = set()
    for p in principals:
        if p.startswith('%') and RE_USERNAME.match(p[1:]):
            users.update(_group_members(p[1:]))
        elif RE_USERNAME.match(p) and not p.isupper():
            users.add(p)
        else:
            return '"%s" (alias, ALL, uid or netgroup) cannot be verified' % p
    missing = sorted(u for u in users if u != 'root' and not _usable_hash(shadow.get(u)))
    if missing:
        return 'no usable password for %s' % ', '.join(missing)
    return ''


def _nopasswd_hits(shadow=None):
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
                             'lines': end - start + 1, 'text': text.strip(),
                             'blocked': _password_gap(text, shadow)})
    return hits


def check_sudo_nopasswd():
    shadow = _shadow_map()
    hits = _nopasswd_hits(shadow)
    if not hits:
        return _item(
            'sudo_nopasswd',
            'No sudo rule allows an empty password',
            'medium', 'ok',
            'No active NOPASSWD entry was found in /etc/sudoers or /etc/sudoers.d.',
            'No action needed.',
        )

    files = sorted(set(h['file'] for h in hits))
    safe = [h for h in hits if not h['blocked']]
    blocked = [h for h in hits if h['blocked']]
    detail = 'Passwordless sudo is allowed by %d rule(s): %s' % (
        len(hits), ', '.join(files))
    if blocked:
        detail += '. %d rule(s) are left alone because removing NOPASSWD would ' \
                  'lock their users out of sudo.' % len(blocked)
    group = detect_os()['sudo_group']
    plan = []
    if safe:
        plan = ['Back up %s' % ', '.join(sorted(set(h['file'] for h in safe))),
                'Remove only the NOPASSWD: tag, the rule itself stays',
                'Validate the new file with "visudo -cf" before it replaces the old one']
        plan += ['  change %s:%d  %s' % (h['file'], h['line'], h['text'][:100])
                 for h in safe[:6]]
    plan += ['  skip   %s:%d  %s' % (h['file'], h['line'], h['blocked'])
             for h in blocked[:6]]
    return _item(
        'sudo_nopasswd',
        'The following sudo files contain the NOPASSWD flag: %s' % ', '.join(files),
        'medium', 'risk',
        detail,
        'Remove the NOPASSWD tag so sudo asks for the user password again; keep '
        'the rule itself. On this distribution the admin group is "%' + group + '". '
        'Users without a password must get one first ("passwd <user>"), otherwise '
        'they lose sudo entirely.',
        fixable=bool(safe),
        plan=plan,
        extra={'files': files,
               'rules': [{'file': h['file'], 'line': h['line'], 'text': h['text'][:200],
                          'skip': h['blocked']} for h in hits]},
    )


def _strip_nopasswd(body, shadow):
    """Drop the NOPASSWD: tag from every rule whose users can type a password.

    Returns (new_body, changed_line_count, skipped [(line, text, reason)]).
    """
    targets, skipped = set(), []
    for start, end, text in _logical_lines(body):
        if text.lstrip().startswith('#') or not RE_NOPASSWD.search(text):
            continue
        gap = _password_gap(text, shadow)
        if gap:
            skipped.append((start + 1, text.strip(), gap))
            continue
        targets.update(range(start, end + 1))
    lines = body.splitlines(True)
    count = 0
    for idx in sorted(targets):
        new = RE_NOPASSWD_TAG.sub('', lines[idx])
        if new != lines[idx]:
            lines[idx] = new
            count += 1
    return ''.join(lines), count, skipped


def _fix_sudo_nopasswd():
    shadow = _shadow_map()
    hits = _nopasswd_hits(shadow)
    if not hits:
        raise FixError('No NOPASSWD rule is left to fix.')
    files = sorted(set(h['file'] for h in hits if not h['blocked']))
    if not files:
        raise FixError('Nothing changed: every NOPASSWD rule would lock its users out '
                       '(%s). Give them a password first.'
                       % '; '.join('%s:%d %s' % (h['file'], h['line'], h['blocked'])
                                   for h in hits))
    if _live() and not _bin('visudo'):
        raise FixError('visudo was not found; sudoers is never edited without validation.')
    bid, _ = _backup(files, 'sudo_nopasswd')

    changes, originals, staged = [], {}, {}
    try:
        for path in files:
            body = _read(path, '')
            new_body, count, _skipped = _strip_nopasswd(body, shadow)
            if not count:
                continue
            tmp = _stage(path, new_body)
            staged[path] = tmp
            originals[path] = body
            if _live():
                out, ok = _run_bin('visudo', '-c', '-f', tmp)
                if not ok:
                    raise FixError('visudo rejected the new %s, nothing was changed: %s'
                                   % (path, out.strip()[:300] or 'unknown error'))
            changes.append('Removed NOPASSWD from %d line(s) in %s' % (count, path))
    except Exception:
        for tmp in staged.values():
            _discard(tmp)
        raise

    committed = []
    try:
        for path, tmp in staged.items():
            _commit(tmp, path)
            committed.append(path)
        if _live():
            # the main file pulls in every drop-in, so this checks the whole policy
            out, ok = _run_bin('visudo', '-c', '-f', _path('/etc/sudoers'))
            if not ok:
                raise FixError('Rolled back, sudoers validation failed: %s'
                               % (out.strip()[:300] or 'unknown error'))
    except Exception:
        for path in committed:
            _write(path, originals[path])
        for path, tmp in staged.items():
            if path not in committed:
                _discard(tmp)
        raise

    for h in hits:
        if h['blocked']:
            changes.append('Skipped %s:%d (%s)' % (h['file'], h['line'], h['blocked']))
    return {'changes': changes, 'backup': bid, 'reload': ''}


# ---------------------------------------------------------------------------
# check 3/4 - SSH hardening
# ---------------------------------------------------------------------------

# older OpenSSH reports the same setting under its previous name
SSH_ALIASES = {'without-password': 'prohibit-password'}


def _ssh_files():
    files = []
    for p in _glob('/etc/ssh/sshd_config.d/*.conf'):
        files.append(p)
    files.append('/etc/ssh/sshd_config')
    return [p for p in files if _exists(p)]


def _ssh_global(body):
    """Yield (index, key, value) for directives before the first Match block.

    Anything after "Match" only applies to the matched connections, so it never
    decides the global value.
    """
    for idx, line in enumerate(body.splitlines()):
        if line.lstrip().startswith('#'):
            continue
        if RE_SSH_MATCH.match(line):
            return
        m = RE_SSH_KEY.match(line)
        if m:
            yield idx, m.group(1), m.group(2)


def _ssh_effective(key):
    """Return (value, source) using sshd -T when possible, else config parsing."""
    if _live():
        out, ok = _run_bin('sshd', '-T')
        if ok:
            for line in out.splitlines():
                parts = line.strip().split(None, 1)
                if len(parts) == 2 and parts[0].lower() == key.lower():
                    value = parts[1].strip().lower()
                    return SSH_ALIASES.get(value, value), 'sshd -T'
    # sshd uses the first value it reads; drop-ins are included before the rest
    for path in _ssh_files():
        for _idx, k, v in _ssh_global(_read(path, '')):
            if k.lower() == key.lower():
                value = v.strip().lower()
                return SSH_ALIASES.get(value, value), path
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
            plan=['Back up the file that declares PermitRootLogin',
                  'Set PermitRootLogin prohibit-password',
                  'Validate with "sshd -t" before and after replacing the file, '
                  'then reload sshd; roll back on failure'],
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
            plan=['Back up the file that declares PasswordAuthentication',
                  'Set PasswordAuthentication no',
                  'Validate with "sshd -t" before and after replacing the file, '
                  'then reload sshd; roll back on failure',
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
    """First file that globally declares `key` (drop-ins are read before the main file)."""
    for path in _ssh_files():
        for _idx, k, _v in _ssh_global(_read(path, '')):
            if k.lower() == key.lower():
                return path
    return None


def _reload_sshd():
    # Debian/Ubuntu call the unit "ssh", RHEL family calls it "sshd"
    svc = detect_os()['ssh_service']
    other = 'ssh' if svc == 'sshd' else 'sshd'
    for args in (('systemctl', 'reload', svc), ('systemctl', 'reload', other),
                 ('service', svc, 'reload'), ('service', other, 'reload')):
        _out, ok = _run_bin(*args)
        if ok:
            return args[2] if args[0] == 'systemctl' else args[1]
    return None


def _set_ssh_key(key, value):
    files = _ssh_files()
    if not files:
        raise FixError('sshd_config not found.')
    if _live() and not _bin('sshd'):
        raise FixError('sshd was not found; sshd_config is never edited without "sshd -t".')
    # edit the file that actually carries the directive, otherwise sshd keeps
    # using the value from an earlier Include
    path = _ssh_declared_file(key) or '/etc/ssh/sshd_config'
    body = _read(path, '')

    lines = body.splitlines(True)
    new_line = '%s %s\n' % (key, value)
    target = None
    for idx, k, _v in _ssh_global(body):
        if k.lower() == key.lower():
            target = idx
            break
    if target is not None:
        lines[target] = new_line
    else:
        # appended after a Match block it would only apply inside that block
        at = None
        for idx, raw in enumerate(lines):
            if RE_SSH_MATCH.match(raw):
                at = idx
                break
        if at is None:
            if lines and not lines[-1].endswith('\n'):
                lines[-1] += '\n'
            lines.append(new_line)
        else:
            lines.insert(at, new_line)

    bid, _ = _backup([path], 'ssh_%s' % key.lower())
    tmp = _stage(path, ''.join(lines))
    if _live():
        out, ok = _run_bin('sshd', '-t', '-f', tmp)
        if not ok:
            _discard(tmp)
            raise FixError('"sshd -t" rejected the new %s, nothing was changed: %s'
                           % (path, out.strip()[:300] or 'unknown error'))
    _commit(tmp, path)
    changes = ['Set %s %s in %s' % (key, value, path)]

    if _live():
        out, ok = _run_bin('sshd', '-t')
        if not ok:
            _write(path, body)
            raise FixError('Rolled back, "sshd -t" rejected the full configuration: %s'
                           % (out.strip()[:300] or 'unknown error'))

    # confirm the new value is really the effective one before sshd reloads it,
    # so a rollback here never leaves the running daemon on a different config
    now, now_src = _ssh_effective(key)
    if now is not None and now != value:
        _write(path, body)
        raise FixError('Rolled back: %s still resolves to "%s" (from %s), the value '
                       'is overridden by another config file.'
                       % (key, now, now_src))

    if _live():
        svc = _reload_sshd()
        if svc:
            changes.append('Reloaded %s' % svc)
        else:
            changes.append('Config saved but reload failed - run "systemctl reload %s" '
                           'manually' % detect_os()['ssh_service'])
    return {'changes': changes, 'backup': bid, 'reload': ''}


def _fix_ssh_root_login():
    return _set_ssh_key('PermitRootLogin', 'prohibit-password')


def _fix_ssh_password_auth():
    return _set_ssh_key('PasswordAuthentication', 'no')


# ---------------------------------------------------------------------------
# check 5 - sensitive file permissions
# ---------------------------------------------------------------------------

PERM_RULES = [
    # (path, max mode, group that may additionally read the file)
    ('/etc/passwd', 0o644, None),
    # Debian/Ubuntu ship 0640 root:shadow so setgid unix_chkpwd can verify
    # passwords; forcing 0600 there breaks screen lockers and PAM helpers
    ('/etc/shadow', 0o600, 'shadow'),
    ('/etc/group', 0o644, None),
    ('/etc/gshadow', 0o600, 'shadow'),
    ('/etc/sudoers', 0o440, None),
    ('/etc/ssh/sshd_config', 0o600, None),
]


def _perm_issues(entries=None):
    """Return files whose mode has bits outside the allowed mask, or a non-root owner.

    `entries` is a list of (path, mode) or (path, mode, uid, gid) tuples; when
    omitted the live files are read. Kept separable so the rule can be
    unit-tested without touching the filesystem.
    """
    rules = dict((r[0], r) for r in PERM_RULES)
    if entries is None:
        entries = []
        for path, _max, _grp in PERM_RULES:
            try:
                st = os.stat(_path(path))
            except OSError:
                continue
            entries.append((path, stat.S_IMODE(st.st_mode), st.st_uid, st.st_gid))
    issues = []
    for entry in entries:
        path, cur = entry[0], entry[1]
        uid = entry[2] if len(entry) > 2 else 0
        gid = entry[3] if len(entry) > 3 else None
        rule = rules.get(path)
        if rule is None:
            continue
        want = rule[1]
        if rule[2] and gid is not None and _group_name(gid) == rule[2]:
            want |= 0o040
        bad_mode = bool(cur & ~want)  # any bit outside the allowed mask
        bad_owner = uid != 0
        if bad_mode or bad_owner:
            issues.append({'path': path, 'current': oct(cur), 'want': oct(want),
                           'target': oct(cur & want), 'uid': uid,
                           'bad_mode': bad_mode, 'bad_owner': bad_owner})
    return issues


def check_file_permissions():
    issues = _perm_issues()
    if not issues:
        return _item(
            'file_permissions',
            'Sensitive system files have safe permissions',
            'low', 'ok',
            'All checked files are owned by root and at or below their maximum mode.',
            'No action needed.',
        )
    parts = []
    plan = []
    for i in issues:
        if i['bad_mode']:
            parts.append('%s is %s (max %s)' % (i['path'], i['current'], i['want']))
            plan.append('chmod %s %s' % (i['target'][2:], i['path']))
        if i['bad_owner']:
            parts.append('%s is owned by uid %s' % (i['path'], i['uid']))
            plan.append('chown root %s' % i['path'])
    critical = any(i['path'] in ('/etc/shadow', '/etc/sudoers') for i in issues)
    return _item(
        'file_permissions',
        'Sensitive system files are readable by more users than needed',
        'high' if critical else 'medium', 'risk',
        '; '.join(parts),
        'Restore the standard modes: 644 /etc/passwd, 644 /etc/group, 600 /etc/shadow '
        'and /etc/gshadow (640 when the group is "shadow"), 440 /etc/sudoers, '
        '600 sshd_config, all owned by root. Only the extra bits are removed.',
        fixable=True,
        plan=plan,
        extra={'files': issues},
    )


def _fix_file_permissions():
    issues = _perm_issues()
    if not issues:
        raise FixError('Permissions already correct.')
    previous = [{'path': i['path'], 'mode': int(i['current'], 8), 'uid': i['uid']}
                for i in issues]
    bid, _ = _backup([], 'file_permissions', previous)
    changes = []
    for i in issues:
        try:
            if i['bad_owner'] and hasattr(os, 'chown'):
                os.chown(_path(i['path']), 0, -1)
                changes.append('%s: owner uid %s -> root' % (i['path'], i['uid']))
            if i['bad_mode']:
                os.chmod(_path(i['path']), int(i['target'], 8))
                changes.append('%s: %s -> %s' % (i['path'], i['current'], i['target']))
        except OSError as exc:
            raise FixError('chmod/chown failed on %s: %s' % (i['path'], exc))
    return {'changes': changes, 'backup': bid, 'reload': ''}


# ---------------------------------------------------------------------------
# check 6 - accounts with an empty password
# ---------------------------------------------------------------------------

def _empty_password_users():
    shadow = _shadow_map()
    if shadow is None:
        return None
    return [user for user, value in shadow.items() if value == '']


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
              'Re-read /etc/shadow to confirm every account is locked',
              'No copy of /etc/shadow is kept; to undo, set a password with '
              '"passwd <user>"'],
        extra={'users': users},
    )


def _fix_empty_password():
    users = _empty_password_users() or []
    if not users:
        raise FixError('No empty password account is left.')
    odd = [u for u in users if not RE_USERNAME.match(u)]
    if odd:
        raise FixError('Unexpected user name(s) in /etc/shadow: %s. Lock them by hand.'
                       % ', '.join(repr(u) for u in odd))
    if _live() and not _bin('passwd'):
        raise FixError('passwd was not found.')
    # only the account names are recorded: a copy of /etc/shadow would keep every
    # password hash on disk and a restore would bring old passwords back
    bid, _ = _backup([], 'empty_password', extra={'accounts': users})

    errors = []
    if _live():
        for user in users:
            out, ok = _run_bin('passwd', '-l', user)
            if not ok:
                errors.append('%s: %s' % (user, out.strip()[:200] or 'passwd -l failed'))
    else:
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

    # trust the file, not the exit code
    left = _empty_password_users() or []
    if left:
        raise FixError('Still without a password: %s. %s'
                       % (', '.join(left), '; '.join(errors)))
    return {'changes': ['Locked account %s' % u for u in users],
            'backup': bid, 'reload': ''}


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

    if _live():
        # "firewall-cmd --state" prints "not running" when stopped, so compare
        # the whole answer and the exit code, not a substring
        out, ok = _run_bin('firewall-cmd', '--state')
        if ok and out.strip().lower() == 'running':
            active = True
            evidence.append('firewalld is running')
        out, ok = _run_bin('ufw', 'status')
        if ok and out.strip().lower().startswith('status: active'):
            active = True
            evidence.append('ufw status: active')
        out, ok = _run_bin('iptables', '-S')
        rules = [l for l in out.splitlines() if l.startswith('-A')] if ok else []
        if rules:
            evidence.append('iptables has %d rule(s)' % len(rules))

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
    if _live():
        out, ok = _run_bin('fail2ban-client', 'status')
        running = ok and 'jail list' in out.lower()
    if installed and (running or not _live()):
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
    if _live() and not enabled:
        # exit code 0 is the only "enabled" answer; a missing aa-status binary
        # also prints nothing, which used to be read as enabled
        _out, ok = _run_bin('aa-status', '--enabled')
        if ok:
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
        out, ok = _run_bin('uname', '-r')
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
# request guards
# ---------------------------------------------------------------------------

def _truthy(value):
    return str(value or '').strip().lower() in ('1', 'true', 'yes', 'on')


def _cross_site_request():
    """True when a browser sent this request from another origin (CSRF).

    Browsers always attach Origin (or at least Referer) to a cross-site POST, so
    a mismatch with the panel's own host means another page is driving the
    admin's session. Clients without either header (curl, the panel itself)
    still need the panel session.
    """
    try:
        from flask import request
        headers = request.headers
        hosts = set([request.host.lower()])
        for h in (headers.get('X-Forwarded-Host') or '').split(','):
            if h.strip():
                hosts.add(h.strip().lower())
    except Exception:  # not inside a flask request (tests, CLI)
        return False
    src = (headers.get('Origin') or headers.get('Referer') or '').strip()
    if not src:
        return False
    if src.lower() == 'null':
        return True
    return urlparse(src).netloc.lower() not in hosts


def _is_sudoers(path):
    return path == '/etc/sudoers' or path.startswith('/etc/sudoers.d/')


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
        # the debug switch only works inside a test sysroot, never on a real host
        if os.environ.get('SECRISK_ALLOW_ANON') == '1' and SYSROOT:
            return True
        try:
            from flask import session
        except Exception:
            return False
        try:
            if len(session) == 0:
                return False
            for key in ('login', 'uid', 'user', 'username'):
                if session.get(key):
                    return True
        except Exception:
            return False
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
        _purge_sensitive_backups()
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
        args = args or {}
        rid = args.get('id', '')
        if _cross_site_request():
            return {'status': False, 'msg': 'Cross-site request refused.'}
        fixer = FIXERS.get(rid)
        if not fixer:
            return {'status': False, 'msg': 'This risk has no automatic fix.'}
        if rid in DANGEROUS and not _truthy(args.get('confirm')):
            return {'status': False, 'need_confirm': True,
                    'msg': 'This fix can lock you out of SSH. Test key login in a '
                           'second session, then confirm (confirm=1).'}
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

        if result.get('backup'):
            _seal_backup(result['backup'])
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
        _purge_sensitive_backups()
        items = []
        for name in sorted(os.listdir(BACKUP_PATH), reverse=True):
            if not RE_BACKUP_ID.match(name) or not os.path.isfile(_manifest_path(name)):
                continue
            try:
                data = _load_manifest(name)
            except Exception:
                continue
            data['id'] = name
            items.append(data)
        return {'status': True, 'items': items[:30]}

    def restore(self, args):
        args = args or {}
        if _cross_site_request():
            return {'status': False, 'msg': 'Cross-site request refused.'}
        bid = args.get('backup', '')
        force = _truthy(args.get('force'))
        if not RE_BACKUP_ID.match(bid or ''):
            return {'status': False, 'msg': 'Invalid backup id.'}
        root = os.path.join(BACKUP_PATH, bid)
        if not os.path.isfile(_manifest_path(bid)):
            return {'status': False, 'msg': 'Backup not found.'}
        try:
            data = _load_manifest(bid)
        except Exception as exc:
            return {'status': False, 'msg': 'Cannot read manifest: %s' % exc}

        real_root = os.path.realpath(root) + os.sep
        files = []
        for entry in data.get('files', []):
            path = entry.get('path') or ''
            src = os.path.realpath(os.path.join(root, entry.get('file') or ''))
            # the manifest decides nothing outside /etc or outside its own folder
            if (path in NO_BACKUP or not path.startswith('/etc/')
                    or '..' in path.split('/') or not src.startswith(real_root)
                    or not os.path.isfile(src)):
                continue
            files.append((entry, src))
        modes = [m for m in data.get('modes', [])
                 if (m.get('path') or '').startswith('/etc/') and m.get('mode') is not None]

        if not files and not modes:
            if data.get('accounts'):
                return {'status': False,
                        'msg': 'Locked accounts (%s) are not unlocked automatically: that '
                               'would bring back a login without password. Set a password '
                               'with "passwd <user>" instead.' % ', '.join(data['accounts'])}
            return {'status': False, 'msg': 'Nothing to restore in this backup.'}

        # refuse to silently undo edits made after the fix
        after = data.get('after')
        drift = []
        for entry, _src in files:
            if after is None or after.get(entry['path']) != _sha256(entry['path']):
                drift.append(entry['path'])
        for m in modes:
            if m.get('after') is None or _mode(m['path']) != m['after']:
                drift.append('%s (mode)' % m['path'])
        if drift and not force:
            return {'status': False, 'drift': drift,
                    'msg': 'Changed since this fix (or the backup predates v1.2): %s. '
                           'Restoring would undo those edits; confirm to restore anyway.'
                           % ', '.join(drift)}

        sudo_touched = any(_is_sudoers(e['path']) for e, _s in files)
        ssh_touched = any(e['path'].startswith('/etc/ssh/') for e, _s in files)
        if _live() and sudo_touched and not _bin('visudo'):
            return {'status': False, 'msg': 'visudo not found; sudoers is never restored '
                                            'without validation.'}
        if _live() and ssh_touched and not _bin('sshd'):
            return {'status': False, 'msg': 'sshd not found; sshd_config is never restored '
                                            'without "sshd -t".'}

        current, staged = {}, {}
        try:
            for entry, src in files:
                path = entry['path']
                if not os.path.isdir(os.path.dirname(_path(path))):
                    continue
                with open(src, 'rb') as f:
                    content = f.read()
                current[path] = _read_bytes(path)
                tmp = _stage(path, content)
                staged[path] = tmp
                if entry.get('mode') is not None:
                    os.chmod(tmp, entry['mode'])
                if _live() and _is_sudoers(path):
                    out, ok = _run_bin('visudo', '-c', '-f', tmp)
                    if not ok:
                        raise FixError('visudo rejected the backup of %s: %s'
                                       % (path, out.strip()[:300] or 'unknown error'))
                if _live() and path.startswith('/etc/ssh/'):
                    out, ok = _run_bin('sshd', '-t', '-f', tmp)
                    if not ok:
                        raise FixError('"sshd -t" rejected the backup of %s: %s'
                                       % (path, out.strip()[:300] or 'unknown error'))
        except (FixError, IOError, OSError) as exc:
            for tmp in staged.values():
                _discard(tmp)
            return {'status': False, 'msg': 'Nothing was restored: %s' % exc}

        restored = []
        try:
            for path, tmp in staged.items():
                _commit(tmp, path)
                restored.append(path)
            if _live() and sudo_touched:
                out, ok = _run_bin('visudo', '-c', '-f', _path('/etc/sudoers'))
                if not ok:
                    raise FixError('sudoers validation failed: %s' % out.strip()[:300])
            if _live() and ssh_touched:
                out, ok = _run_bin('sshd', '-t')
                if not ok:
                    raise FixError('"sshd -t" failed: %s' % out.strip()[:300])
        except (FixError, IOError, OSError) as exc:
            for path in restored:
                if current.get(path) is None:
                    try:
                        os.remove(_path(path))
                    except OSError:
                        pass
                else:
                    _write(path, current[path])
            for path, tmp in staged.items():
                if path not in restored:
                    _discard(tmp)
            return {'status': False, 'msg': 'Rolled back, restore failed: %s' % exc}

        for m in modes:
            dst = _path(m['path'])
            if not os.path.isfile(dst):
                continue
            try:
                os.chmod(dst, m['mode'])
                if m.get('uid') not in (None, 0) and hasattr(os, 'chown'):
                    os.chown(dst, m['uid'], -1)
                restored.append('%s (mode)' % m['path'])
            except (OSError, IOError) as exc:
                return {'status': False, 'msg': 'chmod failed on %s: %s'
                        % (m['path'], exc)}

        changes = ['Restored ' + ', '.join(restored)]
        if _live() and ssh_touched:
            svc = _reload_sshd()
            changes.append('Reloaded %s' % svc if svc else
                           'Reload sshd manually: the automatic reload failed')
        _log({'id': data.get('risk', ''), 'title': 'Restore %s' % bid, 'ok': True,
              'changes': changes, 'backup': ''})
        return {'status': True, 'msg': 'Restored %d file(s).' % len(restored),
                'changes': changes}


# CLI entry point: `python securityrisk_main.py scan` for quick server checks
if __name__ == '__main__':
    cmd = sys.argv[1] if len(sys.argv) > 1 else 'scan'
    if cmd == 'scan':
        _items, _summary = run_checks()
        print(json.dumps({'summary': _summary, 'items': _items},
                         ensure_ascii=False, indent=2))
    elif cmd == 'fix' and len(sys.argv) > 2 and sys.argv[2] in FIXERS:
        # the operator typed the id on the server, which is the confirmation
        print(json.dumps(securityrisk_main().fix({'id': sys.argv[2], 'confirm': '1'}),
                         ensure_ascii=False, indent=2))
    else:
        print('usage: securityrisk_main.py [scan|fix <%s>]' % '|'.join(sorted(FIXERS)))
