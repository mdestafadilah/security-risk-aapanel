#!/bin/bash
# aaPanel third-party plugin installer for "Security Risk".
# The panel copies the plugin directory to /www/server/panel/plugin/securityrisk
# and runs this script from inside that directory.

PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

plugin_path="$(cd "$(dirname "$0")" && pwd)"

echo "Installing Security Risk into ${plugin_path}"

# data/ holds fix logs and file backups, so it must exist before the first fix
if [ ! -d "${plugin_path}/data/backup" ]; then
    mkdir -p "${plugin_path}/data/backup"
fi
chmod 700 "${plugin_path}/data" 2>/dev/null
chmod 700 "${plugin_path}/data/backup" 2>/dev/null

chmod 644 "${plugin_path}/securityrisk_main.py" 2>/dev/null
chmod 644 "${plugin_path}/index.html" 2>/dev/null
chmod 644 "${plugin_path}/info.json" 2>/dev/null
chmod +x "${plugin_path}"/*.sh 2>/dev/null

find "${plugin_path}" -name "*.pyc" -delete 2>/dev/null

# report the distribution so the install log shows which rule set will be used
if [ -f /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    echo "Detected OS: ${PRETTY_NAME:-${NAME:-unknown} ${VERSION_ID:-}} (id=${ID:-unknown})"
fi

# the panel imports the plugin with python3; make the requirement visible early
if command -v python3 >/dev/null 2>&1; then
    python3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 6) else 1)" \
        && echo "python3 $(python3 -V 2>&1 | awk '{print $2}') detected" \
        || echo "WARNING: python3 >= 3.6 is required by this plugin"
fi

echo "Security Risk installed."
echo 'Successify'
