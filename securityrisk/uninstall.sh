#!/bin/bash
# Uninstaller for the "Security Risk" aaPanel plugin.
#
# By default the fix log and the file backups under data/ are KEPT, so an
# accidental uninstall never destroys the copy of your original sudoers/profile.
# Run "bash uninstall.sh --purge" to delete them as well.

PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

plugin_path="$(cd "$(dirname "$0")" && pwd)"

case "${plugin_path}" in
    /www/server/panel/plugin/*) ;;
    *)
        echo "Refusing to run outside the panel plugin directory: ${plugin_path}"
        exit 1
        ;;
esac

find "${plugin_path}" -name "*.pyc" -delete 2>/dev/null

if [ "$1" = "--purge" ]; then
    rm -rf "${plugin_path}/data"
    echo "Removed fix log and backups."
else
    echo "Kept ${plugin_path}/data (fix log + backups). Use --purge to delete it."
fi

echo 'Successify'
