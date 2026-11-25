#!/usr/bin/env python
# coding: utf-8
"""
Package src/ as dist/securityrisk.zip for the aaPanel plugin installer.

The source lives in src/, but the panel requires the folder inside the zip to
match the plugin name in info.json ("securityrisk"), so files are stored under
that name instead.

    python tools/make_zip.py
"""

import io
import os
import json
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SRC = os.path.join(ROOT, 'src')
DIST = os.path.join(ROOT, 'dist')

FILES = ['securityrisk_main.py', 'index.html', 'info.json', 'icon.png',
         'install.sh', 'uninstall.sh']


def main():
    with io.open(os.path.join(SRC, 'info.json'), encoding='utf-8') as f:
        name = json.load(f)['name']
    if not os.path.isdir(DIST):
        os.makedirs(DIST)
    out = os.path.join(DIST, '%s.zip' % name)
    with zipfile.ZipFile(out, 'w', zipfile.ZIP_DEFLATED) as z:
        for rel in FILES:
            z.write(os.path.join(SRC, rel), '%s/%s' % (name, rel))
    print('wrote %s' % out)


if __name__ == '__main__':
    main()
