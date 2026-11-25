#!/usr/bin/env python
# coding: utf-8
"""
Build a static preview of index.html with a mocked panel backend.

The real page talks to /plugin?action=a&name=securityrisk&s=<method>; this script
injects a fetch() shim with fixture data so the layout can be reviewed (and
screenshotted) without an aaPanel server.

    python tools/make_preview.py
"""

import io
import os

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SRC = os.path.join(ROOT, 'securityrisk', 'index.html')
OUT_DIR = os.path.join(ROOT, 'preview')
OUT = os.path.join(OUT_DIR, 'index.html')

MOCK = r"""
<script>
/* ---- preview shim: answers the plugin API with fixture data ---- */
(function () {
  var ITEMS = [
    {id:'cli_timeout', title:'No command line timeout is configured for exit', level:'medium',
     status:'risk', fixable:true, danger:false,
     detail:'TMOUT is not defined in /etc/profile, /etc/profile.d/*.sh or /etc/bash.bashrc, so an idle root shell never expires.',
     solution:'Add TMOUT=300 (readonly, exported) to /etc/profile, then re-login or run "source /etc/profile". Keep the value at 600 seconds or less.',
     plan:['Append "TMOUT=300" + "readonly TMOUT" + "export TMOUT" to /etc/profile',
           'Back up /etc/profile before writing',
           'Re-run this check to confirm the value is picked up'],
     commands:[]},
    {id:'sudo_nopasswd', title:'The following sudo files contain the NOPASSWD flag: /etc/sudoers, /etc/sudoers.d/90-cloud-init-users',
     level:'medium', status:'risk', fixable:true, danger:false,
     detail:'Passwordless sudo is allowed by 3 rule(s): /etc/sudoers, /etc/sudoers.d/90-cloud-init-users',
     solution:'Comment out or remove the NOPASSWD marker in the listed files. Sudo will then ask for the user password again. Validate with "visudo -c". On this distribution the admin group is "%sudo", so keep the group rule and drop only the NOPASSWD part.',
     plan:['Back up /etc/sudoers, /etc/sudoers.d/90-cloud-init-users',
           'Comment out every line that contains NOPASSWD:',
           'Validate the result with "visudo -c" and roll back if it fails',
           '  /etc/sudoers:4  %sudo ALL=(ALL:ALL) NOPASSWD: ALL',
           '  /etc/sudoers:5  bob ALL=(ALL) NOPASSWD: ALL, PASSWD: /bin/ls',
           '  /etc/sudoers.d/90-cloud-init-users:1  cloud-init ALL=(ALL) NOPASSWD: ALL'],
     commands:[],
     rules:[{file:'/etc/sudoers', line:4, text:'%sudo ALL=(ALL:ALL) NOPASSWD: ALL'},
            {file:'/etc/sudoers', line:5, text:'bob ALL=(ALL) NOPASSWD: ALL, \\'},
            {file:'/etc/sudoers.d/90-cloud-init-users', line:1, text:'cloud-init ALL=(ALL) NOPASSWD: ALL'}]},
    {id:'ssh_password_auth', title:'SSH accepts password authentication', level:'medium',
     status:'risk', fixable:true, danger:true,
     detail:'PasswordAuthentication yes (from /etc/ssh/sshd_config). Brute-force attacks against passwords are the most common way servers get compromised.',
     solution:'Disable password login once every admin uses a key: "PasswordAuthentication no", then reload sshd.',
     plan:['Back up /etc/ssh/sshd_config','Set PasswordAuthentication no',
           'Validate with "sshd -t", reload sshd, roll back on failure',
           'Make sure you have a working SSH key before confirming'], commands:[]},
    {id:'ssh_root_login', title:'SSH allows direct root login', level:'medium', status:'risk',
     fixable:true, danger:false,
     detail:'PermitRootLogin yes (from /etc/ssh/sshd_config).',
     solution:'Set "PermitRootLogin prohibit-password" so root can only log in with a key, then run "sshd -t" and reload sshd.',
     plan:['Back up /etc/ssh/sshd_config','Set PermitRootLogin prohibit-password',
           'Validate with "sshd -t", reload sshd, roll back on failure'], commands:[]},
    {id:'firewall', title:'No host firewall is enabled', level:'medium', status:'risk',
     fixable:false, danger:false,
     platform:'Debian / Ubuntu',
     detail:'Neither ufw nor any other packet filter was found active on Ubuntu 22.04.4 LTS.',
     solution:'Enable ufw (the firewall Debian / Ubuntu ships with) and allow only the ports you actually use: SSH, the panel port 8888, and HTTP/HTTPS if you serve sites.',
     plan:[],
     commands:['ufw allow 22/tcp','ufw allow 8888/tcp','ufw --force enable','ufw status verbose']},
    {id:'fail2ban', title:'Fail2ban is not protecting the server', level:'medium', status:'risk',
     fixable:false, danger:false,
     platform:'Debian / Ubuntu',
     detail:'No fail2ban jail was detected, so repeated login failures are never blocked at the IP level.',
     solution:'Install fail2ban and enable the sshd jail. aaPanel also ships an SSH brute-force protection module you can use instead.',
     plan:[], commands:['apt-get update && apt-get install -y fail2ban',
                        'systemctl enable --now fail2ban','fail2ban-client status sshd']},
    {id:'apparmor', title:'AppArmor is enabled', level:'low', status:'ok',
     fixable:false, danger:false, platform:'Debian / Ubuntu',
     detail:'The kernel AppArmor module is active on Ubuntu 22.04.4 LTS.',
     solution:'No action needed.', plan:[], commands:[]},
    {id:'file_permissions', title:'Sensitive system files have safe permissions', level:'low',
     status:'ok', fixable:false, danger:false,
     detail:'All checked files are at or below their maximum allowed mode.',
     solution:'No action needed.', plan:[], commands:[]},
    {id:'empty_password', title:'No account has an empty password', level:'low', status:'ok',
     fixable:false, danger:false,
     detail:'Every entry in /etc/shadow has a password hash or a lock marker.',
     solution:'No action needed.', plan:[], commands:[]},
    {id:'panel_ssl', title:'The panel is served over HTTPS', level:'low', status:'ok',
     fixable:false, danger:false,
     detail:'Panel SSL marker /www/server/panel/data/ssl.pl is present.',
     solution:'No action needed.', plan:[], commands:[]}
  ];

  var HISTORY = [
    {time: Math.floor(Date.now()/1000) - 180, id:'sudo_nopasswd',
     title:'The following sudo files contain the NOPASSWD flag', ok:true,
     changes:['Commented out 3 line(s) in /etc/sudoers',
              'Commented out 1 line(s) in /etc/sudoers.d/90-cloud-init-users'],
     backup:'20261125-095512-sudo_nopasswd'},
    {time: Math.floor(Date.now()/1000) - 900, id:'ssh_root_login',
     title:'SSH allows direct root login', ok:true,
     changes:['Set PermitRootLogin prohibit-password in /etc/ssh/sshd_config','Reloaded sshd'],
     backup:'20261125-094102-ssh_permitrootlogin'},
    {time: Math.floor(Date.now()/1000) - 3600, id:'cli_timeout',
     title:'No command line timeout is configured for exit', ok:false,
     msg:'Rolled back, validation failed: /etc/profile: permission denied',
     changes:[], backup:''}
  ];

  function payload(method) {
    if (method === 'get_history') return {status:true, items: HISTORY};
    if (method === 'fix') {
      var copy = JSON.parse(JSON.stringify(ITEMS[0]));
      copy.status = 'ok'; copy.title = 'Command line timeout is configured';
      copy.detail = 'TMOUT=300 (at /etc/profile:31).'; copy.fixable = false; copy.plan = [];
      return {status:true, msg:'Applied 1 change(s).', item: copy,
              changes:['Appended TMOUT=300 block to /etc/profile'],
              backup:'20261125-100001-cli_timeout'};
    }
    if (method === 'restore') return {status:true, msg:'Restored 1 file(s).'};
    return {
      status:true, items: ITEMS, scan_time: Math.floor(Date.now()/1000),
      summary:{total:10, risk:6, ok:4, unknown:0, fixable:4, high:0, medium:6, low:0},
      system:{hostname:'srv-jkt-01', os:'Ubuntu 22.04.4 LTS', os_id:'ubuntu',
              os_name:'Ubuntu', os_version:'22.04', family:'debian',
              family_label:'Debian / Ubuntu', pkg:'apt-get', firewall:'ufw',
              ssh_service:'ssh', sudo_group:'sudo', mac:'AppArmor',
              panel_port:'8888', kernel:'5.15.0-119-generic'},
      last_fix: HISTORY[0]
    };
  }

  window.fetch = function (url) {
    var m = /s=([a-z_]+)/.exec(url || '');
    var body = JSON.stringify(payload(m ? m[1] : 'get_index'));
    return new Promise(function (resolve) {
      setTimeout(function () {
        resolve({ok: true, status: 200, text: function () { return Promise.resolve(body); }});
      }, 260);
    });
  };
})();
</script>
"""


def main():
    with io.open(SRC, 'r', encoding='utf-8') as f:
        html = f.read()
    marker = '<div id="toasts"></div>'
    if marker not in html:
        raise SystemExit('anchor not found in index.html')
    html = html.replace(marker, marker + '\n' + MOCK, 1)
    if not os.path.isdir(OUT_DIR):
        os.makedirs(OUT_DIR)
    with io.open(OUT, 'w', encoding='utf-8', newline='\n') as f:
        f.write(html)
    print('wrote %s' % OUT)


if __name__ == '__main__':
    main()
