# Security Risk — plugin aaPanel

Plugin pihak ketiga untuk aaPanel yang memindai *hardening* server, menampilkan
daftar temuan (seperti **"No command line timeout is configured for exit"** dan
**"sudo files contain the NOPASSWD flag"**), lalu menyediakan tombol **Resolve**
untuk memperbaikinya langsung dari panel.

Dokumentasi plugin yang dipakai sebagai acuan: `aaPanel Linux Panel Plug-in
development documentation v1.1` (struktur file, `info.json`, kelas
`<nama>_main`, route `/plugin?action=a&name=<nama>&s=<method>`, dan `public`).

```
securityrisk/
├── securityrisk_main.py   # backend: rule engine + fix engine
├── index.html             # frontend: daftar risiko, tombol Resolve, riwayat
├── info.json              # metadata plugin (name harus = nama folder)
├── icon.png               # 128x128
├── install.sh             # dipanggil panel saat instalasi
└── uninstall.sh           # pembersihan (backup dipertahankan kecuali --purge)
```

## Cara kerja

1. **Scan** — `index.html` memanggil `POST /plugin?action=a&name=securityrisk&s=get_index`.
   Backend mendeteksi distribusi lebih dulu, lalu menjalankan 10 pemeriksaan
   langsung terhadap kondisi server (`/etc/profile`, `/etc/sudoers*`,
   `/etc/ssh/sshd_config`, `/etc/shadow`, dst).
2. **List** — setiap temuan dikembalikan sebagai objek: `title`, `level`
   (`high|medium|low`), `status` (`risk|ok|unknown`), `detail`, `solution`,
   `fixable`, `plan` (daftar perubahan yang akan dilakukan), dan `rules`
   (baris file yang bermasalah).
3. **Resolve** — tombol membuka dialog konfirmasi berisi rencana perubahan,
   lalu memanggil `s=fix` dengan `id` temuan.

Plugin **tidak** membaca cache hasil "Security Risk" bawaan panel — ia
memeriksa sendiri kondisi file sistem. Konsekuensinya hasil selalu real-time
dan tombol Resolve benar-benar bisa mengeksekusi perbaikan, bukan sekadar
menampilkan teks saran.

## Dukungan distribusi

OS dibaca dari `/etc/os-release` (fallback: `/etc/redhat-release`,
`/etc/rocky-release`, `/etc/almalinux-release`, `/etc/centos-release`,
`/etc/debian_version`), lalu dipetakan ke satu *family*. Profilnya dipakai
untuk semua yang berbeda antar distro, bukan hanya ditampilkan:

| Family | Distro yang dikenali | Paket | Firewall | Unit SSH | Grup admin | MAC |
|---|---|---|---|---|---|---|
| `debian` | Debian, Ubuntu, Mint, Kali, Raspbian, Pop!_OS | `apt-get` | `ufw` | `ssh` | `%sudo` | AppArmor |
| `rhel` | RHEL, **Rocky Linux**, AlmaLinux, CentOS, Fedora, Oracle, Amazon | `dnf` (fallback `yum`) | `firewalld` | `sshd` | `%wheel` | SELinux |
| `suse` | openSUSE, SLES | `zypper` | `firewalld` | `sshd` | `%wheel` | AppArmor |
| `alpine` | Alpine | `apk` | `awall` | `sshd` | `%wheel` | — |
| `arch` | Arch, Manjaro | `pacman` | `nftables` | `sshd` | `%wheel` | AppArmor |
| `unknown` | distro lain / container minimal | — | saran `iptables` | `sshd` | `%wheel` | — |

Yang ikut menyesuaikan:

- **Perintah firewall** memakai backend distro (ufw vs `firewall-cmd` vs
  `iptables`) dan **port panel asli** dari `/www/server/panel/data/port.pl`,
  bukan 8888 hard-code.
- **Instalasi fail2ban** memakai paket manager yang ada; di RHEL/Rocky
  ditambahkan `dnf install -y epel-release` lebih dulu karena fail2ban ada di EPEL.
- **Reload SSH** memakai unit yang benar (`ssh` di Debian/Ubuntu, `sshd` di RHEL).
- **Saran sudo** menyebut grup admin distro (`%sudo` atau `%wheel`).
- **Pemeriksaan MAC** hanya muncul bila relevan: `selinux` di family RHEL,
  `apparmor` di Debian/SUSE. Di distro lain keduanya dilewati, bukan
  dilaporkan sebagai "unknown".
- Nama OS, family, paket, firewall, dan grup admin tampil sebagai pill di
  header UI; temuan yang khas distro diberi badge platform.

### Pengamanan setiap perbaikan

| Langkah | Detail |
|---|---|
| Backup | Semua file yang disentuh disalin ke `data/backup/<waktu>-<id>/` sebelum ditulis, lengkap dengan `manifest.json` (path asli + mode). `/etc/shadow` dan `/etc/gshadow` **tidak pernah** disalin: fix akun hanya mencatat nama akun. |
| Tulis | Isi baru ditulis ke file sementara di direktori yang sama (fsync), diberi owner, mode, dan label SELinux file asli, lalu menggantikan file asli secara atomik (`os.replace`). Disk penuh atau proses mati tidak bisa meninggalkan sudoers/sshd_config kosong. |
| Validasi | File sementara divalidasi **sebelum** menyentuh file asli (`visudo -cf <tmp>`, `sshd -t -f <tmp>`), lalu konfigurasi lengkap divalidasi lagi (`visudo -cf /etc/sudoers`, `sshd -t`). |
| Exit code | Perintah dijalankan lewat `subprocess` dengan daftar argumen (tanpa shell), `LC_ALL=C`, batas waktu, dan **exit code asli**. `public.ExecShell` sengaja tidak dipakai karena tidak mengembalikan exit code, sehingga validator selalu terlihat berhasil. |
| Rollback | Jika validasi gagal, isi file dikembalikan dan API mengembalikan `status:false` beserta pesan aslinya. Untuk SSH, nilai efektif dicek **sebelum** reload, jadi rollback tidak pernah meninggalkan daemon dengan config berbeda. |
| Verifikasi | Pemeriksaan dijalankan ulang; UI menampilkan status baru, bukan asumsi "berhasil". `passwd -l` dianggap berhasil hanya jika `/etc/shadow` benar-benar berubah. |
| Riwayat | Setiap aksi dicatat di `data/fix.log` (JSON lines) dan bisa di-*restore* dari panel. Backup dipangkas otomatis ke 40 terbaru. |
| Restore | Backup divalidasi dulu (`visudo`/`sshd -t`) dan sshd di-reload sesudahnya. Jika file sudah diubah lagi setelah fix (hash disimpan saat fix), restore ditolak kecuali dikonfirmasi (`force=1`). Akun yang dikunci tidak pernah dibuka lewat restore. |

## Daftar pemeriksaan

11 aturan total, 10 dijalankan pada satu server (selinux *atau* apparmor).

| id | Temuan | Level | Aksi |
|---|---|---|---|
| `cli_timeout` | `TMOUT` tidak diset / > 600 detik | medium | **Auto** — menambah `TMOUT=300`, `readonly TMOUT`, `export TMOUT` ke `/etc/profile` (atau memperbaiki nilai yang ada) |
| `sudo_nopasswd` | Ada `NOPASSWD:` di `/etc/sudoers` atau `/etc/sudoers.d/*` | medium | **Auto** — hanya tag `NOPASSWD:` yang dihapus, rule-nya tetap. Rule yang usernya tidak punya password (mis. `ubuntu`/`ec2-user` di image cloud), alias, atau `ALL` **dilewati** supaya tidak kehilangan akses sudo |
| `ssh_root_login` | `PermitRootLogin yes` | medium | **Auto** — diubah ke `prohibit-password`, `sshd -t`, reload sshd |
| `ssh_password_auth` | `PasswordAuthentication yes` | medium | **Auto (berisiko)** — diubah ke `no`; backend menolak tanpa `confirm=1` (UI: centang konfirmasi) karena bisa mengunci login |
| `file_permissions` | `/etc/shadow`, `/etc/sudoers`, dll. terlalu terbuka atau bukan milik root | high/medium | **Auto** — hanya bit berlebih yang dicabut, owner dikembalikan ke root. `0640 root:shadow` (bawaan Debian/Ubuntu untuk `unix_chkpwd`) diterima |
| `empty_password` | Akun di `/etc/shadow` tanpa hash | high | **Auto** — `passwd -l <user>`, lalu `/etc/shadow` dibaca ulang untuk memastikan |
| `firewall` | Tidak ada ufw/firewalld/iptables aktif | medium | Manual — perintah backend firewall distro ditampilkan untuk dicopy |
| `fail2ban` | Tidak terpasang / tidak jalan | medium | Manual — perintah instalasi sesuai paket manager (RHEL: EPEL dulu) |
| `selinux` | SELinux *permissive*/*disabled* (khusus RHEL family) | medium | Manual — `setenforce 1`; untuk `disabled` butuh reboot + relabel |
| `apparmor` | AppArmor tidak aktif (khusus Debian/SUSE) | low | Manual — install + `systemctl enable --now apparmor` |
| `panel_ssl` | Panel belum HTTPS (`ssl.pl` tidak ada) | low | Manual — arahkan ke Panel Settings |

Aturan severity mengikuti sumber temuan: `NOPASSWD` dan timeout CLI = *medium*,
sama seperti daftar Security Risk aaPanel. Permission `/etc/shadow` dan akun
tanpa password dinaikkan ke *high*.

## Endpoint (semua POST)

```bash
# scan penuh
curl -s -X POST 'http://SERVER:8888/plugin?action=a&name=securityrisk&s=get_index'

# perbaiki satu temuan
curl -s -X POST 'http://SERVER:8888/plugin?action=a&name=securityrisk&s=fix' -d 'id=sudo_nopasswd'
curl -s -X POST 'http://SERVER:8888/plugin?action=a&name=securityrisk&s=fix' -d 'id=ssh_password_auth&confirm=1'

# riwayat perbaikan
curl -s -X POST 'http://SERVER:8888/plugin?action=a&name=securityrisk&s=get_history'

# daftar backup + restore
curl -s -X POST 'http://SERVER:8888/plugin?action=a&name=securityrisk&s=list_backups'
curl -s -X POST 'http://SERVER:8888/plugin?action=a&name=securityrisk&s=restore' -d 'backup=20261125-095512-sudo_nopasswd'
```

`restore` menolak `backup` yang tidak cocok dengan pola id (anti path
traversal), mengabaikan entri manifest di luar `/etc/` atau di luar folder
backup-nya, dan mengembalikan `drift` bila file sudah berubah sejak fix (kirim
ulang dengan `force=1` untuk tetap menimpa). Nama parameter `action`, `s`, `name`, `a` tidak dipakai di body,
sesuai catatan dokumentasi.

**Kontrol akses.** Semua request dari UI lewat router `/plugin?action=...` yang
mewarisi session panel. Route pintas `/{plugin}/{method}.json` yang dijelaskan
dokumentasi *tidak* mewarisi session, jadi kelas plugin mendefinisikan
`_check()` yang hanya mengizinkan request dengan session panel aktif — tanpa
itu siapa pun bisa memanggil `fix` dan mengubah `/etc/sudoers` tanpa login.
`SECRISK_ALLOW_ANON=1` hanya berlaku bila `SECRISK_SYSROOT` juga diset (mode uji),
jadi tidak bisa membuka server sungguhan.

**CSRF.** UI mengirim token panel (`x-http-token` + `request_token`). Selain itu
`fix` dan `restore` menolak request browser yang `Origin`/`Referer`-nya bukan
host panel (termasuk `X-Forwarded-Host` bila di belakang reverse proxy).

## Instalasi

Manual (paling mudah untuk pengembangan):

```bash
cd /www/server/panel/plugin
unzip securityrisk.zip          # menghasilkan folder securityrisk/
bash securityrisk/install.sh
bt restart                      # atau: /etc/init.d/bt restart
```

Setelah restart, plugin muncul di daftar plugin panel. Jika ingin memasang dari
file zip lewat UI, unggah `dist/securityrisk.zip` pada menu plugin pihak ketiga
(aaPanel memanggil `install.sh` otomatis dan mengharapkan output `Successify`).

Syarat: Python 3.6+ (bawaan panel), dijalankan sebagai root — beberapa
pemeriksaan (`/etc/shadow`, `sshd -T`, `visudo`) memerlukannya. Bila bukan root,
item terkait akan tampil `unknown`, bukan gagal.

## Uji lokal

Rule engine tidak bergantung pada path absolut, sehingga bisa diuji di mesin
pengembang dengan `SECRISK_SYSROOT`:

```bash
python tests/test_local.py     # 133 assertion: deteksi, fix, validator, backup, restore, profil OS
python tools/make_preview.py   # preview/index.html + data contoh untuk review UI
```

Hasil uji terakhir: **133 passed, 0 failed** — mencakup deteksi awal, penulisan
`TMOUT`, penghapusan tag `NOPASSWD` (termasuk baris lanjutan `\`) dan rule
yang dilewati, validator berbasis exit code, rollback, penguncian akun,
penulisan ulang sshd_config (termasuk saat nilainya berasal dari
`sshd_config.d`), aturan permission, riwayat, restore byte-for-byte, plus tiga
fixture distro:

| Fixture | Yang diverifikasi |
|---|---|
| Ubuntu 22.04 | family `debian`, `apt-get`, `ufw`, unit `ssh`, `%sudo`, AppArmor aktif, perintah firewall memakai port panel 8888 |
| Rocky Linux 9.4 | family `rhel`, `dnf`, `firewalld`, unit `sshd`, `%wheel`, SELinux *enforcing* = ok, fail2ban lewat EPEL, port panel 12345 |
| tanpa os-release | fallback `Generic Linux`, tanpa cek SELinux/AppArmor, saran `iptables` |

## Catatan

- Sumber aaPanel menulis `tmout=300`, padahal variabel shell-nya **`TMOUT`**
  (huruf besar, case-sensitive). Plugin memakai `TMOUT` — dengan `tmout` biasa
  nilainya hanya jadi variabel shell sementara dan tidak pernah berlaku.
- Perubahan `/etc/profile` hanya berlaku pada shell login baru. Sesi yang sedang
  terbuka tetap tanpa timeout sampai login ulang.
- `ssh_password_auth` bisa mengunci Anda jika belum punya SSH key yang bekerja.
  Uji login key di sesi kedua sebelum menekan Resolve; konfigurasi divalidasi
  `sshd -t` dan di-rollback bila ditolak.
- Perbaikan firewall dan fail2ban sengaja manual: port yang dibuka berbeda di
  setiap server, dan menebak bisa memutus akses panel.
- Backup **tidak** dihapus saat uninstall (kecuali `bash uninstall.sh --purge`).
