# 83 Grooti — writeup

**Target:** `172.17.0.8` — **Ubuntu 24.04.2 LTS (noble)**, Apache **2.4.58-1ubuntu8.7**,
OpenSSH **9.6p1-3ubuntu13.12**, MySQL **8.0.42-0ubuntu0.24.04.2**, PHP **8.3.6**,
sudo 1.9.15p5, cron 3.0pl1. Three listening TCP ports: **22, 80, 3306**. No UDP.
**Result:** unauthenticated HTTP → SSH `uid=1001(grooti)` → **`Uid: 0 0 0 0`**.
**Reward:** `/root/grooti.txt`, 1005 bytes, ASCII art — **there is no `FLAG{}` in this
lab** (§10, with the search and its counts).

**Full catalogue description** (the queue's fourth field, read whole rather than truncated):

> *"Enumeración de directorios web, bases de datos y escalada de privilegios en linux."*

**Topology.** `auto_deploy.sh` was read, never run. One container, default bridge, no custom
network, no macvlan, no second host (`auto_deploy.sh:131`; the `while true` is at `:145`).
The engagement is single-host and stayed single-host. Note `:46` — the script would `docker
stop` and `docker rm` **any** container whose id starts `5938*`, i.e. it reaches outside this
lab. Another reason never to run it.

---

## 0. The headline

**The queue label is correct about the class and wrong about the route.** Three things invert
the obvious reading of this lab:

1. **The catalogue's *escalation de privilegios* claim is true, but its *base de datos*
   claim is unreachable, and the escalation is not where either the artefact or the hint
   points.** The database is advertised by `secret/instrucciones.txt` and it cannot be
   entered: the client the image ships rejects the flag the hint tells you to use, the host
   in the hint is stale, and **no artefact in the image carries `rocket`'s password**. The
   real chain never touches the database. Full accounting in §5 and §6/D1.
2. **A second, subtler misattribution inside the artefact: `grooti`'s own crontab is a decoy
   that can never fire.** Both `root`'s and `grooti`'s crontabs run `/opt/cleanup.sh`, and
   `/opt/cleanup.sh` is `-rwxr-xr-- root:root` — other bits are `r`, **no `x`**. Measured as
   `grooti`: `rc=126, Permission denied`, which is exactly what cron does. A tester who reads
   the crontab files concludes there are two routes; there is one. §6/D2.
3. **The enumeration lesson the queue asked for: fifteen surfaces (E1–E15), 1 525
   non-mutation application-level probes across three units, one account, and every row
   with a positive control, a negative control and a work count** — plus a **second instance
   of lab 188's absent-file trap, with the phantoms counted** (§2, §11.1).

And the finding that decides the engagement is not on any service. It is a **36-byte
root-owned script whose payload path is group-writable by the account you log in as** — and
`root`'s crontab executes it once a minute. §6/F7.

---

## 1. Surface

```
$ nmap -sV -Pn -p- --version-all 172.17.0.8
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.12 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.58 ((Ubuntu))
3306/tcp open  mysql   MySQL 8.0.42-0ubuntu0.24.04.2
Not shown: 65532 closed tcp ports (conn-refused)
```

**Cross-check: the scan and the kernel agree, independently.** The container has no `ss` and
no `netstat`, so the socket list came from `/proc`:

```
$ cat /proc/net/tcp          # 4 listener rows
   0: 00000000:0050 ...  0x50   = 80
   1: 00000000:0016 ...  0x16   = 22
   2: 00000000:0CEA ...  0xCEA  = 3306   uid 102 (mysql)
   3: 0100007F:8124 ...  0x8124 = 33060  uid 102 (mysqlx, loopback only)
$ cat /proc/net/tcp6         # 1 listener row: ::0016 = 22 (the same socket, v6)
$ cat /proc/net/udp          # header only
$ cat /proc/net/udp6         # header only
```

Union = **3 remote TCP ports**, matching `-p-` exactly. `0xCEA = 3306` and
`0x8124 = 33060` **computed, not read**. The two UDP files are **1 line each and that line
is the header** — a blank and a header look identical in a report, so the count is printed.

**What a TCP scan cannot see — measured, with the work count:**

| Check | Result | Work count |
|---|---|---|
| `/proc/net/udp` | header only | **0** socket lines (1 line total) |
| `/proc/net/udp6` | header only | **0** socket lines (1 line total) |
| `docker inspect … .Config.ExposedPorts` | `{"22/tcp":{},"80/tcp":{},"3306/tcp":{}}` | 1 image |
| `/proc/net/tcp` + `tcp6` | 4 + 1 listener rows | **5** rows |
| `getcap -r /` | empty | **0** lines |
| `find / -xdev \( -perm -4000 -o -perm -2000 \)` | stock Ubuntu set | **16** binaries |
| `/etc/cron.d/` + `/var/spool/cron/crontabs/` | 2 system fragments + **2 user crontabs** | **4** job files |
| `docker history --no-trunc` | 19 layers, **no plaintext credential** | 19 layers read whole |

Note the last row: lab 188's decisive finding was a `chpasswd` in the build record. **Here
there is no such layer**, and that negative is scoped — I read all 19 layers, not a summary.

### 1.1 Stack and versions — from the artefact, not from the banner

| Layer | Finding | Source |
|---|---|---|
| OS | **Ubuntu 24.04.2 LTS (noble)** | `/etc/os-release` `VERSION="24.04.2 LTS (Noble Numbat)"` |
| Web | **Apache httpd 2.4.58-1ubuntu8.7**, `DocumentRoot /var/www/html`, one vhost, no `Alias`, no `Rewrite` | `dpkg-query`; `sites-enabled/000-default.conf` |
| App | **PHP 8.3.6** under a **global** handler: `mods-enabled/php8.3.conf:1-2` `<FilesMatch ".+\.ph(?:ar\|p\|tml)$"> SetHandler application/x-httpd-php` | `php -v`; `php8.3.conf` |
| PHP write sinks | 2 files, `generate.php` and `download.php`, both POST-only | `find /var/www/html -name '*.php'` → 2 |
| SSH | **OpenSSH 9.6p1 Ubuntu-3ubuntu13.12**, OpenSSL 3.0.13 | `/usr/sbin/sshd -V` |
| DB | **MySQL 8.0.42**, **`bind-address = 0.0.0.0`** | `mysqld.cnf:31` |
| Accounts | **`grooti` (uid 1001) is the only account with a login shell and a real password hash.** `ubuntu` (1000) is locked (`!`), `root` is `*` | `/etc/passwd`, `/etc/shadow` |
| Hash | **yescrypt** `$y$j9T$…` for `grooti`; `!` for every system account | `/etc/shadow` |
| sudo | default only: `root ALL=(ALL:ALL) ALL`, `%sudo ALL=(ALL:ALL) ALL`; **`/etc/sudoers.d/` contains 1 file (`README`)**. `grooti` is **not** in `sudo` | `/etc/sudoers` |
| Capabilities | none (`getcap -r /` → 0 lines) | `getcap` |
| SUID | 16, all stock Ubuntu | `find`, `stat` |
| Reward | `/root/grooti.txt`, **1005 B**, `0644 root:root`, inside `/root` `0700` | `ls`, `wc -c`, `md5sum` |

**The `grooti` account is the whole target surface, and the artefact says so once, quietly.**
`/etc/shadow` has exactly one non-`!`, non-`*` field:

```
grooti:$y$j9T$ToV8xhw471w4Z5vt8zQ9C0$mzHXXOK0PlAFk6kIwejd4afmKkbBsGERyR3qGU8AWI.:20287:0:99999:7:::
```

`awk -F: '$3>=1000 && $7 !~ /nologin/' /etc/passwd` → **1** account, so the completeness of
every username sweep below is **verified against the artefact, not assumed** (the lab 87 /
lab 188 discipline).

### 1.2 Surfaces a status-code or label scan gets wrong here

| Surface | Naive read | Actual |
|---|---|---|
| `/documentos/` | linked from `index.html:41` as *"Mi base de datos"* | **404:272**. The link is dead. The real database page is `/secret/` |
| `/.htaccess`, `/.htpasswd`, `/.php`, `/.phar` | 403 → "protected file exists" | **403 for 8 names, 0 of which exist.** §2, E5/E6, §11.1 |
| `/server-status` | 403 → "mod_status, locked down" | correct and **provably so**: `200` / **4019 B** from `127.0.0.1`, and the same `403:275` body as the 8 phantoms |
| `/unprivate/` | the name says private | **`200`, 939 B, an autoindex listing.** §6/F1 |
| `/opt/cleanup.sh` | readable ⇒ runnable | `0754 root:root` — readable by all, **executable by nobody but root**. §6/D2 |
| `--ssl=0` (from `instrucciones.txt`) | the documented way in | `mysql: [ERROR] unknown variable 'ssl=0'`, rc=7, on the shipped 8.0.42 client |

---

## 2. The enumeration inventory

This is the deliverable the queue asked for. **Every row carries a positive control, a
negative control, and a work count, and the last column says what the surface was actually
decisive for** — because enumeration nobody acts on is reconnaissance theatre, and a surface
that produced no finding still gets its row.

| # | Surface | Positive control | Negative control | Work count | Which finding it produced |
|---|---|---|---|---|---|
| **E1** | `nmap -p-` TCP sweep | 3 open ports, each carrying a service banner | 65 532 `conn-refused` | **65 535 ports** | **The port inventory.** Cross-checked against `/proc/net/tcp`+`tcp6` (**5** listener rows, 4 unique sockets) — a second, independent instrument, same answer. **3306 was not noise**, and E13 is what made it matter |
| **E2** | UDP sweep via `/proc/net/udp{,6}` | — | — | **0** socket lines; **1** header line per file | **No UDP surface, as a measurement.** An `nmap -p-` alone could not say this (retrieval-hazards row 1) |
| **E3** | Docroot sweep, external HTTP | `/` → `200` **1436 B**; `/unprivate/secret/password16.zip` → `200` **429 B** | 2 names that **cannot exist** + 34 other absent paths → **`404:272`, one single distinct body hash** (`f2e790ff3d9a`) | **63 paths** → **22×`200`, 5×`403`, 36×`404`**; 22 URLs = **20 distinct filesystem resources** and **17 distinct bodies** | **F1, F4.** The sweep is *complete*, not lucky: the artefact independently lists **16 files + 5 directories = 21 nodes**, all 21 reachable, so the 36 negatives are evidence rather than noise. This is the `SELECT COUNT(*)` the lab 87 model asks for |
| **E4** | `autoindex` — proving E3's "no unlisted subdirectory" | **I created** `/var/www/html/lab83_probe_a/inside.txt` → `GET /lab83_probe_a/` = `200` **951 B**, body lists `inside.txt`; and an empty `/lab83_probe_b/` → `200` **753 B** with `Index of` | — (both are positive) | **2 directories created then removed, 5 GETs** | **Made E3's completeness a measurement instead of an assumption** — self-corrections §1. The control **fired twice**. And it was not academic: `/unprivate/` is itself a **live listing** (939 B), which is how the credential-serving terminal was reached without a wordlist |
| **E5** | `.ht*` name rule | `.htaccess` **created** → `403:275`, md5 `dd525d40a0e7`; **deleted** → `403:275`, **byte-identical** | `.HTACCESS`, `.Htaccess` → `404:272` — the rule is case-sensitive | **9 probes** (6 names + 3 toggle states) | **F2.** The toggle is what settles it: existence does not change the answer. **A status sweep reports 4 present files where 0 exist**, and the 4 are the highest-value names in any wordlist |
| **E6** | `.ph*` name rule (`php8.3.conf:9-10`) | same mechanism, second independent rule | `.pht`, `.php5`, `.php.bak`, `.Phar`, `.PHP` → `404:272` | **10 probes** | **F2 extended to 8 phantoms, 0 real files** (checked with `test -e` per name, all 8 absent) |
| **E7** | `server-status` attribution | **`200` / 4019 B** from `127.0.0.1` inside the container — the endpoint is real and mod_status works | `403:275` from outside, **the same md5 as all 8 E5/E6 phantoms** | **6 probes** (1 loopback GET + 3 body-hash comparisons + 2 already in E3) | **F2's second half, and it is the more useful half:** neither the status code nor the body hash can attribute a `403` to a rule. A `Require local` block and a name-based deny are **byte-identical from outside** |
| **E8** | `generate.php` / `download.php` POST matrix | `number=1` → `200` **14 B** md5 `00b0dc0ef859` = the **shipped** file (the write *fails*, the file is `root:root 0644`); `number=15/17/42` → `200` **10 B** = my own content echoed back. **Two different branches, two different byte counts** | `number=0/101/abc/empty` → `200` with an error body, **byte-identical within each endpoint** (52 B on `generate.php`, 76 B on `download.php`) | **20 requests** (2 endpoints × 9 values, + 2 GET rejections) | **F3.** Both endpoints hand out the encrypted `password16.zip` unauthenticated — and the source's own `// --- IDOR ACTIVADO en 16 ---` is **not an IDOR** (no ownership predicate, no session, both endpoints equally open). The `number=1` byte-count difference is also the **destructive** half: F8 |
| **E9** | PHP execution under the write sink | **I wrote** `/var/www/html/unprivate/secret/lab83_handler.php` → `200`, body `LAB83-HANDLER-PROOF uid=33 euid=33`, and from `/proc/self/status` of the PHP process: `Name: apache2`, `Uid: 33 33 33 33`, `CapEff: 0000000000000000` | the sink's own output: POST body `<?php echo "LAB83-RCE-"…; ?>` with `number=99` came back **verbatim, unexecuted** | **4 operations** (2 writes + 2 GETs) | **A control that HELD, with a green positive control.** The write sink **cannot choose a filename** — `generate.php:33` hard-codes `"password" . $numero . ".txt"` — so a world-executable PHP handler one suffix away is unreachable. This is the RCE question answered by measurement rather than by argument |
| **E10** | ZipCrypto self-test | the control archive is written by **`/usr/bin/zip -P`**, opened by **`/usr/bin/unzip -P`** (`rc=0`, exact bytes), **and** decrypted by my code — three implementations agree | wrong password → `rc=82` from `unzip` **and** `None` from my code | **6 assertions** | **Made E11's negative meaningful — and caught two real defects in my own primitive** before it could produce one. §11.2, §11.3 |
| **E11** | ZipCrypto candidate sweep | `password1` at candidate **1015** of 1132 | 1131 wrong candidates; **rate asserted** at **12 879/s** — a real keystream, no KDF shortcut (lab 87 §11.2's rate assertion, applied to a stream cipher) | **1 332 candidates** (1132 + 200 rate probes) | **F4 — and honestly: the sweep was redundant.** `imagenes/README.txt` had already published the password (`(password1) Encuentra donde ponerla ;)`). The crack works; the *design* is what makes it unnecessary |
| **E12** | MySQL authentication | rate ladder: 3 wrong passwords → `ERROR 1045`, 0.05 / 0.06 / 0.05 s, **no throttling** | impossible user `nosuchuser_zz_7c1e5b2a` → **byte-identical** `1045`; and local-only `debian-sys-maint` with its **real** password over TCP → **also byte-identical** `1045` | **39 attempts** (3 ladder + 1 impossible user + 1 local-only user + 34 candidates) | **A control that HELD: MySQL 8's `1045` carries zero user *and* zero password discrimination.** The 34-candidate sweep returned **0 hits**, and that negative is now attributable to the credential rather than to my client |
| **E13** | MySQL external reachability | the **unauthenticated initial handshake packet**, read from the analyst host over TCP: protocol 10, `8.0.42-0ubuntu0.24.04.2`, connection id, `caching_sha2_password` plugin name — no credentials sent | — (it is itself the positive) | **1 connection** | **F5.** `bind-address = 0.0.0.0` puts the database on the internet-facing interface. Proven by a **live protocol exchange**, not by an open port (retrieval-hazards row 1) |
| **E14** | MySQL auth **positive control** — added *after* E12, because E12's oracle had never fired | `debian-sys-maint` + its real password **over TCP `127.0.0.1:3306`** → `CURRENT_USER() = debian-sys-maint@localhost`, `COUNT(*) = 4` | — | **1 attempt** | **Fired.** Proves the exact client, transport and auth path in E12 *can* succeed, so E12's 34 misses are about the credential and about nothing else. §23's rule: a component that failed to start and a component that is not installed are different findings |
| **E15** | SSH authentication + user oracle | correct password → `AUTHOK` in **0.08 s**; rate ladder 3 wrong → `AUTHFAIL` at **2.15 / 4.25 / 2.15 s** — the yescrypt envelope, not throttling | `grooti`, `ubuntu`, `root`, `rocket` **and** `zzz_definitely_not_here_9f3a`, all with the same wrong password → **byte-identical** `Authentication failed.` | **42 attempts** (3 ladder + 34 candidates + 5 oracle probes) | **F6 — the credential: `grooti` / `YoSoYgRoOt`, candidate 29 of 34, 96 s, no lockout, no penalty.** And a **second control that held**: sshd is not a username oracle, so the *username* had to come from the web surface (§3), not from port 22 |

### 2.1 The aggregate, in three units, and why it is not one number

Lab 188 wrote "178 probes" and the audited figure was 159 application-level plus 65 535
ports. So the units are separated here rather than blended:

| Unit | Count | Rows |
|---|---|---|
| **HTTP requests** | **110** | E3 63 · E4 5 · E5 9 · E6 10 · E7 1 · E8 20 · E9 2 |
| **Authentication attempts** | **83** | E12 39 · E13 1 · E14 1 · E15 42 |
| **Candidate verifications (ZipCrypto)** | **1 332** | E11 |
| **Non-mutation probes, total** | **1 525** | `110 + 83 + 1332` |
| **Ports** (different unit, **not** summed) | **65 535** | E1 |
| **UDP socket lines** | **0** | E2 |
| **Filesystem mutations** (all reverted, §9) | **11** | 3 probe artefacts in the docroot · 1 `/tmp/malicious.sh` · 1 `/tmp/LAB83.crontab` · 2 in `/home/grooti` · 2 crontab installs · 2 files the *target's own* code created and unlinked |

### 2.2 What the surfaces do *not* give you, stated precisely

- **No MySQL access.** `rocket@%` exists and the port is open; **34 candidates from the
  shipped wordlist produced 0 hits** and the image carries no credential for it. §6/D1.
- **No role, no uid, no home directory** from outside. `grooti` is disclosed as a *name* by
  `/secret/index.html`; its **uid 1001, its group membership and its sudo status came from
  the artefact**, and are reported as ground truth rather than as unauthenticated findings.
- **No password.** The web surface discloses a *list* of 34 candidate passwords and one ZIP
  password; which of them is the credential is settled only by E15.
- **No data.** `/archives/` and `/secret/` are static HTML. There is no application, no
  database-backed page and no login form anywhere in the docroot — the "database" is a
  downloadable file, not a service behind one.

---

## 3. Content and credential enumeration — the part that actually mattered

| Endpoint | Status | Bytes | Work count | What it disclosed |
|---|---|---|---|---|
| `/` | 200 | 1436 | 1 | `index.html:39-43` links `/imagenes/`, **`/documentos/`**, `/archives/`. `index.html:44-49` is an HTML comment: *"Creo que Rocket ha entrado a mi base de datos..."* — the only hint that the DB matters |
| `/secret/` | 200 | 2579 | 1 | A three-row roster: **`grooti` (Administrador)**, `rocket` (Subcordinador), `Naia` (Total). **This is where the SSH username comes from** — the only unauthenticated disclosure of `grooti` as an account |
| `/secret/instrucciones.txt` | 200 | 571 | 1 | 101 blank lines, then on **line 102** `mysql -u rocket -p -h 172.17.0.2 --ssl=0` — below the fold of any browser. The three defects are §6/D1 |
| `/imagenes/README.txt` | 200 | 39 | 1 | `(password1) Encuentra donde ponerla ;)` — **and this is the ZIP's password, verbatim.** The "encrypted" archive is not protecting anything |
| `/archives/index.html` | 200 | 2045 | 1 | A fake invoice, `Grand Total 20,000 Galactic Credits`. Content, nothing more |
| `/unprivate/` | 200 | **939** | 1 | **autoindex listing** — `secret/` and a `Parent Directory` link. The whole hidden half of the lab is one directory name away |
| `/unprivate/secret/` | 200 | 2415 | 1 | `generate.php`'s form: `content` + `number` (1–100), *"Acceso restringido al sistema de logs de la nave"* |

**The ZIP, and what is inside it.** `password16.zip` is 429 bytes, method 8, **flag `0x0009`
— bit 0 set, so ZipCrypto**, no AES extra field (`0x9901` absent), one member
`password16.txt`, 327 bytes uncompressed, CRC `0xdead4cc8`. ZipCrypto is the traditional
PKWARE stream cipher and is not a KDF, so it is both crackable and, more importantly,
**fast enough that a rate assertion is mandatory** — E11 asserts 12 879 candidates/s, which
is what a keystream costs and what a "the KDF never ran" failure would not look like.

Password `password1` → **34 candidates**, one per line, 327 bytes, md5
`cb6eb006820251ca5bd363a0e1e7c87a`. Candidate **29** is `grooti`'s SSH password. The other 33
are stock rockyou-style filler, and **all 34 fail against MySQL** (E12).

---

## 4. The class

**Entry criterion:** *does the artefact's own credential material reach an account that a
scheduled-job misconfiguration is waiting on?*

**Source that settled it — the sink, read before any request:**

```
/opt/cleanup.sh:1-3          (mode 754 root:root, 36 bytes, owner root:root)
     1  #!/bin/bash
     2
     3  bash /tmp/malicious.sh
```

```
$ stat -c '%n mode=%a owner=%U:%G size=%s' /tmp/malicious.sh
/tmp/malicious.sh mode=764 owner=root:grooti size=221
```

```
$ cat /var/spool/cron/crontabs/root | tail -1
* * * * * /opt/cleanup.sh
```

The chain of ownership is the whole finding: **a script owned by `root`, executed by `root`'s
crontab, sources a file in `/tmp` that is `root:grooti` mode `764`.** The group `grooti` has
`w`, and `grooti` the user has `grooti` as its **primary** group. `grooti` cannot touch
`/opt/cleanup.sh` at all — and does not need to.

---

## 5. Chain

| # | → | Mechanism | Identity proof |
|---|---|---|---|
| 1 | unauth | TCP recon; `/proc/net/udp{,6}` **0** socket lines; Apache identified as 2.4.58 from `dpkg`, not from the banner | — |
| 2 | unauth | Docroot sweep, 63 paths; `/unprivate/` autoindex is the pivot | `/unprivate/` → `200` **939 B**, `Index of /unprivate`; 2 impossible names → `404:272`, one body hash |
| 3 | unauth | `GET /unprivate/secret/password16.zip` — no form, no session, no credential | `200`, **429 B**, md5 `f04703f0c72c` |
| 4 | unauth | ZipCrypto, password `password1` | Positive control FIRED first (`zip -P` → `unzip -P` → my decryptor, all three agreeing); rate 12 879/s; **1015**/1132 |
| 5 | unauth | The user name comes from the roster page, **not** from port 22 | `/secret/index.html` → `grooti` / `Administrador` / `Activo`; sshd gives a **byte-identical** `Authentication failed.` for `grooti` and for a name that cannot exist |
| 6 | **`uid=1001(grooti)`** | SSH with `YoSoYgRoOt` — candidate 29 of 34 | `id` → `uid=1001(grooti) gid=1001(grooti) groups=1001(grooti),100(users)`; `id -u` → **1001**; `whoami` → `grooti`; `/proc/self/status` → `Uid: 1001 1001 1001 1001`, `Groups: 100 1001`, `CapEff: 0000000000000000` |
| 7 | `uid=1001(grooti)` | **Negative control first:** the identical operation into `/root` fails; then `test -w /tmp/malicious.sh` **as `grooti`** | `touch /root/LAB83_195ec585b008e396_NEG` → `Permission denied`, **rc=2**; `test -w /tmp/malicious.sh` → **WRITABLE**; `test -w /opt/cleanup.sh` → **NOT-WRITABLE**; positive control for the same predicate on a file `grooti` owns with mode 700 → **EXECUTABLE** |
| 8 | **`Uid: 0 0 0 0`** | `/tmp/malicious.sh` overwritten through the group-writable path; `root`'s `* * * * * /opt/cleanup.sh` sources it. Oracle **manufactured**: the marker name is random, and the payload is executed by *both* crontabs, so each run records its own identity | `whoami=root`, `id=uid=0(root) gid=0(root) groups=0(root)`, `euid=0`, `Uid: 0 0 0 0`, `Gid: 0 0 0 0`, `Groups: 0`, `CapEff: 00000000a80425fb`, **`ppid_comm=cleanup.sh`** — read from the **un-escalated** `grooti` session, and the witness is `-rw-r--r-- 1 root root 225` |

### 5.1 Hop 8's oracle — manufactured, because `id` alone would have been misread

The chain has **no** message that echoes back: `cleanup.sh` prints nothing, cron is silent,
and the container has **no syslog** (`/var/log/` has no `syslog`, so cron's own output has
nowhere to go — the same blind spot as lab 218's `fail2ban`). Reporting "root's cron runs my
script, therefore I would be root" is a claim about the future dressed as a result.

So the oracle was built before the exploit, in three states:

1. **Negative control, first.** As `grooti`, the identical `touch` into `/root` (`0700`)
   produced **nothing** — `Permission denied`, rc=2 — and `ls -l /root/` is
   `Permission denied` too. The witness path is therefore one only the target identity can
   create.
2. **The payload writes two artefacts with one random marker**, and it is run by *two*
   crontabs, so each run names itself:
   `/tmp/<MARK>.by-root.txt` and `/root/<MARK>.by-root.txt` as root;
   `/tmp/<MARK>.by-grooti.txt` as grooti.
3. **Read back from the un-escalated session**, which needs no escalation to see the proof:

```
$ ls -l /tmp/LAB83PROOFfd41c14b43d4.by-root.txt
-rw-r--r-- 1 root root 225 Sep 30 21:12 /tmp/LAB83PROOFfd41c14b43d4.by-root.txt

$ cat /tmp/LAB83PROOFfd41c14b43d4.by-root.txt
marker=LAB83PROOFfd41c14b43d4
when=2026-09-30T19:12:01Z
whoami=root
id=uid=0(root) gid=0(root) groups=0(root)
euid=0
Uid:	0	0	0	0
Gid:	0	0	0	0
Groups:	0
CapPrm:	00000000a80425fb
CapEff:	00000000a80425fb
ppid_comm=cleanup.sh
```

**`CapEff: 00000000a80425fb` is the discriminator.** `grooti`'s own session carries
`CapEff: 0000000000000000`; a full capability bounding set is only ever present with uid 0.
`ppid_comm=cleanup.sh` names the parent, so the file is not a coincidence of timing.
`/root/<MARK>.by-root.txt` is the same bytes in a path `grooti` provably cannot write, and it
is **still unreadable from the `grooti` session** — which is the point: the identity that
created it is the identity that cannot read it back.

**A reproducible limit on this rung, reported as a limit.** Hop 7's `grooti` run of
`bash /opt/cleanup.sh` over SSH **does** produce `/tmp/<MARK>.by-grooti.txt`, owned by
`grooti`, containing `Uid: 1001 1001 1001 1001` and `CapEff: 0000000000000000`. A tester who
tests the script by hand and concludes "the escalation does not work" would be testing
`bash <file>`, which needs only **read** permission, rather than `execve`, which needs
**execute** — and those differ by exactly one bit on this file. See §6/D2.

---

## 6. Findings

### F1 — The directory named `unprivate` is not private, and it holds the credentials
**CWE-732 / CWE-276 / CWE-200 · High**

```
$ ls -ld /var/www/html/unprivate /var/www/html/unprivate/secret
drwxrwxrwx 1 root root 4096 /var/www/html/unprivate
drwxrwxrwx 1 root root 4096 /var/www/html/unprivate/secret
```

There is **no `<Directory>` block anywhere in the image** that mentions `unprivate`
(`apache2.conf` has three: `/`, `/usr/share`, `/var/www/`, and the last is
`Require all granted` with `Options Indexes`). Consequences, all measured unauthenticated:

```
/unprivate/                            200     939   <- autoindex listing, "secret/" visible
/unprivate/secret/                     200    2415   <- the credential terminal
/unprivate/secret/password16.zip       200     429   <- the encrypted candidate list
```

The database agrees that this is where the secret is — `files_secret.rutas` row 4 is
`secret → /unprivate/secret`, a **URL path**, while rows 1–3 are filesystem paths.

**Impact:** every byte of the lab's credential material is one unauthenticated `GET` from a
directory whose name promises the opposite. The name is doing security work that no
configuration does.

**Remediation:** `<Directory /var/www/html/unprivate> Require all denied </Directory>`, and
drop `Options Indexes` on the docroot; `chmod 750` the tree. A directory called `unprivate`
that is world-readable is worse than a directory called `private` that fails to exist,
because it is the first thing a reviewer trusts.

### F2 — Eight name-based `403`s for eight files that do not exist, and one real `403` indistinguishable from them
**CWE-441 / configuration · Medium as a finding, High as a measurement hazard**

```
apache2.conf:194-196     <FilesMatch "^\.ht">
                             Require all denied
                         </FilesMatch>
mods-enabled/php8.3.conf:9-10   <FilesMatch "^\.ph(?:ar|p|ps|tml)$">
                             Require all denied
                         </FilesMatch>
```

Both are evaluated **by name, before existence**. Measured:

| Name | Response | Exists? |
|---|---|---|
| `/.htaccess` `.htpasswd` `.htaccess.bak` `.htpasswd.bak` `.php` `.phar` `.phps` `.phtml` | `403` **275 B**, md5 `dd525d40a0e7` — **one single body** | **0 of 8** (`test -e` per name) |
| `/.HTACCESS` `/.Htaccess` `/.Phar` `/.PHP` `/.pht` `/.php5` `/.php.bak` | `404` **272 B**, md5 `f2e790ff3d9a` | 0 of 7 — the rules are case-sensitive |
| `/server-status` | `403` **275 B**, **md5 `dd525d40a0e7` — identical to all 8** | the endpoint **is** real: `200` / **4019 B** from `127.0.0.1` |

**The existence toggle settles it**, because nothing else can distinguish "protected file"
from "name matched a rule":

```
/.htaccess, file ABSENT  -> 403:275  md5 dd525d40a0e7
/.htaccess, file CREATED -> 403:275  md5 dd525d40a0e7
/.htaccess, file DELETED -> 403:275  md5 dd525d40a0e7
```

**Impact.** A status-code sweep reports **8 disclosed configuration files where 0 exist**,
and the phantoms are `.htaccess`, `.htpasswd`, `.php`, `.phar` — the first four names in any
web wordlist. Symmetrically, `mod_status` is **correctly** held and cannot be distinguished
from a name-match by either the status or the body.

**Remediation.** Nothing needs to change in Apache — the deny is doing its job. The finding
is for the *reader*: any inventory of this target must be built with an existence check or a
toggle, never from status codes. And if the intent was to hide nothing, the `.ht*` rules are
pure cost; if the intent was to hide something, they do not.

### F3 — The credential terminal serves its own secret, and the artefact calls it something it is not
**CWE-639 (mislabel) + CWE-200 · High**

```
download.php:22          // --- IDOR ACTIVADO en 16 ---
download.php:23-24       if ($numero === 16) { $zipPath = __DIR__ . '/password16.zip';
```

```
POST /unprivate/secret/download.php  content=x&number=16
  -> 200, 429 bytes, md5 f04703f0c72c
     Content-Disposition: attachment; filename="password16.txt"
     X-Secret-IDOR: true
     X-Groot-Access: unlocked
```

**It is not an IDOR**, and the difference matters, because a tester who accepts the label
will look for an ownership predicate that does not exist and will miss the defect that does:

- an IDOR needs **an ownership predicate and a cross-identity read** (labs 85 and 243). There
  is **no session, no identity and no owner** anywhere in either script — the whole
  authorisation state is *absent*, not *checked*.
- the **same object is returned by the other endpoint with no special behaviour**:
  `generate.php` at `number=16` returns the **byte-identical 429 bytes**, and its own comment
  reads *"Aquí devolvemos el archivo ZIP real camuflado como .txt"*.
- both are reachable with `GET` refused and a single unauthenticated `POST`, and
  `number=16.9` and `number="16 "` both reach the branch (`intval` truncation), so the range
  check is not a boundary.

**The real defect is "there is no authentication at all", plus two response headers that
assert an access decision that never happened** — `X-Secret-IDOR: true` and
`X-Groot-Access: unlocked` are a machine-readable claim about authorisation, emitted by a
script that never authorises anything.

**Remediation:** authenticate both endpoints; delete both headers; the IDOR label should go,
because it sends a reviewer looking for a comparison that does not exist.

### F4 — Credential material ships in the image, and the password protecting it ships beside it
**CWE-522 / CWE-312 / CWE-521 · High**

```
$ cat /var/www/html/imagenes/README.txt
(password1) Encuentra donde ponerla ;)

$ cat /var/www/html/unprivate/secret/password16.zip   # 429 B, ZipCrypto, flag 0x0009
$ # password = "password1"  ->  34 candidate passwords, one of which is grooti's SSH password
```

The candidate list is `rockyou`-shaped filler (`admin123`, `qwerty`, `iloveyou`,
`dragon2024`, `batman2025` …) with two lab-specific entries. It is a **short, low-entropy
password on the only login account in the image**, and the ZIP's own password is printed in
a world-readable text file two directories away, so the encryption contributes nothing.

**Impact:** `grooti` is `uid=1001` and one command away from root (F7). The whole distance
between "an unauthenticated `GET`" and "`Uid: 0 0 0 0`" is 34 guesses.

**Remediation:** do not ship working credentials in an image. If a puzzle needs a wordlist,
ship one that is not the answer key; if it needs a puzzle, ship a hint that does not *be* the
key.

### F5 — MySQL on `0.0.0.0`, with an application account at `%`
**CWE-668 / CWE-284 · Medium (the account's grants are small; the exposure is not)**

```
/etc/mysql/mysql.conf.d/mysqld.cnf:31   bind-address		= 0.0.0.0
```

Proven by a **live, unauthenticated protocol exchange from the analyst host** — the initial
handshake packet, which needs no credential at all:

```
protocol version: 10
server version  : 8.0.42-0ubuntu0.24.04.2
plugin name     : caching_sha2_password
```

`rocket@%` holds `GRANT SELECT ON files_secret.*` and nothing else, which limits the damage;
`root@localhost` uses `auth_socket`, so it is not remotely reachable at all. The finding is
the interface, not the grants.

**Remediation:** `bind-address = 127.0.0.1`. A control that held and is worth naming:
`/etc/mysql/debian.cnf` (which holds the `debian-sys-maint` password) is **`0600 root:root`**,
verified readable **only** as root — the opposite of lab 117's `0644` `wp-config.php`.

### F6 — A one-hour, 34-candidate password on the only login account — and no username oracle
**CWE-521 · High**

Recovered at **candidate 29 of 34**, in **96 s** over 34 serial attempts (≈2.8 s each,
entirely the yescrypt cost). No lockout, no delay, no `PerSourcePenalties` — the rate ladder
before the sweep (2.15 / 4.25 / 2.15 s for three wrong attempts) proves the absence of
throttling is measured and not assumed, which is the same discipline that saved lab 188 from
filing its own rate limit as a firewall.

Worth recording as a control that **held**: sshd returns **byte-identical**
`Authentication failed.` for `grooti`, `ubuntu`, `root`, `rocket` and
`zzz_definitely_not_here_9f3a`. Port 22 discloses **nothing** about which accounts exist; the
username had to come from the web surface (`/secret/index.html`), and the *completeness* of
that list was checked against `/etc/passwd` (`awk … uid>=1000 && login shell` → **1**).

The one asymmetry is in the success direction: `AUTHOK` returns in **0.08 s** against
`2.4–4.3 s` for failures. That is a timing oracle for *a correct credential*, not for
*existence*, and it is the normal cost of a password-based KDF.

### F7 — A group-writable payload path that root's crontab executes once a minute
**CWE-732 / CWE-269 / CWE-78 · Critical**

The three facts, each measured:

```
$ stat -c '%n mode=%a owner=%U:%G' /opt/cleanup.sh /tmp/malicious.sh
/opt/cleanup.sh     mode=754 owner=root:root
/tmp/malicious.sh   mode=764 owner=root:grooti

$ tail -1 /var/spool/cron/crontabs/root
* * * * * /opt/cleanup.sh

$ cat /opt/cleanup.sh
#!/bin/bash

bash /tmp/malicious.sh
```

`mode=764` on `root:grooti` means **the group has `w`**, and `grooti`'s primary group **is**
`grooti` — so the account that logs in over SSH can rewrite the file that `root`'s crontab
sources, with no credential, no sudo and no write to anything root owns.

Measured **as `grooti`**, not as root through `docker exec` (self-corrections §2 — the whole
finding is the identity, and a `test -w` run as root would have said WRITABLE for every file
in the image and proved nothing):

```
$ id -u
1001
$ test -w /tmp/malicious.sh && echo WRITABLE || echo NOT-WRITABLE
WRITABLE
$ test -w /opt/cleanup.sh && echo WRITABLE || echo NOT-WRITABLE
NOT-WRITABLE
```

and the resulting root execution is §5.1: `Uid: 0 0 0 0`, `CapEff: 00000000a80425fb`,
`ppid_comm=cleanup.sh`, witnessed from the un-escalated session.

**Impact:** any `www-data` RCE, any `grooti` login, any write into `/tmp` by any local user
is root on the next minute boundary. The escalation is not a chain to be assembled; it is a
mode bit.

**Remediation:** three changes, in order of value. (1) Delete the
`bash /tmp/<file>` indirection — a root cron job should invoke a fixed, root-owned binary
with absolute paths, never a path any user can write. (2) `/tmp/malicious.sh` must be
`root:root 0755` at most. (3) Check the other setuid-adjacent defaults this image ships:
**16** setuid binaries and a `sudoers` with `%sudo ALL=(ALL:ALL) ALL`.

### F8 — An unauthenticated `POST` silently deletes shipped content
**CWE-732 / CWE-73 · Medium — reported separately from F3, because one fix does not cover both**

```php
generate.php:33   file_put_contents($filepath, $texto);          // return value never checked
generate.php:34-40  … header('Content-Length: ' . filesize($filepath)); readfile($filepath);
generate.php:41   unlink($filepath);                              // unconditional
```

`file_put_contents` **fails** for every pre-existing `password<N>.txt` (they are
`root:root 0644` and PHP runs as `www-data`), and `unlink` **succeeds** anyway because the
directory is `0777`. So one unauthenticated `POST` with `number=N` **removes**
`/var/www/html/unprivate/secret/password<N>.txt` for any N in 1–100.

This is not a theoretical finding — **I hit it**. My own enumeration POST with `number=1`
returned the shipped 14-byte file (the failed-write branch) and deleted it; a repeat POST
returned my own 10-byte content, and `find` afterwards showed `password1.txt` gone. E8's
byte-count difference (14 B vs 10 B) is what made it visible instead of silent. It was
restored from the image in §9 and verified byte-exact.

The same asymmetry is visible without side effects: `number=2/3/5/100` return the **shipped**
contents (`Prueba otra vez`, `Igual la fuerza bruta es un recurso...`,
`Asi no lo vas a conseguir...`, `Caaaa…asi ;)`) because the write failed, while
`number=15/17/42` return my own content. A script that returns different bytes depending on
whether it could write, and never says which, is a script with two undocumented modes.

**Remediation:** check `file_put_contents`'s return value and abort on false; do not
`unlink` on the failure path; `chmod 750` the directory and own the files as the web user.

### Not filed as a finding, on purpose

- **"RCE through the PHP write sink."** Refuted by control (E9): my `<?php … ?>` came back
  **verbatim**, while a `.php` file in the *same directory* executed as `uid=33`. The
  barrier is real and it is the filename, which `generate.php:33` hard-codes. This is lab 12's
  "installed ≠ vulnerable" with the polarity reversed: the handler is global and the sink is
  one suffix short, and no amount of parameter fuzzing moves the suffix.
- **"`.htaccess` can be used to re-enable PHP."** `AllowOverride None` at
  `apache2.conf:161,166,172` and at the vhost, so a per-directory file cannot speak. And it
  would be `403` anyway (F2). Not tested against a real write — no write path to it exists.
- **"sudo is the escalation."** `grooti` is not in `sudo`; `sudo -l` as `grooti` answers
  `sudo: a password is required`, and `/etc/sudoers.d/` holds one file, `README`.
- **"grooti's own crontab is the escalation."** Refuted by measurement — §6/D2.
- **"A default credential in the build record."** Lab 188's decisive finding has no analogue
  here: all **19** layers of `docker history --no-trunc` were read and **none** contains a
  credential. The negative is scoped to that count.

---

## 6bis. Defects in the lab itself

The brief asks for the real path when the lab misattributes its own. It does, twice, and once
the advertised leg is unreachable.

### D1 — The advertised database leg cannot be entered, and adds nothing if it could
**The catalogue says "Enumeración de directorios web, bases de datos y escalada de
privilegios". The escalation is real. The database is neither reachable nor necessary.**

`/var/www/html/secret/instrucciones.txt` is world-readable and its payload sits on
**line 102**, after 101 blank lines, so no browser renders it. That line is:

```
mysql -u rocket -p -h 172.17.0.2 --ssl=0
```

Four independent defects, each measured:

1. **The option does not exist on the client the image ships.**
   `mysql -u rocket -p -h … --ssl=0` → `mysql: [ERROR] unknown variable 'ssl=0'`, **rc=7**.
   MySQL 8.0.42 requires `--ssl-mode=DISABLED`. The hint as written **cannot execute**.
2. **The host is stale.** `172.17.0.2`; this instance is `172.17.0.8`.
3. **No artefact in the image carries `rocket`'s password.** Searched, with counts:
   the shipped wordlist (E12, **34 candidates, 0 hits**, rate-laddered first);
   `files_secret.rutas` has **4 rows**, none of them a credential; `/root/.mysql_history`
   read in full (D3); `docker history --no-trunc`, **19 layers**, none carrying a secret;
   and a whole-filesystem sweep for files newer than `2025-07-01` outside `/usr`,
   `/var/lib/{dpkg,mysql,apt,log,cache}` — **no credential artefact**. The only secret
   present is `debian-sys-maint`'s, in `0600 root:root`, for a localhost-only account.
4. **Even a solved database leg adds nothing.** `files_secret.rutas` is 4 rows of which
   **3 point at paths that do not exist** and the 4th is the URL that the web already serves
   to anyone:

   | row | `nombre` | `ruta` | exists? |
   |---|---|---|---|
   | 1 | imagenes | `/var/www/html/files/imagenes/` | **no** (the live one is `/var/www/html/imagenes/`) |
   | 2 | documentos | `/var/www/html/files/documentos/` | **no** — and `/documentos/` 404s too |
   | 3 | facturas | `/var/www/html/files/facturas/` | **no** (the live one is `/archives/`) |
   | 4 | secret | **`/unprivate/secret`** | **yes — and `GET /unprivate/secret/password16.zip` is `200` with no credential** |

   So the table's only live value is a pointer to something the enumeration had already
   found. The database is **not on the path**.

**The real path, in one line:** `/` → autoindex at `/unprivate/` → `GET
…/password16.zip` → ZIP password `password1` (printed in `imagenes/README.txt`) → 34
candidates → SSH `grooti` → write `/tmp/malicious.sh` → `root`'s crontab → **`Uid: 0 0 0 0`**.
**Zero database involvement.**

A second misattribution in the same family: `index.html:41` advertises
`<a href="/documentos/">Mi base de datos</a>`; `/documentos/` returns `404:272`, and the
`rutas` row that names it points at a directory that does not exist either. The real
"base de datos" page is `/secret/`.

### D2 — `grooti`'s own crontab is a decoy that can never fire
**Two of the lab's declared routes are one.**

```
/var/spool/cron/crontabs/root      ->  * * * * * /opt/cleanup.sh
/var/spool/cron/crontabs/grooti    ->  * * * * * /opt/cleanup.sh     (identical)
/opt/cleanup.sh                    ->  -rwxr-xr-- 1 root root
```

`754` = `rwx`/`r-x`/`r--`. Other has **read but not execute**. Measured **as `grooti`**:

```
$ test -r /opt/cleanup.sh && echo READABLE || echo NOT-READABLE
READABLE
$ test -x /opt/cleanup.sh && echo EXECUTABLE || echo NOT-EXECUTABLE
NOT-EXECUTABLE
$ /opt/cleanup.sh; echo "rc=$?"
rc=126
bash: line 1: /opt/cleanup.sh: Permission denied
```

`rc=126` is exactly what cron gets, so `grooti`'s cron line fails silently — and silently,
because **the container has no syslog**, so cron's own diagnostic goes nowhere. I watched the
root-owned witness for **over four minutes across thirteen polls** and it was rewritten every
minute, while no `grooti`-owned run ever appeared.

**The control that establishes this is a dead crontab, not a missing file.** I installed a
second job into `grooti`'s crontab (`* * * * * /bin/sh -c 'id > /tmp/GROOTICRON.<rand>.txt'`)
and it **fired within 60 s**, producing `-rw-rw-r-- 1 grooti grooti 65` containing
`uid=1001(grooti) gid=1001(grooti) groups=1001(grooti),100(users)`. So `grooti`'s crontab is
live, `cron` is running (`/usr/sbin/cron -P`, pid 52), and the reason is the mode bit. Per
§23: an absent effect and an inert mechanism are different findings, and only the second is a
property of the target.

The trap this sets is sharp, and it is the same trap that produced a false privesc in lab 87
§5.1 and lab 33: **testing `bash /opt/cleanup.sh` by hand succeeds as `grooti` and proves
nothing about privilege**, because `bash` needs only *read*. The escalation needs cron, cron
needs *execute*, and execute is exactly what `grooti` lacks.

### D3 — `.mysql_history` disagrees with the live table
`/root/.mysql_history` (mode `0600`, root) is the build's own SQL session, and it shows the
`rutas` table being repointed at build time:

```
INSERT INTO rutas(nombre, ruta) VALUES … ('secret','/var/www/html/files/secret/');
UPDATE rutas SET ruta='/unprivate/secret' WHERE id=4;
```

The table as built said the secret lived at `/var/www/html/files/secret/`, which **does not
exist**; it was updated to the live URL. Anyone who reads the artefact's history and the live
table gets two different answers about where the secret is, and the history is the one that
looks authoritative. The same file also records
`GRANT SELECT … TO 'blue'@'%'; RENAME USER 'blue'@'%' TO 'rocket'@'%';` — so the username the
hint hands you is a **deliberately renamed** account, which is consistent with the hint being
unusable anyway (D1).

---

## 7. Controls that held

Every row has a positive control: a case where the same detector was shown firing, or — for
rows where no success exists to point at — a demonstrated reason the instrument could have
been trusted and was not.

| # | Control | Positive control / how the detector was proven able to fire | Negative evidence |
|---|---|---|---|
| **C1** | The docroot sweep's `404` really means "absent" | 22 real resources, each with its own byte count (1436 / 1141 / 2045 / 2579 / 571 / 939 / 2415 / 429 / 105820 …) | 36 absent paths → `404:272`, **one** distinct body hash. Two impossible names in the wordlist by construction. **And the artefact independently lists 16 files + 5 dirs = 21 nodes, all 21 reached — so 36 negatives are evidence, not a blind spot** |
| **C2** | `403` does not mean "the file exists" | the toggle: `.htaccess` absent → `403:275`, created → `403:275`, deleted → `403:275`, **byte-identical all three** | `test -e` on all 8 names → **0 exist**; `test -e` on the 7 case variants → `404:272` |
| **C3** | `403` cannot be attributed to a rule | `server-status` from `127.0.0.1` → **`200`, 4019 B** — the endpoint is real and works | from outside it is `403:275`, md5 `dd525d40a0e7` — **identical to all 8 phantoms** |
| **C4** | The ZipCrypto oracle can report a success | the control archive written by **`/usr/bin/zip -P`**, opened by **`/usr/bin/unzip -P`** (`rc=0`, exact bytes), **and** decrypted by my code — three independent implementations agree | wrong password → `rc=82` from `unzip` **and** `None` from my code. **This control is what caught two defects in my own primitive (§11.2, §11.3) before they could become a negative** |
| **C5** | The ZipCrypto sweep is doing real work | **rate asserted at 12 879 candidates/s** — the cost of a keystream, not of a shortcut | a `find-nothing` primitive would have run at millions per second, as lab 87's `password_verify` did at 44 M/s |
| **C6** | The MySQL auth oracle can report a success | `debian-sys-maint` + its real password **over TCP** → `CURRENT_USER() = debian-sys-maint@localhost`, `COUNT(*) = 4` | `1045` is **byte-identical** for a wrong password, for `nosuchuser_zz_7c1e5b2a`, and for the *correct* password of a host-restricted account. **A uniform answer is a result about the query, not about the credential** |
| **C7** | MySQL was not throttling me | rate ladder: 3 wrong passwords → 0.05 / 0.06 / 0.05 s | 34 candidates in **2 s** (≈17/s), all `1045`. No later negative is attributable to my own rate |
| **C8** | sshd was not throttling me | rate ladder: 2.15 / 4.25 / 2.15 s for three wrong attempts — the yescrypt envelope | 34 candidates in **96 s** (≈2.8 s each). Success at **0.08 s**, i.e. a KDF that ran, not one that was skipped |
| **C9** | sshd is not a username oracle | the success: `AUTHOK`, 0.08 s | `Authentication failed.` **byte-identical** for `grooti`, `ubuntu`, `root`, `rocket`, `zzz_definitely_not_here_9f3a`. Completeness checked against `/etc/passwd` → **1** account |
| **C10** | `/opt/cleanup.sh` is genuinely not executable by `grooti` | the **redone** positive control: `cp` + `chmod 700` a copy `grooti` owns → `test -x` = **EXECUTABLE**, and it runs (`rc=0`) | `test -x /opt/cleanup.sh` as `grooti` → **NOT-EXECUTABLE**; `/opt/cleanup.sh` → **rc=126**. *My first version of this control used `touch`, which creates `0644` — it could not fire and I redid it (§11.6)* |
| **C11** | `grooti`'s crontab is live, so its silence is the mode and not a dead crontab | installed `/tmp/GROOTICRON.<rand>.txt` job → fired within **60 s**, `-rw-rw-r-- 1 grooti grooti 65`, `uid=1001(grooti)` | over **4 minutes / 13 polls** no `grooti`-owned run of `/opt/cleanup.sh` ever appeared, while the root-owned witness was rewritten **every minute** |
| **C12** | No RCE through the write sink | **I created** `…/lab83_handler.php` → `200`, `LAB83-HANDLER-PROOF uid=33 euid=33`, `Name: apache2`, `Uid: 33 33 33 33` | the sink's own output returns `<?php … ?>` **verbatim**. The handler is global; the filename is fixed at `generate.php:33` |
| **C13** | `AllowOverride None` means no `.htaccess` lever | — | `apache2.conf:161,166,172` all `AllowOverride None`; a probe `.htaccess` written into the docroot changed nothing (and was `403` anyway, C2) |
| **C14** | `debian.cnf` does not leak to a low-privilege identity | readable **as root** → the `debian-sys-maint` password | `0600 root:root`; no other identity can read it (§23 — recorded as a measured property, not inferred from the mode alone, by reading it only from the escalated session) |
| **C15** | sudo is not the escalation path | — | `grooti` ∉ `sudo`; `sudo -l` as `grooti` → `a password is required`; `/etc/sudoers.d/` = **1** file, `README` |
| **C16** | My own probes were not modifying the measurement | baseline hashes captured before any write and re-checked after | 11 mutations, all reverted from the image and verified (§9) |

On **C11** and **C14**: both are the §23 rule applied to *this* lab. Before I could write
"grooti's crontab never fires", I had to show that crontab **can** fire; before I could write
"no low-privilege identity can read `debian.cnf`", I had to read it from an identity that can.

---

## 8. NOT tested (scope, not gaps in effort)

- **Any password outside the 34 the image ships.** No wordlist corpus exists on this host
  (`/usr/share/wordlists` absent, no seclists, no rockyou), so every search here is
  *generated*, not exhaustive. For MySQL that means `rocket`'s password is **unknown**, not
  absent: 34 candidates, 0 hits, and no other source in the image.
- **A symlink or hardlink abuse of the `0777` write directory.** The sink's filename is fixed
  at `password<N>.txt` and `file_put_contents` follows symlinks, so a pre-planted symlink
  *might* redirect a write. It needs a write to plant one, `generate.php` does not create
  links, and I did not attempt it. Not tested.
- **`SELECT INTO OUTFILE` / `LOAD DATA` as `rocket`.** `secure_file_priv =
  /var/lib/mysql-files/` and `local_infile = OFF` were measured **as root**, not as `rocket`;
  `rocket` holds `SELECT` only, so I expected no write path and did not test one. Not tested
  as `rocket`.
- **The full keyspace of the ZIP password.** Not enumerated — the published hint made it
  unnecessary, and I say so rather than claiming a crack where a hint existed (F4).
- **Any of the 16 stock setuid binaries.** `find` counted them; none is a lab vector
  (`chfn chsh gpasswd mount newgrp passwd su sudo umount ssh-keysign
  dbus-daemon-launch-helper ssh-agent crontab chage expiry pam_extrausers_chkpwd unix_chkpwd`
  — all Ubuntu defaults, `getcap -r /` = 0 lines). I did not attempt any of them.
- **Whether the escalation still works if `/tmp` is mounted `noexec` or with a sticky
  `nosuid` policy.** Not the shipped configuration; not tested.
- **Why the lab ships `mysqlx-bind-address = 127.0.0.1` while `bind-address = 0.0.0.0`.**
  Observed, not investigated.

---

## 9. Discarded with reason

| Hypothesis | Why discarded |
|---|---|
| **"12 disclosed configuration files in the docroot"** — what a status-code sweep reports here | **Refuted by the existence toggle.** 8 names return `403:275` and **0 of them exist**; `.htaccess` created and deleted gives the same three bytes. F2 |
| **"mod_status is exposed but locked"** | Half right. `403` from outside, but the **positive control fires**: `200` / 4019 B from `127.0.0.1`. Locked down correctly, and **indistinguishable from a name-match** by status or body. C3 |
| **"RCE via the PHP write sink"** | **Refuted by control.** `<?php …?>` returns verbatim; a `.php` in the same directory executes as `uid=33`. `generate.php:33` hard-codes `.txt`. C12 |
| **"`/opt/cleanup.sh` is writable by `grooti`"** | **Refuted as the mechanism, measured as `grooti`:** `test -w` → NOT-WRITABLE. The mechanism is the file it **sources**. Reporting `cleanup.sh` as the writable artefact would be the lab 112 `FilesMatch` mistake in a new costume |
| **"`grooti`'s crontab is the escalation"** | **Refuted by measurement:** `rc=126`, no `x` bit for other. And by control: the crontab *is* live (C11), so the silence is the mode, not a dead crontab. D2 |
| **"The database is the entry point"** | **Refuted, with counts.** The hint's own flag does not exist on the shipped client (`rc=7`), its host is stale, no artefact carries `rocket`'s password (34 candidates / 0 hits, 19 image layers, one whole-filesystem sweep), and 3 of the table's 4 rows are dead paths while the 4th is a URL that serves its bytes with no credential at all. D1 |
| **"The password is in the build record"** (lab 188's shape) | **Scoped negative.** All **19** layers of `docker history --no-trunc` read; none contains a credential |
| **"`/tmp/malicious.sh` is writable because `/tmp` is `1777`"** | **Wrong mechanism.** The sticky bit means `grooti` cannot unlink or replace a file `grooti` does not own. The write works because the file is **`root:grooti` `764`** — a group bit, not a `/tmp` property. F7 |
| **"Re-running the terminal with `number=16.9` reaches the ZIP"** | It does, but it is `intval` truncation, not a range bypass, and the same bytes are already reachable with `number=16` from either endpoint. Folded into F3 rather than filed separately |

---

## 10. Reward

**A reward exists and there is no `FLAG{}` in this lab.** The reward is
`/root/grooti.txt`, **1005 bytes**, md5 `18ce1c942fd5475a824db7967202adf4`, mode `0644
root:root`, inside `/root` mode `0700` — so it is reachable **only** at the escalated
identity. Its content is 15 lines of Unicode braille ASCII art of Groot.

The absence of `FLAG{}` is measured, not assumed:

| Search | Work count | Result |
|---|---|---|
| Filename sweep `*flag*` / `*FLAG*` across `/` (`-xdev`) | **3 hits each**, all inspected | false positives: perl `bits/waitflags.ph`, `bits/ss_flags.ph`, `/var/lib/mysql/debian-5.7.flag` |
| Filename sweep `*secret*` | **5 hits**, all inspected | `secrets.py` + its `.pyc`, `/var/lib/mysql/files_secret`, and the lab's own two `secret` directories |
| Filename sweep `*reward*` `*premio*` `*ctf*` | **0 hits each** | nothing |
| Filename sweep `*grooti*` | **6 hits**, all inspected | crontab, the jpg, `/home/grooti`, `/root/grooti.txt`, and **2 of my own probes** (declared) |
| Content sweep `FLAG{` `flag{` `FLAG[` `ctf{` `CTF{` over `/root /home /etc /opt /srv /var/www /var/spool /tmp /usr/local` | **0 files matched**, printed explicitly | nothing |
| `/root` at `euid=0` | 1 directory, **7 entries** | `.bashrc .local .mysql_history .profile .selected_editor .ssh grooti.txt` — plus my one witness, removed by the restore |
| `/opt` | 1 directory, **1 entry** | `cleanup.sh` |
| Files newer than `2025-07-18`, whole filesystem, excluding `/proc /sys /run /dev /tmp /var/lib/{mysql,log,cache,dpkg,apt} /usr /etc/ssl` and my own artefacts | **≈180 paths**, all inspected | dpkg/systemd/apt/php/ucf bookkeeping, `/etc/{passwd,shadow,sudoers}`, host keys, `/var/lib/mecab` dictionaries — container plumbing and package state, nothing planted |

**No `FLAG{}` here** — count it from the `FLAG{}` column of `corpus/INDEX.md` — and the
reward is reached, like lab 87, **at full privilege**: the search above ran after the
escalation, from `Uid: 0 0 0 0`.

---

## 11. Instrumentation defects

Eight. **Three would have invented a finding and two would have deleted one.** None of them
errored.

### 11.1 My ZipCrypto key schedule was fed ciphertext, not plaintext — a clean, plausible, zero-match negative
My first reader produced `None` for **every** candidate, at a rate that looked fine. ZipCrypto's
`update_keys` must be fed the **plaintext** byte; I was feeding it the ciphertext byte. A
broken keystream and a wrong password produce the same output — `None` — and 1 132 of them
would have been filed as "the ZIP does not crack".

**What caught it** was the positive control refusing to fire: the harness printed
`POSITIVE CONTROL DID NOT FIRE -- refusing to report negatives` and exited **2** rather than
sweep. §11.2 in lab 87 is the same shape — *a cryptographic step that finishes implausibly
fast did not run* — except here the rate was plausible and only the control saved it.

*Rule: the control must run before the work, and it must be allowed to abort the work.*

### 11.2 Six cipher variants "failed" because my ZIP **builder** was broken, and I spent three rounds on the wrong thing
To test candidate CRC formulations I hand-built a ZipCrypto archive in-harness. It was
malformed — my local file header declared `nlen=11` and I never appended the 11-byte
filename, so `unzip` read compressed data as the name. **All six variants reported failure,
identically, for a reason that had nothing to do with the cipher.**

The tell was structural, not numerical: six *different* implementations failing *the same
way* is not a cipher result. `unzip -l` on the archive (not `unzip -p`) listed it correctly
once the builder was fixed, and diffing against a `zipfile`-produced reference showed the
missing 11 bytes.

**The fix was to stop synthesising the control**: the positive control is now written by
**`/usr/bin/zip -P`** and read by **`/usr/bin/unzip -P`**, with my code as the third
implementor. That is lab 188's lesson one level up — *the fix was not to debug the synthesised
control, it was to stop synthesising it.* My own dict file says so about the bcrypt control
("the fix was not to debug `gensalt` but to stop synthesizing the control") and I did not
apply it until I had wasted three rounds.

### 11.3 `unzip -p file -P pw` puts the password in the member list
`unzip` stops option parsing at the zipfile, so `-P` became a **member name** and every
control returned **`rc=11 no matching files`**. That reads exactly like "the archive is
healthy, the password is wrong" — a control that could never succeed and reported it as a
negative. Caught because **`rc=11` is not `rc=82`** (82 = wrong password): one number
distinguished "my command line was wrong" from "the credential was wrong".

### 11.4 My unquoted heredoc expanded the payload's own runtime variables at authoring time
The escalation payload was written through `cat > file <<EOF` — **unquoted**. The shell
expanded `$M`, `$(whoami)`, `$EUID` and `$(date)` **on the analyst host**, so the payload that
reached the target read `echo "marker="` and wrote to `/tmp/.root.txt`: **not a random,
distinguishable marker**, which is exactly what the oracle was supposed to be.

This is self-corrections §15 in a new costume — *a sanitiser that rewrites the language it
never validated*, except the rewriting step was my own authoring, not the target's. Caught
because I looked at the files the payload actually produced instead of assuming it had run;
the fixed version is built as a **Python string literal** so no shell ever sees it.

### 11.5 A host-side redirect inside a compound command (§17, hit again)
```
printf '<?php …' > /var/www/html/unprivate/secret/lab83_handler.php
bash: line 13: /var/www/html/unprivate/secret/lab83_handler.php: No such file or directory
```
The `< file` was redirected by the **analyst's** shell, not inside the container. The
sibling `docker exec … printf … > file` in the same command had succeeded, and the two
disagreeing is what exposed it — the same structural tell §17 prescribes.

### 11.6 My first `test -x` positive control could not fire
The control for "is `/opt/cleanup.sh` executable by `grooti`?" was `touch lab83_x; test -x
lab83_x`. **`touch` creates `0644`**, so the control correctly answered `NOT-EXECUTABLE` on a
file `grooti` *does* own — and a control that can only fail proves nothing about the target.
Redone with `cp` + `chmod 700`, it returned **EXECUTABLE** and the copy ran (`rc=0`).

The *conclusion* survived either way, which is exactly why it needed reporting: **the label
carried the argument, not the evidence.**

### 11.7 `echo "rc=$?"` expanded on the analyst host, and printed `rc=0` for commands that returned 2
Inside an unquoted Python heredoc, `$?` was substituted locally. Several control lines printed
`rc=0` for commands whose real exit status was `2`. Caught because paramiko's own
`recv_exit_status()` disagreed with the printed value; **every exit status quoted in this
writeup is the transport's, not the echoed one.**

### 11.8 `ls -l /root/<marker>` → `Permission denied`, whether or not the marker exists
I reached for the obvious read-back and it is the obvious trap: `/root` is `0700`, so `ls`,
`cat` **and `test -e`** all answer `Permission denied` / `exists_rc=1` for a path that exists
and for one that does not. That is `[ -r ]`-style silence, and it is why the oracle is not
the `/root` witness alone: the decisive artefact is the **`/tmp` witness whose filename
records the identity**, plus a `touch` into `/root` that was proven to fail **before** the
exploit. The `/root` copy is corroboration, not the proof.

### And one accounting defect, caught in advance
Lab 188's summary column said "178 sondas" and the audited figure was **159 application-level
probes plus 65 535 ports** — two units blended. This writeup keeps three units apart
(§2.1: **110** HTTP requests, **83** authentication attempts, **1 332** candidate
verifications, **65 535** ports, **11** filesystem mutations) and refuses a single total
across them. The arithmetic is printed so it can be recomputed.

---

## 12. Reproducibility

Harness files used during the engagement are in `/tmp/opencode/l83/` on the analysis host:
`sweep_http.sh` (the status/bytes/md5/`X-Redirect-By`/`Location` probe), `zipcrypto.py`
(ZipCrypto reader **plus** the self-test), `crack83.py`, `sshsweep.py`, `hop1.py`–`hop7.py`,
and the `ev/` evidence directory. None is required to reproduce any result above: every claim
is quoted with its literal response, its `file:line`, or its work count.

The recovered SSH password and the 34-candidate wordlist are deliberately **not** reproduced
in full here, consistent with the rest of the corpus; the wordlist's md5
(`cb6eb006820251ca5bd363a0e1e7c87a`) and the ZIP password's location
(`imagenes/README.txt`) are recorded so the claim is checkable.

**Lab state at the end of the engagement: restored from the image and verified positively**,
eight checks — `/tmp/malicious.sh` back to md5 `e3d665a93b340cf861df4b34208e79fd`, mode
`764 root:grooti`, 221 B; `/root/grooti.txt` md5 `18ce1c942fd5475a824db7967202adf4`, 1005 B;
`/var/spool/cron/crontabs/grooti` back to **1117 B** (its shipped size); `/tmp` containing
only `malicious.sh` and MySQL's own `tmp.ngOCkV7Loy`; `password1.txt` back to **14 B, dated
Jul 22 2025** — the file my own enumeration POST had deleted, restored from the image;
`find /var/www/html` back to **22 entries** with **0** probe dirs and **0** `.htaccess`;
`/root` containing only `grooti.txt`; and every baseline HTTP hash identical to the opening
sweep (`/` 1436 B `3663afdaeed4`, `/unprivate/` 939 B `99c82aa14660`, `password1.txt` 14 B
`00b0dc0ef859`, `password16.zip` 429 B `f04703f0c72c`, `/.htaccess` 403 `dd525d40a0e7`,
`/documentos/` 404 `f2e790ff3d9a`). Recreate, never undo.

**And re-verified again after the E9 probes that followed it** (a second `.php` handler probe
and four further `generate.php` POSTs were run on the restored instance), because a restore is
a claim until it is re-checked against the thing the restore is supposed to produce: docroot
**22** entries, **0** probe artefacts, `/tmp` holding only `malicious.sh` and MySQL's own
`tmp.ngOCkV7Loy`, `/root` holding only `grooti.txt`, `password1.txt` still **14 bytes, mtime
`2025-07-22`** — i.e. the `number=99` probe created and unlinked `password99.txt` through the
target's own code and left nothing — and SSH still answering `uid=1001(grooti)`.