# ROAD TO OLYMPUS — DockerLabs lab 113 (Difficult)

**Target:** three hosts, deployed as three separate images
**Date:** 2026-09-28
**Reward obtained:** **none exists.** No `FLAG{}`, no reward text, no completion token on any of the three hosts. Demonstrated by exhaustive search in §6 — reported as an absence, not invented.
**Lab verdict:** three-host pivoting engagement fully traversed. Root on hosts 1 and 2; host 3 reached, its writable surface obtained and proven, its credential-gated surface not.
**The transferable result:** the transport decision criterion and its verification discriminator, in §10. The lab itself is a thin wrapper around them.

---

## 1. Autocorrección (read this first)

Five times in this engagement I asserted something and measurement contradicted it. Three of the five produced clean, believable answers that were wrong, and two of those would have been reported as findings.

### 1.1 I built a reverse tunnel, watched it register a session, and it routed nothing

The most important error in the engagement, and the reason §10 exists.

To make Zeus (`30.30.30.0/24`) reachable I put a `chisel server` on **Poseidon** and ran a `chisel client` on **Hades** asking for `R:socks`. The logs were perfect:

```
2026/09/28 14:57:24 server: session#1: tun: proxy#R:127.0.0.1:1080=>socks: Listening
```

A session, a SOCKS remote, a "Listening" line. It read exactly like a working tunnel. It routed nothing.

`R:` means **reverse**: the *server* listens and the traffic is proxied *through the client*. So that SOCKS listener was bound on **Poseidon's loopback**, not on my host. My existing proxy at `127.0.0.1:1080` gained no route to Zeus. Probing Zeus through it returned `OPEN: []` — which is byte-for-byte what "Zeus is down" looks like, and byte-for-byte what "my tunnel is wrong" looks like.

The correction was to invert the arrangement: `chisel server` on **my** host, `chisel client` on the far end. Now the listener lands where I can use it:

```
$ curl --socks5-hostname 127.0.0.1:1081 http://30.30.30.2/ -o /dev/null -w 'HTTP %{http_code}\n'
HTTP 200
```

**The rule this produced:** a registered tunnel session is a claim about the *control plane*, not a measurement of the *data plane*. See §10.3.

### 1.2 My yescrypt oracle returned a confident negative for every input, including wrong ones

I needed to test password candidates against Poseidon's and Zeus's `$y$j9T$` hashes. My first oracle used the salt string as it appeared in `/etc/shadow`, and every candidate returned `False`:

```
b'P0seid\xc3\xb3n2022!'  match=False
b'cerbero'               match=False
```

A uniform negative across eight candidates is the signature of a *dead* detector, not of eight wrong passwords. Checking the same candidate against Hades — where I already knew the answer — should have returned `True`, and returned `False` too. The oracle was broken, not the passwords.

The bug: my self-test salt was the wrong length, and glibc's yescrypt returns `*0` for a salt it rejects, which I had not checked for. With a correctly-sized 22-character salt the oracle went live immediately:

```
ORACLE LIVE: True
b'P0seid\xc3\xb3n2022!'  match=True
```

**I had already recorded "the documented password does not work" as a finding.** It was an artefact of my own harness. This is the fourth appearance across the series of a detector pointed at something that cannot succeed, and the second appearance of it producing a *negative* dressed as a conclusion.

### 1.3 I read a base32 "password hint" as authoritative and it was an encoding decoy

Hades' index template carries, in an HTML comment, what is presented as the real SSH password:

```
JZKECZ2NPJAWOTT2JVTU42SVM5HGU23HJZVFCZ22NJGWOTTNKVTU26SJM5GXUQLHJV5ESZ2NPJEWOTLKIU6Q====
```

Decoded base32 → base64 → bytes:

```
50 30 73 65 69 64 f3 6e 32 30 32 32 21
```

which reads as `P0seid` + `0xf3` + `n2022!`. The `0xf3` is Latin-1 `ó`. The visible password table on the same site gives `P0seidón2022!` — and that one, sent as **UTF-8** (`0xc3 0xb3`), is what the hash actually matches:

```
503073656964c3b36e3230323221  match=True
```

The hint is a trap that only fires if you decode it and believe the result. The correct procedure was to treat the hint as a *candidate generator* and settle it against the hash — which is what §1.2 finally forced me to do. **A hint that decodes cleanly is not thereby correct.**

### 1.4 Three "port in use" errors I attributed to the target

The hop-2 client refused to start with `Server cannot listen on R:1445=>30.30.30.2:445`, and the same for `R:1021`, then `R:2222`. I initially read that as the tunnel rejecting the remote. It was not: port **2222 was already bound on my own workstation** by a process I could not see (no PID exposed to an unprivileged `ss`), and the other failures were stale chisel clients of my own still holding listeners. Three separate causes, one symptom, and in all three cases the instrument was the problem.

The generalisable error: I attributed an error to the far side of a tunnel before confirming the near side was clean. `ss` on the *originating* host is the cheap check and I skipped it twice.

### 1.5 I misread chisel's SOCKS5 reply and briefly believed SMB was dead

My scanner read 4 bytes after the SOCKS `CONNECT` reply. Chisel prepends a 4-byte marker (its server port, `0x031e1e1e`) before the bound address, so every banner came back as `b'\x1e\x1e\x1e\x03\x92\xec'` — garbage that looked like a protocol refusing me. Reading 10 bytes gave `220 (vsFTPd 3.0.5)` and `SSH-2.0-OpenSSH_8.9p1` immediately.

This is the "silence indicts your framing, not the target" case applied to a SOCKS layer instead of a protocol: I had invented a framing from a partial read, then treated the resulting gibberish as evidence about Samba.

---

## 2. Real surface, per host

The name and the catalogue entry are both wrong about the tooling. The landing page describes **Ligolo-ng** in detail; the status line for the lab says **Chisel**; **neither is installed on any host**. The pivot required me to supply the transport myself.

### Host 1 — Hades (`10.10.10.2` / `20.20.20.3`)

| Element | Value | Established by |
|---|---|---|
| OS | Ubuntu 24.04 LTS | `/etc/os-release` |
| Ports | `22/tcp` OpenSSH 9.6p1, `80/tcp` Werkzeug 3.0.4 / Python 3.12.3 | `nmap -sV -Pn -p-` |
| Web app | Flask, 18 lines, **static content only** — no injection, no auth, no forms | `app/app.py` read in full |
| App identity | runs as **`root`** (pid 17) | `ps aux` |
| Accounts | `cerbero` (uid 1001), in group `27(sudo)` | `id` |
| Privilege | `cerbero` → `(ALL : ALL) ALL`, own password | `sudo -l` |
| Layout defect | route `/saltar` calls `render_template("saltar.html")` but the file lives at `static/html/saltar.html`, not `templates/` → the route 500s | source vs directory listing |

**The web app is not the entry point.** It is a lab manual rendered as HTML. Its only security-relevant content is the base32 decoy of §1.3. The real entry is SSH.

### Host 2 — Poseidon (`20.20.20.2` / `30.30.30.3`)

| Element | Value | Established by |
|---|---|---|
| OS | Debian GNU/Linux 11 (bullseye) | `/etc/os-release` |
| Ports | `22/tcp` OpenSSH, `80/tcp` Apache/2.4.54 (Debian) | `nmap -sV`, `Server:` header |
| Interpreter | PHP 7.4.33 CLI | `php -v` |
| App | `/var/www/html/database.php` — `PDO::query()` on raw POST input | source read in full |
| DB | SQLite `/var/www/html/dioses.db` (root-owned, in the docroot) | source + query |
| **Webroot** | **`drwxrwxrwx` (0777), `www-data:www-data`** | `ls -la /var/www/html` |
| Accounts | `megalodon` (uid 1000), in group `27(sudo)`, `(ALL:ALL) ALL` | `id`, `sudo -l` |
| Tooling | no python3, nc, socat; has curl, perl, gcc | `command -v` |

Full TCP scan performed through the tunnel: `1-65535` → only `22` and `80`.

### Host 3 — Zeus (`30.30.30.2`)

| Element | Value | Established by |
|---|---|---|
| OS | Ubuntu 22.04.4 LTS | `/etc/os-release` |
| Ports | `21` vsFTPd 3.0.5, `22` OpenSSH 8.9p1, `80` Apache/2.4.52, `139`/`445` Samba | banner reads |
| Accounts | `rayito` (1000), `hercules` (1001); hashes `$y$j9T$` yescrypt, **not recovered** | `/etc/shadow` |
| **Sudoers** | **`rayito ALL=(ALL) NOPASSWD: ALL`** | `/etc/sudoers` |
| Samba | `[shared] path=/samba/shared writable=yes guest ok=yes read only=no`, dir mode `drwxrwxrwx` | `smb.conf`, `ls` |
| FTP | `anonymous_enable=NO`, `local_root=/home/hercules`, `userlist_enable=YES` | `vsftpd.conf`, live `530` |
| Webroot | `drwxr-xr-x root:root`, **stock Ubuntu default page**, not writable | `ls`, 10671 bytes of default HTML |
| Anomaly | `/start.sh` invokes `./smb_request.sh` — **the file does not exist** | `find / -name smb_request*` → nothing |
| Anomaly | `/home/hercules/muerte_a_kratos.exe` is **`ELF 64-bit ... not stripped`**, not a PE | `file` |

Full TCP scan from Poseidon: `1-65535` → only `21, 22, 80, 139, 445`.

---

## 3. Findings

### 3.1 Unfiltered SQL execution — CWE-89

`database.php` passes the `buscar` POST parameter straight into `PDO::query()`:

```php
$stmt = $conexion->query($buscar);
```

The only guard is a keyword blacklist:

```php
$blacklist = array('USERS', 'PASSWORDS', 'VERSION', 'UNION', 'INSERT', 'UPDATE', 'DELETE');
```

**The blacklist names tables that do not exist.** The credential tables are `usuarios` and `contrasena`:

```sql
CREATE TABLE usuarios (id INTEGER PRIMARY KEY AUTOINCREMENT,
    nombre_usuario TEXT NOT NULL UNIQUE, email TEXT UNIQUE);
CREATE TABLE contrasena (id INTEGER PRIMARY KEY AUTOINCREMENT,
    id_usuario INTEGER NOT NULL, contrasena_hash TEXT NOT NULL UNIQUE, ...);
```

`USERS` does not match `usuarios`; `PASSWORDS` does not match `contrasena`. The filter is a **strict subset of what it appears to protect** — it blocks the English words an attacker would guess and none of the Spanish words the schema actually uses.

**Evidence, executed through the tunnel:**

```
$ curl --socks5-hostname 127.0.0.1:1080 -X POST http://20.20.20.2/database.php \
       --data-urlencode 'buscar=SELECT * FROM usuarios'
1 | Poseidon | poseidon@olimpo.deux
2 | megalodon | megalodon@olimpo.deux

$ curl ... --data-urlencode 'buscar=SELECT * FROM contrasena'
1 | 1 | $sha1$oceanos$QqFgxFPmqRex1ZKFCZ2ONJKWOTTNKFTU46SBM5ZKFCZ2ONJKWOTTNKFTU4GQPdkh3nQSWp3I=
2 | 2 | $sha1$hahahaha$JZKFCZ2ONJKWOTTNKFTU46SBM5HG2TLHJV5ECZ2NPJEWOTL2IFTU26SFM5GXU23HJVVEKPI=
```

`sqlite_master` enumeration returns the full schema, and the `SELECT sql` column returns every `CREATE TABLE` statement, so the schema is fully readable.

**Impact:** unauthenticated read of the entire database including the credential table, and arbitrary query execution. Also unauthenticated *write* — the blacklist blocks `INSERT`/`UPDATE`/`DELETE` as keywords, so those specific verbs are filtered, but nothing prevents `PRAGMA`, `ATTACH`, or `ALTER`. The docroot being `0777` (CWE-732) means the SQLite file itself is replaceable by any local user.

**Root cause:** the filter validates a *representation* — a set of English substrings — rather than authorising the operation. A blacklist cannot enumerate what it does not know exists, and the author wrote the filter against the table names they expected, not the ones they shipped. The same shape as `decision-making.md` §1, pointed at a filter instead of a parameter.

**Remediation:** use bound parameters. If arbitrary queries are a feature, expose them as a named, allow-listed set of prepared statements; if they are not, the `buscar` parameter is a search term and belongs in a `LIKE` clause with a bound value, never in a statement. Additionally remove the `0777` on the docroot and move `dioses.db` outside it.

### 3.2 World-writable web application directory — CWE-732

```
drwxrwxrwx 2 www-data www-data 4096 Aug 28  2024 /var/www/html
-rw-r--r-- 1 www-data www-data 1990 Aug 14  2024 database.php
-rw-r--r-- 1 root     root    40960 Aug 28  2024 dioses.db
```

The directory is `0777` while the files inside are `0644`. Any local account on Poseidon — not only `www-data` — can create, replace or delete a PHP file in the document root, which Apache then executes. `dioses.db` is root-owned but sits inside the writable directory, so it can be replaced by rename even though it cannot be edited in place.

Not used in this chain (I reached the database over HTTP, not by writing a file), reported as an independent finding because it is the same *class* as the primitive the lab hands out for free on host 3.

**Root cause:** directory permissions left at the image-build default.
**Remediation:** `0755` on the docroot, `0640` on the database, database file relocated outside the document root.

### 3.3 Passwordless full root in sudoers — CWE-250 / CWE-269

`/etc/sudoers` on Zeus:

```
rayito ALL=(ALL) NOPASSWD: ALL
```

Any authentication as `rayito` is immediately root with no second factor and no password reuse requirement. `hercules` is not in sudoers, so the two accounts have materially different privilege for no stated reason.

**Not used in this chain**, because I could not authenticate as `rayito` at all (§4.1). It is reported because it is the escalation that *would* follow from the one credential I failed to recover, and an assessor fixing only the credential problem would inherit it unchanged.

**Remediation:** drop the `NOPASSWD: ALL` line; grant only the specific commands required, with a password.

### 3.4 Unauthenticated read/write SMB share — CWE-306 / CWE-732 / CWE-284

```
[shared]
    path = /samba/shared
    writable = yes
    browsable = yes
    guest ok = yes
    read only = no
```

`map to guest = bad user` means any account that fails authentication is retried as guest. Combined with `guest ok = yes` and `read only = no`, an anonymous client gets a writable share. Proven over the wire, through the two-hop tunnel, from my workstation:

```
$ smbclient //127.0.0.1/shared -p 1445 -N -c "put /w/webshell.php webshell.php"
putting file /w/webshell.php as \webshell.php (10.7 kb/s) (average 10.7 kb/s)

$ ls -la /samba/shared/     # on Zeus
-rwxr--r-- 1 nobody nogroup   22 Sep 28 15:15 webshell.php
```

**Impact:** anonymous write to a filesystem served by the target. It did not reach the webroot (§4.2), so the impact here is *write to a non-executed directory* — which is still a persistence and staging primitive, and a foothold if anything else on the host later consumes that path.

**Root cause:** three permissive directives combined; each is individually defensible for a shared folder, and the combination is the bug.
**Remediation:** remove `guest ok = yes`; set `read only = yes` unless the share genuinely needs anonymous writes; drop `map to guest = bad user`, which silently converts "wrong password" into "anonymous access" and destroys the distinction an administrator is trying to enforce.

### 3.5 A shipped file calls a script that does not exist — CWE-1104 (incomplete / broken deployment)

`/start.sh` on Zeus, verbatim:

```bash
./smb_request.sh &
```

`find / -name "smb_request*"` returns nothing. The startup script forks a non-existent file every boot; the shell reports `./smb_request.sh: No such file or directory` to the container log and continues, so the failure is invisible from the outside — every listed service comes up healthy.

The builder's own history explains it:

```
$ cat /root/.bash_history
passwd hercules
ls
cd home
ls
cd rayito/
ls
cd ..
cd hercules/
ls
cd
ls
cd /
ls
rm -rf smb_request.sh
cat start.sh
...
```

`rm -rf smb_request.sh` was run **after** `start.sh` was written, and the reference was never removed. This is almost certainly the lab's intended trigger — a script that watches the share and does something when a file appears — and it is **absent from the shipped image**.

**Impact on the engagement:** the intended final step of the third host cannot execute. Reported as a finding in its own right, separately from the escalation, because the target is wrong in both directions at once: it hides a working primitive (the writable share) behind a documented step that cannot run.

**Remediation:** either ship `smb_request.sh` or delete its invocation; add a `set -e`-style guard so a missing file aborts startup rather than being logged and ignored.

### 3.6 A binary named `.exe` that is neither a Windows binary nor a reward — CWE-497 (inappropriate binary naming) / CWE-506

`/home/hercules/muerte_a_kratos.exe`:

```
ELF 64-bit LSB pie executable, x86-64, dynamically linked, not stripped, for GNU/Linux 3.2.0
```

Disassembly of `main` shows: `time(0)` → `srand` → `fopen("kratos.txt","w")` → a loop of 10 iterations writing a base32 header line then 9 random 32-hex-char lines → `fclose` → `fork` → in the child `execlp("bash", "bash", "-c", "echo 'Happy Hacking, here is nothing...'", NULL)`.

The `.rodata` strings are unambiguous:

```
kratos.txt
No se pudo abrir el archivo
echo 'Happy Hacking, here is nothing...'
bash
```

Executed on the target:

```
$ ./muerte_a_kratos.exe
Happy Hacking, here is nothing...
RC=0
$ head -3 kratos.txt
AGUAbABlAGMAdAByAG8AYwB1AHQANABjADEAMABuACE=
b3e5c438984ac375948e3678d5716851
b3688a0124be72306ce9252fa900151d
```

The values are `rand()` output seeded from `time(0)` — **regenerated on every run, identical in no two runs, and carrying no information**. The program is a decoy, and its own literal output string says so.

Two lessons: the extension is not the format (`file` settles it in one command), and a decoy that *executes* and *writes a file* is more convincing than one that refuses — the `RC=0` and the freshly written `kratos.txt` are what make it read as a success.

---

## 4. Controls that held (reported with the same prominence as the bugs that fired)

### 4.1 SSH on Zeus — credential wall held

Four candidate pairs across both accounts, all rejected:

```
rayito/rayito: denied      hercules/hercules: denied
rayito/Templ02019!: denied hercules/Templ02019!: denied
```

**Control positive:** the identical code path, identical SOCKS transport, was run against Poseidon with a known-good credential and returned `uid=1000(megalodon)`. The negative is therefore about the credentials, not about the tunnel or my harness. The `$y$j9T$` yescrypt hashes for `rayito` and `hercules` were not recovered, and §4.1's `NOPASSWD` escalation is consequently unreachable in this run.

### 4.2 Anonymous FTP refused — CWE-... control held

```
$ USER anonymous
530 Permission denied.
$ PASS test@test.com
503 Login with USER first.
$ SYST / PWD / LIST
530 Please login with USER and PASS.
```

`vsftpd.conf` states why: `anonymous_enable=NO`, plus `userlist_enable=YES`. The banner is served before authentication, so the service is discoverable, but no content is.

### 4.3 Samba share traversal refused

```
$ smbclient //127.0.0.1/shared -p 1445 -N -c "cd /; ls; cd ../; ls"
  webshell.php      A   22   Mon Sep 28 15:15:54 2026
  p.txt             A   30   Mon Sep 28 15:13:05 2026
  webshell.php      A   22   Mon Sep 28 15:15:54 2026
  p.txt             A   30   Mon Sep 28 15:13:05 2026
```

`cd ../` returns the same two files. The share is chrooted, so the anonymous write of §3.4 cannot be aimed elsewhere.

### 4.4 SMB write does not reach the webroot — and the negative is proven, not assumed

This is the negative result most worth stating carefully, because "the webshell 404'd" is exactly the shape of claim that can be a broken detector.

I did not infer the boundary from the 404. I proved both halves:

*positive control* — the write **succeeded**, so the channel is connected:

```
putting file /w/webshell.php as \webshell.php (10.7 kb/s) (average 10.7 kb/s)
$ ls -la /samba/shared/
-rwxr--r-- 1 nobody nogroup   22 Sep 28 15:15 webshell.php
```

*negative* — the web server still does not serve it:

```
$ curl --socks5-hostname 127.0.0.1:1081 http://30.30.30.2/webshell.php -w 'HTTP %{http_code}'
HTTP 404
$ ls -la /var/www/html/     # on Zeus — unchanged
-rw-r--r-- 1 root root 10671 Aug 26  2024 index.html
```

The write lands in `/samba/shared` and the docroot is a different directory with different ownership. The 404 is a statement about the filesystem, not about my detector.

---

## 5. Chain, in order, with each jump justified

| # | From → To | Action | Justification |
|---|---|---|---|
| 0 | my host → Hades | `nmap -sV -Pn -p- 10.10.10.2` | Entry. Port 80 is a static Flask app with no input; SSH is the only dynamic surface. |
| 1 | Hades | Read `app.py` in full (18 lines) before probing | Established there is no injection sink, so the web tier is not the entry. |
| 2 | Hades | Recover the SSH password via the base32 comment, then **verify it against `/etc/shadow`** | The decoded hint was wrong (§1.3). The hash is the authority. |
| 3 | Hades | `id` → `uid=1001(cerbero)`, group `27(sudo)` | Execution identity measured, never assumed. |
| 4 | Hades | `sudo -l` with own password → `(ALL : ALL) ALL` | Root. `id` again → `uid=0(root)`. |
| 5 | my host → Poseidon | Probe `20.20.20.2` directly: **refused**. From Hades: `22` and `80` open | Establishes that the hop is required *and* that the segmentation is real. Measured from both sides before any tunnel. |
| 6 | — | Decide transport: reverse SOCKS, `chisel server` here / `chisel client` on Hades | Full criterion in §10. |
| 7 | — | **Discriminator:** `curl --socks5 127.0.0.1:1080 http://20.20.20.2/` → `HTTP 200` | Not "the port is open". A third party's request traversing the tunnel. |
| 8 | Poseidon | `nmap`-equivalent full TCP scan through the SOCKS: `1-65535` → `22, 80` | Confirm the surface is small enough to reason about. |
| 9 | Poseidon | Read `database.php` and `dioses.sql` before attacking | The sink and the schema, both before the first probe. |
| 10 | Poseidon | `SELECT * FROM usuarios` / `FROM contrasena` | The blacklist names tables that do not exist (§3.1). |
| 11 | Poseidon | `megalodon` / `Templ02019!` → `id` → `uid=1000`, sudo group → `uid=0` | The DB hash was `$sha1$` and not the SSH credential; the yescrypt hash was, and the documented password matched it. |
| 12 | Poseidon → Zeus | Probe `30.30.30.2` from Poseidon: `21, 22, 80, 139, 445` | Zeus is a *different* surface. Assuming host 2's shape here would have missed FTP and SMB entirely. |
| 13 | — | Second hop: `chisel server` here (port 9002), `chisel client` on Poseidon, reached via a forward from Hades | Chained because Poseidon cannot reach my host directly (macvlan isolation). |
| 14 | — | **Discriminator:** `curl --socks5-hostname 127.0.0.1:1081 http://30.30.30.2/` → `HTTP 200`, **and** Zeus' `access.log` records the peer as `30.30.30.3` | Second half is the attribution control: it proves the request originated from Poseidon's leg, not from a local artifact. |
| 15 | Zeus | Per-service reverse forward `R:1445:30.30.30.2:445`; `smbclient -N` | Chosen over SOCKS because SMB needs its own stateful multi-packet session and the tooling wants a real TCP peer. |
| 16 | Zeus | `smbclient -L` → `shared` visible with no credentials | Anonymous enumeration. |
| 17 | Zeus | `put` a file, then read `/samba/shared/` **on the target** to confirm | Write primitive, proven by a nonce-style witness created in this run (§4.4). |
| 18 | Zeus | Attempt the escalation: write `webshell.php` → `HTTP 404` | The lab's obvious move, and it does not work. The boundary held. |

**The two SSH hops are the same bug twice.** `cerbero` and `megalodon` each have `(ALL:ALL) ALL` and each reuses their own login password for `sudo`. Neither account needed a second credential. Reported as one finding class in §3 with two independent instances, because the fix is identical and the instances are structurally identical — but they are two hosts and two separate sudoers entries.

---

## 6. Reward — literal

**There is no reward.** This is reported as an absence, with the search that establishes it.

```
# On all three hosts:
$ grep -rliE 'flag\{|CTF\{' / --exclude-dir=proc --exclude-dir=sys --exclude-dir=dev
(no output on any host)

$ grep -rliE 'flag|ctf\{' / --exclude-dir=proc --exclude-dir=sys --exclude-dir=dev --exclude-dir=usr
(only /var/lib/dpkg/status and package metadata — no application content)
```

Additional places checked, all negative: every table in the Poseidon SQLite database via `sqlite_master` and `SELECT sql`; `/root/`, `/home/*`, `/samba/shared`, `/srv/ftp`, `/var/www/html` on all three hosts; the Hades app directory and templates; `/root/.bash_history` on Zeus.

The one artefact that looks like a reward is the decoy of §3.6, and it is self-labelling: `echo 'Happy Hacking, here is nothing...'`. Its `kratos.txt` output is `rand()` seeded from `time(0)`, so it differs on every execution and encodes nothing.

Six previous labs in this series also had no reward. In each case the correct output was the same: state the absence, show the search, do not manufacture a value.

---

## 7. Tested / not tested / could not test

**Tested**
- Full TCP `1-65535` on all three hosts (Hades and Poseidon from my host / through the tunnel; Zeus from Poseidon, and again through the hop-2 tunnel). No UDP scan was attempted on any host — see the gap below.
- Source read in full on every reachable host before attacking: Hades `app.py` + templates, Poseidon `database.php` + `dioses.sql` + `smb.conf`/`vsftpd.conf`/`sudoers`, Zeus `start.sh` + `smb.conf` + `vsftpd.conf` + the ELF's disassembly.
- The SQLi blacklist tested both by keyword (`UNION`, `VERSION` → rejected as designed) and by real table name (`usuarios`, `contrasena` → returned data).
- SMB: anonymous list, anonymous write, `cd ../` traversal, webroot reachability — each with a positive control.
- The yescrypt oracle, once repaired, against Hades (`True` expected, `True` obtained) before being used on Poseidon and Zeus.
- Binary reversal: `file`, `strings`, `objdump -d` of `main`, and execution on the target.

**Not tested**
- Credential recovery for `rayito` and `hercules` beyond 35 targeted candidates. The `$y$j9T$` yescrypt parameters (`j9T` = 7 rounds) are strong; a full dictionary or mask attack was out of scope for a pivoting lab and was not attempted.
- Whether the SMB share is consumed by anything on Zeus, given that `smb_request.sh` is absent (§3.5). With the watcher missing, nothing appears to.
- HTTP-level testing of anything on Zeus beyond `/` and `/webshell.php`. The docroot holds a single stock default page, so there is no application surface.
- Whether the `0777` docroot on Poseidon was intended as a hint toward a planted webshell. I reached the database directly, so the write primitive was never needed.

**Could not test — declared as a gap, not a closed door**
- **No UDP scan on any of the three hosts.** `nmap -p-` is TCP. Every host publishes an SSH service and the operational design suggests a management plane, but I have **no evidence either way** about UDP. This is coverage I did not perform, and it is recorded as such rather than as a finding.
- `nmap --proxy socks5://` failed on this build (`libnsock proxy_node_new(): Invalid protocol in proxy specification string`), so all tunneled scanning was done with a purpose-written SOCKS5 client. The client's own reach was proven before use (§5 steps 7 and 14), but it is not nmap and does not carry nmap's version-detection scripts; service versions on Poseidon and Zeus come from banner reads and `Server:` headers, not full `-sV` probes.
- SMB version and dialect enumeration was not completed. The anonymous `smbclient -L` succeeded, which is the functional result that mattered, but the negotiated dialect and Samba version are unmeasured.
- Whether the Hades `/saltar` route's 500 is a live defect or masked by an exception handler was not resolved; the source shows `render_template` on a file that is not in `templates/`, which is sufficient to explain it.

---

## 8. Not proven, versus discarded with a reason

These are separated deliberately, because "I did not do it" and "I did it and it failed" carry different information.

**Not proven**
- Whether `rayito` or `hercules` is the intended Zeus credential, and whether the `NOPASSWD: ALL` line is reachable in the lab's intended solution. It almost certainly is — the line is unconditional and `rayito` is a normal login — but I did not get there.
- Whether the Poseidon `$sha1$` hashes in `contrasena` correspond to any real credential. The documented `Templ02019!` matched the **yescrypt** shadow hash, not the `$sha1$` one; the two are different schemes for what is presumably the same account, and only one is live for SSH. I did not determine what the `$sha1$` values protect, if anything.

**Discarded, with the reason**
- **Ligolo-ng as the intended transport** — described at length by the target's own landing page, but not installed on any host, and not needed once a SOCKS layer exists. *Discarded on availability, not on merit.*
- **Chisel as the "intended" tool** — named in the lab's status line, also not installed. Supplied by me; treated as a means, not as the lesson.
- **Anonymous FTP on Zeus** — `anonymous_enable=NO` in config, and `530` on the wire. *Control held*, not a gap.
- **Traversing out of the Samba share** — `cd ../` returns the same listing. *Control held.*
- **Reaching the webroot through the share** — the share is `/samba/shared`, the docroot is `/var/www/html`; the write succeeded and the fetch 404'd. *Control held, proven with a positive (§4.4).*
- **Cracking the Zeus yescrypt hashes with the lab's own documented passwords** — tested the documented Poseidon password and the account-name patterns against both Zeus hashes. No match. The hashes are not derived from any value published on any of the three hosts.

---

## 9. What this lab is actually about

The lab is a thin wrapper. Its three bugs (unfiltered SQL behind a blacklist that names the wrong tables, a `0777` docroot, an anonymous writable share) are unremarkable, and one of its three hosts is unreachable without a credential I could not recover. What the lab supplies that is genuinely hard to improvise is the **transport decision** and — much more importantly — **the way that decision is verified**.

Three things it gets right that a technician working from memory gets wrong:

1. **The name and the documentation both lie about the tooling.** The page teaches Ligolo-ng. The status line says Chisel. Neither is installed. A learner who trusts the page and has no chisel is stuck at the first hop, and a learner who has chisel but reaches for the wrong *mode* gets a tunnel that registers a session and routes nothing — which is §1.1, and it cost me a full cycle and nearly produced a "Zeus is unreachable" conclusion written into a report.
2. **The chain punishes assuming the next host resembles the last.** Poseidon is Apache + PHP + SQLi + a `0777` docroot. Zeus is Apache + FTP + **SMB** + SSH, and its interesting primitive is not injection at all. The share is what a lab of this shape would call the entry, and it is invisible if you carry Poseidon's model of "web app = the surface" across the hop. §5 step 12 exists for this reason.
3. **The obvious final move does not work.** The writable share does not reach the webroot, and the script that was presumably going to consume it was `rm`'d by the builder before the image shipped. The lab's happy path is broken in the build, and the thing it would have unlocked is a decoy anyway.

The design lesson for an author is in §3.5 and §3.6 together: the lab ships three self-labelling artefacts — a base32 "password" that is off by an encoding, a `.exe` that is an ELF printing "here is nothing", and a startup line for a script that no longer exists. Each is individually detectable, but a learner has to notice that *decoding cleanly* is not the same as *being right* three separate times. That is a good exercise. It is a poor exercise if the intended solution is only reachable through one of them, and here it is not.

---

## 10. Pivoting: the decision criterion, per transport, and the discriminator

This is the part of the lab worth publishing, because it is the class the rest of the methodology has no oracle for. Everything below was exercised on this engagement, including the parts that went wrong.

### 10.1 The one question that separates the transports

> **Where does the legitimate connection originate?**

Not "which tool do I have" and not "which is fastest". Every mode exists to place a listener on one side and an origin on the other, and the mode is determined by which of those two the *target* must be.

| Question you are answering | Mode | Direction | Who originates |
|---|---|---|---|
| Must host A reach a port of host B? | `ssh -L`, `chisel` local forward (`<lport>:<rhost>:<rport>`), `socat` | forward | A's side |
| Must someone *outside* reach a port on A? | `ssh -R`, `chisel R:` reverse | reverse | the far end, through A |
| Must my tools reach an arbitrary unknown port surface, with raw `connect()` and no per-port setup? | SOCKS5 / `chisel R:socks` | reverse + dynamic | the far end, on demand |
| Must the *whole segment* be routable, including UDP and ICMP, and tool invocation must be unchanged? | TUN device (ligolo, `wg`) | tun | the far end, transparently |

**Why SOCKS and not a per-port forward, here.** Zeus' port surface was unknown at the moment I had to commit to a transport. A forward gives one port; I would have had to rebuild the tunnel for every port I discovered, and the discovery itself needs a port. SOCKS terminates arbitrary `connect()` at the far end, so one tunnel serves `nmap`, `ssh`, `curl` and `smbclient` unchanged. That is the whole argument, and it is a question about the *target's* state, not about the tool.

**Why not ligolo despite the target's own recommendation.** A TUN device is the right answer when the segment must appear as a real interface — when the tooling you will run assumes a local NIC, when you need UDP or ICMP, or when you want routing to "just work". It also requires elevated privileges locally (a TUN device), which is a real cost in a containerised or unprivileged operator environment. For a TCP-only engagement over a known segmentation, SOCKS is strictly less invasive. I note the lab's page is *not* wrong that ligolo is the better tool for pivoting generally — it is wrong that it is present.

### 10.2 The information each transport needs before it can work

This is the part that produces the silent failure, and the two transports fail in opposite ways:

- **A reverse tunnel needs a port on my side that the far end can reach.** If it cannot dial me, the client retries forever and logs `connect: connection refused` — an error at least, and a safe one. Poseidon could not reach my host directly (macvlan isolation) and could not resolve `10.10.10.1`; that is why hop 2 needed an intermediate forward from Hades.
- **A forward needs the destination to be reachable from wherever the connection is terminated.** If I forward `1080 → 20.20.20.2:22` but the proxy cannot see `20.20.20.2`, the listener opens and every connection to it fails. **The port is open and nothing arrives.** This is the dangerous case: it is indistinguishable from a target that is down.
- **A SOCKS needs both of the above, plus a client that speaks SOCKS.** `nmap --proxy socks5://` is not universally supported (`libnsock proxy_node_new(): Invalid protocol in proxy specification string` on this build), and `proxychains4` was not installed. A SOCKS you cannot point a tool at is a SOCKS you do not have.
- **Chained hops need each intermediate to relay for the next**, and the relay must be declared *by the hop below it*, not assumed. Hop 2 worked because Hades' hop-1 client carried an extra forward (`19002:10.10.10.1:9002`), which is a different remote on an existing session — not a second independent tunnel.

### 10.3 The discriminator: prove traffic crosses, not that a port exists

**A tunnel session is a claim about the control plane. It is not a measurement of the data plane.** This is the single most useful thing to state about pivoting, and it is what §1.1 cost me.

Three levels of evidence, weakest to strongest:

1. **The client logged `Connected`.** Says the websocket to the server is up. Says nothing about routing. The wrong arrangement in §1.1 produced a *registered session with a "Listening" SOCKS* and still routed nothing.
2. **A port is open locally.** Says the listener bound. Says nothing about where traffic goes when it arrives.
3. **A third party answered through the tunnel, and I can attribute its answer to the far end.** This is the only one that counts.

For (3) on this engagement, per hop:

```
# hop 1 — did Poseidon answer, through Hades?
$ curl --socks5-hostname 127.0.0.1:1080 http://20.20.20.2/ -o /dev/null -w 'HTTP %{http_code}\n'
HTTP 200

# hop 2 — did Zeus answer, through Poseidon?
$ curl --socks5-hostname 127.0.0.1:1081 http://30.30.30.2/ -o /dev/null -w 'HTTP %{http_code}\n'
HTTP 200
```

And the attribution half — the request did not merely *succeed*, it succeeded **as Poseidon**:

```
$ tail -3 /var/log/apache2/access.log     # on Zeus
30.30.30.3 - - [28/Sep/2026:15:04:26 +0000] "GET / HTTP/1.1" 200 10926 "-" "curl/8.18.0"
```

`30.30.30.3` is Poseidon's leg. My workstation is `10.10.10.1` and has no route to `30.30.30.0/24` at all — so this log line is proof that the bytes came through Poseidon, and it would have read differently if a local artefact had answered. That is a witness created by the component under test, carrying information the `HTTP 200` did not.

A second, cheaper discriminator I used and recommend: **compare against the known-good path.** Running the identical tool, with the identical credentials, against a host I *can* reach, and getting the expected answer, converts every subsequent negative into a statement about the target. That is how the Zeus SSH rejection in §4.1 is trustworthy rather than a guess.

### 10.4 The error of not pivoting, and the error of pivoting too far

Both are scope decisions, and both are made *before* the tunnel goes up, not after.

- **Not pivoting is the default.** Each new segment is a new scope question. In a real engagement, reaching a host that was not in the written scope is an incident regardless of how it was reached — the fact that a tunnel made it convenient is an aggravating detail, not a mitigation.
- **Pivoting too far is the failure mode of a tool that makes it easy.** Once a SOCKS exists, `nmap -p-` on the next range is one keystroke and requires no decision. The range graph here is three hosts and three networks; a tunnel that has been handed a SOCKS will happily scan whatever else the far end can see, and the report then contains findings about systems the client never agreed to be tested.
- **The correct artifact is the scope graph, and it is declared before the tunnel is built.** For this engagement:

```
        [ operator workstation ]
                 10.10.10.1
                      |
                 pivoting1 (10.10.10.0/24)
                      |
                 HADES 10.10.10.2  ── hop 1: reverse SOCKS ──►
                 20.20.20.3  ◄── macvlan, internal ──┐
                      |                             │
                 pivoting2 (20.20.20.0/24)          │
                      |                             │
                 POSEIDON 20.20.20.2 ── hop 2: reverse SOCKS via a forward from Hades ──►
                 30.30.30.3  ◄── macvlan, internal ──┘
                      |
                 pivoting3 (30.30.30.0/24)
                      |
                 ZEUS 30.30.30.2
```

Three hosts, two hops, one declared perimeter at each macvlan boundary. The second and third networks are `--internal`, so no host on them has a route off the lab. **The reachability graph is the finding; the tunnels are the means.** A report whose summary is "I ran chisel with these flags" has reported the method and nothing else; a report that says "Hades and Poseidon were in scope, Zeus was not directly routable and became reachable only through a second hop, and here is the chain of decisions that made it reachable" has reported the engagement.

### 10.5 Chisel syntax notes that cost time

Recorded because they are version-specific and the errors are unhelpful:

- `F:` and `L:` prefixes are **invalid** in chisel 1.10.1 — `Invalid remote`. A local forward is written bare: `<localport>:<remotehost>:<remoteport>`, e.g. `19002:10.10.10.1:9002`.
- `R:` binds the listener on the **server**. This is the §1.1 trap and it is the most important line in this subsection.
- Two reverse remotes on one server need distinct local ports: `R:socks` (defaults to `1080`) and `R:127.0.0.1:1081:socks` for the second hop. A second hop requesting a bare `R:socks` collides with the first and the client logs `Server cannot listen on R:127.0.0.1:1080=>socks`.
- Reverse remotes below port 1024 are refused by an unprivileged server, and a port already in use **on your own host** produces the same `Server cannot listen` message as a genuine remote failure. Check `ss` locally before blaming the far side.
- The SOCKS5 `CONNECT` reply is 10 bytes, not 4: chisel puts a 4-byte marker (its own server port) where `BND.ADDR` would be. A 4-byte read yields banners like `b'\x1e\x1e\x1e\x03\x92\xec'`, which look like a hostile protocol and are entirely your own framing error (§1.5).

---

## 11. Restoration

All three containers were destroyed and recreated from the images, and the network topology rebuilt:

```
$ docker rm -f 1_hades_container 2_poseidon_container 3_zeus_container
$ for n in pivoting1 pivoting2 pivoting3; do docker network rm $n; done
$ docker network create --subnet=10.10.10.0/24 pivoting1
$ docker network create -d macvlan --subnet=20.20.20.0/24 --gateway=20.20.20.1 \
      --internal --opt macvlan_mode=bridge pivoting2
$ docker network create -d macvlan --subnet=30.30.30.0/24 --gateway=30.30.30.1 \
      --internal --opt macvlan_mode=bridge pivoting3
$ docker run -d --network=pivoting1 --name 1_hades_container 1_hades:latest
$ docker run -d --network=pivoting2 --name 2_poseidon_container 2_poseidon:latest
$ docker run -d --network=pivoting3 --name 3_zeus_container 3_zeus:latest
$ docker network connect pivoting2 1_hades_container
$ docker network connect pivoting3 2_poseidon_container
```

Verified after rebuild:

```
1_hades_container    -> pivoting1=10.10.10.2  pivoting2=20.20.20.3
2_poseidon_container -> pivoting2=20.20.20.2  pivoting3=30.30.30.3
3_zeus_container     -> pivoting3=30.30.30.2
```

All three `Up`, all four original services listening on Zeus, and the segmentation still enforced from the operator's position (a direct probe of `20.20.20.2` and `30.30.30.2` from the workstation is refused without a tunnel). The only residue from the engagement is the two files written through the guest share during §4.4, which are removed by the container recreation.
