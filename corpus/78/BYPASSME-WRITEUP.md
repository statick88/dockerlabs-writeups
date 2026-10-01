# 78 Bypassme — writeup

**Difficulty:** *fácil* · **Catalogue line:** `78|Bypassme|facil|information disclosure, web fuzzing, credential leakage`

**Headline: the catalogue named one of the three things this lab actually
contains, and the two things it does contain that matter are not on the list.**
"Web fuzzing" is a method, not a vulnerability. "Credential leakage" is a real
defect and is **not on the path of anything** — I removed it and the entire chain
was unchanged. The load-bearing disclosure is named. The two entry points that
make the whole thing reproducible with zero knowledge — a hardcoded credential
and a substring-match authentication bypass — are **not** in the catalogue at
all.

---

## Surface

```
$ nmap -sV -Pn -p- --open 172.17.0.2
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.11 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.58 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
Not shown: 65533 closed tcp ports (conn-refused)
```

**Second instrument on the sockets**, so an absent surface is measured and not
inferred (`/proc/net/tcp`, `/proc/net/tcp6`, `/proc/net/udp`, `/proc/net/udp6`,
one header line counted on each):

| File | Listeners (`st 0A`) | Notes |
|---|---|---|
| `/proc/net/tcp` | **2** — `00000000:0016` (22), `00000000:0050` (80) | 6 further rows are `st 06` (TIME_WAIT) to `172.17.0.1` |
| `/proc/net/tcp6` | **1** — `[::]:0016` (22) | same sshd, v6 |
| `/proc/net/udp` | **0** | header only |
| `/proc/net/udp6` | **0** | header only |

`nmap -p-` and `/proc/net/tcp*` agree exactly: 2 TCP services, **0 UDP**. No
management plane, no BMC.

**Hidden surface found, and how:** none beyond the process list. The entrypoint
`/etc/.start_services` names four things —

```
#!/bin/bash

service apache2 start
service ssh start
service cron start
su - conx -c "/home/conx/.s"
tail -f /dev/null
```

— of which the fourth launches a **world-rw Unix socket**, `/home/conx/.cache/.sock`
(`srwxrw-rw-`, `chmod 766` at `/home/conx/.s:11`), served by
`socat UNIX-LISTEN:"$SOCKET",fork EXEC:/bin/bash`. It is unreachable from any
identity I could obtain: `/home/conx` is `710 conx:albert` and `/home/conx/.cache`
is `770 conx:albert`, so only `conx` and group `albert` can traverse, and
`www-data` is in neither (`id www-data` → `groups=33(www-data)`).

---

## Stack and versions — read from version-bearing files, before anything else

| Component | Version | Source line, verbatim |
|---|---|---|
| OS | Ubuntu 24.04.2 LTS | `/etc/os-release`: `PRETTY_NAME="Ubuntu 24.04.2 LTS"` |
| Web server | Apache **2.4.58** | `dpkg-query`: `apache2 2.4.58-1ubuntu8.6`; `apache2ctl -v`: `Server version: Apache/2.4.58 (Ubuntu)` |
| Language runtime | PHP **8.3.6** | `php -v`: `PHP 8.3.6 (cli) 8.3.6-0ubuntu0.24.04.4`; `dpkg-query`: `php8.3-cli 8.3.6-0ubuntu0.24.04.4` |
| SSH | OpenSSH **9.6p1** | `dpkg-query`: `openssh-server 1:9.6p1-3ubuntu13.11`; `sshd -V`: `OpenSSH_9.6p1 Ubuntu-3ubuntu13.11, OpenSSL 3.0.13 30 Jan 2024` |
| Scheduler | cron 3.0pl1 | `dpkg-query`: `cron 3.0pl1-184ubuntu2` |
| Helper | socat 1.8.0.0 | `dpkg-query`: `socat 1.8.0.0-4build3` |

**Was the manifest's label right? It never claimed a platform, so there is
nothing to be wrong about — and I am recording that rather than manufacturing a
mislabelling.** The manifest's fourth field is
`information disclosure, web fuzzing, credential leakage`; it names three
*classes*, not a product. The artefact is a **three-file PHP application** —
`/var/www/html/index.php`, `login.php`, `welcome.php`, plus `logs/.htaccess` and
`logs/logs.txt`. `find /var/www -mindepth 1` returns **7 entries** and that is
the entire webroot. No CMS, no framework, no `composer.json`, no `vendor/`, no
plugin directory. This is the *small hand-written PHP app* shape, not the
WordPress shape (the shape labs 32 and 220 were queued as and turned out to be
Joomla 4.0.3 and a plain PHP app), and I checked for it rather than assuming it
from the difficulty label.

---

## The class, and the general statement it contributes

> **An information disclosure is only a finding when it is not what the artefact
> is supposed to serve.**

What makes it a finding rather than a smell: **there is a decision somewhere in
the deployment that says this must not be readable, and a path that does not
consult that decision.** A `Server:` banner or an `X-Powered-By` header is
hygiene — nothing ever decided the version was secret. Here the deployment made
an explicit, written decision and then shipped a second reader inside the same
server that ignores it:

```
/var/www/html/logs/.htaccess:1  <Files "*">
/var/www/html/logs/.htaccess:2    Require all denied
/var/www/html/logs/.htaccess:3  </Files>
```

That is the finding. Not "a log file is in the docroot" — the docroot is where
Apache serves from, and a file being *in* the docroot is exactly what it is
supposed to do. The finding is that the authorisation decision is enforced by
**the HTTP request path**, and `include()` is not that path.

The same class, same structure, one lab over: a source file served with its
original content type, a `.git` directory, a backup, an env file, a stack trace
carrying a path, a comment naming an internal host. **Something the deployment
assumed was not readable became readable.** The discriminator that separates this
class from "an ugly artefact" is one question: *name the control that was
supposed to hold, and name the path that bypasses it.* Here both names are
`logs/.htaccess:2` and `index.php:24`.

---

## Chain

One path, two independent entries, one hop. Every identity measured.

| # | → | Mechanism | Identity proof |
|---|---|---|---|
| 0 | unauthenticated HTTP client `172.17.0.1` | any client can obtain a session: `POST /login.php` with `password='1'='1` | the **negative control** — `admin`/`wrongpass` → `302 Location: login.php?fail=1`; and **no session at all** → `302`/0 B on `index.php?page=logs/logs.txt` |
| 1 | "admin" session | `login.php:14` grants `$_SESSION['loggedin']=true` | `Set-Cookie: PHPSESSID=…; path=/` + `Location: index.php?page=welcome`, `302` |
| 2 | full disclosure of `logs/logs.txt` | `index.php:24` `include($target)` — a filesystem include, not an HTTP request, so `.htaccess` never runs | `200` / **1 639 B** / md5 `a8e6f6d5c1d2ec8013c13b3a58e86560` |

`id` was measured at every hop that had an identity to measure:

```
$ docker exec bypassme_container id
uid=0(root) gid=0(root) groups=0(root)          <- OPERATOR-SIDE, how I read the artefact
$ docker exec -u www-data bypassme_container id
uid=33(www-data) gid=33(www-data) groups=33(www-data)   <- the identity that EXECUTES the include
$ id albert
uid=1001(albert) gid=1001(albert) groups=1001(albert)
$ id conx
uid=1002(conx) gid=1002(conx) groups=1002(conx)
$ id www-data
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

**Label the reads.** Everything under "artefact" below — `/etc/shadow`,
`/root/`, `/home/conx/.s`, the mode tables — was read as `uid=0(root)` through
`docker exec`. That is the **operator** identity, not something the target
granted. The exploit chain and every oracle in the Findings section were proven
**over HTTP and SSH from outside the container**, by an ordinary network client
at `172.17.0.1`, with no `docker exec` in the path. Two different claims, two
different identities, kept apart.

**There is no `Uid:`/`Euid:` transition anywhere in this chain**, and I am not
summarising it as "no escalation" — there is no escalation *to* attempt. No
setuid path is reachable from a session.

---

## Findings

### F1 — CWE-798 / CWE-259, hardcoded administrative credential

`/var/www/html/login.php:14`, verbatim:

```php
    // Simula una inyección lógica
    if (($u === "admin" && $p === "IsAdminInThisPage") || strpos($p, "'1'='1") !== false) {
```

* **CWE-798** (Use of Hard-coded Credentials) for the `admin` /
  `IsAdminInThisPage` pair; **CWE-259** (Use of Hard-coded Password) because the
  string is a password checked with `===` and it is the whole authentication
  decision.
* **Evidence, literal.** `POST /login.php` with `username=admin&
  password=IsAdminInThisPage` →
  `HTTP/1.1 302 Found` / `Set-Cookie: PHPSESSID=l3autvndpkesdtl0ps0u71kok2; path=/` /
  `Location: index.php?page=welcome` / `Content-Length: 0`.
* **Negative control, byte-distinguishable.** `username=admin&password=wrongpass`
  → `302` / `Location: login.php?fail=1` / `Content-Length: 0`. Both are `302`
  with `Content-Length: 0`, so **the status and the length are identical** — the
  discriminator had to be the `Location` header. Recorded because a status sweep
  would have called both a success.
* **Impact:** full administrative panel to anyone who reads the file, forever,
  with no rotation path and no rate limit. In this lab it is also a **host
  credential shape**, which makes it worse than a web-only one: see the SSH
  negative below.
* **Root cause:** the credential is a literal inside the request handler and
  there is no credential store anywhere in the image — `php -m` lists
  `PDO` and no driver, and the artefact contains no `mysqli`, `pgsql` or
  `sqlite3` reference anywhere in `/var/www` (grep for those three: **`/var/www` → 0
  files**; `/etc/php` → **2** files, both the stock `php.ini`).
* **Fix:**
* **Fix:** move authentication to a store with per-user hashed secrets; if a
  bootstrap account is unavoidable, source it from an environment secret and
  force rotation.

### F2 — CWE-287 / CWE-697, authentication bypass by substring match, with **no SQL anywhere in the application**

The second half of the same line:

```php
|| strpos($p, "'1'='1") !== false) {
```

* **CWE-697** (Incorrect Comparison) is the mechanism; **CWE-287** (Improper
  Authentication) is the consequence. **This is not SQL injection**, and the lab
  names it "Simula una inyección lógica" / a "simulated logical injection" —
  the author is honest that it is simulated.
* **The proof that it is not SQL: the application has no database.**
  `php -m` → `PDO` is present, **no `pdo_mysql`, `pdo_pgsql`, `pdo_sqlite`,
  `mysqli`, `pgsql` or `sqlite3` driver**; the process list contains **no
  `mariadbd`, `mysqld`, `postgres` or `mongod`**; grepping `/var/www` and
  `/etc/php` for `mysqli|pgsql|sqlite` → **2** files, both the stock
  `php.ini`, and the same grep over `/var/www` → **0**. There is nothing to
  inject *into*. The substring test runs before
  anything else and short-circuits the `&&`.
* **Evidence, literal, three probes that show it is a substring and not a
  grammar:**

  | `password` value | `Location` |
  |---|---|
  | `x' OR '1'='1` | `index.php?page=welcome` |
  | `'1'='1` | `index.php?page=welcome` |
  | `'1'='1zzz` | `index.php?page=welcome` ← **trailing garbage still authenticates** |

  The third row is the discriminator: no SQL engine would accept `'1'='1zzz`.
  The username is irrelevant — `zz` and `anything` both authenticate on this
  string. (`admin` + `'1'='1` was **not** probed; it would take the same branch
  by the short-circuit, but I am not counting an unrun probe.)
* **Impact:** the administrative panel, with **zero knowledge and zero
  credentials**, to any anonymous client, in one HTTP request. On its own this
  makes F1 redundant, and it makes the disclosure in F3 reachable by anyone who
  has never seen a password.
* **Root cause:** a magic string used as an authentication decision, with
  `strpos(...) !== false` where a comparison against a presented secret belongs.
* **Fix:** delete the branch. There is no legitimate reason for a substring of
  the password field to grant a session; if a backdoor must exist for testing, it
  must be behind a build flag that is off in production.

### F3 — CWE-22 / CWE-538, the disclosure: `include()` is a second reader that does not consult the server's authorisation decision

**This is the load-bearing finding of the engagement.**

`/var/www/html/index.php:9-27`, verbatim:

```php
$page = $_GET['page'] ?? 'welcome';

// Agrega automáticamente extensión .php si no tiene punto (opcional)
if (!str_contains($page, '.') && !str_starts_with($page, 'php://')) {
    $page .= '.php';
}

$base_dir = realpath(__DIR__);
$target = realpath($base_dir . '/' . $page);

if (
    $target &&
    str_starts_with($target, $base_dir) &&
    is_file($target)
) {
    include($target);
} else {
    echo "<h2>Access denied or file not found.</h2>";
}
```

* **Evidence, literal, side by side. Same file, same server, same request
  identity, two answers:**

  ```
  $ curl -s -o /dev/null -w '%{http_code} %{size_download}\n' \
      http://172.17.0.2/logs/logs.txt                      # DIRECT, over HTTP
  403 275

  $ curl -s -b <session> -w '%{http_code} %{size_download}\n' \
      'http://172.17.0.2/index.php?page=logs/logs.txt'   # VIA THE APPLICATION
  200 1639
  ```

  The direct request is refused by the `.htaccess`. The application request
  returns the file. **1 639 B** of the log, verbatim, md5 of the response body
  `a8e6f6d5c1d2ec8013c13b3a58e86560`.
* **Attribution of the 403, from the server's own error log — not from the
  status code** (a `403` cannot tell you which directive fired, and lab 218
  established that two layers can return two different 403s):

  ```
  [Wed Sep 30 14:44:50 2026] [authz_core:error] [pid 31] [client 172.17.0.1:46998]
      AH01630: client denied by server configuration: /var/www/html/logs/logs.txt
  ```

  And `AllowOverride` really does let that file speak —
  `/etc/apache2/apache2.conf:170-172`: `<Directory /var/www/>` … `AllowOverride All`.
  So the control is live, correctly configured, and it holds — on the request path.
* **The oracle, green in both directions.** A name that **cannot exist**,
  `page=logs/zzq7x9impossible91.txt`, returns `200` / **43 B** /
  md5 `a9836630f40c55a9c03a326c09902921` — `<h2>Access denied or file not
  found.</h2>` — byte-distinguishable from 1 639 B. A real file I created and
  then deleted, `logs/probe78.txt`, returned `200` / **26 B** /
  md5 `ffb545ffd14a90be04881ffc37b4d41d`, containing my marker. **Three
  distinct bodies, so the 200-status sweep is not the detector here — the byte
  count and the md5 are.**
* **Byte accounting, computed rather than read.** The file on disk is **1 637 B**
  (`md5 56dcce057bac00214b79f5c1bc13a8a8`). The HTTP body is **1 639 B**. Delta
  **+2**, which is exactly what `index.php` emits after its closing tag: line 28 is
  `?>`, lines 29-30 are blank, giving `?>\n\n\n` — and PHP swallows the one
  newline immediately following `?>`, so the output gains **two**. 1 637 + 2 =
  1 639. `diff` against a `docker cp` of the file reports exactly two added `\n`
  at the end and nothing else.
* **The same dead code class as labs 146 and 243, in a new costume.**
  `index.php:12` explicitly *permits* `php://` — `!str_starts_with($page,
  'php://')` is there to stop the `.php` suffix being appended. **`realpath()`
  returns `false` for every stream-wrapper path**, so the exception the author
  wrote can never be reached. Measured, not inferred, from the interpreter:

  ```
  $ php -r '$b=realpath("/var/www/html"); foreach([... ] as $t){...}'
  input                                                    realpath guard(target,base)
  logs/logs.txt                                            '/var/www/html/logs/logs.txt' INCLUDE
  ../../etc/passwd                                         false    DENY
  /var/www/html/logs/logs.txt                              false    DENY
  php://filter/convert.base64-encode/resource=logs/logs.txt false    DENY
  php://filter/convert.base64-encode/resource=/etc/passwd  false    DENY
  ```

  **The framework never calls what the file contains.** The file reads as though
  it permits `php://filter`; `realpath()` ignores it. Over HTTP, all four
  `php://` spellings plus `pHp://`, `....//....//`, an absolute path, a trailing
  `/`, and `\0.php` returned the identical 43 B denial body — **10 negatives, 1
  distinguishable negative signature, 0 hits.**
* **The guard is a string prefix, not a path-component prefix — latent, not
  exploitable here.** `str_starts_with($target, $base_dir)` returns **true** for
  `/var/www/html_evil/x.php`; measured in isolation with the same predicate.
  `ls -la /var/www/` shows only `html`, so no sibling directory exists and there
  is no route. Reported as a hardening note, **not** as a finding: the
  difference between those two things is whether a measurable path exists, and
  here it does not.
* **No write primitive, so no RCE — and I did not claim one.** `www-data` is the
  identity that executes the include. Read as **that identity**, via
  `su -s /bin/sh www-data -c "touch …"`:

  ```
  /var/www/html             NOT-writable   (755 root:root)
  /var/www/html/logs        WRITABLE       (755 www-data:www-data)
  ```

  So a write into `logs/` would have been includable. **No write primitive
  exists in this chain, 0 attempts.** The RCE is under NOT tested with a count,
  not in the negatives.
* **Impact:** the application's access-control decision is not the deployment's
  access-control decision. Anything placed in a `Require all denied` directory
  under the docroot is readable by any session, and by F2 any anonymous client
  can obtain a session.
* **Fix:** do not let a request value reach `include()` at all. If page selection
  is required, resolve it against a fixed allowlist of page identifiers mapped to
  known files — not against a filesystem path.

### F4 — CWE-312, credentials at rest in a reversible encoding

Inside the disclosed file, `/var/www/html/logs/logs.txt`:

```
[2024-03-29 12:04:12] DEBUG: Trying password 'YWRtaW4xMjM='
[2024-03-29 12:04:14] DEBUG: Trying password 'dGVzdDEyMw=='
[2024-03-29 12:04:24] DEBUG: Trying password 'NGxiM3J0MTIz'
[2024-03-29 12:04:25] SUCCESS: Auth success for user 'albert'
```

* **CWE-312** (Cleartext Storage of Sensitive Information) — base64 is an
  encoding, not a protection, and a log line is the worst place for a secret.
* **Three values, three decodes, computed and not guessed:**

  | Literal | `base64 -d` | length |
  |---|---|---|
  | `YWRtaW4xMjM=` | `admin123` | 8 |
  | `dGVzdDEyMw==` | `test123` | 7 |
  | `NGxiM3J0MTIz` | `4lb3rt123` | 9 |

  **I want to be explicit about the third one, because it is where this finding
  nearly became a fabricated one.** The surrounding log line says
  `Auth success for user 'albert'`, so the natural reading of `NGxiM3J0MTIz` is
  `albert123`, and that is what I had written down before running the decoder.
  It is **not** `albert123`. It is `4lb3rt123` — leetspeak. Had I reported the
  context-derived guess, I would have filed a credential that was never in the
  file, and my later "it does not authenticate" test would have been testing the
  wrong string and would have been meaningless.
* **Impact:** three passwords, in a file the deployment explicitly declared
  unreadable. Two of the three (`admin123`, `test123`) name accounts that **do
  not exist** on this host — `/etc/passwd` has 25 lines and contains no `admin`
  and no `test` (`root`, `albert`, `conx` and **21** accounts
  whose shell is `nologin`). One names a real account.
* **This finding is **not load-bearing**. Nothing in this engagement depends on
  it.** See the load-bearing section.
* **Fix:** never write a candidate or accepted secret to a log, in any encoding.
  Log the event and the outcome; log a salted hash or nothing.

### F5 — CWE-384, session fixation (found, **not** chained, delivery unproven)

**A correction to my own instrument, before the finding.** My first source for
this was `php -i`, and `php -i` on this host reports the **CLI SAPI**, loading
`/etc/php/8.3/cli/php.ini` — *not* the `apache2` SAPI that serves the
application. §22 says a control must exercise the same code path as the target,
and a config dump from a neighbouring SAPI is the same mistake. So the value
that matters here is **the value the framework consumes**, and for a cookie flag
that value is observable on the wire:

```
$ curl -s -i -X POST -d 'username=admin&password=IsAdminInThisPage' http://172.17.0.2/login.php
HTTP/1.1 302 Found
Set-Cookie: PHPSESSID=l3autvndpkesdtl0ps0u71kok2; path=/
```

No `HttpOnly`, no `Secure`, no `SameSite`. **That header is the measurement, and
it is the finding** — the `php.ini` value is only corroboration. For
`use_strict_mode` the consumed value is behavioural, and step 3 of the table
below measures it: a session id PHP had never seen was adopted and honoured.
(Corroborating CLI-SAPI readings, quoted only because they agree and only with
that label: `session.cookie_httponly => Off`, `session.cookie_secure => Off`,
`session.use_strict_mode => Off`, `session.name => PHPSESSID`.)

* **CWE-384** (Session Fixation); **CWE-1004** (Sensitive Cookie Without
  `HttpOnly`).
* **Evidence, executed, not inferred.** With `session.use_strict_mode=Off`, PHP
  adopts an attacker-supplied session id:

  | step | request | result |
  |---|---|---|
  | 1 | `GET /login.php` with `Cookie: PHPSESSID=zzq7x9FIXEDBYATTACKER0001` | `200` |
  | 2 | `POST /login.php` `password='1'='1` with the same cookie | `302` |
  | 3 | **fresh client**, same cookie, **no login performed** → `GET /index.php?page=welcome` | **`200` / 1 332 B**, body contains `Welcome, admin!` |
  | control | fresh client, `PHPSESSID=zzq7x9NEVERUSED0002`, never authenticated | **`302` / 0 B** |

  Byte-distinguishable in both directions (1 332 vs 0).
* **Delivery is NOT proven — it is stated as not proven.** I did **not** test for XSS, an open redirect, or any
  attacker-controlled `Set-Cookie` — **0 probes for each**, and they belong under
  NOT tested. What I can say from the source read is that the three response
  writers are `login.php:5,16,19` (fixed `Location` values) and `index.php:5` /
  `welcome.php:4` (fixed `Location` values): **no response value the request
  controls reaches a `Location` or a header**, so there is no obvious delivery
  primitive in the code as shipped. "No obvious" is an inference from a source
  read, not a measurement, and it is labelled as one. The
  *fixation* is proven; *placing the chosen id in a victim's browser* is not.
  Filing them together would tell a client that patching one fixed the other,
  which is the lab-243 fusion error.
* **And it changes nothing here anyway:** F2 gives an attacker the panel with no
  session of their victim's, at any id they like.
* **Fix:** `session.use_strict_mode=1`, `session_regenerate_id(true)` on
  privilege change, `session.cookie_httponly=1`, `session.cookie_secure=1`.

### Two disclosures that are real but are **hygiene**, filed so the report is not padded

The brief's class statement names "a comment naming an internal host" as a
member of the class. It is worth being precise about the threshold, because both
of these are *in* the served page:

```
/var/www/html/welcome.php:9   <!-- dev note: remember to secure logs.txt path before deploy -->
/var/www/html/welcome.php:57  <p class="danger">[!] Warning: System error logs are exposed to the public folder</p>
```

Both are served to **any session holder**, including one obtained with zero
credentials via F2 — I read them out of the 1 332 B panel body at offset lines 2
and 50. So they are genuine disclosures of an internal filename and of the
architecture. They are **not findings**, for two measurable reasons:

1. Neither is load-bearing. `GET /logs.txt` (the name the comment gives, with no
   directory) returns **`404` / 272 B** — the name alone does not locate the file.
   The comment is a signpost; the fuzzing did the work.
2. Line 57 is the **application telling the truth about itself in its own UI**.
   An app that announces its own exposure has not been exploited, and a
   disclosure that the deployment already published is not a disclosure *to* the
   deployment.

Filed as observation, not as a finding. That is the threshold stated as a rule:
**name the control that should have held and the path that bypasses it.** For
the comment there is no such path — it is prose.

---

## Which disclosure is load-bearing, and which one I would delete

The catalogue declares three things. Here is the honest shape of them.

| Declared item | Is it a finding? | Load-bearing? | Verdict |
|---|---|---|---|
| **information disclosure** | **Yes** — F3 | **YES** — it is the entire payload of the chain | keep |
| **web fuzzing** | **No** — it is a *method*. I used 68 candidates to find a path I then had to *prove* with a second instrument. A method is not a vulnerability and belongs in a technique section, not a findings list. | n/a | **delete — nothing changes** |
| **credential leakage** | **Yes** — F4, CWE-312, three reversible secrets in a file | **NO.** See below | keep as a defect; it is not a link in the chain |

**The chain, stated as a graph rather than a list:**

```
                    ┌─ F1 hardcoded admin/IsAdminInThisPage ─┐
anonymous client ───┤                                        ├──> "admin" session ──> F3 include() ──> logs/logs.txt (1 639 B)
                    └─ F2 strpos($p,"'1'='1") ───────────────┘                                          │
                                                  (zero credentials)                                   └──> F4 three base64 secrets
```

**F1 and F2 are alternative entries for the same node.** Either one reaches the
session; they are independent, in the lab-243 sense — but unlike lab 243 they are
*both* real, and fixing either one ships nothing against the other, because F2
needs no secret to remove. **Neither F1 nor F2 is named by the catalogue.**

**F3 is the only load-bearing disclosure.** It is the reason the lab is called
`Bypassme`: the one control that was written down (`Require all denied`) is
genuinely enforced, and there is a second reader inside the same process that
does not go through it.

**F4 is the one I would delete from the report and nothing would change.**
Delete F4 entirely and the chain — anonymous client → session → disclosure — is
byte-for-byte identical, because F4 sits *downstream* of the disclosure as a
**consequence**, not *upstream* of it as a **credential source**. Nothing in
this lab is unlocked by `4lb3rt123` or `admin123`. I proved that rather than
asserting it:

* `4lb3rt123` against `albert` over SSH → `AUTH_FAIL`.
* `admin123` against `admin` over SSH → `AUTH_FAIL` (and `admin` is not an
  account).
* `IsAdminInThisPage` against `albert` → `AUTH_FAIL`.
* `4lb3rt123` against `root` → `AUTH_FAIL` (`PermitRootLogin no`).

**So: the credential leakage is real, reportable, and buys the attacker nothing
— because the same artefact's sibling defect already gives the panel away for
free.** That is the single most useful thing this lab has to say about the
catalogue's framing, and it is the opposite of lab 243. In 243 the two bugs are
independent and both are needed to reach different outcomes. Here the two are
**ordered**, and the downstream one is redundant.

### The version of the class this lab contributes, for the methodology

Extend the information-disclosure row rather than adding one:

> An information disclosure is a finding **iff** a control elsewhere in the
> deployment decided the object was unreadable **and** a second, ungoverned read
> path returns it. State both names: the control, and the path that bypasses it.
> `logs/.htaccess:2` (`Require all denied`) and `index.php:24` (`include($target)`)
> are the two names in lab 78. **A credential recovered from a disclosure is not
> automatically load-bearing** — lab 78's three base64 secrets are downstream
> dead ends, because the same application's auth bypass hands over the panel with
> no secret at all. Before filing a credential-leakage finding as part of a
> chain, ask what it unlocks and **measure whether it unlocks anything.**

---

## Controls that held

| Control | Positive control that proves this detector works |
|---|---|
| **`logs/.htaccess` — `Require all denied`** | **Held on the HTTP path, and the denial is attributable.** Server error log: `AH01630: client denied by server configuration: /var/www/html/logs/logs.txt`. `AllowOverride All` at `apache2.conf:172` means the file is actually read, so it is not inert. **The detector fired 7 times on the same path**: `GET /logs/logs.txt` directly (in two separate batches), via `/logs/./logs.txt`, and via `//logs//logs.txt` — every one `403` / 275 B / md5 `0a0ce486142867ee709125cd88f1dd10`. The normalisation variants do **not** bypass it. **What it does not hold against:** `include()`. |
| **`realpath()` + `str_starts_with($target, $base_dir)` — path traversal** | **Held, and the negative is not a zero-work negative.** Oracle green in both directions on the same request path: `page=logs/logs.txt` → 200/1 639 B; `page=logs/zzq7x9impossible91.txt` → 200/**43 B** — two different bodies. **10 further traversal and stream-wrapper spellings** all returned the identical 43 B body (`../../etc/passwd`, `../../../etc/passwd`, absolute `/var/www/html/logs/logs.txt`, `....//....//etc/passwd`, 3 × `php://` plus `pHp://`, `logs/logs.txt/`, `logs/logs.txt\0.php`). **Count: 12 include-path probes, 2 readable, 10 negatives, all one signature, 0 hits.** A separate PHP-CLI harness reproduced all five of the same predicates against `realpath()` directly, which is why the 43 B is a measurement and not an untested guess. |
| **The 404 detector** | **Proven green before any belief about absence.** `zzq7x9impossiblecontrol01.php`, `zzq7x9impossiblecontrol02.log`, `zzq7x9impossiblecontrol03.txt` and `thispathcannotexist4d7b1a9e` were planted in the wordlist; all four returned **404 / 272 B / md5 `7139ceb6…`**, byte-identical to 47 genuinely-absent names. Server-side confirmation from the error log: `script '/var/www/html/zzq7x9impossiblecontrol01.php' not found or unable to stat`. A 404 sweep on this target is trustworthy. |
| **Null-byte truncation on the denial** | `GET /logs/logs.txt%00` → **404 / 272 B**, i.e. it falls through to the *global* 404 baseline and does **not** reach the `.htaccess`. Contrast lab 188, where `^\.ht` being case-sensitive let `.HTACCESS` return 200/36 B: `<Files "*">` matches every name, so that bypass class is closed here. Measured, one probe. |
| **SSH password authentication** | **Oracle proven in both directions before believing any of the 9 negatives.** A disposable account `oracle78` with a known password → **`AUTH_OK` at 0.13 s**; the same account one character off → `AUTH_FAIL` at 2.37 s; a bare wrong password → `AUTH_FAIL` at 2.33 s. The ~2.2 s gap is the KDF running on failure and being skipped on success — the §36 signature, in the correct direction, and the tell that the instrument is measuring something. `/etc/shadow` prefix for the control was `$y$` (yescrypt), so the KDF is real and `crypt()` never silently fell back to DES. **Restore verified byte-exact:** `/etc/passwd` md5 `b665e525b3e22f32a3b462205a2b8994`, `/etc/shadow` md5 `99d016c2e3e7caf9ec3b2a9b5ff93c06`, 25 lines each — identical to the pre-test values, and `grep -c oracle78` returns **0** in `passwd`, `shadow`, `group`, `gshadow`, `subgid`, `subuid`. |
| **`PermitRootLogin no`** | Firewalls the obvious move: `root`/`4lb3rt123` → `AUTH_FAIL` at 3.20 s (a real KDF, not an instant reject — the existing-account latency band). |
| **The session gate on `index.php` and `welcome.php`** | Real, and stated as such: with **no cookie**, `index.php?page=logs/logs.txt` → **302 / 0 B**. The disclosure is **post-authentication**. It does not pretend to be pre-auth — but the authentication is free (F2), so the gate buys nothing. |
| **Not a control, and reported as a defect: `logs/logs.txt` narrates its own exposure** | `logs.txt:24-25` contains `[!!!] SECURITY ALERT: logs/logs.txt is PUBLICLY EXPOSED` and `[!!!] Use this file with caution credentials may be compromised`. That is a **constant, not an oracle**: 3 identical requests returned 43 B / md5 `0a0ce486…`. The lab's own log asserts a state (`PUBLICLY EXPOSED`) that is **false for the HTTP path** and **true only for the `include()` path**. Same shape as lab 188's `Associated name: Joshua` finding — filed as an artefact defect, not as a result. |

---

## NOT tested — separate from "discarded with a reason"

Per the brief's rule, **a count of zero means UNTESTED, and it belongs here, not
in the negatives.**

| Item | Work count | Why untested |
|---|---|---|
| **Remote code execution.** Write a `.php` file into `logs/` (which `www-data` **can** write: measured, `WRITABLE` via `su -s /bin/sh www-data`, vs the docroot root `NOT-writable` at `755 root:root`) and include it. | **0 attempts** | No write primitive exists anywhere in this chain. The app has no upload handler, no SQL, no template injection, no deserialisation point, and no reachable path traversal. I did not look for a way to obtain one and did not find one; I am not claiming the RCE is impossible, I am saying it was never attempted because the primitive is absent. |
| **The `conx` socat socket** `/home/conx/.cache/.sock` (`srwxrw-rw-`, `socat … EXEC:/bin/bash`). | **0 connections** | Unreachable from any identity I could obtain. `/home/conx` is `710 conx:albert`, `.cache` is `770 conx:albert`; `www-data` is in neither group and `conx`'s and `albert`'s passwords are unknown (both `AUTH_FAIL` on SSH, `albert` tested with 3 candidates, `conx` with 0). Reachable **only** after a foothold in `conx` or `albert`, which this engagement did not obtain. |
| **Cracking `albert`'s or `conx`'s real password.** | **0 wordlist candidates run** | No cracking was attempted and none is claimed. Total SSH traffic for the whole engagement: **10 attempts over 9 distinct (user, password) pairs** — 5 target pairs (`albert`/`albert123`, `albert`/`4lb3rt123`, `albert`/`IsAdminInThisPage`, `admin`/`admin123`, `root`/`4lb3rt123`), 3 oracle-control pairs on `oracle78`, 1 impossible-user control, and 1 repeat of `albert`/`4lb3rt123` in the second batch. All 10 rows are itemised in Controls. |
| **Whether `admin`/`IsAdminInThisPage` is reused as a *host* password for any account.** | **2 accounts × 1 value = 2 probes** (`albert`, `root`); `conx` **not tested** with it | Both tested were `AUTH_FAIL`. `conx` was not tried with this value — that is an untested cell, not a negative. |
| **`/etc/cron.d`, per-user crontabs, and any writable-by-me cron path.** | Files enumerated: `/var/spool/cron/crontabs/` = **0 entries**, `crontab -l` for root = `no crontab for root`, `/etc/cron.d` contents read (system jobs only, all root). **0 write attempts.** | `sudo` is **not installed** on this image (`sh: sudo: not found`, `/etc/sudoers` does not exist, `/etc/sudoers.d/` does not exist, the `sudo` group has **0** members), so there is no escalation surface of the lab-93 shape here at all. |
| **Timing/content side channels on the login comparison.** | **0 probes** | Not attempted. The auth decision is a constant-time-irrelevant `===` on two short literals; there is nothing here a side channel would add that a two-request read did not already give. |

---

## Discarded with a reason — findings I dropped, and why

| Dropped candidate | Reason |
|---|---|
| **SQL injection in `login.php`** | **There is no database.** No `mysqli`/`pgsql`/`sqlite3`/`pdo_*` driver in `php -m`; no database process in the process list; zero such references in `/var/www`. The `'1'='1` string is a `strpos()` substring test and `password='1'='1zzz` still authenticates, which no SQL engine would accept. Reported as **F2, auth bypass**, under the right CWE — the lab's own comment calls it *"Simula una inyección lógica"*, a simulated injection. Reporting it as SQLi would have been the most attractive wrong finding available. |
| **Information disclosure via `Server: Apache/2.4.58 (Ubuntu)`** | `ServerTokens` is at its distro default. No deployment decision says this version is secret, so it fails the class's own threshold — a banner is hygiene. Recorded in Stack and versions, not in Findings. |
| **`session.cookie_secure=Off` as a standalone finding** | Folded into **F5** rather than filed separately: with the app served over plain HTTP on port 80 and **no TLS listener in the image** — `/etc/apache2/ports.conf:7-13` puts both `Listen 443` lines inside `<IfModule ssl_module>` / `<IfModule mod_gnutls.c>`, and `apache2ctl -M | grep -iE 'ssl\|gnutls'` returns **empty**, so neither module is loaded, the `Secure` flag cannot be set meaningfully. One finding, one fix. |
| **A second credential from `logs.txt` line 16: `DEBUG: User 'albert' added to sudo group`** | **The artefact's claim is false.** `grep -E "sudo\|admin" /etc/group` → `sudo:x:27:` with **zero** members, and `sudo` is not installed. The log line narrates a privilege grant that does not exist. Reported as an **artefact defect** under Controls, not as a finding — an escalation that is written in a log file but not in the system is not an escalation. |
| **A stack-trace / `display_errors` disclosure** | **The measurement is the served body, not the ini.** The PHP notices this application provably raises — `session_start(): Ignoring session_start() because a session is already active` — exist in `/var/log/apache2/error.log`, and I read the served bodies of all three pages (`login.php` 1 826 B, the panel 1 332 B, the disclosure 1 639 B) and found **no notice and no path in any of them**. **0 disclosed traces.** Corroboration only, and labelled as the CLI SAPI again: `display_errors => Off`, `log_errors => On`. |

---

## Instrumentation defects

Six, and **three of them would have produced a finding that does not exist**.

### D1 — The 403 bucket would have reported 13 of 13 present, when 2 files and 1 directory exist

The `<Files "*">` directive in `logs/.htaccess` is **evaluated by name before the
file is checked for existence** — the same mechanism as lab 188's
`<FilesMatch "^\.ht">`. Every one of these returned `403` / **275 B** /
md5 `0a0ce486142867ee709125cd88f1dd10`, byte-identical:

```
/logs/logs.txt          /logs/index.html      /.htaccess          /.htpasswd
/index.phps             /server-status        /logs/              /logs/access.log
/logs/error.log         /logs/auth.log        /logs/logs          /logs/log
/logs/logs.html
```

`/logs/index.html`, `/logs/access.log`, `/.htpasswd`, `/server-status` — **none
of these exist.** The second instrument says so: `find /var/www -mindepth 1`
returns **7 entries** total, of which the ones reachable at a `/logs/` URL are
the directory `logs/` and exactly **2** files, `logs.txt` and `.htaccess`. So a
status sweep reports **13 present, 3 real (2 files + 1 directory), 10 phantoms** —
and the phantoms include `.htaccess`, `.htpasswd` and `server-status`, the three
highest-value names in any wordlist.

**What caught it, in order:** the **four** impossible-name controls I planted in
the wordlist before running it (`zzq7x9impossiblecontrol01.php`,
`…02.log`, `…03.txt`, `thispathcannotexist4d7b1a9e` — all four landed in the 404
bucket, so the sweep's *absent* answer was trustworthy while its *present* answer
was not); then the server's own error log naming `nonexistent91.txt` as denied;
then `find` as an independent second instrument. The Apache log is decisive and cheap:

```
AH01630: client denied by server configuration: /var/www/html/logs/nonexistent91.txt
```

The server denied a file it could not have found. **A 403 from this directory
carries zero information about whether the file exists**, and I did not treat one
as a discovery until the include-path oracle gave me a byte-distinguishable
answer.

### D2 — I nearly filed `albert123`, a credential that is not in the file

`logs.txt:12-13` puts `NGxiM3J0MTJz` on the line above
`SUCCESS: Auth success for user 'albert'`. Context supplies the answer:
`albert123`. The base64 answer is `4lb3rt123`. I wrote the context-derived value
down first and only caught it by running the decoder.

This is the brief's *"compute your arithmetic, do not read it"* applied to a
decode: **I had substituted a plausible reading for a computation.** Had it
shipped, the report would have carried a credential the file does not contain,
and every downstream claim about it — including the `AUTH_FAIL` negative — would
have been about a string nobody ever wrote down. The three decodes are now in a
table in F4 with their lengths, and the SSH negative in Controls is against the
**decoded** value.

### D3 — `test -w` through `docker exec` would have reported the wrong docroot writable

My first pass at the RCE question was `docker exec … test -w /var/www/html` —
which is **root**, and would have answered "WRITABLE" for a directory that
`www-data` cannot write. Re-run as the identity that actually executes the
include:

```
$ su -s /bin/sh www-data -c "touch /var/www/html/probe78_w"
touch: cannot touch '/var/www/html/probe78_w': Permission denied     NOT-writable
$ su -s /bin/sh www-data -c "touch /var/www/html/logs/probe78_w"
                                                                  WRITABLE
```

`/var/www/html` is `755 root:root`; `/var/www/html/logs` is `755 www-data:www-data`.
The root reading would have produced the **more** alarming answer and the **wrong**
one, and it would have turned a 0-attempt RCE into an apparent 1-step one. This
is the thirteenth-plus-one instance of the `test -w` defect, and the writeability
in the Findings section is quoted from the `su` run, not the `docker exec` run.

### D4 — My own positive control mutated the files under test

Certifying the SSH oracle green required a known-good credential, so I created
`oracle78`. `useradd`/`userdel` then left **`/etc/passwd-`, `/etc/shadow-`,
`/etc/group-`, `/etc/gshadow-`, `/etc/subgid-`, `/etc/subuid-`** behind, and the
`-` copies **contained `oracle78`** while the live files did not. A password-file
diff taken at the wrong moment would have shown the target credentialed account
as changed. Handled: `cp -a` backups taken first, restore verified by **md5 and
line count** on both files (identical to the pre-test values), `userdel -r`,
and the six `-` artefacts located with `find / -xdev -newermt` and removed.

The family resemblance to lab 129 is exact: `chpasswd` on a new account replaced
the shadow line of the account being cracked, and the cracker would have reported
"no match" against its own canary with a green control and a plausible rate.

### D5 — `bc` is not installed; a blank count is not a zero

```
find / -xdev -type f -printf "%s\n" | paste -sd+ | bc
sh: 4: bc: not found
```

The corpus byte total came back **empty**. §19's shape: blank and zero are
identical on the page, and "0 bytes searched" would have been filed as a
measured property. Recomputed with `awk`: **812 440 752 bytes across 13 782
files**. The reward conclusion below rests on the `awk` number.

### D6 — Two readings of the same byte count, and I used neither as evidence

The Apache access log's `%b` for `GET /index.php?page=logs/logs.txt` is `1922`;
`curl`'s `size_download` for the same request is `1639`. The deltas are not
constant across requests — `1615` vs `1332` (+283), `301` vs `43` (+258),
`339` vs `0`, `436` vs `275` (+161). I did not resolve the cause and I am not
guessing at one. **Every byte count in this writeup is `curl`'s**, and the
access log was used only for the `AH01630` attribution lines, which is the use
the RUNBOOK prescribes for it. A sweep that had taken its counts from the access
log would have been wrong by 17% on the decisive request.

---

## Reward

**There is no reward in this lab.** Measured, not assumed.

```
$ find / -xdev -type f 2>/dev/null | wc -l
13782
$ find / -xdev -type f -printf "%s\n" 2>/dev/null | awk '{s+=$1} END {print s}'
812440752                       # 812 440 752 bytes
```

**The positive control ran first, on the same sweep, before I believed the
negative** (§26 and §12 — a sweep that has never found anything is not a sweep):

```
$ grep -rIlE "logs/logs\.txt is" / --exclude-dir=proc --exclude-dir=sys
/var/www/html/logs/logs.txt          <- 1 of 13 782 files, exactly the file I knew contained it
```

The detector works and can see into files. Then the target sweep, same corpus,
same tool — one regex, brace-delimited, so it cannot be inflated by ordinary
English or build vocabulary:

```
$ grep -rIlE "(FLAG|flag|WOPR|DL|dl|CTF|ctf|token|secret|reward)\{" / \
      --exclude-dir=proc --exclude-dir=sys | wc -l
0
```

**0 files of 13 782.** Nine prefixes, case-variant, both braces.

**A second, deliberately sloppier sweep — and why it was the wrong instrument.**
Dropping the braces and searching the bare word `flag` returns **741 files**:

```
$ grep -rIoh -E "[A-Za-z_-]*[Ff][Ll][Aa][Gg][A-Za-z_-]*" \
      /usr/bin/c_rehash /usr/bin/bashbug /etc/default/useradd | sort -u
CFLAGS
flag
flags
```

**I did not read all 741, and I am not claiming to have.** I classified the
three files in the head of the list, and the entire extracted token set from
them is `CFLAGS`, `flag`, `flags` — the **word** `flag` in compiler and
command-line vocabulary, plus `bashbug`'s uppercase `FLAG` inside its own
`--flag`-style option help. That is enough to show the number is an artefact of
the pattern, not a property of the corpus: this is lab 168's shape exactly — a
distinctive pattern in a searcher becomes a liability the moment the pattern is
a plain English word. The brace-delimited form is what makes the number mean
something, and it is why I quote `0 files of 13 782` and not `741`. The honest
statement is: **the bare-word sweep is not a usable instrument here, and the
usable one returned zero.**

**And I read the corpus for my own artefacts before believing that zero** (§26 —
lab 168 found its own probe script because the script contained the pattern in
its search pattern). Everything I created in the container was: `probe78.txt`
and `probe78_w` (deleted), `/root/BACKUP78_passwd` and `/root/BACKUP78_shadow`
(deleted), the account `oracle78` (deleted, 0 references in 6 files), and the six
`/etc/*-` backups (deleted). **None contains any of the nine reward prefixes**,
and none of my probes were written into the container's filesystem at all — every
probe file is on the host under `/tmp/opencode/lab78/`, outside the searched
corpus. `find / -xdev -newermt "2026-09-30" -type f`, filtered for Docker's own
`/var/lib`, `/var/log`, `/run`, `/tmp`, `/proc`, `/sys` churn, returned **10
paths, all `/etc/{group,gshadow,passwd,shadow,subgid,subuid}` and their `-`
copies** — every one of them mine, every one of them removed.

**No `FLAG{}` and none of the nine searched prefixes in `prefix{}` form.** I am
not claiming to have swept *every* token format that could exist — I am claiming
nine prefixes, two case variants, both braces, 0 hits, 13 782 files, with the
sweep's detector proven live first. The point at
[`../INDEX.md`](../INDEX.md)'s `FLAG{}` column is the single source for this
corpus-wide property; this row contributes an absence with a count behind it.

---

## Restore

Recreated from the image, not by undoing edits.

```
$ docker rm -f bypassme_container && docker run -d --name bypassme_container bypassme:latest
$ docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' bypassme_container
172.17.0.2                        # same address, so every cited probe reproduces
```

**Positive verification after restore** — the service answering again with its
shipped values, not a `docker ps` line:

```
GET /login.php                          -> 200 1826
POST /login.php  password='1'='1'       -> 302        (F2 still fires)
GET /index.php?page=logs/logs.txt       -> 200 1639    (F3 still fires)
GET /logs/logs.txt                      -> 403  275    (the control still holds)
md5sum /etc/passwd  -> b665e525b3e22f32a3b462205a2b8994   (identical to pre-test)
md5sum /etc/shadow  -> 99d016c2e3e7caf9ec3b2a9b5ff93c06   (identical to pre-test)
md5sum logs.txt     -> 56dcce057bac00214b79f5c1bc13a8a8   (identical to pre-test)
grep -c oracle78    -> 0 0 0             (no trace of the oracle account)
find /var/www -mindepth 1 | wc -l -> 7  (the shipped webroot, unchanged)
```

## Artifacts left in this engagement

* `~/dockerlabs/labs/78/bypassme.tar` (136.9 MB) and the
  `bypassme:latest` image (1.67 GB) — **left in place**, re-obtainable from the
  archive, and other workers are running concurrently. Reclaim by **image
  name** only; never `docker system prune`.
* `/tmp/opencode/lab78/` — host-side probe scripts and captured bodies, outside
  the searched container corpus. Nothing of mine is inside the container.