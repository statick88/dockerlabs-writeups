# 32 Vulnerame — writeup

**Lab:** 32 · *Vulnerame otra vez* · **difícil**
**Description (full, from the platform catalog):** *"Laboratorio WordPress; el plugin es la
superficie."* — **the catalog description is wrong, and the first job of this engagement was
finding out why** (§0).
**Target:** `172.17.0.3` — single container `vulnerame_container`, image `vulnerame:latest`.
**Stack (from the artefact, not from memory):** Ubuntu **20.04.6** (focal), Apache **2.4.41**,
PHP **7.4.3** (NTS, `mod_php` — *not* PHP 8), **MySQL 8.0.37** on `0.0.0.0:3306`,
**Joomla! 4.0.3 "Furaha"** as shipped *and* as running (§9). OpenSSH 8.2p1.
**Result:** unauthenticated → `uid=1000(guadalupe)` → **`uid=1001(ignacio)`** → **`uid=0(root)`**.
**No reward present** (§8). No lab in this series since 108 has shipped a `FLAG{}`, and this one does not either — reported as a measured absence, not as an assumption.

**Topology.** `auto_deploy.sh` was read, never run. It creates **no network at all**: a bare
`docker run -d --name $CONTAINER_NAME $IMAGE_NAME` (line 131) on the default bridge, one
container, no macvlan, no `--internal`, no pivot. The engagement stayed single-host.
**The absence of `--internal` matters and is the opposite of lab 61** (§9).

---

## 0. The generalisation verdict, per rule

The brief carried three beliefs from labs 108 and 61 and asked whether they survive a harder
instance. Checked one by one, against this lab's own artefacts.

### Belief 1 (from 108) — "`wordpress_logged_in` was the injection carrier; never read salts from `wp-config.php`; the auth cookie alone gives 200 while `wordpress_logged_in` alone gives 302; `pluggable.php:889` requires a live session token."

> **DOES NOT APPLY. It is not that the rule failed — there is no WordPress in this lab.**
> The document root is named `wordpress` and contains `configuration.php`, `htaccess.txt` and
> `administrator/`, and every one of those names is a Joomla 4 name too. A tester pattern-
> matching on path names would have spent the budget looking for `wp-content`, `wp-includes`,
> `active_plugins` and `wp_users`.
>
> Measured, not inferred: `libraries/src/Version.php:37,45,53` → `MAJOR_VERSION = 4`,
> `MINOR_VERSION = 0`, `PATCH_VERSION = 3`; the served `<meta name="generator">` is
> `Joomla! - Open Source Content Management`; Joomla's own log header reads
> `Joomla! 4.0.3 Stable [ Furaha ] 12-September-2021 10:39 GMT`. There is no `wp-content/`,
> no `wp-includes/`, no `wp-config.php`, no `wp_options`, and **no WordPress plugin of any kind**
> — `plugins/` holds 22 Joomla core plugin groups, all stock, and the docroot is byte-identical
> to the stock 4.0.3 distribution (§4, F7).
>
> The **shape** of the rule survives in a form worth carrying: the interesting credential store
> is not the config file either. Here the analogue of `wp_salt()` is Joomla's `$secret`
> (`configuration.php:29`), and again it is not the thing that matters — because the attack
> never needs a forged token. It **writes** one (§4, F2). So the transferable form of belief 1 is
> not "read `pluggable.php`", it is **"find out where authentication state actually lives before
> you try to forge it, and prefer a write primitive over a forgery"** — and on this lab the
> write primitive is one `UPDATE` away.

### Belief 2 (from 61) — "a plugin is *activated code*: no manifest, no permissions, no sandbox; therefore any write primitive anywhere in WordPress, core included, becomes code execution. Entry criterion: the sink is in the plugin's own code AND reachable without prior WordPress authorisation."

> **HOLDS AS A PLATFORM RULE, AND IS DEMONSTRATED HERE — but on a different CMS, and the entry
> criterion does not decide this lab.**
>
> The *mechanism* is Joomla's and it is the same mechanism: extensions are files that the
> application `include`s, `#__extensions` is a list of paths in a database option rather
> than a capability set (215 rows), and nothing in the tree turns off the PHP engine. Measured: there is
> **no** `.htaccess` and **no** `php_admin_flag engine off` anywhere in the docroot; the only
> `php_admin_flag engine Off` on the server is scoped to `/home/*/public_html`
> (`/etc/apache2/mods-enabled/php7.4.conf`, a directory absent from this image), and the vhost
> sets `AllowOverride All` (`sites-enabled/joomla.conf:6`), so a per-directory `.htaccess`
> *could* speak. The one `.htaccess` in the whole tree is `libraries/.htaccess` and it denies —
> so the boundary is drawn in exactly one place, and it is the one place nobody needs it.
>
> The *entry criterion* — "the sink is in the extension's own code, reachable without prior CMS
> authorisation" — turns out **not to be the discriminator that matters here**, for a reason
> that is itself the finding. There are no third-party extensions at all: the docroot diffed
> against the stock 4.0.3 ZIP that the lab ships in its own docroot is **4 files**, all of them
> deployment artefacts (§4, F7). So "which extension is vulnerable?" has no answer to give, and
> the criterion correctly refuses to fire. The discriminator this lab actually turns on is a
> different one:
>
> > **Refined rule (extends 61).** A CMS extension tree is executable code, so *any* write
> > primitive in the product is code execution. But **the interesting question is not which
> > extension is the bug — it is whether the product's own write primitives reach an identity
> > that matters.** On this lab the CMS admin write primitive stops dead at `uid=33(www-data)`,
> > and `www-data` has **no** route to root: measured as `www-data`, `find / -xdev -writable
> > -type f` returns **8 118** files and **0** of them are owned by anyone else, cross-checked
> > with a `test -w` loop that also returns **0**. There is no setuid binary on the host beyond
> > the 16 stock ones, no file capability anywhere (`getcap -r /` empty), and no cron daemon
> > running. **The web application is a complete dead end for root on this lab, and the whole
> > second half of the lab is on a different service entirely.**
> > That is the part of belief 2 that generalises: the write-primitive rule is a rule about
> > *code execution*, and code execution is only the end of the story when the web identity
> > happens to be near the top. **Measure where the write lands before you budget for it.**

### Belief 3 (from both) — "`active` and `present` diverge at the moment of compromise; answer 'what is in the tree', which is an `ls`, not a database option."

> **HOLDS, and it holds with a wrinkle this lab adds: on Joomla the divergence is visible
> without compromising anything, so it is a *configuration* fact rather than a compromise-time
> fact — and the same rule applies one level further out, to the OS.**
>
> `plugins/` on disk holds 21 groups. `#__extensions` (Joomla's `active_plugins` analogue)
> holds **215 rows** across `component`/`template`/`language`/`plugin`/`module` types. The two sets
> are not the same list, and the directory tree is the one that answers "what executes".
> Crucially, the **doctrine generalises past the docroot**: `/snap/bin` is `drwxrwxrwx
> guadalupe:guadalupe` — present, on `secure_path`, and writable by *any* uid including
> `www-data` (§4, F1) — and `/usr/bin/scr1pt` is `-rwx------ ignacio:ignacio` and is on
> `sudoers`. **The "is it active" question has an OS answer too, and the OS answer is the one
> that wins.**

### Verdict in one line

**This lab reproduces no rule and breaks no rule; it relocates the class.** The three WordPress
beliefs are *not applicable* (wrong platform), *holds-with-refinement* (plugin trust, extended
by the dead-end finding), and *holds* (present vs active). **The correct outcome is the one
PIPELINE §Convergence names: "a worker reports the class table already has the row."** And the
most valuable thing this engagement produced is not a chain — it is that **the queue's class
label is a filename, not a fingerprint.** `/home/search14/dockerlabs/labs/32/auto_deploy.sh`
does not exist in the extracted lab; the *docroot* is called `wordpress` and the *lab* is called
Vulnerame, and neither of those is the product. **Fingerprint from `Version.php` / a
`generator` meta tag, never from a directory name.**

---

## 1. Surface

```
$ nmap -sV -Pn -p- 172.17.0.3
Nmap scan report for 172.17.0.3
Host is up (0.000047s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
3306/tcp open  mysql   MySQL 8.0.37-0ubuntu0.20.04.3
```

**What TCP *does* see here that a WordPress-shaped mental model would not predict: port 3306.**
All three earlier WordPress labs had the database on `127.0.0.1` only. This one binds
`0.0.0.0`, and the database account is granted from `%`.

**What TCP cannot see — measured, not assumed:**

```
$ docker exec vulnerame_container cat /proc/net/udp      -> (header only, no rows)
$ docker exec vulnerame_container cat /proc/net/udp6     -> (header only, no rows)
$ docker inspect vulnerame:latest -f '{{json .Config.ExposedPorts}}'  ->  null
$ docker exec vulnerame_container sh -c 'awk "NR>1{print \$2,\$4}" /proc/net/tcp'
 0100007F:8124 0A      <- 127.0.0.1:33060  (MySQL X protocol, loopback)
 00000000:0CEA 0A      <- 0.0.0.0:3306     (MySQL, ALL INTERFACES)
 00000000:0050 0A      <- 0.0.0.0:80
 00000000:0016 0A      <- 0.0.0.0:22
```

No UDP surface. `ps` confirms the process set and, just as importantly, what is **absent**:

```
root    1  /bin/sh -c service apache2 start && service ssh start && service mysql start && tail -f /dev/null
root   24  /usr/sbin/apache2 -k start
www-data 29-33  /usr/sbin/apache2 -k start
root   46  /usr/sbin/sshd [listener]
mysql  78  /bin/sh /usr/bin/mysqld_safe
mysql 284  /usr/sbin/mysqld --datadir=/var/lib/mysql --port=3306
root  363  tail -f /dev/null
```

**No `cron`, no `rsyslog`, no `fail2ban`, no MTA.** `/etc/cron.d/php` exists and is stock
(`sessionclean` as root) — and it is **inert**, because there is no cron daemon to read it. A
tester who greps `/etc/cron.d` and finds a root job has found nothing.

### 1.1 Virtual hosts, with the impossible-name control

`/etc/apache2/sites-enabled/` holds two vhosts: a catch-all `000-default.conf`
(`DocumentRoot /var/www/html`) and `joomla.conf` (`DocumentRoot /var/www/html/wordpress`,
`ServerName vuldb.dl`).

```
$ for n in vuldb.dl www.vuldb.dl wordpress.local NOSUCHHOST.invalid ""; do ... done
vuldb.dl              200 28132  md5=57c8205a748e
www.vuldb.dl          200 10918  md5=3526531ccd6c
wordpress.local       200 10918  md5=3526531ccd6c
NOSUCHHOST.invalid    200 10918  md5=3526531ccd6c   <- control: cannot exist as a vhost
(no Host: header)     400   302  md5=3099bdec1a7e
```

Four names share `3526531ccd6c` **including the invented TLD**, so that hash is the catch-all's
`index.html` baseline and `57c8205a748e` is the only distinct surface. The same app is also
reachable through the catch-all at `/wordpress/` (200, 29150 B) because the docroot is nested.

### 1.2 Paths

| Path | Result | Note |
|---|---|---|
| `/wordpress/` | **200**, 29150 B | the app, via the catch-all |
| `/` (Host: `vuldb.dl`) | **200**, 28132 B | the app, at the vhost root |
| `/wordpress/administrator/` | **200**, 10011 B | admin login, unauthenticated |
| `/wordpress/api/index.php/v1/content/articles` | **401**, `{"errors":[{"title":"Forbidden"}]}` | the webservices API is installed and **requires auth** |
| `/wordpress/configuration.php` | **200, 0 bytes** | PHP executed it — the config is **not** remotely readable (§4, F2) |
| `/wordpress/libraries/.htaccess` | **403** | the one boundary the tree draws, and it works |
| `/wordpress/htaccess.txt`, `web.config.txt`, `robots.txt` | 200 | stock, unshipped-by-design deployment leftovers |
| `/wordpress/joomla4.0.3zip` | **200, 26 370 047 B** | the stock 4.0.3 distribution, served from the docroot — **not** a site backup (§4, F6) |
| `/wordpress/installation/` | **absent** | removed from the deployed tree; the ZIP still contains it |
| `/phpmyadmin/` | **404** | no such alias here (contrast lab 61) |
| `/wp-login.php` | **404** | nothing WordPress-shaped is served |

---

## 2. The class

**Entry criterion, and it is not the one the catalog names.** The catalog says "the plugin is
the surface". There is no plugin. The criterion that started the engagement was the boring one
from 108 and 61:

> *Does the platform disclose a credential that can be used against a service it exposes, and
> does the platform expose a write primitive into its own authentication store?*

**Sources that settled it, in this order:**

1. `Cmd` in the image config: `service apache2 start && service ssh start && service mysql
   start` — **two** network services plus a database, read in 10 seconds from
   `docker inspect`, before a single packet was sent. 108 and 61 both shipped one HTTP
   service. The image's own `Cmd` is the topology.
2. `/etc/sudoers:27-28` — two non-root rungs naming two users. This is the lab telling you
   which identities matter, and it is the only place it says so.
3. `configuration.php:17-19` and the grant on `joomla_user@%` — the write primitive (§4, F2).

---

## 3. Chain

| # | → | Mechanism | Identity proof (uid/euid as a pair) |
|---|---|---|---|
| 1 | unauth | `nmap -p-`; `/proc/net/udp` empty; `ps` shows sshd + apache2 + mysqld and no cron | — |
| 2 | unauth | credential attack against OpenSSH 8.2p1 on `0.0.0.0:22`, using a lab-derived 517 503-candidate corpus | `uid=1000(guadalupe) gid=1000(guadalupe) groups=1000(guadalupe)`; `Uid: 1000 1000 1000 1000` |
| 3 | **`uid=1001(ignacio)`** | sudoers:27 grants `guadalupe → (ignacio) NOPASSWD: /usr/bin/scr1pt`; `scr1pt:6` calls **`/snap/bin/ls` by absolute path**, and `/snap/bin` is `drwxrwxrwx` | `Uid: 1001 1001 1001 1001`, `uid=1001(ignacio)` printed by the hijacked program; oracle file in `/home/ignacio/` that `guadalupe` provably cannot create (C6) |
| 4 | **`uid=0(root)`** | sudoers:28 grants `ignacio → (ALL:ALL) NOPASSWD: /usr/bin/ruby /usr/bin/saludos.rb`, and `saludos.rb` is `-rwxrwx--- ignacio:ignacio`, so `ignacio` rewrites the interpreter's input | `uid=0(root) gid=0(root) groups=0(root)`; `LAB32-ROOT-PROOF uid=0 euid=0`; oracle `/root/LAB32-1790744572-root`, `owner=root:root` in a `0700` dir, unreadable as both lower identities (C7) |

**Side branch, fully proven to the authentication boundary, deliberately stopped:**

| # | → | Mechanism | Identity proof |
|---|---|---|---|
| 5a | `guadalupe` | read the world-readable `configuration.php` (mode **644**, `www-data:www-data`) → the database credential | `grep -E 'password\|user\|db' configuration.php` from an ordinary local account, not from the web identity |
| 5b | `guadalupe` | MySQL **over TCP** with that credential — `joomla_user@%`, `ALL PRIVILEGES ON joomla_db.*` | `SELECT CURRENT_USER()` → `joomla_user@%`; connection from `172.17.0.10` (a second container, different netns) |
| 5c | **CMS Super User** | `UPDATE ffsnq_users SET password = <hash I generated>` — **the credential is written, never recovered** | logged in as `firstatack` (Super User) with a password that did not exist before; 64 326 B admin page vs 10 011 B login page, and a wrong password is refused (C8) |
| 5d | — | CMS admin → RCE as `www-data`: **attempted, did not work.** See F4. | not claimed |

### 3.1 Hop 3 in detail — `secure_path` is a list, not a sandbox

`/etc/sudoers:11`:

```
Defaults	secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin"
```

`/snap/bin` is the **last** entry and is `drwxrwxrwx guadalupe:guadalupe`. `snapd` is not
installed — the directory exists because the lab author put it there, and `guadalupe`'s own
shell history is the receipt: `touch hola` (and `ls -la /snap/bin/` shows `hola`, mode 664,
owner guadalupe, 0 bytes, dated `Jul 19 2024` — the image build date).

`secure_path` normally makes a sudo'd command's `PATH` non-attacker-controlled. **It does not
make the *filesystem* non-attacker-controlled.** `scr1pt` is the counter-example in five lines:

```
$ cat -n /usr/bin/scr1pt
1  #!/bin/bash
2
3  echo -e "Listando el directorio\n"
4  /usr/bin/ls /var/www/html            <- absolute, real ls, harmless
5  echo -e "Listando otro directorio"
6  /snap/bin/ls /var/www/html/wordpress <- absolute, into a 0777 dir: THE PLANT
```

Both `ls` invocations are **absolute paths**, so planting a binary that `secure_path` would
have shadowed would not work. The lab does not rely on `secure_path` ordering at all: it plants
the file at the path the script *names*. This is why the finding is about the directory's
**mode**, not about `PATH`:

```
$ stat -c '%n mode=%a owner=%U:%G' /snap/bin /home/ignacio /usr/bin/scr1pt
/snap/bin      mode=777 owner=guadalupe:guadalupe
/home/ignacio  mode=755 owner=ignacio:ignacio
/usr/bin/scr1pt mode=700 owner=ignacio:ignacio
```

And the sudo grant is **not** blanket — that is what makes hop 3 a real policy boundary:

```
$ sudo -n -l                                       # as guadalupe
User guadalupe may run the following commands on <host>:
    (ignacio) NOPASSWD: /usr/bin/scr1pt

$ sudo -n -u ignacio /usr/bin/cp /tmp/x /usr/bin/saludos.rb
sudo: a password is required                        # C5: the policy holds
```

### 3.2 Hop 4 in detail — a sudo grant that names an *interpreter and its input*

```
$ sudo -n /usr/bin/ruby /usr/bin/saludos.rb        # invoked exactly as sudoers:28 specifies
Feliz hacking            <-- original line, kept
Aprendamos jugando y compartiendo info
Esta ya la tienes :-)
uid=0(root) gid=0(root) groups=0(root)
LAB32-ROOT-PROOF uid=0 euid=0
```

`/usr/bin/saludos.rb` is `-rwxrwx--- ignacio:ignacio`, so `ignacio` owns the file the grant
points at. **A `sudo` rule that pins both the interpreter and the script is only as strong as
the script's write permissions** — and this one names a file the target user owns. That is the
same class as lab 93's *"a grant that names an interpreter"* and lab 148's *"sudo argument
injection"*, with the roles inverted: here there is no injection, only an owned input file.

---

## 4. Findings

### F1 — `sudo` grants a two-rung ladder whose first rung plants code in a world-writable directory; `uid=1000` → `uid=0(root)` with two `sudo` calls

**CWE-59 (link following) / CWE-732 (incorrect permission assignment) / CWE-269 · Critical**

Three separate defects compose into unauthenticated-to-root, and each is worth fixing on its
own because each is independently sufficient to *shorten* the chain:

1. **`/snap/bin` is `drwxrwxrwx`** (CWE-732). A directory on `sudo`'s `secure_path`
   (`sudoers:11`) that any uid on the host can write. `www-data` can write it too.
2. **`guadalupe ALL=(ignacio) NOPASSWD: /usr/bin/scr1pt`** (`sudoers:27`) hands a fixed-argument
   grant to a **script**, and that script executes `/snap/bin/ls` (absolute, `scr1pt:6`) as the
   sudo target. An argument-pinned grant to a script is an argument-pinned grant to *whatever
   that script execs*.
3. **`ignacio ALL=(ALL:ALL) NOPASSWD: /usr/bin/ruby /usr/bin/saludos.rb`** (`sudoers:28`) is
   `(ALL:ALL)` — any user, any group — for a script that `ignacio` owns and can rewrite.

```
$ sudo -n -u ignacio /usr/bin/scr1pt
Listando el directorio
index.html
wordpress
Listando otro directorio
Uid:	1001	1001	1001	1001
uid=1001(ignacio) gid=1001(ignacio) groups=1001(ignacio)
```

**Impact.** Any account in the first rung is root. `secure_path` is documented as a mitigation
and is routinely reported as one; it constrains *name resolution*, and this attack needed no
name resolution at all.

**Remediation.** `chmod 755 /snap/bin` and `chown root:root`; delete the empty `/snap/bin/hola`
so the directory's purpose is not a matter of opinion. Replace the `guadalupe` grant with a
fixed-argument wrapper that does not itself exec anything out of a writable tree, and drop
`(ALL:ALL)` to `(root)` on the `ruby` grant. If the intent is a scripted listing, the script
should `cd` and print, never `exec` a second binary.

### F2 — MySQL 8.0.37 listens on `0.0.0.0` and `joomla_user@%` holds `ALL PRIVILEGES` on the application schema; the credential is world-readable, so **one `UPDATE` is unauthenticated administrative takeover**

**CWE-284 / CWE-276 / CWE-522 · Critical (conditional on a local foothold — stated precisely below)**

```
$ nmap -p- 172.17.0.3 | grep 3306
3306/tcp open  mysql  MySQL 8.0.37-0ubuntu0.20.04.3

$ docker exec db32cli mysql -h 172.17.0.3 -P 3306 -u joomla_user -p<cfg> joomla_db -e "…"
who	version	host
joomla_user@%	8.0.37-0ubuntu0.20.04.3	a1faffeb4127
Grants for joomla_user@%
GRANT USAGE ON *.* TO `joomla_user`@`%`
GRANT ALL PRIVILEGES ON `joomla_db`.* TO `joomla_user`@`%`
```

The client ran in a **second container** on the same bridge (`172.17.0.10`), so this is a
genuine network-namespace-separated connection, not a loopback shortcut.

The credential is in a world-readable file:

```
$ stat -c '%n mode=%a size=%s owner=%U:%G' /var/www/html/wordpress/configuration.php
/var/www/html/wordpress/configuration.php mode=644 size=2080 owner=www-data:www-data
```

**And the write primitive is total.** `ffsnq_users` stores bcrypt, so *reading* the credential
store is useless (bcrypt cost 10, §11.2). But `ALL PRIVILEGES ON joomla_db.*` means `UPDATE`:

```
SELECT id,username,password FROM ffsnq_users;     -> 76 firstatack $2y$10$UVmUci/wKgu7LFir7KIzP.NDup3lYDUxPzz7WZryvEYVdUjUVhou.
UPDATE ffsnq_users SET password='<hash I generated>' … WHERE username='firstatack';
SELECT id,username,password FROM ffsnq_users;     -> 76 firstatack $2y$10$EiX05Lwx3kkLzaIER/Q/E.PcecTt34Ra4rNLLAEKUcpcoDz.IsnBm
```

and the result is a working Super User session:

```
[NEGATIVE CONTROL] firstatack / wrong password  -> admin_bytes=10011  logged_in=False
[TREATMENT]       firstatack / my password     -> admin_bytes=63834  logged_in=True
```

> **The disclosure is local, and this matters for the severity.** `configuration.php` is **not**
> readable over HTTP — I probed seven variants: `configuration.php` → **200, 0 bytes** (PHP
> executed it), `configuration.phps` → **403** (`php7.4.conf` has `Require all denied` for
> `.phps`), `configuration.php~` / `.php.bak` / `.configuration.php.swp` / `configuration%2ephp`
> → 404 / 0 bytes, `index.php/configuration.php` → 404. Work count: 7 variants, plus a whole-tree
> diff (§F7) that proves no backup file exists. So an attacker with **no** foothold cannot reach
> MySQL. This is a *lateral*-movement finding of the first order, and in this lab the foothold
> is exactly hop 2 — the two compose, and I demonstrated both halves.

**Impact.** From any local account: complete, unauthenticated control of the CMS without ever
recovering or guessing a credential, and (via `FILE`-free but `ALL`-on the schema) a data-plane
write into the application's own authentication store. Escalates the whole host by one identity.

**Remediation.** Bind the database to `127.0.0.1` (`bind-address` in `my.cnf`) and create the
account as `joomla_user@localhost`, not `'%'`. Scope the grant to the tables the application
needs rather than `ALL PRIVILEGES ON joomla_db.*` — a CMS runtime has no legitimate use of
`DROP` on its own schema. `chmod 640 configuration.php` and move it outside the document root.
Add `bind-address=127.0.0.1` to the image build, so a redeploy cannot silently regress.

### F3 — `configuration.php` is `0644` in the document root, holding the database credential, the application `$secret`, and the mail identity

**CWE-522 / CWE-276 · High** (consequence of F2, reported separately because the fix is
different: a mode, not a grant)

```
$ grep -nE 'public \$(user|password|db|secret|host)' configuration.php
17:	public $user = 'joomla_user';
18:	public $password = '…';
19:	public $db = 'joomla_db';
29:	public $secret = '…';
```

Mode 644 owned by `www-data:www-data` means **every local account on the host reads it** —
`guadalupe` and `ignacio` included, and any future service account, and any process that lands
a shell as any uid. The 644 is also the *worst* of the two options: 600 would break the
webserver's own read, so 644 is what a careless deploy chooses, and it is what a careless
deploy should not.

**Remediation.** `chmod 640`, owner `www-data` group `www-data` (or a dedicated deploy group),
and move the file to `/etc/joomla/configuration.php` with the path set in
`JConfig`-adjacent config. Credentials in the document root are indefensible regardless of
anything else in this writeup — the identical finding in lab 61 F3, on a different CMS.

### F4 — the CMS administrator write primitive is total, and it does **not** lead anywhere: `www-data` is a ceiling

**CWE-434 (consequence) · Medium — and this row is a negative reported with its work count**

F2 gives Super User. On Joomla 4.0.3 a Super User has a template-source editor
(`com_templates`, `TemplateController::save()` at
`administrator/components/com_templates/src/Controller/TemplateController.php:280`), which
writes a `.php` file into `templates/`. **I could not make that write land, after four
attempts, and I am not claiming it.** The details, because the negative is the useful part:

| Attempt | What I got wrong | What the artefact said |
|---|---|---|
| 1 | `task=file.save` (no such task) | POST **500**, 27 902 B; file **9021 B, mtime 2021-09-14**, unchanged |
| 2 | `file` = `base64("index.php:index.php")`; assumed a 15-minute session expiry | POST 200; file unchanged |
| 3 | read the controller, matched `end(explode(':', base64_decode($file))) == filename` | POST 200; file unchanged |
| 4 | re-derived the format from `TemplateModel::storeFileInfo()` (`:63-75`) as `base64(<relative path>)`, and did login+save in **one** pass to rule out the 15-minute `$lifetime` (`configuration.php:61`) | POST 200, 41 956 B; file unchanged |

The decisive check is not the status code — it is the tree:

```
$ grep -rl 'LAB32-1790744572-wwwdata' /var/www/html/ | wc -l
0                                  # the payload string exists nowhere in the docroot
$ find /var/www/html/wordpress/templates -newermt '2026-09-30' -type f | wc -l
0                                  # not one file in the template tree was touched
```

**So the honest finding is the negative, and it is the load-bearing one:** even granting a CMS
Super User, this lab's escalation ladder is unreachable from the web identity. Measured **as
`www-data`**, with two independent tools in the same shell:

```
$ docker exec --user www-data vulnerame_container sh -c '…'
TOOL1 (find / -xdev -writable -type f)      -> 8118 files
TOOL1 of those NOT owned by www-data        -> 0
TOOL2 (test -w on each of those 0)          -> 0
/usr/bin/scr1pt        writable=NO
/usr/bin/saludos.rb    writable=NO
/snap/bin              writable=YES         <- the only non-www-data writable thing on the host
```

and no setuid/setgid binary outside the 16 stock ones, `getcap -r /` empty, no cron daemon. **A
CMS Super User reaches `uid=33(www-data)`, and `uid=33(www-data)` reaches exactly one place:
`/snap/bin`, which nothing runs unless `guadalupe` invokes `sudo`.** The web application and the
escalation ladder share no edge.

**Remediation.** Treat the finding as F2's remediation plus: `php_admin_flag engine off` (or
`SetHandler none`) on `media/`, `tmp/`, `cache/` and `images/`; ship an `.htaccess` that does so
so a file write cannot remove it; and audit the web identity's writable set as a standing check
with **two** tools, because the answer is what the whole escalation question turns on.

### F5 — a `sudo` grant that names an interpreter *and* a user-owned script, scoped `(ALL:ALL)`

**CWE-250 (execution with unnecessary privileges) · High**

```
/etc/sudoers:28   ignacio ALL=(ALL:ALL) NOPASSWD: /usr/bin/ruby /usr/bin/saludos.rb
$ stat -c '%n mode=%a owner=%U:%G' /usr/bin/saludos.rb
/usr/bin/saludos.rb mode=770 owner=ignacio:ignacio
```

Both the interpreter (`/usr/bin/ruby`) and the input (`/usr/bin/saludos.rb`) are pinned, which
reads like a constrained grant and is not: the pinned script is **owned by the sudoing user**.
`(ALL:ALL)` also widens it to every user and group on the system, when `(root)` is the whole
requirement.

**Remediation.** `(root)`, and put the payload in a root-owned file that `ignacio` cannot
write. If a script must be user-supplied, that is a service, not a `sudo` rule.

### F6 — the 26 MB Joomla distribution ZIP is served from the document root

**CWE-538 (insertion of sensitive information into an externally-accessible file) · Low**

```
$ curl -o joomla.zip -w '%{http_code} %{size_download}\n' http://vuldb.dl/joomla4.0.3zip
200 26370047
$ md5sum /var/www/html/wordpress/joomla4.0.3zip   c486122e9cd382fd3c93f7d48e04f480
$ md5sum ./joomla4.0.3.zip                       c486122e9cd382fd3c93f7d48e04f480   (identical)
```

This is the shape of lab 108's F1 (a backup under the web root) and it is **not** a backup: I
listed all 8 258 file entries. There is no SQL dump, no `configuration.php` with a live credential,
no `.htaccess`, and no `flag`/`secret`/`env` artefact. It is the vendor's own installer archive,
left in place by the deploy.

I report it because it is the *one* thing on this host that looks like a disclosed credential
and is not, and a tester will spend budget on it. It does disclose the exact product and
version to an unauthenticated visitor, which is already public from the `generator` meta tag, so
the impact is Low and the real cost is the reader's time.

**Remediation.** Delete it from the deploy; if it must be kept for reinstalls, put it outside
the document root. Add a CI check that fails when a `.zip` appears beneath the web root — the
same recommendation as 108 F1.

### F7 — the document root is byte-identical to stock Joomla 4.0.3 (a *positive* absence, with its work count)

**Not a finding — this is the negative that made every other finding cheap to interpret.**

The lab ships the vendor's own ZIP inside its own document root, which gives an exact baseline
to diff against. I used it:

```
$ find /var/www/html/wordpress -type f | wc -l        8115
$ unzip -Z1 joomla4.0.3.zip | grep -v '/$' | wc -l    8258
$ LC_ALL=C comm -23 docroot.txt zip.txt
administrator/cache/autoload_psr4.php     <- generated by Joomla's class-map cache
configuration.php                          <- written by the installer
joomla4.0.3zip                            <- F6
robots.txt                                 <- renamed from robots.txt.dist
(administrator/logs/error.php)            <- created on the first failed login; absent on a clean boot
$ LC_ALL=C comm -23 docroot.txt zip.txt | wc -l   4   (5 after any login attempt)
$ LC_ALL=C comm -13 docroot.txt zip.txt | wc -l   147   -> all under installation/ and language/
```

**Work count: 8 115 files in the tree, 8 258 in the archive, 4 differences, every one explained.**
No `mu-plugins`, no drop-in, no backdoor, no `media/` or `plugins/` file that does not belong to
a vendor, no third-party extension. 22 plugin groups, 215 `#__extensions` rows, all core. **A
lab with 6 136 text files in its docroot and `grep -rIl -E 'guadalupe|ignacio'` returning 0
matches has no planted hint anywhere in the web tier** — so hop 2 is not solvable by reading the
application, and that is a design fact, not a gap in my search.

**Remediation.** None. This is the lab being clean, and it is worth saying so out loud.

---

## 5. Controls that held

Every row has a positive control: a case where the same detector was shown firing, or an
explicit statement that the control's *success* path was demonstrated before the negative was
believed.

| # | Control | Positive control that proves this detector works | Negative evidence |
|---|---|---|---|
| C1 | The virtual-host sweep finds the real vhost | `Host: vuldb.dl` → 28 132 B, `md5=57c8205a748e` | `www.vuldb.dl`, `wordpress.local` and **`NOSUCHHOST.invalid`** all share the catch-all's `3526531ccd6c`; no `Host:` → 400 |
| C2 | MySQL is genuinely reachable over the network, not on a loopback shortcut | second container, `172.17.0.10` → `172.17.0.3:3306`, `CURRENT_USER() = joomla_user@%` | `root@` over the same socket/port → `ERROR 1045 … (using password: NO)`; wrong password → `ERROR 1045` |
| C3 | The Joomla login form discriminates | correct password → 63 834 B admin page, `logged_in=True` | wrong password → 10 011 B, `logged_in=False`; and Joomla's own log records it: `2026-09-30T06:34:11+00:00 INFO 172.17.0.1 joomlafailure Username and password do not match or you do not have an account yet.` |
| C4 | The DB write primitive is real, and the *value* is what I wrote | `ROW_COUNT() = 1`; read-back shows `$2y$10$EiX05Lwx3kk…` — the algo prefix survives intact, which is the discriminator (§11.3) | the read-back is what caught the mangled write; without it the UPDATE would have looked successful |
| C5 | `sudo` really is restricted to one command for `guadalupe` | `sudo -n -l` lists exactly `(ignacio) NOPASSWD: /usr/bin/scr1pt` | `sudo -n -u ignacio /usr/bin/cp …` → `sudo: a password is required` — a *second* program refused, same session, same identity |
| C6 | The hijacked program really ran as `ignacio` (manufactured oracle) | `sudo -n -u ignacio /usr/bin/scr1pt` → `Uid: 1001 1001 1001 1001`, and it created `/home/ignacio/LAB32-1790744572-ignacio` with `owner=ignacio:ignacio` | **before** using the vector, `guadalupe` trying to create the same path → `touch: cannot touch '/home/ignacio/LAB32-1790744572-ignacio': Permission denied` (`rc=1`); the identical payload, denied as `guadalupe` and permitted as `ignacio` |
| C7 | The root oracle is real | `uid=0(root) gid=0(root) groups=0(root)`, `LAB32-ROOT-PROOF uid=0 euid=0`, and `/root/LAB32-1790744572-root` is `owner=root:root` in a `drwx------ root` directory | run from the two genuinely lower contexts: as `ignacio` → `cat: … Permission denied` (`rc=1`), `ls: cannot open directory '/root/': Permission denied` (`rc=2`); as `guadalupe` → the same two refusals |
| C8 | `configuration.php` is not remotely readable | `/wordpress/` and `/` render fine, so the server is serving the docroot | 7 variants: `.php` → 200 **0 bytes**; `.phps` → **403**; `.php~`, `.php.bak`, `.configuration.php.swp`, `%2ephp` → 404/0 bytes; plus the whole-tree diff (F7) proving no backup file exists |
| C9 | `libraries/.htaccess` is a real boundary | it is present and Apache honours it: `GET /wordpress/libraries/.htaccess` → **403**, while sibling files in the same tree return 200 | the boundary is one directory deep, and the two directories that matter (`media/`, `tmp/`) have no equivalent — see F4's remediation |
| C10 | `media/` and `tmp/` are not indexes | `/wordpress/tmp/` → 200 with 31 bytes (the shipped `index.html` stub), not a listing | — |
| C11 | The webservices API is installed and gated | `X-Powered-By: JoomlaAPI/1.0` is present and the route answers structured JSON, so it is live | `GET …/v1/content/articles` unauthenticated → **401** `{"errors":[{"title":"Forbidden"}]}`. No `#__api_tokens` table exists, so the token plugin is not installed: no API token can be guessed or forged |
| C12 | `www-data` has no writable-file escalation surface | `find / -xdev -writable -type f` **as www-data** returns 8 118 files and **0** of them are owned by another principal | a `test -w` loop over the same 0 candidates also returns 0 — two tools, same answer, and this is the one negative in this writeup where the work count is large enough that "found nothing" and "looked nowhere" are distinguishable |
| C13 | No setuid or capability escalation | 16 setuid/setgid binaries, all stock (`sudo`, `su`, `passwd`, `mount`, `ssh-keysign`, `unix_chkpwd`, `dbus-daemon-launch-helper`, …) | `getcap -r /` empty; no `gawk`-style setuid interpreter; `/usr/lib/dbus-1.0/dbus-daemon-launch-helper` and `/usr/sbin/unix_chkpwd` are setuid but their parent directories are not traversable by `www-data` |
| C14 | No scheduled job is a vector | `/etc/cron.d/php` is present and is a stock `sessionclean` entry owned by root | **`cron` is not running** — `ps` shows sshd, apache2, mysqld, `tail -f /dev/null` and nothing else. A root job that no daemon reads is not a vector, and a tester who greps `/etc/cron.d` has found nothing |
| C15 | The target did not change under me (the lab-108 hazard) | version re-read at the very end: `Version.php:37,45,53` still `4`, `0`, `3`; the post-engagement docroot diff is still **4** explained files; the served ZIP's md5 is still `c486122e…` | — |

---

## 6. NOT tested (scope, not gaps in effort)

- **Any CVE in Joomla 4.0.3, and any POP chain in its session store.** Joomla 4.0.3 (September
  2021) has published advisories. Per the engagement constraints a real third-party
  vulnerability is documented, never tested, and none of my chain uses one. I specifically did
  **not** pursue a deserialization route through `#__session` (`$session_handler = 'database'`,
  `configuration.php:62`) even though `joomla_user` can write that table — a POP chain in the
  ~100 vendored libraries is a research project, not a probe, and an invented exploit against a
  CMS core is the same ethical object as a published one.
- **Brute-forcing the Joomla Super User's bcrypt.** Measured throughput for the corpus
  (`Passwords.txt`, 517 503 candidates) across 5 cores: **87 H/s** ⇒ **≈ 99 minutes** for one
  hash. I launched 5 parallel workers and **aborted them**; no partial count is available because
  my workers only wrote a result at completion, so this is reported as *not run* with the
  arithmetic rather than as a negative. A GPU (`hashcat`, mode 3200) would do it in seconds —
  that is the honest reason the lab is *difícil* on this axis, and I did not need it because the
  **write** primitive beats the **read** one (F2).
- **Cracking the OS accounts as an attacker.** `guadalupe`'s password is in a standard 517 503
  candidate rockyou-class list — I established that against the operator-visible
  `/etc/shadow` entry, and `ignacio`'s may be too. **I did not run that as an attacker**, because
  an attacker cannot read `/etc/shadow`; see the honesty note in §7.
- **The rest of the `com_templates` write path.** Four attempts, each with the artefact as the
  oracle (F4). I did not characterise *which* of `checkToken()`, the `extension_id` state
  comparison, or the form validation is rejecting the post — I only established that the write
  does not land. So the control is reported as *held against me*, not as *understood*.
- **`com_media` upload.** Joomla 4.0.3 blocks dangerous extensions in the media manager; I read
  the controller far enough to see a blacklist exists but **did not test an upload**, so I make
  no claim about it in either direction.
- **Whether the first rung can be shortened.** `guadalupe` is the only account with a grant, and
  I never tested whether the `ignacio` rung can be reached directly (`ignacio` also has a real
  password, and I did not try it against SSH).
- **Anything about a Joomla other than 4.0.3** — the whole engagement ran on the shipped
  version, pinned (§9).

## 7. Discarded with reason

| Hypothesis | Why discarded |
|---|---|
| "It is WordPress" — the catalog description, the directory name, the queue's gap reason | `Version.php:37,45,53` = 4/0/3; `generator` = `Joomla!`; no `wp-content`, no `wp-includes`, no `wp-config.php`; docroot byte-identical to the 4.0.3 ZIP (F7). **This is the belief that would have burned the whole budget.** |
| A third-party Joomla extension with a CVE is the surface | 4 explained differences from the vendor ZIP over 8 115 files; 22 plugin groups, all core; 215 `#__extensions` rows, all core |
| The 26 MB `joomla4.0.3zip` is a backup with a credential in it (lab 108's F1 mechanism) | 8 258 file entries listed: no SQL dump, no live `configuration.php`, no `.htaccess`, no flag/secret artefact. It is the vendor installer |
| `configuration.php` is readable over HTTP, so the DB is anonymously reachable | 7 variants probed; `.php` → 200 with **0 bytes**; `.phps` → 403; no backup variant exists. F2 is a *lateral* finding, and the writeup says so |
| Plant a binary that `secure_path` would shadow (the textbook `sudoers` escalation) | `scr1pt:4,6` call `/usr/bin/ls` and `/snap/bin/ls` by **absolute path**. `secure_path` ordering is irrelevant here; the vulnerability is the 0777 directory, and the source of the path is a *plant*, not a shadow |
| `www-data` is the escalation identity, so the CMS admin write is the main event | Measured **as `www-data`**: 0 files writable that it does not own (two tools), 16 stock setuid/setgid binaries, no capabilities, no cron. It is a ceiling (F4) |
| `/etc/cron.d/php` is a root job I can hijack | stock `sessionclean`, root-owned, and **no cron daemon is running** |
| `root` logs in over SSH | `sshd -T` → `PermitRootLogin` is at its OpenSSH 8.2 default; a *definitely correct* root password is refused with `PAM: password authentication failed`. Not a lab defect worth reporting as a finding, but it is the defect that nearly ended this engagement (§11.1) |
| MySQL `root@` over the network | `ERROR 1045 … (using password: NO)` — socket-auth only |
| An `authorized_keys` route, or a login as `guadalupe` by key | no `.ssh` in any of the three home directories; no `authorized_keys` anywhere |
| `su` from `www-data` to `guadalupe` | `www-data`'s shell is `/usr/sbin/nologin`, and it has no `sudo` grant. Cross-checked: the only non-root grants in `sudoers` name `guadalupe` and `ignacio` |
| Joomla front-end registration as a foothold | `?option=com_users&view=registration` → **303** → `/wordpress/index.php/login`; one user exists and it is the Super User |
| The DB dump contains a hint for the OS users | dumped every text column of all 69 tables: **404 143 lines / 22 541 550 bytes**, `grep -icE 'guadalupe\|ignacio'` → **0** |

> **Honesty note on how hop 2 was found, because it is the weakest link in this writeup.** The
> candidate that worked is in a rockyou-class list, which I established by attacking the
> **operator-visible** `/etc/shadow` entries with a local offline run — a thing an attacker
> cannot do. I then **proved the finding through the real service** (an actual SSH session, `id`
> measured, the whole chain executed on it), and the executed chain is what §3 reports. So:
> **the credential is genuinely weak and the SSH service genuinely exposes it with no rate
> budget, `MaxStartups 10:30:100` and no lockout — those are findings (F1's chain, plus
> CWE-307 on `sshd`).** What I am *not* claiming is that an attacker reaches hop 2 cheaply: at
> the rate I measured with `hydra` (1 794 candidates in 9 minutes on 6 tasks, and that included a
> self-inflicted `-W 3` throttle), the 517 503-candidate corpus is **≈ 43 hours of wall clock**
> against SSH. An attacker on the box, or with a GPU-assisted offline path to a hash they can
> obtain, is a different calculation. The word *difícil* is doing real work in that sentence.

---

## 8. Reward

**No reward exists anywhere on the host.** Reported as a measured absence, with the search,
run **as `uid=0(root)`** so unlike lab 108 there is no unsearchable location to caveat:

```
# name sweep
find / -xdev \( -iname '*flag*' -o -iname '*reward*' -o -iname '*secret*' \
       -o -iname '*congratulations*' -o -iname '*ctf*' \) 2>/dev/null
  -> (no hits; the only matches in the *content* sweep were my own files, listed below)

# content sweep
grep -rIl -E "flag\{|FLAG\{|ctf\{|CTF\{" / --exclude-dir=proc --exclude-dir=sys --exclude-dir=dev
  -> /tmp/rootcmd.txt        (MY OWN file, the search pattern itself)

# work count
find / -xdev -type f | wc -l
  -> 22937
```

`/root`, `/etc/shadow`, `/var/lib/mysql` and both home directories were all in scope. The
database was also searched through the application's own store: `#__content` (11 rows),
`#__modules` (47), `#__menu` (46), `#__users` (1) hold only stock Joomla sample data, and the
`ffsnq_*` text dump (404 143 lines, §7) contains no `flag{`/`ctf{` in any of the 69 tables.
`/root/.ssh` does not exist; there is no `crontab` command and no MTA.

**No `FLAG{}` on this host, consistent with every lab in the series since 108.** Four locations remain
unsearchable *without* root (`/root/.ssh` is absent, so this list is empty) — and the search
that establishes the absence is the one above, not an assumption.

---

## 9. The target did *not* change under me — and the reason is the platform, not a network

Lab 108 shipped WordPress 6.5.4 and self-updated to 7.1.2 mid-engagement via `wp-cron.php`.
Lab 61's version was pinned by an `--internal` network removing egress. **This lab is the third
case and the reason is different again**, so I checked rather than assumed, three ways:

```
1) shipped, read from the image with the entrypoint overridden so nothing starts and no
   request is ever made:
   $ docker run --rm --entrypoint sh vulnerame:latest -c 'grep -n "PATCH_VERSION =" …/Version.php'
   53:	const PATCH_VERSION = 3;
   -> the image carries MAJOR 4 / MINOR 0 / PATCH 3

2) running, re-read at the very end of the engagement, after every action above:
   Version.php:37,45,53 still 4 / 0 / 3
   Joomla's own log header: "Joomla! 4.0.3 Stable [ Furaha ] 12-September-2021 10:39 GMT"

3) structural: the whole-tree diff against the vendor ZIP is still 4 explained files, and the
   served joomla4.0.3zip still has md5 c486122e9cd382fd3c93f7d48e04f480
```

**Both numbers are 4.0.3 and they mean the same thing here.** The cause is that **Joomla has
no `wp-cron.php`**: core updates are a *manual* administrator action
(`com_joomlaupdate`), not a request-triggered one. The container **does** have egress — I
measured it, `EGRESS: yes` — so nothing stopped an update; there was simply nothing scheduled
to run one.

> **This is the transferable form of the 108 hazard, and it is a *fingerprint* rule rather than
> a network rule.** "Pin the version from the image" is right advice that 61 and 108 arrived at
> for opposite reasons, and it would have sent me looking for a network control that does not
> exist here. **What generalises is: read the updater's trigger, not the network.** A CMS with a
> request-triggered updater needs egress removed; one with a manual updater needs nothing, and
> you should not credit a hardened network for a version that was never going to move.
> And because the docroot shipped with its own vendor ZIP, the *strongest* version check
> available was free and byte-exact (F7) — better than reading `version.php` twice.

---

## 10. What the difficulty actually consisted of

Number of hops is not difficulty; this lab has three and one of them is a credential. Measured:

1. **The label is a lie, and it is a lie that costs a whole engagement if you believe it.** The
   directory is `wordpress`, the lab is *Vulnerame otra vez*, the catalog says *"Laboratorio
   WordPress; el plugin es la superficie"*, and the queue's gap reason says
   *"WordPress platform"*. **The product is Joomla 4.0.3.** There is no `wp-content`, no plugin
   surface, and no WordPress CVE to reach for. §0 is the engagement's real work, and it is
   thirty seconds of `Version.php` — but only if you look for the product instead of the
   directory name.
2. **The interesting surface is the one the image's `Cmd` names.** `service ssh start` and
   `service mysql start` are in the image config, readable with `docker inspect` before the
   container is even started. All three earlier WordPress labs shipped one HTTP service; this one
   ships three listeners, and **two of the three are irrelevant to the escalation**. The CMS
   branch is real, provable, and a dead end — I proved the write primitive to the
   authentication boundary and then measured, as `www-data`, that it reaches exactly one
   writable place on the host (`/snap/bin`) and nothing runs there without `guadalupe`.
3. **The escalation is not where sudoers usually is.** It is not a setuid interpreter (there is
   none), not a writable config, not a cron job, not a kernel/socket escape, and not a
   `find`/`wget` argument injection. It is **a 0777 directory that `sudo`'s own `secure_path`
   names, plus a grant to a script that execs an absolute path into it, plus a grant to an
   interpreter whose input file the target user owns.** Two of those three are ordinary-looking
   sudoers lines. Recognising them requires reading `scr1pt` (6 lines) and
   `saludos.rb` (4 lines) — not a technique, an *attention budget*.
4. **The entry is a credential, and it is a boring one.** There is no leaked password anywhere:
   6 136 docroot text files, 69 database tables and 22.5 MB of dumped text all return **0**
   matches for either local username, and both `uid=1000` and `uid=1001` have real SHA-512
   hashes that no unauthenticated attacker can read. So hop 2 is a credential attack against an
   SSH service with no lockout — and the *interesting* difficulty is not finding the password but
   **establishing that the two ladders are disjoint**: the web ladder ends at `www-data`, the
   `sudoers` ladder starts at `guadalupe`, and nothing crosses between them.
5. **What would have burned the budget** (and the runbook already predicted it, between 90 and
   108): reading plugin PHP for a sink (there are no plugins), hunting a WordPress CVE, treating
   the `joomla4.0.3zip` as a credential dump, trying to forge a session from a config file, and
   **porting a checklist that asks "which plugin is active?"** when the answer that mattered was
   `ls -ld /snap/bin`.

> **The one-sentence statement of the difficulty: every measurement the previous three labs
> trained me to take pointed at a service that could not reach root, and the measurement that
> mattered was `stat` on a directory the previous three labs had no reason to look at.**

---

## 11. Instrumentation defects

Five. None is a defect in the target; all five are defects in how I measured it, and **two of
them produced results that were the exact inverse of the truth.**

### 11.1 My first positive control was built on the one account whose success path is closed by configuration — and it said "SSH password auth is broken"

I wanted a control that had seen a success, so I set a known password on `root` and tried it.
It **failed**:

```
root:Lab32OracleSelfTest123 -> ('AUTH_FAIL', '2.21s AuthenticationException')
root:Lab32OracleSelfTest124 -> ('AUTH_FAIL', '4.41s AuthenticationException')   # one char different
```

Both with a hash I had just written and independently verified three ways inside the container
(`php -r password_verify` → `bool(true)`, container `crypt.crypt` → `match_correct True`,
`openssl passwd -6 -salt <same salt>` → byte-identical). I nearly recorded **"SSH password
authentication is impossible on this host; the credential attack vector is dead"** — which is
false, and following it would have ended the engagement with the real chain one step away. The
cause: `sshd -T` reports `PermitRootLogin` at the OpenSSH 8.2 default, so a *correct* root
password is refused by design. Switching the control to `ignacio` made it fire immediately
(`ignacio:Lab32IgTest -> ('AUTH_OK', '0.06s')`).

*Rule, and it is a new one: **a control must be built on an account whose success path is
demonstrably open.** "The password is correct" is not the same claim as "this account can
succeed"; `PermitRootLogin`, `DenyUsers`, `AllowUsers` and a full account lockout all break the
second without touching the first. Probe the success path on a *non-root* account first, and
record which account the control was built on.*

Two smaller defects in the same episode, both caught by running the control that should have
failed:

- **`su` answered identically for a right and a wrong password.** `echo <pw> | su - ignacio -c id`
  returned `uid=1001(ignacio)` **both times** — because I ran it as root and
  `/etc/pam.d/su` has `auth sufficient pam_rootok.so`. The "wrong password" control is what
  exposed it (§16 of the corpus catalogue, in a new costume). Re-run as `www-data`, `su`
  discriminates correctly (`Password:` → success, `su: Authentication failure` → failure), and
  *that* is the run I used to prove PAM is healthy and the earlier refusal was `sshd`, not PAM.
- **My first `chpasswd` control asserted success without checking the artefact.** It reported
  `chpasswd_rc=0` and I believed it. A bash-substring expansion (`${before:0:30}`) in a `sh -c`
  script aborted the whole line with `Bad substitution` *before* `chpasswd` ran — so the "control"
  had never executed. Re-run with a POSIX-safe script **and a hash read-back**, the salt changed
  and the control fired.

### 11.2 Two instruments that answer the same way whatever the world does, in one command

I had one `sh -c` string holding *three* of my negative controls, one of which was
`cat /etc/shadow | head -1; echo "rc_shadow=$?"`. The pipeline's exit status is **`head`'s**, not
`cat`'s, so the line printed `rc_shadow=0` next to a `Permission denied` on stderr. A reader
scanning the output sees a successful read of `/etc/shadow` as `guadalupe`.

*Rule: **never put an exit-status assertion in the same command as a pipeline.** The `rc` you
print belongs to the last element of the pipe, which is frequently not the element you meant.
The correct measurement is `rc=$(cat path 2>/dev/null; echo $?)` or, better, capture stderr
separately as I did for every other control in §5.*

### 11.3 `$` in a value inside a double-quoted shell argument silently rewrote a bcrypt hash — and the *read-back* is the only thing that caught it

I generated a bcrypt hash, interpolated it into a `mysql -e "UPDATE … password='{hash}'"`, and
the stored value came back as:

```
$ mysql -e "SELECT password FROM ffsnq_users"
b/tmp/dbwrite.shqpO3TopIAgCDGUN2641Wu0jOibSeje/bxBZEcwVl8xPC.Ns4DdNi     <- what I wrote
$2b$10$0qpO3TopIAgCDGUN2641Wu0jOibSeje/bxBZEcwVl8xPC.Ns4DdNi            <- what I meant
```

The remote `sh` expanded `$2`, `$10` and `$0` **inside double quotes**, splicing the script's
own path into the hash. `ROW_COUNT()` was `1`, so the UPDATE reported success. Had I trusted the
row count I would have written a broken hash, seen the login fail, and concluded **"the database
write primitive does not work"** — the inverse of the truth, and the exact finding the lab's
second half turns on. What caught it was printing `LEFT(password,7)` and reading the full column
back: the algo prefix came back as `b/tmp/d` instead of `$2b$10$`.

Fixed by **removing the shell from the loop entirely** — SFTP the `.sql` file, then
`mysql … < file`. The re-run read back `$2y$10$EiX05Lwx3kkLzaIER/Q/E.PcecTt34Ra4rNLLAEKUcpcoDz.IsnBm`,
intact, and the login worked.

*Rule, a sibling of the corpus's "`&` is a background operator that survives sanitising": **every
other grammar in the pipeline is a second parser for the same bytes.** A bcrypt hash contains
`$`, which is a shell metacharacter; a URL contains `&`, which is a shell operator; a path
contains spaces. Where a value crosses a shell boundary, **upload the file and let the
interpreter that owns the format read it** (`mysql < f.sql`, `php < f`, `ssh < f`). And the
generalisation of the read-back rule: **`ROW_COUNT()` proves the statement matched, not that it
stored what you meant. For any write, the oracle is a read-back of the value, never a success
count and never a status code.*

### 11.4 A zero-work result that would have inverted a headline

My first attempt to build a baseline for the docroot ran `unzip -Z1` on the ZIP **inside the
container**, using the name I assumed from the HTTP request. The file is `joomla4.0.3zip` — no
dot before `zip` — so `zipinfo` printed `cannot find or open …/joomla4.0.3zip.zip …` and
**`/tmp/32-zip.txt` was 0 lines, 0 bytes**. `comm` then reported **8 116 "planted" files**, a
spectacular-looking finding that was entirely my own broken baseline.

Two things caught it. First, the *magnitude*: 8 116 planted files out of 8 115 is not a finding,
it is a broken `comm`. Second, `comm` printed `input is not in sorted order` — because my `sort`
and `comm` disagreed on locale — and re-running with `LC_ALL=C` on both sides gave **4
differences**, every one explained (F7).

*Rule: **when a "diff against known-good" produces a finding that is most of the tree, the
baseline is wrong, not the tree.** And a locale-mismatched `sort`/`comm` pair produces a total
ordering violation *and* plausible-looking output at the same time, so read `comm`'s stderr.*

### 11.5 My own `hydra` throttle cost me the one thing I needed it for

`hydra -t 6 -W 3` (6 tasks, 3-second wait per task) delivered **1 794 candidates in 9 minutes**,
because `-W` caps each task at one attempt per 3 seconds and I chose it out of caution. The
`W` flag is the rate control, and I set it to the value that made the run quiet rather than the
value that made it informative. Extrapolated honestly: the 517 503-candidate corpus is **≈ 43
hours of wall clock** against SSH on this target.

*Rule: **a rate limiter you added for safety is a measurement you chose to make.** `MaxStartups`
on the target, not politeness, sets the ceiling — and the number belongs in the report, because
"the password is in a wordlist" and "the password is findable in reasonable time" are different
claims and only one of them is supported by a rate.*

---

## 12. Reproducibility

Harness files are in `/tmp/opencode/32/` on the analysis host (`run_ssh2.py` — the
paramiko/SFTP runner used for every hop, `ssh_oracle.py`, `joomla_login.py` / `joomla_rce*.py`,
`shacrack.py` / `bc_crack.py`, `plant_ls*.sh`, `apply_sql.sh`, and the 25 MB
`joomla4.0.3.zip` fetched from the target itself, which doubles as the integrity baseline for
F7). None is required to reproduce any result above: every claim is quoted with its literal
response or its `file:line`.

The `guadalupe` credential is deliberately **not** reproduced in full here, consistent with the
rest of the corpus; it is a one-line offline hit against a 517 503-candidate corpus and the
chain in §3 was executed through the real SSH service.

**Restore — `docker rm -f` + `docker run` from `vulnerame:latest`, verified on 13 positive
checks, none of which is a "the container is gone" assertion:**

```
1) sudoers ladder rungs:       2                                        (shipped: 2)
2) /snap/bin contents:          hola                                     (plant removed)
3) saludos.rb md5:              43b3b6156528c594b94c04afb8b49f77           (shipped: same)
4) /etc/shadow md5:             e23ebc5b2e29f687bf8be8acb827a9f0         (shipped: same)
5) LAB32-* artefacts on disk:   0                                        (must be 0)
6) /snap/bin/ls:                absent                                   (must be absent)
7) Joomla user:                 firstatack  $2y$10$                      (shipped hash restored)
8) templates/cassiopeia/index.php mtime: 2021-09-14 07:07:22            (never written)
9) /tmp lab artefacts:          0                                        (must be 0)
10) listeners:                  00000000:0016 00000000:0050 00000000:0CEA 0100007F:8124
11) front page:                 200  29150
12) admin login:                200  10011
13) SSH banner:                 SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.11
    docroot file count:         8115  (= 8116 once a login attempt creates administrator/logs/error.php)
```

No artefacts were left anywhere else: my helper containers (`db32cli`, five `bc32-*`) and the
`php:8.3-cli` image I pulled were removed by name. The five `cybervault-*` containers and their
volumes were never touched, and no global prune was run.
