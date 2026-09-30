# ACME Corporation — DockerLabs Writeup

**Target:** `http://172.17.0.3:80` (container `acme_container`, image `acme:latest`, Apache/2.4.52 Ubuntu, PHP-FPM 8.1, MariaDB, OpenSSH)
**Internal services:** `127.0.0.1:8080` (Apache vhost → WordPress), `127.0.0.1:3306` (MariaDB), `127.0.0.1:9000` (PHP-FPM), `0.0.0.0:22` (OpenSSH)
**Date:** 2026-09-27
**Outcome:** Two flags recovered. User-level flag as an unprivileged SSH user; root flag as **uid=0** through a two-hop chain that required no application credentials at all.

---

## 1. Target, stack, and how the chain was actually found

The lab ships as a single tar loaded into Docker; there is no API specification and no Swagger surface. Reconnaissance therefore started from the exposed ports and went straight to source, which is the §7 rule in action: **read the container before probing the container.**

| Port | Binding | Service |
|---|---|---|
| 22 | `0.0.0.0` | OpenSSH (`sshd -D`, under supervisord) |
| 80 | `0.0.0.0` | Apache — `DocumentRoot /var/www/maintenance`, a single static decoy page |
| 8080 | **`127.0.0.1` only** | Apache vhost `wordpress.conf` — `DocumentRoot /var/www/wordpress` |
| 3306 | `127.0.0.1` | MariaDB |
| 9000 | `127.0.0.1` | PHP-FPM FastCGI |

The published surface is one static HTML page. The actual attack surface is a *bastion topology*: the public host is a maintenance decoy, and the interesting service is an internal-only vhost that any local account can reach over loopback. Port 8080 being bound to `127.0.0.1` is what makes the lab's name literal — and it is the pivot the whole chain turns on.

### The decoy, and what it was actually telling me

Port 80 serves a styled "Modo Mantenimiento" page reading *"El acceso a las consolas de gestión se realiza exclusivamente mediante el servicio SSH. Pruebe a conectarse por SSH con **cualquier usuario**"*, with the hint *"El servidor SSH emitirá automáticamente el banner de bienvenida del nodo con el protocolo de mantenimiento."*

Read as attacker guidance, that page is not a hint — it is a **map of the intended chain**, and the `X-Notice` response header (`Connect via SSH to view system access banner`) repeats it. The claim "cualquier usuario" is a lure toward spraying credentials. The real defect is one layer down: `sshd_config` sets `Banner /etc/issue.net`, and `/etc/issue.net` is served **before the authentication prompt**. There is no guessing, no spraying, and no lockout to evade. The credential is *handed to the client*, unauthenticated, by the server's own login banner.

**A note on target-supplied text.** The container's startup log contains a line styled as an error: `Removed matches synchronization on error (Restored CVE-2026-63030 Desync Bug)`. That string is data emitted by the target, not a finding, and it was treated as such. No request-desync behaviour was observed, no HTTP desync was tested, and the root cause below was derived independently from file permissions and interpreter configuration. The flag value happens to embed a matching identifier, which is the lab's own narrative — not evidence. This is the correct handling of a target that asserts a vulnerability about itself: **a target's claim about its own weakness carries zero evidentiary weight until reproduced.**

The same defect the §7 rule in [Decision Making](decision-making.md) describes is present here too, in the same shape: `/etc/ssh/sshd_config:16` carries the comment `# Banner with credential hints for Nmap` directly above `Banner /etc/issue.net` (`:17`). The configuration names its own purpose and names the tool expected to find it. Two independent targets, the same annotation antipattern — which is a reasonable prior that it is a habit of this exercise series rather than a coincidence, and a standing reminder that a config file is a source file and carries the same comments.


---

## 2. Finding 1 — Operational credentials disclosed in a pre-authentication banner

**Category:** CWE-497 Exposure of Sensitive System Information to an Unauthorized Control Sphere, with CWE-200.

### Evidence

SSH connection to the exposed port, with **no credentials supplied at the point the banner is emitted**:

```
$ ssh usuario@172.17.0.3
Warning: Permanently added '172.17.0.3' (ED25519) to the list of known hosts.
===================================================================
[*] ACME Corporation - Nodo Bastion de Mantenimiento Interno
[!] AVISO DE SEGURIDAD Y ACCESO:
[!] Portal corporativo en proceso de migracion a infraestructura interna.
[!] Credenciales temporales asignadas para tareas de mantenimiento:
[!]   - Usuario: usuario
[!]   - Password: <REDACTED>
===================================================================
usuario@172.17.0.3's password:
```

The ordering is the whole finding. The banner is emitted **above** the `password:` prompt. The client receives a working username and password before it has authenticated to anything — no request required, no guessing, no rate limiting, and nothing to brute-force because there is no guessing involved.

Login then succeeds with exactly the disclosed material, and **no** WordPress, database, or application credential is required at any point:

```
usuario@172.17.0.3's password:
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 7.0.0-34-generic x86_64)
usuario@172.17.0.3:~$ id; hostname; whoami
uid=1000(usuario) gid=1000(usuario) groups=1000(usuario)
05d3737a07ff
usuario
```

Session established as an ordinary, unprivileged, non-sudoable account.

### Flag 1 — recovered

`/home/usuario/user.txt` is `root`-readable but owned by `usuario` at mode `644`, so the foothold account reads it directly:

```
usuario@172.17.0.3:~$ cat /home/usuario/user.txt
<flag value withheld — sha256 99a0ef6c44d6710794dc0f62f5ba69359f2c45148b53155e4277b4446bb997d3>
```

**Proof of possession, not the value** — per `decision-making.md` §"Claim vs verified", `sha256(flag)` proves possession without publishing the secret:

| Artifact | sha256 | bytes |
|---|---|---|
| `/home/usuario/user.txt` | `99a0ef6c44d6710794dc0f62f5ba69359f2c45148b53155e4277b4446bb997d3` | 39 |

### Impact

Complete pre-authentication compromise of the bastion. An anonymous network peer reads a valid credential from the service's own greeting and logs in. The account is low-privilege, so this is a foothold rather than host compromise — but the foothold is on a host whose entire purpose is to front internal services, and step 3 shows what a foothold on this host is worth.

### Root cause

`/etc/ssh/sshd_config` sets `Banner /etc/issue.net`, and that file is a static, world-readable, world-writable-by-build text containing a live credential. Two independent failures compose:

1. **A credential was written into a file served pre-auth.** SSH banners are shown to every connecting party, authenticated or not. They are a *public* channel by specification; a banner is the wrong place for a secret under any circumstances.
2. **The credential is real and static.** `/entrypoint.sh` provisions the account at build time with a fixed password, so every deployment of this image ships the same working secret. The banner is not a stale copy of a rotated credential — it is a live one.

Note the layering. The public page's claim that access is "exclusively via SSH" is *true*, and it is the problem: the design routes all administrative trust through a single service whose pre-auth channel is a public broadcast.

### Remediation

1. Remove the credential from the banner immediately and treat it as compromised — rotate the account's password and every credential it could reach.
2. Move the notice to `/etc/issue` or MOTD, which is emitted **after** successful authentication, and keep it free of secrets.
3. Ban credentials in any pre-auth channel as a CI check, not a review convention: grep the image for `Banner`-referenced files and fail the build on a password-shaped literal.
4. Provision per-deployment credentials at first boot from a secret store, never baked into an image layer. A credential in an image is a credential in every clone of that image, forever, including in any registry the image was ever pushed to.
5. If a banner is genuinely required for operational reasons, sign it and treat it as public — and put nothing in it that is not already public.

---

## 3. Finding 2 — World-writable document root: code execution with no application credentials

**Category:** CWE-732 Incorrect Permission Assignment for Critical Resource, chained with CWE-434 and CWE-269 (execution at the interpreter's privilege).

This is the finding that carries the chain, and its most important property is what it **does not** require: **no WordPress account, no admin password, no SQL injection, no application-level exploit of any kind.** The application is never attacked. A file is written to a directory, and the interpreter picks it up.

### Evidence

`/entrypoint.sh` sets the permissions explicitly, which is what makes this a designed defect rather than a packaging accident:

```
chown -R www-data:www-data /var/www/maintenance /var/www/wordpress
chmod -R 775 /var/www/wordpress
chmod -R 777 /var/www/wordpress/wp-content
```

Observed state — the entire `wp-content` tree, and the plugins directory inside it, are world-writable:

```
drwxrwxrwx 1 www-data www-data 4096 Aug 18 23:42 /var/www/wordpress/wp-content/plugins/
-rwxrwxrwx 1 www-data www-data 2669 Jul  6 21:09 /var/www/wordpress/wp-content/plugins/hello.php
drwxrwxrwx 3 root     root     4096 Sep 27 21:23 /var/www/wordpress/wp-content/uploads/
```

The `usuario` account from Finding 1 is in group `usuario` and holds no membership in `www-data`, so the `777` — not group membership — is what authorises the write. Staging the payload as the unprivileged foothold user:

```
usuario@172.17.0.3:~$ echo <base64> | base64 -d > /var/www/wordpress/wp-content/probe.php
$ ls -l /var/www/wordpress/wp-content/probe.php
-rw-rw-r-- 1 usuario usuario 409 Sep 27 21:26 /var/www/wordpress/wp-content/probe.php
```

The file is now owned by `usuario` and lives inside the document root of the internal vhost. Requesting it needs no WordPress session, because Apache serves `wp-content` as a static path and hands `.php` to the FPM handler:

```
usuario@172.17.0.3:~$ curl -s http://127.0.0.1:8080/wp-content/probe.php
```

```
=== PHP RCE as ===
uid=0(root) gid=0(root) groups=0(root)
=== sudo -n -l (as this user) ===
User root may run the following commands on 05d3737a07ff:
    (ALL : ALL) ALL
=== cat /root/root.txt direct ===
<flag value withheld — sha256 f02e22b392250b831c4c045a7540bc833060e542196cd8183c91105dd786ba27>
=== sudo -n cat /root/root.txt (privesc) ===
<flag value withheld — sha256 f02e22b392250b831c4c045a7540bc833060e542196cd8183c91105dd786ba27>
=== whoami under sudo ===
root
```

### Flag 2 — recovered

| Artifact | sha256 |
|---|---|
| `/root/root.txt` (`root:root`, mode `600`) | `f02e22b392250b831c4c045a7540bc833060e542196cd8183c91105dd786ba27` |

Reached as `uid=0(root)`, mode-`600` file that the `usuario` foothold could not read.

### A correction the evidence forced

The first hypothesis was that this chain ended at `www-data` and needed a privilege escalation to cross to root. **The evidence contradicted it.** `id` inside the executed PHP returned `uid=0(root)` on the very first call, and `cat /root/root.txt` succeeded with **no `sudo` at all** — the `sudo -n` line was never the mechanism. The escalation had already happened at the interpreter boundary, one hop earlier than assumed:

```
$ grep -E '^\s*(user|group|listen)' /etc/php/8.1/fpm/pool.d/www.conf
user = root
group = root
listen = 127.0.0.1:9000
$ ps -o user,pid,args -C php-fpm8.1
root         281 php-fpm: master process (/etc/php/8.1/fpm/php-fpm.conf)
root         350 php-fpm: pool www
root         352 php-fpm: pool www
```

**The PHP-FPM worker pool runs as `root`.** So the real chain is two hops, not three, and the honest finding is not "web shell plus privesc" — it is **"web shell, and the web service is already root."** Every PHP execution primitive on this host is a root shell, and any PHP-level vulnerability anywhere in the document root is a full host compromise with no further work. Had the assumption gone unchallenged, the report would have named a privesc step that does not exist and understated the severity of the interpreter misconfiguration, which is the actual root cause.

### Impact

Unauthenticated-to-the-application remote code execution **as root**, from any local account on the host, requiring only write access to a world-writable directory. Root-owned filesystem read and write, arbitrary package installation, credential extraction from the whole host, and a pivot to every internal service on loopback including the database socket. The compromise is total and needs no application-layer exploit.

### Root cause

Two independent defects, either of which alone is serious:

1. **CWE-732 — the document root is world-writable.** `chmod -R 777` on `wp-content` hands code-drop rights to *every* local account, including any account obtained by a low-severity foothold. The directory is writable precisely because a build step needs to write there; the fix is to make the owning service account the only writer (`775`, owner `www-data`) and to keep the build writing through that account.
2. **CWE-269 — the interpreter executes as root.** `user = root` in the FPM pool means the process identity has no confinement whatsoever. The `listen.owner/listen.group = www-data` socket restriction is irrelevant: it controls *who may connect to the FPM socket*, not *what the worker becomes* once a request is accepted.

The dangerous composition is worth stating plainly: defect 1 is what makes the write possible, and defect 2 is what makes the write worth doing. A world-writable document root behind a properly-confined `www-data` pool is a serious finding. Behind a root pool, it is a one-request host takeover. **Report the interpreter's execution identity as a finding in its own right** — it is the assumption every other web-app severity rating silently depends on, and it is the one most often left at the distro default and never verified.

### Remediation

1. Set `user = www-data` / `group = www-data` in the FPM pool and restart it. Verify with a request that prints the execution identity — do not assume the distro default survived the image build.
2. Set `chmod 775` on `wp-content`, owned `www-data:www-data`, and remove the `777`. Nothing in a running site needs a world-writable content directory; if a plugin does, fix the plugin.
3. Move uploaded and generated content **outside** the document root entirely, served by a handler that streams with an explicit `Content-Type`. A PHP file should never be reachable at a predictable static path.
4. Disable the PHP engine in any directory that accepts writes, or gate execution behind a hard-coded path allowlist rather than a `FilesMatch \.php$` pattern applied to a tree that includes user-writable space.
5. Run the whole stack — Apache, PHP-FPM, MariaDB — as distinct unprivileged users, and add a container-level read-only root filesystem with dropped capabilities so an interpreter compromise cannot reach the host.

---

## 4. Finding 3 — Passwordless root sudo granted to the web service account

**Category:** CWE-250 Execution with Unnecessary Privileges / CWE-269.

**This finding was not used in the chain, and it is reported anyway.** That distinction matters and is stated explicitly rather than buried.

`/etc/sudoers` contains:

```
www-data ALL=(ALL) NOPASSWD: ALL
```

Had PHP-FPM been confined to `www-data`, this single line would have converted every code-execution primitive on the site into root — no exploit chain, no kernel bug, just `sudo -n /bin/bash`. It was never needed, because the pool was already running as root (Finding 2). Two independent paths to root existed; the chain took one, and this is the other.

Per `decision-making.md` §"Load-bearing does not mean classified", the inverse case deserves the same discipline: an unused root path is not a non-finding because the chain found a shorter one. A reviewer who fixed only the `777` would believe they had closed the hole, while `www-data` retained passwordless root. **The remediation for this line is independent of, and additional to, everything in Finding 2.** It is reported with its own impact and its own fix for exactly that reason.

**Remediation:** delete the line. If a task genuinely requires privilege, grant the specific binary as a specific user, with an argument allowlist — `www-data` needs no `sudo` at all once the pool runs as `www-data`. Add a CI check that fails the build if any `NOPASSWD: ALL` rule exists for a non-interactive service account.

---

## 5. The chain, in order, and why each step is necessary

| # | Action | Credential required | Delivers |
|---|---|---|---|
| 1 | Port scan → `22/tcp`, `80/tcp` exposed | none | the SSH surface exists |
| 2 | Connect to `22`, read the banner **before** authenticating | none | a working username and password (Finding 1) |
| 3 | Log in as the disclosed user | the disclosed credential | `uid=1000`, unprivileged, no sudo — **flag 1** |
| 4 | Read `sshd_config` → `Banner`; read Apache vhosts → WordPress on `127.0.0.1:8080`; read `entrypoint.sh` | foothold | the document root, the `777`, the FPM pool identity |
| 5 | Write a `.php` file into world-writable `wp-content` as the foothold user | foothold only | a file owned by `usuario` inside the document root |
| 6 | `GET http://127.0.0.1:8080/wp-content/probe.php` | foothold only (loopback) | code execution by the FPM pool — Finding 2 |
| 7 | Observe `uid=0`; read `/root/root.txt` | none | **flag 2**, as root |

**Why each step is load-bearing:**

- **Step 1→2:** step 2 is impossible without the banner; the credential is not guessable and not derivable.
- **Step 2→3:** the foothold is unprivileged by design (`id` → `uid=1000`, `sudo -n -l` → *"a password is required"*, no rule in `/etc/sudoers.d/`). It buys nothing on its own. It buys **filesystem access as a named local account**, which is what step 5 needs.
- **Step 3→5:** the write requires *some* local identity. Any account would do — the point is that Finding 1's low-privilege account is sufficient, which is what makes the chain's severity independent of the credential's importance.
- **Step 5→6:** the file must be *inside the document root* to be reachable, and *writable by the foothold* to be plantable. Both conditions come from Finding 2; neither is an application exploit.
- **Step 6→7:** reaching `127.0.0.1:8080` requires being **on the host**. A remote attacker with only Finding 1's credential on a different machine cannot use it — which is exactly why this is a bastion-topology lab. The loopback binding is a real control that Finding 2 partially defeats by running from the inside.

Note what is **absent** from that table: any WordPress login, any database credential, any application-level exploit, and any `sudo`. The application is never compromised in the conventional sense. It is bypassed entirely by writing a file the interpreter will pick up. **A vulnerability class that requires no interaction with the application's own logic is invisible to every scanner that probes endpoints** — which is the argument for reading source and reading permissions first.

---

## 6. What did not work, and what was not tried

### Discarded with a reason

| Path | Why discarded |
|---|---|
| Credential guessing / user enumeration on SSH | Not attempted, and not needed. The credential is disclosed pre-auth. Spraying here would be both pointless and a self-DoS risk against a live `sshd` (`decision-making.md` §"Self-DoS is a testing defect"). |
| HTTP request smuggling / desync | **Never tested**, and specifically *not* on the strength of the `CVE-2026-63030 Desync Bug` string in the container's startup log. That line is target-supplied text, not a finding. No desync behaviour was observed, and the root causes here are permissions and interpreter identity — neither of which desync would explain. Recorded as **not tested**, not as dismissed. |
| WordPress login / admin credential path | Not needed. `wp-content` is writable by any local account, so the entire authentication surface of the application is bypassable. The `wp core install` step in `entrypoint.sh` does provision an admin account, but using it would have been *slower and weaker* than writing a file — worth recording as the reason the app's auth was never a factor. |
| MySQL `SELECT … INTO OUTFILE` / `LOAD_FILE` | **Tested and failed.** `wp_user` holds `ALL PRIVILEGES` on `wordpress.*` but `USAGE` globally, so no `FILE` privilege. `LOAD_FILE('/etc/hostname')` returned `NULL`; the outfile attempt was refused. Dead end, with the reason recorded. |
| Privilege escalation from `www-data` via `sudo` | **Tested and unnecessary.** The `NOPASSWD: ALL` rule exists and would have worked, but `sudo -n cat` was never the mechanism — `cat` as plain `www-data`/root already succeeded. Reported as an independent finding (Finding 3), not as a chain step. |
| SUID/cron/systemd abuse | Enumerated and found nothing usable: the SUID set is the stock Ubuntu set (`newgrp`, `chfn`, `mount`, `umount`, `su`, `bash`, `sudo`, `ssh-agent`, `unix_chkpwd`, `pam_extrausers_chkpwd`) with no custom binary; `/etc/crontab` has no entries; `/var/spool/cron/crontabs/` is empty; `/etc/cron.d/` holds only stock `e2scrub_all` and `php`. The escalation was in the FPM pool all along. |
| Unauthenticated access to port 8080 from the host | Refused at the network layer — confirmed. The vhost binds `127.0.0.1:8080` and the connection from the test host failed. It is reachable from *inside* the container only, which is the point of the bastion design. |

### Not tested — open, with the vector recorded

- **The MariaDB instance.** `mysql -u root` succeeds over the unix socket **with no password** (verified). Unreachable from the foothold account, so it was not a chain step — but on any host where the socket is exposed or the account is in a group that can reach it, that is instant full database compromise. Not exercised further.
- **WordPress itself, as an application.** No plugin, theme, or core vulnerability was assessed. With `akismet` and `hello.php` as the only plugins there was no CVE surface to chase, and the file-drop path made the question moot. The WordPress version was never fingerprinted.
- **The `/api`-equivalent surface.** None exists. There is no JSON API, no OpenAPI document, and no Swagger UI in this lab, so the "document the spec before fuzzuring" shortcut from `api_web.md` had nothing to apply to. Recorded so the next reader does not look for it.
- **Other local accounts.** `/etc/passwd` was enumerated for uid < 65534; the only interactive account is the one in Finding 1. Whether other seeded accounts exist with different privilege was not tested.
- **Network pivoting.** No attempt was made to reach services beyond the container's own loopback set, or to fingerprint the Docker host. Out of scope for the lab.
- **Persistence.** The planted `probe.php` was **removed** after evidence capture (`rm -f /var/www/wordpress/wp-content/probe.php`, verified). No persistence mechanism was installed or tested.

---

## 7. Artifacts

Raw evidence under `/tmp/opencode/dl_labs/acme-evidence/`:

| File | Contents |
|---|---|
| `root.html`, `root.hdr` | the port-80 decoy page and headers, including the `X-Notice` banner hint |
| `ssh_login.txt` | the full SSH transcript: pre-auth banner, password prompt, successful login as `uid=1000` (password redacted) |
| `rce_wwwdata.txt` | the executed payload output: `uid=0`, `sudo -n -l`, both flag reads |

Container-side evidence, reproducible with `docker exec acme_container`:

| Path | What it shows |
|---|---|
| `/etc/ssh/sshd_config` | `Banner /etc/issue.net`, `PasswordAuthentication yes` |
| `/etc/issue.net` | the credential disclosure, mode 644, served pre-auth |
| `/etc/apache2/sites-available/wordpress.conf` | the internal vhost on `127.0.0.1:8080` |
| `/etc/php/8.1/fpm/pool.d/www.conf` | `user = root` — the interpreter's execution identity |
| `/etc/sudoers` | `www-data ALL=(ALL) NOPASSWD: ALL` (Finding 3) |
| `/entrypoint.sh` | the build-time design: `chmod -R 777`, the provisioned accounts, the `wp core install` step |

**No credential, cookie, token, or flag value from this engagement appears in this document.** The SSH password, the WordPress admin password, the database password, and both flag values are withheld; each flag is identified by its `sha256` and its on-disk path instead, which is the convention this repository already sets in `decision-making.md` §"`sha256(flag)` is the proof, not the value."
