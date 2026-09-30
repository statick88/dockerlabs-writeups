# 188 Wargames — writeup

**Target:** `172.17.0.3` — **Debian GNU/Linux 13 (trixie)**, Apache **2.4.65-2**, OpenSSH
**10.0p2 Debian-7**, vsftpd **3.0.5-0.2**, Python **3.13.5-1**, sudo 1.9.16p2-3.
Four listening TCP ports: **21, 22, 80, 5000**. No UDP.
**Result:** unauthenticated → `uid=1000(joshua)` (SSH) → **`Uid: 0 0 0 0`** (SUID `godmode`).
**Reward recovered:** `WOPR{THE_GAME_IS_ENDING_YOU_WIN}` — **there is no `FLAG{}` in this lab**
(§10, with the search and its counts).

**Full catalogue description** (the queue truncated it):
*"El objetivo principal de este laboratorio fue practicar técnicas de reconocimiento, análisis
de servicios y escalada de privilegios en un entorno controlado con un fuerte componente de
lógica y análisis estático."*

**Topology.** `auto_deploy.sh` was read, never run. One container, default bridge, **no custom
network, no macvlan, no second host** (`auto_deploy.sh:131`; the `while true` is at `:145`).
The engagement is single-host and stayed single-host. Note `:46` — the script would `docker stop`
and `docker rm` **any** container whose id starts `5938*`, i.e. it reaches outside this lab.
Another reason never to run it.

---

## 0. The headline

**The manifest label for this lab is `recon and service analysis`, and that is the correct
class — but the single most valuable thing in the image is not on any service. It is in the
image's own build record.**

Three things invert the obvious reading of this lab:

1. **The catalogue's platform neighbours are all WordPress; this one is not.** There is no
   WordPress, no `wp-*` path, no PHP. Port 5000 speaks a custom line protocol. The lesson is
   lab 32's again, in its purest form: *read a version-bearing file before writing a single word
   about the platform.* Here the version-bearing files are `/etc/os-release`
   (`PRETTY_NAME="Debian GNU/Linux 13 (trixie)"`, `DEBIAN_VERSION_FULL=13.2`) and
   `dpkg-query -W` (`apache2 2.4.65-2`, `openssh-server 1:10.0p1-7`, `vsftpd 3.0.5-0.2`).
2. **The service's most eye-catching output is a decoy, and I proved it two independent ways.**
   The WOPR AI hands over a 64-hex value explicitly labelled `SSH PASSWORD`. It is not joshua's
   password — not over SSH, and not against the shadow hash directly. It is also not `godmode`'s
   passphrase. §6/F2, §9.
3. **The credential is in `docker history`, in plaintext, and the runtime files do not contain
   it.** `echo "joshua:1983@1983" | chpasswd` is a build layer. The lab's own description names
   *"análisis estático"*, and this is the surface it means — not the SUID binary, which is
   comparatively obvious. §5, F3.

And the enumeration lesson the queue asked for: **eleven surfaces (E1–E11), 159 application-level
probes, one account, and the account's completeness confirmed against `/etc/passwd` rather than
assumed** — plus a
**second instance of lab 87's absent-path trap, in a different costume** (§2.2, §11.1). Lab 87's
was a `301`; this lab's is a **`403` that a name-based rule emits before it ever checks whether
the file exists**, and a status-code sweep here reports **5 present files when 2 exist**.

---

## 1. Surface

```
$ nmap -sV -Pn -p- --version-all 172.17.0.3
PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.5
22/tcp   open  ssh     OpenSSH 10.0p2 Debian 7 (protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.65 ((Debian))
5000/tcp open  upnp?
Not shown: 65531 closed tcp ports (conn-refused)
```

Port 5000 is unrecognised to nmap and its fingerprint is the service's own banner — which is
itself the identification: the probe bodies are all
`"WELCOME TO WOPR\nSHALL WE PLAY A GAME?\n\n>\x20"`. **The service names itself**, and no version
string is offered; the version that matters is read from the artefact (§1.1).

**Cross-check: the scan and the kernel agree, independently.** The container has no `ss` and no
`netstat` (`ss -lntup` → `NOSOCKTOOL`), so the socket list came from `/proc`:

```
$ cat /proc/net/tcp            # 3 listener rows
   0: 00000000:1388 ...   <- 5000/udp? no: 0x1388 = 5000
   1: 00000000:0016 ...   <- 0x16 = 22
   2: 00000000:0050 ...   <- 0x50 = 80
$ cat /proc/net/tcp6           # 2 listener rows
   0: ...:0015 ...       <- 0x15 = 21
   1: ...:0016 ...       <- 22
```

Union = **4 TCP ports**, matching `-p-` exactly. `0x1388 = 5000` computed, not read.

**What a TCP scan cannot see — measured, with the work count:**

| Check | Result | Work count |
|---|---|---|
| `/proc/net/udp` | header only | **0** socket lines (1 line total, header) |
| `/proc/net/udp6` | header only | **0** socket lines (1 line total, header) |
| `docker inspect … .Config.ExposedPorts` | `{"5000/tcp":{}}` | 1 image |
| `getcap -r /` | empty | **0** lines |
| `find / -xdev \( -perm -4000 -o -perm -2000 \)` | 19 binaries | **19** files |
| `/etc/cron.d/` + `/var/spool/cron/crontabs/` | only Debian defaults | **0** job files |

Note the two UDP checks are **1 line each** and that line is the header. A blank and a header
look identical in a report; these are counted (§14 of self-corrections).

### 1.1 Stack and versions — from the artefact, not from the banner

| Layer | Finding | Source |
|---|---|---|
| OS | Debian GNU/Linux **13 (trixie)**, 13.2 | `/etc/os-release` |
| Web | **Apache httpd 2.4.65-2**, `DocumentRoot /var/www/html`, one vhost, no `Alias`, no `Rewrite` | `dpkg -l`; `sites-enabled/000-default.conf` |
| App | `python3 3.13.5-1` — a custom TCP service on **5000** | `dpkg -l`; `/usr/local/bin/script.py` |
| SSH | **OpenSSH 10.0p2 Debian-7**, OpenSSL 3.5.4 | `/usr/sbin/sshd -V` |
| FTP | **vsftpd 3.0.5-0.2**, `anonymous_enable=NO`, `local_enable=YES` | `/etc/vsftpd.conf` |
| Accounts | **`joshua` is the only `uid≥1000` with a login shell.** `root`'s password field is `*` | `/etc/passwd`, `/etc/shadow` |
| Hash | **yescrypt** `$y$j9T$…`, 73 chars — the Debian trixie default | `/etc/shadow` |
| SUID | 19 binaries; **`/usr/local/bin/godmode` `4755 root:root`** is the load-bearing one | `find`, `stat` |
| Capabilities | none (`getcap -r /` → 0 lines) | `getcap` |
| Reward | `/root/flag.txt`, 33 bytes, `0664 root:root` | `ls`, `wc -c` |

**A version discrepancy worth recording rather than smoothing over.** `dpkg-query` reports
`openssh-server 1:10.0p1-7`, and the binary self-reports `OpenSSH_10.0p2 Debian-7`
(`/usr/sbin/sshd -V`), which is also what the wire banner carries
(`SSH-2.0-OpenSSH_10.0p2 Debian-7`). The **package version and the binary version disagree**;
the binary is the deployed artefact, so 10.0p2 is the version that matters. Recorded because a
writeup that quotes `1:10.0p1-7` and a scanner that quotes `10.0p2` are both *right about
different things*, and the reader needs to know which is which.

### 1.2 Surfaces a status-code or label scan gets wrong here

| Surface | Naive read | Actual |
|---|---|---|
| `/` | 200, 118 bytes → "the site" | a 4-line stub: *"Try more basic connection"* |
| `/README.txt` | 200, 980 bytes → "documentation" | **in the docroot, `0664`, world-readable**, and it is the lab's hint sheet — including one hint that does not work (§9) |
| `/.htaccess`, `/.htpasswd` | 403 → "file exists, protected" | **`403` for names that do not exist.** §2.2, §11.1 |
| `/server-status` | 403 → "mod_status present, locked down" | 403 because `Require local` (`mods-available/status.conf:7`) — a *mod_status* endpoint, **correctly held**, and proven so: `200`/5004 bytes from `127.0.0.1`, `403`/275 from outside |
| port 21 | "FTP, anonymous share" | `anonymous_enable=NO`; the "shared network folder" in the README **does not exist** (`/srv/ftp` is empty) |
| port 5000 | "unknown service" | a WOPR simulation; **the name in the banner is not the name of the auth command** |
| `GODMODE` (from the README) | a working override | **does not work**; the actual trigger is `logon joshua` (§9) |

---

## 2. The enumeration inventory

This is the deliverable the queue asked for. **Every row carries a positive control, a negative
control, and a work count, and the last column says what the surface was actually decisive
for** — because enumeration nobody acts on is reconnaissance theatre, and a surface that
produced no finding still gets its row.

| # | Surface | Positive control | Negative control | Work count | Finding it produced |
|---|---|---|---|---|---|
| **E1** | `nmap -p-` TCP sweep | 4 open ports, each with a service banner | 65 531 `conn-refused` | **65 535 ports** | **The port inventory, and the confirmation that 21/80 were *not* noise.** Cross-checked against `/proc/net/tcp`+`tcp6` (4 listeners) — a second, independent instrument, same answer |
| **E2** | UDP sweep via `/proc/net/udp{,6}` | — | — | **0** socket lines, 1 header line, per file | **No UDP surface, as a measurement.** An `nmap -p-` alone could not say this (retrieval-hazards row 1) |
| **E3** | Apache docroot sweep | `index.html` → `200` **118 B**; `README.txt` → `200` **980 B** — and the artefact independently lists **exactly 2 files** | **2 names that cannot exist** (`zzz_definitely_not_here_9f3a.tmp`, `qqqq_impossible_name_zz_7c1e5b2a.txt`) → `404:272`, byte-identical to each other | **65 paths** (2 real + 63 probed) → **2 real, 60 absent, 3 phantom `403`s** | **F4.** The 3 phantom `403`s are the finding: a name-based deny emits `403` **before** checking existence, so a status sweep reports **5 present files when 2 exist** — and the phantoms are `.htaccess`, `.htpasswd`, `.htaccess.bak`, the exact names a scanner hunts for. §11.1 |
| **E4** | `autoindex` (proving E3's "no subdirectories") | **I created** `/var/www/html/aa_probe/inside.txt` → `GET /aa_probe/` = `200` **941 B**, body contains `inside.txt`; and an empty `/bb_empty/` → `200` **743 B** with `Index of` | — (both are positive) | **2 control dirs, created then removed** | **Made E3's "0 subdirectories" a measurement.** Without this the autoindex module would have "confirmed" an absence on a surface that had **never once fired** — self-corrections §1. The control **fired twice** |
| **E5** | WOPR `logon <name>` | `logon joshua` → **`GREETINGS PROFESSOR FALKEN.`**; also fires for `LOGON JOSHUA`, `logon Joshua`, `logon JOSHUA` | `logon` + 22 other names, incl. `root`, `admin`, `www-data`, `falken`, `gospher`, and **2 names that cannot exist**, plus the **empty string** → all silent (`I'M AFRAID I CAN'T DO THAT.`) | **23 names: 1 FIRED, 22 silent, 0 undiscriminated** | **F1.** A clean **user-existence oracle**, unauthenticated, on a non-HTTP protocol a scanner will not touch. **Completeness verified against the artefact:** `awk -F: '$3>=1000 && $7 !~ /nologin/'` → **1** account. One hit out of 23, and the ground truth says exactly one account exists |
| **E6** | WOPR AI response-class sweep | **6** distinct handlers identified: `who are you`, `purpose`, `play a game`, `play <GAME>`, `help`, `list games` | 1 uniform class | **62 inputs → 12 distinct response classes** (37+7+4+3+2+2+2+1+1+1+1+1 = 62, arithmetic checked); **37** of 62 collapse to `I'M AFRAID I CAN'T DO THAT.` | **F1** (mapped the reachable command space) and **F2** (found the `trusted` branch). Also established the case-insensitivity boundary: the token test is `in text` on `.lower()`, so `DEBUG IGNORE` fires |
| **E7** | WOPR `ignore debug` (untrusted) | — | — | **3 runs, all `71` B, md5 `292f6ecb7fa9`** (identical) | **A control that did NOT hold, and is reported as such.** It leaks `Associated name: Joshua` — but it is a **constant**, not an oracle: byte-identical across runs, and it names Joshua regardless of any input. **It carries zero user-existence information.** I initially mislabelled two probes as "negative controls" (`ignore debugX`, `DEBUG IGNORE`); both correctly *fire*, because the test is a substring test. The conclusion is unchanged and is now stated from the md5, not from my label |
| **E8** | vsftpd user enumeration | `220 (vsFTPd 3.0.5)` → `331 Please specify a password.` → `530 Login incorrect.` — **the credential check demonstrably ran** | `anonymous:anonymous` and `zzq_impossible_4711:x` → **byte-identical** `530 Login incorrect.` | **2 usernames** | **A control that HELD.** FTP carries **no** user-existence information. Confirmed by configuration, not inferred: `anonymous_enable=NO`, and `/srv/ftp` is **empty** — so the README's "shared network folder" is a **second decoy** |
| **E9** | sshd user enumeration | — (deliberately not run as a sweep) | `joshua` + wrong password → `AUTH_FAIL` **2.24 s**; `zzq_impossible_4711` + same wrong password → `AUTH_FAIL` **3.22 s** | **2 users, 2 attempts** | **A control that HELD**, and it cost me an outage first: these two attempts are what tripped `PerSourcePenalties` (§11.2). Identical exception type; the 0.98 s spread is yescrypt timing noise. **This is a 2-probe negative, not a sweep** — see §8 |
| **E10** | SUID / SGID inventory | `stat -c '%a %U:%G' /usr/local/bin/godmode` → `4755 root:root` | `getcap -r /` → **0 lines** (cross-checked against `find`) | **19** SUID/SGID files, **0** capabilities | **F5.** Isolated the one non-factory SUID binary out of 19, and confirmed `sudo`, `su`, `mount`, `passwd`, `newgrp` are all **stock Debian modes** — i.e. not the escalation |
| **E11** | Image build record (`docker history --no-trunc`) | — | — | **17 build layers** read in full | **F3 — the decisive surface.** The layer record contains `echo "joshua:1983@1983" | chpasswd` in plaintext. Not one runtime file contains that password: `/etc/shadow` holds a yescrypt hash, there is no `.bash_history`, no `authorized_keys`, no build script, and the only other copy in the whole filesystem is the source of `script.py` itself — which carries the **decoy** |

**Aggregate: 159 application-level probes** — 65 docroot paths + 23 `logon` names + 62 AI
inputs + 3 leak runs + 2 FTP users + 2 sshd users + 2 autoindex controls — **plus E1's 65,535
ports, which is a different unit and is not summed with them.** One account throughout, and the
artefact confirms there is exactly one.

```
$ awk -F: '$3>=1000 && $7 !~ /(nologin|false|sync)/ {print $1,$3,$7}' /etc/passwd
joshua 1000 /bin/sh
```

That is why E5's 22 negatives are *evidence*: the probe range provably contains the one positive,
so the instrument was pointed at the right place — and, as in lab 87, the sweep's completeness is
**verified against the ground truth, not assumed**.

### 2.1 What the surfaces do *not* give you, stated precisely

- **No role, and no privilege level, from outside.** `logon joshua` discloses the *name* only.
  That he is an ordinary user with no sudo rights came from `sudoers` after I was in — reported
  as ground truth, not as an unauthenticated finding. `sudoers` has no `joshua` entry and
  `id joshua` shows `groups=1000(joshua)` only: **he is not in `%sudo`**.
- **No filesystem disclosure from WOPR.** The AI leaks a name and a hex string. It is not a
  directory lister, and `play` reaches only three implemented games.
- **No email, no hash, no session material** on any surface.
- **A decoy that reads like a lead.** The AI's `SSH PASSWORD:` label is a *label*, and I treated
  it as a hypothesis to be tested, not as a credential (§6/F2, §9).

### 2.2 The absent-path trap, in a different costume than lab 87's

Lab 87's trap was a `301` with `X-Redirect-By` and **0 bytes**, byte-identical to a path that
cannot exist — a first sweep reported 24 of 24 present. This lab has the same disease with a
different symptom, and it is worth stating side by side because **a tester carrying lab 87's
rule would have expected a `301` here, found a clean `404`, and concluded the docroot was safe.**

```
$ cat /etc/apache2/apache2.conf:192-197
# The following lines prevent .htaccess and .htpasswd files from being
# viewed by Web clients.
<FilesMatch "^\.ht">
	Require all denied
</FilesMatch>
```

`mod_authz_core` evaluates `<FilesMatch>` **by name, before the file is known to exist**. So:

| Path | Exists? | Response |
|---|---|---|
| `/index.html` | **yes** | `200`, 118 B |
| `/README.txt` | **yes** | `200`, 980 B |
| `/.htaccess` | **no** | **`403`, 275 B** |
| `/.htpasswd` | **no** | **`403`, 275 B** |
| `/.htaccess.bak` | **no** | **`403`, 275 B** |
| `/.htrandom` | **no** | **`403`, 275 B** |
| `/zzz_definitely_not_here_9f3a.tmp` | no | `404`, 272 B |
| `/qqqq_impossible_name_zz_7c1e5b2a.txt` | no | `404`, 272 B |

`/server-status` also returns `403` (275 B) and is **not** a dotfile — it is `mod_status`
correctly held by `Require local`. So **two different causes produce the same 275-byte body**,
which is precisely why a status code cannot be the discriminator.

**The control that settled it** — same path, existence toggled, response unchanged:

```
BEFORE  /var/www/html/.htaccess  does not exist   GET /.htaccess -> 403  275
CREATE  /var/www/html/.htaccess  16 bytes         GET /.htaccess -> 403  275   <- identical
REMOVE  /var/www/html/.htaccess  does not exist   GET /.htaccess -> 403  275   <- identical
```

Existence is **irrelevant** to the status. So `403` here means *"this name is refused"*, never
*"this file is protected"* — and the correct discriminator is the **body bytes** (`200` + a real
length) against the `403:275` and `404:272` baselines.

**Re-swept with the corrected discriminator: 65 paths tried, 2 real, 60 absent, 3 phantom.**
A naive status-code sweep of the same 65 would have filed **5 disclosed files, 3 of them
fabricated**, and would have named `.htaccess` and `.htpasswd` specifically.

---

## 3. The class

**Entry criterion:** *does any unauthenticated, non-HTTP surface disclose an identity or a
credential, and does the artefact's own build record disclose what the runtime files withhold?*

**Source that settled it — the two sinks, read before any request:**

```
/usr/local/bin/script.py   (WOPR, 4251 B, mode 0755)
    if cmd.lower() == "logon joshua":
        trusted = True
    ...
    if trusted and all(x in text for x in ["ignore", "debug", "audit"]):
        return """
[DEBUG MODE ENABLED]
Legacy authentication module active.
SSH USER: joshua
SSH PASSWORD: 60a3f3cb2811ddcea679773863baabd1c78420a13b197b16725905230589bbdb
"""
```

```
/usr/local/bin/godmode   (ELF 64-bit, 16160 B, mode 4755 root:root)
    11a8:  lea 0xe79(%rip),%rdx        # 2028   -> the string "--wopr"
    11b5:  call 1050 <strcmp@plt>      -> strcmp(argv[1], "--wopr")
    11bc:  jne 11e3                    -> mismatch: "ACCESS DENIED. DEFCON remains at 5."
    11c3:  call 1070 <setuid@plt>      edi=0
    11cd:  call 1060 <setgid@plt>      edi=0
    11dc:  call 1040 <system@plt>      # 202f -> "/bin/bash"
```

Both sinks read off the artefact before the first packet. Note that the **auth string for the
SUID binary is a hardcoded constant in `.rodata`**, so `godmode` needed no credential attack at
all — only the *knowledge* of it, which the reverse engineering supplies. That is the
"análisis estático" half of the lab's own description, and it is a different half from the
reconnaissance half.

---

## 4. The credential oracle — the rate was the finding, and a limit was too

The decisive step is a credential attack, so the oracle is documented in full. Lab 87's lesson
was that `password_verify()` is silently always-false on every WordPress ≥ 7 install at
44,339,785 candidates/s. **This lab's lesson is the mirror image: a healthy oracle, and a target
with a hard rate budget that will turn your own attack into a false negative.**

### 4.1 The budget, read from the config the daemon consumes

`/usr/sbin/sshd -T` (§21 — the setting the daemon actually reads, not the file's text):

```
$ /usr/sbin/sshd -T | grep -iE 'persource|passwordauth|usepam|maxauthtries'
persourcepenalties crash:90 authfail:5 noauth:1 grace-exceeded:10 refuseconnection:10 max:600 min:15 …
passwordauthentication yes
usepam yes
maxauthtries 6
```

OpenSSH ≥ 9.8 penalises a **source address**. `authfail:5` means **five failed authentications
penalise the source for at least `min:15` seconds**, and during the penalty the daemon answers:

```
$ exec 3<>/dev/tcp/172.17.0.3/22; head -1 <&3
Not allowed at this time
```

**That is not a block and not a firewall.** `hosts.allow` and `hosts.deny` are both **empty**,
`ldd /usr/sbin/sshd` shows **no `libwrap`**, and the string is in the binary:
`strings /usr/sbin/sshd | grep -i 'not allowed'` → `Not allowed at t at this time`. It took one
connection without authenticating (`noauth:1`, 1 second) to trip, on top of my four failed
passwords. I diagnosed it as a TCP wrapper first and was wrong; **the config and the binary
settled it in two commands.**

### 4.2 Two oracles, and the rate assertion on each

| Oracle | Positive control | Negative control | Rate | Verdict |
|---|---|---|---|---|
| **Network** — PAM over SSH | `joshua` / the correct password → **`AUTH_OK`, 0.09 s** | `joshua` / correct **+ 1 char** → `AUTH_FAIL`, 2.24 s; `joshua` / uppercased → `AUTH_FAIL`, 4.43 s | **2.24–4.43 s** on failures | **GREEN.** Multi-second latency is a real yescrypt KDF; lab 87's 44 M/s always-false would return in microseconds |
| **Offline** — `libxcrypt` via `ctypes` against `/etc/shadow` | `crypt('CANARY188', canary_hash) == canary_hash` → **True** | `crypt('CANARY188X', …)` → **False** | **96.9–98.0 candidates/s** over 100 probes | **GREEN**, same library PAM links against, same `$y$j9T$` format, and the rate proves the KDF ran |

The offline oracle's control hash was **not synthesised**: it is a genuine same-format yescrypt
hash of a known password, produced by the system's own `chpasswd`/PAM, read back from
`/etc/shadow`, and used after the throwaway account was deleted. §22's rule — *a control must
exercise the same code path as the target* — is satisfied by construction here: the control
hash and the target hash were produced by the same PAM stack, and the comparison primitive is
`libcrypt.so.1`, the same library `pam_unix` calls.

Both oracles also carry a **shape assertion** that aborts before any work
(`$y$` prefix, exactly 73 characters, and not the glibc DES sentinel `*0`). That assertion
earned its place — see §11.3.

### 4.3 The negative that survived, with its count

**4,397 lab-themed and common candidates, 0 matches, oracle green at 97.2 candidates/s, 45.23 s
elapsed.** No wordlist corpus exists on this analysis host (`/usr/share/wordlists` absent, no
rockyou, no seclists — the same gap lab 87 recorded), so the search was **generated, not
exhaustive**, and I do not claim otherwise. The same 4,397 candidates were also tested as
SHA-256, MD5, SHA-1 and SHA-512 preimages of the AI's 64-hex value: **0 hits each**.

That negative is reported, but it did not decide the engagement: the credential came from the
build record (§5, F3).

---

## 5. Chain

| # | → | Mechanism | Identity proof |
|---|---|---|---|
| 1 | unauth | TCP recon; `/proc/net/udp{,6}` **0** sockets; `/proc/net/tcp{,6}` = 4 listeners, agreeing with `-p-`; artefact read for versions | — |
| 2 | unauth | **E3** docroot sweep, 65 paths → `index.html` + `README.txt`; **3 phantom `403`s** refuted by an impossible-name control and an existence toggle | `403:275` byte-identical for existing and absent `.htaccess`; absent names → `404:272` |
| 3 | unauth | **E5** WOPR `logon` sweep, 23 names → **`joshua`** | `logon joshua` → `GREETINGS PROFESSOR FALKEN.`; 22 others silent, incl. 2 impossible names; `/etc/passwd` says exactly 1 account |
| 4 | unauth | **E11** read the image's build record → `echo "joshua:1983@1983" | chpasswd` | Two independent confirmations: `libxcrypt` vs the live shadow hash (**True**, with a green control) **and** `AUTH_OK` over SSH |
| 5 | **`uid=1000(joshua)`** | SSH password authentication, PAM `common-auth` → yescrypt | `uid=1000(joshua) gid=1000(joshua) groups=1000(joshua)`; `whoami` → `joshua`; `pwd` → `/home/joshua`; `/proc/self/status` → `Uid: 1000 1000 1000 1000`, `Gid: 1000 1000 1000 1000`, `CapPrm: 0000000000000000`, `CapEff: 0000000000000000` |
| 6 | **`euid=0(root)`** | `/usr/local/bin/godmode --wopr` — SUID-root binary, `strcmp` at `0x11b5`, then `setuid(0)`, `setgid(0)`, `system("/bin/bash")` | `uid=0(root) gid=0(root) groups=0(root),1000(joshua)`; `/usr/bin/id -u` → **0**; `whoami` → `root`; `/proc/self/status` → `Uid: 0 0 0 0`, `Gid: 0 0 0 0`, `CapPrm/CapEff: 00000000a80425fb` |
| 7 | root | read the reward | `/root/flag.txt`, 33 bytes, `WOPR{THE_GAME_IS_ENDING_YOU_WIN}` |

### 5.1 Hop 6's oracle — manufactured, and read back from the unprivileged side

`id` is enough here **only because the SUID bit is real and `setuid(0)` is unconditional after
the `strcmp`**. So I still built the marker the RUNBOOK asks for, and the negative control
first.

**Negative control, as `uid=1000(joshua)` before touching the binary:**

```
$ ls -ld /root
drwx------ 1 root root 4096 Sep 30 13:05 /root
$ cat /root/flag.txt
cat: /root/flag.txt: Permission denied        rc=1
$ /usr/local/bin/godmode zzz_wrong_passphrase
W.O.P.R. Simulation System v1.0
ACCESS DENIED. DEFCON remains at 5.
$ echo 'id' | /usr/local/bin/godmode
W.O.P.R. Simulation System v1.0
ACCESS DENIED. DEFCON remains at 5.
```

**Then the escalation**, writing a randomly-named marker into the root-only directory:

```
$ /usr/local/bin/godmode --wopr        # stdin: id; id -u; /proc/self/status; whoami; touch /root/WG188-35b1947049372b12; ls -la /root; cat /root/flag.txt
uid=0(root) gid=0(root) groups=0(root),1000(joshua)
0
Name:    cat
Uid:     0  0  0  0
Gid:     0  0  0  0
CapPrm:  00000000a80425fb
CapEff:  00000000a80425fb
root
-rw-r--r-- 1 root root    0 Sep 30 13:09 WG188-35b1947049372b12
-rw-rw-r-- 1 root root   33 Dec 29  2025 flag.txt
WOPR{THE_GAME_IS_ENDING_YOU_WIN}
```

**And the marker verified from the unprivileged session, independently of the escalated shell:**

```
$ ls -la /root/WG188-35b1947049372b12        # as uid=1000(joshua)
ls: cannot access '/root/WG188-35b1947049372b12': Permission denied     rc=2
```

The witness is a file in a `drwx------` directory, **owned by root**, with a **random 16-hex
name** so it cannot be confused with anything pre-existing, timestamped at the moment of the
attempt — and the identity that created it is the identity that **cannot even read it back**.
That is the marker the RUNBOOK asks for: *distinguishable by design, in a path only the target
identity can create*.

**The uid/euid pair, reported as a pair** (rule 7). Note that `groups=0(root),1000(joshua)`:
`setuid(0)`/`setgid(0)` do **not** call `setgroups()`/`initgroups()`, so the caller's
supplementary group survives into the root shell. That is a real, if minor, hardening note
(§6/F5) and it is only visible because the pair was read rather than summarised as "root".

---

## 6. Findings

### F1 — Unauthenticated user-existence oracle on a non-HTTP service
**CWE-203 / CWE-204 · Low**

`/usr/local/bin/script.py` sets `trusted = True` on `cmd.lower() == "logon joshua"` and
otherwise says `I'M AFRAID I CAN'T DO THAT.`, so the service answers differently for exactly
one account.

| Probe | Response | Bytes |
|---|---|---|
| `logon joshua` | `GREETINGS PROFESSOR FALKEN.` | 22 |
| `logon root` / `admin` / `www-data` / `falken` / … | `I'M AFRAID I CAN'T DO THAT.` | 29 |
| `logon` + 2 impossible names, + the empty string | `I'M AFRAID I CAN'T DO THAT.` | 29 |

**23 names, 1 fired, 22 silent, 0 undiscriminated**; `/etc/passwd` confirms one account exists,
so the sweep is complete rather than lucky.

Separately, the untrusted branch (`ignore` + `debug`) discloses `Associated name: Joshua`
without any authentication. **That is a constant, not an oracle** — 3 runs, 71 bytes, md5
`292f6ecb7fa9` every time — so it is a disclosure, not a query.

**Impact:** a username, and a ready-made confirmation that it is real, from a port no HTTP
scanner enumerates.

**Remediation:** require a credential before `logon` changes state, or return a uniform
response. The service has no authentication of any kind, which is the root of F2 as well.

### F2 — The AI discloses a credential labelled `SSH PASSWORD` that is not a credential
**CWE-200 / CWE-522 · Informational (a decoy that reads like a lead)**

```
[DEBUG MODE ENABLED]
Legacy authentication module active.
SSH USER: joshua
SSH PASSWORD: 60a3f3cb2811ddcea679773863baabd1c78420a13b197b16725905230589bbdb
```

64 lowercase hex characters, 32 bytes when decoded, not a PEM, not a key. **It is not joshua's
password, and it is not `godmode`'s passphrase.** Proven by two independent paths and by the
binary:

| Test | Path | Result |
|---|---|---|
| `joshua` / the 64-hex over SSH | PAM yescrypt | `AUTH_FAIL` |
| `crypt('60a3f3…bbdb', joshua_hash) == joshua_hash` | `libxcrypt`, direct, green control | **no** |
| the same + `\n`, leading space, uppercase, and 3 truncations | `libxcrypt` | **no** (9 variants) |
| SHA-256 / MD5 / SHA-1 / SHA-512 of 4,397 candidates | host | **0 hits** each |
| `godmode 60a3f3…bbdb` | SUID binary, as joshua | `ACCESS DENIED. DEFCON remains at 5.` |
| `godmode --wopr` | SUID binary, as joshua | **root** |

The 64-hex string appears in exactly **one** place in the entire filesystem — the source of the
service that emits it (`grep -rl` → 1 file). **It is a decoy.** A tester who reads
`SSH PASSWORD:` and files it as a recovered credential would be reporting a label.

**Remediation:** remove it. A simulation that prints a fake credential under a real-sounding
label trains exactly the wrong habit, and it cost me the only credential-attack result in the
engagement.

### F3 — Plaintext credential in the image build record
**CWE-522 / CWE-538 · High as a build-pipeline defect**

```
$ docker history --no-trunc wargames:latest
... /bin/sh -c useradd -m joshua                                    69.6kB
... /bin/sh -c echo "joshua:1983@1983" | chpasswd                    12.3kB
```

The password is in the **layer metadata**, in plaintext, in the artefact anyone who pulls the
image receives. Nothing at runtime discloses it: `/etc/shadow` holds a yescrypt hash, there is
no `.bash_history`, no `authorized_keys`, no build script, and `docker history` is the **only**
place it appears.

**Impact:** full recovery of the sole interactive account from the image alone, with no
brute force and no service interaction. On a real registry this is a published credential.

**Remediation:** `RUN echo 'joshua:…' | chpasswd && rm -f /etc/shadow-` in a **single layer**,
or better, take the password from a build secret and rotate it. Add a CI check that fails a build
whose history matches a credential pattern — `docker history` is a *text* surface and it is
scannable.

### F4 — A name-based deny emits `403` before checking existence, and it is case-sensitive
**CWE-441 / CWE-16 · Low, with a proven bypass**

Debian's `apache2.conf:195` `<FilesMatch "^\.ht">` + `Require all denied` refuses **by name**.
A 65-path sweep reports **5 present files when 2 exist**, and the 3 phantoms are `.htaccess`,
`.htpasswd` and `.htaccess.bak` — the highest-value names in any wordlist. Proven by toggling
existence: `403:275` whether the file is there or not.

**And the rule is case-sensitive**, which is a real, demonstrated bypass:

```
$ echo marker > /var/www/html/.htaccess ; GET /.htaccess  -> 403  275   (denied)
$ echo UPPERCASE_DOTFILE_SERVED_MARKER_188 > /var/www/html/.HTACCESS
$ GET /.HTACCESS -> 200   36 bytes, body contains UPPERCASE_DOTFILE_SERVED_MARKER_188
$ GET /.Htaccess -> 404   (rule does not fire — case-sensitive)
```

Boundary measured, 10 paths: `/.ht`, `/.htrandom`, `/.htaccess.bak`, `/.htaccess.txt` → `403:275`;
`/ahtrandom`, `/a.ht`, `/x.ht.foo`, `/.Htaccess`, `/..htrandom`, `/htrandom` → `404:272`.
So the predicate is `^\.ht` on the final segment, **case-sensitive**.

**Impact:** low in this lab (no dotfile exists), but the bypass is general — any
case-insensitive-origin filesystem (Windows shares, some object stores, macOS) would serve the
file under a different case. And the enumeration consequence is the real cost: a scanner
keyed on status codes files three phantom disclosures here.

**Remediation:** `<FilesMatch "(?i)^\.ht">`, or `RedirectMatch 404 (?i)^\.ht` if the goal is to
make the files *invisible* rather than merely forbidden — the current rule advertises their
existence by answering differently for `.ht*` than for anything else.

### F5 — SUID-root `godmode` escalates any account to root
**CWE-269 / CWE-250 · Critical (given a foothold)**

```
$ stat -c '%a %U:%G' /usr/local/bin/godmode
4755 root:root
```

`strcmp(argv[1], "--wopr")` at `0x11b5` then `setuid(0)`, `setgid(0)`,
`system("/bin/bash")`. The passphrase is a hardcoded constant in `.rodata` (`0x2028`), so this
is not a credential attack — it is a **known-constant** privesc, and the whole lab's
"análisis estático" is aimed at it.

Two hardening notes: `setuid(0)`/`setgid(0)` without `setgroups()` leave the caller's
supplementary groups intact (`groups=0(root),1000(joshua)`), and `system()` runs
`/bin/bash` via `/bin/sh` with no argument vector control.

**Remediation:** `chmod u-s /usr/local/bin/godmode`. A SUID binary whose only gate is a
string constant in its own `.rodata` is not an access control.

### F6 — Three of the lab's four documented leads do not work
**CWE-1188 / lab-design · Informational**

`/var/www/html/README.txt` is world-readable in the docroot and is the lab's hint sheet. It
makes three claims; I tested all three rather than acting on them.

| The README says | Measured | Verdict |
|---|---|---|
| *"Authorized staff can still access it through a special override. (Codename: GODMODE)"* | `logon GODMODE` → **silent**; the real trigger is `logon joshua`. `GODMODE` as a `logon` value does nothing. | **wrong** — and the **binary** is named `godmode`, so the hint points at the right artefact and the wrong *mechanism* |
| *"Some files may be available through the shared network folder."* | `anonymous_enable=NO`; `anon:anon` → `530`; `/srv/ftp` is **empty** (0 entries) | **wrong** |
| *"The HTTP interface may provide hidden hints for operators."* | `/` is a 4-line stub, `index.html` is 118 B, docroot = 2 files, `server-status` is `403` | **nothing there** |

A hint that names a real artefact but the wrong mechanism is worse than no hint: I spent a
WOPR session on `GODMODE` before reading `script.py`. Worth reporting as a lab defect, not as a
finding against the target.

### Not filed as a finding, on purpose

- **"The 64-hex is a hash of the password."** Refuted: 4,397 candidates × 4 digests, 0 hits (§9).
- **"Anonymous FTP is a misconfiguration."** It is **off by configuration** (`anonymous_enable=NO`),
  which is a correct default, not a defect. `local_enable=YES` is the Debian default and the
  single account's password is the gate.
- **"The docroot has no dotfiles."** True, and I verified it against the artefact
  (`find /var/www/html -type f` → 2) rather than against a status code.
- **`/root/flag.txt` is mode `0664`.** World-*readable*, but `/root` is `0700`, so the mode is
  inert; I am not filing it as a disclosure. It is reported in F-table form only because the
  file's mode is a genuine (if harmless) misconfiguration worth a client note.

---

## 7. Controls that held

Every row has a **positive control**: a case where the same detector was shown firing, or a
demonstrated reason the instrument could have been trusted and was not.

| # | Control | Positive control / how the detector was proven able to fire | Negative evidence |
|---|---|---|---|
| C1 | `nmap -p-` saw the whole TCP surface | 4 open ports, each with a service banner, and **every** port probed (65 535) | `/proc/net/tcp` + `tcp6` = 4 listeners, agreeing independently; 65 531 `conn-refused` |
| C2 | No UDP surface | the **files exist and were read** — 1 line each, the header | 0 socket lines in each; the count is explicit so this is a measurement, not a blank |
| C3 | Docroot enumeration discriminates real from absent | `index.html` → `200`/118 B; `README.txt` → `200`/980 B; and `find` independently lists **exactly 2 files** | 2 impossible names → `404:272`, byte-identical; 65 paths → **2 real, 60 absent, 3 phantom** |
| C4 | `autoindex` can list the docroot, so "0 subdirectories" means something | **I created** `/var/www/html/aa_probe/inside.txt` → `/aa_probe/` = `200`/941 B, body contains `inside.txt`; `/bb_empty/` = `200`/743 B with `Index of` | the control **fired twice**; both dirs removed and the removal verified (`probe subdirs: 0`) |
| C5 | The `403` is name-based, not existence-based | `.htaccess` **created** → `403:275`; **deleted** → `403:275` — identical | 10-path boundary map; `/.Htaccess` → `404`, so the rule is case-sensitive |
| C5b | The two `403` causes are distinguishable, though not by status | `server-status` returns the **same 275 bytes** as `.htaccess` — but for a different reason, and its positive control fires: from `127.0.0.1` it is `200`/**5004** bytes; from outside `403`/275. Cause read at `status.conf:7` (`Require local`) | both are `403:275`, so the **status cannot attribute the block** — only the cause can |
| C6 | The case bypass is real, not a typo in my request | same file, two cases: `.htaccess` → `403:275`; `.HTACCESS` → `200`, 36 B, **body contains my marker** | the marker string is in the served body, so the file was really read |
| C7 | The WOPR `logon` oracle discriminates | `logon joshua` → `GREETINGS PROFESSOR FALKEN.`; 4 case variants all fire | 22 silent names incl. 2 impossible names and the empty string; 0 undiscriminated |
| C8 | The WOPR sweep is complete, not lucky | — | `/etc/passwd` → **1** account with `uid≥1000` and a login shell. 1 hit out of 23 |
| C9 | The AI response space is mapped, not guessed | 5 distinct handlers identified by response, over 62 inputs | 37 of 62 collapse to one class; 12 classes total, each attributed |
| C10 | The untrusted `ignore debug` leak is a **constant**, not an oracle | — | 3 runs → 71 B, md5 `292f6ecb7fa9`, identical. It names Joshua regardless of input |
| C11 | FTP carries no user-existence information | the check **ran**: `220` → `331 Please specify a password.` → `530 Login incorrect.` | `anon:anon` and `zzq_impossible_4711:x` → **byte-identical** `530`. Confirmed by config: `anonymous_enable=NO`, `/srv/ftp` empty |
| C12 | sshd carries no user-existence information | failures take 2.24 s / 3.22 s — a real yescrypt KDF, so the comparison is meaningful | identical exception type; 0.98 s spread is timing noise. **2 probes only** — §8 |
| C13 | The network credential oracle can report success | `joshua` / correct → **`AUTH_OK`, 0.09 s** | correct + 1 char → `AUTH_FAIL` 2.24 s; uppercased → `AUTH_FAIL` 4.43 s |
| C14 | The offline oracle can report success, on the same code path | `crypt('CANARY188', canary_hash) == canary_hash` → **True**, where the control hash was produced by the system's own `chpasswd`/PAM in the same `$y$j9T$` format | `crypt('CANARY188X', …)` → **False**; rate **96.9–98.0/s** over 100 probes, and a `>500/s` assertion that would have aborted |
| C15 | The build-record credential is the real one | `crypt('1983@1983', joshua_hash) == joshua_hash` → **True** with C14 green; **and** `AUTH_OK` over SSH | `1983@1983X` → **False**; `1983` (the obvious truncation) → **False** |
| C16 | `godmode`'s gate is real | `--wopr` → `euid=0`; the `strcmp` target is the `.rodata` constant at `0x2028` | wrong passphrase → `ACCESS DENIED`; **no argument** → `ACCESS DENIED` (the `argc<=1` branch at `main+0x1d`) |
| C17 | The privesc is real, and the oracle is not an artefact of my shell | `Uid: 0 0 0 0`, `Gid: 0 0 0 0`, `CapEff: 00000000a80425fb`, `id -u` → **0**, and a **root-owned** file created in `/root` (0700) | as `uid=1000(joshua)`, the identical read of that file is `Permission denied` (rc=2) and `cat /root/flag.txt` is `Permission denied` (rc=1) |
| C18 | My own rate limit was not manufacturing negatives | the **rate ladder**: the oracle's own KDF rate was measured before every batch (2.24–4.43 s online, 96.9–98.0/s offline) and a 4,397-candidate batch completed at 97.2/s | the 5-failure penalty was identified, diagnosed and waited out (§4.1, §11.2) rather than mistaken for a credential result |

On C18: the ladder *is* the control, and it was run before the batches, so that a uniform
failure could be attributed to the target rather than to me. In this lab that discipline was not
hypothetical — my own attack rate really did take SSH offline for ~45 s.

---

## 8. NOT tested (scope, not gaps in effort)

- **An sshd user-existence sweep.** 2 probes, not 23. `PerSourcePenalties authfail:5 min:15`
  makes a real sweep impossible from one source address without accepting a multi-hour
  wall-clock cost, and I chose to spend the budget on proving the oracle instead. C12 is a
  **2-probe negative, not a sweep**, and is labelled as such in both tables.
- **A larger credential corpus.** 4,397 generated candidates, no wordlist corpus available on
  this host. Given the password is 8 characters and non-trivial, the space is certainly not
  exhausted. I make no claim about it — and it did not matter, because F3 supplied the
  credential outright.
- **The `per_source_penalties` state as an attack surface.** I confirmed the setting, the string,
  and the trigger. I did **not** attempt to use the penalty mechanism to deny service to a third
  party, and I would not without explicit authorisation.
- **Whether `godmode` is reachable by any other account.** `root` is locked (`*`), so there is
  no second non-root account to test. I did not create one.
- **The 18 other SUID binaries as escalation paths.** Counted (19) and their modes inspected;
  all are stock Debian setuid programs with no lab-specific behaviour. I did not attempt
  `mount`, `newgrp` or `passwd` abuse — out of scope for a lab whose escalation is `godmode`.
- **IPv6 reachability of ports 21/22.** `/proc/net/tcp6` shows both bound to `::`; from the
  analysis host the container has only an IPv4 address, so I could not test them. **0 IPv6
  probes** — untested, not absent.
- **Apache modules beyond the ones `a2query -m` listed.** `mod_status` is present and correctly
  held; I did not audit the remaining enabled modules for handler mappings (lab 146's shape).
- **Any behaviour of the WOPR protocol under concurrency.** `server.listen(5)` with one thread
  per client; `play_tictactoe` blocks on `recv`. I used one connection at a time and did not
  test resource exhaustion.

---

## 9. Discarded with reason

| Hypothesis | Why discarded |
|---|---|
| **The 64-hex `SSH PASSWORD` is joshua's credential** | **Refuted twice, independently.** `AUTH_FAIL` over PAM (2.24–4.43 s, real KDF); and `crypt()` against the live shadow hash with a green control returns **no** for 9 variants. It appears in exactly **1** file in the filesystem — the source of the service that emits it. It is also not `godmode`'s passphrase (`--wopr` is). §6/F2 |
| **The 64-hex is a digest whose preimage is the password** | 4,397 candidates × SHA-256/MD5/SHA-1/SHA-512 → **0 hits each** |
| **`README.txt`'s `GODMODE` is the auth override** | **Refuted by control.** `logon GODMODE` → silent, and the subsequent `ignore debug audit` returns the **untrusted** DIAGNOSTIC response, i.e. the session never became trusted. The real trigger is `logon joshua`. §6/F6 |
| **`README.txt`'s "shared network folder" is anonymous FTP** | **Refuted by config and by count.** `anonymous_enable=NO`; `anon:anon` → `530`; `/srv/ftp` has **0 entries** |
| **The docroot exposes 5 files (naive status-code read)** | **Refuted by control.** 3 of the 5 are phantoms emitted by a name-based `FilesMatch`; toggling existence leaves the `403:275` unchanged, and 2 impossible names give a different baseline (`404:272`). Re-swept: **65 paths, 2 real, 60 absent, 3 phantom**. §2.2, §11.1 |
| **"Not allowed at this time" is a TCP-wrapper block or a firewall** | **Refuted.** `hosts.allow` and `hosts.deny` are both empty, `ldd` shows no `libwrap`, and the string is in the sshd binary. It is `PerSourcePenalties`, triggered **by me**. §4.1, §11.2 |
| **4,397 candidates with no match means the password is strong** | **Rejected as an inference.** No wordlist corpus exists on this host, so the search is generated, not exhaustive — and it was in any case the wrong question, because the credential was in the build record all along. Reported as a scoped negative with its count, not as a property of the password |
| **Root is reachable directly** | `root`'s shadow field is `*` (locked). Only two accounts have a login shell: `root` and `joshua`, and `id joshua` shows `groups=1000(joshua)` — **not** in `%sudo`, and `sudoers` has no `joshua` entry. There is no sudo rung |
| **`sudo` is the escalation** | Refuted by the artefact: `%sudo ALL=(ALL:ALL) ALL` exists but joshua is not in the group. `secure_path` ends at `/bin` (lab 32's check) and `/bin` is not world-writable — not pursued further since the vector does not exist |

---

## 10. Reward

**A reward exists and was recovered, read at `euid=0`:**

```
$ cat /root/flag.txt
WOPR{THE_GAME_IS_ENDING_YOU_WIN}          33 bytes
```

**There is no `FLAG{}` in this lab**, and the search that proves it was run as `euid=0` with
explicit counts. This is a `WOPR{}` wrapper, so the corpus convention applies: the `FLAG{}`
column of `corpus/INDEX.md` is where the absence of a literal `FLAG{}` is recorded, and this
lab is recorded as a **reward recovered, non-`FLAG{}` format** — the same treatment as labs 62
and 249.

| Search | Work count | Result |
|---|---|---|
| Filename sweep `*flag*` `*premio*` `*recomp*` `*ctf*` `*secret*` across `/` (`-xdev`), as `euid=0` | **49 hits**, all inspected | 1 real: `/root/flag.txt`. 48 false positives: `libctf0`/`libctf-nobfd0` (Compact C Type Format), `linux/kernel-page-flags.h`, 6 perl `*flags.ph`, `PA_FLAG_*` uapi headers, `secrets.py`, `secrets.cpython-313.pyc`, 7 `libctf` dpkg files |
| Content sweep `FLAG{` `flag{` `WOPR{` `ctf{` `CTF{` across `/` (`--exclude-dir=proc,sys,dev`) | **2 files matched**, both inspected | `/root/flag.txt` (the reward) **and `/tmp/inner.sh`, which was my own transport script** — it contains the literal `WOPR{` because the search pattern is in it. Disclosed as my artefact, not a second reward |
| `/root` at `euid=0` | 1 directory | `.bashrc`, `.profile`, `.ssh/` (empty), `flag.txt` — nothing else, once my marker and my backup were removed |
| `/home` | 1 directory | `joshua` only (mode `0700`, the 3 stock dotfiles) |
| `/opt` | 1 directory | **empty** |
| `/srv` | 2 entries | `ftp/` — **empty** (0 files), which is what refutes the README's "shared network folder" |
| Accounts with a login shell | 2 | `root` (password `*`), `joshua` — the sweep's completeness check (C8) |

---

## 11. Instrumentation defects

**Six. Three of them would have invented a finding, two would have deleted one, and one cost me
the only credential result in the engagement.** All six are defects in how I measured the
target, not in the target — which is why they are listed separately from Findings.

### 11.1 The docroot sweep's 3 phantom files — lab 87's lesson, and I nearly filed the opposite error
A status-code-keyed sweep of the docroot reported **5 present files: `index.html`, `README.txt`,
`.htaccess`, `.htpasswd`, `server-status`**. **Only 2 of the 5 exist.**

```
$ curl -o/dev/null -w '%{http_code}:%{size_download}\n' http://172.17.0.3/.htaccess
403:275          # file does NOT exist
$ echo marker > /var/www/html/.htaccess ; curl … /.htaccess
403:275          # identical, file now exists
$ rm -f /var/www/html/.htaccess ; curl … /.htaccess
403:275          # identical again
```

`apache2.conf:195`'s `<FilesMatch "^\.ht">` is evaluated **by name, before existence**.
`server-status` returns the same 275-byte 403 for a *completely different reason*
(`mod_status` + `Require local`), so the status cannot even attribute the block.

**What caught it** was the discipline lab 87 exists to teach, arriving in a new costume: I had
two impossible names in the wordlist, and when I went back to read the *config* rather than the
status codes, the mechanism was three lines long. Note the inversion against lab 87 — there, a
`301` catch-all made absent paths look **present**; here a `403` name-rule does the same, and a
tester carrying lab 87's rule would have expected a `301`, found a clean `404` on random names,
and concluded the docroot was safe.

*Rule: the discriminator for any bulk enumeration must be a property of the response body (a byte
count, a hash) rather than a status code — and a name-based access rule will satisfy it for names
that do not exist.*

### 11.2 My own attack rate took SSH offline, and it looked exactly like a firewall
After 4 failed password attempts plus a few banner probes, every connection returned:

```
Not allowed at this time
```

My first diagnosis was a **TCP wrapper** — because that is the string Debian's `hosts_access`
emits, and I had seen it behave that way before. **That diagnosis was wrong**, and it would have
become a filed finding ("the target blocks repeated authentication"). Three commands refuted it:
`/etc/hosts.deny` and `/etc/hosts.allow` are **empty**; `ldd /usr/sbin/sshd` shows **no
`libwrap`**; and `strings /usr/sbin/sshd` contains `Not allowed at t at this time`. The real
cause, from `sshd -T`:

```
persourcepenalties crash:90 authfail:5 noauth:1 grace-exceeded:10 refuseconnection:10 max:600 min:15
```

OpenSSH ≥ 9.8 penalises a **source address**: `authfail:5` failures, then at least 15 s of
refusal. The ~45 s outage was **my own rate**, wearing the costume of a target-side control.

*Rule: an access-denied string from a service you are brute-forcing is the first thing to
suspect as your own rate. Read the daemon's effective config (`sshd -T`, not the file) and the
binary's string table before filing it as a control that held.*

### 11.3 I reproduced lab 36's defect almost exactly — an oracle that never ran the KDF
My first offline cracker used `ctypes` to call `crypt_gensalt_rn` to mint a same-format control
hash. It returned `rc=0` with an **empty salt**, so `crypt()` fell back to glibc DES:

```
gensalt rc=0 salt=b''
same-format hash: b'*0' len 2
POSITIVE CONTROL  crypt('CANARY188',h)==h  -> False
NEGATIVE CONTROL  crypt('CANARY188X',h)==h  -> False
RATE: 50 candidates in 0.00s = 3276800.0/s
```

**3,276,800 candidates/s and a 2-character result.** Both controls report `False`, so the
instrument looks perfectly symmetric — and would have certified a negative of anything. This is
lab 36's shape: *the yescrypt scanner got `*0` without ever executing the KDF; the tell was the
rate.* My cause was a 6-argument `ctypes` prototype for a **5-argument** C function (and a later
attempt **segfaulted**, exit 139, rather than lying — also worth knowing).

The fix was not to debug `gensalt` but to stop synthesising the control: mint it with the
system's own `chpasswd`/PAM, read it back from `/etc/shadow`, and delete the account. Same
format, same library, same code path as the target — §22 satisfied by construction.

*Rule: a positive control that reports `False` is a broken instrument, and a control pair where
both branches return the same value is not a control pair. Assert on the rate, and assert on the
shape of the value the primitive returns.*

### 11.4 A shape assertion caught me deleting the account I was trying to crack
I installed a canary password on **joshua** to prove the network oracle could fire, saved the
original hash, and restored it with `sed`. The `diff` said `IDENTICAL` and the value printed
correctly — so I moved on. Later, `grep -c "^joshua:" /etc/shadow` returned **0**.

Root cause: when I created the throwaway account with `useradd` + `chpasswd`, **joshua's line
was replaced rather than added** — `/etc/shadow` stayed at 25 lines, and the byte delta was
exactly `+3`, the difference between the 9-character username `canary188` and the 6-character
`joshua`. Had the cracker been pointed at `/etc/shadow` at that moment it would have reported
"no match" against the **canary's** hash, with a green-looking control and a plausible rate.

What caught it was a **shape assertion** I had added for an unrelated reason
(`$y$` prefix, exactly 73 chars): the file was **empty**, the assertion aborted, and the
harness refused to run. Restored from a byte-exact `cp -a` backup — 25 lines, joshua's hash
byte-identical, canary removed from `passwd` and `shadow`.

*Rule: never restore a credential file you have mutated in place without a byte-exact copy, and
keep the shape assertion even when you do not yet know what it will catch. `cp -a` is the
restore; `sed -i` on `/etc/shadow` is not.*

### 11.5 I labelled two probes "negative controls" when both were positives
In the WOPR sweep I wrote that `ignore debugX` and `DEBUG IGNORE` were negative controls for the
untrusted leak. **Both actually fire** — `script.py` tests `all(x in text …)` on
`user_input.lower()`, so a substring is enough and case does not matter. The conclusion
("this response is a constant") survived, but it was resting on a mislabelling rather than on
the md5, which is the actual evidence: 3 runs, 71 bytes, `292f6ecb7fa9` every time.

*Rule: name a control by what it did, not by what you expected it to do — and when a result
survives a mislabelled control, re-derive it from the measurement before writing it down.*

### 11.6 `rtk` does not exist inside the container, and one `ls | grep` silently found nothing
Two small ones. A `ls -la /var/www/html/ | grep -i ht` I ran **inside** the container returned
nothing because my own wrapper binary is not on the container's `PATH`
(`sh: 1: rtk: not found`) — and in a pipeline that failure is invisible unless you read stderr.
Separately, the `printf`/`heredoc` transport for my first reward script mangled a multi-line
payload (`/bin/bash: line 1: fg: no job control`, and **no output at all**), which looked like
the escalated shell had produced nothing. Base64 transport fixed it.

*Rule: verify that the tool you are piping into exists in the environment you are piping into,
and when a multi-line payload crosses a process boundary, transport it base64-encoded — a
silent no-output from a shell you have just escalated is the most expensive kind of blank.*

---

## 12. Reproducibility

Harness files used during the engagement are in `/tmp/opencode/188/` on the analysis host
(`wopr.py`, `woprsweep.py`, `logonsweep.py`, `sshenum.py`, `cred.py`, `extract.py`,
`oracle2.py`, `verify188.py`, `privesc.py`, `reward2.py`, `cleanup.py`, `wl.txt`, `cands.txt`,
`sweep.txt`, and `ev/`). They are not required to reproduce any result above: every claim is
quoted with its literal response, its `file:line`, or its work count.

The recovered credential and the reward are **not** reproduced in full here beyond the reward
itself, which is the lab's own reward string and is reported because §10 requires it. The
password appears in §6/F3 quoted from `docker history` because **that is the finding**: quoting
it is the only way to show that the build record discloses it.

**Lab state at the end of the engagement: restored from the image and verified positively.**
Recreated, not reverted (`docker rm -f` + `docker run` from `wargames:latest`), then six
positive checks, all passing:

1. WOPR answers with its banner: `WELCOME TO WOPR` / `SHALL WE PLAY A GAME?`
2. `GET /` → `200`, **118** bytes; `GET /README.txt` → `200`, **980** bytes
3. `GET /.htaccess` → `403`; `GET /.HTACCESS` → `404` (the file is absent again, so the
   case-bypass artefact is gone)
4. joshua's shadow entry is byte-identical to the shipped hash
   (`$y$j9T$XyPUXMUViZrJ/uMOZjRy..$OjEiB7CDgGDWTdyr/KgrFm3VtDlL10wqaYbg9NEOq7D`)
5. `canary188` = 0 in `passwd` and `shadow`; `WG188-*` markers = **0** anywhere on `/xdev`;
   `/tmp` = **0** entries; docroot = **2** files and **0** subdirectories; `/etc/shadow` = 25 lines
6. `/root/flag.txt` intact, 33 bytes, `WOPR{THE_GAME_IS_ENDING_YOU_WIN}`

Before recreating, an in-place audit confirmed the same counts from inside the running
container, and the `godmode` mode/owner is back to `4755 root:root`.

**Reclaim.** The extracted tar `labs/188/wargames.tar` (573 MB) was deleted after the writeup
landed, per the PIPELINE reclaim policy. The **image was deliberately left in place**: the
restored container still references it, and `docker rmi wargames:latest` refuses with
`must be forced (container … is using its referenced image)`. Forcing it, or removing the
container to free it, would trade the verified restore for ~1 GB — and the restore is the
deliverable. No global prune was run at any point; the seven `cybervault-*` containers from the
other project were left untouched (verified: 7 still running).

---

## 13. What this lab adds to the methodology

Three items are new *classes of surface* rather than new instances of existing ones, so per the
RUNBOOK they are proposed to the parent rather than written into shared files here.

1. **An absent-path trap that answers `403` instead of `301`.** Lab 87 established the rule
   ("a name that cannot exist is a mandatory member of the wordlist; the discriminator must be a
   response property, not a status code"). Lab 188 is a **second instance with a different
   mechanism** — a name-based `FilesMatch` evaluated before existence — and it is *stronger*
   evidence for the rule than lab 87's, because here the phantoms are the highest-value names
   in any wordlist (`.htaccess`, `.htpasswd`) and two unrelated causes produce the same 275-byte
   body. **Extend the existing row; do not add a new one.**
2. **The image build record as a static-analysis surface that carries plaintext secrets.**
   `docker history --no-trunc` is a text surface, it is in the artefact, and it held the only
   usable credential in the lab while no runtime file held it. This is the "análisis estático"
   the catalogue description names, and it is a class the corpus does not have. **New section.**
3. **A credential-attack rate budget imposed by the target, and the resulting self-inflicted
   false negative.** `PerSourcePenalties authfail:5 min:15` is a *measured* budget rather than an
   estimate, and the resulting outage is byte-for-byte indistinguishable from a firewall block.
   This extends lab 283's "your own rate limit, wearing a false negative" to a **daemon-enforced
   budget read from `sshd -T`**. **Extend the existing row; do not add a new one.**

The lab's own class label is accurate, and the enumeration inventory (§2) is the deliverable:
**159 application-level probes, one account, every row with a control pair and a work count, and
three of the eleven surfaces produced no finding — which is recorded rather than left blank.**
