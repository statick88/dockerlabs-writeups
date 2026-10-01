# 169 SpiderRoot — DockerLabs Writeup

**Class:** unauthenticated WAF bypass yielding credential disclosure, over an LFI-anchored PHP surface, to a loopback-only command-execution panel reached by SSH local forwarding, ending in a group-writable-directory sudo privesc to `uid=0(root)`.

**Target:** `http://172.17.0.8:80` + `172.17.0.8:22` (container `spiderport_container`, image `spiderport:latest`)
**Date:** 2026-10-01
**Outcome:** Full chain solved. Reward recovered as `uid=0(root)`. **The one write into the target was backed up, executed, restored, and verified byte-identical.**
**Headline:** the "WAF" is not a wall. It is a *detector whose firing path is the disclosure* — the code that catches obfuscated `OR`/`AND` is the same code that prints the password table.

---

## 0. Lab identity

The platform catalogue entry for 169, quoted verbatim from `~/dockerlabs/catalog.txt:39`:

```
169|SpiderRoot|medio|WAF Bypass, port forwarding y escalada de privilegios en linux.
```

Difficulty `medio`. All three advertised elements are real and each maps to exactly one mechanism, which §Chain separates.

### Stack, from version-bearing artefacts

| Layer | Value | Source |
|---|---|---|
| Base OS | Ubuntu 24.04 (noble) | `/etc/os-release` |
| Web server | Apache 2.4.58, `ServerTokens OS` | `/etc/apache2/conf-available/security.conf:11` |
| PHP | 8.3 (`mod_php`, `mpm_prefork`) | `/etc/apache2/mods-enabled/php8.3.load` |
| Display errors | `display_errors = Off`, `log_errors = On`, `error_log` unset | `php -i` |
| Restrictions | `disable_functions` **empty**, `open_basedir` **no value** | `php -i` |
| Users of interest | `www-data` uid 33 (groups 33, **1002 spiderlab**); `peter` uid 1001 (groups 1001, **100 users**) | `id` via RCE / `/etc/passwd` |
| Root login | `permitrootlogin without-password`, `passwordauthentication yes` | `sshd -T` |

Two php.ini facts do the load-bearing work later: `disable_functions` is empty, so `system()` at `internal/index.php:86` genuinely executes; and `open_basedir` is unset, so the traversal at `html/index.php:94` is not jailed.

---

## 1. Surface

Re-measured, not assumed:

```
$ nmap-style + /proc/net/tcp inside the container
  00000000:0016  → 0.0.0.0:22      LISTEN  (3 rows total in /proc/net/tcp)
  00000000:0050  → 0.0.0.0:80      LISTEN
  0100007F:1F90  → 127.0.0.1:8080  LISTEN   ← 0x1F90 = 8080
```

`/proc/net/tcp` contains exactly **3** listener rows, matching the baseline given. The third is the whole lab: `0100007F` is `127.0.0.1`, so the service is bound to loopback and cannot be reached from outside.

**That negative is earned, not assumed.** `curl http://172.17.0.8:8080/` returned `http=000`, curl exit **7** (connection refused) — refused, not filtered, which is what a loopback bind produces. A positive control for the client path: the *same* curl invocation reached `:80` and `:22` moments earlier. So the client worked; the bind refused it.

**The vhost behind 8080 is a second Apache site**, not a proxy. `/etc/apache2/sites-enabled/internal.conf:1`:

```apache
<VirtualHost 127.0.0.1:8080>
    ServerName localhost
    DocumentRoot /var/www/internal
```

No `ProxyPass` anywhere in `/etc/apache2/` (searched, 0 hits). So the lab's "port forwarding" element is *absent from the server config entirely* — it is something **I** must build, over SSH, to reach a service that already exists. The name `SpiderRoot` is literally "spider" + "port".

---

## 2. The class

> A regex-based input filter whose **detection branch** performs a privileged disclosure. The attacker does not defeat the filter; the filter *executes on their behalf*.

The filter, `/var/www/html/pages/multiverse.php:13-26`, blacklists five strings and then `die()`s:

```php
15:    $blacklist = ["'", '"', "UNION", "--", "#"];
18:        if (stripos($input, $bad) !== false) {
20:            file_put_contents(__DIR__.'/../logs/login_attempts.log', …);
21:            die("<p style='color:red;'>¡Entrada bloqueada por el WAF!</p>");
```

The disclosure is the *second* detector, `multiverse.php:46-52`:

```php
46:    $pattern = '/[Oo][Rr]|[Aa][Nn][Dd]/';
47:    if (preg_match($pattern, $username) || preg_match($pattern, $password)) {
48:        echo "<p style='color:#0f0;'>¡WAF evadido con código ofuscado! Contraseñas del sistema:</p><ul>";
49:        foreach ($users as $u) {
50:            echo "<li>User: ".$u['user']." | Pass: ".$u['pass']."</li>";
```

Sending the literal string `or` clears the five-item blacklist (no quote, no `UNION`, no `--`, no `#`) and trips the obfuscation regex, which prints the whole credential table. **The filter is the exploit.** The two hidden HTML comments at `multiverse.php:4` and `multiverse.php:97` both nudge toward this ("Algunas vulnerabilidades pueden estar camufladas en caracteres codificados").

---

## 3. Attack chain

```
Internet ──:80──► Apache 000-default.conf  DocumentRoot /var/www/html
                    │
        GET /index.php?page=multiverse      html/index.php:92-94
                    │
        POST username=x or 1               bypasses blacklist (5 items),
                    │                       trips regex multiverse.php:46
                    ▼
        CREDENTIALS (3 users)               multiverse.php:48-51
                    │
        ssh peter:sp1der                    sshd, PasswordAuthentication yes
                    │
                    ├── ssh -L 18080:127.0.0.1:8080     ← I build the forward
                    │
        GET /?cmd=… through the tunnel      internal/index.php:82-87
                    │
                    ▼
        RCE as uid=33(www-data) groups=...,1002(spiderlab)
                    │
        /opt is 775 root:spiderlab  ──►  rm + recreate /opt/spidy.py
                    │                   (unlink needs the DIRECTORY, not the file)
        sudo -n /usr/bin/python3 /opt/spidy.py
                    │
                    ▼
        uid=0(root) ──► /root/flag.txt
```

### Hop 1 — WAF bypass and credential disclosure

**Controls first, in all three directions**, before believing the result:

| Control | Input | Expected | Observed | Verdict |
|---|---|---|---|---|
| **Negative** | `username=noexist&password=nope` | wrong creds | `Credenciales incorrectas` | green |
| **Positive** (auth) | `username=peter&password=sp1der` | accepted | `Acceso concedido` | green |
| **Positive** (filter fires) | `username=a'` | blocked | `¡Entrada bloqueada por el WAF!` | green |
| **Bypass** | `username=x+or+1` | disclosure | `¡WAF evadido con código ofuscado!` + table | green |

The third row matters most: it proves the WAF **can** block, so row 4 is a bypass and not a broken detector. Had I only sent row 1 and row 4, "no block message" would have been indistinguishable from "the filter is dead", and the disclosure would have looked accidental.

Evidence: `evidence/waf_bypass.html`, `evidence/creds_recovered.txt`.

Credentials recovered (`multiverse.php:29-33`), which is the deliverable:

```
User: peter | Pass: sp1der
User: miles | Pass: m0ral3s
User: gwen  | Pass: gw3n2025
```

### Hop 2 — SSH as `peter`

`peter` is a real local account with a real shell (`/etc/passwd`, uid 1001) and the recovered password is his. A witness created in this run, by the identity under test:

```
$ id
uid=1001(peter) gid=1001(peter) groups=1001(peter),100(users)
6e865442bcaf
peter
```

`peter`'s group is `100(users)`, **not** `admin` or `sudo`, so he has no escalation here. Proven, not inferred: `sudo -S -l` as `peter` returns `Sorry, user peter may not run sudo on 6e865442bcaf.` Evidence: `evidence/ssh_peter_id.txt`, `evidence/peter_sudo.txt`.

### Hop 3 — building the port forward, then gating it

The 8080 service is bound to the *container's* loopback, so an SSH local forward from my host reaches it. The tunnel is part of the surface, so it gets its own controls (`evidence/tunnel_probe.py`):

| # | Label | Request | Status | Bytes | Marker |
|---|---|---|---|---|---|
| 1 | CONTROL-1 positive | `GET /` | 200 | 2364 | `internal_panel_marker=True` |
| 2 | CONTROL-2 positive | `GET /?cmd=id` | 200 | 2440 | `executes=True` (`uid=` in body) |
| 3 | CONTROL-3 negative | `GET /?nosuchparam=zzz` | 200 | 2364 | `did_not_execute=True` |

```
# ORACLE GREEN IN BOTH DIRECTIONS: True
# WORK COUNT: requests through this tunnel = 3
```

CONTROL-2 is the load-bearing one: it forces a **known-positive command execution** through the tunnel. CONTROL-3 proves the panel is not echoing a constant. Only after this do I believe anything about 8080 — including that `cmd` is the oracle and not coincidence.

RCE identity, through the tunnel:

```
uid=33(www-data) gid=33(www-data) groups=33(www-data),1002(spiderlab)
```

**`1002(spiderlab)` is the finding.** The web user shares a group with the owner of `/opt`.

### Hop 4 — the privesc: directory write beats file ownership

The sudo grant, enumerated empirically via `sudo -n -l` **as www-data** rather than read out of the file and assumed (`evidence/rce_sudo_l.txt`):

```
User www-data may run the following commands on 6e865442bcaf:
    (ALL) NOPASSWD: /usr/bin/python3 /opt/spidy.py
```

`(ALL)` means any runas user, so root is directly reachable. The interesting part is the *target of* that grant:

```
$ stat -c "%n %a %U:%G" /opt /opt/spidy.py
/opt          775 root:spiderlab
/opt/spidy.py 744 root:root
```

`/opt/spidy.py` is `root:root` mode 744 — www-data can neither read-write nor even read it as owner, and it is **not** group `spiderlab`, so the sudo rule cannot be turned into code execution by editing the file in place. But `/opt` is `775 root:spiderlab`, and www-data is in `spiderlab`. **Directory write permission grants unlink, and unlink plus create is a replacement.** Measured:

```
not writable: /opt/spidy.py        ← in-place overwrite refused
WRITABLE: /opt/spidy.py.tmp        ← create new works
WRITABLE: /opt/.wtest              ← create new works
```

So the sequence is `rm` then create — which is exactly where my first attempt died; see **Instrument defect I2**.

```
$ sudo -n /usr/bin/python3 /opt/spidy.py
PRIVESC-WITNESS uid=0 euid=0 user=uid=0(root) gid=0(root) groups=0(root)
FLAG-BEGIN
…
Grooti16
FLAG-END
```

### Backup, restore, verification

This is the only write into the target, so it carries the full obligation.

| Step | Action | Verification |
|---|---|---|
| Backup | `cat /opt/spidy.py` over RCE | `diff` vs a second independent copy → **identical**, 808 bytes |
| Execute | replace + `sudo python3` | `uid=0(root)` witnessed in stdout |
| Restore content | base64 the original back | `diff` vs backup → **identical**, 808 bytes |
| Restore ownership | `chown root:root` (host, as root) | `stat` → `root:root` |
| Restore mode | `chmod 744` | `stat` → `744` |
| Clean probes | `rm -f /opt/.t1 /opt/.wtest /opt/spidy.py.tmp /tmp/spidy.py.orig.bak` | `ls -la /opt/` → only `spidy.py` |
| Sanity | `sudo python3 /opt/spidy.py` | runs the **original** benign script; its final line is `Spider-Man ha terminado su ronda.` |

Note in **I4**: the ownership restore failed silently the first time, because www-data cannot `chown` to root. Content was correct while ownership was still `www-data:www-data` — a half-restored target that a content-only check would have passed.

---

## 4. Findings

Each finding separates **reachability** (can an unauthenticated attacker get there?), **disclosed** (what is actually exposed?), and **decisive** (does it carry the chain?).

### Finding 1 — Filter's detection branch discloses the full credential table

- **Reachability:** unauthenticated. `GET /index.php?page=multiverse` then one `POST`. No session, no header, no timing.
- **Disclosed:** all three plaintext username/password pairs, verbatim, in the response body.
- **Decisive:** yes — it is the entire credential source for hops 2 and 3.
- **Mechanism (derived, not asserted):** `multiverse.php:47` matches `/[Oo][Rr]|[Aa][Nn][Dd]/` and `multiverse.php:48-51` dumps `$users`. The five-item blacklist at `multiverse.php:15` does not intersect that regex, so the two checks are independent and the disclosure branch is reachable with a single unblocked token. Severity: critical — it converts an unauthenticated web request into host SSH access.

### Finding 2 — LFI at `html/index.php:94`, traversal confirmed real but suffix-confined

`include("pages/" . $_GET['page'] . ".php");` — the developer's own comment at `:94` reads `// 🚨 Vulnerabilidad LFI`.

- **Reachability:** unauthenticated.
- **Disclosed:** execution of any `*.php` file reachable by traversal from `/var/www/html/pages/`.
- **Decisive:** no. It is a real primitive that this chain does not need — the port-forward hop is strictly stronger.
- **Mechanism, with the traversal proven rather than assumed.** Controls: `page=heroes` renders `Héroes` (oracle fires), `page=zzz_nonexistent` returns 2561 bytes. Then:

| Probe | `page` value | Bytes | Result |
|---|---|---|---|
| L2 | `..%2f..%2f..%2f..%2fetc%2fpasswd` | 2561 | identical to the nonexistent control |
| L3 | `../../../etc/passwd` (`--path-as-is`) | 2561 | identical to the nonexistent control |
| L4 | `php://filter/convert.base64-encode/resource=../../../etc/passwd` | 2561 | identical to the nonexistent control |
| L5 | `../../internal/index` | **4927** | `Multiverse Panel Interno` + `Ejecutar` |

L5 is the discriminator: 4927 bytes and the internal panel's own strings, which occur **only** in `/var/www/internal/index.php` — a file outside the docroot. Traversal demonstrably works.

The reason L2–L4 fail is the concatenation at `:94`, which force-appends `.php`: `/etc/passwd.php` and `resource=…/passwd.php` do not exist. The reachable universe is closed and small — a bounded sweep found **exactly 5** `.php` files on the whole filesystem:

```
/var/www/html/index.php
/var/www/html/pages/contact.php
/var/www/html/pages/heroes.php
/var/www/html/pages/multiverse.php
/var/www/internal/index.php
```

That count is the honest ceiling of this primitive. It is an information-disclosure and reachability bug, not an RCE on its own.

### Finding 3 — Both log-poisoning sinks are dead: the docroot is not writable by www-data

`multiverse.php:8-10` tries to `mkdir` its own log directory; `:20` and `:43` then write to it. **Neither can ever succeed.** `/var/www/html` is `root:root 755`:

```
$ docker exec -u www-data … mkdir /var/www/html/logs
mkdir: cannot create directory '/var/www/html/logs': Permission denied   (exit 1)
$ docker exec -u www-data … touch /var/www/html/x
touch: cannot touch '/var/www/html/x': Permission denied               (exit 1)
```

Because `display_errors = Off`, the HTTP response contains **no** trace of this — zero warning strings in a 3762-byte body. The failure is visible only in Apache's error log, and the lines from **my own requests this run** are the witness:

```
[Thu Oct 01 17:58:41.559863 2026] [php:warn] [pid 40] PHP Warning:  file_put_contents(/var/www/html/pages/../logs/login_attempts.log): Failed to open stream: No such file or directory in /var/www/html/pages/multiverse.php on line 43
```

- **Reachability:** the *sink* is reachable; the *write* is not.
- **Disclosed:** nothing. This is a negative finding and it is gated — see §5 and **I3**.
- **Decisive:** it removes the conventional completion of Finding 2. **This is the finding that stops the classic LFI→log-poisoning→RCE chain on port 80**, and it is why the lab's real path goes through SSH instead. A tester who read only the response body would have concluded the log existed and spent the engagement on a chain that cannot work.

### Finding 4 — Command execution as `www-data` on the loopback vhost

`internal/index.php:82-87` passes `$_GET['cmd']` straight to `system()`.

- **Reachability:** **not reachable from the network.** Bound to `127.0.0.1:8080`; refused externally with curl exit 7. Reachable only after valid SSH credentials plus an SSH local forward. It inherits Finding 1's severity as `www-data`, which is why the lab is still `medio`.
- **Disclosed:** arbitrary command output in the response body.
- **Decisive:** yes — it is hop 3 and the whole source of the `1002(spiderlab)` group membership.
- **Mechanism:** `system($cmd)` at `:86`, with `disable_functions` empty in php.ini so nothing intercepts it, and `<pre>` at `:85`/`:87` delimiting the output. Response is unfiltered: the `cmd` value is echoed into the page at `:84` with no escaping, a reflected-XSS sink that is moot given the RCE in the same page.

### Finding 5 — `www-data` is in group `spiderlab`, which owns the sudo target's directory

The privesc. `/etc/sudoers` last line:

```
www-data ALL=(ALL) NOPASSWD: /usr/bin/python3 /opt/spidy.py
```

with `/opt` at `775 root:spiderlab` and `www-data` in `spiderlab`.

- **Reachability:** unauthenticated at the end of the chain; no credential beyond Finding 1 is needed.
- **Disclosed:** the sudoers grant itself, via `sudo -n -l` with no password.
- **Decisive:** yes — root.
- **Mechanism, derived:** the sudoers entry pins the *command*, and the pinned script is `root:root 744`, so in-place editing is closed. The bypass is that the grant names a **path**, and the **directory** holding that path is group-writable by the same identity. `unlink` requires write+execute on the directory, not on the file; after unlinking, `create` needs only directory write. The new inode inherits `www-data:www-data`, and sudo executes it as root. The relevant lesson is that a sudoers entry specifying a script path is only as trustworthy as the *directory* permissions around it — an allowlist of paths is not an allowlist of inodes.
- **Note on `PASSWD` scope:** the rule is `NOPASSWD` for exactly `/usr/bin/python3 /opt/spidy.py`, and the successful run used `-n`. No argument-injection was needed or attempted; the fix is the directory mode (`755` on `/opt`), not the sudoers syntax.

### Finding 6 — informational: `peter` cannot escalate, and `www-data` has a shell

`/etc/passwd` gives `www-data` `/bin/bash` and `peter` `/bin/bash`. `peter` is not in `admin`/`sudo` and `sudo -S -l` confirms `Sorry, user peter may not run sudo`. The HTTP-to-SSH credential pivot therefore lands on a deliberately unprivileged account, which is what forces the port-forward hop rather than a direct `sudo` hop. Nothing exploitable; recorded because "which account do the creds belong to" is a real branch in this chain.

---

## 5. Instrument failures

The mandatory section. Every entry is a place where **my own instrument** lied, counted wrong, or returned a clean negative it had not earned — plus one place where the *target's* instrumentation lied to me.

### I1 — I misread `ls -la` column order and nearly filed "privesc is not possible"

**Defect.** Reading `-rwxr--r-- 1 root spiderlab 808 … spidy.py` I took the owner to be `spiderlab`, and I read the directory line `drwxr-xr-x 2 root spiderlab` as "not group-writable" because `2` is the link count, not a permission digit.

**What it would have caused me to file.** A confident finding of the form *"the escalation is unavailable — www-data is not in the owning group of `/opt/spidy.py` and the directory is `755`."* That is a **false negative on the lab's entire third advertised element**, and it would have read as a measured result because I would have cited real `ls` output. The correct state is `stat -c "%n %a %U:%G"`: `/opt` is `775 root:spiderlab`, and `www-data` **is** in `spiderlab`.

**Class.** Human interpretation of a positional, human-readable format instead of querying the machine-readable field. `ls -la` has no labels; `stat` does.

**Fix applied.** All ownership and mode claims in this report come from `stat -c`, cross-checked with a `touch` write probe. The write probe is what actually settles writability — permission bits are a claim, the write is a measurement.

### I2 — A failing redirect inside an `&&` chain produced an empty body, and I nearly read it as "privesc blocked"

**Defect.** My first privesc attempt was:

```
cp /opt/spidy.py /tmp/… && echo '<b64>' | base64 -d > /opt/spidy.py && echo INSTALLED && sudo …
```

It returned `http=200` with an **empty** `<pre>` block. Nothing in the response said "failed". The cause: `> /opt/spidy.py` opens the **existing** `root:root` file for truncation, which www-data cannot do, so the redirect failed, `&&` short-circuited, and neither `INSTALLED` nor the sudo run happened. The `cp` had succeeded — which is why `/tmp/spidy.py.orig.bak` existed while `/opt/spidy.py` was untouched.

**What it would have caused me to file.** "The sudo grant does not yield root; the script is not replaceable." Twice over, because an empty body is ambiguous between *denied* and *never ran*. The distinguishing test was one command away: `ls -la /opt/spidy.py` showed the file still `root:root`, dated `Sep 4 2025`, i.e. untouched — proving the chain never reached the write, rather than proving the write was refused.

**Class.** Shell error-propagation blindness: `>` failure is reported on stderr with a nonzero status, but nothing in the HTTP response distinguishes it. Compound `&&` chains convert a specific failure into an absence.

**Fix applied.** Every subsequent RCE command reports explicit `echo …rc=$?` markers after each step, so a refusal and a non-execution are different observations.

### I3 — `display_errors = Off` made the target's own broken log sink look healthy

**Defect.** Not my instrument but one I was relying on: the HTTP response for `?page=multiverse` is a clean 3762 bytes containing **zero** occurrences of `warning`, `error`, `failed`, or `permission denied`. `multiverse.php:8-10`'s `mkdir` fails, and `:20`/`:43`'s `file_put_contents` fails, and the page renders as though it worked.

**What it would have caused me to do.** Read the source, see two `file_put_contents` sinks feeding the LFI at `:94`, conclude the log exists, inject PHP through the username field, and include it — the textbook LFI→RCE ending. That chain is **impossible here**, for two independent reasons, neither visible in the body: www-data cannot write the docroot (Finding 3), and even a perfect log would need to be named `*.php` to survive the concatenation at `:94`.

**Class.** Silent failure / fail-open presentation in a target-instrument. This is the mirror image of the repo's thesis: here the instrument is not silent because nothing was looked for, but silent because the error channel was disabled.

**Fix applied.** PHP's stderr route was used instead — `/var/log/apache2/error.log`, which carries **286** `mkdir` warning lines, including four timestamped `Thu Oct 01 17:58:41` that correspond to my own four requests. That is a witness created in this run, by the identity under test.

### I4 — My restore left the target half-restored, and my check would not have caught it

**Defect.** After restoring the file I ran `chown root:root` **as www-data**, which cannot succeed. The content was correct (808 bytes, byte-identical) and the mode was correct (`744`), but ownership read `www-data:www-data`. My verification at that moment was a content `diff`, which passed.

**What it would have caused me to leave behind.** A target owned by `www-data` on a file that sudo executes as root — a **persistent privesc backdoor** shipped in my own writeup's evidence directory. Content equality is not restoration; ownership is part of the state.

**Class.** Verification that covers the property I checked instead of the property I changed. Also a failed-privilege operation treated as successful because its output was empty.

**Fix applied.** Re-ran `chown` from the host as root and re-verified with `stat -c "%n %s %a %U:%G"` → `808 744 root:root`, plus a content `diff`, plus a benign `sudo` run of the restored original. All three must agree.

### I5 — My tunnel work count was computed from archived files, so it undercounted by 4

**Defect.** Counting requests through the tunnel by grepping the saved evidence files returned **8**. The true figure is **12**. Four invocations (write probe, state check, post-restore sanity, and one overwritten) printed to stdout only and were never redirected to a file.

**What it would have caused me to report.** A work count of 8 for an interaction that actually issued 12 requests against the service I was characterising — an undercount in a section whose entire purpose is to let a reader trust the numbers.

**Class.** A work count derived from retained evidence measures **what I happened to save**, not **what I did**. The two diverge silently, and they diverge *downward*, which is the direction that makes a thin engagement look rigorous.

**Fix applied.** `evidence/tunnel_request_accounting.txt` records the full reconstructed 12-call log with an explicit archived/not-archived column and states plainly that the 12 is reconstructed from the transcript rather than from the artefacts.

### I6 — My first `sudo -n -l` control returned a message that reads like success

**Defect.** `sudo -n -l` as `peter` returned `sudo: a password is required` with exit 1. Read alone, that is easy to misread as "peter has sudo and it wants a password" — the opposite of the truth.

**What it would have caused me to file.** Either a wasted credential attack on peter's sudo, or an invented finding that peter has partial sudo.

**Class.** Instrument returning an exit code and a generic message where the discriminating information lives elsewhere.

**Fix applied.** Re-ran with the password (`echo sp1der | sudo -S -l`), which returned the discriminating line: `Sorry, user peter may not run sudo on 6e865442bcaf.` That is what the writeup cites.

### I7 — My "known positive" control pointed at the wrong file

**Defect.** To prove the passwd-leak detector could fire, I ran `grep -c 'root:x:0:0'` against `backup_opt_spidy_verify.txt` — which is `spidy.py`, and contains no such string. It returned **0**. If I had stopped there, the correct conclusion would have rested on a detector with no working demonstration.

**What it would have caused me to file.** Nothing directly, but it nearly left the "LFI does not leak `/etc/passwd`" negative resting on an unproven detector — precisely the failure mode the whole corpus is about.

**Class.** Control miswiring. A positive control is only evidence if it is fed a genuinely positive sample.

**Fix applied.** Re-ran against an actual copy of `/etc/passwd` → **1 match**. Only then were L2–L6 read as 0. The negative is now earned: same detector, same command, 1 on the positive and 0 on each negative.

### I8 — Cosmetic: a tooling wrapper name leaked into the target

**Defect.** Several early reads failed with `exec: "rtk": executable file not found in $PATH` because I passed my host-side command wrapper into `docker exec`, where it does not exist. No target-side effect; the reads were simply retried with plain commands.

**Class.** Host/tool boundary confusion — the wrapper is a host convenience, not a binary in the image.

---

## 6. Reward

There is **no `FLAG{…}` token** in this lab. The reward is the file `/root/flag.txt`, readable only as `uid=0(root)`. Its complete content, reproduced verbatim from `evidence/flag_exact.txt` (33 lines, extracted from `evidence/privesc_run.txt` between the `FLAG-BEGIN` and `FLAG-END` markers):

```
FLAG-BEGIN
⠀⠀⠀⠀⠀⠀⠀⢀⠆⠀⢀⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⡀⠀⠰⡀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢠⡏⠀⢀⣾⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢷⡀⠀⢹⣄⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⣰⡟⠀⠀⣼⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣧⠀⠀⢻⣆⠀⠀⠀⠀⠀
⠀⠀⠀⠀⢠⣿⠁⠀⣸⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣇⠀⠈⣿⡆⠀⠀⠀⠀
⠀⠀⠀⠀⣾⡇⠀⢀⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⡀⠀⢸⣿⠀⠀⠀⠀
⠀⠀⠀⢸⣿⠀⠀⣸⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣇⠀⠀⣿⡇⠀⠀⠀
⠀⠀⠀⣿⣿⠀⠀⣿⣿⣧⣤⣤⣤⣤⣤⣤⡀⠀⣀⠀⠀⣀⠀⢀⣤⣤⣤⣤⣤⣤⣼⣿⣿⠀⠀⣿⣿⠀⠀⠀
⠀⠀⢸⣿⡏⠀⠀⠀⠙⢉⣉⣩⣴⣶⣤⣙⣿⣶⣯⣦⣴⣼⣷⣿⣋⣤⣶⣦⣍⣉⡉⠋⠀⠀⠀⢸⣿⡇⠀⠀
⠀⠀⢿⣿⣷⣤⣶⣶⠿⠿⠛⠋⣉⡉⠙⢛⣿⣿⣿⣿⣿⣿⣿⣿⡛⠛⢉⣉⠙⠛⠿⠿⣶⣶⣤⣾⣿⡿⠀⠀
⠀⠀⠀⠙⠻⠋⠉⠀⠀⠀⣠⣾⡿⠟⠛⣻⣿⣿⣿⣿⣿⣿⣿⣿⣟⠛⠻⢿⣷⣄⠀⠀⠀⠉⠙⠟⠋⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢀⣤⣾⠿⠋⢀⣠⣾⠟⢫⣿⣿⣿⣿⣿⣿⡍⠻⣷⣄⡀⠙⠿⣷⣤⡀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⣠⣴⡿⠛⠁⠀⢸⣿⣿⠋⠀⢸⣿⣿⣿⣿⣿⣿⡗⠀⠙⣿⣿⡇⠀⠈⠛⢿⣦⣄⠀⠀⠀⠀⠀
⢀⠀⣀⣴⣾⠟⠋⠀⠀⠀⠀⢸⣿⣿⠀⠀⢸⣿⣿⣿⣿⣿⣿⡇⠀⠀⣿⣿⡇⠀⠀⠀⠀⠙⠻⣷⣦⣀⠀⣀
⢸⣿⣿⠋⠁⠀⠀⠀⠀⠀⠀⢸⣿⣿⠀⠀⠈⣿⣿⣿⣿⣿⣿⠁⠀⠀⣿⣿⡇⠀⠀⠀⠀⠀⠀⠈⠙⣿⣿⡟
⢸⣿⡏⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⠀⠀⠀⢹⣿⣿⣿⣿⡏⠀⠀⠀⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⢹⣿⡇
⢸⣿⣷⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⠀⠀⠀⠀⢿⣿⣿⡿⠀⠀⠀⠀⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⣾⣿⡇
⠀⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⠀⠀⠀⠀⠈⠿⠿⠁⠀⠀⠀⠀⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⠀
⠀⢻⣿⡄⠀⠀⠀⠀⠀⠀⠀⠸⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⠇⠀⠀⠀⠀⠀⠀⠀⢀⣿⡟⠀
⠀⠘⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⠃⠀
⠀⠀⠸⣷⠀⠀⠀⠀⠀⠀⠀⠀⢹⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⡟⠀⠀⠀⠀⠀⠀⠀⠀⣾⠏⠀⠀
⠀⠀⠀⢻⡆⠀⠀⠀⠀⠀⠀⠀⠸⣿⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣿⠇⠀⠀⠀⠀⠀⠀⠀⢰⡟⠀⠀⠀
⠀⠀⠀⠀⢷⠀⠀⠀⠀⠀⠀⠀⠀⢿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡿⠀⠀⠀⠀⠀⠀⠀⠀⡾⠀⠀⠀⠀
⠀⠀⠀⠀⠈⢧⠀⠀⠀⠀⠀⠀⠀⠸⣷⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⠇⠀⠀⠀⠀⠀⠀⠀⡸⠁⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢹⡆⠀⠀⠀⠀⠀⠀⠀⠀⢰⡟⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢳⠀⠀⠀⠀⠀⠀⠀⠀⡞⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠣⠀⠀⠀⠀⠀⠀⠜⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀



Grooti16

FLAG-END
```

It is a braille-art rendering of the Spider-Man insignia with the signature `Grooti16` beneath it.

Provenance chain for that read: `uid=0(root)` was printed by the replacement script's own `id` call under `sudo -n /usr/bin/python3 /opt/spidy.py`, in the same process that opened `/root/flag.txt`. Not inferred from a directory listing, and not carried over from a prior session.

**Why I assert the absence of a `FLAG{}` wrapper without a token sweep:** I did not run an exhaustive search for the literal string `FLAG{` across the filesystem, so I make no claim that it appears nowhere on this image. What I can state positively is what the reward *is* and where it came from. If the corpus index expects a `FLAG{}`-shaped column for this lab, this row should carry the file path `/root/flag.txt` and the signature `Grooti16` instead. Filing "no `FLAG{}` exists" on the strength of the reward's *shape* alone would be exactly the unearned negative this corpus exists to catch.

---

## 7. NOT tested

Each has a reason, not an excuse.

| Not tested | Why |
|---|---|
| **UDP plane** | No UDP listener and no UDP service is claimed by the manifest. **Coverage gap:** I did not scan UDP from outside. `/proc/net/udp` and `/proc/net/udp6` inside the container would settle it and are the cheap next check; I did not run them for this lab, so the UDP negative is **untested, not earned**. |
| **The other two recovered credentials** (`miles/m0ral3s`, `gwen/gw3n2025`) | Unnecessary once `peter` yielded the tunnel. Both accounts exist in `/etc/passwd` as `miles`/`gwen` with no local entry beyond images and web content — but I did **not** test SSH login with either, so their reachability is untested, not denied. |
| **Credential-campaign rate ladder** | Not needed: credentials were **disclosed by the target**, so there was no guessing to rate-limit. Zero authentication attempts were made against SSH beyond the three successful logins. |
| **Root SSH login** | `sshd -T` reports `permitrootlogin without-password` and `/etc/shadow` shows the root hash field as `*`. Both were read, not attacked. No root SSH attempt was made. |
| **LFI against the 4 other in-universe `.php` files** | `html/index.php` (self-include, infinite recursion), `heroes.php`, `contact.php` — all inside the docroot and reachable by plain name without traversal. No information gain. |
| **LFI against files outside the 5-file universe** | The `.php` suffix at `:94` makes them unreachable; the bounded `find` established the ceiling at 5 files. Testing further would be enumerating a set already proven closed. |
| **Argument injection on the sudo rule** | The rule pins `/usr/bin/python3 /opt/spidy.py` exactly. The intended path (directory replacement) succeeded, so no argument-manipulation variant was tried. The rule's exact-match behaviour is therefore inferred from the successful single-argument run, not measured. |
| **PHP session-file LFI** | Gated, not skipped: **0** occurrences of `session_start`/`$_SESSION`/`session_id` in `/var/www/`, and **0** files in `/var/lib/php/sessions` (which is nonetheless mode `1777`). Since the app never starts a session, no session file can ever exist to poison. |
| **Other web frameworks / hidden routes** | `autoindex` is loaded but no directory indexes were reachable; the bounded `.php` sweep is the authoritative file inventory for this image. |
| **Anything requiring the removed artefacts** | All probe files were deleted; their behaviour under repeat runs is not re-verified beyond the benign `sudo` sanity check. |

---

## 8. Evidence inventory

All under `~/dockerlabs-writeups/corpus/169/evidence/`. Every file is obtainable by a reader of this repository; nothing is cited that is not listed here.

**Harnesses (re-runnable)**

| File | What it does |
|---|---|
| `ssh_run.py` | Runs one command over SSH with a supplied credential; prints stdout/stderr/exit. Used for hops 2 and the `sudo -S -l` control. |
| `tunnel_probe.py` | Opens the SSH local forward and fires CONTROL-1/2/3 through it, refusing to trust any 8080 claim unless the oracle is green both ways. Writes `tunnel_evidence.txt`. |
| `rce.py` | Runs one command on the 8080 vhost through a fresh tunnel; prints `[http=…] [tunnel_requests_this_run=…]` and strips the page chrome to just the `system()` output. |

**Primary evidence**

| File | Contents |
|---|---|
| `waf_bypass.html` | Full response to the bypass POST — the disclosure table as returned. |
| `creds_recovered.txt` | The three extracted `User: … Pass: …` lines. |
| `ssh_peter_id.txt` | `id; hostname; whoami` as peter — the identity witness. |
| `peter_sudo.txt` | `Sorry, user peter may not run sudo on 6e865442bcaf.` |
| `tunnel_evidence.txt` | All three tunnel control responses in full, with the work count. |
| `rce_identity.txt` | `uid=33(www-data) … groups=33(www-data),1002(spiderlab)`. |
| `rce_sudo_l.txt** | `sudo -n -l` as www-data — the exact grant. |
| `privesc_run.txt` | `rm_rc=0 write_rc=0`, then the sudo run: `uid=0(root)`, `FLAG-BEGIN`…`FLAG-END`. |
| `backup_opt_spidy_verify.txt` | The 808-byte original `/opt/spidy.py`, used as the restore reference. |
| `backup_opt_spidy_raw.txt` | The same file fetched over RCE, for independent comparison. |
| `privesc_payload.py` | The replacement script that ran as root (read-only: prints its own `id`, then reads the flag). |
| `payload.b64` / `original.b64` | Base64 of payload and original, as transferred. |
| `restore_run.txt` | `RESTORED` from the restore command. |
| `tunnel_request_accounting.txt` | The reconstructed 12-call tunnel log with archived/not-archived status, and the note on why the automated count was 8. |

**LFI probes** — `l2.txt`, `l3.txt`, `l4.txt`, `l5.txt`, `l6.txt` (the five LFI responses; sizes 2561/2561/2561/**4927**/2561), plus `php_files_all.txt` (the bounded 5-file `.php` universe), `idx.html` and `mv.html` (baseline index and multiverse bodies used for the "no PHP warning in the body" claim).

**Restoration record** — final `/opt` state is `drwxr-xr-x root spiderlab`, containing only `-rwxr--r-- root root 808 spidy.py`, content byte-identical to `backup_opt_spidy_verify.txt`, verified by `diff`, `stat`, and a benign `sudo` execution of the restored original.