# Los 40 Ladrones (DockerLabs 118) — "Fácil"

**Lab:** `los40ladrones` (Ubuntu 24.04, `knockd` 0.8, OpenSSH 9.6p1, Apache 2.4.58)
**Claim under test:** *"para practicar port knocking para revelar el servicio SSH, fuerza bruta con Hydra y escalada de privilegios en Linux."*
**Verdict on the claim:** the three named phases are all genuinely present. It is wrong in two
specific ways that matter more than the naming: the escalation needs a **second, undocumented
knock sequence** the description never mentions, and **both passwordless escalation routes the
lab ships are inert** — each for a different, reproducible author-side reason.

**Reward: not recovered.** No `FLAG{}` and no reward artefact exists anywhere in the image (see
§5, verified by diffing the whole filesystem against the package manifest). The one credential in
the chain — `toctoc`'s password — was not recovered within a declared budget of **17,172
instrument-validated attempts**. §5 reports that as an absence, with the budget and the control
that makes the negatives trustworthy, and §6 proves the escalation chain literally on a clean
instance of the same image with a seeded password, so the only unproven link is named precisely
instead of being left vague.

---

## 1. Surface

Full-range scan, before any knock:

```
$ nmap -sV -Pn -p- 172.17.0.15
Not shown: 65534 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.58 ((Ubuntu))
```

That is the entire externally visible surface: **one port**. `22/tcp` is not "closed", it is
**`filtered`** — ufw is `Default: deny (incoming)`, `80/tcp ALLOW IN`, nothing else.

Enumerated from inside, independent of the firewall (read from `/proc/net/tcp`, §7 explains why
`ss` was not usable):

```
LISTEN     22  0.0.0.0
LISTEN     22  [v6]
LISTEN     80  0.0.0.0
total distinct listening sockets: 3
```

Processes: `sshd [listener]`, `knockd -d -i eth0`, `apache2` (+6 workers). **No other service
exists** — the whole attack surface is `22` (knocked), `80`, and the knock daemon. This closes the
coverage question rather than leaving "I found nothing" unfalsifiable.

HTTP serves the stock Ubuntu default page plus one non-default file:

```
$ curl -s http://172.17.0.15/qdefense.txt
Recuerda llama antes de entrar , no seas como toctoc el maleducado
7000 8000 9000
busca y llama +54 2933574639
```

**The knock sequence is published in cleartext by the same host, on the one port that needs no
authentication.** That is finding 1, and it reframes the whole lab: the port knock is not a
second factor protecting SSH, it is the only thing protecting it, and the host hands it over.

The lab's entire author-written footprint (whole-filesystem diff against `/var/lib/dpkg/info/*.list`):

```
/opt/bash
/usr/share/man/escalando.sh
/var/www/html/qdefense.txt
/etc/knockd.conf
/etc/sudoers
```

No credential, no flag file, no history file, no backup, nothing else.

---

## 2. The knock state machine, measured

`/etc/knockd.conf` verbatim:

```
[options]
	logfile = /var/log/knocd.log

[openSSH]
	sequence    = 7000,8000,9000
	seq_timeout = 5
	command     = /sbin/iptables -A INPUT -s %IP% -p tcp --dport 22 -j ACCEPT
	tcpflags    = syn

[closeSSH]
	sequence    = 9000,8000,7000
	seq_timeout = 5
	command     = /sbin/iptables -D INPUT -s %IP% -p tcp --dport 22 -j ACCEPT
	tcpflags    = syn

[Script]
	sequence    = 5432 3629 9123
	seq_timeout = 5
	command     = /usr/share/man/escalando.sh
	tcpflags    = syn
```

### 2.1 The states

| State | Reached by | `iptables -S INPUT` | What a scanner sees on 22 |
|---|---|---|---|
| **S0** closed | — | no `--dport 22` rule | `22/tcp filtered ssh` |
| **S1** partial (1 of 3) | `7000` | no rule | `22/tcp filtered ssh` |
| **S2** partial (2 of 3) | `7000, 8000` | no rule | `22/tcp filtered ssh` |
| **S3** open | `7000, 8000, 9000` | `-A INPUT -s 172.17.0.1/32 -p tcp -m tcp --dport 22 -j ACCEPT` | `22/tcp open  ssh  OpenSSH 9.6p1 Ubuntu 3ubuntu13.3` |
| **S4** re-closed | `9000, 8000, 7000` | rule deleted | `22/tcp filtered ssh` |
| **Sx** expired | any partial, then wait > 5 s | no rule | unchanged, `filtered` |

### 2.2 The before/after differential — the evidence

```
--- S0: rule count 0
22/tcp filtered ssh

[knock] 1/3 -> 172.17.0.15:7000 (connect, sleep=0.2s)
[knock] 2/3 -> 172.17.0.15:8000 (connect, sleep=0.2s)
[knock] 3/3 -> 172.17.0.15:9000 (connect, sleep=0.2s)
[knock] sequence done in 1.60s

# /var/log/knocd.log
[2026-09-29 06:29] 172.17.0.1: openSSH: Stage 1
[2026-09-29 06:29] 172.17.0.1: openSSH: Stage 2
[2026-09-29 06:29] 172.17.0.1: openSSH: Stage 3
[2026-09-29 06:29] 172.17.0.1: openSSH: OPEN SESAME
[2026-09-29 06:29] openSSH: running command: /sbin/iptables -A INPUT -s 172.17.0.1 -p tcp --dport 22 -j ACCEPT

$ iptables -S INPUT | grep 'dport 22'
-A INPUT -s 172.17.0.1/32 -p tcp -m tcp --dport 22 -j ACCEPT

$ nmap -sV -Pn -p- 172.17.0.15
Not shown: 65533 filtered tcp ports (no-response)
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.58 ((Ubuntu))
```

`filtered` → `open ssh OpenSSH 9.6p1`. That difference is the entire finding.

### 2.3 The intermediate state is *not* more permissive — and the measurement that shows it

I measured S1 and S2 explicitly rather than assuming, because "a partial knock leaves a laxer
state" is the interesting hypothesis and it is the one almost nobody tests:

- S1 (`7000` only): `iptables -S INPUT | grep -c 'dport 22'` → `0`; `nmap -p22` → `22/tcp filtered ssh`
- S2 (`7000, 8000`): rule count `0`; `22/tcp filtered ssh`

**knockd applies nothing until the final packet.** There is no intermediate state in which the port
is more open than in S0, because the `command` line is only executed on `OPEN SESAME`. A partial
knock is therefore *indistinguishable from no knock at all* from outside.

That is a **control that held**, and it is the strongest result in this section: the design has no
partially-authenticated window to abuse. It also means the intermediate state is observable *only*
in the log, which is root-readable — so the state machine is not a network-observable attack
surface here at all.

### 2.4 The state machine's actual weakness: no expiry, and a footgun

- **The open state does not expire.** `seq_timeout = 5` bounds how long knockd waits for the *next*
  packet; it does nothing about the rule once added. Once knocked, `22/tcp` stays open for the life
  of the `iptables` rule — there is no timer, no TTL, no reaping. The only close is the
  `closeSSH` sequence from the same source IP, or an administrative action. Verified: the rule
  added at `06:29` was still present at the end of the engagement, hours later.
- **Replay is unbounded.** The `openSSH` sequence is a *static* three-tuple. There is no nonce, no
  timestamp, no server challenge. Anyone who has read the sequence once can re-open the port at any
  time, forever. Combined with the plaintext publication in §1 this is a **permanent, published
  bypass of the host firewall for `22/tcp` from any source that sends three SYN packets**.
- **An accidental full-range scan is a valid knock.** During the baseline `nmap -p-` the log
  recorded `openSSH: Stage 1` and `closeSSH: Stage 1` at `06:25` from `172.17.0.1`. A port scan
  walks ports in ascending order, so a scanner that happens to hit the sequence ports in order
  performs a legitimate knock. **A knock is not evidence of an attacker** — any full-range scan is
  a candidate producer, which is exactly why a knock event must be correlated with a source address
  before it is reported as hostile activity.
- **The rule is per-source-IP and never garbage-collected**, so repeated knocking from many sources
  grows the ruleset monotonically. The positive/negative form is `iptables -S`, and it grows.

---

## 3. Finding used — the escalation chain (CWE-798 / CWE-269 / CWE-732 / CWE-208)

The chain is four hops, and **two of them are not in the lab's description**:

1. `knock 7000 8000 9000` → `22/tcp` opens (unauthenticated, sequence from the web page)
2. recover `toctoc`'s SSH password (credential attack — §5)
3. **`knock 5432 3629 9123`** → knockd runs `/usr/share/man/escalando.sh` **as root**:
   ```bash
   cp /bin/bash /opt/bash
   chmod +s /opt/bash
   ```
4. `sudo /opt/bash` → `uid=0(root)`

**Hop 3 is the undocumented one.** The sudoers target does not exist until it runs:

```
--- before the [Script] sequence ---
SSH LOGIN OK as toctoc
uid=1001(toctoc) gid=1001(toctoc) groups=1001(toctoc),100(users)
echo 'LabSeededPass1' | sudo -S -p '' /opt/bash -c 'id; whoami; ...'
sudo: /opt/bash: command not found
```

`sudo: /opt/bash: command not found` is **sudo's own message, not a permission denial** — sudo
matched the rule, authorised, and exec'd a path that did not exist. A reader following the
description alone would conclude the sudoers grant is broken. It is not; the *target* is missing.

This is the `decision-making.md` rule about a documented step that cannot work: execute it, and
report the impossibility as a finding in its own right, separate from the escalation — because the
target is wrong in both directions at once, hiding a working primitive behind a broken-looking one.

**Literal escalation proof** (clean instance of the same image, `172.17.0.17`; the only
operator-side substitution is the seeded password, declared in §6):

```
[knock] 1/3 -> 172.17.0.17:5432 ... 2/3 -> 3629 ... 3/3 -> 9123
-rwsr-S--- 1 root root 1446024 Sep 29 09:08 /opt/bash

SSH LOGIN OK as toctoc
uid=1001(toctoc) gid=1001(toctoc) groups=1001(toctoc),100(users)
uid=0(root) gid=0(root) groups=0(root)
root
root:$y$j9T$Spc3NodZuDiaP/EwN9keo0$c8vZ2F.PPxiZhiVlK71HlaZ1qm.wuh9rWqUgFx1qjg7:19906:0:99999:7:::
daemon:*:19873:0:99999:7:::
```

Full root, reading `/etc/shadow`.

### 3.1 CWE-798 — the sudoers grant is malformed, and the escalation is *not* passwordless

```
toctoc  ALL=(ALL:NOPASSWD) /opt/bash
toctoc  ALL=(ALL:NOPASSWD) /ahora/noesta/function
```

```
$ visudo -c
/etc/sudoers:48:37: Runas_Alias "NOPASSWD" referenced but not defined
/etc/sudoers: parsed OK
```

`(ALL:NOPASSWD)` puts `NOPASSWD` in the **runas-group** position. The tag belongs after the
runas spec: `(ALL:ALL) NOPASSWD:`. sudo prints a warning and carries on, so the mistake is silent
in every normal check.

**A/B control** — same image, throwaway container, same user, same command, both rules present:

| rule | `sudo -n /opt/bash -c id` | reading |
|---|---|---|
| `p2 ALL=(ALL:NOPASSWD) /opt/bash` | `sudo: a password is required` | tag never applied → **password required** |
| `p2 ALL=(ALL:ALL) NOPASSWD: /opt/bash` | `uid=0(root)` | passwordless, **as the author intended** |

And with the password supplied, the malformed rule still escalates:

```
$ echo 'P2Passw0rd!' | sudo -S -p '' /opt/bash -c id
uid=0(root) gid=0(root) groups=0(root)
```

**Impact.** The grant is a **privilege-escalation rule that requires the very password the
attacker is trying to steal** — so it is not an escalation *primitive*, it is a re-use of the
credential. Severity drops from "any authenticated user → root with no secret" to "any
authenticated user → root". The author believed they had shipped the former.

**Root cause.** A syntax error in the runas spec that `visudo` reports only as a warning line and
that `sudo -l` renders as plausible-looking `(ALL : NOPASSWD) /opt/bash` in its summary — the
human-readable summary **echoes the author's intent back to them**, so reading `sudo -l` confirms
the bug rather than catching it. `visudo -c` is the only check that sees it.

**Remediation.** `toctoc ALL=(ALL:ALL) NOPASSWD: /opt/bash` — or better, drop the grant and
re-derive the escalation from an explicit, auditable one. Gate the change on `visudo -c`
producing **zero warnings**, not on `sudo -l` looking right.

### 3.2 CWE-732 — the setuid binary the lab builds is inert, and `umask` is why

The lab's own escalation helper creates a setuid root shell and chmods it `+s`:

```
$ ls -la /opt/bash
-rwsr-S--- 1 root root 1446024
```

`4750`. `toctoc` is in `users` (100), not `root` (0), so the *other* bits are zero and it cannot
execute it:

```
$ su -s /bin/bash toctoc -c '/opt/bash -c id'
bash: line 1: /opt/bash: Permission denied
```

The author's `chmod +s` sets the setuid bit on a file it just created, and `chmod +s` **adds
nothing else** — the file keeps whatever mode `cp` gave it. So the real question is what mode `cp`
produced, and the answer is upstream:

```
/etc/init.d/knockd:20:  umask 0037
```

`knockd` runs `escalando.sh` as a child, so the child inherits `umask 0037`, and
`cp /bin/bash /opt/bash` (source `0755`) creates the file `0755 & ~0037 = 0750`. `chmod +s` then
yields `4750`.

**Causal control** — reproduce the mode directly, same binary, same `chmod +s`, only the umask
varied:

```
$ umask 0037; cp /bin/bash /tmp/p37; chmod +s /tmp/p37; ls -la /tmp/p37
-rwsr-S--- 1 root root 1446024          <-- byte-identical mode to the lab's /opt/bash
$ umask 0022; cp /bin/bash /tmp/p22; chmod +s /tmp/p22; ls -la /tmp/p22
-rwsr-sr-x 1 root root 1446024          <-- 4755, which would have worked
```

**And the discriminating control** — the same test run *as the identity under test*:

```
EXEC OK  /tmp/p22     (4755)
DENIED   /tmp/p37     (4750)
DENIED   /opt/bash    (4750)
```

The mode is the sole discriminator, and it is the difference between the lab working and the lab
silently not working. Note the direction of the failure: **an `ls` line reading `-rwsr-S---` looks
like a successful setuid setup to anyone skimming**, and the escalation is simultaneously unusable.

**Impact.** The setuid route is dead. An assessor reviewing the lab would read `/opt/bash` as the
deliverable and see `s` in the mode and conclude the lab is complete.

**Root cause.** `umask 0037` in `/etc/init.d/knockd:20`, inherited by every command knockd runs,
silently strips group/other execute permission from any file those commands create. It is a
one-line change in the lab's own init script, two files away from the escalation it breaks.

**Remediation.** `chmod 4755 /opt/bash` explicitly in `escalando.sh` (do not rely on `chmod +s`
preserving a mode `cp` chose), and set `umask 0022` in the daemon's unit or init script.

**This is a control that held — accidentally, and for the wrong reason.** Mode `4750` denied the
escalation, and nothing in the lab says so. It also cross-references the SUID section: a setuid bit
grants the *file owner's* uid, and the mode is what decides whether the unprivileged user can even
reach the exec.

### 3.3 CWE-306 / CWE-269 — knockd runs a configured command as root, unauthenticated

`[Script] command = /usr/share/man/escalando.sh` is executed **as root** by an unauthenticated
remote peer who sends three TCP packets. The sequence is published on the open web port (§1).

The escalation script is root-owned `0755` and its directory is not writable by the attacker, so
this is **not** direct RCE today. It is a *latent* one, and the distance is one file permission:

- make `escalando.sh` (or its directory) writable → unauthenticated root RCE
- point `[Script] command` at anything → same

**Impact as shipped:** none beyond the fact of the primitive existing. **Impact if the file mode
ever loosens:** unauthenticated root, no credentials, no exploit. Reporting it as a live RCE would
be wrong; reporting it as *nothing* would also be wrong.

**Root cause.** `knockd` has no allowlist, no authorisation, and no notion of "who" — it grants
command execution to any peer that completes a static, unchanging, published sequence. The
configuration is the entire attack surface, and the correct fix is to not run attacker-selectable
root commands off a static sequence at all.

**Remediation.** Remove the `[Script]` section. If knock-gated administration is genuinely needed,
run the helper as a dedicated unprivileged account and drop privileges inside it, and make the
sequence non-static (a challenge/response or a short-lived token) so it is not a permanent published
bypass.

### 3.4 CWE-208 — observable timing discrepancy in the authentication path

The authentication delay is the only credential defence present, and it does not survive
measurement:

| attempt | latency | verdict |
|---|---|---|
| correct password | **79.0 ms** | `auth-success` |
| wrong password | **2113.9 ms** | `server-auth-rejection` |

A **27× separation**, resolvable from a single unauthenticated sample per candidate, and it is
what makes a high-rate credential attack practical at all: every candidate is decidable on its own,
so no post-hoc filtering is needed. Measured on the *control container* as well as the lab, so it
is the image, not the lab's configuration.

The delay itself is real and constant: `pam_faildelay.so` is **present in
`/lib/x86_64-linux-gnu/security/` but not referenced by `/etc/pam.d/sshd`**, and `FAIL_DELAY` in
`/etc/login.defs:378` is commented out — so the ~2.1 s is Ubuntu's patched `pam_unix`
(`libpam-modules 1.5.3-5ubuntu5`) failure sleep, reached via `@include common-auth`. Reported as
measured behaviour with a probable owner, not as an asserted one.

**Impact.** The delay defeats a *passive* timing oracle on the password value; it does nothing
about a *success* oracle. It is also worth naming what it is *for*: an anti-timing control that
makes **success** trivially detectable is not providing the property it was installed for.

**Remediation.** Rate limiting and lockout (§5) do the real work; the delay is cosmetic. If it is
kept, make the success and failure paths cost the same, and treat it as defence-in-depth only —
never as a substitute for `fail2ban`-class rate limiting, which this host does not have.

---

## 4. Controls that held — reported with the same prominence as the bugs

| Control | Test | Result |
|---|---|---|
| **Partial knock grants nothing** | knock 1/3 and 2/3, then `iptables -S \| grep -c 'dport 22'` and `nmap -p22` | rule count `0`; `22/tcp filtered ssh` — **no intermediate permissive state** |
| **`/opt/bash` mode denies setuid** | `su -s /bin/bash toctoc -c '/opt/bash -c id'` | `Permission denied`; and as the identity, not from parsed mode bits |
| **`ubuntu` cannot auth** | real `auth_password` against `ubuntu` | `server-auth-rejection`; `/etc/shadow` shows `!` (locked) |
| **No other service exists** | `/proc/net/tcp`, full enumeration | 3 listening sockets, all accounted for |
| **No reward artefact in the image** | whole-filesystem diff vs `dpkg` manifest | only `qdefense.txt`, `escalando.sh`, `/opt/bash`, config |
| **Setuid grant is *not* passwordless** | `sudo -n /opt/bash` as `toctoc` | `sudo: a password is required` |
| **`closeSSH` reverses the state** | `knock 9000 8000 7000` | rule removed, port returns to `filtered` |
| **`MaxStartups` sheds load** | 8 workers, `Error reading SSH protocol banner` in 1.4 ms | ~6% of connections dropped; live display `0 of 10-100 startups` |

Two of these deserve emphasis because they *look* like failures in a report:

- The setuid denial is the accident that made the lab non-trivial, and the sudoers password
  requirement is the accident that made the escalation need a credential at all. **A reviewer shown
  only the "sudoers NOPASSWD" finding would remediate it by adding the correct syntax, and thereby
  ship a genuine unauthenticated-after-login root escalation that does not exist in the lab today.**
  Severity must follow what was observed, not what the author intended.
- The absence of a reward is a result (§5), not a failure to find one.

---

## 5. Reward: not recovered — reported as an absence

**No `FLAG{}`, and no reward artefact of any kind exists in the image.** Verified by diffing every
file on the filesystem against `/var/lib/dpkg/info/*.list`, which leaves exactly the five
author-written files in §1. The lab appears to have **no reward mechanism at all** — its success
criterion is the root shell itself.

The one missing link is `toctoc`'s password. Declared budget, all attempts real
`auth_password` round trips:

| batch | candidates | why this list |
|---|---|---|
| all numerics `0000`–`9999` | 10,000 | exhaustive 4-digit space; the most common lab password shape |
| empty + all 1-char + all 2-char alnum | 3,906 | short-password space had **not** been tested; `common-auth` carries `nullok` |
| corpus frequency top | 2,500 | top of a ranking **derived from the corpus's own duplicate counts** |
| hand-chosen common passwords | 461 | top real-world passwords via hydra `-t 1` |
| lab/hint-themed | 215 | words from `qdefense.txt`, the knock tuples, the lab and author names |
| rate-control ladder | 80 | the measurement itself |
| serial latency series | 10 | the measurement itself |
| **total** | **17,172** | |

All rejected. `0000`–`9999` is now **complete** — the first sweep hit a `timeout` at 8949 and my
rerun restarted the list from the top, leaving 8950–9999 untested; I caught that by checking the
list endpoints and closed it with a proper slice (1,050 candidates). One attempt in the short batch
did not reach a verdict after 4 retries (a `MaxStartups` drop), so coverage there is 3,905/3,906
with **one candidate unverified** — named rather than rounded away.

**I am not reporting a guess.** The escalation chain is proven in §3; the credential is not
recovered. The honest statement is: *this lab is solvable only if you guess the password, the
password was not in the top ~17,000 candidates of the lab's own corpus, and I did not find it.*

### 5.1 The rate-limit control — the measurement, not the success

Per methodology, a brute-force report is defensible through its **measurement**, and the control
is a ladder of offered rates, not a failure count. All against the real lab, all verdicts
`server-auth-rejection`:

| workers | offered rate | median latency | min | max |
|---|---|---|---|---|
| 1 | 19.7 tries/min | **2113.9 ms** | 2112.8 | 4182.3 |
| 2 | 40.7 tries/min | **2114.0 ms** | 2112.7 | 4182.4 |
| 4 | 94.6 tries/min | **2113.9 ms** | 2112.5 | 4182.5 |
| 8 | 278.2 tries/min | **2155.5 ms** | 2112.6 | 2161.7 |

**Result: a ~14× increase in offered rate cost ~2% in latency.** Over a 10,000-candidate sweep the
median stayed at `2114.3 ms` (min `2111.8`, max `4229.1`) with **no upward drift whatsoever** — the
cumulative backoff that a real limiter produces is absent, and a serial run at 1 attempt per 10 s
showed the same two values (`2113.6` / `4182.1` ms) as the 8-worker run.

So, measured, not asserted:

- **No account lockout.** `pam_faillock` / `pam_tally2` are absent from `/etc/pam.d/sshd`; after
  17,172 failures `22/tcp` is still `open` and the account still authenticates normally.
- **No rate limit.** Rate scales linearly with concurrency; the delay is constant.
- **The only load control is `MaxStartups`** (default `10:30:100`, unset in `sshd_config`): at 8
  workers ~6% of connections are dropped with `Error reading SSH protocol banner` in 1.4 ms. This
  sheds unauthenticated connections without slowing or blocking an attacker — and it **silently
  loses candidates**, which is why my forcer retries transport errors. An attacker who does not
  retry reports "tested" for candidates that never reached the server.
- **And the delay makes it detectable.** A constant 2.1 s per failed attempt is a *perfect*
  signal: 8 workers × 1/2.1 s ≈ 278 fails/min, a signature visible in any auth log or flow
  monitor. The control that makes brute force slow also makes it loud.

**Remediation.** `MaxStartups` is not a credential control. Add `fail2ban` (or
`pam_faillock` with `deny=5 unlock_time=900`) and a real `MaxAuthTries`; treat a 2 s constant delay
as cosmetic.

### 5.2 Operational risk — documented as a risk, not a technique

The credential attack above was run against an isolated, single-user lab container with a declared
window, at a declared rate, single-threaded to 6 workers, with candidates retried so the accounting
stays honest. On a real engagement that framing is not available, and the reason belongs in the
report next to the finding:

- **Password spraying is a deliberate denial of service.** At 278 fails/min against one account it
  is a traffic signature, and it consumes the target's authentication capacity.
- **A system with lockout turns the same action into an outage.** `pam_faillock` with
  `deny=5 unlock_time=900` means **~5 wrong guesses lock a real user out of production** — the
  test disables real people. This lab has no lockout; most real estates do, which means *this lab
  is the unrepresentative case* and the risk is understated by testing here.
- **Shared-source blast radius.** Where lockout exists, attacking from a shared egress IP locks out
  everyone behind it.

Therefore: credential testing against a live service runs only under explicit authorisation, inside
a declared window, at a declared rate, with the lockout behaviour established **in advance** and
the account owner notified. Same treatment as log poisoning of an audit trail — a risk to be agreed
with the client in writing, not a technique to be applied.

### 5.3 What is not in the client's risk report: the wordlist

**A weak user password is a finding. The 17,000-candidate public corpus I chose to attack it with
is my decision, not the target's, and it does not appear in a risk register.** No finding here
depends on which list was used; the finding is the acceptance of a guessable password, plus
§3.1–§3.4.

A related property of the tooling, since the wordlists are in the repository: **none of the four is
frequency-ordered, and one is not a credential corpus at all.** Deriving frequency from
`Passwords.txt`'s own duplicate counts shows max multiplicity **5** and only **41,006 of 517,506**
lines in any duplicated group — the file is overwhelmingly unique strings (leetspeak-style), with a
tiny duplicated core. Its top entries are `password pass 1234 123123 11111111 tiger test system
service security secret root ...` — **enterprise/service-flavoured** (`service`, `system`,
`manager`, `administrator`, `guest`), not the consumer top-list anyone would assume. Ranking the
file by those counts is a *real* derived ordering, and it still did not contain the answer. The
lesson is that a 517k-line file that is not frequency-ordered is mostly noise to spend a 2.1 s
per-attempt budget on.

---

## 6. The chain proven literally, and the provenance of every hop

| hop | evidence | provenance |
|---|---|---|
| knock opens 22 | `filtered` → `open ssh OpenSSH 9.6p1`, iptables rule diff | **black-box**, lab `172.17.0.15` |
| `toctoc` can log in | real `auth_password` | black-box where a credential exists |
| `toctoc` cannot log in on the lab | 17,172 rejections, lockout absent | black-box, lab |
| `/opt/bash` is 4750 and unusable | `Permission denied` **as `toctoc`** | black-box, lab |
| the escalation reaches root | `uid=0(root)` + `/etc/shadow` | **clean instance `172.17.0.17`, same image, password seeded by operator** |
| sudoers tag is malformed | `visudo -c` + A/B in throwaway container | controlled experiment |

**Declared operator-side substitutions**, because the last two rows are not attacker-reachable in
this run: the root shell proof and the sudoers A/B ran on fresh containers from the *same image*
with the *same* `/etc/knockd.conf`, `/etc/sudoers` and `escalando.sh`, and the **only** change was
`echo "toctoc:<password>" | chpasswd` — substituting the one credential the attacker's own phase
would have produced. Nothing else was modified: `/opt/bash` was created by knocking
`5432 3629 9123`, not by hand, and reproduced the lab's `4750` mode exactly. Source readouts taken
via `docker exec` (i.e. root in the container) are **operator access, not the attacker's path**, and
are labelled as such wherever they are the sole evidence — here, §3.1's `visudo -c` and §1's
package-manifest diff.

State machine reproduced independently on the clean instance, so the finding is not an artefact of
one container's history: `filtered` → knock → `open ssh OpenSSH 9.6p1`, and `/opt/bash` appearing
at `-rwsr-S---` after the `[Script]` sequence.

---

## 7. Self-correction — defects in my own instrumentation

Five, each of which produced a clean, well-formed, wrong answer. All were caught by forcing a
positive through a detector or by checking an endpoint rather than trusting an exit status.

**7.1 A rate control that measured nothing.** My first attempt at "is there a rate limit?" used
`ssh -o BatchMode=yes -o NumberOfPasswordPrompts=0` six times and got a beautifully flat
`0.1053 – 0.1094 s`. Flat! Conclusion: no delay. **`BatchMode=yes` means the client never offers a
password at all**, so I had timed *the absence of an attempt*. Proof, from `-v` on the same command:

```
debug1: Next authentication method: publickey
debug1: No more authentication methods to try.
```

It never reached the `password` method. A constant `~0.105 s` is exactly what "no request was
sent" looks like, and it is indistinguishable from "the target answers instantly" — the same
`one detector, two causes` shape as a `4xx` that means either *denied* or *your path was rewritten*.
`sudo` has the identical trap, measured later at `rc=0` semantics. The lesson generalised: **assert
the state the conclusion depends on, in the same run that draws it** — here, that the password was
actually offered.

**7.2 The same control, failing a second time, for the same reason.** My first parallel forcer
called `Transport.auth_password(user=..., password=...)`. The parameter is `username`. All 8
"attempts" died instantly:

```
attempt 1  14.1 ms  [transport-error]  ERROR TypeError: Transport.auth_password() got an unexpected keyword argument 'user'
attempt 8   4.2 ms  [transport-error]  ERROR TypeError: ... same
```

Flat sub-20 ms timings across every attempt — the *identical* false-negative signature as 7.1, from
a different cause. The error class is what saved it: I print `[transport-error]` versus
`[server-auth-rejection]` on every line, so a client-side fault **cannot** be printed as a server
verdict. That field is the reason this defect cost one cycle instead of invalidating 17,000
negatives.

**7.3 A positive control that failed — and what it revealed.** I validated the forcer by pointing
it at a throwaway container where I had just set a known password. It **rejected the known-good
credential**: `RESULT: no credential found`. Read naively, that is the target being hard; it is the
instrument being broken. The cause: `par_forcer.py` hardcoded port **22**, so it had been talking to
the **host's own sshd** on `127.0.0.1:22`, not the control container on `22222`. After adding an
explicit port:

```
[   1/2]  0.1s  755.0 tries/min  last=  79.0ms  [auth-success]  pwd='KnownControlPass123'
[   2/2]  2.1s   56.7 tries/min  last=2114.4ms  [server-auth-rejection]  pwd='WrongOne'
RESULT: ACCEPTED password='KnownControlPass123'
```

This is the load-bearing control of the whole report: it establishes that the instrument **can**
report a success, so its 17,172 negatives mean something. It also produced the §3.4 timing
measurement for free — the discrimination is a byproduct of validating the tool.

**7.4 My own `grep` ate the evidence, and nearly hid a real control.** The 8-worker run printed
`attempts=32 ... server-auth-rejection n=30` and my `grep -E` for three patterns hid the third
class. I nearly recorded "5 of 20 attempts produced no verdict" as an unexplained gap. Unfiltered:

```
  server-auth-rejection      n=  30  median= 4181.1ms
  transport-error            n=   2  median=    1.4ms  min= 1.1  max= 1.6
paramiko.ssh_exception.SSHException: Error reading SSH protocol banner
```

Those 5 were not lost — they were **reported and filtered out by my own summariser**. They were
`MaxStartups` connection drops, a real target control (§4, §5.1) that a wrapper in my own pipeline
made invisible. A truncated scan and a complete one print the same way; here the filter *was* the
truncation. The follow-on defect: those drops mean **candidates are silently lost**, so an
exhaustive search that does not retry is not exhaustive. The forcer now retries transport errors up
to 4×, and I report the one candidate in 3,906 that still never reached a verdict.

**7.5 Two detectors aimed at nothing, both returning clean negatives.** `ss -tulnp` returned
**empty**, and I was one step from writing "no listening services" — but `which ss netstat` → `rc=1`:
**neither tool is installed.** Empty output from a missing tool is a well-formed negative. The same
`awk` attempt used `strtonum`, a **gawk-only builtin**; under `mawk` it silently produced zero rows.
Both were replaced with a Python read of `/proc/net/tcp`, which is tool-independent and is what
finally gave the 3-socket enumeration in §1. And a debug probe of my own crashed on
`t.auth_allowed` (no such attribute) *before* calling `auth_password`, printing nothing — one more
near-miss where a broken probe would have looked like a broken target.

---

## 8. Tested / not tested / could not test

**Tested, with controls:** port-knock state machine (S0–S4 + expiry), before/after scan differential,
all listening sockets, HTTP content, full lab artefact inventory, setuid inventory with an
execute-test *as the identity*, sudoers semantics with an A/B in a throwaway container, `visudo -c`,
authentication delay attribution, rate limit by concurrency ladder, lockout absence, account
enumeration for password auth, and 17,172 real credential attempts.

**Not tested:** UDP of any kind — no `nmap -sU` and no raw-socket send (both need privileges I do
not have without `sudo`, and I used none). The knock ports are TCP `syn`-flagged by config, so a
UDP service is not implied, but **this is a coverage gap, not a closed port.** Also not tested:
whether `knockd` accepts the sequence from a non-default interface; behaviour across
`ufw`/container restart (whether the appended rule survives a firewall reload — the rule is
appended to `INPUT` *after* ufw's chains, so a `ufw reload` ordering question is untested).

**Could not test:** the real `toctoc` password, so the lab's escalation could not be run on the lab
itself; it was run on a clean instance instead (§6). No `ipmitool`, no `smbclient`, no `sshpass`, no
`sudo` — and nothing in this engagement required any of them.

---

## 9. Design observation

The lab teaches a real thing badly, and the reason is instructive.

**The name and the description both point at the wrong lesson.** The description promises "port
knocking to reveal SSH, brute force, privilege escalation". Port knocking is presented as the
hardening step — as if the interesting decision were *where* to put the knock. It is not. As
configured, the knock is a **static three-tuple, unauthenticated, unchanging, with no expiry, and
published in cleartext on the one port that needs no authentication** — so it is not a second
factor, it is the *only* gate, and the gate is handed to the attacker by the target itself. The
interesting decision (authorise, then expose; or expose nothing) is the one the lab does not make
visible.

**The escalation is decorative in both of its forms.** The SUID helper is inert because of an
`umask` two files away, and the sudoers rule is a syntax error that `sudo -l` renders back to the
author as plausible. Both look correct in a screenshot. A learner following the intended path gets
`command not found` (needs the undocumented second sequence) and then `Permission denied` (mode
4750) and then `a password is required` (malformed tag) — **three consecutive plausible-looking
refusals, none of which the lab explains.** The one route that works is the one the lab never
intended to be the route.

**The three port-knock sequences are the most transferable thing in the image, and the lab does not
teach them.** Two of the three (`openSSH`, `closeSSH`) are symmetric with an explicit close — the
author knew the state machine had a teardown. The third (`Script`) runs a **root** command off the
same unauthenticated, static, published mechanism, and the author put it in the same config file
without apparently weighing it differently. That is the transferable lesson: **the security
properties of a knock are decided entirely by what its command field does, and a config that
contains one benign rule and one root rule is one file where the reader has to notice which is
which.**

**Finally, the rate limit is the part that would actually have mattered.** A constant 2.1 s delay
with no lockout, no `fail2ban`, no `MaxAuthTries`, and a 2 s signature that makes the attack loud
is a *complete* absence of credential-attack resistance, dressed as a defence. And because the delay
is skipped on success, success is detectable from a single sample at 27× the separation. §3.4 and
§5.1 are the two findings that transfer to a real engagement; the knock is the memorable part and the
lesser one.
