# DockHackLab (DockerLabs 129) — "Medium"

**Description:** *"Laboratorio para practicar port knocking, subida de ficheros PHP e inyección de claves SSH para escalar privilegios."*

**Verdict on the description: one of three elements is real, one is decorative, one is absent.**

| Claimed | Reality |
|---|---|
| Port knocking | **Real mechanism, dead end.** `knockd` runs, state machine verified, and the command it fires cannot succeed in this container. |
| PHP file upload | **Real, and the entry point.** Unauthenticated RCE as `www-data`. |
| SSH key injection to escalate privileges | **The class is real and was the whole point** — but the escalation it enables is *abuse of a granted capability*, not escape. |

There is **no LFI anywhere on this host** (see §1.3), which is the shape the methodology needed to test: the "include executes as an identity that can write" question had to be answered **without** an LFI, and the answer turned out to be more useful for it.

---

## 1. Surface

### 1.1 External

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.4 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.58 ((Ubuntu))
Not shown: 65533 closed tcp ports (conn-refused)
```

Ubuntu 24.04, Apache 2.4.58, PHP 8.3, OpenSSH 9.6p1. Only 22 and 80. The `knockd` ports (12345/54321/24680/13579) are **not open services** — they are consumed by a listener that never opens a port.

### 1.2 Services actually running (measured, not assumed)

```
root   15  /usr/sbin/sshd [listener] 0 of 10-100 startups
root   33  /usr/sbin/apache2 -k start
www-data 38..42  /usr/sbin/apache2 -k start
root   50  /usr/sbin/knockd -d -i eth0
```

`service knockd status` printed only a usage line — **that is an init-script artifact, not an absence.** The process table is the measurement. Had I trusted the status line I would have reported "port knocking is not present", the same mistake as lab 141 (narrative ≠ evidence).

`ufw` **is** genuinely absent: `service ufw start` failed with `iptables ... Permission denied`, and `CapEff` lacks `cap_net_admin`. Noted because the deploy script starts it, and a report saying "firewall active" would be false.

### 1.3 Source read before attacking (§7)

```
# /etc/knockd.conf
[options]
	logfile=/var/log/knockd.log
[SCRIPT]
	sequence    = 12345,54321,24680,13579
	seq_timeout = 5
	command     = /usr/bin/launch
	tcpflags    = syn

# /usr/bin/launch
nohup /usr/bin/dockerd 2>/dev/null &

# /etc/sudoers (non-default lines)
www-data ALL=(firsthacking) NOPASSWD: /usr/bin/nano
firsthacking ALL=(ALL) NOPASSWD: /usr/bin/docker

# /var/www/html/hackademy/upload.php  (allowlist)
if($imageFileType != "php" && $imageFileType != "png" && $imageFileType != "jpeg"
&& $imageFileType != "gif" ) { ... }
```

Two findings from source alone:

1. **The upload allowlist explicitly permits `php`.** The `getimagesize()` content check is commented out. This is not a MIME-map bypass (lab 118's mechanism) — it is an allowlist that names the dangerous extension. The transfer from lab 118 holds: *the extension that executes is decided by configuration, and here the configuration says yes out loud.*
2. **The `sudo` grant names a program, not a shell.** `www-data` may run `/usr/bin/nano` **as `firsthacking`**. Per the existing sudo-rule oracle, that is a capability grant: *what does this program do as that user?* GNU nano 7.2 has `^T Execute`, which runs a command as the nano process user.

### 1.4 LFI: searched for and confirmed absent

```
# find / -xdev -name '*.php' -not -path '/usr/share/*'
/var/www/html/hackademy/upload.php
(+ my own two uploaded probes)

# grep -rln 'include|require' --include=*.php /   -> no results
# auto_prepend_file / auto_append_file / include_path / open_basedir -> all commented out
```

**No LFI, no `include`, no log-poisoning sink.** The methodology's "measure both identities" rule was built around an LFI; here the interesting answer is that the *distance between the identities* is created by something else entirely, and the LFI framing would have been the wrong model.

---

## 2. The knock state machine, measured

The oracle from lab 118 was reused, not rewritten. `knockd`'s log is the oracle: it names each stage and the terminal transition.

### 2.1 Controls first

- **Positive control:** full sequence → `[... ] 172.17.0.1: SCRIPT: OPEN SESAME` + `running command: /usr/bin/launch`.
- **Negative control:** wrong sequence (9999, 8888, 7777) → **no** stage lines, no `OPEN SESAME`.

Without the positive control, "the knock did nothing" would be a statement about my script.

### 2.2 The states

| Input | Log | Meaning |
|---|---|---|
| Stages 1–3 only, then stop | `Stage 2`, `Stage 3` — **no** `OPEN SESAME` | nothing committed |
| Full sequence, 7 s gap (> `seq_timeout=5`) | stops at `Stage 3` | sequence expired |
| Full sequence, fast | `OPEN SESAME` → `running command: /usr/bin/launch` | command fired |

**Control that held: a partial knock leaves no partially-authenticated window.** 3-of-4 stages left the extra-listener count unchanged at `1` and never fired the command. Same conclusion as lab 118, reached with a different sequence length and a different daemon config — and it is the answer the reader cannot otherwise distinguish from untested.

### 2.3 What the command actually does — and why it fails

`OPEN SESAME` runs `/usr/bin/launch` as **root**, which starts a nested `dockerd`. Measured:

```
root  294  [dockerd] <defunct>
srw-rw---- 1 root docker 0 /var/run/docker.sock
```

The process is a **zombie** and the socket is a **stale leftover** — `docker ps` from root inside the container returns `Cannot connect to the Docker daemon`. Reproduced on a second knock: a second zombie (`1505 [dockerd] <defunct>`) and the same dead socket. So the port knock **opens no attack surface at all** in this container.

Root cause, captured literally rather than guessed:

```
failed to start daemon: Error initializing network controller: error obtaining controller
instance: failed to create NAT chain DOCKER: iptables failed: iptables -t nat -N DOCKER:
iptables v1.8.10 (nf_tables): Could not fetch rule set generation id: Permission denied
(you must be root)
 (exit status 4)
```

and the capability set that explains it:

```
Current: cap_chown,cap_dac_override,...,cap_net_bind_service,cap_net_raw,cap_sys_chroot,...  (no cap_net_admin)
```

**Positive control on the diagnosis:** the same binary with networking disabled (`dockerd --iptables=false --bridge=none`) gets past the failure — so `iptables`/`NET_ADMIN` is the blocker, not the binary. This is the identical missing capability that made `ufw` fail, which is why the two failures correlate.

> **Design note / deployment caveat.** The lab's own `auto_deploy.sh` runs the container `--privileged`, which *would* supply `NET_ADMIN` and make the nested `dockerd` start. This engagement ran unprivileged (no sudo available). So "the knock is a dead end" is a statement about **this deployment**, and the honest report says so rather than asserting it about the image. Per the container section's own rule — the Dockerfile is a claim, the runtime flags are the measurement.

---

## 3. Finding used — the chain (CWE-798 / CWE-269 / CWE-732)

### 3.1 Entry: unauthenticated RCE as `www-data` (CWE-434)

Upload of a benign `.php`:

```
$ curl -F "fileToUpload=@probe_ok.php" -F "submit=1" http://IP/hackademy/upload.php
El archivo probe_ok.php ha sido subido y alterado xxx_tuarchivo , localizalo y actua.

$ curl http://IP/hackademy/klp_probe_ok.php
PHOENIX_MARKER_apache2handler
```

**Negative control:** a `.txt` upload returned `Solo se permiten archivos JPG, JPEG, PNG y ......No se pudo subir el archivo.` The allowlist demonstrably discriminates, so the `.php` acceptance is the allowlist's decision and not a bypass of it.

**Identity of the reader, measured from inside:**

```
PHP_EXEC_ID: uid=33(www-data) gid=33(www-data) groups=33(www-data)
HOME: (unset)
READER can write /home/firsthacking? NO
READER can write /home/firsthacking/.ssh? NO
READER write result: FAILED
ls: cannot access '/home/ubuntu/.ssh': Permission denied
drwxr-x--- 1 firsthacking firsthacking 4096 Jul 13  2024 /home/firsthacking
drwxr-x--- 2 ubuntu       ubuntu       4096 May 30  2024 /home/ubuntu
```

**This is the finding the methodology was missing, stated as a measurement: the reading identity cannot write, and that is not a failed attack — it is the distance that constitutes the vulnerability.** `test -w` was run *as `www-data`*, and it said NO. Run as root the same predicate says YES, which is the lab-118 `test -w` trap in its exact form.

**Impact:** unauthenticated remote code execution as `www-data`. **Root cause:** an extension allowlist that lists `php` as permitted, with the content check commented out. **Remediation:** never key an upload filter on the client-supplied extension; store outside the document root or under a non-executing handler; re-enable a content check; set a restrictive umask so uploads are not `0777`.

### 3.2 The bridge: a sudo grant that names a program (CWE-269 / CWE-250)

```
$ sudo -n -l   (as www-data)
User www-data may run the following commands:
    (firsthacking) NOPASSWD: /usr/bin/nano
```

Controls around it:

| Attempt | Result |
|---|---|
| `sudo -n -u firsthacking /usr/bin/nano --version` | `GNU nano, version 7.2` — **granted** |
| `sudo -n -u firsthacking /usr/bin/id` | `sudo: a password is required` — denied |
| `sudo -n -u root /usr/bin/nano --version` | `sudo: a password is required` — denied |

Two negative controls matter here specifically: the rule is **scoped to one target user**, and it is **scoped to one program**. So the escalation surface is exactly "run this editor as `firsthacking`", and nothing wider. Reporting "www-data can sudo to root" would have been false.

`nano ^T Execute` then runs a command **as `firsthacking`**. Verified, with the command writing its own identity to a file:

```
$ id > /tmp/stage/marker.txt     # executed via sudo -u firsthacking nano, ^T
$ cat /tmp/stage/marker.txt
uid=1001(firsthacking) gid=1001(firsthacking) groups=1001(firsthacking),100(users)
```

**Impact:** `www-data` obtains code execution as `firsthacking`. **Root cause:** a `NOPASSWD` rule granting a general-purpose interactive editor (with a built-in command-execution feature) to a daemon account, scoped to a target user. **Remediation:** remove the grant; if an editor is genuinely needed, grant a purpose-built non-interactive tool; never grant an editor *plus* a target account, because the editor is an interpreter for `^T`/`!`/`system()` and the grant is therefore code execution under a different name.

### 3.3 SSH key injection (CWE-798)

Executed **as the writing identity**, self-recording:

```
$ (as firsthacking via ^T)
$ id
uid=1001(firsthacking) gid=1001(firsthacking) groups=1001(firsthacking),100(users)
$ ls -ld /home/firsthacking/.ssh /home/firsthacking/.ssh/authorized_keys
drwx------ 2 firsthacking firsthacking 4096 /home/firsthacking/.ssh
-rw-rw-r-- 1 firsthacking firsthacking  101 /home/firsthacking/.ssh/authorized_keys
```

```
$ ssh -i lab_key firsthacking@IP 'id; whoami; hostname; pwd; uname -a'
uid=1001(firsthacking) gid=1001(firsthacking) groups=1001(firsthacking),100(users)
firsthacking
783251e2748c
/home/firsthacking
Linux 783251e2748c 7.0.0-34-generic #34-Ubuntu SMP PREEMPT_DYNAMIC ... x86_64 GNU/Linux
```

Negative controls, both correct:

| Attempt | Result |
|---|---|
| injected key, user `ubuntu` | `Permission denied (publickey,password)` |
| never-injected key, user `firsthacking` | `Permission denied (publickey,password)` |

So the login is attributable to **the specific injected key in the specific account**, not to a permissive sshd.

**Impact:** durable authenticated access as `firsthacking` that survives every process restart, created without ever touching that account's credentials. **Root cause:** a web-service identity holding a sudo grant scoped to another user's account. **Remediation:** remove the `www-data → nano` rule (§3.2); the injection is a *consequence*, not an independent bug. Fixing the uploader alone leaves the injection path intact for any other `www-data` primitive.

### 3.4 The permission-bit boundary — measured, and it contradicts the folklore

`0600` is what OpenSSH's documentation recommends. **Measured on this target, the actual boundary is world-writability, not `0600`:**

| mode as the writing identity sees it | login |
|---|---|
| `664 firsthacking:firsthacking` | **OK** |
| `666 firsthacking:firsthacking` | **DENIED** |
| `604 firsthacking:firsthacking` | **OK** |
| `644 firsthacking:firsthacking` | **OK** |
| `620 firsthacking:firsthacking` | **OK** |
| `600 firsthacking:firsthacking` | **OK** |

Every row is a real `ssh` attempt after a `chmod` **performed as `firsthacking` inside the container**, and the mode in the left column is **read back as that same identity** (`docker exec -u firsthacking … stat -c '%a %U:%G'`) — not parsed from bits and not observed as root.

The mechanism is OpenSSH's `StrictModes`: what matters is that the file is **not writable by group or other**, and is owned by the user or root. `0664` passes because the group is the user's own primary group, not a privilege boundary. So:

- **`0644` does *not* fail on this target** — the lab-118 anecdote ("`0644` breaks with a silent error") is a property of that configuration, not a universal law. Reporting the folklore as a finding here would have been wrong.
- **`0666` fails, and the error says nothing about permissions:** `Permission denied (publickey,password)`. It reads exactly like a wrong key. A tester who trusts the folklore checks the key; the actual cause is one `chmod` away and invisible in the message.
- **The operational consequence is the same either way:** always write `0600`/`0700`. The measurement is for the *report* (don't state a false universal), not for the *exploit* (always be strict).

### 3.5 What the injection did **not** buy: escalation is a dead end here

`firsthacking` carries `(ALL) NOPASSWD: /usr/bin/docker`, which is root-equivalent **on a host with a live daemon**:

```
User firsthacking may run the following commands:
    (ALL) NOPASSWD: /usr/bin/docker

$ sudo -n /usr/bin/docker run --rm -v /:/host alpine chroot /host /bin/bash -c id
docker: Cannot connect to the Docker daemon at unix:///var/run/docker.sock. ...
```

`sudo /usr/bin/dockerd` is **not** covered: `sudo: a password is required`. The rule names `/usr/bin/docker` only, so the tester cannot start the very daemon the grant depends on. Enumerated for other rungs, all denied: `/usr/bin/nsenter`, `/usr/bin/cp`, `/usr/bin/tee`, `/usr/bin/mount`, `/bin/bash`, `/usr/bin/env`, `/usr/bin/find`.

The remaining identity hops are closed by design, each verified **as the identity**:

| From | Attempt | Result |
|---|---|---|
| `firsthacking` | `touch /home/ubuntu/.probe` | `Permission denied` |
| `www-data` | `sudo -n -u ubuntu /usr/bin/nano --version` | `sudo: a password is required` |
| `www-data` | write `/home/firsthacking/.probe_write` | `Permission denied` |

And `ubuntu` — the one account in the `sudo` group — has no `.ssh` directory and its home is `0750 ubuntu:ubuntu`, unreachable from both lower identities.

**So the honest terminal verdict: the chain reaches `firsthacking` and stops.** Root is *configured to be* one sudo rule away and is unreachable only because the docker daemon cannot start in this container (§2.3). I did not obtain root, and I am not going to call `firsthacking` root.

---

## 4. Controls that held — reported with the same prominence as the bugs

1. **The sudo grant is properly scoped.** One program, one target user. Two negative controls (a different program, a different user) both denied. A broad `NOPASSWD: ALL` would have made the whole chain trivial; this one required reading the program.
2. **A partial port knock leaves no partially-authenticated window.** 3-of-4 stages never fired the command and changed no listener.
3. **The sequence has a timeout that works.** A 7 s gap between stages aborted the sequence — `seq_timeout=5` is enforced, so a knock cannot be dripped slowly.
4. **OpenSSH's `StrictModes` rejected a world-writable `authorized_keys`**, even though it accepted `0644` and `0664`. The control fired on exactly the condition that matters, and **fired silently** — the strongest argument in this lab for writing the mode correctly rather than for the folklore.
5. **Account isolation held in both directions.** `www-data` could not write `firsthacking`'s home; `firsthacking` could not write `ubuntu`'s. No cross-account write path existed without the sudo bridge.
6. **`ubuntu` was not reachable** by either obtained identity despite holding full `sudo` — the target's most privileged account was never a stepping stone.

---

## 5. Reward: not present — reported as an absence

```
$ find / -xdev -iname "*flag*" -o -iname "*reward*" -o -iname "*secret*" | grep -vE '^/proc|^/sys|/usr/lib/python|/usr/share'
/usr/lib/x86_64-linux-gnu/perl/5.38.2/bits/waitflags.ph
/usr/lib/x86_64-linux-gnu/perl/5.38.2/bits/ss_flags.ph
```

Only Perl module filenames matching `*flags*`. `/root/` is `0700` and unreadable from either obtained identity, so a root-only reward cannot be excluded by inspection — but **no reward was reachable without root, and root was not obtained.** No `FLAG{}` exists in any form I could reach. This is the fourteenth consecutive lab without a reward; reporting the absence with the evidence above is the correct outcome, not inventing a value.

---

## 6. The chain, proven literally

| # | Action | Identity that performed it | Evidence |
|---|---|---|---|
| 1 | Upload `.php` | unauthenticated | `El archivo ... ha sido subido` |
| 2 | Execute it | `uid=33(www-data)` | `PHP_EXEC_ID: uid=33(www-data)` |
| 3 | Read other homes | `www-data` | `READER write result: FAILED` |
| 4 | `sudo -u firsthacking nano` | `www-data` → `firsthacking` | `GNU nano, version 7.2` |
| 5 | `^T Execute` → `id` | `firsthacking` | `uid=1001(firsthacking)` |
| 6 | Create `.ssh` + `authorized_keys` | `firsthacking` | `-rw-rw-r-- 1 firsthacking firsthacking` |
| 7 | Measure boundary as writer | `firsthacking` | table in §3.4 |
| 8 | `ssh` with injected key | `firsthacking` | `uid=1001(firsthacking) ... /home/firsthacking` |
| 9 | `sudo docker` (root-equivalent) | `firsthacking` | `(ALL) NOPASSWD: /usr/bin/docker` |
| 10 | **STOPPED** — daemon dead | — | `Cannot connect to the Docker daemon` |

---

## 7. Self-correction — defects in my own instrumentation

This section is the most important one in the writeup. **Four separate defects, each of which produced clean, believable, wrong output.** All four would have become false claims in the report.

### 7.1 The positive control that never had a working save path

`script(1)` + `nano` to write as `firsthacking`. It ran for several rounds and every attempt "failed" to create the file. Three stacked causes:

| # | Cause | Symptom | Why it is dangerous |
|---|---|---|---|
| 1 | `docker exec` without `-t` | `Standard input is not a terminal` | nano aborts before reading anything |
| 2 | `TERM` unset inside the container | `Error opening terminal: unknown` | **aborts before any keystroke matters** — looks like "the target refused" |
| 3 | `-t` tty in canonical mode + `IXON` | `^T` arrives as the text `"^T"`; `^X` (0x18) eaten as XON | keystrokes silently discarded |

Then, after all that was fixed, the *decisive* bug:

> **`docker exec -t` without `-i` does not attach stdin.** The tty exists, nano paints its banner, and **not one byte I wrote ever reached it.** My screen showed a static banner and no redraw, which is exactly what a target that ignores your input looks like.

And the last one, which is a genuine methodological lesson:

> **Raw mode disables `ICRNL`, so `\n` is not Enter — `\r` is.** I was submitting an **empty** command. Nano returned to the main buffer, the prompt closed cleanly, and the target command never ran. The output was indistinguishable from "the execute feature is disabled".

**Detected only because I insisted the instrument prove it could report a success** (`id` writing its own uid to a file, read back). Until that printed `uid=1001(firsthacking)`, every negative from this harness was worthless. *A control that has never seen a success is not a control* — and here the failure mode was compounded: the instrument was simultaneously the thing I was testing and the thing producing my evidence.

### 7.2 The five-mode permission table that measured nothing

My first permission-boundary run printed **five "LOGIN OK" rows and one "DENIED"** — a clean, publishable-looking result. It was **entirely fabricated by my own script**: the `chmod` ran **on the host**, where the container path does not exist. Every one of those rows re-tested the *same unmodified `0664` file*. The `chmod: cannot access ... No such file or directory` error was printed inline and scrolled past.

Had I not read the modes back from inside the container, the writeup would have claimed a permission boundary that my measurements never touched. The fix was to (a) perform the `chmod` **as the writing identity inside the container** and (b) **read the mode back as that identity** before each login attempt. A truncated sweep and a complete one print identically; so does a sweep that never mutated anything.

### 7.3 Two service-status lines I nearly reported as facts

- `service knockd status` → usage text. I nearly wrote "port knocking is not installed". The process table showed `knockd -d -i eth0` running. **Instrument artifact ≠ absence.**
- `service ufw start` → `...fail!`. This one *was* real (missing `NET_ADMIN`), and I confirmed the mechanism rather than trusting either message.

The general rule I took from this: **`ps` and `/proc` are the measurement; init-script output is a claim.**

### 7.4 The knock "did nothing" that actually fired twice

My first conclusion was "the knock opens no port, so port knocking is decorative here." The `knockd` log already contradicted me — `OPEN SESAME` and `running command: /usr/bin/launch` — from a **2024 build log inside the image**. Re-running the sequence reproduced `OPEN SESAME` twice. The command fires reliably; what fails is the daemon it starts, and only the process table plus the literal `iptables` error separated those two facts. "No new port" was true and completely misleading on its own.

---

## 8. Tested / not tested / discarded with reason

**Tested and verified**
- Full port scan, service versions.
- Knock state machine: positive, negative, partial, and timeout-expired.
- Upload allowlist with a matched negative control; RCE identity measured.
- `www-data` writability of every other home, **as `www-data`**.
- sudo grant: positive control + two scoped negative controls.
- `^T Execute` identity, with a self-verifying positive control.
- `authorized_keys` created, injected, and used for a real login.
- Two negative controls on the SSH login (wrong user; never-injected key).
- Permission-bit boundary, six modes, chmod'ed and read back **as the writing identity**.
- `docker` escalation: attempted, and the failure traced to a literal `iptables` error.
- Every remaining account hop, each attempted **as the identity**.

**Not tested (and why)**
- `docker.sock` mounted into the container — there is none; the nested socket is a stale inode from a dead daemon.
- Kernel/namespace escape — the container lacks `NET_ADMIN` and the Docker socket, so no escape primitive was reachable; per the container section, the boundary check *is* the deliverable.
- Any interaction with `/root/` — unreadable (`0700`) from both obtained identities.
- The knock's behaviour under `--privileged` — **requires sudo, unavailable in this session.** Reported as a deployment caveat, not as a finding.

**Discarded with reason**
- **LFI / log poisoning** — no `include`, no `require`, no `auto_prepend_file`, no writable-log include. Confirmed absent by search, not assumed from the description.
- **MIME-map case-sensitivity trick** (lab 118) — unnecessary here: the allowlist permits `php` outright, so there is no case trick to find. Would have been noise.
- **`ubuntu` as an escalation target** — unreachable from both identities (home `0750`, no sudo rule, no `.ssh`).
- **Other sudoables** — enumerated and denied (§3.5).

---

## 9. Design observation

**The lab is a two-identity machine, and that is its real pedagogy.** Almost everything interesting is arranged around the gap between `www-data` (reads, cannot write) and `firsthacking` (owns the home). The description advertises three techniques; the substance is **one measurement** — the distance between the identity that reaches the code and the identity allowed to write — and the sudo grant is the only thing that crosses it. A tester who uploads a shell and then tries to write a key will hit `Permission denied` and conclude the lab is broken. The lab only makes sense if you notice that the RCE identity is not the writing identity, and go looking for the bridge.

**The description's third element ("inyección de claves SSH para escalar privilegios") is the interesting one, because the escalation it advertises is the part that does not work.** The injection succeeds cleanly; the escalation it promises dies on a missing `NET_ADMIN`, and the `docker` grant that would have been root is unreachable because its own daemon cannot start. The lab thus teaches something the description gets backwards: **writing another account's `authorized_keys` changes your identity — it does not, by itself, cross a privilege boundary.** The escalation is a separate, independently-configured sudo rule. Conflating the two is exactly the mistake the report must avoid.

**And the most transferable artifact is a control that fired silently.** OpenSSH refused a world-writable `authorized_keys` with `Permission denied (publickey,password)` — an error that mentions neither permissions nor the file. Anyone debugging that will check their key. That is the strongest possible argument for the boring practice of writing `0600`, and it is a better lesson than the folklore that `0644` fails, which this target disproved.
