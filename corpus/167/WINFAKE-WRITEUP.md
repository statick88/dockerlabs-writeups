# 167 WinFake — DockerLabs writeup

**Target:** `http://172.17.0.5:80` (container `winfake_container`, image `winfake:latest`, digest `sha256:b00e81015992dd7130ec4ea80388fcd9ee4dbd07adac803b9b9abd0a8e27a692`)
**Catalogue text (verbatim, from `tooling/download-labs.sh list`):** `Laboratorio sencillo donde debemos inspeccionar el código fuente para obtener información de cómo realizar la intrusión.`
**Date:** 2026-09-30
**Outcome:** User-level reward recovered as `uid=1000` from inside the restricted shell. The `uid=0` leg was **proved as a working escalation on a clone of the same image, and not executed against the target** — root's password resisted 560,608 distinct offline candidates. That non-result is reported below with its counts rather than papered over.

---

## 1. Was the manifest's label right? Yes — and it is worth saying so

`tooling/labs.manifest:75` reads `167|WinFake|facil|source-code inspection as the entry point; the only lab where reading the code IS the first step`.

Labs 32 and 220 are queued as "WordPress platform" and are Joomla 4.0.3 and a six-file PHP app respectively. Rule 1 says the platform label is a filename, not a fingerprint. **This one survives the check.** The version-bearing file is the dpkg status database:

```
apache2=2.4.58-1ubuntu8.6
openssh-server=1:9.6p1-3ubuntu13.12
python3=3.12.3-0ubuntu2
```

`/etc/os-release` → `NAME="Ubuntu"`, `VERSION="24.04.2 LTS (Noble Numbat)"`. The image's own labels are `org.opencontainers.image.ref.name=ubuntu`, `version=24.04`.

So the artefact is what the catalogue says it is: a static single-page site plus a deliberately hostile login shell, with **no web application vulnerability of any kind**. Source inspection is not a shortcut here, it is the only entry. This is the first lab in the queue whose label I checked and did not have to overturn.

## 2. Surface

```
$ nmap -sV -Pn -p- 172.17.0.5
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.12 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.58 ((Ubuntu))
```

Per §23, before recording any absent surface I established the processes meant to serve them were **running**, rather than inferring it from the scan:

```
$ docker exec winfake_container ps aux
root  15 ... /usr/sbin/sshd: /usr/sbin/sshd [listener] 0 of 10-100 startups
root  33 ... /usr/sbin/apache2 -k start
www-data 37 ... /usr/sbin/apache2 -k start
www-data 38 ... /usr/sbin/apache2 -k start

$ cat /proc/net/tcp     → 2 rows: 00000000:0016 (22) and 00000000:0050 (80), uid 0, state 0A
$ cat /proc/net/udp     → 0 rows
```

Both services up, both bound on all interfaces, **no UDP surface** (0 rows, a counted zero rather than an assumed one). The docroot contains exactly one file and no dotfiles:

```
$ ls -la /var/www/html/
-rw-r--r-- 1 root root 5678 Jul 10  2025 index.html
```

A package-set diff against a vanilla `ubuntu:24.04` showed the delta is Apache2, OpenSSH, sudo, nano, wget and `python3-jwt` — **no hidden service**. (`python3-jwt` is installed and nothing on disk imports it; noted, not acted on.)

**The target still serves what the source said.** The live body and the artefact are the same bytes:

```
$ curl -s http://172.17.0.5/ | md5sum
e65e9d427accef3a700760c064fc9470
$ docker cp winfake_container:/var/www/html/index.html - | md5sum
e65e9d427accef3a700760c064fc9470     (5678 bytes both sides)
```

## 3. What reading the source gave me, before a single request

This is the section the lab exists for. Four artefacts in the image, all read offline with `docker run --rm --entrypoint sh` before touching the network.

**(a) The username — `index.html:14`.** Inside the CSS `body` rule, a declaration that is not valid CSS at all:

```css
        body {
            font-family: "Segoe UI", Arial, sans-serif;
            background: #f4f4f9;
            margin: 0;
            padding: 0;
            color: #333;
		    top: pipe;
        }
```

`top: pipe` names the account. Confirmed in `/etc/passwd`:

```
pipe:x:1000:1000:pipe,,,:/home/pipe:/usr/local/bin/windows.py
```

**(b) The acrostic — `index.html:63`.**

```html
	    <article hidden="acrostico inicial">
		    <h2>HIDDEN</h2>
	    </article>
```

Computed, not eyeballed: 22 `<h2>` elements; the hidden one contributes `H`, the 21 visible ones give

```
WINSERVERROOTFAKENEWS
```

Robust across every variant the markup supports — initials of titles (22 and 21), first-word initials (identical), last letters (`Nssa?sdsds5aannlsds5as`, junk), paragraph initials (`LLELBDLELEOELLLLLLLRE`, junk). The title acrostic is the intended one.

**(c) The sink — `/usr/local/bin/windows.py:215-220`.** `pipe`'s login shell is a fake PowerShell. Its command filter, line 35:

```python
BLOCKED_LINUX_CMDS = ["ls", "pwd", "cat", "rm", "touch", "chmod", "clear", "nano", "vim", "gcc", "python", "bash", "sh", "sudo", "zsh", "apt", "vi", "python3"]
```

and then, verbatim:

```python
            # Ejecutar su root real
            if cmd == "su" and args == ["root"]:
                try:
                    subprocess.run(["su", "root"])
```

**`su` is absent from an 18-entry blocklist.** The author special-cased the one command that escapes, and forgot to blacklist it. The filter is a first-token string match (`cmd_parts[0].lower()`), so `su root` reaches the real `su` by design.

**(d) A decoy copy of the shell.** There are **two different `windows.py`** in the image:

| File | Size | `su root` sink | `import subprocess` | Blocklist |
|---|---|---|---|---|
| `/usr/local/bin/windows.py` | 10284 B | **yes** (215-220) | yes | 18 entries, no `su` |
| `/root/windows.py` | 7654 B | **no** | **no** | 15 entries, **has** `whoami` |

Only the first is reachable — it is what `/etc/passwd` names as `pipe`'s shell. Reading the wrong copy produces a clean, confident, completely wrong conclusion: "the shell has no escape and `whoami` is blocked". I hit this myself: my first `diff` of the two copies is what revealed it.

### What reading the source saved, concretely

- **Username enumeration: not needed.** The account is `pipe`. Without the CSS hint this is a username-enumeration problem against a yescrypt-protected SSH service.
- **Payload guessing: not needed.** The escalation is the literal string `su root`, sitting in the source, permitted by the source's own blocklist. A black-box approach would have had to work through the 18-entry filter — trying encodings, `/bin//su`, aliases, absolute paths — and would plausibly have concluded the shell was hermetic and moved on. The bypass that took real work here was a *different* one (§4, finding 1).
- **No web testing at all.** There is no web application. `index.html` is static; nothing in it processes input.
- **No CVE work, no fingerprinting needed.**

### What reading the source did **not** save — the honest ledger

- **It did not give the password.** `pipe`'s password is `kisses`. That is a plain dictionary word, not present in the artefact's vocabulary; it fell out of an offline wordlist run. Every attempt to derive it from `WINSERVERROOTFAKENEWS` failed — 763 acrostic substrings, then 14,530 candidates drawn from the artefact's own 798-word vocabulary with case and digit decorations. **The acrostic is not a credential.**
- **It did not give root's password**, and I never found it. See §7.

This is the one place where the catalogue's framing needs a qualifier: the source gives you *how* to intrude (the account, the shell, the sink) but **not** the credential. The credential was a dictionary word. A solver who trusted the acrostic as a password and, on failure, concluded the lab was broken would be wrong in the same way as the author of lab 117's `defined('AUTH_KEY')` finding — treating a decodable string as a consumed one.

## 4. Findings

### Finding 1 — The shell's content filter is an exact string comparison and is trivially bypassed

**CWE-20 Improper Input Validation** (path normalisation), with CWE-22-adjacent reach. Severity: low on its own; it matters because this filter is the lab's only stated attempt to stop the operator from reading the shell that contains the escalation sink.

`/usr/local/bin/windows.py:59-62`:

```python
    # Bloquear la lectura específica de /usr/local/bin/windows.py
    if args[0] == "/usr/local/bin/windows.py":
        print(f"{RED}Acceso denegado al archivo especificado: {args[0]}{RED}")
        return
```

The guard compares the **raw argument string**. The consumer, two lines later, is `os.path.isfile(path)` / `open(path)` — which normalises the path. Three states, measured live:

| Input | Result |
|---|---|
| `type /usr/local/bin/windows.py` | `Acceso denegado al archivo especificado: /usr/local/bin/windows.py` |
| `type //usr/local/bin/windows.py` | **full file dumped**, from `#!/usr/bin/env python3` onward |
| `type /usr/./local/bin/windows.py` | **full file dumped** |

The positive control is the first row: the same verb, the same session, the same file, denied — so the difference is the path spelling and nothing else.

**Root cause:** a denylist of literal strings where the consumer accepts any path that resolves to the same inode. **Fix:** resolve the path (`os.path.realpath`) and compare the resolved value, or simply drop the special case — a shell that runs as `pipe` can read every file `pipe` can read, and pretending otherwise is what created the bypass.

### Finding 2 — The blocklist's refusal is byte-identical to "command not implemented"

**CWE-209 Generation of Error Message Containing Sensitive Information** is not the right fit; this is a **diagnosability / control-attribution defect**. Severity: informational for the target, high for the tester.

Two different code paths emit the same string:

- line 224, for a **blocked** command: `El término '{cmd}' no se reconoce como el nombre de un cmdlet, función, archivo de script o programa ejecutable.`
- line 266, the **`else` fallback** for anything unhandled: the same sentence, character for character.

Measured in one session:

```
$== ls          → El término 'ls' no se reconnue ...      (blocked: 'ls' IS in line 35)
$== id          → El término 'id' no se reconnue ...      (not blocked: 'id' is NOT in line 35)
```

`ls` and `id` are on **opposite sides** of the filter and produce indistinguishable output. Any attempt to prove "the blocklist held" using the response alone is therefore impossible: a filter that was never applied and a filter that was applied look identical. §16's shape, planted inside the lab rather than inside my tooling.

This is also why I could not use the filter as a control anywhere in this engagement, and why "18 commands blocked" is not a measurable property of the target.

### Finding 3 — The only identity verb in the shell fabricates its answer

**CWE-451 User Interface (UI) Misrepresentation of Critical Information.** Severity: informational (no security impact) but it is the sharpest thing in the lab.

```
$== whoami
DESKTOP-KVHRNUK\pipe
```

`fake_whoami()` at `windows.py:172-195` prints `f"{FAKE_HOSTNAME}\\{FAKE_USER}"`, where `FAKE_HOSTNAME` is regenerated at random on every process start (`windows.py:19`) and `FAKE_USER` is the literal `"pipe"` (`windows.py:20`). It reports a Windows identity, a random one, and never the real one.

Meanwhile `whoami` **is** in the decoy copy's blocklist and is **not** in the live copy's — so the live shell both removes the real identity command and replaces it with a confident lie. The only trustworthy identity read inside that shell is `/proc/self/status`, which is what I used:

```
Name:	python3
Uid:	1000	1000	1000	1000
Gid:	1000	1000	1000	1000
Groups:	100 1000
```

This is §21 in costume: **ask what the component actually consumes, not what the name promises.** A tester who believed `whoami` here would have reported `pid 1` / `root` for a container whose shell runs as uid 1000.

### Finding 4 — The decoy copy of the shell (`/root/windows.py`)

Not a vulnerability. A **lab-design defect** worth recording because it is a trap aimed at exactly the methodology this corpus uses. Two copies of the same filename, different contents, one reachable. Reading the decoy yields a false negative on the sink and a false positive on the blocklist (`whoami` "blocked"). Reported as the lab's problem, not the tester's — the same category as lab 112's unrunnable chain.

## 5. Chain

| # | → | Mechanism | Identity proof (verbatim) |
|---|---|---|---|
| 0 | unauthenticated | HTTP 200, 5678 B static page; SSH banner | `Apache/2.4.58 (Ubuntu)`, `OpenSSH 9.6p1 Ubuntu 3ubuntu13.12` |
| 1 | **`pipe` / uid 1000** | SSH password auth, credential from a 99,583-entry offline wordlist (`pipe:kisses`) | `Uid:	1000	1000	1000	1000` / `Groups:	100 1000` read from `/proc/self/status` **inside** the restricted shell |
| 2 | **uid=1000, unprivileged read** | `type /home/pipe/user.txt` — `user.txt` is mode 644 despite being root-owned in a `pipe`-owned home | `d970977b69a543ce746095e2b660d107` (same uid, no transition) |
| 3 | **`uid=0` — sink reached, NOT completed on target** | `su root` special-cased at `windows.py:215`; real `su` prompts for a password not recovered | on the target: `Password:` prompt, then no further hop available |
| 3′ | **`uid=0` — proved on a clone of the same image** | identical chain, root's password supplied | `Uid:	0	0	0	0`, `Groups:	0`, and `uid=0(root) gid=0(root) groups=0(root)` |

**No setuid transition occurs anywhere in this chain.** Every `Uid:` field — real, effective, saved and filesystem — is the same value at each hop (`1000 1000 1000 1000` before, `0 0 0 0` after). There is no `euid` to report separately because nothing sets one.

### Proof that hop 3′ is the same code path, not a neighbouring one

§22 requires the control to exercise the target's code path. The positive control for the sink was run on a **clone** (`winfake_ctl`, same image digest `sha256:b00e810…`), never on the target:

1. Set a known password for `pipe` and for `root` on the clone only.
2. Ran the *unmodified* attacker script against the clone.
3. Observed the full chain end to end, identity measured at both ends.

Two independent facts establish the `Password:` prompt is a real `su` and not part of the fake shell:

- `grep -ci password /usr/local/bin/windows.py` → **0**. The string does not occur in the shell at all, so it cannot have produced the prompt.
- The prompt's children are a different process: before the sink `/proc/self/status` reports `Name: python3` (the shell itself); after it, the session is `root@7530593512e9:/home/pipe#`.

## 6. Controls that held — and the positive control for each

| Control | Positive control that proves the detector works | Result |
|---|---|---|
| `/etc/shadow` is unreadable by `pipe` | `type /etc/issue.net` in the same session **succeeded** — so the `type` verb works and the refusal is about permissions, not a broken command | **held**: `Error al leer el archivo: [Errno 13] Permission denied: '/etc/shadow'` |
| `su root` from `pipe` is gated by root's password | stock `/etc/pam.d/su` (`auth sufficient pam_rootok.so`, no `pam_wheel.so trust`, no `pam_permit`); and the same `su root` on the clone **did** succeed once the password was supplied | **held** — the gate is real, and it is the only thing blocking the last hop |
| root cannot log in over SSH with a password | `sshd -T` → `permitrootlogin without-password`; **positive control**: password authentication is genuinely enabled (`passwordauthentication yes`) and `pipe:kisses` authenticates over it in the same session — so root's rejection is about root, not about password auth being off | **held** |
| SSH key auth is offered but there are no keys to offer | `/home/pipe/.ssh` absent; `/root/.ssh` exists but is **empty** (0 files) — a counted zero, not an assumed one | held (nothing to find) |
| `whoami` inside the shell | — | **did not hold** — fabricated identity (Finding 3) |
| The `type` denylist | see Finding 1 | **did not hold** — bypassed twice |
| The 18-entry command blocklist | — | **unmeasurable** — identical output on both sides (Finding 2) |

## 7. Every negative, with its work count

Per rule 6: a count of zero means UNTESTED and belongs in §8.

| Negative | Work count | Instrument |
|---|---|---|
| `pipe`'s password is not derivable from the acrostic | 763 candidates (all contiguous substrings of `winserverrootfakenews` and `hwinserverrootfakenews`, ×3 case forms) | offline yescrypt |
| `pipe`/`root` password is not in the artefact's vocabulary | 14,530 candidates over a 798-word vocabulary drawn from `index.html` + both `windows.py` copies, with case and 10 digit/suffix decorations | offline yescrypt |
| live SSH spray | 8 users × 47 passwords = **376 attempts**, 1127.6 s, all `AuthenticationException` | paramiko |
| **root's password not recovered** | **560,608 distinct candidates** verified offline against the yescrypt hash | offline yescrypt |
| no literal `FLAG{}` anywhere in the image | **11,993 files** scanned, **0** matches | `grep -rIl "FLAG{"` |
| no UDP surface | `/proc/net/udp` → **0 rows** | kernel |
| no second service | `/proc/net/tcp` → **2 rows**; package delta vs vanilla `ubuntu:24.04` → Apache2/OpenSSH/sudo/nano/wget/`python3-jwt` only | dpkg |

**Arithmetic, computed rather than read.** The 560,608 is the **distinct union** of five candidate sets, not their sum. Per-set distinct counts, each reproduced and asserted equal to the count its own script printed (14,530 / 99,583 / 421,445 / 131,887):

```
naive sum                     = 14,530 + 99,583 + 421,445 + 131,887 = 667,445
overlap removed               = 106,837
DISTINCT UNION actually tested = 560,608
```

The wordlists are local (`PenTestMethodology/wordlists/`); no third-party service was contacted and nothing was downloaded.

**The oracle was proven green before any of those negatives was believed.** A clone container's `pipe` hash was checked with a password I set myself:

```
oracle green (known-good verifies=True, known-bad verifies=False)
```

and the same gate ran at the top of every subsequent search, aborting the run if it failed. The SSH detector was green the same way: `pipe:CtlPass-9182` **authenticated** and `pipe:win` was rejected, by the identical client code.

**The `FLAG{}` zero has its own positive control** (§12 — a tool that finds nothing has made a claim about the world, not about itself):

```
acrostico              files_matched=1
BLOCKED_LINUX_CMDS     files_matched=2
Microsoft Windows      files_matched=9
TechWorld              files_matched=1
```

The same `grep`, the same tree, four strings known to be present. So zero matches for `FLAG{` is a measured zero.

## 8. NOT tested (vs discarded with a reason)

**NOT tested:**

- Root's password beyond 560,608 candidates. No rockyou-equivalent list exists on this host; I did not download one, and I did not attempt to derive it from anything other than the artefact and three local lists. Root's hash is `$y$j9T$` — yescrypt at `N=9`, which is weak enough to be practical with a real cracking rig and a full list. **This is the one open leg.**
- Whether `root.txt`'s value changes at runtime (it is baked into the image; §9).
- Whether the `python3-jwt` package is a hint to something unbuilt. Nothing imports it; I did not go looking for a JWT surface that no listener serves.
- SFTP/SCP as `pipe` — `subsystem sftp` is configured and `pipe` authenticates, so an SFTP channel is available. Not exercised.

**Discarded with a reason:**

- **Escalation as `pipe` by any route other than `su root`.** Not an assumption — the shell has exactly four verbs with side effects: `type` (read), `del` (unlink), `mkdir`/`rmdir` (**directories only**, `os.mkdir` at line 108). There is no verb that creates a file, so no crontab, no `authorized_keys`, no PAM write, no module drop. `/etc/pam.d/su` grants nothing to group `users`. `sudo` is on the blocklist *and* `pipe` is in no privileged group (`pipe:x:1000:1000:pipe,,,` — empty supplementary group list).
- **Root SSH by password.** `sshd -T` says `permitrootlogin without-password`, and the positive control above shows that is a root-specific policy rather than password auth being disabled.
- **HTTP attack surface.** One static 5678-byte file, no dotfiles, no parameters, nothing that reflects input. There is nothing to test.

## 9. Reward

**No literal `FLAG{}`.** The search and its count are in §7: 11,993 files, 0 matches, with a green positive control on the same tool.

Two functional rewards, both bare 32-character hex strings, as `user.txt` and `root.txt`:

| File | Value | How obtained |
|---|---|---|
| `/home/pipe/user.txt` | `d970977b69a543ce746095e2b660d107` | **recovered on the target**, as `uid=1000`, inside the restricted shell: `type /home/pipe/user.txt` |
| `/root/root.txt` | `fa209fcfb40c4276bd2ceb9f08bf5f7b` | **established as an image property, not obtained by escalating on the target** |

On the second row I want to be exact about the distinction, because it is the difference between a result and a claim:

- I **did not** reach `uid=0` on the target. `su root` prompted and I had no password.
- I **did** prove the sink works, on a clone of the same image, reaching `Uid: 0 0 0 0` and reading `/root/root.txt` there.
- The value above is therefore justified by image identity, not by the target: all three containers (`winfake_container`, `winfake_ctl`, `winfake_fresh`) run digest `sha256:b00e810…` and all three carry byte-identical reward files:

```
winfake_container    root.txt=0fa706de3333cf3c7145aa3b6a36b993 user.txt=38dff55252f79fe424e6dee1c194ed97
winfake_ctl          root.txt=0fa706de3333cf3c7145aa3b6a36b993 user.txt=38dff55252f79fe424e6dee1c194ed97
winfake_fresh        root.txt=0fa706de3333cf3c7145aa3b6a36b993 user.txt=38dff55252f79fe424e6dee1c194ed97
```

I altered only `/etc/shadow` on the clone (two passwords), never a reward file. A reader who wants to check this should re-fetch the archive; this corpus is a transcript, not a reproduction.

## 10. Instrumentation defects — mine, and what caught them

Six. Every one of them produced well-formed output.

1. **My own host wrapper executed inside the container.** I ran `docker exec … sh -c 'rtk ls -la /home/pipe; …'`. `rtk` is my host-side tool wrapper; inside the container it does not exist, so three enumerations — `/home/pipe`, `/root/`, `/etc/sudoers.d/` — printed `sh: rtk: not found` and **returned nothing**. A clean, empty listing of a directory I had not actually looked at. §11/§14 exactly: a command that fails while doing nothing, whose output looks like an absence. Caught by noticing the empty result had no accompanying error on the line where success should have been. Re-run with `ls`: `/home/pipe` has 8 entries and `/root` has 8.

2. **A format string eaten by the wrong shell.** `dpkg-query -W -f="\${Package}=\${Version}\n"` inside single quotes was right; inside double quotes the **host** shell expanded `${Package}` to empty and the command printed three bare `=`. Three empty results, exit 0, and it read as "the query returned three rows". §17. Fixed by quoting for the shell that actually reads it.

3. **A library silently falling back to the wrong algorithm.** The container's Python `crypt.crypt('test', '$y$j9T$abcdefghijklmnopqrs')` returned a hash that did **not** start with `$y$`, and I initially read that as "this host cannot do yescrypt". It can: my fabricated salt was invalid and libxcrypt fell back to a legacy format. Passing the *real* hash string from `/etc/shadow` produced `$y$j9T$pvvGn…` immediately, and `crypt.crypt('test', h) == h` held. I also went via `passlib.hash.yescrypt`, which does not exist as an importable name. §12 in reverse: the tool reported an empty answer and I nearly believed it.

4. **My own wrapper truncating a count — which would have become a wrong work count.** `rtk sort -u sorted-passwords.txt | wc -l` → **55,385**. The true figure, from `LC_ALL=C sort -u` and independently from Python, is **99,584** (99,583 non-empty). I was one command away from reporting "55,385 candidates tested" in a document whose entire credibility rests on work counts. Rule 6 makes the count load-bearing; the count itself needed a second tool.

5. **I overstated my own coverage by 6,311 candidates.** Computing the union of the five candidate sets, I added a case variant (`w.upper()+suffix`) that no script had actually verified. That produced 566,919 — a number no run had earned. Fixed by reconstructing each script's candidate construction exactly and **asserting the reproductions matched the counts those scripts printed** (14,530 / 99,583 / 421,445 / 131,887) before summing. The honest figure is 560,608.

6. **A positive control that ran six times instead of once.** `multiprocessing.Pool` re-executed the module-level oracle gate in every worker, so `oracle green` printed once per worker and on the parent. Harmless here — the gate is idempotent and it passed everywhere — but a gate that runs N times is not a single gate, and had it been a destructive setup step I would have run it six times without realising.

A seventh is the lab's, not mine, and it is listed above because it is the most instructive thing in the engagement: **the target ships an instrument that reports a confident answer it did not earn.** `whoami` inside `pipe`'s shell returns `DESKTOP-KVHRNUK\pipe`, a fabricated Windows identity generated at random per process. A tester reaching for the obvious identity command would have recorded `root` or `pid 1`. The real identity was only available from `/proc/self/status`, and only because I had already read the source and knew the command did not exist.

## 11. Restore

Recreated from the image, not by undoing edits, and verified with **positive** checks:

```
$ docker rm -f winfake_container && docker run -d --name winfake_container winfake:latest
$ docker exec winfake_container id                              → uid=0(root) gid=0(root) groups=0(root)
$ ps aux | grep -c '[s]shd: /usr/sbin/sshd [listener]'           → 1
$ curl -s http://172.17.0.5/ | wc -c                             → 5678
$ curl -s http://172.17.0.5/ | md5sum                            → e65e9d427accef3a700760c064fc9470
$ grep '^pipe:' /etc/shadow | cut -c1-24                         → $y$j9T$pvvGnLoWnkTXD5RsI
```

The page is back to the shipped bytes, sshd is listening, and `pipe`'s hash still carries the **shipped** salt `$y$j9T$pvvGnLoWnkTXD5RsI` — the target's credentials were never modified. (`/etc/shadow-` holds a *different* salt, `$y$j9T$187HGjxrXR8aD94Ga`; that is the build-time pre-`chpasswd` state, not evidence of tampering.)

Post-restore the shipped credential still authenticates and the user reward is still reachable:

```
$== whoami              → DESKTOP-KVHRNUK\pipe
$== type /home/pipe/user.txt → d970977b69a543ce746095e2b660d107
```

**Artefacts.** Auxiliary containers `winfake_ctl` and `winfake_fresh` removed. Only `winfake_container` remains. The seven `cybervault-*` containers belonging to another project are untouched and still running (verified: 7). No `docker system prune`, no `image prune`, no `volume prune` was run at any point.

## 12. What this lab adds to the methodology

The class is **not new** — credential-guessing-to-restricted-shell and the string-match-filter-bypass are already covered — but this case is a clean instance of a rule the corpus states and has not yet had a lab exercise end to end:

> **A source read is worth exactly what it hands you.** Here it handed over an account name, a login shell, and an escalation sink, and it handed over **no credential at all**. Reporting "the source revealed the password" would have been false — the password was `kisses`, a dictionary word, and the acrostic `WINSERVERROOTFAKENEWS` was never a password in any of 763 forms I tested. Reading the source moved the work from *enumeration* to *one dictionary lookup*, which is a large win, and it did not move the work from *credential recovery* to *nothing*.

The second-order rule is the decoy: **the artefact contained two files with the same name and different contents, and only one of them was reachable.** Every conclusion drawn from the unread one — no sink, `whoami` blocked — was wrong, and each was wrong in a direction that would have *ended* the engagement. Check which copy a configuration or source reference actually points at.