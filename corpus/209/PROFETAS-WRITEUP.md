# PROFETAS — DockerLabs (id 209, Medio)

**Ninth DockerLabs engagement.** Solved end to end. Four hops, all four advertised vectors real.

| | |
|---|---|
| Image | `profetas:latest` (Ubuntu 24.04.3, kernel 6.12.38) |
| Surface | `22/tcp` OpenSSH 9.6p1, `80/tcp` Apache 2.4.58, PHP 8.3.6, MariaDB |
| Accounts | `jeremias` (1001), `ezequiel` (1002), `ubuntu` (1000), `root` |
| Rewards | `DL{flag_user-8F3A7C9B12}` (jeremias), `fl4sk1pwd` (root password), `DL{flag_root-C6A4F19D03}` (root) |

The catalog advertised *"SQLi, XXE, Desofuscación Python, Sudoers croc"*. **All four were real**, which makes this the
first lab in nine where the description was not misleading. It is still misleading in a smaller way: the application
it presents on port 80 is a fake login followed by a decorative monitoring dashboard, and **neither has anything to do
with the four advertised vectors**. The real entry point is a file called `externalentitiinjection.php`.

---

## 1. Surface

```
$ docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' profetas_container
172.17.0.11

$ nmap -sV -Pn -p- 172.17.0.11
Nmap scan report for 172.17.0.11
Host is up (0.000045s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.14 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.58 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Two TCP ports, nothing else. No database port, no management plane. The whole chain is
**web → SSH → one sudoers rule**, and every credential in it is either in the application source or on the
filesystem. `nmap -sU` was not attempted: it needs root and is unavailable on this host, so **UDP coverage is a
declared gap, not a closed port** (per `decision-making.md`, "a scanner's blind spot is not an absence of service").
The image's `EXPOSE` and the absence of any UDP listener in the service manifests are corroboration, not proof.

### Source read before testing (§7)

Per `decision-making.md` §7 the source was read whole before any payload was sent. The webroot is seven PHP files
and the read paid for itself immediately — it is where the SQLi, the XXE, the credential hint and the dead end are
all visible without a single probe.

```
/var/www/html/
  admin.php                    5174   the SQLi login
  config.php                    135   mysqli("localhost","ctf","ctf","ctfdb")
  dashboard.php                 647   session gate on 'auth'
  externalentitiinjection.php 20975   the XXE parser
  index.php                    4104   the fake login + the hidden base64 hint
  logout.php                     79
  upload.php                   1619   a decoy 500 page, no PHP at all
  test.txt                       13   "test_content"  <- the lab's own XXE oracle
  logs/xxe_attempts.log           0
  uploads/                     (empty)
```

`upload.php` is worth one line because it is a trap: it is a static HTML page that *claims* to be a 500 error from
`Apache/2.4.54 (Debian)` and carries `<!-- notadmin -->`. The host runs `Apache/2.4.58 (Ubuntu)`. A scanner or a
reader chasing the wrong fingerprint would report a Debian host and a broken upload endpoint. **Discarded with
reason:** no upload primitive exists in this application.

---

## 2. Findings

### F1 — SQL injection: the filters cover the wrong parameter (CWE-89)

`admin.php:14-51`. The handler assembles:

```php
$sql = "SELECT * FROM users WHERE username = '$final_user' AND password = '$pass'";
```

Four filters are applied, and **every one of them is applied to the username only**:

| Filter | Line | Applies to |
|---|---|---|
| strip `"` `;` `\` `` ` `` | `:28` | `$processed_user` |
| blacklist ` OR ` ` AND ` ` UNION ` ` SELECT ` … `--` `/*` `*/` `#` | `:31-37` | `$processed_user` |
| lowercase + strip spaces | `:40` | `$processed_user` |
| `=` → `!=` on `\d+=\d+` | `:43-45` | `$processed_user` |

`$pass` is read at `:16` and interpolated at `:51` with **no transformation of any kind**. The screen full of
defences is on one column of a two-column statement.

Evidence:

```
# control: wrong password on a valid-shaped user
POST username=notadmin&password=wrongpass   ->  ⚠️ Credenciales incorrectas

# control: username that fails the prefix check
POST username=admin&password=x               ->  Pista: usaurio 'notadmin'

# attack: password field, untouched by all four filters
POST username=notadmin&password=' OR 1=1-- -
HTTP/1.1 302 Found
Location: dashboard.php
```

The 302 is not a 200-with-a-token: `admin.php:58-61` sets `$_SESSION['auth'] = true` and redirects only when
`$res->num_rows > 0`. A 302 *is* the authentication oracle.

**Impact:** authentication bypass to the application's authenticated tier.

**Root cause:** per-value validation instead of per-statement. The remediation is not a fifth filter on
`$pass`; it is parameterised queries (`mysqli_prepare` / bound parameters) so that no column is trusted because of
where it sits.

### F2 — XXE: `LIBXML_NOENT` with the DTD loader enabled (CWE-611)

`externalentitiinjection.php:20-49`:

```php
$old_entity_loader = libxml_disable_entity_loader(false);
libxml_use_internal_errors(true);
$xml = simplexml_load_string($xml_string, 'SimpleXMLElement', LIBXML_NOENT | LIBXML_DTDLOAD);
```

Three separate misconfigurations compose into arbitrary file read:

1. `LIBXML_NOENT` — substitute entities, i.e. expand them into the document.
2. `LIBXML_DTDLOAD` — load the external subset.
3. `libxml_disable_entity_loader(false)` — a **PHP 8.0 no-op**. The function is deprecated and does nothing; it is
   the most reassuring line in the file and protects nothing. See F6.

Impact: arbitrary file read as `www-data`, plus SSRF (external DTD over `http://`).

**Remediation:** drop `LIBXML_NOENT` and `LIBXML_DTDLOAD`; if a DTD is genuinely required, use
`XMLReader` with entity resolution disabled and an `XMLParserHandler` that refuses external entities; and for
PHP ≥ 8.0 delete the `libxml_disable_entity_loader` call, because it signals a control that is not there.

### F3 — The application swallows the only diagnostic that would explain its own failures (CWE-209)

This is the finding the lab is actually about, and it is a *different class* from the XXE.

`parseXMLData()` reads `libxml_get_errors()` **only inside the `if ($xml === false)` branch** (`:33-38`). On the
success path the error list is discarded. Combined with `libxml_use_internal_errors(true)`, a failed external
entity fetch does not raise — it **degrades to an empty string**, and the handler renders an empty cell.

The consequence, measured (see §4 for the method):

| probe | result |
|---|---|
| `file:///var/www/html/test.txt` (0644, 13 B) | `VALUE len=13 'test_content\n'` |
| `file:///dev/null` (readable, always empty) | `NO-OUTPUT` |
| `file:///var/www/html/does_not_exist` | `NO-OUTPUT` |
| `file:///home/jeremias/ezequiel.pyc` (exists, 0644, dir 0750) | `NO-OUTPUT` |
| `file:///root/` (a directory) | `NO-OUTPUT` |
| `file:///etc/shadow` (exists, 0640) | `NO-OUTPUT` |

**Six conditions, one bit.** "The file read returned nothing" is not a finding; it is the union of *empty file*,
*no such file*, *permission denied*, *is a directory* and *I/O error*. An auditor who reports the first one as
"XXE confirmed but the target file is empty or missing" will be wrong four times out of five.

The app *had* the information. libxml records `Failed to load external entity` with an errno for every one of these;
the handler read the list and then threw it away.

**Remediation:** when a fetch fails, surface the libxml error code; and treat an entity that expanded to the empty
string as an error rather than as a value.

### F4 — Authentication state key mismatch: the shipped login is a dead end (CWE-287 / CWE-306)

`index.php:12` sets `$_SESSION['logged'] = true` on any POST, with no credential check at all. Every consumer of
that state checks a **different key**:

| file | line | checks |
|---|---|---|
| `dashboard.php` | `:3` | `!isset($_SESSION['auth'])` |
| `externalentitiinjection.php` | `:5` | `!isset($_SESSION['auth']) \|\| $_SESSION['auth'] !== true` |

Measured:

```
POST /index.php (any user/pass)          -> 302
GET  /dashboard.php  with that session   -> 302 -> /index.php
GET  /externalentitiinjection.php        -> 302 -> /index.php
```

So the elaborate "ProfetaNet — Monitorización de Servidores" panel with its sixteen prophets, its random status
colours and its Luke 8:17 epigraph is **unreachable through its own login form**, and leads nowhere even if reached.
The only way in is the SQLi, which sets `auth` directly.

This is reported as a finding rather than a footnote because the fake login is the target's front page and it
*looks* like the intended entry point. Two consequences: an auditor who stops at the login form concludes the
application is unauthenticated-but-harmless; and the *real* authentication tier has no legitimate front door, so
every visitor must use the injection. **Remediation:** one session key, and a login form that actually
authenticates.

### F5 — A credential that cannot authenticate through its own login form (CWE-521)

The `users` table has exactly one row (recovered by boolean-blind extraction, and independently corroborated by
root's `.mysql_history`, §7):

```
INSERT INTO users VALUES (1,'notadmin','SuperSecurePass');
```

`admin.php:48` builds `$final_user = "realadmin" . $processed_user`, so the statement always queries
`username = 'realadmin...'`. **No input can match the only account that exists.** The correct credential is
unreachable, which means the application has no working login and cannot be audited by its intended route.

Root cause is a renamed account, not a missing check — which is why a reviewer reading only the filters would not
see it. **Remediation:** the prefix rewrite has no defensible purpose; remove it.

### F6 — Hardcoded database credentials in the document root (CWE-798)

`config.php`:

```php
$conn = new mysqli("localhost", "ctf", "ctf", "ctfdb");
```

`ctf/ctf`, world-readable, inside the document root, with `ALL PRIVILEGES ON ctfdb.*` (per root's
`.mysql_history`). Not load-bearing in this chain — the SQLi did not need it — but it is a real disclosure and it
is one request from anonymous. **Remediation:** move credentials out of the docroot and out of source control;
grant the application only the specific statements it issues.

### F7 — `libxml_disable_entity_loader(false)` is a no-op on PHP 8 (CWE-1164 / misleading control)

`:23` and `:46`. Deprecated in PHP 8.0 and non-functional; since libxml 2.9 external entity loading is already off
by default and only `LIBXML_NOENT | LIBXML_DTDLOAD` re-enables it. A reviewer skimming for "entity loader disabled?"
finds the line and concludes the parser is hardened. **It is the single most dangerous line in the file**, because
it is the one that looks like the control. This is `decision-making.md` §7 landing in a function call: a reassuring
name, no behaviour.

### F8 — Session fixation surface on the fake login (CWE-384, minor)

`index.php:2` calls `session_start()` and `:12` promotes the session with no `session_regenerate_id()`. Not
load-bearing (the injection sets `auth` on whatever session it is given), reported for completeness.

---

## 3. Deobfuscation: `/home/jeremias/ezequiel.pyc`

Reached as `jeremias`. This was half the lab, not a formality.

```
-rw-r--r-- 1 jeremias jeremias 7682 Jan 16  2026 ezequiel.pyc
md5 1e932453bfb5dbe2dab6683002bad737
```

### 3.1 Establishing provenance before reading anything

Fetched over SFTP with the remote md5 carried across and recomputed locally, because an earlier attempt to move the
file with `base64 -w0` over a command channel silently truncated it to 6144 of 7682 bytes and the md5 caught it:

```
remote /home/jeremias/ezequiel.pyc = 1e932453bfb5dbe2dab6683002bad737
local  ezequiel.pyc              = 1e932453bfb5dbe2dab6683002bad737  (7682 bytes)
MATCH
```

**A truncated artifact is still a valid-looking artifact.** A `.pyc` missing its last 1.5 KB still unmarshals.

### 3.2 Interpreter version — the first trap

```
pyc magic     f30d0d0a   -> CPython 3.13
host python3  2b0e0d0a   -> CPython 3.12.3
source name   conceded.py
```

`marshal.loads()` on 3.12 **succeeded** and returned a code object with entirely plausible `co_names` and
`co_consts` — the function names, the string literals `'234r3fsd2'` and `'-34fsdrr32'`, the tuple `(3, 6)`. The only
tell was that `dis` emitted nonsense: `INTRINSIC_1_INVALID`, `CALL_INTRINSIC_1 (INTRINSIC_IMPORT_STAR)`,
`CALL 0` followed by an immediate `STORE_FAST`.

**A cross-version unmarshal that does not crash is not a validated parse.** A 3.13 code object has fields 3.12 does
not, so the constants you are about to reason from may not be the constants the author wrote. Getting a real 3.13
interpreter (`uv python install 3.13`, magic confirmed `f30d0d0a` before use) took two minutes and made every later
conclusion sound.

### 3.3 What the transform actually is

Five functions, three of which are the encoding, and **no key anywhere**:

```python
_p1 = '234r3fsd2'
_p2 = '-34fsdrr32'

def _e1(d):                                  # base64( rot13( base64(x) ) )
    a  = base64.b64encode(d.encode()).decode()
    b1 = codecs.encode(a, 'rot_13')
    return base64.b64encode(b1.encode()).decode()

def _e2(d):                                  # base32( reverse( hex(x) ) )
    hx = d.encode().hex()[::-1]
    return base64.b32encode(hx.encode()).decode()

def _e3(d):                                  # reverse( base85( zlib(x) ) )
    return base64.b85encode(zlib.compress(d.encode())).decode()[::-1]

_O = [_e1(_p1), _e2(_p2), _e3(_p1 + _p2)]
```

```
_O[0] = WndaMHB3QXpwMkRs
_O[1] = GIZTGMZSG4ZDONBWGM3TMNRUGMZTGZBS
_O[2] = N$Mm^50&IcMMKfu8He-4^DrYqYHbm_$c
```

**There is no passphrase, no salt, no KDF, and no key.** The `_O` table was built by calling the encoders on two
plaintext string literals that are sitting in the same file. This is the same entry criterion as the binary-reversing
oracle in `infrastructure.md` — look for the KDF, find its absence, and the recovery is arithmetic — applied to
bytecode instead of an import table. `_O[2]` encodes the *concatenation* of the other two plaintexts and
**is never read by anything**.

### 3.4 The decoy, and the one real anti-analysis measure

`class X` is an LCG keystream XOR cipher, and it is **never referenced anywhere in the module**:

```python
class X:
    def __init__(s): s._a = 3735928559                    # 0xDEADBEEF
    def _r(s, n):
        x = s._a
        for _ in range(n):
            x = (x * 25214903917 + 11) & 281474976710655  # LCG, modulus 2^48
        return x
    def f(s, d):                                          # XOR keystream
        t = bytearray()
        for i, ch in enumerate(d.encode() if isinstance(d, str) else d):
            t.append(ch ^ (s._r(i) & 255))
        return bytes(t)
```

A reverser who reads the file top-down, sees a stream cipher with a hardcoded seed, and spends the engagement
attacking it never notices that the credential is three layers of base64/rot13/base32 away from two string
literals. This is `decision-making.md` §7 with a cipher on it: **the impressive object is the decoy, and intent is
not reachability.**

The one genuine anti-analysis measure is `random.seed(4919)` (`:86`) — a **fixed PRNG seed**. It makes `_o1()` and
`_o2()` (50-element float sums, 5×5 random matrices, both results discarded) fully deterministic, which is what
makes the sample reproducible. It is also a security finding in its own right: a fixed seed is not entropy.

### 3.5 Verification — three independent oracles

**(a) Re-derive every layer from first principles**, without calling the sample's own helpers:

```
_e1('234r3fsd2')  -> base64(rot13(base64(s)))  == _O[0]   OK
_e2('-34fsdrr32')  -> base32(hex(s)[::-1])      == _O[1]   OK
_e3(s)             -> reverse(base85(zlib(s))) == _O[2]   OK
```

**(b) Recompile the reconstruction and diff code-object signatures** against the original — recursively, over
`co_name`, `co_argcount`, `co_names` and every non-code constant. This validates *my reading*, not the result:

```
IDENTICAL: every nested function, argcount, name and constant matches
```

The only residual is `__firstlineno__` (`X` 9 vs 4, `V` 64 vs 46) — source layout, not semantics, and reported as
such rather than papered over.

**(c) Adjudicate with the sample's own comparison loop** (`V.v`, a non-early-exit bytewise accumulator):

```
v(obj, '234r3fsd2-34fsdrr32'   ) -> True
v(obj, 'jeremias'              ) -> 0
v(obj, 'ezequiel'              ) -> 0
v(obj, '234r3fsd2-34fsdrr3'    ) -> 0
v(obj, '234r3fsd2-34fsdrr32x'  ) -> 0
v(obj, '234r3fsd2'             ) -> 0
```

**Secret: `234r3fsd2-34fsdrr32`** — and the account's own success banner prints the masked shape
`Password: 2...-3..`, whose leading `2` and `-3` agree with the recovered string at offsets 0 and 9. Reported as
**partial** corroboration only: the banner is 8 glyphs wide and the secret is 19 characters, so the mask widths do
not correspond to the real length and it cannot confirm the whole value.

Verified by use, which is the only oracle that counts:

```
$ python3 sshx.py try ezequiel '234r3fsd2-34fsdrr32'
### ezequiel:... -> OK
uid=1002(ezequiel) gid=1002(ezequiel) groups=1002(ezequiel),100(users)
```

### 3.6 The sample is broken three independent ways, and hides all three

**This is the most valuable thing in the file.** `concedido.py` cannot reach its own success path, for three
unrelated reasons, and a bare `except:` in `m()` converts all of them into one silent exit.

**Defect 1 — `m()` calls `V()` with no argument, but `__init__` takes one.**

```python
def __init__(s):        # co_argcount == 1, co_varnames == ('s',)  -- there is no `self`
    s._ct = 0
    s._st = 3405691582
...
v = V()                 # TypeError: missing 1 required positional argument
```

Every method in both classes takes the **instance as its first parameter** — they were written as module-level
functions and stuffed into class bodies, so `def __init__(self, s)` should have been `def __init__(s)`. Note this
is only visible from the *bytecode*: `co_varnames` is `('s',)`, not `('self', 's')`.

**Defect 2 — `def m()` shadows `import math as m`.** `_o1()` calls `m.sin`, `m.exp`, `m.cos`, but the module-level
`def m():` at line 61 rebinds the name. Result:

```
AttributeError: 'function' object has no attribute 'sin'
```

**Defect 3 — `V._x` inverts the transform in the wrong order.**

```python
l1 = b.b64decode(b.b64decode(c.decode(_O[0], 'rot_13')).decode())
```

`_e1` builds `base64(rot13(base64(s)))`, so inverting it requires **decode first, then rot13**. The sample applies
rot13 *before* the first decode, so the second `b64decode` is handed 12 raw bytes:

```
rot13(_O[0])     = 'JaqnZUO3DKcjZxEf'
b64decode(that)  = b'%\xaa\xa7eC\xb7\x0c\xa7#g\x11\x1f'   <- raw bytes, no longer base64 text
b64decode(that)  = Error: Incorrect padding
```

**Empirical proof, not inference.** The shipped `.pyc` was executed under a pty and fed the correct password:

```
    ╔═══════════════════════════════════════╗
    ║    SISTEMA DE AUTENTICACIÓN SEGURA    ║
    ║         v3.14.159 - INTERNO           ║
    ╚═══════════════════════════════════════╝
🔐  Contraseña: 234r3fsd2-34fsdrr32
---- exit status: 0 ----
```

It prompts, accepts the correct password, and then prints **neither** `ACCESO CONCEDIDO` **nor**
`Error: verificación falló`. One silent exit, three different crashes, zero diagnostics.

**Why this matters beyond the lab:** the bare `except:` is the same defect as F3 in a different language. A
catch-all converts three specific failures into one indistinguishable outcome, and the program's only observable
behaviour — "it exited" — is compatible with all of them. The lab hands you the secret and then makes the program
unable to confirm it, so the *only* honest way to close the loop is to drive the code objects yourself. That is
why §3.5(c) exists.

---

## 4. XXE: how a real one was distinguished from a payload returned unprocessed

This is the section the methodology has no oracle for, so it is written out in full.

### 4.1 The control that makes it decidable

The lab ships `/var/www/html/test.txt` containing the string `test_content`. That file is the oracle, and it is
placed so that the *value* is the discriminator, not the status code:

```
### T0 CONTROL: plain document, no entity
sent:     <name>alice</name> <role>tester</role>
returned: name=alice  role=tester

### T1 CONTROL: INTERNAL entity only, no external reference
sent:     <!ENTITY x "INLINE_MARKER_12345"> ... <name>&x;</name>
returned: name=INLINE_MARKER_12345          <- expanded, but nothing was fetched

### T2 ATTACK: EXTERNAL entity, file:///var/www/html/test.txt
sent:     <!ENTITY x SYSTEM "file:///var/www/html/test.txt"> ... <name>&x;</name>
returned: name=test_content
```

**`test_content` is a value that appears in no request I ever sent.** The parser cannot synthesise it, cannot
echo it, and cannot infer it. This is the whole difference between "my payload came back" and "the target read a
file":

| Result | What it proves |
|---|---|
| Response contains my entity declaration verbatim | The parser did not process anything. **Not a finding.** |
| Response contains my *internal* entity's value | Entity substitution is on. Proves `LIBXML_NOENT`, nothing about reach. |
| Response contains a **file's** content | The parser resolved an **external** reference. That is XXE. |

Three states, and only the third is the vulnerability. The middle one is the trap: a lab that reports
"T1 succeeded, therefore XXE confirmed" has demonstrated a capability that every XML parser since 2008 has.

### 4.2 The channel

The exfiltration channel here is **the HTTP response itself**. `LIBXML_NOENT` expands the entity into the parsed
document, the document is `json_encode`d, and the field is rendered into the result table at `:110-135`. The signal
travels back in-band, so **no out-of-band infrastructure is required** — which is worth stating plainly, because
"if you have no OOB you have no XXE" is only true for blind XXE. In-band reflection is a complete channel, and
treating it as a weaker case of OOB is a mistake that costs engagements.

### 4.3 Vectors distinguished, and what each one proves

Each vector tests a *different capability* of the parser, which is why testing several is what establishes that the
control is absent rather than merely misconfigured:

| vector | capability tested | result |
|---|---|---|
| internal entity | `LIBXML_NOENT` substitution | expanded (T1) |
| `file://` external entity | external reference resolution | **`/etc/passwd` read in full, 29 lines** |
| `php://filter/convert.base64-encode` | stream-wrapper resolution | resolved (succeeded) |
| `http://` in an external DTD subset | SSRF / network egress | not exercised end-to-end — see §9 |
| `expect://` | code execution | not attempted — see §9 |

The `file://` read of `/etc/passwd` is the decisive one, and it is worth noting that the lab *helps* here:
`externalentitiinjection.php:113-116` special-cases a value beginning with `root:` and renders it in a
`file-content` div. The author built the confirmation into the page, which is a hint, not evidence — the evidence
is that the content came from a file I never sent.

### 4.4 A third outcome, and why it is the dangerous one

A failed external fetch does **not** raise. With `libxml_use_internal_errors(true)` the parse succeeds with the
entity expanded to the empty string, and the page renders an empty cell. Measured over eight probes (§2, F3): one
returned content, **seven returned a byte-identical empty result** spanning an empty file, a missing file, a
permission-denied file, a directory, and a root-only file.

The diagnostic runs in the direction the method requires — *the failure names the block*. But it cannot run
here, because the application reads the libxml error list and throws it away on the success path. What saved the
analysis was an **independent channel**: the file modes, checked outside the application.

```
/etc/sudoers.d/ezequiel   0644  -> VALUE, content returned
/etc/sudoers              0640  -> NO-OUTPUT
```

A world-readable file returned and a root-only file did not, so the empty result is a **permission** signal, not a
parser failure. That is a conclusion about the *filesystem*, established from a source the application does not
control, and it is why the empty cell could be interpreted at all.

---

## 5. Chain

| # | Hop | Identity after | Why this step, and not another |
|---|---|---|---|
| 1 | SQLi in `admin.php` **password** field → `$_SESSION['auth']` | `www-data` (via session) | The four filters are on the username. The `notadmin` prefix check at `:19` is the only gate and it is a *string* test, not an auth decision. |
| 2 | XXE file read in `externalentitiinjection.php` | `www-data` | `/etc/passwd` confirmed three accounts and the sudoers hint. The pyc is **not** reachable from here — see §6. |
| 3 | Base64 hint in `index.php:191`, hidden in `color: black` text | — | `cmVjdWVyZGEuLi4gdHUgY29udHJhc2VxYSBlcyB0dSB1c3Vhcmlv` → `recuerda... tu contraseñas es tu usuario`. A label, not evidence — tested differentially. |
| 4 | SSH `jeremias:jeremias` | `uid=1001(jeremias)` | `id` first. The same guess against `ezequiel` and `ubuntu` returns `AUTH_FAILED`, which is what makes the positive a result rather than a fluke of a permissive authenticator. |
| 5 | Read `/home/jeremias/ezequiel.pyc`, deobfuscate | `jeremias` | §3. This is why the pyc is in *jeremias'* home and not `ezequiel`'s: it is one hop further than it needs to be. |
| 6 | SSH `ezequiel:234r3fsd2-34fsdrr32` | `uid=1002(ezequiel)` | `id` first. |
| 7 | `sudo croc send /root/passw0rd_r00t.txt` | **root file read** | The sudoers rule pins the *program*, not its arguments. |
| 8 | `DL{flag_root-C6A4F19D03}` from `/root/root.txt` | — | via step 7 applied to the directory. |

### The sudoers escalation, in full

`/etc/sudoers.d/ezequiel`:

```
ezequiel ALL=(ALL) NOPASSWD: /usr/local/bin/croc
```

`croc` is v10.3.1, a 15 MB Go file-transfer client at `/usr/local/bin/croc`, mode `0755 root:root`, not setuid.
The rule names a program with no argument restriction, so **root can be made to run `croc send <path>`**: croc,
executing with root's privileges, opens the named file and transmits it. The receiving end runs as the
unprivileged account and writes the bytes to `--stdout`. What assembles is an **arbitrary root file-read primitive
built out of a file-transfer client, not out of a shell** — and `croc send /root` (a *directory*) is arbitrary root
file *enumeration* the same way, which is how `/root/root.txt` was found.

Three pieces of evidence that the elevation is real, none of them circular:

```
# 1. croc's own line, produced by the root-owned process
Sending 0 files (10 B)
Sending 'passw0rd_r00t.txt' (10 B)

# 2. the process table: every sudo-launched croc is root-owned
    425 root  sudo -n /usr/local/bin/croc ... send /root/passw0rd_r00t.txt
    427 root  /usr/local/bin/croc ... send /root/passw0rd_r00t.txt

# 3. the low-privilege user cannot even kill them
$ pkill -x croc        # kills every croc it owns, leaves all six root ones
```

Evidence 3 is the one worth keeping. An escalation you cannot clean up as the low-privilege user is an
escalation, and it is observable without executing a single line of the target's code.

### croc v10.3.1 transfer mechanics (cost roughly ten cycles; recording it so nobody repeats it)

1. **The default protocol does not complete in this environment.** The sender joins its room and advertises
   `9015,9016,9017,9018`; the receiver logs `public IP address`, then prints a bare `EOF` and exits `rc=1` with no
   error. Reproduced with sender and receiver on the *same host over loopback*, so it is not a topology problem.
2. **`--classic` is gated by an interactive confirmation that `--yes` does not answer** — `--yes` covers file
   prompts, not this one. Without a tty it reads EOF and exits `0` having transferred nothing, which looks like
   success.
3. **The gate is persisted per-`$HOME` at `$HOME/.config/croc/classic_enabled`** (contents: `enabled`). Under
   `sudo`, `env_reset` sets `HOME=/root`, so the *elevated* croc reads **root's** config, not the attacker's.
   Answer the prompt once to create it, then omit `--classic` entirely — passing the flag is itself the request, so
   it re-prompts forever.
4. **The receiver needs the phrase in `CROC_SECRET`, not positionally.** `croc <code>` is the new-protocol form.
5. **croc reads piped stdin as the payload.** Without `--ignore-stdin`,
   `printf 'y\n' | croc send /root/file` sends `stdin (2 B)` and ignores the filename — a *successful* transfer of
   the wrong thing.
6. **Multicast peer discovery crosses hosts on a shared segment.** A receiver on the attacker host discovered
   `172.17.0.11` and paired with a *stale* sender from an earlier experiment; the sender advertised ports
   `9015-9018` while the receiver got `9030-9033`, and the room never matched. Two relays, not one bug. Kill stale
   processes and use exactly one relay.

---

## 6. Control tests — what held

Reported with the same prominence as the findings, because a reader cannot tell an untested control from a
holding one.

| Control | Probe | Verdict |
|---|---|---|
| Session gate on the XML panel | `GET /externalentitiinjection.php` with only `logged` set | **held** — `302` to `index.php` |
| Session gate on the dashboard | `GET /dashboard.php` with only `logged` set | **held** — `302` |
| sudo is scoped, not blanket | `sudo -n id` | **held** — `sudo: a password is required` |
| sudoers grant is real and narrow | `sudo -n -l` | `(ALL) NOPASSWD: /usr/local/bin/croc` — and nothing else |
| Environment injection | `sudo -n CROC_SECRET=x croc --version` | **held** — `sorry, you are not allowed to set the following environment variables` |
| croc is not a writable/setuid target | `ls -la /usr/local/bin/croc` | **held** — `0755 root:root` |
| Home directory isolation | XXE as `www-data` against `/home/jeremias/ezequiel.pyc` | **held** — `0750` on the directory blocks traversal; the file is `0644` but unreachable |
| Root SSH | `ssh root@…` with the recovered password | **held** — `AUTH_FAILED`; `KbdInteractiveAuthentication no` and no explicit `PermitRootLogin`, so the default `prohibit-password` applies |
| Cross-account cleanup | `jeremias` cannot delete `ezequiel`'s files | **held** |
| The lab's own decoder | run the shipped `.pyc` with the correct password | **failed** — §3.6, three defects, one silent exit |
| `sudoers.d/jeremias` | file exists, **1 byte**, grants nothing | **held** — but see §9 |

Two of these are worth more than a finding. The **`0750` home directory** is what forced the chain through
`jeremias` before `ezequiel`, and it is a control that turned out to be load-bearing. The **scoped sudo rule** is
the difference between "passwordless root" and "root can run one specific program", and probing a *different*
program is what proved the scoping — `sudo -l` alone would only have been a claim.

---

## 7. Unused findings

Load-bearing things not used in the chain, each with its own impact.

- **Hardcoded DB credential** `ctf/ctf` with `ALL PRIVILEGES ON ctfdb.*`, in the document root (F6). Not needed —
  the SQLi was unauthenticated.
- **`LOAD_FILE()` / `INTO OUTFILE`** from the SQLi. Not tested: the `mysqld` user faces the same `0750` barrier as
  `www-data` for the pyc, and `secure_path`/file privileges were not probed. Listed as untested, not as absent.
- **SSRF via an external DTD over `http://`.** `LIBXML_DTDLOAD` is set, so the external subset is loaded and this
  should work. Not exercised end to end, because it needs a listener the target can reach and the in-band file
  read already solved the lab. **The SSRF half of F2 is therefore reported as reasoned-from-source, not measured.**
- **`php://filter`** resolved successfully, confirming stream wrappers are live. Not needed beyond that.
- **Blind SQL extraction** of the `users` table worked and is how the single row was recovered before root's
  `.mysql_history` corroborated it. Two independent sources agreeing is why F5 is stated as fact.
- **root's `.mysql_history`**, obtained through the croc primitive, independently confirms the schema, the `ctf`
  grant and the sole `notadmin` row. Root's `.bash_history` shows `nano admin.php` and `su ezequiel`, `su jeremias`.

---

## 8. Self-correction — prominent, because it cost the most

Four of my own instruments were wrong before the chain closed. None was a defect in the target.

**8.1 I hashed the whole HTTP response to compare two XXE probes, and the hash measured my own payload.**
The page echoes the submitted XML back into the `<textarea>` (`:519`) and carries a timestamp and session id in the
footer, so five responses that were semantically identical produced five different md5s — and I briefly had a
"they differ, so they're distinguishable" result that was pure self-reference. Fixed by extracting **only the
parsed field value** and comparing that. *This is `decision-making.md` §1 pointed at my own comparison: validate the
value, not the representation of it.*

**8.2 I asserted the wrong root cause for `V._x`'s failure, from a filtered disassembly.**
My disassembly helper skipped any instruction with an empty `argrepr`, and in CPython 3.13 `CALL n` carries its
argument count in `arg` — so **every single call instruction was silently deleted**, leaving me to read a stack with
no calls in it. I concluded "`_x` applies one base64 decode too many" and wrote that down. The real defect is
**rot13 and base64-decode applied in the wrong order**. What caught it was not re-reading the code; it was the
**runtime error type**. `binascii.Error: Incorrect padding` can only come from `b64decode`, which located the failing
call precisely. *A filtered view of a stack is not a stack. When the conclusion is about control flow, confirm the
failure point from the program's own error, not from your rendering of it.*

**8.3 `pkill -f croc` killed the shell that contained the string `croc`.**
`pkill -f` matches full command lines, and my launcher was literally
`sh -c 'pkill -f croc; … bash /tmp/esc.sh …'`. The launcher killed itself, the new run never started, and I read the
**previous** run's log — which looked like a plausible current result, complete with a stale code phrase. Fixed by
killing by port (`fuser -k 9009/tcp`) or by exact name. *This is the "witness you did not create in this run" shape
aimed at a launcher: the file on disk was well-formed, one step behind the truth, and nothing downstream could tell.*

**8.4 My first blind-extraction loop returned empty for every value, and I nearly recorded the table as empty.**
The bug: the prefix-search loop tested `SUBSTRING(expr,1,mid) = $prefix` with `$prefix` empty, which is false for
every `mid`, so it broke on the first iteration. The fix was `SUBSTRING(expr,1,mid) = SUBSTRING('$prefix',1,mid)`,
which is trivially true when `prefix` is empty and therefore lets the search grow. *A detector that returns "nothing
found" for a table that demonstrably has rows is measuring itself — the same discipline as the existence detector
that matched its own error message.*

Two more that cost a cycle each, recorded because both are traps in this lab specifically:

- **croc's flag grammar.** `--relay` is global (before the subcommand), `--port`/`--code` are `send` options
  (after it), and `--port` is invalid for the receiver form entirely. Three misplacements, each producing
  `flag provided but not defined`, each looking like a target problem.
- **croc reads piped stdin as the payload.** `printf 'y\n' | croc send /root/file` transferred `stdin (2 B)` and
  ignored the filename. The transfer *succeeded*. Only `--ignore-stdin` fixes it, and the tell is croc's own
  `Sending 'stdin' (2 B)` line.

---

## 9. Not tested vs discarded, and one design observation

### Not tested (coverage gap, declared)

- **UDP.** `nmap -sU` needs root and is unavailable here. No UDP coverage exists in this engagement.
- **`http://` external-DTD SSRF.** The half of F2 that would require a listener the target can reach.
- **`expect://` code execution through the XML parser.** PHP 8.3's stream wrapper list was not enumerated and the
  vector was not fired.
- **The SQLi beyond the `users` table.** `INFORMATION_SCHEMA` enumeration was attempted and the extractor bug
  (8.4) blocked it; only `users` was extracted, via the pre-existing character-by-character routine.
- **Any privilege escalation other than the croc rule.** The setuid sweep found only stock Ubuntu binaries, and
  `/etc/cron.d` holds only `e2scrub_all` and `php`.

### Discarded, with reason

| Discarded | Reason |
|---|---|
| Upload primitive | `upload.php` is a static HTML decoy; no `<?php` in it, and it advertises a wrong server version. |
| `ProfetaNet` login | Sets `logged`, every consumer checks `auth` (F4). Measured `302`, not reasoned. |
| XXE to reach the `.pyc` | `/home/jeremias` is `0750`; `www-data` cannot traverse it. The file is world-readable *within* the directory and unreachable *through* it — a boundary, not a bug. |
| `jeremias` sudo | `/etc/sudoers.d/jeremias` is 1 byte and grants nothing. `sudo -n -l` returns nothing for him. |
| Reversing `class X` | It is a complete, correct LCG stream cipher that **nothing references**. The real secret is `_p1 + _p2`. Attacking the cipher is the intended waste of time. |
| `sudo` as root / any other program | Refused. The rule pins one program. |
| The public croc relay | Reachable, but using it would have sent lab data to a third party. A relay on the attacker-controlled host was used instead. |

### Design observation

The lab is unusually well made in one respect and unusually self-defeating in another.

**Well made:** every control is a *real* control, not theatre. The `0750` home directory, the scoped sudo rule, the
`env_reset` environment refusal and the session gate all held, and the `0750` is load-bearing — it is what makes
the `.pyc` a second hop instead of a freebie. The lab also ships its own oracle (`test.txt`), which is a generous
and pedagogically correct thing to do.

**Self-defeating:** the deobfuscated sample cannot verify its own secret, and the front page cannot reach its own
authenticated tier. In both cases the author built a control or a feature and then broke it, and in both cases a
bare `except:` / a wrong session key hides the breakage behind a plausible-looking surface. The result is that the
two most valuable artefacts in the lab — the credential oracle and the entry point — can only be exercised by
reading them, not by running them.

There is a third instance of the same habit. `/etc/sudoers.d/jeremias` **exists**: a real, root-owned sudoers
fragment with a plausible name, granting nothing, one byte long. It is an *authorization artifact that looks like a
grant*. An auditor auditing sudoers by listing `/etc/sudoers.d/` sees a policy for a second account and has to read
the file to learn it is empty. Per `decision-making.md` §5 that is a finding in its own right — a file whose
existence is a claim and whose content is not.

---

## 10. Rewards

| Path | Value | How obtained |
|---|---|---|
| `/home/jeremias/user.txt` | `DL{flag_user-8F3A7C9B12}` | direct read as `jeremias` |
| `/root/passw0rd_r00t.txt` | `fl4sk1pwd` | `sudo croc send` — root file read |
| `/root/root.txt` | `DL{flag_root-C6A4F19D03` | `sudo croc send /root` — root directory enumeration |

Note the format is `DL{...}`, not `FLAG{...}`. The root password was recovered by an arbitrary-file-read primitive
rather than by a root shell, because **root SSH is correctly refused** — the credential's only remaining use is as
a credential, and that is reported as such rather than inflated into a root session.

## 11. Restoration

The lab was left as shipped and verified by md5 against a container recreated from the original
`labs/209/profetas.tar`.

```
e3f087412ab3c19810fe24bc6840af87  /var/www/html/admin.php
5f7e820342feae96603c0ea621c07e95  /var/www/html/config.php
1fe0e1b05e303abeb509ad5bfbc5a26c  /var/www/html/dashboard.php
dac60a79bce0b031ab36a440e0beaad4  /var/www/html/externalentitiinjection.php
7906817bc9e832ef597154257019ffc4  /var/www/html/index.php
a532f69954b89732468448265da4d92e  /var/www/html/logout.php
11665ab994c972a7afa185c739874444  /var/www/html/upload.php
87978e0dfadc2f75cafc0d21600eaa55  /var/www/html/test.txt
1e932453bfb5dbe2dab6683002bad737  /home/jeremias/ezequiel.pyc
43953b010520cdcabb7eea8e4071c8c1  /home/jeremias/user.txt
6b470d4c3fd1014854c852d546187076  /home/ezequiel/acces0.txt
d379c673537eb32eb897477fa190b3b0  /root/root.txt
a97d6de97b539c3db78a94a843a2aab8  /root/passw0rd_r00t.txt
```

All identical before and after. The container and image were removed and reloaded from the tarball, and the
`~/.config/croc/` directory that did not exist in the shipped image is confirmed absent. Every SQLi and XXE probe
was read-only; the webroot md5s never changed.

The only artefact that could not be removed unprivileged was a set of root-owned `croc-stdin-*` files in
`/home/ezequiel` and the root-owned croc processes — **both consequences of the escalation itself**, and both
discarded with the container.
