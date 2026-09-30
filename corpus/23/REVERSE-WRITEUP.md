# REVERSE — DockerLabs lab 23 (Medio)

*Seventeenth lab of the series. The catalogue description is **true in three of its four claims** and false in one: "Máquina donde se analiza un binario para acceder a un subdominio, se explota una vulnerabilidad LFI con log poisoning para obtener acceso al sistema." The binary → subdomain hand-off is real and is the best-constructed first stage in the series so far. The LFI is real. The log poisoning is real. But **"obtener acceso al sistema" stops at an unprivileged web user** — there is no privilege escalation available from that identity, and the one sudo artifact the lab ships is a *secret dispenser that does not yield a shell*. The description's implied fourth claim (that the chain ends somewhere privileged) is the one that does not hold.*

**Result: `uid=33(www-data)`,** an arbitrary-command primitive in a web-server process, reached in three hops from an unauthenticated HTTP request.
**Reward: none exists.** Tenth consecutive lab without one; §9 is the exhaustive search that establishes the absence, and §9.1 states precisely what was *not* attempted and why.

Secrets in this document are published as SHA-256 prefixes, following this repository's own rule that *`sha256(flag)` proves possession without publishing the secret*. The method is reproducible from the disassembly without them. The one secret that **is** published literally is the sudoers rule, because it is configuration evidence rather than a credential.

| Artifact | len | sha256 (first 32) |
|---|---|---|
| Derived binary password | 13 | `58c2c512b89fc28ab3635ce068d619c7` |
| Base64 blob printed by the binary | 28 | `862270afc4ea8c4ca524dad2f9b72fbd` |
| Decoded internal host name | 18 | `a911e6bed40fa33ce3a8d5f9374ff3eb` |
| Helper gate password | 9 | `22b2f5d0b7eae359c118d8bb41a121e9` |
| Secret disclosed by the helper | 24 | `0800d00ccb7372f849f47cf191b5063d` |

---

## 1. Autocorrection (read this first)

Five errors in this engagement, all of them mine, four of them in my own instrumentation. Two of them would have produced a *confident report of absence* — "log poisoning is blocked here" — which is the failure mode this repository has now seen five times.

### 1.1 I nearly declared log poisoning dead by reading mode bits

The Apache logs are `-rw-r----- root:adm`. My first reading was the standard one: the include runs as `www-data`, `www-data` is not `root`, therefore the log is unreadable and the log-poisoning leg cannot work. **That is false, and it is false in the way this repository has documented twice** — *ownership by a group that happens to be yours is not write access, and is not read access either.*

The truth: `www-data` is a member of group `adm`. It reads the log byte-for-byte identically to root. The permission link in the chain **holds**, and had I trusted the mode string I would have thrown away the lab's actual third stage and written "the log is not readable by the include" into a report.

The measurement that settled it was not a mode string. It was **reading the same file as each identity**:

```
as root      -> 60 bytes, first line "[…] "GET / HTTP/1.0…"
as www-data  -> 60 bytes, first line "[…] "GET / HTTP/1.0…"   (identical)
```

And the *first* attempt at that measurement was itself broken, in the exact way §1 warns about — see 1.2.

### 1.2 My readability probe returned a clean reading of the wrong process's exit code

My first permission probe was:

```sh
su -s /bin/sh www-data -c "head -c 40 $f" 2>&1 | head -1
echo " [rc=$?]"
```

It printed an empty string and `rc=0` — a well-formed, believable reading of **nothing**. Two independent defects in one line:

1. `$?` is the exit status of `head -1`, not of `su` and not of the `open()` that actually failed. A detector that cannot fail, pointed at the question.
2. The `2>&1` was consumed by the pipe, so the *real* diagnostic — a `Permission denied` on stderr — was discarded, and the empty line was indistinguishable from a genuinely empty file.

The follow-up attempt was worse: I redirected to a path that did not exist **inside the container**, producing `cannot create /tmp/opencode/pos.txt: Directory nonexistent` and a `wc -c` of empty. I had written a host path into a container command. Both versions of this probe reported "www-data read 0 bytes" and I was one command from the wrong conclusion in 1.1. Fixed by capturing stderr to a file that exists on the target side and comparing byte counts across identities.

### 1.3 A `404` I read as "not poisonable" was my own URL shape

Twice. The first injection attempt produced `404` and I recorded the log as unchanged. The cause was mine: I built the payload with Python's `urllib.parse.quote()` at default settings, which encodes `/` as `%2F`. Apache ships `AllowEncodedSlashes Off`, so **any request containing `%2F` is a `404` regardless of the path** — a well-formed answer, one step behind nothing at all. The second attempt kept the `%2F`-free path but put a short component in front of the payload (`/QJ/` + payload), so the request became an ordinary 404 for a directory that does not exist, and a 404 **writes no error-log entry at all**.

Only the measured threshold separated the real thing from the fake:

| path length | HTTP | error.log delta |
|---|---|---|
| 100 | `404` | 0 |
| 500 | `403` | +1182 |
| 2000 | `403` | +4182 |
| 4000 | `403` | +8182 |

The trigger is a **single path component longer than the 255-byte filename limit** → `errno 36 ENAMETOOLONG` → `403` **plus** an error-log entry quoting the decoded path. Both of my "not poisonable" results were a `404`, i.e. *the request never reached the code that writes the log*. This is the Grandma lesson verbatim: **a `404` has two indistinguishable causes, and the boring one here was mine.**

### 1.4 I nearly filed a client bug as a target control, and nearly filed a target control as a client bug

A raw newline in `User-Agent` returned `400`. That answer has two indistinguishable causes: Apache refuses an embedded CR/LF in a header, or my client mangled the bytes. **I could not tell them apart from curl's output**, and both readings lead to a wrong report — one blames my tooling, the other claims a control that may not exist.

Resolved by forbidding the client from touching the payload: a raw Python socket sending the CRLF-embedded header verbatim returned `400` as well. So the control is **the target's**, and it is genuinely there.

### 1.5 I read a plausible 6-byte string as a recovered password

Two adjacent 6-byte constants, `S3cRet` and `d00m`, sit immediately before the game's prompt strings in `.rodata` and together spell a leetspeak phrase. Every heuristic in this repository's reversing section points at them: adjacency, immediacy to the prompt, plausible appearance. I submitted their concatenation and got `Contraseña incorrecta…`.

The reason is visible only in the **call site**, not in the constant table — and this is precisely the existing rule *"prefer the call site to the constant table"*. `main` does not compare the input to a stored password. It calls `containsRequiredChars(const std::string&)` (`:21containsRequiredChars…`, `0x4044ee`), which builds **four `std::regex` objects and requires `length() == 13`**. The two constants are *regex patterns*, not a password, and the two 2-byte neighbours are patterns too. The password is a **permutation satisfying four pattern constraints plus a length**, which is a different problem from the one the constants suggest — and the constant that made me confident is a label, not a value.

---

## 2. Real surface

### 2.1 Host

| | |
|---|---|
| OS | Parrot Security 6.2 (lorikeet), Debian-derived |
| Services | `80/tcp` only — Apache httpd 2.4.62, PHP 8.2.26 (`mpm_prefork`) |
| Attack surface | one port, two vhosts, one unauthenticated PHP `include()` |
| Entry identity reached | `uid=33(www-data) gid=33(www-data) groups=33(www-data),4(adm)` |

`nmap -sV -Pn -p- 172.17.0.9`:

```
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.62 ((Debian))
Not shown: 65534 closed tcp ports (conn-refused)
```

Single container, no macvlan, no second host. The image declares **no `EXPOSE`** directive and its entrypoint is `/bin/sh -c bash $@` with `Cmd = /bin/sh -c iniciar`, where `iniciar` is three lines: start apache2, sleep, `tail -f /dev/null`. Nothing is listening that is not in the Apache config.

### 2.2 Vhost table — the central evidence

Two vhosts, and the *default* one is not a real host. Per the vhosting rule in `api_web.md`, each candidate was read **three times with no writes** and hashed after dropping `Date`/`ETag`/`Last-Modified` and collapsing whitespace:

| `Host:` | read 1 | read 2 | read 3 | verdict |
|---|---|---|---|---|
| the name decoded from the binary | `2d38449569dcb3bd` | `2d38449569dcb3bd` | `2d38449569dcb3bd` | **stable, distinct → real host** |
| the first vhost in the config | `1d3ed7da27f93ca3` | `1d3ed7da27f93ca3` | `1d3ed7da27f93ca3` | **identical to the provably-absent control → baseline** |
| a name that cannot exist | `1d3ed7da27f93ca3` | `1d3ed7da27f93ca3` | `1d3ed7da27f93ca3` | **control** |

Every name answers `200` — that is not information. **Three distinct hashes would have meant the sweep found everything; two means it found exactly one real host**, and the config's own first vhost is the catch-all, not a discovery. The provably-absent control is what makes this decidable, and the three-identical-reads requirement is what stops a moving body from reading as a host. Both directions of the rule are exercised here: one of these two "hosts" is the baseline.

### 2.3 The binary — the entry criterion, applied

`secret` is world-readable **inside the document root of the default vhost**, so it is downloadable over HTTP with no authentication:

```
http_code=200 size=2850872      # on-disk size is 2850872 — byte-identical transport
secret: ELF 64-bit LSB executable, x86-64, statically linked, not stripped
md5=e6a2a489b257a383d013e2e81665ff2e
```

**The reversing entry criterion settles the strategy in two lookups:**

- **Is there a KDF?** `nm -C secret | grep -icE 'pbkdf2|scrypt|argon2|bcrypt'` → **0**. There is no dynamic section at all (statically linked), and `EVP_*`/`AES_*` symbol count is **0**. So this is **not** a cryptanalysis problem and the decompiler is not the next step. Without that check this would have been scoped as a crypto engagement and cost hours.
- **What is it, then?** A C++ quiz: `secret.cpp` in the string table, `main` at `0x404716`, and two functions that matter — `containsRequiredChars` (`0x4044ee`) and `decodeMessage` (`0x4042a5`). Not stripped, so the entry point is named rather than hunted.

Note the negative half, which is what makes the scoping honest: **the decoded host name does not appear in `strings` output at all** — not in cleartext, and the binary is not obfuscated. It is constructed at runtime and printed base64-encoded. A `strings | grep` sweep for the hostname returns nothing, so the "grep the binary for the subdomain" shortcut that the lab's own framing invites **does not work**, and a reviewer who only ran it would conclude the binary is a dead end.

---

## 3. The chain

```
[1] unauthenticated HTTP GET /secret_dir/secret        (default vhost, document root)
      └─ 2850872 bytes, ELF, not stripped, no KDF import  → §2.3
[2] static analysis: main → containsRequiredChars(pw)   → §1.5, §4.1
      4 regex_search constraints + length == 13
      └─ a 13-character input satisfying all four  → decodeMessage()
[3] decodeMessage() prints a base64 blob
      └─ base64 -d → the second vhost's name          → §2.2
[4] Host: <that name> → a different document root, /var/www/subdominio
      └─ experiments.php?module=… → include() of an attacker-chosen path  → §4.2
[5] primitive 1: read   — /etc/passwd bytes come back, so this is exfiltration, not an oracle
      primitive 2: execute — a request path >255 bytes is reflected into the Apache error log
                     as a decoded line; including that log executes it
      └─ uid=33(www-data)                               → §4.3, §5
[6] as www-data: sudo -u nova /opt/password_nova  (NOPASSWD, one binary)
      └─ discloses a secret that authenticates to NO account   → §4.4, §8
[chain ends here — no privilege escalation exists from uid=33]
```

---

## 4. Findings

### 4.1 Client-side secret check in a distributed binary — CWE-602 / CWE-321

**The defect.** `main` (`0x404716`) reads a line from `std::cin` and passes it to `containsRequiredChars` (`0x4044ee`). That function constructs four `std::basic_regex` objects from four constants at `0x57e081`, `0x57e083`, `0x57e086` and `0x57e08d`, `regex_search`es the input against each, and returns true only if **all four match and `length() == 0xd`**.

**Why this is a finding and not a curiosity.** The check is a *client-side gate on a secret*, and it is the only thing between a 2.8 MB world-readable binary and the name of an internal host. Because the four patterns are individually satisfiable and the length is a sum, **the set of accepted inputs is not the author's input** — it is any 13-character permutation meeting four pattern constraints. There is no key to steal and nothing to brute-force: an attacker *derives* the input from the disassembly in minutes.

**Root cause.** Authentication-shaped logic implemented as a pattern test inside a distributed client, with the satisfiability of the constraints left unexamined.

**Remediation.** Do not ship a secret gate inside a publicly downloadable artifact. If the binary must remain public, it must hold no capability on its own — the message it protects has to be authorized server-side.

**The transferable part, and it is the general form of the trap in §1.5:** *the constants adjacent to a prompt look like a credential and are not one.* The adjacency heuristic that this repository already documents for a key and its IV is exactly right — and it was **also** what made me confident here, where the adjacent bytes were four independent patterns and the missing fact was the length constraint one function away. The discriminator that resolved it was not another look at the constants: it was **the call site's argument shape** — four regex objects and a `cmp 0xd`, where a value comparison would have been a `strcmp`.

### 4.2 Unrestricted local file inclusion — CWE-98 (CWE-22), bytes returned

**The sink, verbatim** (`/var/www/subdominio/experiments.php`):

```php
// Verificamos si el parámetro 'module' está presente en la URL.
$module = isset($_GET['module']) ? $_GET['module'] : 'default';
// Creamos la ruta completa del archivo a incluir, sin directorio base ni restricciones.
$filePath = $module;
if (file_exists($filePath)) {
    include($filePath);
} else {
    echo "<h1>Modulo no encontrado</h1>";
```

`$filePath` is `$module` with no `basename()`, no `realpath()` containment check, no allowlist, no suffix. The comment above it states the omission in prose — which is exactly §7's "comments mark where the author *admitted* a problem, a strict subset of where the problems are", and I verified reachability independently rather than trusting the comment.

**The three-way split, measured rather than assumed** (this is the existing LFI section applied):

| capability | test | result |
|---|---|---|
| **open** the file | `module=/etc/passwd` | file exists, `include` runs |
| **act as an oracle** | `module=/etc/definitely-not-here-7q4x2p` | `200`, 99 bytes, "Modulo no encontrado" |
| **return the bytes** | `module=/etc/passwd` | **200, content returned** — `root:x:0:0:root:/root:/bin/bash`, `daemon:x:1:1:…` |

**This is exfiltration, not an existence oracle.** The three states separate cleanly, which is what makes the finding decidable: a known-present file with **known content** (the app's own `modules/default.php`, whose text I had already read out of the image) returned its rendered bytes, and a provably-absent path returned a different, distinct body. Same status code, different bodies — so the two states were genuinely separated and not a costume.

**Root cause.** The value reaches `include()` unfiltered. Note what is *not* the root cause: `open_basedir` is unset, but that is a defence-in-depth absence, not the bug. Patching `open_basedir` alone would leave the parameter reaching `include()`.

**Remediation.** An explicit allowlist of module identifiers, resolved through `basename()` and compared against that list before the include; `allow_url_include=Off` retained; and `open_basedir` set to the document root as a second layer. The remediation must address *reaching* an unintended file — it does not address §4.3, which is a different bug with a different fix.

### 4.3 Attacker-controlled data reflected into a log that is then executed — CWE-117 **and** CWE-98, as two findings

This is the lab's third stage, and it is genuinely two defects with two remediations. Merging them is how a reviewer fixes one and ships.

#### 4.3.1 Log injection — the reflected data reaches a log file unsanitised (CWE-117)

A request path longer than the filesystem's 255-byte filename limit is rejected by Apache with `errno 36 (File name too long)` and the **URL-decoded** path is written to `/var/log/apache2/error.log`. Attacker-controlled bytes therefore land in a persistent server-side file.

**Which field, and why that one.** The obvious field is `User-Agent`, and on this target **it is correctly blocked** (§6.1). The field that works is **the request path, and specifically the `%U` token of Apache's error-log format** — the *escaped* path, as opposed to `%r`, the raw request line, which the access log uses. That single difference in one directive is the whole finding:

```
/etc/apache2/apache2.conf:213  LogFormat "%h %l %u %t \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i\"" combined
```

`combined` logs `%r` — the request line verbatim, which cannot contain a newline. The **error** log has no `ErrorLogFormat` directive, so it uses Apache's built-in default, which is built on `%m%U%q` — and **`%U` is the unescaped path**. Same request, two log files, two different field choices, and only one of them decodes `%0a` into a real byte.

**Impact.** Any data an attacker can route into `%U` is persisted server-side, unsanitised, in a file the web process can read. That is a log-forgery primitive on its own, independent of any file-inclusion bug: it is the ability to write arbitrary lines into a server audit trail.

**Root cause.** A log format that renders attacker-controlled input in decoded form, with no output-side neutralisation of control characters.

**Remediation.** Sanitise at the sink: set an explicit `ErrorLogFormat` built on the raw request line rather than `%U`, and neutralise CR/LF in any field an attacker can reach. **This fix alone does not close the chain** — see 4.3.2.

#### 4.3.2 The included log executes whatever was written into it (CWE-98 → code execution)

Combined with §4.2, including that log file runs its contents as PHP. **The evidence that the injected code executed** — not that the log changed:

```
$ # 1. inject, with a run-scoped nonce
$ printf 'RUNW67PBrFK=uid=33(www-data)' is the marker this run wrote
$ curl -s -o /dev/null -H 'Host: <internal>' "http://172.17.0.9/QJ<?php echo \"RUNW67PBrFK=\".trim(shell_exec(\"id\")); ?>" + 'a'*250
  inject http=403
$ # 2. include the log
$ curl -s -H 'Host: <internal>' "http://172.17.0.9/experiments.php?module=/var/log/apache2/error.log"
  http=200 bytes=31055
$ # 3. the marker, carrying the executing identity, in the HTTP RESPONSE BODY
RUNW67PBrFK=uid=33(www-data)
RUNW67PBrFK=uid=33(www-data)
```

**Why this is the required proof and not the weaker one.** "The log changed" is not evidence of execution, and a known-answer payload would be evidence of a payload I already knew. The marker is a **nonce generated in this run**, absent before the run, and it is read back in a **different channel** — the response body of a second, unrelated request. It appears twice because Apache quotes the path twice in the same entry (once in `access to …`, once in `filesystem path …`). The first command inside the new primitive was `id`, and its answer is a finding in its own right (§8): **`uid=33(www-data)`, not root.**

**The permission link, measured as the identity that does the include** (the control almost nobody applies):

| identity | bytes read from `/var/log/apache2/access.log` | error |
|---|---|---|
| `root` | 60 | none |
| `www-data` | **60** | none |

Identical. The chain's weakest link — *is the log readable by the process that includes it* — **holds**, and the reason is the one in §1.1: `www-data` is in group `adm` and the files are `-rw-r----- root:adm`. Had the include run as an account outside `adm`, the primitive would have returned a broken include, and that is a failure mode that **reads exactly like a dead log-poisoning vector**.

**Root cause.** Two independent defects joined: a log the web process can read, and a file-inclusion sink with no allowlist. **Neither is sufficient alone** — the injection without the include is log forgery, the include without the injection is inert.

**Remediation.** Fix §4.2's allowlist — that alone closes this chain. Then, independently: store logs outside any path reachable by the application, and never `include()` a path derived from user input.

### 4.4 An unprivileged web user is granted a NOPASSWD helper that discloses a secret — CWE-250 / CWE-522

**The rule, verbatim from the target:**

```sudoers
User www-data may run the following commands on 07fcd4f3bd9a:
    (nova : nova) NOPASSWD: /opt/password_nova
```

**The helper**, `-rwx--x--x 1 root nova 400 /opt/password_nova` — 400 bytes, **unreadable even by its own owning group** (`nova` has `--x`, not `r`). It prompts, reads a password on line 9, and on a match discloses a second secret and exits. Literal output on success:

```
Contraseña correcta, mi contraseña es: [24-char secret, sha256 0800d00c…]
```

**Two findings, and the second is the one that is easy to miss.**

1. **CWE-250 — unnecessary privilege.** The web-server identity is granted passwordless execution of a root-owned helper. The sudoers rule is *properly scoped to one binary* (§6.4), which is the control that keeps this at "a secret dispenser" rather than "a root shell" — but the grant itself is a privilege decision made on behalf of a component that has no business making one, and a web process is one RCE away from triggering it.
2. **CWE-522 — insufficiently protected credentials.** The helper's entire purpose is to print a secret to its caller. Its gate is a **9-character common password** (sha256 `22b2f5d0…`) which its own prompt advertises as being in a well-known wordlist. So the secret is protected by a credential that is (a) drawn from a published list and (b) **disclosed on screen in the very prompt that asks for it**. Any principal who can reach the helper gets the secret.

**Root cause.** A "verify the operator" helper written as a wordlist-checked gate in front of a hardcoded secret, and then wired into `sudoers` for the web user.

**Remediation.** Delete the helper and the sudoers grant. If a secret must be distributed, it is not distributed through a world-executable binary gated by a guessable password.

**The finding that is *not* here, and this is the honest part.** I did not find a privilege escalation. The disclosed secret **does not authenticate to any account on this host** — I tested it against both non-root accounts via `su` under a PTY and both returned `Authentication failure` (§8.2). So the chain terminates at `uid=33(www-data)` and this finding is a *dead end that discloses a secret*, not a step in an escalation.

### 4.5 `/root` is mode 755 — CWE-732

`drwxr-xr-x 1 root root 4096 /root`. Debian's default is `700`. As `www-data` the directory **is listable**, and its contents are Parrot desktop defaults; `.ssh` is `700` and correctly refused:

```
/root: ENTERED          (www-data)
/root/.ssh/: Permission denied
/home/maci: denied      /home/nova: denied
```

**Impact.** Every file in root's home that is not separately restricted is disclosed to any local account. Here that set happens to be KDE configuration and dotfile boilerplate, so **no credential was recovered** — but that is luck, not design, and the same mode on a different host exposes root's history, tokens and `~/.aws`.

**Root cause.** An image built from a desktop base that was never hardened; `chmod 700 /root` was not applied.

**Remediation.** `chmod 700 /root`, and assert it in the image build.

### 4.6 Session directory is world-writable and holds a stale session — CWE-732 (low)

`/var/lib/php/sessions` is `drwx-wx-wt root root` (mode `1777`, sticky) and contains a pre-seeded session owned by `www-data` with content `clicks|i:12;`. Confirmed writable by the identity under test (`www-data` → `WRITE_OK`). PHP's own default here is `1777`, so the sticky bit limits cross-user deletion and this is **low severity**; it is filed because a stale session file in a world-writable directory is a persistence surface, and because the file's content (`clicks`, a counter the front-end JavaScript also tracks) is unexplained by any code in the image.

---

## 5. Log poisoning: the criterion, not the payload

The technique is 20 lines long and is in every cheat sheet. What is not written down anywhere is **how to choose the field, and what to check before you claim it works.** This is the section I would want in my own hands on a real engagement, so it is written as criteria.

### 5.1 The objective is a newline, not code

A log injection is the insertion of a **line break** into a log. Everything else — the payload, the execution — is supplied by whatever *reads* the log later. So:

> **A `\n` in a `User-Agent` or in a login URL is a log injection on its own, whether or not any LFI follows.**

And the corollary, which is the part that decides how you file it: **they are two findings with two remediations.** The newline is fixed at the *input* or the *log format* (sanitisation, CWE-117). The execution is fixed by *not including log files* and by fixing the inclusion sink (CWE-98). A report that files one and leaves the other open will be closed, and the chain will still work.

### 5.2 You must control a whole line, and the break must land in a line something interprets

Two conditions, and the second is the one that is usually assumed rather than checked:

1. the attacker controls a **complete line**'s worth of the target's log format, and
2. the break **falls inside a field that is rendered**, so the remainder of the attacker's data becomes line *n+1* rather than staying inside a quoted field on line *n*.

**This is why the field choice is the finding.** `User-Agent` is the usual answer because it is a field where the attacker controls the raw value *and* where it is rendered last, unquoted-adjacent, at the end of the line. On this target that field is **correctly rejected** (§6.1) — the reason is a general one, not a lab quirk: **a header cannot carry a raw CR/LF, because accepting one is request smuggling.** Any HTTP server that lets you put a newline in a header has a worse bug than log injection.

So on a real target the productive question is not *"which header?"* but **"which log field renders attacker data, and in what form?"** The answer here was neither a header nor the access log: it was **`%U` in the error log's default format**, which is the *unescaped* path, while the access log's `combined` format uses `%r`, the *raw* request line. Two directives, same request, and only one of them decodes the attacker's `%0a` into a byte.

**Record what you chose and why the others were rejected, with the reason.** A rejected field with a reason is knowledge; a field you never tried is indistinguishable from a field that does not work.

### 5.3 The control almost nobody applies: the log must be readable **by the process that includes it**

The chain has two independent permission requirements, and they are on **different files**:

- the *writer* must be able to append to the log, and
- the *includer* must be able to **read** it.

A break in the second is the nastier one, because **it presents as a broken include**, which is byte-for-byte what a dead log-poisoning vector looks like. You get an empty response, a PHP warning, and no output — and the natural conclusion is "the vector is blocked", when in fact the vector is fine and the *permissions* are wrong.

So measure **both** ends, and measure the reader **as the reader**:

| | writer side | reader side |
|---|---|---|
| who | `www-data` (the request) | `www-data` (the include) |
| how to check | append a line, read it back | read the same file as that identity, compare against another identity |

And read the file as the identity rather than parsing the mode string. Here the mode said `-rw-r----- root:adm` and the truth was that `www-data` **is in group `adm`** and reads it byte-identically to root. A mode-bit reading would have retired a working third stage and reported a control that does not exist.

### 5.4 The negative you have to test: the log changed is not proof of execution

This is the failure the whole section exists to prevent. Three progressively stronger oracles:

1. **"The log contains my string"** — worthless on its own. It proves the injection landed and nothing else.
2. **"The response changed"** — worthless. A different error, a different length, an extra warning, all look identical to execution.
3. **"A marker I generated in this run, which did not exist before it, came back in a different channel, carrying the identity that ran it."** — this is the one. The marker must be a **nonce**, not a payload you already knew, and it must be read back over a **different request** than the one that wrote it.

**Positive control for the detector itself.** Before believing the include-based read, force a positive through it: include a file whose contents you already know (here, the app's own `modules/default.php`, 963 bytes of known text) and require the known bytes back. An LFI read endpoint that returns `200` proves nothing on its own; a read endpoint that returns *the bytes you predicted* is connected to the filesystem.

### 5.5 The operational risk, which is why this belongs in a report and not in a default playbook

**Writing to the target's logs is destructive if those logs are an audit trail or a compliance record.** Poisoning an Apache access log to gain execution silently corrupts the evidence of the very incident you are the first responder to. In an engagement that is **a decision taken with the client, in scope, before you do it** — not a technique you execute by default because the tutorial says so.

In a disposable lab it is free. In production, a single poisoned log line is a spoliation event, and the operator who wrote it may be the one who has to explain it.

The transferable practice, which costs nothing:

- **Prefer a vector whose write is already routine.** The long-path rejection used here is a response the attacker triggers thousands of times a day, so the injected line is statistically indistinguishable from the noise around it. A vector that writes a *unique, recognisable* line into a quiet log is one that will be noticed — and noticed by the person reading it.
- **Know which log you are about to write to** — is it shipped, retained, or under a retention hold? If yes, that is a conversation, not a keystroke.
- **State it in the writeup as a risk you accepted and why.** An engagement record that does not say "this step writes to the target's logs" leaves the next person unable to judge whether it was acceptable.

---

## 6. Controls that held (each with its positive control)

Reporting a control that held with the same prominence as a bug that fired: a reader cannot distinguish an untested control from a holding one.

### 6.1 Apache rejects an embedded CR/LF in a request header — `400`

```
raw socket, User-Agent: "inject-probe\nINJECTED-RAW-SOCKET-9f2a"  → HTTP/1.1 400 Bad Request
```
**Positive control:** the same raw-socket client sending a well-formed request returns `200`. So the `400` is the target's parse-time refusal, not my framing. **This is the control that killed the textbook vector**, and it is a real one: accepting a newline in a header is request smuggling.

### 6.2 Apache escapes control characters in log fields — `%0a` becomes a literal `\n`

A path containing `%0a` produces a log entry holding a **literal backslash-n**, not a byte `0x0a`. Verified at byte level, not by grep:

```
$ od -c | cut -c1-90
…   F i l e   n a m e   t o o   l o n g   :   [ c l i e n t   \ n
```

**Positive control:** in that *same* log line, every printable byte of the payload — `<?php echo "…" ; ?>` — survived verbatim. So the escaping is selective (control characters only) and the detector is measuring the right thing. **This control and §4.3.1 are the same mechanism seen from two sides:** escaping is why the canonical newline injection fails, and the *unescaped* `%U` field is why the payload still lands.

### 6.3 The `file_exists()` gate blocks stream wrappers and unreadable files

| request | result | reading |
|---|---|---|
| `module=/etc/hostname` | `200`, **13 bytes** | positive control: the read primitive works |
| `module=/opt/password_nova` | `200`, **0 bytes** | `--x--x--x` — no read bit, so `include` cannot open it |
| `module=http://127.0.0.1/etc/hostname` | `200`, "Modulo no encontrado" | wrapper is not a real path, and `allow_url_include=Off` |

The `--x--x--x` case is the interesting one: `file_exists()` returns **true**, the branch is taken, and the include still yields nothing. So the *gate* passing is not the same as the *read* succeeding — the three-way split in §4.2 again, and the reason I could not read the helper through the LFI and had to obtain its source a different way.

### 6.4 The sudoers allowlist is scoped to one binary

```
sudo -n -u nova /usr/bin/id      → sudo: a password is required
sudo -n -u nova /bin/sh -c id    → sudo: a password is required
sudo -u nova /opt/password_nova  → runs (discloses a secret)
```

**Positive control:** the one allowed binary works in the same breath, same `sudo -u nova`, same identity. The allowlist cannot be walked by naming a different program, which is what keeps §4.4 a secret disclosure rather than a root shell. Note the rule grants *no* argument restriction, so `sudo -u nova /opt/password_nova <args>` is permitted — but the helper ignores its arguments and reads only stdin (confirmed in §8.1), so there is no argument-injection sink behind it.

### 6.5 Two non-root accounts, and the disclosed secret opens neither

`maci:x:1000` and `nova:x:1001`, homes both `700`. The secret disclosed by §4.4's helper authenticates to **neither** — see §8.2. Reported because a chain that reaches a credential dispenser and stops there should say so, with the reason, so the next engagement does not spend the same hour.

---

## 7. Chain integrity: what is proven vs what is carried by a weaker link

| hop | evidence class | strength |
|---|---|---|
| binary → vhost name | behavioural: the binary printed it, `base64 -d` produced it, and the `Host:` header changed the served document root to a **different hash** | **strong** — two independent channels agree |
| vhost routing | three stable normalised hashes + a provably-absent control | **strong** — the control is what makes it decidable |
| LFI reads bytes | known-content file returns its known bytes; absent file returns a distinct body | **strong** — the three states separate |
| log poisoning executes | run-scoped nonce returned in the response body of a second request, carrying `uid=33(www-data)` | **strong** — the required form |
| log readable by includer | same file read as `root` and as `www-data`, 60 bytes each, identical | **strong** — measured as the identity |
| helper discloses a secret | literal output captured | **strong** for the disclosure |
| secret → an account | **`su` rejected it for both users** | **disproved**, not carried |
| any escalation above `www-data` | **none found** | **absent** |

---

## 8. What I tested, what I did not, what I could not

Three separate lists, because collapsing them is how coverage gets overclaimed.

### 8.1 Tested

- Full TCP surface (`-sV -Pn -p-`), OS, Apache/PHP versions, module list, vhost config, deployed `LogFormat` directives.
- Vhost differential with a provably-absent control and a 3× stability read each.
- Binary: `file`, `nm` import table (KDF/EVP/AES — all zero), `main` and both named functions disassembled, symbol table, `strings`.
- LFI: three-way split, known-content positive control, provably-absent control, wrapper reachability, unreadable-file case.
- Log poisoning: header-field vector, error-log `%U` vector, the 255-byte threshold measured at five lengths, byte-level verification of escaping.
- Privilege: `sudo -l` in full, `id` as the first command in the new primitive, setuid/setgid inventory, `getcap`, world-writable inventory, cron directories, sudoers.d, group-`adm` file inventory, `/root` and both home directories.
- Credential: the helper's gate (top-70 common wordlist) and the disclosed secret against both non-root accounts.

### 8.2 Not tested (with reason)

- **The helper's source was not read as the attacker.** It is `--x--x--x`, unreadable by `www-data` *and* by `nova`. I obtained it through operator access to the image filesystem, which is §7's "read the source" satisfied out of band — **so my statement of the gate logic is source-derived, not attacker-derived, and I flag that rather than implying I read it from the shell.**
- **No UDP scan was possible** on this host (no `nmap -sU` without root, no `ipmitool`). The image declares no `EXPOSE` directive and nothing in the config or process table suggests a UDP service, but this is a **declared coverage gap, not a closed port** — the exact distinction this repository insists on.
- **Password spraying was bounded, not exhaustive.** 70 common passwords against one helper with no rate limiting. I stopped because the helper's purpose is a *gate*, and its real content is only obtainable by satisfying it; had the gate been the intended deliverable, the hint ("in a well-known wordlist") would name the list, not a hash of it.
- **Kernel/container hardening review** (seccomp profile, capabilities, `NoNewPrivs`) was not audited; out of scope for the web-to-shell chain.

### 8.3 Could not test

- Nothing was blocked by tooling. Every primitive ran. The one thing I could not do *from the attacker position* was read the helper (§8.2), and I say which position produced each claim.

### 8.4 Present but not used

- **`session.upload_progress.enabled=On`** with sessions in a `1777` directory. PHP's upload-progress feature writes the multipart **filename** into the session file unsanitised, and the session file is includable by §4.2 — a **second, independent RCE route that does not touch the logs at all.** I identified it and did not use it. Filing it: the log route was sufficient, the upload-progress route is a real finding, and **two independent RCE chains on one inclusion bug are two findings** with the same sink remediation and different causes.
- The 12-byte pre-seeded session file (§4.6) and the `clicks` counter that no code in the image writes.
- `/root`'s world-readable mode (§4.5) — disclosed configuration, no credential recovered.
- `allow_url_fopen=On` with `allow_url_include=Off`: a latent SSRF-grade primitive that `file_exists()` currently forecloses, since a URL is not a real path. Filing it as latent, not as an exposure.

---

## 9. Reward

### 9.1 Exhaustive search

From the attacker position (`uid=33(www-data)`), as root on the image filesystem, and by name and by content:

```
$ grep -rIl -E 'flag\{|FLAG\{|CTF\{|reward' / 2>/dev/null
/usr/share/perl/5.36.0/Pod/Perldoc.pm                     ← incidental doc text
/var/lib/apt/lists/…_non-free_binary-amd64_Packages        ← apt metadata
/var/lib/apt/lists/…_main_binary-amd64_Packages           ← apt metadata
```

Three hits, all incidental. By name, `find / -iname '*flag*' -o -iname '*reward*' -o -iname '*secret*'` returns only `bash-completion` scripts, `man` pages, `tzfile` internals and headers. The full `/var/www` tree is 15 files, all of them the lab's own. `/root` is a stock Parrot desktop home — `.BurpSuite`, `.msf4/config` (a default Metasploit prompt config, 179 bytes), KDE dotfiles, and a `.ssh` that is `700` and correctly refused.

`docker history` shows the image is built from a Parrot base with the lab's PHP files, the binary, the helper and `iniciar` copied in — no reward artifact in any layer.

### 9.2 Conclusion

**No reward exists in this lab.** Tenth consecutive one. I am reporting the absence rather than manufacturing a value, and per this repository's `Impossibility as a valid result` the negative is filed with its evidence and with what *would* have to be different:

- **What was found instead:** `uid=33(www-data)` with arbitrary command execution — a complete compromise of the web tier and the log files, obtained in three hops from an unauthenticated request.
- **What would have to change for a privileged conclusion:** a privilege boundary reachable from `www-data`. The one candidate the lab ships (a sudoers grant to a secret dispenser) is **disproved** at §8.2 — its output authenticates to no account. An escalation vector — a writable file a privileged process executes, a setuid helper with a bounded read, a service credential — would be required, and none is present.

---

## 10. Design observation

**This lab teaches three classes in sequence and gets two of the three teaching points exactly right, which is rare.**

The binary stage is the best-constructed in the series. It is a 2.8 MB statically linked not-stripped C++ binary sitting in a public document root, and the *entry criterion* — look for a KDF — retires it in two commands: zero KDF imports, zero `EVP_*` symbols, no dynamic section. The trap is well designed too. The decoded host name **never appears in `strings`**, so the "grep the binary for the subdomain" move the lab's own description invites returns nothing; the secret is constructed at runtime and base64-printed. And the two most attractive constants in `.rodata` are regex *patterns* sitting next to the prompt, not a password — so the "adjacent literal" heuristic produces a confident wrong answer, and only the **call site** (four regexes, `cmp 0xd`) resolves it. That is `decision-making.md` §7 landing in a symbol table, and it is exactly the shape that makes a reversing stage worth an hour.

The LFI stage is honest and minimal: one parameter, no allowlist, no `realpath()`, and the three states separate cleanly. The source even comments its own omission, which by §7 is an *admission* and a strict subset — I verified reachability anyway.

**The log poisoning stage is the one with a design flaw, and it is instructive.** The stage is built on the textbook field — `User-Agent` — and this target **correctly blocks it**, because a header cannot contain a raw newline without being request smuggling (§6.1). The lab author almost certainly tested the payload with a client that, or a version of the log format that, made it work. What actually works is a *different and much better* finding: a long request path is reflected **URL-decoded** into the error log by `%U`, while the access log's `combined` format uses the raw `%r`. The lab accidentally ships a **better lesson than the one it intended** — the productive question is never "which header?", it is "which log field renders attacker data, and in what form?", and the answer here is a directive difference, not a payload.

**Two design notes for lab authors, both following §7's mirror:**

1. **The third stage does not terminate the chain.** The sudoers grant produces a secret that authenticates to nothing (§8.2). A lab whose escalation stage is a hint dispenser teaches the student that reaching a credential is the same as using it — which is the mistake this repository documents in *a result that survives your first explanation*. Either give the disclosed secret a real account, or make the helper drop a shell, or state plainly in the lab that the objective ends at the web tier. Right now the description's promise of "acceso al sistema" is satisfied at `uid=33`, which is a legitimate result and simply should be labelled as the endpoint.
2. **`/root` at mode 755** on a Parrot desktop base is an unintentional gift. It disclosed nothing here, and a student will spend time on it expecting a flag that is not there. Harden the base or state that the filesystem is clean.
