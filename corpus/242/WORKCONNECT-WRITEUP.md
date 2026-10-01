# 242 WorkConnect — DockerLabs Writeup

**Target:** `http://172.17.0.4:8000` (container `workconnect_container`, image `workconnect:latest`, single container, no compose, no `macvlan`)
**Date:** 2026-09-30
**Outcome:** Unauthenticated RCE as **`uid=1000(recruiter)`**, escalated to **`uid=0(root)`** through a group-writable script that root executes on a 60-second loop. **No reward value** — proven absent as `uid=0`, with counts.
**Headline:** the queue's class label is wrong in a way this corpus has not seen before. It is not a filename mistaken for a fingerprint — **it is not a filename at all.**

---

## 0. The label is a misreading, and it is the finding

| Source | Text |
|---|---|
| Catalogue (`~/dockerlabs/catalog.txt:16`) | `242\|WorkConnect\|medio\|Laboratorio de hacking web que nos permite enumerar los DNIs de la plataforma y reutilizar esa información para continuar con el proceso de intrusión.` |
| Queue (`tooling/labs.manifest:84`) | `242\|WorkConnect\|medio\|enumerating platform DNS records` |
| Artefact | **zero** occurrences of `dns`, case-insensitive, in the whole application tree |

**DNI is not DNS.** `DNI` is *Documento Nacional de Identidad* — the Spanish national identity document number. The catalogue's own sentence is correct and the queue's gap column silently re-expanded the acronym into the wrong protocol. The artefact settles it in three places, quoted verbatim:

```
/opt/workconnect/fuzzer.py:9      PREFIX = "71902"
/opt/workconnect/fuzzer.py:10     TARGET_STRING = "El DNI introducido ya se encuentra registrado"
/opt/workconnect/main.py:32         ("Admin User", "admin@workconnect.com", "71902345A", "SuperSecretAdmin123!"),
/opt/workconnect/templates/register.html:29      <label for="dni">Documento de Identidad (DNI)</label>
/opt/workconnect/templates/register.html:30        <input type="text" id="dni" name="dni" required placeholder="71902....">
```

The enumeration key is a **national identity number**, the UI label says so, and the shipped enumeration tool is named after it. `grep -rIo -i "dns" /opt/workconnect --exclude-dir=venv --exclude-dir=__pycache__ | wc -l` → **`0`**, a count of zero over the whole application tree. This is a measured absence, not an untested one, and §23 applies in reverse: the absence here is a property of the target, because nothing in the image, the `Dockerfile`, the `entrypoint.sh` or the compose surface installs or starts a resolver.

**Consequence for the corpus:** the engagement the queue filed as *first DNS evidence* is the corpus's first **structured-identifier existence-oracle** engagement. That is a real class and it is adjacent to the DNS class, so the transferable material below is written as the DNS class's discipline applied to the thing that is actually there.

### Platform, from version-bearing artefacts

Read before writing a word about the stack, per rule 1. The target is a **bespoke FastAPI application** — no WordPress, no Joomla, no CMS:

| Layer | Value | Source |
|---|---|---|
| Base OS | Debian GNU/Linux 12 (bookworm) | `/etc/os-release` `VERSION_ID="12"` |
| Runtime | Python 3.11.2 | `python3 -V` |
| Framework | fastapi **0.136.1**, starlette **1.0.0**, uvicorn **0.46.0**, pydantic 2.13.3, Jinja2 **3.1.6**, python-multipart 0.0.27 | `pip3 list` inside the artefact |
| Storage | SQLite, file `database.db` | `main.py:13` |
| Declared deps | `fastapi`, `uvicorn`, `jinja2`, `python-multipart` — **no pins** | `requirements.txt:1-4` |
| Image surface | `map[8000/tcp:{}]`, `CMD ["/entrypoint.sh"]`, workdir `/opt/workconnect` | `docker inspect` |

---

## 1. Surface

```
$ nmap -sV -Pn -p- 172.17.0.4
Not shown: 65534 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
8000/tcp open  http    Uvicorn
```

Second instrument, inside the container: `/proc/net/tcp` → **1** listener row, `00000000:1F40` (= 8000), `uid 1000`. So `-p-` and the kernel agree, and the listener's owning uid is the app's own.

**UDP — the surface a TCP scan cannot see, measured rather than assumed.** `nmap -sU` refused to run here (`You requested a scan type which requires root privileges`), so the UDP negative does **not** rest on it:

```
$ cat /proc/net/udp | wc -l        → 1        (header only ⇒ 0 sockets)
$ cat /proc/net/udp6 | wc -l       → 1        (header only ⇒ 0 sockets)
$ cat /etc/resolv.conf             → nameserver 192.168.100.1   (injected by the Docker engine, not a lab service)
```

Zero UDP sockets, zero resolvers, one declared TCP port. This is the count that retires the DNS class for this target.

---

## 2. The class: an existence oracle over a structured identifier

### Entry criterion

> Does an unauthenticated request return a **distinguishable** answer for "this identifier is already taken", and is the identifier's namespace **closed enough to enumerate**?

**Source that settled it** — `main.py:69-73`, quoted verbatim:

```python
    # Vulnerability: explicit check for DNI existence
    c.execute('SELECT * FROM users WHERE dni = ?', (dni,))
    if c.fetchone():
        error_msg = "El DNI introducido ya se encuentra registrado en nuestra plataforma."
        return templates.TemplateResponse(request=request, name="register.html", context={"error": error_msg})
```

The developer's own comment names it. The oracle is in-band, in the response body, on an unauthenticated `POST /register`.

### The control pair, in both directions

A presence/absence detector has exactly one failure mode that matters: **it answers the same thing for everything.** That is the DNS wildcard, in a different costume. If every identifier answers PRESENT, the "found" count is the query count and the enumeration is worthless. So the pair runs first, and it must contain one name that **cannot exist** *in the target's own namespace* and one that **cannot exist at all**:

| Control | Identifier | Verdict | HTTP | Bytes | Marker |
|---|---|---|---|---|---|
| **Positive** (must fire, or every negative below is untrusted) | `71902345A` | `PRESENT` | 200 | **2268** | `ya se encuentra registrado` |
| **Negative A** (right shape, outside the target's namespace) | `00000000T` | `ABSENT` | 200 | **1332** | `Registro completado` |
| **Negative B** (right namespace, format-impossible) | `99999999X` | `ABSENT` | 200 | 1332 | `Registro completado` |

The harness **refuses to sweep** if the positive control does not return `PRESENT` or the negative control does not return `ABSENT` — it exits 2 with the reason. It fired for real during this engagement; see Instrumentation defect **I2**.

### The sweep, closed, with the work count

`evidence/dni_sweep.py`, 20 workers, full keyspace of the advertised tool:

```
# POSITIVE CONTROL  dni=71902345A -> PRESENT  http=200 bytes=2268 present_marker=True absent_marker=False
# NEGATIVE CONTROL  dni=00000000T -> ABSENT  http=200 bytes=1332 present_marker=False absent_marker=True
# oracle green in both directions; control byte sizes recorded above
HIT 71902223C  http=200 bytes=2268
HIT 71902345A  http=200 bytes=2268
HIT 71902565I  http=200 bytes=2268
HIT 71902678E  http=200 bytes=2268
# ------------------------------------------------------------------
# WORK COUNT: candidates submitted = 26000  (numbers 000-1000 x 26 letters)
# WORK COUNT: requests actually completed = 26000
# WORK COUNT: elapsed 135.6 s  rate 191.7 req/s
# VERDICTS: PRESENT=4  ABSENT=25996  INDETERMINATE=0
# RESPONSE SIZES: ABSENT -> [1332]  PRESENT -> [2268]
# FOUND: 4  -> 71902223C, 71902345A, 71902565I, 71902678E
```

**Reading the `000-1000` in that log line.** It is an **exclusive** upper bound, not an
inclusive one: the harness iterates `for i in range(a.lo, a.hi)` with `hi` defaulting to
`1000` (`evidence/dni_sweep.py:65,101`), so the numbers actually submitted are `000`–`999`,
i.e. **1 000 × 26 = 26 000** candidates. Read inclusively the same line would say 26 026,
which the `candidates submitted = 26000` on the line above it disproves. The label the
harness prints is inclusive in appearance and exclusive in fact; the count is the ground
truth.

The negatives are evidence, not a blind spot, for three independent reasons:

1. **The response-size set is a partition, not a spread.** Every one of the 25,996 ABSENT responses was exactly **1332** bytes and every one of the 4 PRESENT responses exactly **2268** bytes — a 936-byte delta, two disjoint singleton sets, **0** `INDETERMINATE`. An oracle that had degraded to a constant answer could not produce two disjoint size classes.
2. **The count closes against an independent source.** 26,000 submitted = 4 + 25,996, and the 4 found are exactly the 4 rows the artefact seeds (`main.py:32-35`).
3. **Coverage is against the artefact, not assumed.** The keyspace is 1,000 numbers × 26 letters = 26,000, which is the whole of what `fuzzer.py:40` generates. Nothing was truncated.

The sweep was run **twice, independently**, from a restored image, with identical results both times (191.7 req/s and 184.2 req/s; 4 found; 0 indeterminate).

### The lesson that generalises past this lab: a check character is a property of the *issuer*, not of the *store*

A Spanish DNI carries a public check character: letter = `"TRWAGMYFPDXBNJZSQVHLCKE"[number mod 23]`. So the keyspace can be cut from 26,000 to **1,000** — if the target validates it. Measured, both ways:

```
-- the four ORIGINAL accounts, check character recomputed from the public DNI algorithm --
   71902345A mod23= K shipped= A VALID= False
   71902223C mod23= Z shipped= C VALID= False
   71902678E mod23= D shipped= E VALID= False
   71902565I mod23= B shipped= I VALID= False
   valid originals: 0 of 4
```

**0 of 4.** And the sweep itself supplies the second half of the proof: for the one number that was already registered, the sweep submitted all 26 letters and **25 of the 26 rows were created by the sweep** (`origin=dni_X@probe.invalid`), including the one that *is* the correct check character. The schema does not validate the field's format at all — `main.py:23` is `dni TEXT NOT NULL UNIQUE`, and nothing between the `Form(...)` and the `INSERT` inspects it.

> **An enumerator who filtered the keyspace by the official check character would have submitted 1,000 candidates, found 0 of 4 accounts, and reported the namespace empty.** The filter is a statement about the *issuer's* policy, not about the *store*, and the store declined to enforce it.

This is the corpus's existing "prevents vs detects" rule (lab 283) with the polarity flipped, and it is the exact analogue of a DNS lesson: **an `ANY` query refused is not the same as no `TXT`, and a resolver that refuses recursion tells you about the resolver, not the zone.** A check character the target does not enforce tells you about the *format's designer*, not about the *records that exist*. Never let a format assumption shrink a keyspace until the target's own validation of that format has been measured — with a positive control, in the direction where the format is *accepted*.

### The artefact's own list of "found" names is 60% phantom

The image ships `dnis_encontrados.txt` — the developer's enumeration output — and it is wrong:

```
listed= 10   in_db= 4
71902121G exists_in_db= False
71902223C exists_in_db= True
71902343H exists_in_db= False
71902345A exists_in_db= True
71902565I exists_in_db= True
71902654B exists_in_db= False
71902667D exists_in_db= False
71902678E exists_in_db= True
71902787J exists_in_db= False
71902887F exists_in_db= False
```

6 of 10 names in the shipped "found" list do not exist. This is labs 87 and 188 in a new costume — a first sweep that reports records that are not there — except here it is **pre-loaded into the image**, so a tester who reads it before sweeping inherits six phantom findings and, worse, a plausible-looking keyspace hint. The rule is the corpus's own: *the artefact's list is not a measurement, and a hit you have not read is not a record.* The counter-rule applies with equal force: a list of 10 that intersects the store in 4 is not evidence that 6 records were deleted; it is evidence the list is stale.

---

## 3. Chain

No hop depends on a credential. The advertised enumeration step is a **measurement**, not the entry path — see finding **F4**.

| # | → | Mechanism | Identity proof, verbatim |
|---|---|---|---|
| 0 | unauthenticated HTTP | `POST /dashboard/update-profile` — handler carries no `Depends`, no session, no token (`main.py:107-113`); the form that reaches it has no CSRF field (`dashboard.html:220-251`) | `Set-Cookie` count = **0** across `GET /`, `/login`, `/register`, `/dashboard` |
| 1 | `uid=1000(recruiter)` | CWE-78, `main.py:122-123` — `cmd = f"curl -I -s {photo_url}"` into `subprocess.check_output(..., shell=True)`, output reflected in-band at `dashboard.html:263` | from the injected process's **own** `/proc/self/status`: `Uid:	1000	1000	1000	1000` · `Gid:	1001	1001	1001	1001` · `Groups:	1000 1001` · `CapEff:	0000000000000000` — **no setuid transition** |
| 2 | `uid=0(root)` | CWE-732, group-writable script executed by root on a loop — `Dockerfile:40-42` (`chown root:humanresources /opt/backup.py`, `chmod 664`) + `entrypoint.sh:6-9` (`python3 /opt/backup.py` as root, every 60 s) | **manufactured oracle**: `/opt/backups/DL242-ROOT-ORACLE-1790801532-a91c.proof`, `owner=root:root mode=644 size=55`, contents `DL242-ROOT-ORACLE-1790801532-a91c uid=0 euid=0 egid=0` |

**Control for hop 2, in the other direction, same path, same identity:**

```
touch: cannot touch '/opt/backups/DL242-CONTROL-SHOULD-FAIL.proof': Permission denied
ls: cannot access '/opt/backups/DL242-CONTROL-SHOULD-FAIL.proof': Permission denied
```

Both fired, from `uid=1000`, against the exact directory the root-run script then wrote into (`Dockerfile:45-47`: `chown root:root /opt/backups`, `chmod 700`). The witness is distinguishable **by design**, not by timestamp luck: the low-privilege identity provably cannot create anything there, so a file appearing there can only have been created by the root loop.

**In-band, so no blind oracle was needed** — the reflection at `dashboard.html:263` is `<pre>{{ cmd_output }}</pre>`, and the response size carries the verdict:

| Request | HTTP | Bytes | `uid=` lines in body |
|---|---|---|---|
| control, no metacharacter: `photo_url=http://127.0.0.1:9/` | 200 | 8310 | **0** |
| treatment, one `;` added: `photo_url=http://127.0.0.1:9/;id;#` | 200 | **9016** | **1** → `uid=1000(recruiter) gid=1001(recruiter)` |

`port 9` is chosen because it is closed on loopback: `curl` fails instantly, so the request cannot deadlock the target (see **F6**, where it does).

---

## 4. Findings

### F1 — CWE-204 / CWE-200: unauthenticated account-existence oracle
`main.py:69-73`. One unauthenticated `POST /register` returns a distinct, human-readable body for a taken DNI versus a free one — 2268 B vs 1332 B, disjoint, no rate limit (191.7 req/s sustained for 135.6 s, **0** refusals in 26,000 requests). The namespace is bounded and enumerable: **26,000 candidates, 26,000 completed, 4 accounts, 135.6 seconds.** Impact: full enumeration of the user base pre-auth, plus a reliable oracle for every other identifier predicate the store adds later. Fix: do not disclose existence in the response body; return one indistinguishable response for both cases and send the conflict to the address the account was registered with.

### F2 — CWE-778 + CWE-400: the enumeration oracle is *destructive*, and the destruction is unauthenticated
`main.py:77` — the negative branch of the oracle is an `INSERT`, not a read:

```python
        c.execute('INSERT INTO users (name, email, dni, password) VALUES (?, ?, ?, ?)', (name, email, dni, password))
```

Measured row counts immediately after the sweep:

```
users_count_after_sweep= 26001
original_seeds= 4
created_by_sweep= 25997
```

Arithmetic closes: 4 seeds + 25,996 sweep negatives + 1 negative control = **26,001**; 25,997 probe-created = 25,996 + 1. So **25,997 accounts were created by 25,997 unauthenticated POSTs**, with no rate limit, no CAPTCHA, no email verification, and no email uniqueness constraint. Impact: mass fake-account creation against a real identity namespace — a store keyed on national ID numbers now holds 25,997 attacker-chosen ones, which is also a durable supply of known-credential logins (each inserted with the attacker's chosen password, see F3). Fix: separate the uniqueness check from registration; a `409` that leaks nothing plus a verification step closes both F1 and F2.

### F3 — CWE-256: passwords stored and compared in cleartext
Schema, `main.py:19-25`: `password TEXT NOT NULL` — no hash, no salt, no KDF. Seeded values, `main.py:32-35`:

```
("Admin User", "admin@workconnect.com", "71902345A", "SuperSecretAdmin123!"),
("Maria Garcia", "maria@workconnect.com", "71902223C", "Maria2026"),
("Target User", "target@workconnect.com", "71902678E", "chocolate"),
("David Sanchez", "david@workconnect.com", "71902565I", "Dav2025*")
```

Login compares in cleartext, `main.py:95`: `c.execute('SELECT * FROM users WHERE dni = ? AND password = ?', (dni, password))`. Impact: any read of the database — the enumeration path alone does not grant one, but F2 guarantees the table is being written to by strangers and F1 guarantees the schema is knowable. Fix: `argon2`/`bcrypt` at rest, `verify()` at login, and a migration path for the 4 cleartext rows.

### F4 — CWE-287 / CWE-306: authentication is not implemented; the login is decorative
This is the most consequential finding and it reframes the advertised chain. `login_post` (`main.py:87-101`) does exactly one thing on success — `return RedirectResponse(url="/dashboard", status_code=status.HTTP_302_FOUND)` (`main.py:99`) — and **sets no cookie**:

```
$ for p in / /login /register /dashboard; do curl -sD- http://172.17.0.4:8000$p | grep -ci 'set-cookie'; done
  GET / set-cookie lines: 0
  GET /login set-cookie lines: 0
  GET /register set-cookie lines: 0
  GET /dashboard set-cookie lines: 0
```

`dashboard_page` (`main.py:103-105`) and `update_profile` (`main.py:107-113`) carry no `Depends`, no session check, no token. Anonymous `GET /dashboard` returns **200, 8291 bytes** and renders the victim's own identity, because the template hardcodes it (`dashboard.html:224` `value="Target User"`, `dashboard.html:228` `value="target@workconnect.com"`).

> **Therefore the enumeration the catalogue advertises is not the intrusion path.** The correct account is: the DNI enumeration is a real, complete, unauthenticated measurement of the user base (F1) — and the "reutilizar esa información para continuar con el proceso de intrusión" step is unnecessary, because there is nothing to reuse. Anyone who plays the advertised game — enumerate, log in, then look for the injection — will find the injection sitting on an endpoint they never needed a credential for, and may credit the wrong hop.

Login still works as an oracle (200/1855 B failure vs 302/0 B success, positive control fired before the rate ladder, after all **60** ladder attempts, and again after the 1,000-candidate spray), so this is filed as **missing authentication**, not as a broken login. Fix: a server-side session; the redirect is not one.

### F5 — CWE-78: unauthenticated command injection, in-band
`main.py:120-123`:

```python
        try:
            # Ejemplo de comando: curl -I -s http://ejemplo.com/foto.jpg
            cmd = f"curl -I -s {photo_url}"
            result = subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.STDOUT)
```

No quoting, no `shlex`, no allowlist, no URL parse. `photo_url` is a `Form(...)` field of an unauthenticated POST. Output is returned to the caller at `main.py:129` → `dashboard.html:263`, so this is in-band and needs no collaborator. Control/treatment differ by **one character** (`;`) and 706 response bytes. Impact: full RCE as the service identity. Fix: `curl` is the wrong tool for a user-supplied URL — fetch with a library, validate the scheme, resolve and pin the address against an SSRF denylist, and drop the shell.

### F6 — CWE-400: one unauthenticated request wedges the whole application permanently
Not advertised, and the most interesting of the six. The handler at `main.py:108` is `async def`, and `main.py:123` blocks the event loop on a subprocess whose destination is **the app's own listener**. With the default `photo_url=http://127.0.0.1:8000/`, the request never returns and the single uvicorn worker never serves again:

```
$ POST /dashboard/update-profile  photo_url=http://127.0.0.1:8000/
  (no response; client -m 6 → http=000)
$ ps -eo pid,etimes,args | grep '[c]url -I'
    133     148 /bin/sh -c curl -I -s http://127.0.0.1:8000/
    134     148 curl -I -s http://127.0.0.1:8000/
$ GET /            → http=000 bytes=0 time=6.00   (app dead)
$ GET /dashboard   → http=000 bytes=0 time=6.00   (app dead)
$ POST /dashboard/update-profile (second, different payload) → http=000 time=6.00
```

`148` seconds and still wedged; `curl` carries no `--max-time`, so there is no natural release. This is `method/self-corrections.md` §3 — *the harness is the outage* — reproduced in a shipped product: the tool the handler invokes is aimed at the process the handler is blocking. I recognised it only because the process table showed a `curl` child of the app's own worker, and I had a positive liveness check (`GET /` = 200/1479 B) to compare against. Fix: `await asyncio.create_subprocess_exec(...)` with per-argument timeouts and a hard cap, and never let a request parameter name a loopback destination.

### F7 — CWE-732: group-writable script executed by root
`Dockerfile:38-42` and `entrypoint.sh:5-9`, quoted:

```
RUN cp /opt/workconnect/backup.py /opt/backup.py && \
    chown root:humanresources /opt/backup.py && \
    chmod 664 /opt/backup.py
```
```
# Backup loop: runs /opt/backup.py every 60 seconds as root in the background
while true; do
    python3 /opt/backup.py >> /var/log/backup.log 2>&1
    sleep 60
done &
```

Measured on the target: `/opt/backup.py root:humanresources 664`, and `recruiter` is in the group — `groups=1001(recruiter),1000(humanresources)` from the injected process, `humanresources:x:1000:recruiter` from `/etc/group`. Any write into that group is code execution as root on the next tick, forever, with no log line of its own. Impact: the escalation in §3. Fix: the group needs read, not write — `root:humanresources 0440` — and a root-run unit that executes a file no unprivileged principal can modify.

### F8 — CWE-352: no CSRF token on the only state-changing form
`dashboard.html:220-251` — the form carries `full_name`, `email`, `bio`, `photo_url` and no token of any kind; `grep` for `csrf`/`token` in the template returns nothing beyond the CSS. Moot in practice while F4 stands (there is no session to ride), and it is listed separately because fixing F4 without this re-opens it: a logged-in `recruiter` would then be one click from F5. Fix: a per-session token validated before the handler body.

### Lab-design defects (the artefact's problems, not the tester's)

- **D1 — the queue's class label is a re-expansion of an acronym.** `DNIs` → *"DNS records"*. The catalogue sentence is right; the gap column is wrong. §Rule 1 of the brief generalises: a class label is not a fingerprint, and here it is not even a filename.
- **D2 — the shipped enumeration tool cannot run on the shipped image.** `fuzzer.py:1` is `import requests`; `requirements.txt:1-4` is `fastapi, uvicorn, jinja2, python-multipart`; inside the artefact, `python3 -c "import requests"` → `ModuleNotFoundError: No module named 'requests'`. The lab ships the instrument for its own advertised step and omits its dependency. §23's rule, pointed the other way: the advertised step is not merely unexploited, it is **unexecutable by the lab's own means**, which is a different statement and a different finding.
- **D3 — the shipped tool's docstring is wrong by 100×.** `fuzzer.py:36` says *"Como son 2.6 millones de combinaciones"* and describes "719 + 5 dígitos + 1 letra"; `fuzzer.py:40` is `for i in range(0, 1000)` formatted `%03d` and `fuzzer.py:42` iterates 26 letters. 1,000 × 26 = **26,000**, not 2,600,000. A tester who budgets from the docstring over-provisions by two orders of magnitude.
- **D4 — the artefact's "found names" file is 60% phantom** (§2 above). Six of the ten names in `dnis_encontrados.txt` do not exist in the shipped database.
- **D5 — the seeded identifiers are not valid identifiers.** 0 of 4 fail the official mod-23 check character, and nothing in the request path validates the field. The advertised enumeration therefore runs over a namespace the platform does not police, and the two most reasonable keyspace optimisations are both wrong here (see §2).

---

## 5. Controls that held

| Control | Positive control that proves this detector works |
|---|---|
| The existence oracle is **not** a wildcard / catch-all — the failure mode that makes an enumeration worthless | `71902345A` → `PRESENT`, 200/**2268** B, marker present (fires **before** the sweep, and the harness aborts if it does not). Negative control `00000000T` → `ABSENT`, 200/**1332** B. Across 26,000 probes the response sizes form two **disjoint singleton sets** with 0 `INDETERMINATE` — an always-true oracle cannot produce that. |
| The login credential oracle discriminates | `71902678E` / `chocolate` → **302**, `location: /dashboard`, 0 bytes — fired **before** the rate ladder, again **after all 60** of its attempts, and again after the 1,000-candidate spray. (An earlier draft of this cell said "after 70 failures"; the measured ladder is 60 — see the next row — and no 70-attempt run exists.) One-character-changed password → 200/**1855** B with `DNI o contraseña incorrectos`, byte-distinct from the success case. |
| The login oracle has no rate budget | 60 consecutive wrong attempts: statuses `{200}`, bytes `{1855}`, elapsed **0.0574 s**, **1,045.5/s**, zero refusals, zero delay growth. The correct password still returned 302 immediately afterwards — the detector was never throttled into a false negative. |
| `/opt/backups` is a real boundary, not a naming convention | `touch` **and** `ls` against the same path from the injected `uid=1000` both returned `Permission denied`, verbatim, twice. The root loop then created a file in exactly that directory. Without this control the escalation witness would be indistinguishable from something the unprivileged identity could have written itself. |
| The injected process holds no ambient privilege | `CapEff:	0000000000000000`, `CapInh:	0000000000000000`, read from the injected process's **own** `/proc/self/status` — no capabilities to inherit on the way up, and no setuid transition at hop 1 (`Uid: 1000 1000 1000 1000`). |
| No `setuid` binary was needed or present on the path | Escalation went through a group permission and a root loop, not through any SUID file. `getcap`-style verification was not run — see NOT tested. |

---

## 6. Reward

**No reward value.** Measured as `uid=0 euid=0`, on the target, with the searcher's own artefacts removed first:

```
uid=0 euid=0
removed '/opt/backups/ROOT3-DL242-ROOT-ORACLE-1790801532-a91c.out'
--- payload file must not contain the token ---
0
--- md5 of restored backup.py ---
93c7c2d83c91e042e9c622781dededca  /opt/backup.py
33  /opt/backup.py
--- /opt/backups now ---
workconnect_backup_20260930_210336
--- work counts ---
regular files: 13969
total bytes: 291034473
--- literal token search: count ---
0
--- literal token search: paths ---
--- end of measurement ---
```

Three earlier sweeps of the same tree each returned **one** hit for the literal token, and every one of them was **my own payload**: `/opt/backup.py` (the installed escalation script), then my two output files under `/opt/backups`. That is `method/self-corrections.md` §26 — *the searcher's own pattern is a match* — and it is why the final run assembles the pattern **at runtime** (`PAT="F""LA""G{"`) so the payload file provably does not contain it, and why the negative is quoted with the counts and not as a bare "no flag".

The case-insensitive sweep for any `flag{` / `dl{` / `wopr{` token over the same tree returns exactly two distinct real files, both false positives and both the same artefact the corpus has already catalogued:

```
/usr/lib/python3/dist-packages/pip/_vendor/pygments/formatters/latex.py
/opt/workconnect/venv/lib/python3.12/site-packages/pip/_vendor/pygments/formatters/latex.py
```

— a LaTeX formatter template, the identical false positive lab 168 recorded.

**Criterion, stated so the count cannot rot:** a reward cell counts only if it contains a literal `prefix{…}` token with content. This one is an absence, backed by 13,969 files and 291,034,473 bytes searched at `euid=0`. It is a property of the `FLAG{}` column of [`../INDEX.md`](../INDEX.md), not a position in any sequence.

---

## 7. NOT tested

- **SSTI.** The injection sink produces shell output, and `cmd_output` is rendered by Jinja2 — but the string is never re-parsed as a template, so there is no path to test. Recorded as an inference from the data flow, not a measurement.
- **XSS.** `photo_url` is reflected at `dashboard.html:242` inside an attribute value. Jinja2 autoescaping is on by default for `.html` templates, so a `<` in the value is expected to be encoded — but I did not submit a payload and read the bytes back. This is an **inference**, and it is the reason the finding list has no XSS entry.
- **`GET /docs`, `/openapi`, `/redoc`.** FastAPI serves these by default and I did not request them. Count: **0 requests**. Untested, not absent.
- **Any SUID / file-capability escalation.** `getcap` was never run. The escalation I used needs no SUID binary, and I make no claim about whether the image has one.
- **The shipped `fuzzer.py` end to end.** I could not run it at all (D2). Its 26,000-candidate keyspace was swept with my own harness instead; whether the shipped tool has an additional defect beyond the missing import is unknown.
- **Post-root persistence.** I reached `euid=0` and searched. I did not attempt to survive a restart, and `Dockerfile` shows the escalation vector is re-armed on every container start anyway.
- **Second-order DNS.** Zero UDP sockets, zero resolvers, and the corpus has no prior DNS engagement to cross-read against.

## 8. Discarded with a reason

- **WordPress / any CMS fingerprinting.** The artefact is a 130-line FastAPI app with a SQLite file and four templates. `wp-content`, `wp-includes`, `Version.php` — none exist, and `pip3 list` shows no CMS dependency. Discarded on the artefact, not on the label.
- **Credential attack as the entry path.** A bounded spray ran anyway and is reported above (**1,000 candidates, 4 DNIs × 250, 0 hits, 1,195.1/s, oracle green before and after**), but F4 establishes there is nothing behind the login, so this is a measurement rather than a path. Reporting it as "credentials cracked" would be the lab 102 error.
- **The modulo-23 keyspace optimisation.** Discarded as a *technique* on measured evidence (0 of 4 seeded accounts carry a valid check character, and the sweep created 25 invalid-check-character records for one number). It is reported in §2 as the finding, not used as the method.
- **A public resolver for the "DNS records" the queue promised.** Not attempted. There is no zone to ask: no resolver in the image, no UDP socket, and querying third-party infrastructure for a DockerLabs hostname is out of scope regardless.

---

## 9. Instrumentation defects — mine

**I1 — My sweep's own log file wrote 0 bytes while stdout was complete.** The harness guarded its close with `if log is not log:` — and an object is always identical to itself, so the condition was never true, the buffer was never flushed, and `sweep-full-26k.txt` was **0 bytes** after a complete 26,000-candidate run. Terminal output was perfect, so a reader of the run would have believed the evidence was on disk. Caught by `wc -c` on the file, not by anything in the output. This is §14 and §19 in a new costume: **a work count read from the file was zero, which means untested, while the same count read from the terminal meant complete.** Fixed (`log is not None` + per-line `flush()`), and the **full sweep was re-run from a restored image** so the on-disk evidence is genuine rather than reconstructed. Both runs agree: 4 found, 0 indeterminate, sizes 1332/2268.

**I2 — I consumed my own negative control.** The first control pair used `99999999X`, which answered `ABSENT`; the harness then ran again and `99999999X` answered **`PRESENT`** — because my first manual probe had **inserted** it (`main.py:77`). The control had been turned into a record by the act of using it. The harness caught it and refused to sweep:

```
# NEGATIVE CONTROL  dni=99999999X -> PRESENT  http=200 bytes=2268 present_marker=True absent_marker=False
# NEGATIVE CONTROL DID NOT BE ABSENT - the control cannot exist but answered PRESENT. STOPPING.
```

That is the control working, and it is also finding F2 arriving as an instrument failure. The generalisable form: **an existence oracle whose negative branch writes is not idempotent, so its control space is consumed by the enumeration itself.** Move the control outside the swept namespace (`00000000T`) or the second run is meaningless. Restored from the image before proceeding.

**I3 — My first escalation payload had a typo, and the root loop proved it for me.** I wrote `_open(...)` instead of `open(...)`. The vector fired; my oracle did not. The tell was in `/var/log/backup.log`, as root's own traceback:

```
Traceback (most recent call last):
  File "/opt/backup.py", line 35, in <module>
    _open('/opt/backups/DL242-ROOT-ORACLE-...proof','w').write(...)
NameError: name '_open' is not defined. Did you mean: 'open'?
```

Reading that as "the escalation failed" would have been the expensive mistake. Reading it as "the escalation happened and my *witness* was malformed" is what it is. Fixed on the next tick; witness appeared within 20 s.

**I4 — `rm -f /opt/backups/ROOT-*` removed nothing and returned 0.** Inside a nested `subprocess.run(..., shell=True)`, the globbed form silently matched nothing while exiting **0**, and the "clean tree" claim I was about to write into the reward section depended on it. The explicit `rm -fv /opt/backups/<full-path>` printed `removed '…'` and `rm_rc=0`. §11 exactly: *a tool that succeeds while doing nothing manufactures a negative that confirms what you hoped.* The reward count was re-taken with the explicit form and with `test -e … && echo STILL_THERE || echo REMOVED` as the check.

**I5 — `docker exec` is root, so an `id` from it is a statement about my tooling.** Every identity claim in §3 is therefore taken from either the injected process's **own** `/proc/self/status` (`Uid: 1000 1000 1000 1000`, read with no subprocess in the middle) or from a root payload run by the lab's own loop. The one `docker exec … id` in the transcript is labelled as the container's shell, not as the service.

**I6 — I wrote four scratch files into the wrong repository.** A `cd` had reset, so `d.html`, `e.html`, `dni-file-check.txt` and `sweep-rowcount.txt` landed in `~/PenTestMethodology/` instead of this corpus. Caught by `git status` on that repo, not by any error. Moved into `corpus/242/evidence/raw/`; that working tree returned to exactly the state I found it in. Nothing that was not mine was touched. All subsequent scratch writes used absolute paths.

**I7 — The UDP negative had to be rebuilt without `nmap`.** `nmap -sU` refused (`requires root privileges`), so an untested instrument would have been the only source for the claim "no DNS service". Resting it on `/proc/net/udp` and `/proc/net/udp6` (**1 line each = header only = 0 sockets**), cross-checked against the image's `ExposedPorts: 8000/tcp` and a full `-p-` scan, is what turned "I could not scan UDP" into a count. A count of zero would have been UNTESTED; here the count is one header line and the interpretation is stated.

---

## 10. Feed-forward

**The class is absent from `RUNBOOK.md` §5, and the row it proposes was never added.**
This writeup originally said the class "gets a new row"; `RUNBOOK.md` §5 still has no
structured-identifier row, so that forward reference was wrong. The proposed row is stated
here and stays a proposal until someone adds it:

| Class | The question that starts it | The discriminator |
|---|---|---|
| **Structured-identifier enumeration** (proposed, not in `RUNBOOK.md`) | Does an unauthenticated request return a distinguishable answer for "this identifier is taken", and is the namespace closed enough to enumerate? | The response-size set is a **partition into disjoint classes**, and the submitted count closes against the artefact |

The class is also **not** the row the queue asked for. Two things generalise:

1. **Structured-identifier enumeration (this lab).** Entry criterion: *does an unauthenticated request return a distinguishable answer for "this identifier is taken", and is the namespace closed enough to enumerate?* Discriminator: **the response-size set is a partition into disjoint classes, and the count closes against the artefact.** The wildcard lesson transfers directly: an always-positive oracle is a wildcard, and a "found" count equal to the query count is the signature.
2. **The check-character rule, which is the part that will save someone a day.** *A format constraint you did not measure is not a filter you may apply.* 0 of 4 real records satisfied the official DNI check character, and 25 of 26 letters for a registered number were accepted and stored. A keyspace cut from 26,000 to 1,000 would have reported **0 of 4** and called the namespace empty. The general form is the one the corpus already has for `ANY` vs `TXT`: **a refusal tells you about the component that refused, not about the data.** Measure the target's own validation, in the direction where the format is *accepted*, before you let a format shrink your keyspace.

**Cross-reads against siblings, stated explicitly because the corpus has been wrong here before (rule 8):**

- **Agrees with lab 87 and lab 188** — a first pass reporting records that do not exist. Here it is worse in one respect and better in another: worse, because `dnis_encontrados.txt` ships the phantom list *inside the image*, so the false positives are handed to the tester; better, because the list is small enough to close (10 names, 4 real).
- **Agrees with lab 238 (`method/self-corrections.md` §3)** — a handler's own subprocess deadlocking the process that must serve the request. There it was the tester's harness; here it is the shipped product, reachable by one unauthenticated field, and it does not self-release. The check that caught it — *is the process meant to serve this still running, and is there a positive liveness number to compare against* — is now the one to reach for first on any `subprocess` in an `async def`.
- **Agrees with lab 283** on *prevents vs detects*, with the polarity flipped: there the target had no filter; here the target has a format in the UI and no format in the code.
- **Refines, and does not overturn, rule 1.** The queue's class label was wrong for Joomla (32), a six-file PHP app (220), and a Drupal lab queued as WordPress (82). Those were filenames mistaken for fingerprints. **242 is a different failure: the label is an acronym re-expanded into the wrong protocol**, and no amount of reading the artefact's filenames would have caught it — the DNIs are right there in `main.py:32-35`. The check that catches this one is a **count of protocol identifiers in the artefact** (`grep -rIo -i "dns" … | wc -l` → `0`), not a version file. Both checks belong in stage 3.
- **New observation, not yet a rule:** the enumeration step the catalogue advertises is *unnecessary* for the intrusion it advertises, because the endpoint holding the injection has no authentication. A class label can be wrong twice — about the protocol **and** about whether the step is load-bearing. Check the second before budgeting time for the first.

---

## Evidence index

| File | What it is |
|---|---|
| `evidence/dni_sweep.py` | the sweep harness, with the control pair enforced in code and the `INDETERMINATE` bucket |
| `evidence/sweep-full-26k.txt` | the 26,000-candidate run, on disk, **1,436 bytes / 28 lines** (after the I1 fix) |
| `evidence/db-shipped.txt` | `md5` and the 4 seed rows of the shipped `database.db` |
| `evidence/sweep-rowcount.txt` | `users_count_after_sweep=26001`, `created_by_sweep=25997` |
| `evidence/dni-checkletter.txt` | mod-23 recomputation for all 26 letters of one number, for the 4 originals, and the keyspace arithmetic |
| `evidence/dni-file-check.txt` | `dnis_encontrados.txt` against the database — 10 listed, 4 real |
| `evidence/raw/f-identity.html` | the injected process's own `/proc/self/status`, verbatim |
| `evidence/raw/e.html` | `/opt/backup.py` and `/opt/backups` as seen by `uid=1000`, with the `Permission denied` |
| `evidence/raw/h-control.html` | the root-only-path control: `touch` and `ls`, both denied |
| `evidence/raw/root-output5.txt` | the final reward measurement at `uid=0 euid=0`, with the counts |
| `evidence/raw/esc-payload*.txt`, `root-exec*.b64` | every payload, in order, including the two that were wrong |

Target restored from the image and **positively** re-verified: `GET /` 200/1479 B · `POST /login` 302 → `/dashboard` · `POST /register` with a taken DNI 200/2268 B (the PRESENT size measured 26 000 times; the "2291" an earlier draft printed appears nowhere in `evidence/` and is not reproducible) · `/opt/backup.py` md5 `93c7c2d83c91e042e9c622781dededca` · `database.db` md5 `13f03a85914cc376a8d6ad75d48a7352` · `users=4` · `/opt/workconnect` back to 13 entries · `/opt/backups` holds only the loop's own backup directory.
