# Los 3 Hackers (DockerLabs #283) — Writeup

**Lab:** `los3hackers` (image `los3hackers:latest`)
**Base:** Ubuntu 22.04.5 LTS, OpenSSH 8.9p1, Gunicorn (Flask), Python 3.10
**Attacker position:** unauthenticated remote TCP
**Reward:** none exists in this image (see §1). The reachable terminus is an unprivileged user.

---

## 1. Surface

`nmap -sV -Pn -p- 172.17.0.18`:

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.15 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Gunicorn
Not shown: 65533 closed tcp ports (conn-refused)
```

Two ports, and `Server: gunicorn` with **no reverse proxy in front of it** — that matters, because it means the one filter in this application is the *only* filter, and there is no WAF layer to discover.

| Endpoint | Behaviour |
|---|---|
| `GET /` | Story page, one link to `/login` |
| `GET /login` | Red Hacker's admin panel login form |
| `POST /login` | Vulnerable. String-concatenated SQL behind a one-word denylist |
| `GET /dashboard` | Requires any session. Renders a hardcoded "FLAG ENCONTRADA" card |
| `GET /dashboard/backups` | Returns a hardcoded `403` page for *every* session |
| `GET /logout` | Clears the session |
| `GET /wow.zip` | Requires any session. Serves a 204-byte zip containing `permission.txt` |
| `GET /static/<path>` | Serves the single banner image |
| `127.0.0.1:5000` | "Internal Backup Portal". **Loopback-only** — unreachable from outside |

Per-IP rate limit on `POST /login`: 3 failed attempts → 30 s block. Notably, **filter rejections count as failures** (`app.py:743` calls `_registrar_intento_fallido` on the blocked path), so an unaudited fan-out locks out the tester. See §8 — this cost me two invalid readings.

---

## 2. The filter: where it is, what it lists, and whether it prevents or detects

### 2.1 Location and content

`app.py:742`, the only input filter in the entire request path:

```python
# --- Filtro de seguridad parcial: bloquea la palabra OR ---
if re.search(r"(?i)\bor\b", username) or re.search(r"(?i)\bor\b", password):
    _registrar_intento_fallido(client_ip, now)
    return render_template_string(LOGIN_PAGE, error="Patrón no permitido detectado")
```

The sink it guards is `app.py:753`:

```python
query = "SELECT username, role FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
```

**The denylist contains exactly one token: the contiguous substring `or`, delimited by non-`[A-Za-z0-9_]` characters.** It is a *text* match, not a semantic one. I established the exact semantics locally rather than assuming them:

```
o<TAB>r    filter_match=False      <- not contiguous, so \b never applies
o<NL>r     filter_match=False
OR/**/     filter_match=True       <- contiguous, and '/' is a non-word char
dor        filter_match=False      <- 'd' before 'o' is a word char, so no boundary
P4ssw0rd_OR_2026!  filter_match=False <- '_' IS a word char in Python regex
```

`\b` is a zero-width assertion; it does **not** consume a separator. So `o<TAB>r` contains no `or` substring at all. The practical rule: **the filter matches the two characters `or` adjacent, surrounded by non-word characters.**

### 2.2 The oracle, and its positive control

The endpoint has four distinguishable outcomes. **The status code is not the discriminator**: the blocked path returns `200`, exactly like a failed login.

| State | Status | Body marker | Length |
|---|---|---|---|
| `SUCCESS` — query ran, row found | `302` | `Location: /dashboard` | 226 |
| `BLOCKED` — filter fired | `200` | `Patrón no permitido detectado` | 5338 |
| `NOROW` — query ran, no row | `200` | `Usuario o contraseña incorrectos` | 5341 |
| uncaught error | `500` | Werkzeug default page | 290 |

**Positive control, run first, on the live target:**

```
CTRL good credential    | 302 | SUCCESS  | len=226   <- oracle can see a success
CTRL SQLi 'admin'--     | 302 | SUCCESS  | len=226
ORACLE VALID: True
```

A second success on a *different* code path (credential auth vs. injection) confirms the oracle is not accidentally keying on one route.

### 2.3 Does the filter **prevent** or **detect**? — the test

The question is not "does it return an error" but **"did the query execute?"**. A filter that *prevents* rejects the input before the sink; a filter that *detects* lets the query run and then suppresses the output — in which case the query already ran, and (as in the Norc lab) it is still a valid injection.

**The falsification test:** send two payloads that both contain the listed token, both syntactically valid SQL, and with **different execution outcomes**. If the app prevents, the answers must be identical. If it detects, they must differ.

```
P1 ' OR '1'='1' --   | 200 | BLOCKED | len=5338     <- would AUTHENTICATE if executed
P2 ' OR 'x'='x2' --  | 200 | BLOCKED | len=5338     <- would match NO row if executed
bodies byte-identical: True
```

`P1` and `P2` produce **byte-identical** responses. A response that does not vary with the query cannot be a function of a query that ran. The same length (5338) distinguishes them from the query-executed states (5341 / 226), so this is not an artifact of two states colliding.

**Second, independent differential** — same account, same database, only the listed token differs:

```
D1 ' OR 'x'='x2' --  | 200 | BLOCKED | len=5338
D2 nosuchacct        | 200 | NOROW   | len=5341
```

Both refer to a database that cannot match. The answers differ, so the decision is made by the presence of one substring and by nothing in the database.

**Third, structural confirmation:** the `return` at `app.py:744` precedes `sqlite3.connect(DB_PATH)` at `app.py:746`. On the blocked path no database handle is ever opened. (This is read from source, and it *agrees* with the two behavioural tests above — it is not the basis of the conclusion.)

> **Verdict: the filter PREVENTS.** It is an input-side gate, not an output-side detector. It is a real control for the one token it lists — and it is irrelevant to every other token, because the injection does not need the one token it blocks.

---

## 3. Auditing the denylist by category

The method that generalises: **a denylist is evaluated for what it does not contain.** Enumerate the *categories* of SQL syntax; every absent category is a bypass, and probing one payload per category is far cheaper than fuzzing variants of the one keyword that is listed.

| # | Category | Listed? | Probe | Result |
|---|---|---|---|---|
| 1 | boolean keyword `OR` | **YES** | `' OR '1'='1' --` | `BLOCKED` — works for what it lists |
| 2 | **line comment `--`** | no | `admin'--` | **`SUCCESS` — full auth bypass** |
| 3 | `UNION` | no | `' UNION SELECT username,role FROM users --` | `SUCCESS` |
| 4 | `LIKE` | no | `admin' AND username LIKE 'a%' --` | `SUCCESS` |
| 5 | subquery / parentheses | no | `admin' AND 1=(SELECT 1) --` | `SUCCESS` |
| 6 | encoding (URL / hex) | no | `admin%27--`, `%61dmin'--` | `SUCCESS` — **but see §3.1: not a bypass** |
| 7 | keyword re-tokenised (`o<TAB>r`, `o<NL>r`) | n/a | `admin'\to\tr\t1=1\t--` | `NOROW` — **not a bypass**, see §3.2 |
| 8 | comment-split keyword (`OR/**/`) | effectively covered | `admin' OR/**/1=1--` | `BLOCKED` — **control that held** |
| 9 | stacked statement `;` | no | `admin'; SELECT 1 --` | `500` — not exploitable, but see Finding 3 |
| 10 | **false positives** | — | `admin` + `red.or.blue` | `BLOCKED` — see Finding 4 |

**Ten categories, fourteen requests.** The bypass (category 2) required no encoding, no obfuscation and no cleverness: the denylist blocks the boolean operator, and the comment makes the operator unnecessary.

### 3.1 Encoding is the expected first answer, and it is **wrong** here

The instinct is that a filter matching a literal string is defeated by encoding. The correct question is **which layer the filter inspects**, and the answer decides whether encoding is a bypass at all.

Raw wire bytes, no re-encoding:

```
E1  wire: admin%27--    | 302 | SUCCESS    <- the filter did NOT fire
E3  wire: %61dmin'--    | 302 | SUCCESS
E2  wire: admin%2527--  | 200 | NOROW      <- one decode yields a literal '%27'
```

Werkzeug decodes the form body **before** the view function runs, so `request.form.get("username")` at `app.py:736` already holds the canonical value `admin'--`, and the filter at `:742` inspects that canonical value. **Encoding is not a bypass here, precisely because the filter runs at the right layer.** The §1 defect (validating the representation instead of the value) is *absent* here.

> This is a rejected first response with evidence. Reporting "encoding bypasses the filter" would have been a confident, well-formed, entirely wrong finding.

### 3.2 Splitting the keyword is also not a bypass here

```
D1 admin'\to\tr\t1=1\t--  | 200 | NOROW
D2 admin'\no\nr\n1=1\n--  | 200 | NOROW
```

Two independent reasons, both verified locally against SQLite:

1. The filter does not fire, because `\b` is zero-width and `o<TAB>r` contains no contiguous `or`.
2. SQLite's tokenizer splits on whitespace, so `o\tr` becomes two identifier tokens and the statement is a **syntax error** — `OperationalError: near "o": syntax error`.

The filter and the parser agree here *for a reason that is not luck*: `\b` anchors perform the same tokenisation the SQL tokenizer performs. The classic "split the keyword" trick is defeated by word-boundary anchors, and it fails closed (a syntax error) rather than open.

### 3.3 The controls that held

- **`OR/**/` is blocked.** `/` is a non-word character, so `\b` still matches. A control that genuinely held, with the reason identified rather than assumed.
- **Stacked statements cannot execute.** `execute()` rejects multi-statement input.
- **The 500 page leaks no internals.** Werkzeug's generic page; `DEBUG` is off.
- **The internal portal really is loopback-only.** `curl` from outside → connection refused, `http_code=000`, exit 7. It was reachable only from a shell already on the box.

---

## 4. Findings

### Finding 1 — SQL injection: a keyword denylist in front of a concatenated query
**CWE-89** (Improper Neutralisation of Special Elements used in an SQL Command) · **CWE-184** (Incomplete List of Disallowed Inputs) · severity: **critical**

**Evidence.**
```
query = "SELECT username, role FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
if re.search(r"(?i)\bor\b", username) or re.search(r"(?i)\bor\b", password):
```
```
admin'--   -> 302  Location: /dashboard
```

**The injection is a full read primitive, not merely an auth bypass.** The endpoint returns one bit — whether a row came back — and that bit carries arbitrary database content. Seven content checks, each with a paired negative:

```
some password starts with 'A'   -> True    some password starts with 'Z' -> False
users table has 2 rows          -> True    users table has 7 rows        -> False
'rate_limit' table exists       -> True    a table named 'zzz' exists    -> False
schema has only 2 tables        -> True
ALL CHECKS AGREE: True
```

Extracted end-to-end, one bit at a time, with the length control confirming the result:

```
FULL admin password read out of the database via the injection:
     'Adm1nHACKBBO_2024!'
length: 18     control len=18: True     total probes: 141
```

**Impact.** Unauthenticated read of the entire database, including `sqlite_master`. The single table read does not change the severity: any additional table added to this file is readable by the same primitive, and the read is anonymous.

**Root cause.** Two defects, and the second is the one that matters. The primary defect is the concatenation. The *mitigation* is a denylist of one keyword, which is `CWE-184`: the control's value is a function of the size of its list, not of the grammar it must cover. **A denylist's coverage is its length; an allowlist's coverage is its completeness.** The author's own comment states the gap — "no bloquea comentarios SQL ni UNION, asi que sigue siendo inyectable" — and the comment was correct, which is a point for the lab, not a mitigation.

**Remediation.** Parameterise the query (`sqlite3` placeholders), so no input is ever parsed as SQL. If a textual filter is retained for defence in depth, it must be an allowlist applied to the *parsed* value, and it must not be the control of record. Fix the root cause first: the denylist is what turned a latent concatenation into a "protected" endpoint.

### Finding 2 — Session signing secret hardcoded in source
**CWE-798** (Use of Hard-coded Credentials) · severity: **high**

`app.py:8` — `app.secret_key = "ihatefw_corp_dev_secret_2024"`

Forged cookie, accepted by the server:

```
forged cookie accepted by /dashboard -> 200, session badge = 'root'
```

**Impact.** Any user can mint a session with any `username` and any `role`. On this application the damage is bounded only because every other authorization check is absent (Finding 3) — which is not a mitigation, it is the reason the impact is currently limited. In a normal application this is a complete authentication bypass.

**Root cause.** A development secret shipped in the production image, unchanged.

**Remediation.** Load the secret from the environment or a secret store, rotate it, and fail closed at startup if it is absent. Never commit a value that signs a session.

### Finding 3 — Inconsistent error handling on the login path: a swallowed exception and an uncaught one
**CWE-209** (Generation of Error Message Containing Sensitive Information) · **CWE-755** (Improper Handling of Exceptional Conditions) · severity: **low**

Two different failure classes, two different handlers on the same code path:

```
E1 malformed query  (admin')  -> 200 | NOROW   | len=5341
E2 wrong password              -> 200 | NOROW   | len=5341
E1 and E2 byte-identical: True
E3 stacked statement           -> 500 | HTTP500 | len=290
```

A deliberate SQL syntax error is **byte-identical** to a wrong password, because `app.py:758` swallows it:

```python
except sqlite3.Error:
    row = None
```

But the stacked-statement error escapes as a `500`, because it is not that class. The program's own failure settles it — I did not have to reason about the class hierarchy:

```
File "/var/www/app/app.py", line 756, in login
    c.execute(query)
sqlite3.Warning: You can only execute one statement at a time.
```

`sqlite3.Warning` is **not** a subclass of `sqlite3.Error` (verified: `issubclass(sqlite3.Warning, sqlite3.Error)` is `False`, while `ProgrammingError` is `True`). So `except sqlite3.Error` misses it.

**Impact.** Low on its own, for two reasons worth stating separately. First, a `500` on `/login` is a residual one-bit oracle on a path that is already fully injectable, so it adds no new capability here. Second — and this is the transferable part — **the same handler would hide a genuine database fault in a non-injectable application.** A connection failure, a locked database, a disk error and a wrong password would all render as "wrong password", and the operator would be reading authentication logs for a database outage.

**Root cause.** A blanket `except` on an exception base chosen from memory rather than from the exception hierarchy the driver actually uses.

**Remediation.** Catch the specific exceptions expected; let the rest propagate to a handler that logs the cause and returns a generic message. Log the distinction between "no such user" and "query failed".

### Finding 4 — The denylist's false positives: a valid credential rejected with a security-policy message
**CWE-20** (Improper Input Validation) · severity: **low**

```
FP1 admin / 'red.or.blue'    | 200 | BLOCKED | len=5338
FP2 admin / 'red0rblue'      | 200 | NOROW   | len=5341
FP3 admin / 'red!blue'       | 200 | NOROW   | len=5341
```

`admin` is a real account (FP2 and FP3 reach the authentication path; FP1 never does). A password containing `or` as a standalone token — `red.or.blue`, `p4ss-for-2026`, `a_or_b` — is rejected with *"Patrón no permitido detectado"* instead of an authentication result.

**Impact.** A legitimate user is told a **security policy** fired when in fact their password is fine, and is given no way to discover which characters are refused. The user cannot distinguish "my password is wrong" from "my password is forbidden", and the support path for the two is different.

**Root cause.** A security control implemented as a text match over a whole field, with no notion of where the value ends and syntax begins.

**Remediation.** Deleted along with Finding 1's primary fix. A password field should not be pattern-scanned for SQL keywords at all; the only reason it is scanned here is that it is concatenated into a statement.

### Finding 5 — `/dashboard/backups` presents an authorization decision that does not exist
**CWE-863** (Incorrect Authorization) · **CWE-284** (Improper Access Control) · severity: **medium** (as a report-integrity defect; see below)

The page asserts a privilege boundary:

> *"El módulo de Respaldos requiere privilegios de nivel **superadmin** que tu sesión actual no posee."*

The handler tests no such thing (`app.py:934-938`) — it checks session membership and returns a constant:

```python
@app.route("/dashboard/backups")
def backups():
    if "username" not in session:
        return redirect(url_for("index"))
    return BACKUPS_403_PAGE, 403
```

Body-hash differential (the discriminator from `decision-making.md`, whitespace-normalised):

```
no session (anon)            -> 302  redirect -> /
real session role=admin      -> 403  body_sha256=aeb263542e9d2486
real session role=staff      -> 403  body_sha256=aeb263542e9d2486
FORGED role=superadmin       -> 403  body_sha256=aeb263542e9d2486
FORGED role=root,user=root   -> 403  body_sha256=aeb263542e9d2486
distinct (status, body-hash) across ALL authenticated cases: 1
```

**A session claiming `role=superadmin` receives exactly the same page as `role=staff`.** One distinct body hash across every authenticated case means the sweep found no variation: there is no authorization decision on this endpoint, only a static page behind a membership check.

**Impact.** As a security finding this is low — nothing is disclosed. As a **report-integrity** finding it is worse. A reader who reaches `/dashboard/backups`, reads a confident page naming a `superadmin` requirement, and files "the backups module is protected by superadmin authorization" has filed a control the application does not implement. The next session inherits a boundary that was never tested, and the day someone adds a real `/dashboard/backups` handler behind the same membership check, it ships as "already authorized".

**Root cause.** A hardcoded page standing in for an access-control decision. This is the mirror image of the config-mitigation rule in `infrastructure.md` — there, a shipped mitigation was inert while the operative directive had no comment; here, a page that *describes* a mitigation is inert and nothing else exists.

**Remediation.** Either implement the role check the page claims, or remove the page and the claim. A 403 that is returned to every caller is documentation, not a control.

### Finding 6 — Credential disclosed in a downloadable "backup", and shipped world-readable in the image
**CWE-522** (Insufficiently Protected Credentials) · **CWE-732** (Incorrect Permission Assignment) · severity: **medium**

`GET /wow.zip` requires only *any* session, and returns a 204-byte archive:

```
Archive:  wow.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
       26  2026-06-30 04:27   permission.txt
permission.txt -> redhacker:<ssh password>
```

The same credential is also present in `/entrypoint.sh`, shipped at mode `0755` — world-readable — together with the other two users' passwords and the database credentials.

**Impact.** The file is served behind the *weakest* possible gate: any session, including the `soporte` staff account, and including a session forged per Finding 2. Combined with Finding 1 it is reachable fully anonymously. A backup artefact that contains a live credential and sits behind a one-line session check is a credential store with a web front end.

**Root cause.** Credentials committed to an image and to a served artefact; `wow.zip` is world-readable at `0664` on disk as well.

**Remediation.** Remove secrets from images and from anything served; use a secret store; scope the download endpoint to a role that actually exists. Rotate all four credentials in this image.

### Finding 7 — A decoy secret presented as `🚩 FLAG ENCONTRADA / CRITICAL`
**CWE-200** (Exposure of Sensitive Information) — inverted: a non-secret presented as one · severity: **informational**

The dashboard renders a `CRITICAL`-badged "flag" card whose value is a constant in the template. Verified across two identities, §11. The value is *disclosed* and is nonetheless **not a secret**: it is byte-identical for a `staff` session and an `admin` session, and possessing it changes nothing the application does.

**Why it is worth a finding rather than a footnote.** A `CRITICAL` badge on a value that is not a secret trains the reader to accept badges as evidence — and the disclosure trichotomy exists precisely to stop that: *reachable* is trivial, *disclosed* here is a value, and *decisive* is the third question, and it is the only one that decides whether a disclosure is a finding. This is the one place in the lab where the presented reward is a control failure rather than a gap.

**Remediation.** Remove the card, or make it reflect an actual per-user secret. Do not badge a constant.

---

## 5. Controls that held (with positive control each)

| Control | Evidence | Positive control |
|---|---|---|
| Per-IP rate limit, 3 fails → 30 s | `Demasiados intentos fallidos. Intenta de nuevo en N segundos.` | Confirmed it fires — twice, on me (§8) |
| Loopback-only internal portal | `curl` from outside → `http_code=000`, exit 7 | Reachable from a shell on the box → `200`, 5398 bytes |
| `OR/**/` comment-split keyword | `BLOCKED` | `admin'--` (no `or`) → `SUCCESS`, same instance |
| Werkzeug `DEBUG` off | 500 body is the generic 290-byte page | No traceback, no source in the body |
| Session membership required on `/wow.zip` and `/dashboard` | anon → `302` to `/` | Authenticated session → content |
| `execute()` rejects stacked statements | `ProgrammingError`/`Warning` | A single statement in the same field works |
| `sudo` unavailable to all three users | `sudo -n -l` → `a password is required` (both users) | Root and `%sudo` rules exist in config; none of the three users is in those groups |
| No writable path to a root-context process | `/etc/cron.d/maintenance` → `not writable`, `root root 0644` | bluehacker *can* write `m.sh` (§6) |
| `m.sh` attribute protection | `chmod`/`chmod u+s` as bluehacker → `Operation not permitted` | `test -w` as bluehacker → `WRITABLE` (content yes, attributes no) |

---

## 6. The chain

Each hop's **executing identity** was measured, never inherited.

**1. SQLi → authenticated session.**
`admin'--` → `302 /dashboard`, session badge `admin`. The bypass contains no listed token.

**2. Credential disclosure → SSH as `redhacker`.**
`GET /wow.zip` (session required) → `permission.txt` → SSH password.
```
$ id
uid=1000(redhacker) gid=1000(redhacker) groups=1000(redhacker)
```

**3. Loopback pivot → `bluehacker` credential.**
`redhacker`'s `user.txt` points at the internal portal. It is not reachable externally (control above), so the shell is the pivot:
```
$ python3 -c "...urlopen('http://127.0.0.1:5000/')..."
http_code=200 bytes=5398
   bluehacker
   <ssh password>
```
*(Note: `curl` is not installed on the target. I assumed it was, got `command not found`, and used the interpreter that is present. That was my error, not a target fact.)*

**4. Group-writable cron script → execution as `blackhacker`.**

Backup taken **before** the write (`sha256 59c46bd4…`, 124 bytes), per the write-class rule. Permission tested **as the identity that would use it**:
```
$ id
uid=1001(bluehacker) gid=1001(bluehacker) groups=1001(bluehacker)
$ test -w /opt/maintenance/m.sh
test -w => WRITABLE (as uid=1001)
$ ls -la /opt/maintenance/m.sh
-rwxrwxr-x 1 blackhacker bluehacker 124 ...   <- group bluehacker, mode 775
```

Payload written, then verified byte-for-byte on the target:
```
intended payload sha256: 8dcab4abcc1a9268588484d050b50fc8aabae44eebe2b25f5560721675c604ef
on-target:               8dcab4abcc1a9268588484d050b50fc8aabae44eebe2b25f5560721675c604ef   (253 bytes)
```

Execution proof, read back through the chain, **carrying a nonce created in this run**:
```
uid=1002(blackhacker) gid=1002(blackhacker) groups=1002(blackhacker)
NONCE=n28384e1f96ddec4
blackhacker
mtime=2026-09-29 14:17:01 bytes=104 owner=blackhacker
```

Three independent witnesses, and the byte count is what distinguishes a fresh execution from a stale file: **90 → 104**, with the mtime moving `14:16:01 → 14:17:01`. The first read returned `NONCE=%s` — a literal, because my generator failed to substitute the placeholder — and the file it came from was left by the *previous* payload. That reading was discarded (§8).

**Terminus.** Read as `uid=1002(blackhacker)`:
```
--- /home/blackhacker/user.txt ---
No confío en contraseñas.
No confío en personas.
Las contraseñas se olvidan.
Las personas cometen errores.
Los privilegios...
Esos sí permanecen.
- Black
```

### 6.1 Root is not reachable — derivation

The chain terminates at `blackhacker`. This is derived, not assumed:

1. **`sudo`** — `sudo -n -l` returns `a password is required` for both `redhacker` and `bluehacker`. Config (`/etc/sudoers`, `/etc/sudoers.d/`) grants only `root`, `%admin` and `%sudo`; `id` shows all three users are in **only** their own private group. No rule applies.
2. **`su`** — `root:*:...` in `/etc/shadow`; the account is locked. No password to authenticate with.
3. **setuid binaries** — the Ubuntu default set only (`su`, `sudo`, `passwd`, `chsh`, `chfn`, `newgrp`, `mount`, `umount`, `chage`, `expiry`, `crontab`, `ssh-agent`, `ssh-keysign`, `unix_chkpwd`, `pam_extrausers_chkpwd`, dbus helpers). Each requires either root's password or an already-root caller. `crontab` writes the caller's own crontab, which runs as the caller. `unix_chkpwd` serves the calling user's own password change.
4. **The one cron job runs as `blackhacker`** — measured above, `uid=1002`, not root.
5. **`/etc/cron.d/maintenance` is `root root 0644`** — not writable, so the job's *definition* cannot be changed, only its *script*.
6. **`/root/root.txt`** is `drwx------ root root`; `cat` returns `Permission denied` from the attacker's shell.

**What would make this solvable:** a cron job running as root, a sudoers grant for one of the three users, or a setuid-root helper reachable by them. None exists. The lab's own `/entrypoint.sh:308-310` claims the first:

> `# Un script que corre cada minuto como root, pero el archivo tiene permisos`
> `# de escritura para el usuario bluehacker. ...conseguir ejecucion como root.`

**That comment is false**, and the measurement is what refutes it — `uid=1002`. See §7.

---

## 7. Lab design observation

**The third act is advertised and not delivered.** The entrypoint labels the cron job *"Segunda vulnerabilidad de escalada"* and its comment states it runs as root. It does not: `/etc/cron.d/maintenance` reads `* * * * * blackhacker /opt/maintenance/m.sh`. Measured, `uid=1002`.

The consequences are structural, not cosmetic:

- The escalation lands on the **third unprivileged account**, not on root. The chain red → blue → black is a *lateral* pivot, and the reward narrative ("Los privilegios... Esos sí permanecen") is about persistence, not privilege.
- A learner who reads the comment concludes the lab is broken, because the documented final step cannot work. A learner who **measures** reaches `uid=1002` and correctly concludes there is no escalation — and finds `/root/root.txt` permanently out of reach, with the epilogue text the lab clearly intended them to read.
- The comment is a stopping condition in the exact sense of `decision-making.md` §7: a confident-looking annotation that ends the derivation, and whose absence of a *reachable* conclusion downstream cannot be detected by a green check.

**A target that names its own weakness teaches reading comments.** The author was right about the SQLi gap (*"sigue siendo inyectable"*) and wrong about the cron identity, which is the more interesting of the two — because the SQLi gap was announced and the false escalation was announced too, and only one of them is a puzzle.

**For the author:** either run the job as root, or delete the root claim and let the third act be about persistence. Do not ship a comment that asserts a privilege the image does not grant.

---

## 8. Autocorrection — readings I discarded, and what each one would have cost

Five defects in my own instrumentation. All five produced well-formed, confident, wrong output, and none of them was detectable from the output itself.

**8.1 An encoder measured instead of the target.** My first probe wrapped every value in `urllib.parse.urlencode()`. Sending the already-encoded `admin%27--` therefore put `admin%2527--` on the wire, and the application correctly reported "no such user" for a username that legitimately contained a percent sign. I had recorded two results labelled "encoding is not a bypass" that actually measured `urlencode`. **Fix:** send the bytes verbatim; the encoding test is only meaningful if the harness does not touch the payload. This is the "your own client can be the reason a payload does not work" rule — the same shape as a URL-quoter emitting `%2F` and reading as a `404`.

**8.2 A lockout poller that returned a uniform false.** `truthy()` mapped any non-302 to `False` and caught every exception. When my own per-IP rate limit was active, `1=1` returned `False` — a clean, uniform, entirely false negative, identical to what "the injection is dead" looks like. The control was what caught it, which is the entire reason for having one. **Fix:** a rate-limited answer is not a data bit; abort and retry. A detector pointed at something that does not exist returns a clean, believable negative, and here the "something" was my own lockout.

**8.3 A stale witness, one step behind the truth.** After writing the nonce-bearing payload, I polled for the proof file and accepted the first reading containing `uid=` — which was a file created by the **previous** payload version, containing the literal `NONCE=%s` because my generator had not substituted the placeholder. A well-formed answer, one step behind. **Fix:** require the nonce, and require the byte count to move (90 → 104). Existence is not content, and a witness must be created in this run by the identity under test.

**8.4 A non-monotone predicate in a binary search.** The extraction searched for `substr(...) = char(N)`, which is true at exactly one value. Binary search assumes monotonicity: `FALSE` at `mid` was read as "the answer is above `mid`", so every character converged to the top of the range and the extractor returned `~~~~`. **`~~~~` is the signature of a broken search, not of a password**, and it would have been reported as "the admin password begins with four tildes" — a confident, plausible, fabricated extraction. **Fix:** use a monotone predicate (`unicode(...) <= N`). The tell was four identical characters, each equal to the range maximum.

**8.5 A re-test that sent a different payload.** The stacked-statement `500` did not reproduce when I hand-encoded the request — because I omitted `%27` for the opening quote, so the server received `admin; SELECT 1 --` *inside a string literal*, which is valid and returns no row. My re-test was not a failed reproduction; it was a different request. **Fix:** reproduce the exact bytes, and when the program's own log already carries the answer, read the log.

**Common shape.** In four of the five, the failure produced output that a reader would accept. The controls that saved each one were all the same: a positive control run first, a byte count instead of a status, a nonce carried through the run, and a value compared against a boundary I could predict.

---

## 9. Not tested vs. discarded with reason

**Tested:** the login denylist across ten categories; the injection's data channel (7 paired content checks + full 18-character extraction); the 500's root cause from the program's own traceback; the `/dashboard/backups` gate across five session states including two forged; the "flag" across two identities; loopback reachability from outside and from a shell; the cron write with permission tested as the identity; nonce-bearing execution proof read back as `blackhacker`; the sudo/suid/cron/shadow enumeration for root.

**Not tested (out of scope, no authorisation):** writes to any table; `ATTACH DATABASE` or extension loading; attempts to modify `/etc/cron.d/maintenance`; any brute force beyond the single-credential authentications performed; container escape; touching the `cybervault-*` containers.

**Discarded with reason:**

| Path | Why discarded |
|---|---|
| Encoding as the bypass | Refuted by measurement — the filter runs after the framework decode (§3.1) |
| Keyword splitting (`o<TAB>r`) | Refuted by measurement — the filter requires a contiguous `or`, *and* SQLite's tokenizer rejects the split statement |
| `OR/**/` comment-split | Refuted by measurement — `/` is a non-word char, so `\b` matches; this is a control that held |
| Stacked statements for execution | `execute()` rejects multi-statement input; the 500 proves rejection, not execution |
| SSTI via `render_template_string` | Every template is a module-level constant and the only interpolated value is an `int` (`segundos_restantes`). No user-controlled string reaches a template. Not reachable |
| Traversal on `/static/<path>` | `send_file` on a fixed `static_dir`; not probed further as the chain did not need it — **declared untested**, not discarded |
| Reading `/entrypoint.sh` as a chain step | Possible (mode `0755`) and it discloses all three SSH passwords, but I took the credentials from `/wow.zip` so that every hop in §6 is reachable through the web application alone. Reported as Finding 6, not used |
| `su` to root | `root:*` in shadow; no password exists to supply |

---

## 10. Evasion and blacklist auditing — the transferable criteria

### 10.1 Preventing vs. detecting: the question that decides it

> **Did the query execute?**

A filter that **prevents** rejects the input with a visible error, before the sink. A filter that **detects** accepts the input, runs the query, and returns a data-free response afterwards — in which case **the query has already run**, and it is still a valid injection whether or not you can see the result. This is the same criterion as the Norc lab's read-only SQLi: a filter that "stops" you at the output layer has not stopped the injection.

Three tests, in increasing strength:

1. **Structural** — does the early return precede the sink? Weakest on its own: it is a claim about the source, and the running binary is not the file you read.
2. **Differential** — send two payloads with the *same* filter-relevant property and *different* execution outcomes. Identical answers ⇒ the response is not a function of the query ⇒ prevention. This is the one to rely on.
3. **The oracle is the observable difference, never the status code.** Here the blocked path returns `200` and the successful login returns `302`, so a status-code filter would report every blocked payload as a normal response and the bypass as "an odd redirect". Count the distinct response bodies, not the codes — and remember the direction in which this fails: a body-hash discriminator pointed at a *moving* page yields a false **positive** dressed as a successful enumeration.

### 10.2 Auditing a denylist: enumerate categories, not variants

A denylist is evaluated **by what it does not contain**. The categories to enumerate:

1. Boolean operators
2. Comments — `--`, `/* */`
3. `UNION` / `UNION ALL`
4. String functions — `LIKE`, `GLOB`, `BETWEEN`, `IN`
5. Subqueries and parentheses
6. Stacked statements
7. Encoding — URL, hex, base64, `char()`
8. Case and separator variation inside a listed token
9. **Whatever the filter does not tokenise** — the boundary of its own matching

Every absent category is a bypass, and **one probe per category is faster than any number of payload variants.** Here: one listed category, four usable absent ones, fourteen requests, no fuzzing. If you find yourself mutating a single blocked payload, you are working inside category 8 when the win is in category 2.

**The counter-intuitive result, and it is the transferable part:** categories 7 and 8 both failed. The filter was *correct* about encoding (it inspects the canonical value, after the framework decodes) and *correct* about separator variation (word-boundary anchors tokenise the same way the SQL tokenizer does). **A denylist is most often defeated by an omission, never by an obfuscation of the thing it lists.** Report the omission; it is also the one that is cheap to fix.

### 10.3 The operational gate — and why this is the part that bills

**Evading a WAF or a security filter on a client system is one of the few techniques in this methodology that can end in a report to a regulator, a charge, or a contractual penalty, and no generic "pentest authorization" letter covers it by default.** It is therefore not a technique to execute on discovery. It is a decision, taken in writing, before the request is sent:

- **The filter is identified** — vendor, rule ID, the exact signature, the layer. Not "there seems to be a WAF".
- **Its coverage is stated** — which categories the rule matches, and therefore which are open. §10.2 is the document.
- **The scope names the authorization** — evasion testing is explicitly in or explicitly out. If it is out, the finding is still reported; only the proof-of-concept is withheld.
- **The window and rate are declared**, as for any write.
- **The client contact is named.** A filter's owner is usually a different team from the application's, and that team needs to hear about it from you rather than from an incident.

**And the deliverable changes shape.** The finding is a **configuration finding on the client's system** — *"this control is evadible because category 2 is absent"* — with a remediation and an owner. It is **not** a proof-of-concept to hand over, and a working bypass payload in the report is a liability: it is a copy-paste template for someone else, and it names your client's control as defeatable in their own document. Attach the category table; describe the bypass; leave the payload in the engagement record, not in the deliverable.

**When the filter is the client's own application code — as here — none of this applies.** A denylist in a Flask view is a bug in the code under test, it is in scope by default, and the report is an ordinary CWE-89 with a CWE-184 control defect. The gate above is for evading a *third party's* protective control, which is a different act with a different owner and a different authorisation. Keeping those two apart is the judgement: the same byte sequence is a finding in one case and a breach of contract in the other.

---

## 11. Reward

**There is no reward in this image.** Reported as an absence, with evidence rather than inference.

- A filesystem sweep for the reward token over `/` (excluding `/proc`, `/sys`, `/dev`) returned **no matches**.
- A sweep executed as `blackhacker`, covering `/home /opt /srv /var/www /tmp`, returned **no matches** in any readable location.
- `/root/root.txt` — the epilogue text the lab clearly intends the solver to read — is `drwx------ root root` and returns `Permission denied`. §6.1 derives that no route to root exists.
- The dashboard's "🚩 FLAG ENCONTRADA / CRITICAL" card renders a **constant** from the template. Verified across two identities:

```
session=admin    /dashboard 200  flag-code='{SQLi_bypass_r4t3_l1m1t_pwn3d}'
session=soporte  /dashboard 200  flag-code='{SQLi_bypass_r4t3_l1m1t_pwn3d}'
distinct flag values across two different identities: 1
```

  One distinct value. Applying the disclosure trichotomy: it is *reachable* (trivially) and *disclosed* (a value is rendered), but it is **not decisive** — possessing it changes nothing the application does, and it is byte-identical for a staff account and an administrator. It is a decoy presented with a `CRITICAL` badge. Reported as **Finding 7 (informational)** rather than as a reward.

---

## 12. Restoration

Destroyed and recreated from the image; the written artifact was verified byte-for-byte against the backup taken before the write:

```
removed rc=0
recreated rc=0
$ sha256sum /opt/maintenance/m.sh
59c46bd4c6cb493f6c3ad9440364e3dcb8d22627869e7188fbaa91cc48cd1e12   <- identical to the pre-write backup
-rwxrwxr-x 1 blackhacker bluehacker 124 ... m.sh                   <- original content, 124 bytes
$ ls /tmp/lab283_*
ls: cannot access '/tmp/lab283_*': No such file or directory        <- all artefacts removed
```

**Untouched:** all `cybervault-*` containers, and the uncommitted work from the six previous labs (staged in the index, left exactly as found).
