# 85 Aidor — writeup

**Class:** IDOR / broken object-level authorization (CWE-639) — **plus** an
independent unauthenticated variant and a session-hijack write path.
**Difficulty:** facil. **First evidence for this class in the corpus.**
**Target:** `172.17.0.2:5000`, single container, `aidor:latest`.

> `corpus/85/` did not exist before this engagement. Nothing was rewritten or
> verified-in-place; this is new evidence, and it is the first IDOR writeup the
> corpus holds, so the entry criterion is stated in full below.

---

## Surface

```
$ nmap -sV -Pn -p- 172.17.0.2
Not shown: 65533 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 10.0p2 Debian 7 (protocol 2.0)
5000/tcp open  http    Werkzeug httpd 3.1.3 (Python 3.13.5)
```

**Stack and versions, read from the artefact, not from memory:**
- `Werkzeug httpd 3.1.3 (Python 3.13.5)` — nmap banner, corroborated by
  `/usr/lib/python3/dist-packages/flask/app.py` in the traceback at
  `app.py:43` and the `Werkzeug Debugger` page.
- Flask, single-file app. `app.py` is 150 lines, no framework extension, no ORM.

**What TCP cannot see — checked, not assumed:**
- UDP: `cat /proc/net/udp /proc/net/udp6` inside the container returned **header
  rows only, zero socket lines**. No UDP management plane. `ExposedPorts` is
  empty. The only listener on the host is Flask's dev server plus `sshd`.
- Virtual hosts: not applicable and not assumed. The app has no `Host`-based
  dispatch (read in full, 5 routes), so vhost enumeration has no surface to
  enumerate. Recorded as read-from-source, not as a negative scan result.
- Entrypoint, from `docker inspect`:
  `Cmd=[/bin/sh -c 'service ssh start && python3 app.py && tail -f /dev/null']`,
  `User=` (empty ⇒ root), no entrypoint script, no compose file.
- `auto_deploy.sh` **read, not run** (it ends in `while true` at line 145). It
  describes **one** container on the default bridge — no `macvlan`, no
  `--internal` segments, no second host. The lab is single-host as deployed.

**Trípleta applied:** reachable (5000/tcp) → body carries a per-user profile
record including a password hash → decisive: the same request with a different
`id` returns a **different principal's** record, and the `id` is the only
difference. That third step is what separates this from "the app is reachable".

---

## The class

**Entry criterion.** A request is IDOR — not merely unauthenticated — when
**an authenticated principal is presented and the server still returns an object
that is not theirs.** The test is not "did I see data I should not"; it is
"was there a subject, and did the object's owner differ from the subject".

The generalisable form, and the discriminator I actually used here:

| The response you get | What it is | Why |
|---|---|---|
| 200 with another user's record, **no session presented** | **Unauthenticated BOLA** (CWE-306/862) | There is no subject to bypass. Different root cause in the code even when the same line is at fault. |
| 200 with another user's record, **my own session presented** | **IDOR proper** (CWE-639) | A subject exists and was not bound to the object. |
| 302 to `/` | No such object | This is the negative, and it must be byte-distinguishable from the above or the whole finding is unfalsifiable. |

Aidor exhibits **all three**, and the writeup files them separately because
merging them tells the client they patched one thing when they patched neither.
`app.py:103` is the shared root cause:

```python
103:    user_id = request.args.get('id') or session.get('user_id')
```

`request.args` is consulted **first**, before the session, and either branch
falls through to an unscoped lookup at `app.py:110`:

```python
110:    cursor.execute('SELECT * FROM users WHERE id=?', (user_id,))
```

The query is keyed on `id` alone. There is no `AND user_id = session['user_id']`
anywhere in the file — I read all 150 lines. **The decisive artefact is the
absence of the ownership predicate in the lookup**, and no status code tells you
that; the source does, in seconds.

**A third, distinct failure sits one line later and is the reason this lab has
teeth:**

```python
118:    session['user_id'] = user[0]
```

The handler *writes the victim's id back into the caller's session*. That turns a
read bug into a **write** bug, because `/change_password` deliberately trusts the
session and not the URL:

```python
125:    if 'user_id' not in session:
128:    user_id = session['user_id']
136:    cursor.execute('UPDATE users SET password=? WHERE id=?', (hashed_password, user_id))
```

So the IDOR is not merely confidentiality. It is a **session-identity rewrite**
that the next route trusts blindly. That is the chain, and it is the part a
scanner would never produce.

---

## Chain

My identity throughout is the throwaway account **`probe.aa11`, id 55**, created
via the app's own `/register`. The victim is `miguel.hernandez`, id 9, and the
target is `admin`, id 27. Identity is read out of the response body
(`user-id">#NN`) at every hop, not assumed from the cookie.

| # | → | Mechanism | Identity proof |
|---|----|-----------|----------------|
| 0 | `probe.aa11` (55) | `POST /register` (`app.py:83-95`), auto-logged-in at `app.py:94` | `register=302`; dashboard renders `user-id">#55`, `Bienvenido, probe.aa` |
| 1 | admin (27) — **read** | `GET /dashboard?id=27` with my id-55 session. `app.py:103` prefers `request.args`; `app.py:110` looks up by `id` only | body: `Bienvenido, admin`, `user-id">#27`, `admin@company.com` |
| 2 | admin (27) — **session rewritten** | `app.py:118` sets `session['user_id']=27`. Re-reading `/dashboard` with no `id` now renders admin | `user-id">#27` **on a request that carried no `id` at all** — the subject is now the victim |
| 3 | admin (27) — **write** | `POST /change_password` reads `session['user_id']` (`app.py:128`), issues `UPDATE … WHERE id=27` (`app.py:136`) | `Location: /dashboard?id=27` — the redirect target is the *victim's* id, not mine |
| 4 | admin (27) — **new credentials, fresh session** | Fresh unauthenticated `POST /` with the password I chose | `admin_login_http=302` (success; failure is `401`); dashboard renders `user-id">#27`, `Bienvenido, admin`, `admin@company.com` |
| 5 | all 52 users — **automated** | One `GET /dashboard?id=N` per id, **no cookie sent at all** | 53 records extracted; ids 1, 2 and ≥55 correctly return `302 Location: /` |

**Hop 2 is the load-bearing evidence and it is worth stating plainly:** the
identity changed on a request that carried no attacker-chosen parameter. That
distinguishes "I forged a cookie" from "the server overwrote my session", and it
is the difference between a session-fixation story and a broken-authorization
story.

### The write, closed with literal evidence

I did not stop at "the redirect looked right". I read the stored hash back over
HTTP and compared it against a hash I computed locally:

```
$ python3 -c "import hashlib; print(hashlib.sha256(b'ADMIN-TAKEOVER-BY-85').hexdigest())"
9c7cc5bd3399913605371ab81950b9bd38982f57c34cbfb248f28c89f418ae3f

$ curl -s "http://172.17.0.2:5000/dashboard?id=27"   # unauthenticated
passwordField.value = '9c7cc5bd3399913605371ab81950b9bd38982f57c34cbfb248f28c89f418ae3f'
```

Byte-identical. Admin's password in the database is now a value I chose. The
victim account at id 9 closed the same way (`c7d11317…` = `sha256("CHAINED-OWNERSHIP-9")`).

### The automated extraction the lab asks for

The platform description is *"practicar la vulnerabilidad IDOR y conseguir
automatizar la extracción de información de distintos usuarios registrados"*.
Done as specified — **zero credentials, zero session**:

| ID | Username | Email | Stored hash |
|---|---|---|---|
| 3 | juan.perez | juan.perez@example.com | `5e884898…d1542d8` |
| 4 | maria.garcia | maria.garcia@example.com | `5e884898…d1542d8` |
| … | … | … | … |
| 9 | miguel.hernandez | miguel.hernandez@example.com | `4fbfaa40…f5e7caed44` ← **my write** |
| 27 | admin | admin@company.com | `9c7cc5bd…f418ae3f` ← **my write** |
| 52 | pingu | pingu@pingu.es | `dd0284ae…902eb1060a3` |
| 53 | pepe | pepe@pepe.es | `7c9e7c14…5691834` |
| 54 | aidor | aidor@aidor.es | `7499aced…251e0fc35` |
| 55 | probe.aa11 | probe@lab.local | `4fbfaa40…f5e7caed44` ← **mine** |

52 pre-existing records, ids **3–54**. Ids 1 and 2 do not exist and return
`302`, which is what proves the enumeration is complete rather than merely long.

The same-`5e884898…` hash on 50 filler accounts is `sha256("password")`, verified
against the library rather than assumed.

---

## Findings

### 1. IDOR / missing object-level authorization on the dashboard — CWE-639

**Evidence** (`app.py:100-120`, read from the deployed artefact):

```python
100: @app.route('/dashboard')
103:     user_id = request.args.get('id') or session.get('user_id')
110:     cursor.execute('SELECT * FROM users WHERE id=?', (user_id,))
118:     session['user_id'] = user[0]
120:     return render_template('dashboard.html', user=user)
```

Executed: as `probe.aa11` (id 55) → `GET /dashboard?id=27` → `200`,
`Bienvenido, admin`, `user-id">#27`, `admin@company.com`.

**Impact.** Any authenticated user reads any other user's full profile —
username, e-mail, and password hash. 52 records in scope, including `admin`.

**Root cause.** The object lookup is keyed on a client-supplied identifier with
no ownership predicate. The handler authenticates the *request* and then
authorises the *object* by nothing at all.

**Remediation.** Bind the object to the subject in the query itself, never in a
parameter that precedes the session:

```python
user_id = session.get('user_id')                      # session only
cursor.execute('SELECT * FROM users WHERE id=? AND id=?', (user_id, user_id))
```

If a self-service route genuinely needs an arbitrary id, authorise it explicitly
(ownership **or** an admin role) — and then remove the `session['user_id']=`
write at line 118, which is finding 3.

### 2. Unauthenticated access to every user record — CWE-306 / CWE-862

**Evidence.** The same request, **no `Cookie` header sent at all**:

```
$ curl -sS -o u_admin.html -w "%{http_code}\n" "http://172.17.0.2:5000/dashboard?id=27"
200
$ grep -oE 'Bienvenido, [a-z.]+|user-id">#[0-9]+' u_admin.html
Bienvenido, admin
user-id">#27
```

`app.py:103` reads `request.args` **before** `session`, and `app.py:105` only
redirects when *both* are empty. No `?id=` ⇒ no authentication check ever runs.

**Impact.** This is the more severe of the two: it needs no account, no
credential, and no prior access. Full user table disclosure to an anonymous
client in 52 requests.

**Root cause.** Authentication is expressed as *fallback* (`A or B`) rather than
as a *precondition*. Line 105 enforces "have I got an id?" and mistakes that
for "am I authenticated?".

**Remediation.** Authenticate before the object is ever resolved. A `login_required`
decorator on the route makes the `?id=`-only case structurally impossible.

### 3. Session identity rewritten from a request parameter — CWE-620 / CWE-384-adjacent

**Evidence.** `app.py:118`, `session['user_id'] = user[0]`, executes on a
*victim* row. Then, on a request carrying **no `id` parameter**, the session
renders as the victim:

```
hop0 my own session identity:            user-id">#55
hop1 after GET /dashboard?id=27:         user-id">#27
```

and the write that follows targets the victim, proven by the stored hash
matching `sha256("ADMIN-TAKEOVER-BY-85")` byte-for-byte, and by hop 4 — a
**fresh, unauthenticated** login as `admin` succeeding with `302`.

**Impact.** Full account takeover of any user including `admin`, from any
starting account, in three requests. The session is laundered: the attacker's own
identity is overwritten, so audit logs of `session['user_id']` show the victim.

**Root cause.** Assigning a *request-derived* value into the *session* is an
unauthenticated privilege transfer. Every downstream route that reads
`session['user_id']` inherits it; `/change_password` at `app.py:128` is the
exploitable consumer.

**Remediation.** A handler must never write a client-supplied identifier into
session state. `user_id` in the session must be set **only** at successful
authentication (`app.py:55` and `app.py:94`, the only two legitimate sites) and
be immutable thereafter.

### 4. Password hashes rendered into the page, and pre-filled into a visible field — CWE-200 / CWE-522

**Evidence.** `dashboard.html:628` prints `{{ user[2] }}` — the stored hash — and
`dashboard.html:709-714` goes further, in the template's own words:

```javascript
710:  // NOTA: En un entorno real esto NO se debería hacer por seguridad
712:  const passwordField = document.querySelector('input[name="new_password"]');
713:  passwordField.value = '{{ user[2] }}';
714:  passwordField.type = 'text';
```

Retrieved unauthenticated:

```
password-hash">d033e22ae348aeb5660fc2140aec35850c4da997
passwordField.value = 'd033e22ae348aeb5660fc2140aec35850c4da997'
```

**Impact.** The hash is a `GET`-parameter disclosure on its own, and it is
**one click** from plaintext credentials: the app pre-fills the *new password*
field with the hash and flips it to `type='text'`. Every one of the 50 filler
accounts shares `sha256("password")`, so the entire user table cracks at once
against a dictionary of size one. This is what turns finding 1/2 from a P3
disclosure into a full-credential compromise, and it is a **separate root cause**
from the missing ownership check — patching the SQL alone does not fix it.

**Remediation.** Never render a credential, in any encoding, into a response or
a DOM value. Remove lines 709-714 entirely; the comment acknowledges the
anti-pattern and ships it anyway.

### 5. Werkzeug interactive debugger exposed to anonymous clients — CWE-489

**Evidence.** `app.py:150`, `app.run(debug=True, …)`. Forcing one unhandled
exception with `POST /` missing the `password` field returns `500` whose body
contains, for an **anonymous** client:

```
Traceback (most recent call last)
  File "/home/app.py", line 43, in index
    password = request.form['password']
SECRET = "MvJLSdYSNpe9xgZz3Iyj";
The console is locked and needs to be unlocked by entering the PIN.
```

**Impact, and the limit of it.** Proven: full source disclosure, internal paths,
the debugger `SECRET`, and a live PIN-gated console. I derived the PIN the
running app computes — `906-399-845` — and it did **not** yield code execution;
`/console` and the `?__debugger__=…` GET returned `400`, and the `cmd=…` request
returned the ordinary login page, i.e. the parameters were ignored. **I therefore
do not claim RCE.** See *NOT tested*. The exposure is real on its own terms: a
hardcoded `secret_key` is the same line of code, and this ships both.

**Remediation.** `debug=False`. Gate on an environment flag, never on a literal
in a lab-shaped image.

### 6. Hardcoded Flask session secret — CWE-798

**Evidence.** `app.py:7`, `app.secret_key = 'my_secret_key'`.

**Impact.** The session cookie is a client-side signed blob keyed on a constant
that is published in the image. In a real deployment this alone is session
forgery. **I did not forge a cookie** — with findings 2 and 3 there is no need,
and the honest statement is that the weakness is proven from source and its
exploitation is *not* demonstrated here. Filed separately so that a client
cannot read finding 3's remediation and conclude the secret key is handled.

**Remediation.** Load from environment/secret store; rotate.

---

## Controls that held

| Control | Positive control that proves this detector works |
|---|---|
| Login authentication on `POST /` | `admin` + my chosen password → `302`; wrong password → `401`. Both seen, so the `401` is a real refusal and not a broken endpoint. |
| The `302`-vs-`200` discriminator itself | Positive: `id=55` with my session → `200`, `user-id">#55`. Negative: `id=1`, `id=2`, `id=99999` → `302 Location: /`. The two are byte-distinguishable, so "I got admin's page" is falsifiable. |
| Object-existence oracle | `id=27` → `200`; `id=99999` → `302`. A 200 therefore *means* a real object, and enumeration completeness is provable, not assumed. |
| Write path detector | `POST /change_password` on my **own** id 55 → `Location: /dashboard?id=55`, then a fresh login with the new password → `302`. The detector fires on a legitimate write before I trust it on a cross-object one. |
| Cross-object write is real, not a coincidence of hashing | Stored hash read back equals a hash I computed **locally** with `hashlib`, not just "login works". Two independent channels agree. |
| Lab restore | `docker rm -f` + `docker run` from the image. Verified **positively**: `login_page=200`; id 9 back to `5e884898…`, id 27 back to `d033e22a…`; `probe present = False`; `max id = 54`. |

**Controls that did *not* hold** are findings 1–6. There is no fifth category
and the two lists are not merged.

---

## NOT tested vs discarded with reason

### NOT tested (no time, no tooling, or out of scope — not a negative result)

- **SSH authentication on `22/tcp`.** `sshpass` is not installed
  (`failed to execute process: No such file or directory (os error 2)` on every
  attempt), so the credential guesses never left the host. I am recording this as
  untested, **not** as "SSH is secure". The only `uid>=1000` account is `aidor`
  (`getent passwd`), whose web hash `7499aced…` did not match any candidate I
  tried. Whether the web-IDOR chain reaches SSH is **unknown**.
- **Crash-consistency of the SQLite writes** under concurrent
  `/change_password` on the same row. Not probed; a single-writer `sqlite3.connect`
  per request, so this is a robustness question rather than a security one here.
- **Whether `app.py:118` session rewriting is exploitable across Flask's cookie
  rotation** under `SESSION_COOKIE_SECURE` / a multi-worker deployment. The lab
  runs the Werkzeug dev server single-process, so the deployed topology cannot
  answer it.
- **Rate limiting / lockout on `/login`** and on the 52-request enumeration. The
  enumeration completed unthrottled, which is a note, not a tested control.

### Discarded with reason (tried, and the reason it was dropped)

- **`admin`'s stored hash `d033e22ae348aeb5660fc2140aec35850c4da997` is
  `md5("admin")`.** Discarded — **I asserted this from memory and it is false.**
  `hashlib.md5(b"admin")` = `21232f297a57a5a743894a0e4a801fc3`. The guess is a
  32-char MD5 while the app hashes with SHA-256 (`app.py:46`), so the two are not
  even comparable. No plaintext for `admin` was recovered by guessing. The
  takeover in finding 3 does not depend on cracking it, which is exactly why it
  is the stronger result.
- **"Werkzeug `/console` gives RCE."** Discarded as **unproven**, not as false.
  The PIN derived correctly (`906-399-845`, from `get_pin_and_cookie_name` on the
  live app) but the console returned `400` and the `cmd=` request returned the
  login page. Per the runbook's no-oracle rule I will not file a claim about the
  future as a result.
- **Python-library fingerprinting from the banner** (`Werkzeug httpd 3.1.3`) as
  evidence for a CVE. Discarded: the version is a banner claim. The real version
  evidence is the traceback paths at `/usr/lib/python3/dist-packages/werkzeug/`,
  which is why finding 5 is filed on `app.py:150` and not on a CVE.

---

## Instrumentation defects

The most valuable section. **Three of my own failures produced output that
looked exactly like a result.** All three are recorded because the reader is
entitled to know which of the evidence above was nearly a lie.

### 1. A cookie jar that read but never wrote — manufactured a *false negative*

The first write attempt returned `Location: /dashboard?id=55`, and I read that as
"the write failed, the session was not poisoned". **Both halves of that reading
were wrong.** I used `curl -b c_chain.jar`, which loads the jar but **does not
persist a `Set-Cookie` to it**; the poisoned session from the preceding IDOR
request was discarded between calls, so the POST went to my own id 55. The
`id=55` in the redirect was not a failure signal at all — it was the successful
write landing on my own account, verified afterwards when logging in with
`CHAINED-OWNERSHIP-9` returned `302` where `ProbeAA11` returned `401`.

**What caught it:** the redirect target is the *object id the `UPDATE` used*, so
an unexpected value is a claim about the write, not about the session. Re-running
with `-b jar -c jar` produced `id=9` and the victim takeover.
**The lesson:** for a stateful-cookie vector, *persisting the cookie is part of
the exploit*, and a jar used read-only will silently convert a working attack into
a clean-looking `401`/`id=own` result.

### 2. A control that was silently a second attack

I intended a benign control — "the same `POST /change_password` on my **own**
account must also work, proving the detector is not lying." I ran it with
`c_chain.jar`, the **poisoned** session from finding 3. It wrote
`probe-self-test` to **victim id 9** and reported `Location: /dashboard?id=9`,
which I initially read as the control passing. Reading id 9's hash back gave
`4fbfaa40…`, which is `sha256("probe-self-test")` — my "control" had mutated a
third account.

**What caught it:** comparing the read-back hash against hashes I computed
locally. One of them belonged to a password I had only ever sent in a *control*.
**The lesson:** a control run on a session that is already in the compromised
state is not a control, it is a second exploitation. State every control's
starting identity explicitly or it will silently inherit the attack's state.

### 3. An arithmetic slip in my own restore verification

I asserted the shipped database holds "54 users". It holds **52** (ids 3–54,
with 1 and 2 absent). The restore check printed `rows = 52`, which contradicted
the number I had written down. The container was correct; my expectation was not.
**What caught it:** `max id = 54` and `rows = 52` are consistent only if 1 and 2
are missing — which is the same fact the `302` on `?id=1` and `?id=2` reported
independently over HTTP. Two sources agreed; my headcount was the odd one out.

### Defect that did *not* mislead me, recorded anyway

`sshpass` being absent produced six identical
`failed to execute process: No such file or directory` lines. Six identical
"failures" from six different credential guesses is the shape of an
**instrumentation** failure, not six authentication refusals. Reporting them as
six failed logins would have manufactured a negative. Listed under *NOT tested*.

---

## Reward

**No reward exists for lab 85.** Measured absence, with the search that
established it — not an assumption:

1. **Platform lab page.** `GET https://dockerlabs.es/maquinas/85` → `404`;
   `GET /maquina/85` → `404`. No page exists from which a flag could be read.
2. **Platform download page**, the one endpoint that *is* authenticated and
   live: `GET /maquinas/85/descargar` → `200`, body grepped for
   `flag{…}`, `DL{…}`, `FLAG`, `congratul`, `reward`, `recompensa` → **no match**.
3. **Full archive manifest.** `unzip -l aidor.zip` contains exactly two entries:
   `aidor.tar` and `auto_deploy.sh`. No flag file, no README, no `.txt`.
4. **Whole image filesystem**, exhaustively and as root:
   `grep -rIoE "(FLAG|DL|CTF|HTB)\{[^}]{1,80}\}" /` excluding `/proc` →
   **zero matches**.
5. **Reachability check.** The only candidate privileged location is
   `/root` (`drwx------ root root`, containing `.ssh/`, `.sqlite_history`).
   Reaching it needs code execution, and I did not achieve code execution
   (finding 5). So a flag in `/root` cannot be excluded — it is **absent from
   every place a flag would be published**, and if one exists it is
   unreached, not undiscovered.

This is consistent with the corpus: 22 of 27 previous engagements had no
`FLAG{}` either. **The IDOR is the lab's deliverable** — the platform description
asks for automated extraction of registered users' data, and §Chain delivers
exactly that, 52 records, unauthenticated. No reward was invented to fill the gap.

---

## Feed-forward

Per RUNBOOK stage 10, `INDEX.md` was checked before writing. **IDOR is absent
from the class catalogue** (`RUNBOOK.md:121-133`) — no row, no heading. This is
a genuinely new class, and the row that should land in `api_web.md` is the
**entry criterion**, not the payload:

> A request is IDOR — not merely unauthenticated — when an authenticated
> principal is presented and the server returns an object that is not theirs.
> The discriminator is the presence of a subject, so an auditor must run three
> requests, not two: an object you own (`200`, positive control), an object you
> do not own (`200` ⇒ IDOR), and an object that does not exist (`302` ⇒ the
> oracle is live and the 200s are real). A route that returns `200` for
> `?id=<other>` **without any session** is a *different finding* — unauthenticated
> BOLA — and merging the two tells the client they patched one thing.
>
> Read the `WHERE` clause, not the `WHERE` *guard*. `?id` outranking the session
> in an `A or B` is unauthenticated by construction; and a handler that writes a
> request-derived id back into `session` (`app.py:118`) converts a read bug into
> account takeover on the next route that trusts the session — which no status
> code will show you.

Two rules this lab adds that the runbook does not yet carry:

- **A stateful-cookie vector has a step the payload does not.** Persisting the
  `Set-Cookie` between the poisoning request and the next one *is* part of the
  exploit. A jar used read-only converts a working attack into a clean negative
  (defect 1). And no control may run on a session already in the compromised
  state, or it becomes a second attack (defect 2).
- **Close a write with a value you computed, not a status code.** `302` proves
  the endpoint responded. Comparing the stored hash against a locally computed
  hash proves the write landed where I claim, on an independent channel.

---

## Lab restored

```
docker rm -f aidor_container && docker run -d --name aidor_container aidor:latest
```

Verified **positively** (not by absence of damage):

- `login_page=200` — the service answers again.
- `id=9` → `5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8` (shipped)
- `id=27` → `d033e22ae348aeb5660fc2140aec35850c4da997` (shipped)
- `probe present = False`, `max id = 54`, `rows = 52` — the shipped 52 accounts, my
  three mutated rows and my throwaway account gone.
- Container `/tmp` is empty and carries the shipped `Nov 17 2025` mtime. Nothing
  of mine is in it.
- One artefact of mine was found in the **originals** directory — a stray `p.html`
  from a `curl -o` that landed in the shell's working directory — and was removed.
  `labs/85/` now contains exactly `aidor.tar` and `auto_deploy.sh`, as shipped.
  No file created by another principal was touched.
- All scratch files (cookie jars, bodies, `extraction.txt`) live in
  `/tmp/opencode/aidor/`, outside the lab and the evidence repo.
