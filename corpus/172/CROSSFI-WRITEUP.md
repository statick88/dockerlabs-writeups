# Crossfi (DockerLabs 172) — CSRF at two levels

**Lab:** 172 · *Crossfi* · Medio · author *El Pingüino de Mario*, 27/11/2025 · category `Bug Bounty`
**Description (full, from the platform catalog):** *"Laboratorio para explotar la vulnerabilidad CSRF en dos niveles distintos, primero en la funcionalidad de cambio de contraseña y después en detectar el campo vulnerable donde no se incluye la cabecera CSRF."*
**Target:** `http://172.17.0.3:5000` — single container `crossfi_container`, image `crossfi:latest`
**Stack (from the artefact):** Flask 3.1.2, Werkzeug 3.1.3, Python 3.13.5, SQLite, `flask-wtf==1.2.2` **installed but never imported**
**Outcome:** token-less state change on a victim's session at **two** levels; independently, a forged session cookie that makes the CSRF token forgeable and yields unauthenticated account takeover; and, via the credentials the app itself hands out, `uid=1000(balulero) euid=0(root)`.

---

## 1. The class gap, stated before the findings

CSRF is not in `INDEX.md`. It is also the class most often filed wrongly, because three
different claims get collapsed into the word "CSRF". This engagement separates them,
and says which ones the lab actually contains.

| # | Claim | What it requires to be true | Present here? |
|---|---|---|---|
| C1 | There is a **state-changing endpoint** a victim's browser can be made to issue | `POST/PUT/DELETE` that mutates something the victim cares about | **Yes** — `/change-password` (`app.py:143`) |
| C2 | The session cookie is **`SameSite`** | absent from `Set-Cookie` ⇒ browser default applies | **Attribute absent** (`app.py` sets no `SESSION_COOKIE_SAMESITE`) |
| C3 | A **token exists** | `generate_csrf_token` (`app.py:68`) | **Yes**, and it *is* validated on 4 of 5 routes |
| C4 | The token is **actually checked** server-side | `validate_csrf_token` reached on the route | **No on `/change-password`; yes on 4 level-2 routes; absent on `/update-biografia`** |
| C5 | A **second, distinct** weakness | not the same bug twice | **Yes** — a sibling route with the token omitted |

**Entry criterion (the generalisable one):** *a state-changing request that an attacker can
cause a victim's browser to issue, and that the server honours.* Note what this criterion
deliberately does **not** require: it does not require a token to be absent, and it does
not require the victim's browser to be tricked into anything unusual. C2 matters because
it is a **browser-side** mitigation that sits in front of a server-side property — see
§6, where it is filed as a control that partly held.

The decisive artefact for all of this is `app.py`, and specifically **registration
order**: the level-2 module declares four guarded routes and then, immediately after,
one unguarded route with an identical auth decorator (`app.py:371-374`). Nothing about
the *response* distinguishes the two; only the source does.

---

## Surface

```
$ nmap -sV -Pn -p- 172.17.0.3
Not shown: 65533 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 10.0p2 Debian 7 (protocol 2.0)
5000/tcp open  http    Werkzeug httpd 3.1.3 (Python 3.13.5)
```

Two ports; `auto_deploy.sh` was **read, not run** (`labs/172/auto_deploy.sh:145` is the
`while true; do sleep 1; done` that never returns). It declares no networks, no
`macvlan --internal` segments, and a single `docker run -d` (`:129-132`) — so the
one-container topology is the intended one, confirmed by `ExposedPorts 22/tcp, 5000/tcp`.

**Hidden surface found.** A TCP scan cannot see the interactive Werkzeug debugger,
because it is not a port — it is a *response to a request that raises*. It is live:

```
$ curl -b <session> -X POST http://172.17.0.3:5000/change-password -d 'nothing=here'
HTTP/1.1 500 INTERNAL SERVER ERROR
Server: Werkzeug/3.1.3 Python/3.13.5
Content-Length: 17833
```

The body contains the debugger shell, with the source of the failing frame rendered
inline (`new_password = request.form['new_password']`, `app.py:146`) and the banner
`console is locked and needs to be unlocked by entering the PIN.` Reachable by **any
anonymous visitor**, because `/register` (`app.py:89`) is unauthenticated: register → log
in → trigger → full source disclosure. This is Finding 5.

**Versions read from the artefact, not from memory:** `requirements.txt` → `Flask==3.1.2`,
`flask-wtf==1.2.2`; `Server:` header → `Werkzeug/3.1.3 Python/3.13.5`.

---

## The class

**Entry criterion question that started it:** *is there a `POST` that mutates state and
that carries no proof the request came from the page that issued it?*

**Source that settled it:** `app.py:143-153`. The handler reads exactly one field
(`request.form['new_password']`), writes it straight to the `users` table, and never
consults a token. `validate_csrf_token` is defined 70 lines above at `app.py:74` and is
simply not called.

**And the sharpest single fact in the engagement.** `flask-wtf` is in
`requirements.txt` — the correct library is *installed* — and it is referenced nowhere:

```
$ grep -rn "flask_wtf\|CSRFProtect\|WTForms" /app/
(no output)
```

Confirmed at runtime, from the app's own config object:

```
>>> app.config['WTF_CSRF_ENABLED']
KeyError: 'WTF_CSRF_ENABLED'
```

`CSRFProtect(app)` is never called, so the config key is not merely `False` — **it does
not exist**. This is the cleanest possible separator between *a CSRF library is
available* and *CSRF protection is active*, and it generalises: on any machine, grep for
the protection's constructor before you grep for the vulnerability.

---

## Chain

The lab's design hands out SSH credentials on level-1 success (`app.py:179-180`,
`app.py:294-295`), so the graph of reach continues past the web app. Every hop was
executed, and every identity measured rather than assumed.

| # | → | Mechanism | Identity proof |
|---|----|-----------|----------------|
| 0 | victim `victima` | registers/logs in; holds `session` cookie | `Set-Cookie: session=…; HttpOnly; Path=/` |
| 1 | **Flask process, root** | attacker-driven `POST /change-password`, session cookie only, **no token**; DB password `victima123` → `CSRFLEVEL1_pwned` | `/proc/18/status` → `Uid: 0 0 0 0` (`ps`: `18 root python3 app.py`) |
| 2 | **Flask process, root** | `POST /update-biografia` with browser-cached HTTP Basic, **no token**; `biografia` `''` → `CSRFLEVEL2_pwned_marker_9f2a` | same PID 18, `euid=0` |
| 2' | **Flask process, root** | **forged** session cookie + attacker-chosen `csrf_token`; `nombre` → `TOKEN_FORGERY_PROOF`; `/dashboard` → `HTTP 200` with **no victim interaction at all** | forged cookie accepted by PID 18 |
| 3 | `balulero` | SSH with the credentials the app hands out (`app.py:294-295`) | `uid=1000(balulero) gid=1000(balulero) groups=1000(balulero)` |
| 4 | **`euid=0(root)`** | `/usr/bin/env` is SUID root; `env` does not drop privileges | `uid=1000(balulero) gid=1000(balulero) euid=0(root) groups=1000(balulero)` |

Hop 4 is reported as `uid=1000 … euid=0`, not as "root": the real uid never changes, and
collapsing that pair would hide exactly the fact that makes the escalation a *file
capability* problem rather than a switch-uid problem.

### Evidence — level 1 (`/change-password`)

```
$ curl -b victim.jar -X POST http://172.17.0.3:5000/change-password \
       -H 'Origin: null' -H 'Referer: file:///tmp/exploit.html' \
       --data-raw 'new_password=CSRFLEVEL1_pwned'
HTTP/1.1 200 OK
¡Enhorabuena! Has explotado la vulnerabilidad CSRF
pinguinitojeje

password before = victima123
password after  = CSRFLEVEL1_pwned
```

**Negative control** — the same request without the session cookie:

```
$ curl -X POST .../change-password -H 'Origin: null' --data-raw 'new_password=NO_COOKIE_SHOULD_FAIL'
HTTP/1.1 302 FOUND        Location: /login
password after = CSRFLEVEL1_pwned      ← unchanged
```

So the endpoint is not simply open; it is session-bound and token-less. That is the
precise shape of the flaw.

### Evidence — level 2 (`/update-biografia`)

```
$ curl -u pinguinito:pinguinitojeje -b l2.jar -X POST .../update-biografia \
       -H 'Referer: http://attacker.example/csrf.html' -H 'Origin: http://attacker.example' \
       --data-raw 'biografia=CSRFLEVEL2_pwned_marker_9f2a'
HTTP/1.1 302 FOUND        Location: /csrf-level2
biografia = ''  →  'CSRFLEVEL2_pwned_marker_9f2a'
```

No `csrf_token` field was sent, and the route never reads one. HTTP Basic auth is not a
CSRF defence: a browser re-sends cached Basic credentials on its own, so the attacker
needs only the victim to load a page.

---

## Findings

### Finding 1 — Level 1: `POST /change-password` has no CSRF token (CWE-352)

**Evidence:** `app.py:143-153`, template `dashboard.html:20-27` (the comment
`<!-- VULNERABILITY: No CSRF token here -->` is in the shipped source). Password
`victima123` → `CSRFLEVEL1_pwned` with only a session cookie.

**Impact:** full account takeover. The change-password form is the last line of defence
for an account; taking it removes the user's ability to recover the account at all.

**Root cause:** `validate_csrf_token` (`app.py:74`) is never called on this route, and
`flask-wtf` is installed but never initialised.

**Remediation:** `CSRFProtect(app)` as the first statement after the app object, and a
hidden `csrf_token` field in the form. Nothing else — a `Referer` heuristic is not a
substitute (Finding 3).

### Finding 2 — Level 2: `/update-biografia` omits the token its four siblings enforce (CWE-352, CWE-693)

This is what the lab's own description calls *"el campo vulnerable donde no se incluye la
cabecera CSRF"*, and it is a **different defect from Finding 1**, not a restatement:
Finding 1 is a module with no token; Finding 2 is a module that *has* a working token
system and one route that bypasses it.

```
app.py:304  /update-nombre       @requires_basic_auth   token = request.form.get('csrf_token')   ✔ checked
app.py:321  /update-edad         @requires_basic_auth   token = …                                 ✔ checked
app.py:338  /update-profesion    @requires_basic_auth   token = …                                 ✔ checked
app.py:355  /update-ciudad       @requires_basic_auth   token = …                                 ✔ checked
app.py:372  /update-biografia    @requires_basic_auth   ← no token read at all                     ✘
```

**The UI gives no way to tell the two apart — and asserts protection for both.** All five
profile fields carry the identical green `🔒 Protegido` ("Protected") badge
(`csrf-level2.html:33, 52, 71, 90, 109`), and all five are styled alike. Four of them
render a `csrf_token` hidden input (`:36, 55, 74, 93`); the fifth
(`:111-117`, the biography form) renders none. The badge is a *blanket* claim that is
false for one field in five, and because it is uniform it provides **no signal at all**
to a reader trying to identify which field is the vulnerable one. Anyone auditing this
page visually — which is the obvious way to audit a profile form — will conclude all
five are hardened.

**Impact:** arbitrary write to a shared `profile` row (`WHERE id = 1`,
`app.py:379`) — a single global record, so the attacker corrupts data belonging to
everyone using the level, not just the victim.

**Remediation:** the token check is duplicated by hand five times; that is why one copy
was missed. Apply it once, as a decorator or `before_request`, so the default is
"checked" and any new route is protected unless it explicitly opts out. Never assert a
security property from a CSS badge — derive the label from the guard that enforces it,
so a route that loses its guard also loses its claim.

### Finding 3 — The `Referer`/`Origin` logic is a *scorer*, not a control (CWE-693)

Both exploit handlers compute `is_exploit` **after** the write has already been committed
(`app.py:151` vs `:157-171`; `app.py:379` vs `:384-396`). It decides which template to
render. It cannot prevent anything.

The experiment that proves it — a request that keeps the *appearance* of being
legitimate, so `is_exploit` is `False` and the app reports ordinary success:

```
$ curl -b victim.jar -X POST .../change-password \
       -H 'Referer: http://172.17.0.3:5000/dashboard' -H 'Origin: http://172.17.0.3:5000' \
       --data-raw 'new_password=STEALTH_PLAIN'
HTTP/1.1 302 FOUND                      ← normal path, no congratulation modal
modal string count: 0
password = STEALTH_PLAIN                ← the account was still taken over
```

Same at level 2: with a same-origin `Referer`, `biografia` became `STEALTH_L2_no_flag`
and no success flag was set. **A defender reading the lab's own telemetry would have
recorded "no successful CSRF" for every request that actually succeeded.** This is the
single most transferable lesson in the engagement: a detector placed downstream of the
side effect is a reporting function. Ask of any CSRF control *where in the handler it
runs*, not whether it exists.

### Finding 4 — Hardcoded `app.secret_key` forges the session, which makes the token forgeable (CWE-798, CWE-384)

`app.py:9` — `app.secret_key = 'supersecretkey'`. Flask's session is a **client-side
signed** cookie, so anyone holding the key can mint an arbitrary session. The victim's
cookie is not even needed:

```
$ curl -H "Cookie: session=eyJ1c2VyX2lkIjoxLCJ1c2VybmFtZSI6InZpY3RpbWEiLCJjc3JmX3Rva2VuIjoiQVRUQUNLRVJfQ0hPU0VOX1RPS0VOX2ZmZmYifQ.arxIQA.pKncj1oJ-Kb2yMHeJW1PBEfVmzI" \
       http://172.17.0.3:5000/dashboard
GET /dashboard w/ forged cookie -> HTTP 200
```

**This is the deeper level-2 lesson, and it generalises past this lab.** The CSRF token
is *stored in the session cookie* (`generate_csrf_token`, `app.py:68-72`). A token bound
to a forgeable session is a token the attacker chooses. Proven directly — the *same*
route and the *same* handler that rejected a wrong token accepted an attacker-chosen one:

```
$ curl -u pinguinito:pinguinitojeje -H "Cookie: session=$FORGED" \
       -X POST .../update-nombre \
       -d 'nombre=TOKEN_FORGERY_PROOF' -d 'csrf_token=ATTACKER_CHOSEN_TOKEN_ffff'
nombre in DB = 'TOKEN_FORGERY_PROOF'
```

So the token control measured in §7 is real *against a browser-borne attack* and
**worthless against an attacker who knows the key**. Rank it accordingly, and never
report "CSRF is mitigated by a token" without asking where the token is stored.

**Impact:** unauthenticated impersonation of any user, with no victim interaction and
no CSRF at all. **Remediation:** load the key from the environment, rotate it, and
invalidate existing sessions. Keep CSRF tokens in a server-side store if you want them
to mean anything independently of the session key.

### Finding 5 — `debug=True` on `0.0.0.0`; interactive debugger reachable (CWE-489, CWE-215)

`app.py:408` — `app.run(debug=True, host='0.0.0.0', port=5000)`. An anonymous visitor
(register → login → malformed `POST /change-password`) receives a full Werkzeug debug
page with the failing source frame inline. The `/console` endpoint is mounted — it
answers `400`, not `404`, which is the signature of "present and PIN-gated" rather than
"absent".

I computed the PIN with Werkzeug's own algorithm (`werkzeug/debug/__init__.py:184-215`)
from the container's real `machine-id` (`b17fec3ca61f47399de27e6489347cd1`) and
`uuid.getnode()` (`134693594076093`), reproducing the cookie-name checksum `__wzd…` so
a mismatch would have been visible. `/console` still returned `400`: **the PIN is not
derivable from the data I could reach, and console RCE is NOT proven.** See §8.

**Remediation:** `debug=False` in production, behind a real WSGI server. Independently:
do not let an unhandled exception on an authenticated route return a stack trace.

### Finding 6 — Passwords stored and compared in plaintext (CWE-256, CWE-208)

`app.py:97` inserts the password verbatim; `app.py:118` compares with `user['password'] == password`.
Measured, not assumed:

```
>>> select id,username,password from users
[(1, 'victima', 'CSRFLEVEL1_pwned'), ...]
```

Any database read is an immediate credential dump. The CSRF finding *feeds* this one: the
password an attacker writes over CSRF is then stored in the clear.

### Finding 7 — State-changing `GET /logout`, no token (CWE-352, CWE-650)

`app.py:127-131`. Session cleared, reachable by a plain `GET` — no form, no token, no
`POST`. Measured: `GET /logout` → `302`, and the subsequent `/dashboard` → `302 /login`,
i.e. the session was destroyed. Filed separately from Findings 1-2 because its severity
and its reach differ (see §6).

### Finding 8 — The lab's own files ship the attack (informational, but it changes the threat model)

`/app/exploit.html` and `/app/exploit-level2.html` are in the image, and `INSTRUCCIONES_CSRF.md`
walks the solver through both. They post to `http://127.0.0.1:5000`, so they only work for a
solver running the app locally. Reported because it is a **deployment** fact: any instance
where the webroot is served — or where `/app` is otherwise reachable — hands the attacker
a working CSRF page for free.

---

## Controls that held

Each row is a control that was **observed to fire**, with a positive control proving the
detector is not simply broken. A control that has never seen a success is not a control.

| Control | Where | Positive control that proves this detector works |
|---|---|---|
| **Session binding on `/change-password`** | `app.py:144` `@login_required` | Detector **fires** without a cookie → `302 Location: /login` and the password is **unchanged**. With the cookie → `200` and the password **changes**. The same detector produces both outcomes, so the rejection is attributable to the cookie and not to a dead route. |
| **HTTP Basic on all 5 level-2 routes** | `app.py:56-65` | `POST /update-nombre` with no credentials → `401` + `WWW-Authenticate: Basic realm="CSRF Level 2"`. Gate demonstrably fires. |
| **CSRF token on `/update-nombre` (and 3 siblings)** | `app.py:307-310` | Proven **in both directions**: wrong token → write rejected, `nombre` stays `''`, literal `Token CSRF inválido`; **valid** token on the same route → write **succeeds** (`nombre = 'Auditor Metodologia'`). Sending no token at all → rejected. The second direction is what makes the first meaningful: it proves the rejection was the *token*, not a broken endpoint. |
| **`HttpOnly` on the session cookie** | observed `Set-Cookie: … ; HttpOnly; Path=/` | Present in the header on every issuance. Not bypassed anywhere in this engagement. |
| **Ownership scoping on task API** | `app.py:243`, `:270` | `WHERE id = ? AND user_id = ?` on PUT and DELETE — the query binds the row to the session's user rather than trusting a path id. A clean negative. (Read-only check; see §8.) |
| **The lab's own hint at `flag` absent** | — | A file named `*flag*` that contained a flag would have been found by the same `find` that located `hint.txt`. See §9. |

**The reportable negative:** the token rejection is **not** silently reported as ordinary
success — it emits a distinct message (`Token CSRF inválido`) and the write does not
happen. The control fires *and* is distinguishable from success, which is the ideal
shape. By contrast the `Referer`/`Origin` heuristic (Finding 3) is a control that fires
but reports success on exactly the requests that harmed the user — the worst of both.

---

## NOT tested vs discarded with reason

**NOT tested** (honest gaps, not conclusions):

- **Browser-side delivery.** No browser was available, so I did not observe a real
  cross-origin navigation. Everything above is server-side behaviour proven with the
  session cookie supplied directly. Whether a given browser attaches the cookie to a
  given cross-site request is stated in §6 as browser policy, not as a measurement.
- **Werkzeug debugger PIN.** Mounted, checksum-verified, not derived (§8). Console RCE
  is neither claimed nor refuted.
- **Task API authorisation at runtime.** The `AND user_id = ?` scoping
  (`app.py:243`, `:270`) is read from source and was not exercised with a second user's
  `task_id`. It is listed under "controls that held" as a **source-read** result and is
  flagged here so it is not over-read.
- **Full `/api/tasks` CRUD** — not exercised end to end; it is a `localStorage`-fronted
  demo (`app.js:26-33`) and not part of the declared class.

**Discarded with reason:**

- **XSS.** The task framing warns that CSRF and XSS get conflated. I found no injection
  sink reaching a browser: Jinja2 autoescapes, and the one `| safe` filter
  (`dashboard.html:47`) renders `success_message`, a server-built literal, not user input.
  Discarded on source evidence, not on absence of testing.
- **Session fixation / `Secure` flag.** `SESSION_COOKIE_SECURE=False`, but the lab is
  plain HTTP and there is no TLS to downgrade; flagged, not filed as exploitable here.
- **Container escape.** No socket, no `docker.sock`, no privileged flag. `/proc/self/status`
  read from inside showed no unexpected capabilities. Not pursued further.

---

## Instrumentation defects

The most valuable section, per the runbook. One of these nearly produced a false finding,
and one produced a *false confirmation*.

### 1. `rtk curl` silently drops `-H` headers — this inverted a finding

My first stealth test sent a **same-origin** `Referer`/`Origin` and reported the success
modal, i.e. it suggested the `is_exploit` check could be defeated. It was wrong. The
headers were never sent. Isolated with identical arguments:

```
$ rtk curl  … -H "Referer: http://172.17.0.3:5000/dashboard" -H "Origin: …"  → 0 request headers
$ curl      … -H "Referer: http://172.17.0.3:5000/dashboard" -H "Origin: …"  → both headers present
```

**What caught it:** I had already computed the server's branch logic by hand
(`app.py:163-171` vs `request.host_url`) and it said `is_exploit = False` for those
headers. The instrument and the source disagreed, so the instrument was the suspect.
**Lesson:** a wrapper that takes the same flags as the tool underneath it is not the
same tool. For any finding that depends on a *request header*, verify with `-v` that the
header arrived. This defect is invisible on success and only distorts negatives — the
direction that quietly manufactures findings.

### 2. A real 500 traceback made the debugger look like a 404

`/nope-404` returns an ordinary `404` with no debugger, so "the debugger is not exposed"
looked plausible from a single probe. It is wrong: the debugger only appears when a
handler *raises*, and the routes that raise are all **behind** `@login_required`. A
probe without a session is redirected before the exception can happen. An analyst who
tested unauthenticated and saw `404` would have filed "not exploitable".

**What caught it:** asking what makes the request *unusual* rather than only what makes
it succeed. The trigger is a malformed body, not a bad path.

### 3. The lab's own scoring logic is a decoy

Findings 1-2 and this one are the same underlying weakness viewed two ways, and the
conflation risk is real. The congratulation modal and the SSH credentials are emitted by
`is_exploit`, which sits **after** the write. Treating the modal as "exploit succeeded"
inverts the truth: a stealth request gets **no** modal and **still** succeeds. The modal
is the lab's reward, not a security control, and treating it as one produces a writeup
that says the opposite of the truth.

---

## Reward

**No `FLAG{}` or `DL{}` exists in this lab.** Measured as `euid=0(root)`, not guessed:

```
$ grep -rIoh -E 'DL\{[^}]*\}|FLAG\{[^}]*\}|flag\{[^}]*\}' / --exclude-dir=proc --exclude-dir=sys
(no output)

$ find / \( -name '*flag*' -o -name '*reward*' -o -name '*secret*' -o -name '*.txt' \) -type f
  …  /home/balulero/hint.txt
  …  /app/requirements.txt
```

`/root` and `/home/balulero` were listed in full at root privilege; `/opt` and `/srv` are
empty. The only `*flag*` hits are unrelated (`tty_flags.h`, `dpkg-buildflags`,
`kpageflags`). The two credential-shaped values the app hands out —
`pinguinito:pinguinitojeje` (`app.py:179-180`) and `balulero:balulei`
(`app.py:294-295`) — are **not** a flag: both are hardcoded in the source and both are
reached without difficulty.

**The lab's actual reward is the level-2 transition itself**, gated on `is_exploit`. Its
own instructions call the SSH credentials *"ficticias"* (`INSTRUCCIONES_LEVEL2.md`),
and that is **wrong** — `balulero` exists as `uid=1000` and sshd is running; the
credentials work. Reported as a measured absence with the search that established it,
not invented.

---

## Restore

```
$ docker rm -f crossfi_container && docker run -d --name crossfi_container crossfi:latest
restored IP=172.17.0.3
```

Verified **positively**, not by "the container is up":

```
GET /login                 -> HTTP 200
select count(*) from users -> 0            (all test accounts gone)
profile.biografia           -> ''           (my level-2 write gone)
```

The container was recreated from the image rather than reverted, so the SQLite writes,
the forged sessions and the PIN scratch file are gone by construction. Nothing was
written outside `/tmp/csrf172`; nothing under `labs/` was modified. `git commit` and
`git push` were not run (`git status` read only).

---

## Feed-forward — the CSRF section the methodology lacks

`INDEX.md` has no CSRF row, and after 27 labs the omission is surprising. The four rules
this engagement produced, in the order that would have saved time:

1. **Grep the protection's constructor, not the vulnerability.**
   `flask-wtf` was in `requirements.txt` and absent from `app.py`. A dependency listing
   is evidence of *availability*, never of *enforcement*.
2. **Ask where the control runs relative to the side effect.** Here the check is at
   `app.py:157` and the write at `app.py:151`. A guard downstream of the damage is a
   reporting function; its absence of alerts is not evidence of safety.
3. **A token's strength is the strength of whatever holds it.** The token here is
   correct, enforced, and forgeable, because the session key at `app.py:9` is hardcoded.
   Before filing "CSRF mitigated", establish where the token is *stored*.
4. **A missing `SameSite` is a browser-side control, and it is partial.** It blocks the
   cross-site `POST` but not the top-level `GET` — which is why `GET /logout` (Finding 7)
   remains reachable while the two `POST` endpoints are hardened against it in a modern
   browser. Record SameSite state, then record what it does *not* cover.

Two structural notes for the class: CSRF and XSS must stay separate (no injection sink
existed here — see §8), and **"a token exists" is a fourth, separate question from
"a token is checked"**, which is a fifth question from "the token is unforgeable". Most
CSRF writeups collapse all three into the first.
