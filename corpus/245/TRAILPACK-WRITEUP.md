# 245 TrailPack — writeup

> **Shipped catalogue description, verbatim from `catalog.txt:14`:**
> `245|TrailPack|medio|Laboratorio para practicar distintas vulnerabilidades web, de tal forma que concatenando pequeñas vulnerabilidades consigamos un gran impacto.`
>
> Translation: *a lab for practising distinct web vulnerabilities, such that by
> chaining small vulnerabilities you obtain a large impact.* The description names
> **no class, no platform and no route** — so there is nothing in it to be
> misattributed. What it *does* assert is a **chain**, and the chain is the
> deliverable here: which of the four declared bugs is load-bearing for which, and
> which one can be deleted from the report without changing the outcome.

**Manifest line (confirmed, not duplicated):** `tooling/labs.manifest:83`
`245|TrailPack|medio|several web vulnerabilities in one lab`

---

## 1. Platform — from a version-bearing file, before anything else

The queue entry asserts **no platform**, so there is no filename to misread. The
platform was read from `requirements.txt` and confirmed against the **running
interpreter**, not against the file (§21 — measure what the framework consumes):

`/app/requirements.txt` (verbatim, 4 lines):

```
fastapi==0.115.12
uvicorn[standard]==0.34.2
jinja2==3.1.6
python-multipart==0.0.20
```

`python3 -c "import fastapi,uvicorn,jinja2,starlette; …"` **inside the live
container**:

```
python 3.11.2
fastapi 0.115.12
uvicorn 0.34.2
jinja2 3.1.6
starlette 0.46.2
python-multipart 0.0.20
```

The declared and the consumed versions **agree on all four pins**. `starlette` is
pulled transitively and is not pinned — recorded, because it is the layer that
owns `Jinja2Templates` and therefore owns the autoescaping decision tested in §7.

**The artefact is a 292-line single-file FastAPI application plus 7 Jinja
templates.** `wc -l /app/main.py` → **292**; `find /app -type f` → **9 files** on a
cold container and **10** after first start, when
`__pycache__/main.cpython-311.pyc` appears. There is no
CMS, no `wp-content`, no plugin tree, no `vendor/`, no ORM, no database process,
and no `requirements`-declared web server other than uvicorn. The image's
`Config.Cmd` is `["python3","-m","uvicorn","main:app","--host","0.0.0.0","--port","8000","--log-level","warning"]`
with `User: balutron` and `WorkingDir: /app`.

> **Cross-read against sibling 242.** That lab is *also* a FastAPI app whose
> accounts are keyed by Spanish DNI (`71902345A` …). This is a **different
> application** — different file names, different route set, different author
> comments (`⚠️ VULN-N`), no shared code — but the **identifier namespace is the
> same shape**. 242's "existence oracle over a structured identifier" class
> therefore applies here too, and it is carried by VULN-1 below. Rule 8: stated
> explicitly rather than quietly differing.

### Acronym check (§28)

The catalogue description contains **no acronym** and no protocol name, so the
242 failure — a queue entry re-expanding an abbreviation to the wrong protocol —
**cannot arise here**. Checked and closed rather than assumed: `grep -rIo -i "dns"`
style expansion is not applicable; there is nothing to expand.

---

## 2. Surface

`nmap -sV -Pn -p- 172.17.0.7` (verbatim tail):

```
Nmap scan report for 172.17.0.7
Host is up (0.000045s latency).
Not shown: 65534 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
8000/tcp open  http    Uvicorn
```

**A second instrument, because `-p-` is TCP by definition** (retrieval-hazards,
row 1): `/proc/net/tcp` inside the container → **1** data row,
`00000000:1F40 0A` (`1F40` = 8000, state `0A` = LISTEN), owned by uid 1000.
`/proc/net/udp` and `/proc/net/udp6` → **0 data rows each** (1 header line per
file, counted). Image `Config.ExposedPorts` = `{"8000/tcp":{}}`. **No UDP surface
exists** — and it is a property of the target, not a process that failed to start:
the process serving 8000 was demonstrably up (`GET /` → `200`, 19 492 B) for every
measurement below, so §23 is not in play.

### Route enumeration, with the impossible-name control planted FIRST

Lab 87 and lab 188 both produced sweeps that reported phantoms. So the control went
in **before** the sweep, not after. **16 paths** probed; `/zzq7x-not-a-real-path-9f3a`
cannot exist and is the baseline:

| Path | Status | Bytes | Content-Type | Body md5 (12) |
|---|---|---|---|---|
| `/` | 200 | 19 492 | `text/html` | `f0af8e617361` |
| **`/zzq7x-not-a-real-path-9f3a` (control)** | **404** | **22** | `application/json` | **`689525ee6c81`** |
| `/zzq7x2` (2nd control) | 404 | 22 | `application/json` | `689525ee6c81` |
| `/register` | 200 | 13 322 | `text/html` | `c79d9f391680` |
| `/login` | 200 | 11 078 | `text/html` | `7f6f4502cab1` |
| `/verify-mfa` | 307 | 0 | — | → `/login` |
| `/dashboard` | 307 | 0 | — | → `/login` |
| `/accounting` | 307 | 0 | — | → `/login` |
| `/quejas` | 405 | 31 | `application/json` | `2d7d30ea1c6f` |
| `/api/me` | 401 | 24 | `application/json` | `9791d290f82b` |
| `/logout` | 303 | 0 | — | → `/` |
| `/static/nope.css` | 404 | 22 | `application/json` | `689525ee6c81` |
| `/admin` | 404 | 22 | `application/json` | `689525ee6c81` |
| `/docs` | 404 | 22 | `application/json` | `689525ee6c81` |
| `/favicon.ico` | 404 | 22 | `application/json` | `689525ee6c81` |
| `/openapi.json` | **200** | **4 846** | `application/json` | `a1005d6c9147` |

**The control held and it is the reason the sweep is trustworthy.** Two
impossible names share one 22-byte JSON body, byte-identical to `/admin`,
`/docs`, `/favicon.ico` and `/static/nope.css`. **There is no catch-all vhost and
no phantom 200 in this lab** — 5 of 16 paths are genuinely absent, and the sweep
says so with a byte count rather than a status alone. This is the lab-87 trap
*not* firing, and the reason to say so is that the control was planted first.

`/openapi.json` is served even though `main.py:6` sets `docs_url=None,
redoc_url=None` — `openapi_url` is left at its default. It enumerates **12
routes**, which is **exactly** the set of `@app.<verb>` decorators in the
292-line source (`grep -c '^@app\.' /app/main.py` → **12**). **Completeness
cross-checked against the artefact, not assumed**: 12 declared = 12 present,
0 hidden routes.

Cross-checked the other direction: every endpoint the templates reference exists.
`grep -rho 'href="/…"\|action="/…"\|fetch(…)'` over all 7 templates → **17**
occurrences, **11 distinct** endpoint strings (`/` ×1, `/register` ×3 +
`action` ×1, `/login` ×2 + `action` ×1, `/verify-mfa` ×1, `/quejas` ×1,
`/api/me` ×1, `/accounting` ×1, `/dashboard` ×3, `/logout` ×2) — **all 11**
resolve to a declared route. No dead link.

---

## 3. The class, and the independence question

The author's own source names four bugs. All four comments, verbatim, with the
only other `VULN-` hits being the two extra annotations of VULN-3:

```
main.py:68     # ⚠️ VULN-2: acepta IP desde cabeceras controladas por el cliente
main.py:79     # ⚠️ VULN-3: cookie base64 sin firma
main.py:122    # ⚠️ VULN-1: mensaje diferenciado revela si el DNI existe (user enumeration)
main.py:216    # ⚠️ VULN-3: cookie sin firma — httponly=False para que el JS la lea/escriba
main.py:242    # ⚠️ VULN-4: inyección de comandos — entrada del usuario sin sanitizar en llamada shell
main.py:275    # ⚠️ VULN-3: rol leído de cookie sin firma — falsificable desde el cliente
```

**Entry criterion for the whole lab:** *which request value reaches a sink, and
what does the sink's decision rest on?* Read off the source before any request:
`main.py:245` `f"echo {queja}"` with `shell=True`; `main.py:277`
`if info.get("role") != "admin"` where `info` came from a **client cookie**;
`main.py:186` `ip = _client_ip(request)` where `ip` is the **rate-limit key** and
`_client_ip` reads `X-Forwarded-For` first.

### The dependency graph, and what each arrow is worth

```
   VULN-2  X-Forwarded-For is the rate-limit key
        │  (the ONLY thing that makes a 10 000-value PIN space attackable)
        ▼
   MFA brute force  →  SESSIONS[sid]           (main.py:212, the sole writer)
        │
        ├──────────────► VULN-4  command injection      /quejas
        │                 (needs a session; does NOT need admin, does NOT need VULN-3)
        │
        └──────────────► VULN-3  unsigned cookie        /accounting
                          └──► FLAG{…}
```

| Pair | Does one enable the other? | Evidence |
|---|---|---|
| **VULN-2 → VULN-3** | **Yes, and it is the only way in.** VULN-3 is unreachable without a `SESSIONS` entry, and `SESSIONS` is written at exactly one line, `main.py:212`, reachable only through the MFA check. | `grep -n SESSIONS` → **6 hits**: declaration `:63`, two reads `:76`/`:170`, **one write `:212`**, one `pop` `:287`. The `/accounting` gate needs `sess` *and then* the forged cookie. |
| **VULN-2 → VULN-4** | **Yes, same single door.** `/quejas` needs only `sess` (`main.py:239-241`), but `sess` still only exists post-MFA. | Measured: RCE reached with a **self-registered `role=user`** account, no forged cookie. So VULN-4 does **not** need VULN-3. |
| **VULN-3 → VULN-4** | **No. Independent.** Both hang off the same session but neither requires the other. | Measured in both directions, below. |
| **VULN-1 → anything** | **No. Inert.** | Measured in both directions, below. |

### VULN-2 is quantified, not asserted

The MFA PIN is 4 digits (`main.py:133`
`MFA_PINS[dni] = "".join(random.choices(string.digits, k=4))`), so the space is
**10 000**. The limiter is `main.py:199-203`: three wrong PINs, then
`blocked_until = now + 60`.

* **Without the header**, measured on one fixed source IP: attempts 1/2/3 returned
  `Código incorrecto. Intentos restantes: 2` / `1` / `0`; attempt 4 returned the
  blocked page — `Acceso suspendido temporalmente`, `<strong id="countdown">59</strong> segundos.`,
  9 265 B, status **200**. Attempt at t+62 s returned `Intentos restantes: 2`
  again ⇒ the block expires at 60 s exactly.
  ⇒ ⌈10 000 / 3⌉ = **3 334** windows × 60 s = **200 040 s = 55.5667 h** of
  wall-clock, per IP, and there is no second IP available without VULN-2.
* **With a rotated header**, measured: PIN `1845` found after **1 846** requests
  in **6.257 s** ⇒ **295.0 req/s** ⇒ the full space in **33.89 s**.
* **Speed-up: 5 901.8×.** Median case (5 000 guesses): **16.95 s** versus
  **27.78 h**.

That is the whole argument for VULN-2 in one line: it converts a 55-hour search
into a 34-second one, and it is the only difference between them.

### VULN-1 is inert — measured, not reasoned

**The control that settles it:** the reward was reached on an account I registered
**myself**, and the enumeration was never used at any point in the successful
path. Concretely:

```
POST /register  dni=55500011K&name=Probe&…   → 303   (account created)
POST /login     dni=55500011K&password=probe123 → 303 /verify-mfa   (session_id issued)
<1 846 requests with a rotated X-Forwarded-For>
POST /verify-mfa pin=1845                     → 303 /dashboard
GET  /dashboard                               → 200, 16 166 B
GET  /accounting  (forged role=admin cookie)  → 200, 18 395 B, the reward inside
```

Registration is open (`main.py:109-134`), so **an attacker never needs to know
that a DNI exists** — they mint one. And the enumeration discloses **only
existence**: `main.py:124` returns a string, never a password, a PIN, a balance or
a session. Deleting VULN-1 from the report changes nothing about the outcome.

### The lab defect: a constant that no code path reads

`main.py:57`

```python
TARGET_DNI = "71960227N"
```

`grep -rn "TARGET_DNI" /app` over **10 files** returns **exactly one hit** — the
definition itself (plus the compiled `main.cpython-311.pyc`). It is a dead
constant: written, never read, and **71960227N is the DNI of the first shipped
account**, i.e. the author appears to have left a checker marker that no code
consumes. This is the "secret that authenticates nothing" shape, in its mildest
form — a hint for a grader that grades nothing. It is also the fourth thing to
check after the 87/188 phantom sweeps and the 242 preloaded list, and it is
reported here as **the lab's problem, not the tester's**.

---

## 4. Findings

### F1 — CWE-639 / CWE-204: user enumeration on an unauthenticated endpoint

`main.py:121-124`, verbatim:

```python
    if dni in USERS:
        # ⚠️ VULN-1: mensaje diferenciado revela si el DNI existe (user enumeration)
        return templates.TemplateResponse(request, "register.html",
            {"error": "Este NIF ya está registrado. ¿Tienes cuenta? Inicia sesión."})
```

**Evidence (6 candidates, 1 control class):**

| DNI | Status | Body marker |
|---|---|---|
| `71960227N` | 200, 13 840 B | rendered at `register.html:21` `<p class="text-red-700 text-sm">{{ error }}</p>` → the served body carries `Este NIF ya está registrado. ¿Tienes cuenta? Inicia sesión.` |
| `71968040M` | 200 | same |
| `11325016T` | 200 | same |
| `11352580X` | 200 | same |
| `00000000A` | **303** | — (account created) |
| `99999999X` | **303** | — (account created) |

4 of 4 shipped DNIs distinguishable from 2 of 2 unoccupied ones. No credential,
no session, no data beyond a boolean — and it is the wrong boolean to give away.

**Impact:** names the four customer accounts of a financial application to an
unauthenticated caller, and pairs with F6 (weak passwords) as a targeting list.

**Fix:** return one response for every outcome, and make registration
idempotent-looking (always redirect to `/login`, send the "already registered"
notice out-of-band to the address on file).

---

### F2 — CWE-290 / CWE-350: authentication bypass of the MFA rate limiter

`main.py:67-73` and `main.py:186-188`, verbatim:

```python
def _client_ip(request: Request) -> str:
    # ⚠️ VULN-2: acepta IP desde cabeceras controladas por el cliente
    for header in ("X-Forwarded-For", "X-Real-IP"):
        val = request.headers.get(header, "")
        if val:
            return val.split(",")[0].strip()
    return request.client.host  # type: ignore[union-attr]
```

```python
    ip  = _client_ip(request)
    now = time.time()
    rl  = RATE.setdefault(ip, {"count": 0, "blocked_until": 0.0})
```

**The control that separates "header ignored" from "header used as the key"** —
this is the one measurement the finding rests on, because a rotation test alone
cannot tell a bypass from a server that never counted:

| Direction | Requests | Result |
|---|---|---|
| No header, one fixed IP | 5 | counter decrements `2 → 1 → 0`, then blocked (9 265 B, countdown **59**) |
| **Rotating `X-Forwarded-For`** | 6 | counter **frozen at `2` on all 6** |
| **Same header value reused** | 4 | counter **decrements `2 → 1 → 0`, then blocked** |
| Rotating `X-Real-IP` | 4 | counter **frozen at `2` on all 4** |
| Rotating **non-IP** garbage (`banana-0…3`) | 4 | counter **frozen at `2` on all 4** |

The third row is the load-bearing control: a *constant* header value still
throttles, which proves the header **is** the bucket key rather than being
stripped. The last row proves the value is never validated as an IP — it is an
arbitrary string, so no amount of parsing discipline on the server side would
help; only trusting the transport would.

Comma-list handling confirmed: `X-Forwarded-For: not-an-ip, 8.8.8.8` is accepted
(`main.py:72` `val.split(",")[0]`).

**Impact:** unbounded MFA guessing. 10 000-value space, measured **1 846 requests
in 6.257 s** with a rotated header versus a computed **55.5667 h** without one.
Combined with F6 the MFA factor is decorative.

**Fix:** take the client address from `request.client.host` or, if a proxy is
genuinely in front, from exactly one header that the **edge** overwrites and
strips from the inbound request; key the limiter on `(dni, address)` and a
time window rather than on address alone; make the lockout progressive per
account, not per network.

---

### F3 — CWE-565 / CWE-347: authorization decision taken from an unsigned, client-writable cookie

`main.py:78-93`, `main.py:216-217` and `main.py:275-278`, verbatim:

```python
def _make_user_info(user: dict) -> str:
    # ⚠️ VULN-3: cookie base64 sin firma
    payload = {"user": user["name"], "role": user["role"], "email": user["email"]}
    return base64.b64encode(json.dumps(payload).encode()).decode()
```

```python
    # ⚠️ VULN-3: rol leído de cookie sin firma — falsificable desde el cliente
    info = _read_user_info(request.cookies.get("user_info", ""))
    if info.get("role") != "admin":
        return RedirectResponse("/dashboard?error=access_denied")
```

Raw `Set-Cookie` off the MFA success (verbatim):

```
user_info="eyJ1c2VyIjogIlxiPk5BTUVQUk9CRTwvYj57ezcqN319IiwgInJvbGUiOiAidXNlciIsICJlbWFpbCI6ICJzQHQuaW8ifQ=="; Path=/; SameSite=lax
```

— **no `HttpOnly`, no `Secure`**, and the value is raw base64 with **no MAC, no
nonce, no expiry**. `httponly=False` is deliberate and stated twice
(`main.py:93`, `main.py:216`: *"httponly=False para que el JS la lea/escriba"*);
the templates write it from the browser at `dashboard.html:185-187`.

**Four byte-distinguishable cases, one handler** (redirects **not** followed —
§13):

| Case | Cookies sent | Status | Location / bytes |
|---|---|---|---|
| 1 | none | **307** | `/login` (no session at all) |
| 2 | `session_id` only | **307** | `/dashboard?error=access_denied` |
| 3 | `session_id` + **genuine** `role=user` cookie | **307** | `/dashboard?error=access_denied` |
| 3b | `session_id` + **forged** `role=admin` | **200** | 18 395 B, admin panel |
| 3c | `session_id` + forged `role=""` | **307** | `/dashboard?error=access_denied` |
| 3d | `session_id` + `user_info=not-b64-json` | **307** | `/dashboard?error=access_denied` |

Cases 2 and 3 are the **positive control**: the gate is real, it holds for a
legitimate low-privilege user, and it is byte-identical to the "no cookie" case —
so a report claiming "no authorization check exists" would be wrong. Case 3d is
the negative control on the decoder: `main.py:86-87` `except Exception: return {}`
means garbage yields a **refusal**, not an accidental grant.

**Impact:** any authenticated user of any role reads the full customer register —
every DNI, name, email address and account balance in the system. The `password`
field *is* in the dict handed to the template (`main.py:280`
`{"users": list(USERS.values())}`) but is **not rendered** (`accounting.html:121-125`
prints `u.dni`, `u.email`, `u.balance` and nothing else) — so this is PII
disclosure, **not** a hash leak. That distinction is stated because the two are
routinely conflated and only one of them is true here.

**Fix:** sign the cookie (itsdangerous / an HMAC over the payload with a
server-side key), and — the part that matters more — **stop reading an
authorization decision out of the client at all.** `/accounting` should ask
`USERS[sess["dni"]]["role"]`, which it already has in hand at `main.py:272`. The
cookie is presentation only; the session is the trust boundary. Set `HttpOnly`
on it anyway so it is not a cross-site nuisance.

---

### F4 — CWE-78: OS command injection, `shell=True`, no sanitiser

`main.py:237-251`, verbatim:

```python
async def quejas_post(request: Request, queja: str = Form(...)):
    sess = _get_session(request)
    if not sess:
        return RedirectResponse("/login")
    # ⚠️ VULN-4: inyección de comandos — entrada del usuario sin sanitizar en llamada shell
    try:
        ref = subprocess.check_output(
            f"echo {queja}", shell=True, text=True,
            timeout=5, stderr=subprocess.STDOUT
        ).strip()
```

**No filter exists at all** — this is lab 168's shape, not lab 234's: there is no
blocklist to characterise. **Nine probes, two controls (no-session, plain text),
seven distinct metacharacter classes**, all reflected in-band through
`dashboard.html:168` `<pre …>{{ queja_result }}</pre>`:

| Probe | Reflected `queja_result` |
|---|---|
| no session (control) | **307**, no `<pre>` |
| `hola quejaseguida` (plain) | `hola quejaseguida` |
| `x;id` | `x`⏎`uid=1000(balutron) gid=1000(balutron) groups=1000(balutron)` |
| `x && id` | same |
| `x \| id` | `uid=1000(balutron) gid=1000(balutron) groups=1000(balutron)` |
| `x $(id)` | `x uid=1000(balutron) gid=1000(balutron) groups=1000(balutron)` |
| `` x `id` `` | same |
| `hola⏎id` | `hola`⏎`uid=1000(balutron) …` |
| `x';id;'` | `x;id;` |

Identity measured **as the identity**, quoted from the payload's own output and
cross-read against `/proc/self/status` inside the same primitive:

```
uid=1000(balutron) gid=1000(balutron) groups=1000(balutron)
Uid:	1000	1000	1000	1000
Gid:	1000	1000	1000	1000
Groups:	1000
CapEff:	0000000000000000
NoNewPrivs:	0
Seccomp:	2
```

`uid = euid = 1000`, real/effective/saved/fs all `1000` ⇒ **no setuid transition
anywhere in this lab** (§7's uid/euid pair, not the word "root").

**Impact:** RCE as the application user. Reached on an account I registered
myself with `role=user` and **no forged cookie**, which is the measurement that
separates F4 from F3.

**Escalation above `uid=1000`: not reachable, and measured, not inferred.**
`sudo: not found`; `crontab: not found`; `find / -xdev -perm -4000` → **10
binaries, all stock Debian** (`passwd chsh gpasswd newgrp chfn mount umount env
su`); `/etc/cron.d` holds one root-owned `e2scrub_all`; `CapEff = 0`. The ceiling
of this lab is the application user, and it is the ceiling of the *image*.

**Fix:** `subprocess.run(["echo", queja], …)` with `shell=False`, or drop the
shell entirely — `echo` of user text needs no process at all.

---

### F5 — CWE-208 / CWE-916: unsalted single-round SHA-256 for passwords

`main.py:13-14`, verbatim:

```python
def hash_pw(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()
```

No salt, no work factor, no KDF. A GPU does ~10¹⁰ SHA-256/s, so the entire
4-account table is a rounding error. **Not declared by the author** — no
`VULN-` comment — and reported because it is the multiplier on F1 and F2.

Compounding it, and **this part is source-visible and matters more than the
algorithm**: the four shipped passwords are in cleartext in the artefact,
`main.py:23-48` — `hash_pw("chocolate")`, `hash_pw("barcelona")`,
`hash_pw("123456")`, `hash_pw("password")` — and the four MFA PINs likewise,
`main.py:50-55` (`4829`, `2847`, `9163`, `5512`). Those constants are **not
readable over HTTP by any route** (`grep` for a template that renders them: **0**
hits in 7 templates), so this is **CWE-798 in the source**, not a served leak —
lab 102's distinction, applied in the same direction.

**Fix:** Argon2id or bcrypt with a per-user salt; move the seed accounts and seed
PINs out of the module into a seeding step that does not run in production.

---

### F6 — CWE-521: registration accepts an empty password

`main.py:109-116` declares `password: str = Form(...)`. A **missing** field is
rejected — `POST /login {"dni": …}` (no `password`) → **422**, 93 B — but an
**empty** field is not, and `main.py:129` stores `hash_pw("")`.

```
POST /register dni=77700001R&…&password=   → 303   (account created)
POST /login     dni=77700001R&password=    → 303 /verify-mfa, session_id issued
```

2 probes, 1 control (the 422). **Scope stated honestly: this is not an account
takeover**, because `main.py:121` refuses an occupied DNI and `/register` is the
only writer of `USERS[dni]["password"]` — so an attacker cannot set a victim's
password this way. It is a missing input-requirement control that becomes a
takeover the moment any second password-writing path exists.

**Fix:** `password: str = Form(..., min_length=12)`; reject empty and
whitespace-only at the schema, not in the handler.

---

### F7 — CWE-352 (minor): logout is a state-changing `GET`

`main.py:284-291`. `@app.get("/logout")` calls `SESSIONS.pop(sid)` and
`PENDING.pop(sid)`. A `GET` that destroys server-side state is reachable by any
image tag, and `SameSite=lax` on `session_id` does **not** protect it — lax blocks
cross-site *subresource* requests, and a top-level navigation is still sent.

**This one is an INFERENCE from the `Set-Cookie` attribute and the decorator, not
a measurement** — `curl` does not enforce SameSite, so no cross-origin request was
executed. It is filed under NOT tested as well as here.

**Fix:** make it `POST` with a CSRF token.

---

## 5. Controls that held

| Control | Positive control that proves the detector works | Result |
|---|---|---|
| **Impossible-name path control** (planted **before** the sweep) | `/zzq7x-not-a-real-path-9f3a` and `/zzq7x2` | 404, 22 B, md5 `689525ee6c81` — identical to `/admin`, `/docs`, `/favicon.ico`. **No catch-all, no phantom 200.** |
| **MFA rate limiter** | Same header value **reused** (not rotated) | Counter decrements `2 → 1 → 0` then blocks at 60 s ⇒ the limiter is real, and the rotation result is a bypass and not a disabled filter |
| **MFA success path** | Correct PIN `1845` | `303 → /dashboard`, then `GET /dashboard` `200`/16 166 B. The oracle **fired**; it was not inferred from silence |
| **`/accounting` role gate** | Genuine `role=user` cookie | `307 → /dashboard?error=access_denied`, byte-identical to the no-cookie case ⇒ the gate exists and holds; F3 is a bypass of a real gate, not the absence of one |
| **Cookie decoder** | `user_info=not-b64-json` | `307` refusal (`except Exception: return {}`), never an accidental grant |
| **DNI normalisation on register** | 3 variants: `"  71960227n  "`, `"71960227N"`, `"71960227n"` | **3 of 3** refused with the enumeration message ⇒ `main.py:117` `dni.strip().upper()` blocks DNI squatting |
| **`/login` does not discriminate the failing field** | 3 cases: right-DNI/wrong-pass, wrong-DNI/right-pass | **3 of 3 byte-identical** 11 554 B, same `NIF/DNI o contraseña no válidos.` ⇒ no username oracle on the *login* path (the leak is on *register*, F1) |
| **Session token entropy** | `main.py:156` `secrets.token_hex(32)` | 64 hex chars observed twice, both distinct ⇒ not guessable, and not the weak link |
| **Jinja autoescape** | `queja` = `'<script>alert(1)</script>'` and `'<img src=x onerror=alert(1)>'`, plain-text control `ok` | Control reflects `ok` verbatim; both payloads return `&lt;script&gt;…` / `&lt;img …&gt;` ⇒ **no XSS sink**. `grep -rn 'safe\||safe\|{{{'` → **0 hits in 7 templates**, and the grep is proven live by the same command finding `{{ }}` elsewhere |
| **No SSTI** | Register with `name = <b>NAMEPROBE</b>{{7*7}}`, then read the dashboard | Greeting renders `&lt;b&gt;NAMEPROBE&lt;/b&gt;{{7*7}}` — the value **is** reflected (positive control, the escape is visible in the same string) and the template expression stays **literal**, never evaluated to `49` ⇒ stored values are not re-parsed as templates |
| **Cookie attributes on the session** | `Set-Cookie: session_id=…; HttpOnly; Path=/; SameSite=lax` | `HttpOnly` present on the session cookie — so the *session* is not the client-writable surface; `user_info` is (F3) |
| **Password field not rendered** | `accounting.html:121-125` vs `main.py:280` | The dict carries `password`; the template prints `dni`, `email`, `balance` only ⇒ **PII disclosure, not hash disclosure** |
| **`openapi.json` vs source** | 12 routes declared, `grep -c '^@app\.'` = 12 decorators | Complete agreement ⇒ the 404s in the sweep are absences, not blind spots |
| **Process alive before recording an absence** (§23) | `/proc/net/tcp` shows 1 LISTEN on `1F40`; `GET /` `200`/19 492 B throughout | The UDP and route absences are properties of the target, not of a process that failed to start |

---

## 6. Reward

**`FLAG{cl13nt_s1d3_r0l3_1s_n0_s3cur1ty}`** — recovered on the target, over HTTP,
on the `/accounting` page (18 395 B body; the token is at line 134 of the
rendered response, at `accounting.html:69` in the template).

Reached by: register a throwaway account → login → brute-force the 4-digit MFA
PIN with a rotated `X-Forwarded-For` (F2) → forge the `role=admin` cookie (F3) →
`GET /accounting`.

**The sweep that establishes there is exactly one, with a positive control and a
work count.** Per §26 the search ran **inside the container** so that no probe
script of mine was in the corpus, and a uniquely-marked file was planted first so
the detector was proven live before its silence was believed:

```
STATE_A_canary_present_hits=1     /app/tp245-canary.txt      ← control GREEN
STATE_B_canary_removed_hits=1     /app/templates/accounting.html
final:  files_walked 8557  bytes_read 188399814  unreadable 13  flag_files 1
```

**Both hits were read before being reported.** The first was **my own canary** —
the §26 failure mode, entered deliberately and caught by the control, not by luck.
The second was read: it is a live `<div>` inside `accounting.html`, not a comment
and not a CSS class. The literal `<!-- API Key (flag) -->` at `accounting.html:60`
is a **separate, self-closing** comment that spans only its own line; the `<div>`
at `:61-76` that renders the token is live markup, which is why the token appears
in the served body.

Token-shape sweep over the same 188 MB returned 20 distinct `[A-Za-z0-9_]{3,12}{`
openers, top 5: `ENV{` 221, `opqrstuvwxyz{` 197, `config{` 111, `codes{` 92,
`python{` 83 — all library/runtime syntax, none a reward.

`bc` is not installed in the image, so the first byte count came back **blank**;
per §19 that is **untested, not zero**, and the figure above is the recomputed
one (`/proc`-mounted pseudo-filesystems excluded: they make `os.walk` unbounded).

---

## 7. Chain, with identity measured at every hop

| # | → | Mechanism | Identity proof |
|---|---|---|---|
| 0 | unauthenticated | `POST /register` mints an account (open registration) | no identity asserted |
| 1 | unauthenticated | `POST /login` → `PENDING[sid]`, 4-digit MFA armed | `session_id` = 64 hex, `HttpOnly` |
| 2 | unauthenticated | **F2** — rotate `X-Forwarded-For`; 1 846 of 10 000 PINs | no identity asserted |
| 3 | `role=user` session | `POST /verify-mfa` → `SESSIONS[sid]` | session-bound; `role=user` cookie genuine |
| 4a | `role=user` session | **F4** — `POST /quejas` `; id` | `uid=1000(balutron) gid=1000(balutron) groups=1000(balutron)`, `Uid: 1000 1000 1000 1000`, `CapEff: 0` |
| 4b | → admin (no new execution) | **F3** — forge `role=admin` | no new execution identity; the escalation is a **cookie**, not a hop |

There is **no setuid transition in this lab**. `uid = euid = 1000` at every hop,
and the image contains no route to anything higher.

---

## 8. NOT tested

* **Cross-origin request forgery, measured.** No browser was involved, so the
  `SameSite=lax` reading in F7 is an inference from the attribute, not a result.
  F7 is filed as minor on that basis.
* **Attribute-breakout XSS** (`"' onmouseover='alert(1)`): the payload reached the
  shell and returned `error` — my own quoting was malformed, so the **shell**
  failed, not a filter. **1 probe, untested**; the two tag-context payloads above
  are the ones actually measured.
* **Escalation above `uid=1000`** — measured *absent* (`sudo` absent, `crontab`
  absent, 10 stock setuid binaries, `CapEff=0`), not attempted as a positive
  exploit. There is nothing to attempt.
* **Password cracking against the leaked-looking dict.** `/accounting` hands the
  template a dict containing `password`, and the template does not print it. No
  cracking was attempted because there is nothing to crack from over HTTP. The
  **source-visible** plaintext (`main.py:23-48`) is a source fact, not a cracked
  result.
* **Blind SQLi / command-injection channels.** None exist: every sink here is
  in-band by construction (`main.py:245` output is rendered at
  `dashboard.html:168`). No OOB collaborator was used, deliberately.
* **`PENDING` session leak.** `main.py:157` inserts and only `:211`/`:288` delete;
  abandoned logins are never reaped and there is no TTL. Observed in the source,
  **not measured** as unbounded growth.
* **`/api/me` as an IDOR surface.** No request parameter names a user anywhere in
  the 13 routes (`openapi.json`), so there is no ownership predicate to violate —
  lab 85's discriminator has no entry point here. Structural, not probed.
* **A DNS/virtual-host surface.** One container, one port, one `Host`. No vhost
  control was run because there is nothing to discriminate; the route-level
  impossible-name control in §2 is the substitute that does apply.

---

## 9. Discarded with a reason

* **"The admin link is hidden, so there is authorization."** Discarded:
  `dashboard.html:190` is a client-side `if (data.role === 'admin')` on a
  `classList` toggle, over a cookie the client also writes at `dashboard.html:187`.
  Three-layer client-side gating on one unsigned value. The server-side gate is
  the one in `main.py:277`, and F3 measures it failing.
* **"The cookie is base64, therefore it is encoded, therefore it is opaque."**
  Discarded: `main.py:83-87` decodes it with `json.loads` and hands the dict
  straight to an `==` comparison. Encoding is not a control; the value is
  attacker-supplied by construction.
* **"The MFA limiter is broken because a correct PIN works."** Discarded: a
  correct PIN *should* work. The limiter's question is what happens on **wrong**
  input, and the reused-header control answers it in the direction that shows the
  limiter intact.
* **"A 403-shaped response on `/dashboard` or `/accounting` is a WAF."**
  Discarded: they are `307` with `Location: /login` and 0 bytes — application
  redirects from `main.py:226` / `main.py:274`. There is no WAF component in the
  image (`Config.ExposedPorts` = 8000/tcp only; uvicorn is the server).
* **"A 200 with a `<pre>` block means the injection was filtered."** Not
  applicable and deliberately not claimed: there is no filter. The `200` bodies
  here differ by **bytes**, which is why the discriminator was the reflected
  string and not the status.

---

## 10. Instrumentation defects — mine, and one of them would have cost a finding

1. **A cookie jar that was never wired to the request.** I built a fresh
   `HTTPCookieProcessor` opener per MFA attempt but seeded the session cookie
   into a **different** jar, so **10 000 requests went out with no
   `session_id` cookie at all**. Output: no hit, no error, no counter — the loop
   simply ended. Read naively that is "the PIN space resists 10 000 guesses",
   which would have **deleted F2's impact claim**, or invited the wrong
   conclusion that the limiter is stronger than measured. It was caught because
   the same script had already produced a hit through the `harness.post` path in
   an earlier run, and the two disagreed. **Work count that exposed it: 10 000
   requests, 0 authenticated.** This is §14 with a different costume — a harness
   that did nothing and exited clean.
2. **`pkill -f /app/tp.py` killed the shell running it**, because the pattern
   matched the killer's own command line. Every command in that compound
   statement was lost, and the sweep script silently reverted to a previous
   version (`md5 bb84895…` where I had written `f3dae78…`). Caught by printing
   the md5 on both sides — **the file-transfer integrity check is what caught
   it**, not the run's exit status.
3. **`os.walk("/")` over `/proc` and `/sys`.** The first sweep produced **0 bytes
   of output after 60 s** while still running (`pgrep` returned 2, then 1 — the
   `1` being the `pgrep` itself, which is exactly the §16 shape: a control that
   reports success while measuring nothing). The second version excludes the
   pseudo-filesystems and returned in ~8 s with a real count.
4. **`bc` is not installed**, so a `find … -printf '%s\n' | paste -sd+ | bc`
   byte count returned **empty**. Per §19 that is untested, not zero, and it was
   recomputed with `awk`/Python rather than reported as 0.
5. **The enumeration oracle mutates the namespace — my own controls were
   consumed by my own first use.** `00000000A` and `99999999X` were chosen as
   *cannot-exist* controls for F1; `/register` **creates** accounts, so both
   existed from the second probe onward. This is lab 242's defect reproduced by
   my own sweep: a control drawn from the namespace being enumerated is not
   idempotent. The four DNIs reported as "real" are the ones that existed
   **before** any of my requests; the two reported as "absent" were absent and
   then created by me. Both facts are in the F1 table rather than smoothed over.
6. **My own artefact was a reward hit.** `/app/tp245-canary.txt` came back as
   `flag_files: 1` on the first clean sweep. Found by the planted control, which
   is the only reason it was recognised rather than filed as a second reward
   (lab 82's `.ui-icon-flag{`, lab 168's probe script, lab 242's preloaded
   `dnis_encontrados.txt` — three times over).
7. **One earlier XSS payload measured the shell, not the browser.**
   `queja=<script>alert(1)</script>` returned `error` because `<script>` is a
   shell **redirect** from a nonexistent file. Read as "blocked", it would have
   been a false control. Re-run shell-quoted, it returned
   `&lt;script&gt;alert(1)&lt;/script&gt;` — the opposite verdict from the same
   string.
8. **A citation I had already written down pointed at the wrong file.** The F1
   evidence table said the enumeration message renders at
   `register.html:98`. Line 98 is `</button>`. The `98` was the line number **in
   the response body I had saved to disk**, and I attributed it to the template.
   This is the corpus's own CRITICAL #5 shape — *a citation pointing at a file's
   docblock instead of the code it claimed* — and it was caught **before it
   shipped**, not by re-reading: I extracted all 43 `file:line` citations from
   the draft into a script that `sed -n "${n}p"`s each one and fails loudly.
   43 of 43 now verify. The corrected citation is `register.html:21`
   `<p class="text-red-700 text-sm">{{ error }}</p>`, with the rendered string
   measured in the response.

   The two count errors the same pass caught are recorded here for the same
   reason: I had written **13** routes where `openapi.json` declares **12** and
   `grep -c '^@app\.'` counts **12**, and **8** files under `/app` where a cold
   container has **9**. Both were read-off-the-screen numbers, not counted ones.
   *A count in a report is a claim about a measurement; recompute it.*

---

## 11. Restore

```
docker rm -f trailpack_container && docker run -d --name trailpack_container trailpack:latest
```

Verified **positively**, not by absence of errors:

* `id` inside the fresh container → `uid=1000(balutron) gid=1000(balutron) groups=1000(balutron)`
* `GET /` → **200**; `GET /accounting` → **307 → /login** (the shipped
  unauthenticated behaviour)
* `ls /app` → exactly `__pycache__  main.py  requirements.txt  templates` — the
  four uploaded sweep scripts (`tp.py`, `tp2.py`, `tp3.py`, `sweep.out`,
  `sweep2.out`, `s3.out`, `tp245-canary.txt`) are **gone**, because they were
  written by `uid=1000` into the container's writable layer and the container was
  **recreated from the image**, not reverted.
* All four probe accounts (`55500011K`, `SSTI{{7*7}}X`, `{{7*7}}`, `77700001R`)
  confirmed **gone**: each `POST /register` returned **303 (created)** on the
  restored instance, which is only true of a namespace that no longer held them.
  The container was then recreated once more so it is left exactly as shipped.

No artefacts were left outside `corpus/245/` and `/tmp/opencode/tp245/`; no
volume, image or container belonging to another principal was touched.

---

## 12. Cross-reads and what this lab adds to the methodology

* **Against lab 243 (the independence question).** 243's two bugs are
  **independent** — the admin logs in with no injection at all. 245's four are
  **not independent, and the shape is the mirror image**: three of them are
  genuinely independent *given a session*, and one of the four
  (**VULN-2**) is the single load-bearing bug that all of them hang from.
  Lab 78 asked which item to delete; here the answer is unambiguous and it is the
  **informational** item. *A multi-bug lab has three shapes, not two: independent
  (243), ordered-with-a-dead-tail (78), and gateway-dependent with an inert head
  (245).* The third is the one a "fix each bug in turn" remediation plan gets
  most wrong, because F1 looks like a bug and is not one, while F2 looks like a
  hardening nit and is the whole lab.
* **Against lab 218 / 234 / 84 / 168 (filter classes).** This lab is a fifth
  point on the same axis and the simplest of them: **there is no filter**.
  `main.py:244-245` interpolates straight into a shell string. The four filter
  classes in the corpus are a ladder of *what the filter is made of*; 245 sits
  below all of them, and its entry criterion is therefore the *absence* of any
  code between the form field and `shell=True` — which is a one-line read.
* **Against lab 242 (structured-identifier existence oracles).** Same namespace
  shape, different mechanism: 242's oracle is a dedicated endpoint returning two
  byte-distinct sizes; here it is an incidental **side effect of a differentiated
  error string** at `main.py:124`. That is the weaker and more common form — an
  oracle nobody designed, which survives every refactor that keeps the two
  branches' messages distinct.
* **Against lab 112 / 220 / 282 / 83 (lab-design defects).** A sixth instance,
  and the mildest so far: `main.py:57` `TARGET_DNI = "71960227N"` is a **dead
  constant**, defined and never read across 10 files. The class is worth naming
  because it is the *inverse* of the others — they advertise a path that does not
  run; this advertises a target that nothing checks.
* **New generalisation the corpus did not have.** *A rate limiter keyed on a
  client-supplied address is not a limiter, and the control that proves it is the
  **reused** header value, not the rotated one.* The reused value shows the
  bucket exists; the rotation shows it is addressable. Both are required, and the
  corpus's existing "positive control first" rule does not by itself tell you to
  run the *non*-treatment as the control.
* **Second confirmation of §26 in one engagement** — my own canary file was the
  first reward hit, exactly as in 82, 168 and 242.

---

## 13. One-line summary

Four declared bugs; **three are real and independent given a session, one is a
gateway without which none of them is reachable, and one — the user
enumeration — is inert and is the finding I would delete from a report without
changing its outcome**; `uid=1000(balutron)` throughout with `CapEff=0` and no
setuid transition anywhere; `FLAG{cl13nt_s1d3_r0l3_1s_n0_s3cur1ty}` recovered over
HTTP; and a seventh, undeclared finding (empty-password registration) plus a dead
constant at `main.py:57` that is the lab's own, not the tester's.
