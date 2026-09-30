# TOKENASO — DockerLabs lab 186 (twelfth lab solved)

**Class:** PHP password-reset token forgery + check-then-act race (token double-spend), on an
identity portal that stores its state in SQLite and JSON files.
**Reward:** none present in the image. See §9 — reported as a derived absence, not asserted.

---

## 0. Self-correction, stated first

Two of my instruments were wrong before any finding was recorded, and both would have
produced a *confident wrong answer* if I had trusted them. Both are the shapes already
catalogued in `decision-making.md`, and both are new instances of them.

**0.1 — A winner oracle that returned `True` for success and failure alike.**
My first race harness decided "did this reset win?" by probing `/login.php` and comparing
the HTTP status. `urllib` follows `302` redirects, so a successful login (302 →
`dashboard.php` → 200) and a failed login (200, the re-rendered form) **both** returned
`200`. The probe reported every candidate as a winner and, worse, the harness printed
`final_pw=None` because of a *separate* inconsistency. I only caught it because the count
disagreed with the winner list. Fixed by making the decider `bcrypt.checkpw` against the
hash the application actually stored, and by proving that decider **rejects a known-bad
input first**:

```
detector self-test: known-bad -> False (detector can fail). OK
```

This is `decision-making.md:50` — the check was shaped so the interesting answer and the
boring answer produced the same output. Same defect, third engagement running.

**0.2 — A file-lock poller reading a path that does not exist.**
To test the application's own locking, I spawned a thread polling
`/var/www/html/emails/lock_<user>.txt` on the **host**. The file lives inside the
container; the host has no `/var/www/html` at all. The poller read `OSError` forever and
reported `distinct_pids_in_lockfile=0` — a clean, believable, **structurally incapable**
result. It looked exactly like "the lock is never contended". The lock file is under
`DocumentRoot`, so the correct channel is HTTP. Re-run that way, the same detector
immediately produced a hit:

```
round 3 | n=30 ... | lock_pids_seen=['52']
```

A negative result from a detector that was never connected to the thing it measures is not
a negative result. This is the §"defects in your own instrumentation" obligation
(`decision-making.md:171`) and the sticky-`/tmp` family (`decision-making.md:57`): the
run returned an answer, well-formed, one step behind the truth.

**0.3 — A "clear inbox" detector that could not fail.**
`emails.php` only prints *"Bandeja limpiada"* when a file existed to delete, so that
banner cannot distinguish *cleared* from *there was nothing there*. I asserted on the
banner and it aborted on an empty inbox. Replaced with a count check against a known
baseline (`clear → 0`, `1 mint → 1 row`, `2 serial mints → 2 rows`, `delete removes
exactly 1`). The banner is `decision-making.md:73` verbatim.

**0.4 — A response reader that assumed one JSON shape.**
`check-emails-storage.php` serialises `all_emails` as `[]` when empty and `{...}` when
populated, because PHP renders an empty associative array as a JSON array. My reader
called `.get()` on a list and crashed. Fixed by handling both. (The shape instability is
itself a small API defect, CWE-436, noted in §4.6.)

**0.5 — A container I had already contaminated.**
My first race overwrote the lab's baseline `victim` password, and the harness correctly
refused to continue (`AssertionError: baseline login credential changed`). The correct
response was to destroy and recreate the container from the image, not to undo the change
one field at a time — and the refusal is itself the proof that the detector was live.

---

## 1. Recon

```
$ nmap -sV -Pn -p- 172.17.0.12
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.14 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.58 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
Not shown: 65533 closed tcp ports (conn-refused)
```

- **OS:** Ubuntu 24.04.3 LTS (`/etc/os-release`), confirmed from inside.
- **Stack:** Apache 2.4.58 + PHP (mod_php/prefork) + SQLite. No framework, no ORM.
- **App:** "SecureAuth Pro", a Spanish-language corporate identity portal. DocumentRoot
  `/var/www/html`; `<Directory /var/www/>` at `apache2.conf:170-174` carries
  `Options Indexes FollowSymLinks` and `Require all granted`, so the whole tree is
  browsable and every non-PHP file is downloadable.
- **Execution identity (measured, not assumed — `decision-making.md:143`):**
  `uid=0(root)` is `docker exec`'s identity, **not** the web tier's. The web tier is
  `www-data:www-data`; `/var/www/html/emails` is `drwxr-xr-x www-data www-data`, so
  `www-data` owns the files it races over. I did **not** obtain a shell in the web tier,
  so this is read from the image and from file ownership, not from a primitive — stated
  as such.
- **UDP:** `nmap -sU` needs root and was not run. `EXPOSE` in the image lists no UDP
  port. Coverage gap declared, not closed (`decision-making.md:76`).

**The catalogue description was wrong, as in all eleven previous labs.** It promised
"race Condition, exposición de credenciales y criptografía". Race: real, and the core.
Credential exposure: real, and broader than described. **Cryptography: there is none in
the target** — no TLS, no encryption at rest, no signature, no KDF. The only
"crypto-looking" construct is `hash('sha256', …)`, and its weakness is *predictability*,
not its algorithm. The description named a class the lab does not teach.

The lab *does* annotate itself, violating its own design requirement
(`decision-making.md:138`): `config.php:89` reads `VULNERABILIDAD INTENCIONAL`, and
`:82`, `:137`, `:159` each name what they broke. I read them and then derived the chain
independently, because per `decision-making.md:131-135` the labelled set is a strict
subset of the real one — and here it demonstrably is: the annotations name the race and
say nothing about the unauthenticated database download, the session fixation, the
directory listing, the dead `admin_token`, or the broken `fix_db.php`.

---

## 2. Source read before attacking

`config.php` is the whole lab. Four functions carry the state machine:

| Function | Line | Role |
|---|---|---|
| `generateResetToken` | `config.php:83` | mints the reset token |
| `verifyResetToken` | `config.php:108` | the **check** |
| `markTokenAsUsed` | `config.php:120` | the **act** |
| `saveEmailToInbox` | `config.php:127` | claims a lock, has none that works |

The race is a textbook check-then-act spanning two separate `PDO` statements with no
transaction between them:

```php
// config.php:92,95  — token = H(time_segment . salt), 10-second granularity
$time_segment = floor(time() / 10);
$token = hash('sha256', $time_segment . 'weak_secret_salt');

// config.php:114-116  — CHECK
$stmt = $pdo->prepare("SELECT * FROM reset_tokens WHERE username = ? AND token = ? AND used = 0");
$stmt->execute([$username, $token]);
return $stmt->fetch(PDO::FETCH_ASSOC);

// reset-password.php:25-30  — ~36 ms of bcrypt, then the password write, then the ACT
$hashed_password = password_hash($new_password, PASSWORD_DEFAULT);
$stmt = $pdo->prepare("UPDATE users SET password = ? WHERE username = ?");
$stmt->execute([$hashed_password, $username]);
markTokenAsUsed($token_data['id']);
```

The window is not a sliver of incidental timing. **`password_hash()` sits between the
check and the act**, so the window is one bcrypt evaluation wide *by construction*. That
is what makes it measurable rather than lucky — see §6.

---

## 3. Finding A — predictable reset token (the actual root cause)

**CWE-330** (use of insufficiently random values) / **CWE-640** (weak password recovery
mechanism).

**Evidence — prediction, not observation.** I computed
`sha256(str(int(time/10)) + "weak_secret_salt")` locally and compared it to the token the
application stored. Byte-identical, first attempt:

```
predicted_now 246c743efde1bbbc914c10bd221b3ac9cc0bceec325f08ad8633cc4b5fcbc1f8
actual (from check-emails-storage.php)
             246c743efde1bbbc914c10bd221b3ac9cc0bceec325f08ad8633cc4b5fcbc1f8
```

**Impact.** Complete unauthenticated takeover of the `admin` account, single request, no
concurrency, no leaked inbox, no database download. The salt is a string literal in
world-readable source, so the entire token space is 10 guesses wide (or 1, given the
clock).

**Root cause.** A security token derived by hashing a *guessable* input with a
*hardcoded, source-resident* salt. There is no `random_bytes`, no CSPRNG, no per-token
salt, and no server-side secret. `config.php:89-92` even documents the weakening: the
original granularity was 60 s and the lab changed it to 10 s. Granularity was never the
defect; **the absence of entropy was**, and the comment invites the reader to think
otherwise — the §7 "reassuring comment" pattern (`decision-making.md:133`).

**Remediation.** `bin2hex(random_bytes(32))` as the token, stored hashed
(`password_hash`), compared with `hash_equals`. Time-segment derivation is acceptable
*only* with an HMAC keyed by a server secret that never leaves the host, and even then
the 10 s window is a replay surface.

---

## 4. Findings B–G

### 4.1 B — token double-spend race (CWE-362, CWE-367)

The chain in §6. Impact: a credential documented as *single-use* can be spent N times, and
an attacker who keeps firing **prevents the legitimate owner from using it at all**
(5/5 rounds, §6.3). Root cause: the `used` flag is a read-modify-write across two
autocommit statements with no transaction, no `SELECT … FOR UPDATE`, and no conditional
`UPDATE … WHERE used = 0`. Remediation: make the consume atomic —
`UPDATE reset_tokens SET used=1 WHERE id=? AND used=0` and require `rowCount()===1`, or
wrap check-and-consume in a single transaction with `BEGIN IMMEDIATE`.

### 4.2 C — the application's lock is not a lock (CWE-367, CWE-362)

```php
// config.php:142-147 — the comment says "evitar condiciones de carrera"
while (file_exists($lock_file) && $waited < $max_wait) { usleep(100000); $waited += 0.1; }
file_put_contents($lock_file, getmypid());
```

`file_exists` then `file_put_contents` is a check-then-act on the filesystem with no
`O_EXCL`, no `flock()`, no `fopen(…, 'x')`. Two workers both observe absence and both
enter. Worse, the wait **times out and proceeds anyway**, so after 3 s the code enters the
critical section *knowing* the lock is held. The comment names the property the code does
not have.

**Honest measurement, reported as measured:** at n=30 concurrent mints I observed
**0 lost updates** (120 ACKs, 120 durable rows), and 10 concurrent distinct-id deletes on
the completely unlocked `emails.php:20-27` read-modify-write also lost **0** (10 ACKs,
0 rows remaining, expected 0). I am reporting that, not a race win. Two reasons it may be
unexploitable at this concurrency: (a) the nominal wait loop *does* serialize in practice
because the gap between `file_exists` and the write is microseconds; (b) the `array_slice`
cap at 50 truncates, so a high fan-out would produce a *false* loss signal, which is why
I reset the inbox to zero between rounds and kept n below the cap. **The right reading:
the lock is unsound by construction and I failed to convert that into an observable loss
at n=30. A larger n is the experiment I did not run.**

### 4.3 D — session fixation (CWE-384)

`config.php:3-18` reads `PHPSESSID` out of the `Cookie` header and calls
`session_id($session_id)` **before** `session_start()`. `login.php` never calls
`session_regenerate_id()` — the only call in the codebase is in `forceNewSession()`
(`config.php:241`), which nothing invokes on the login path.

Proven with a positive control and a negative control:

```
1. POSITIVE CONTROL: pre-login, /session-test.php echoes the attacker's chosen id: True
2. login as victim WITH that cookie -> 302, PHPSESSID after login = ['attackerchosensessionid0000000test']
3. attacker reuses the id: GET /dashboard.php 200 sees_admin=True
                            GET /emails.php    200   (victim inbox reachable)
                            GET /admin.php     200   sees_user_table=True
4. NEGATIVE CONTROL: random unused id -> /admin.php 302   (correctly rejected)
```

Impact: full account takeover of whoever logs in next, no credential required. This is
independent of Findings A and B and would survive fixing both. Remediate with
`session_regenerate_id(true)` **immediately after** the credential check, and stop
honouring a client-supplied session id.

### 4.4 E — unauthenticated disclosure endpoints (CWE-306, CWE-200)

Six scripts carry no authentication at all. Two are load-bearing for the chain and are
therefore independent findings in their own right (`decision-making.md:120`):

| Endpoint | Anonymous | Exposes |
|---|---|---|
| `/check-emails-storage.php` | 200 | **every user's** reset token and full reset URL |
| `/database.sqlite` | 200, 20480 B | both bcrypt hashes, all users, roles, all tokens |
| `/database.sqlite.bak` | 200, 20480 B | same, the backup copy |
| `/emails/` | 200 | Apache index listing every inbox file |
| `/get-token.php`, `/get-session.php` | 200 | server-side session id + CSRF token, `Access-Control-Allow-Origin: *` |
| `/session-test.php` | 200 | full `$_SESSION` and `$_COOKIE` |
| `/reset-db.php` | 200 | **drops and recreates both tables** — unauthenticated destructive |

Literal, anonymous, no cookie sent:

```
$ curl -s http://172.17.0.12/database.sqlite | sqlite3  # via python
(1,'diseo','$2y$10$VA9NZes7JP2rmEOrTztby.HzzpWTcu5h66dkOS1lUwuNI4lQMxrr2','diseo@ctf.com','user')
(2,'victim','$2y$10$LnTOhlAdz9wOeql1yE8EP.lOE13kk.d2BtpGLre0tU4SbdqWHiuha','victim@ctf.com','admin')

$ curl -s http://172.17.0.12/check-emails-storage.php
"token": "2d471f508705784ada0a2cb3bbcad51edcb235b57d1596e3641949037c24",
"reset_url": "http://172.17.0.12//reset-password.php?token=2d471f50870...&username=..."
```

**Root cause is placement, not the handlers.** `database.sqlite` lives *inside*
`DocumentRoot` and `apache2.conf:171` sets `Options Indexes`, so no PHP guard applies to
a non-PHP file — the MIME map decides it is a download, exactly the Elevator shape
(`infrastructure.md:869`). Remediate by moving all state outside the webroot and adding
`<FilesMatch "\.(sqlite|json|bak)$"> Require all denied </FilesMatch>`; do not rely on
the handlers.

### 4.5 F — hardcoded credential that is never consumed (CWE-798, CWE-321)

```php
// login.php:21
$admin_cookie_value = base64_encode('P@ssw0rd!User4dm1n2025!#-');
setcookie('admin_token', $admin_cookie_value, [...]);
```

Server-issued on every admin login, 30-day lifetime, `HttpOnly`, `SameSite=Strict`. This
is the diagnostic trichotomy of `decision-making.md:19` applied exactly, and all three
legs have different answers:

- **Reachable** — yes, `200` on `/login.php` as `victim`, `Set-Cookie: admin_token=…`.
- **Disclosed** — a real value, base64 of a hardcoded secret, in source.
- **Decisive** — **no.** `grep -rn "admin_token" /var/www/html/` returns exactly one hit,
  the `setcookie` that mints it. Nothing reads it. Sent alone, it buys nothing:

```
5. admin_token alone -> /dashboard.php 302   (rejected)
   admin_token alone -> /admin.php     302   (rejected)
```

**This is the Elevator finding inverted.** There, two of three config directives were inert
while the operative one carried no comment. Here the artifact is not inert — it is
*minted and never checked* — and the lab's own `setcookie` with `HttpOnly` and
`SameSite=Strict` reads as a deliberate, hardened control. A reviewer skimming for
"hardcoded secret" files this as Critical; the honest severity is **Informational**, with
one real caveat: the cookie is a static, identical value for every admin, so if *any*
future code path ever compares it, every admin is one leaked cookie from every other.
The correct fix is to delete it, not to rotate it. Reporting the name as an exposure
without the decisive leg would be the manufactured finding `decision-making.md:19`
describes.

### 4.6 G — supporting defects

- **CWE-662, improper locking / no busy timeout.** Under concurrency SQLite returns
  `SQLSTATE[HY000]: General error: 5 database is locked` and the app 500s. 7 occurrences
  in `error.log` from one 30-way burst. `PDO` is constructed with no
  `busy_timeout`/`ATTR_TIMEOUT`. This is a real availability defect and it is also the
  *only* thing that ever limited my race fan-out.
- **CWE-436, interpretation conflict.** `all_emails` serialises as `[]` or `{}`
  depending on emptiness (PHP empty-array ambiguity), so any client must branch on the
  response shape. Cost me a crash; will cost a real client a type error.
- **CWE-662, broken documented step.** `fix_db.php` is shipped in the webroot as a repair
  tool. It dies before doing anything:
  `❌ Error: SQLSTATE[HY000]: General error: 1 Cannot add a column with non-constant default`
  (SQLite forbids `ALTER TABLE … ADD COLUMN … DEFAULT CURRENT_TIMESTAMP`). It therefore
  never reaches its `print_r($users)` dump — the disclosure it was written to produce
  does not exist through this path, and does exist through `/database.sqlite` instead. Per
  `decision-making.md:137` this is reported as a finding in its own right, separate from
  the disclosure it failed to deliver. It is also unauthenticated and it mutates schema.
- **CWE-862, missing authorization on `reset-db.php`** — unauthenticated `DROP TABLE`.
- **CWE-352, no CSRF** on `reset-password.php` (POST) — low impact here only because the
  token is the real gate; would matter once the token is fixed.

---

## 5. Controls that held (reported with the same prominence as the bugs)

1. **The `used` flag works — serially.** Replaying a spent token immediately, with no
   concurrency, was rejected **10/10 rounds**. The single-use property is genuinely
   implemented; only its atomicity is missing. This is the control that makes the race
   result mean something: the difference between 10/10 rejection and 23/400 acceptance is
   *concurrency and nothing else*.
2. **Authorization on `admin.php` / `emails.php` / `dashboard.php` is real.** Anonymous
   requests get `302 → login.php`; a random unused session id gets `302`. Measured with a
   no-redirect opener precisely so that the success and the failure could not produce the
   same output.
3. **CSRF on `forgot-password.php` is enforced.** A POST with a wrong token returns
   *"Token de seguridad inválido"* and mints nothing.
4. **Password storage is correct** — `password_hash(PASSWORD_DEFAULT)` (bcrypt cost 10).
   No plaintext, no fast hash. The weakness is the reset *token*, never the password hash.
5. **SQL is parameterised everywhere** — every `$pdo->prepare` uses bound parameters. No
   injection found in any handler.
6. **Output is escaped** — `htmlspecialchars` on every interpolation in the templates. No
   XSS found.
7. **Session cookies** — `PHPSESSID` is `path=/`, and the app never sets
   `session.use_strict_mode`. (The fixation in 4.3 is a missing *regeneration*, not a
   lax cookie flag.)
8. **SSH is genuinely locked out.** Port 22 is open and sshd is running, but there is no
   `authorized_keys` anywhere on the filesystem, `/home/admin` is `0750`, and the lab ships
   no SSH credential. A control that held by omission.

---

## 6. Concurrency — what was measured, how many times, and what the measurement cannot say

This is the section the methodology was missing, so it is reported in full.

### 6.1 What is racy, and the three variants

`decision-making.md` named three shapes. This lab contains two of them:

| Variant | Location | Oracle used |
|---|---|---|
| **check-then-act** (read `used=0`, then set it) | `reset-password.php:11` → `:30` via `config.php:114` / `:120` | app's success string **and** `bcrypt.checkpw` against the stored hash |
| **TOCTOU on a file** (exists, then create) | `config.php:142-147`; also unlocked at `emails.php:20-27` | ACKs issued vs. durable rows counted |
| read-then-write | same two, structurally | — |

### 6.2 The window, measured rather than guessed

The window is bounded from outside by two numbers:

- **Serial span** of one uncontended `reset-password.php` POST, i.e. the full
  check→write→consume path, over 10 rounds:
  `min=118.6 ms  median=127.3 ms  max=129.7 ms`
- **The component that sits inside it**: `password_hash(…, PASSWORD_DEFAULT)` on this
  host = `bcrypt cost10 avg: 35.9 ms` (5 iterations, measured in-container with the same
  interpreter).

So the window is on the order of the bcrypt cost — it is *in the code*, not in the
network, and not in luck. That is the whole reason this lab is exploitable rather than
theoretical: an attacker who fires continuously will land inside a 36 ms window on the
first or second attempt, every time.

**Rates, with the fan-out and the round count stated:**

| Run | Fan-out | Posts | App said "success" | Rate | Rounds with ≥2 successes |
|---|---|---|---|---|---|
| `window.py B1` | 30 | 240 | 15 | **6.25 %** | 5/6 |
| `window.py` (10 rounds) | 40 | 400 | 23 | **5.75 %** | 8/10 |
| `chain.py` (predicted token, no leak used) | 30 | 120 | 14 | 11.7 % | 4/4 admin reached |
| `spray.py` (continuous spray vs. legitimate owner) | 11/round | 55 | 5 | 9.1 % | **5/5 attacker won** |

Every success was independently confirmed: after each round the stored bcrypt hash was
fetched and each candidate tested with `bcrypt.checkpw`. Every round produced exactly one
matching password — the **last writer wins**, which is the correct semantics to expect and
a third confirmation the race is real and not a reporting artefact:

```
### RACE: 23/400 posts reported success = 5.75%; 8/10 rounds had >=2 successes
### passwords_that_actually_authenticated=['B1-0-2','B1-1-5','B1-2-3','B1-3-1','B1-4-6','B1-5-4']
### control: serial replay of a spent token was rejected in 10/10 rounds
```

### 6.3 The impact form that matters

A one-shot burst proves a window exists. The form that proves **impact** is an attacker
who keeps firing while the legitimate owner tries to use the token:

```
round 0 | attacker_posts=11 attacker_ok=1 owner_ok=False | final=ATTACKER_WON
round 1 | attacker_posts=11 attacker_ok=1 owner_ok=False | final=ATTACKER_WON
round 2 | attacker_posts=11 attacker_ok=1 owner_ok=False | final=ATTACKER_WON
round 3 | attacker_posts=11 attacker_ok=1 owner_ok=False | final=ATTACKER_WON
round 4 | attacker_posts=11 attacker_ok=1 owner_ok=False | final=ATTACKER_WON
### attacker won 5/5 rounds AFTER the owner had already consumed the token
```

`owner_ok=False` is the important half: the attacker does not merely *also* win, the
legitimate user is **locked out of their own password reset**. A single-use credential
becomes a persistent denial of recovery plus an account takeover.

### 6.4 What this measurement cannot prove

Stated plainly, because a race report that overclaims is the failure mode this section
exists to prevent:

- **A negative result here would have needed N large.** I did not need one for Finding B —
  the race fired in 8/10 rounds — but had it fired once, "it worked once" would still have
  been a weak claim. The design principle stands: *a race is not disproved by a lost
  race.*
- **The file-lock race (4.2) did not fire at n=30.** 0 lost updates in 120 ACKs, and 0 in
  the unlocked delete path. I report that as a **negative result at one concurrency**,
  not as "no race exists". The lock is unsound by inspection; I failed to demonstrate the
  loss. n=200 was not run.
- **My fan-out is bounded by Apache's workers and by CWE-662.** 30–40 concurrent PHP
  processes is what `prefork` gives me; a determined attacker with more sockets is a
  different experiment. The 5.75 % figure is a property of *my* client, not a bound on
  the vulnerability.
- **All timings are from a loopback-adjacent bridge on one host**, unpatched, otherwise
  idle. The window figure is an upper bound on a quiet system; loaded, it is larger.
- **Single-sample control:** the lockfile poller caught one PID (`52`) once. That proves
  the detector *can* fire; it does not characterise contention.

### 6.5 Isolation of the harness (the sticky-`/tmp` hazard)

Because a concurrency harness is exactly the workload that exposes a shared-directory
fault, this run was contained deliberately:

- Fresh directory per attempt, named uniquely: `/tmp/opencode/t186/race_a1/`. Verified
  empty of other activity before use (`ps aux | grep -c "[r]ace_a1"` → `0`).
- **No shared state file at all.** State lives in the container's own SQLite/JSON, reached
  over HTTP. There is no `/tmp` artefact for a previous identity to leave behind, which
  removes the class of failure rather than testing for it.
- **A nonce is carried through every candidate password** (`B1-0-2`, `TAKEOVER-victim-3-1`)
  and the winner is identified by matching the *stored hash*. Any winning password is
  therefore attributable to *this* run and to *this* identity — the witness is created in
  this run, by the identity under test (`decision-making.md:59`).
- **The container was destroyed and recreated from the image** between measurement
  phases, never patched in place, because the phases mutate the very state being
  measured. The positive control for that restoration is in §0.5: the baseline-credential
  assertion fired on a contaminated container and refused to run.

---

## 7. The chain, in order, with justification for each step

**Chosen chain — predicted token + race, deliberately not using either leak.** Using
`/database.sqlite` or `/check-emails-storage.php` would have reached the same place in two
requests and taught nothing about the concurrency the lab exists to teach. So Finding A's
prediction and Finding B's race are the *only* inputs:

| # | Step | Why here |
|---|---|---|
| 1 | `GET /forgot-password.php` with `Accept: application/json` | The only endpoint that hands out a CSRF token + session id without credentials. Discovered in source (`forgot-password.php:85-89`, `get-token.php`). |
| 2 | `POST` `username=victim` + CSRF | Mints a token. Needs no credential — the endpoint is unauthenticated *by design* for a reset flow. |
| 3 | **Compute** `sha256(floor(time/10)+'weak_secret_salt')` | Finding A. The token is *predicted*, not read. If the prediction is wrong the chain dies here, so it is self-validating. |
| 4 | **30–40 concurrent** POSTs to `reset-password.php` with that token, distinct passwords | Finding B. Needs only that ≥2 workers pass the `used=0` check before either writes `used=1`. |
| 5 | Confirm the winner with `bcrypt.checkpw` against the stored hash | The app's own success string is not trusted; §0.1. |
| 6 | `POST /login.php` with the winner, **no-redirect opener** | 302 means authenticated. |
| 7 | `GET /admin.php` | The gate is `$_SESSION['role'] === 'admin'` (`admin.php:15`), now satisfied legitimately. Full user table. |

```
detector self-test (pre-race, correct password): admin_reachable=True (admin.php 200, table_rendered=True)
round 0 | token=predicted | posts=30 ok=3 | admin_reached=True TAKEOVER-victim-0-3
round 1 | token=predicted | posts=30 ok=4 | admin_reached=True TAKEOVER-victim-1-3
round 2 | token=predicted | posts=30 ok=5 | admin_reached=True TAKEOVER-victim-2-0
round 3 | token=predicted | posts=30 ok=2 | admin_reached=True TAKEOVER-victim-3-1
### admin panel reached in 4/4 rounds with ONLY a predicted token + a race
```

**Shorter, equally valid chain (recorded so the next reader does not have to rediscover
it):** download `/database.sqlite` → read `victim`'s bcrypt hash → crack the shipped
default → log in. That is one request and it depends on Finding E, not on the race. Both
are reported; the second is listed as a shortcut, not as the result.

**Not used in the chain, and why:** session fixation (4.3) reaches `admin.php` on its own
in three requests with no credential and no concurrency — arguably the shortest path in
the lab. It is filed as an independent finding rather than folded in, because it is a
separate defect with a separate fix, and merging it would hide both
(`decision-making.md:79`).

---

## 8. Design observation about the lab

The lab teaches one thing well and undermines it three ways.

**Well:** putting `password_hash()` between the check and the act is an elegant,
self-demonstrating design. The vulnerable window is not an artefact of network timing or
a sleep — it is a *named, measurable, expensive operation the author chose to place
there*. A student can be handed the code and told "count your successes", and the number
they get is a property of the program. That is better than most race-condition training,
which is usually a coin flip.

**Undermined, in the same file:**

1. **The self-documentation removes the exercise.** `config.php:89` says
   `VULNERABILIDAD INTENCIONAL`; `:82` names the token; `:137` claims the lock. A learner
   greps, gets a confident answer, and never derives. This is the design requirement
   `decision-making.md:138` states for lab authors — hide the annotation, keep the
   trigger — and this lab inverts it. Worse, the annotations are **incomplete**: they
   point at the race and are silent on the unauthenticated database download, the session
   fixation, the directory listing, and the dead `admin_token`. So the labelling produces
   both harms at once: it stops the derivation, and it still under-reports.
2. **The one comment that describes the fix is the inert one.** `config.php:137` says
   *"Usar bloqueo de archivo para evitar condiciones de carrera"* — and the code it
   describes does not achieve that. This is `decision-making.md:84` again: the fragment
   that names the exact behaviour is the one every reader selects, and here it is also the
   one that is false. A learner who trusts it learns nothing.
3. **The intended "cryptography" content is absent.** The catalogue promises it. There is
   no TLS, no encryption at rest, no signature, no KDF. Naming a class the lab does not
   teach is the mirror of naming a technology the lab does not contain
   (`decision-making.md:139`).

**And a fairness bug worth reporting as a finding:** `fix_db.php` is shipped as a working
repair tool and cannot run. Its `ALTER TABLE … DEFAULT CURRENT_TIMESTAMP` is rejected by
SQLite, so it 500s before printing anything. A learner told the app has a repair endpoint
will conclude the app is broken. The intended escalation *was* real — it just lives at
`/database.sqlite` instead.

---

## 9. Reward

**No reward is present.** Reported as a derived absence, with the search stated.

```
$ docker run --rm --entrypoint sh tokenaso:latest -c \
  'grep -rniE "flag\{|ctf\{|reward|tokenaso" / --include="*.php" --include="*.html" \
   --include="*.txt" --include="*.json" --include="*.sh" --include="*.md" 2>/dev/null \
   | grep -viE "^/(usr|proc|sys|var/lib|etc/ssl)"
(no output)
$ find / -xdev -iname "*flag*" -o -iname "*reward*" -o -iname "*secret*"
(no output outside /usr, /proc, /sys, /var/lib)
$ grep -rniE "flag|reward" /var/www/html/*.php /opt /root /home /usr/local
(no output)
```

The exposure surface was read end to end: 18 PHP files, `database.sqlite` and its
`.bak`, the `emails/` directory, the Apache config, and `/root`. The admin panel, the
dashboard, and the notification centre were all reached with full admin privilege
(§7, step 7) and none of them renders a reward.

**This is the correct outcome, not a failure to solve.** DockerLabs grants its reward
server-side, on the platform, keyed to the solved-lab state — it is not shipped inside the
container, and nothing in the image emits it. This is the fifth lab in the series with no
in-image reward. The substantive result is the chain and the numbers in §6.

---

## 10. Tested / not tested / not testable

**Tested.** Token prediction (byte-identical, first attempt). Token double-spend
(400 posts, 10 rounds, two fan-outs). Persistent spray vs. legitimate owner (5/5).
End-to-end admin takeover via predicted token (4/4). Session fixation (positive +
negative control). Unauthenticated disclosure on 7 endpoints. `database.sqlite`
exfiltration. Directory listing. `reset-db.php` unauthenticated destruction.
`fix_db.php` failure. `database is locked` under load. `admin_token` decisiveness.
Serial single-use enforcement (10/10). SQLi sweep — parameterised throughout. XSS sweep —
`htmlspecialchars` throughout.

**Not tested (time/scale).** n>40 fan-out (bounded by Apache `prefork` workers and by
CWE-662). n=200 for the file-lock race. Concurrent `reset-db.php` + resets (destructive
interference). Cookie-attribute analysis of `PHPSESSID` beyond `path` (no `session.*`
directives set in `apache2.conf`/`php.ini`, so defaults apply). Whether the 50-row
`array_slice` cap can itself be driven to destroy a user's notification history.

**Not testable in this environment.** `nmap -sU` (needs root) — no UDP coverage obtained;
`EXPOSE` lists none, but that is a manifest, not a scan. SSH authentication (no
credential exists in the image). TLS (none configured). `php.ini` session settings beyond
what `phpinfo`-free inspection reveals.

---

## 11. What is genuinely new here, and where it belongs

Cross-referenced against the three candidate sections before writing anything. The bar set
by the last two engagements was one cross-ref and one clause, so this is deliberately
small — and the concurrency section is **proposed, not created**.

**New for `api_web.md` (web/API):**
- The **check-then-act / double-spend** family with a *measurement* recipe, not a
  technique list: measure the window by timing the operation the author placed between
  the check and the act; confirm the winner against the state the server actually stored,
  never against a status code a redirect-following client flattens; and state the
  fan-out and round count with the rate.
- The **replay-after-consumption** impact form, which is the one that separates a race from
  a curiosity: a continuous sprayer both wins *and* denies the legitimate owner recovery.
  `owner_ok=False` alongside `attacker_ok=True` is the measurement to report.
- **"A control that worked serially and failed concurrently is a finding, and the serial
  control is what gives the concurrent number meaning."** 10/10 serial rejection vs. 23/400
  concurrent acceptance is a contrast, and a lone success rate is not evidence.

**New for `decision-making.md` (transversal), one clause on the existing
"control that cannot fail" rule:** a detector pointed at a path or endpoint that does not
exist **returns a clean, believable negative** — indistinguishable from "the condition
does not occur". Mine read a host path the container did not share and reported
`distinct_pids_in_lockfile=0`. Extend the existing rule with: *prove the negative detector
is connected by forcing a positive through it first.* It is already half-present as "a
control that cannot fail", but nothing there covers a detector that is merely
**disconnected**.

**Deliberately not proposed:** a new `sections/concurrency.md`. The lab's concurrency
findings are all web/API (PHP reset flow, JSON file store, Apache-served artefacts), so
`api_web.md` is the correct home and forcing an eleventh section would fragment a class
that has no non-web instance yet. If a non-web concurrency lab appears — a double-spend
against a queue, a coupon race in a billing daemon, a TOCTOU on a device file — that is
the trigger to propose the section, and it should be proposed then.

**Not proposed either:** the Elevator "inert directive" pattern is already in
`decision-making.md:84` and §4.5 is a third instance (a cookie that is minted and never
read) — reinforcement of an existing rule, so it needs no new text.
