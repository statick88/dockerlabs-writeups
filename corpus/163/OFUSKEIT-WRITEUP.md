# Ofuskeit — DockerLabs Writeup

**Target:** DockerLabs lab `id 163`, severity *Medium*, catalogued as *"Javascript deobfuscation e interacción con una API."*
**Container:** `ofuskeit_container`, image `ofuskeit:latest` (1.10 GB tar), `172.17.0.8`.
**Date:** 2026-09-28. **Position in series:** nineteenth lab solved (18/18 previous).
**Outcome:** reward obtained — `HTTP 200` on the token gate, body `✅ Acceso concedido. Contraseña chocolate123`. **The lab ships no `FLAG{}`; the reward is a plaintext password returned by the API.**

---

## 0. Autocorrection — five things I got wrong, and the two that would have produced a false report

### 0.1 I transcribed the token by hand and it failed — a "wrong key" that was my typing

I read the credential out of the exposed source and retyped it into a request. Result:

```
[control-wrong ] HTTP 401 :: ❌ Token inválido.
[control-utf8  ] HTTP 401 :: ❌ Token inválido.
[CANDIDATE     ] HTTP 401 :: ❌ Token inválido.
```

Three `401`s including my "correct" token. Under the ordinary reading I was one step from writing *"the token in the source does not authenticate — the secret is rotated or the value is a decoy"*, which is a **fabricated finding about the target** built entirely out of my own transcription error. The request body I had actually sent was:

```
{"token": "EKL56L4K57657J<c3 91>E6J74K5<c3 91>g54"}
```

against a source value of `…JÑ456J74K5Ñ6754`. I had dropped the `4` after the first `Ñ` and the `6` after the second, because I retyped the string instead of reading it out of the file.

Fixed by extracting it programmatically and asserting the roundtrip **before** the first offensive use:

```
extracted token    : EKL56L4K57657JÑ456J74K5Ñ6754
codepoints        : [... '0xd1', ... '0xd1', ...]     (two U+00D1)
utf-8 length      : 30 bytes / 28 chars
roundtrip self-test: PASS     (decode(encode(x)) == x, and the bytes occur verbatim in the source)
[control-wrong ] HTTP 401
[control-utf8  ] HTTP 200 :: ✅ Acceso concedido. Contraseña chocolate123
[control-mangled] HTTP 401
```

This is `decision-making.md` §*Extracted rules* — **write the roundtrip test before the first offensive use of any parser** — arriving from the opposite direction from its usual form. The rule is normally stated for token *decoders*; here the parser was a one-line regex and the failure was in the human between the file and the wire. The generalisation is that a hand-copied credential is a **hand-rolled decoder with no test**, and the two non-ASCII characters (`Ñ`, U+00D1, two bytes each) are exactly where a visual copy fails: they are not ASCII, they are not the same width, and a 30-byte value passing as a 28-char value is invisible without counting.

The control that made the difference was not "try harder" — it was that `control-wrong` was already in the script, so a `401` on the candidate was *legible* as a broken candidate rather than as a broken target. A two-state oracle earns its keep on the failure it was not designed for.

### 0.2 My decoder's negative control was mis-specified, and it revealed a real property of the tool

I asserted that an out-of-range index into the bundle's string-table decoder must **throw**. It did not:

```
decoder(0x114) -> returned undefined (typeof undefined)
decoder(0x115) -> returned undefined (typeof undefined)
decoder(0x12c) -> returned undefined (typeof undefined)
decoder(0x200) -> returned undefined (typeof undefined)
decoder(0x12b) -> returned "opacity"    (typeof string)
array length: 22
```

The decoder computes `array[index - 0x116]` and returns it. In JavaScript an out-of-range or negative index yields `undefined` and **does not throw**. So the string-table decoder in an obfuscator.io-style bundle **has no failure mode at all** — it cannot fail, it can only be wrong.

The consequence is specific and expensive. A folding tool that rewrites every `_0xNNNN(0xNN)` call site with whatever the decoder returns will, on an out-of-range call, substitute the literal token `undefined` into the source and produce a file that **looks deobfuscated and is subtly wrong**. Nothing downstream can tell: the output still parses, still runs, and still returns `undefined` where a string was required.

My control was wrong (`threw === true` when the correct post-condition is `typeof result === 'undefined'`), and correcting it produced a check that can actually fail. The corrected post-condition for any deobfuscator is a **count identity**, not a crash:

- every decoder call site in the original resolves to a `string` (**0** substitutions of `undefined`);
- the number of remaining decoder call sites in the output is **0**;
- and, below, the behaviour is unchanged.

Measured on this bundle: `0` occurrences of `undefined` in the output, `0` remaining call sites, `27` call sites folded over `2` passes.

### 0.3 My content sweep returned a clean, believable negative about files I had already fetched

My first docroot sweep probed 6 001 paths and reported:

```
BASELINE (provably absent): 404 272 bytes
=== 200 responses ===
  /api.js  494 bytes
  /index.html  2129 bytes
probed 6001 paths serially; 2 returned 200
```

Two problems, and the first is the one that matters.

**The sweep contradicted a fact I already held.** Earlier in the *same session* I had fetched `script.js` (1916 bytes) and `style.css` (2270 bytes) and confirmed both `200`. A sweep whose answer contradicts an established positive is a broken instrument, and its negative is not evidence of anything.

Root cause, found by inspecting the wordlist rather than the target:

```
wordlist total lines       : 131888
first 5 lines              : ["!","\"","#","%","&"]      <-- punctuation sorts first
index of "script" in filtered: 105289                     <-- real words live at the END
cap applied                : 6000
```

The wordlist is sorted with punctuation first, so the alphanumeric stems that matter sit at index ~105 000. **My arbitrary 6 000-entry cap silently discarded 99.4 % of the usable dictionary**, and the surviving slice was punctuation. The sweep was measuring the wrong 6 000 words and reporting the result in the vocabulary of a complete enumeration. This is `decision-making.md`'s *"a detector pointed at something that does not exist returns a clean, believable negative"* aimed squarely at my own generator, and the reason the cap is worse than no cap is that a truncated sweep and a complete sweep **print identically**.

Corrected (no cap, and the controls printed *before* the results):

```
usable stems (alphanumeric tail, NO cap): 98209
CONTROL baseline provably-absent  : 404
CONTROL known-present script.js  : 200  (must be 200)
=== 200 responses ===
  /api.js         494b
  /index.html     2129b
  /package.json   265b
  /script.js      1916b
probed 66055 in 1.7s, errors=0
```

`script.js` and `package.json` now appear — the two files the broken sweep had denied.

### 0.4 …and then the *fixed* sweep still missed `style.css`, for a different reason

```
CONTROL style.css known-present: 200  (must be 200)
=== 200 responses ===
  200  style.css  2270b
probed 540162 in 15.1s errors=0 200s=1
```

The second sweep's extension set had no `.css`, so the stem `style` never generated `style.css`. This one is a **coverage gap, not a false negative** — the candidate was never constructed, so nothing was denied. I am separating the two deliberately, because collapsing them is how a coverage gap gets reported as an absence of findings. The distinction is visible in the output: §0.3 printed a path I had already fetched and found nothing (a false negative, the instrument lied), while here the path appears in the results once its extension is added (a gap in my candidate set, which I closed).

### 0.5 I nearly reported two 403s as "two dotfiles exist"

Port 80 answered `403` for both `.htaccess` and `.htpasswd`. Before writing that up, the proven-absent-name control:

```
.htaccess           -> 403
.htpasswd           -> 403
.htzzzznotreal      -> 403     <-- provably cannot exist
.ht                 -> 403
.htx                -> 403
.htfoo              -> 403
```

Six names, six identical `403`s, **including one I can prove does not exist**. The `403` is Apache's `FilesMatch "^\.ht"` default denial — a **pattern rule**, not evidence of a file. Reporting "the server exposes `.htaccess`" would have been the `decision-making.md` vhosting finding inverted: here the repeated answer **is** the baseline, and the singleton answers are the discoveries. **I have not established that either file exists, and this writeup does not claim it.**

This is the third time in this series that a name-shaped artefact answered a status code and I had to ask whether the status code was about the *name* or about the *file*. The rule that settles it costs one request and must be run before the finding is written, not after.

---

## 1. Surface

`nmap -sV -Pn -p- 172.17.0.8`:

```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.2p1 Debian 2+deb12u6 (protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.62 ((Debian))
3000/tcp open  http    Node.js Express framework
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
Not shown: 65532 closed tcp ports (conn-refused)
```

TCP only — `nmap -p-` is a **TCP** range scan and this is a coverage statement about TCP. No `nmap -sU` was run (unavailable on this host, no sudo), so any UDP plane is a **declared coverage gap**, not a closed port.

**One container**, as the *Medium* rating implies. `auto_deploy.sh` was **not executed** (it ends in `while true; do sleep 1; done`); the image was loaded and run by hand. Its `docker run` line confirms a single container, `ofuskeit_container` from `ofuskeit:latest`.

### Architecture — the one fact that explains the whole lab

Apache on 80 and Express on 3000 serve **the same directory**, and that directory is the application's own source tree. Established from three independent channels, not one:

1. `package.json` (`"main": "api.js"`, single dependency `express ^5.1.0`) — declares the entry point.
2. `api.js` is retrievable over HTTP on port 80.
3. The Express stack trace on an unhandled error names the file's own path (see §3.4).

```
[stack trace] TypeError: Cannot destructure property 'token' of 'req.body' as it is undefined.
    at /var/www/html/api.js:10:11
    at Layer.handleRequest (/var/www/html/node_modules/router/lib/layer.js:152:17)
    ...
    at jsonParser (/var/www/html/node_modules/body-parser/lib/types/json.js:109:7)
```

`/var/www/html` is simultaneously the document root and the Node application directory. **That single deployment decision is the root cause of every finding in this report**, and it is a *decision*, not a bug — which is the shape `decision-making.md` §4 asks for.

### Files the application serves (port 80, document root)

| Path | Status | Bytes | Note |
|---|---|---|---|
| `/index.html` | 200 | 2129 | Spanish one-page marketing site, "TechFix" |
| `/style.css` | 200 | 2270 | |
| `/script.js` | 200 | 1916 | **obfuscated** — the lab's namesake |
| `/api.js` | 200 | 494 | **the Express application source, in cleartext** |
| `/package.json` | 200 | 265 | |
| `/package-lock.json` | 200 | — | full dependency tree with integrity hashes |
| `/node_modules/` | 200 | — | **full Apache directory listing**, 60+ packages |
| `/robots.txt`, `/.env`, `/.git/config` | 404 | — | genuinely absent (baseline is `404`/272 B) |

**Source maps: none.** Probed `script.js.map`, `style.css.map`, `index.html.map`, `main.js.map`, `app.js.map`, `bundle.js.map` — all `404`; and `grep -c sourceMappingURL script.js` → `0`. This is a **control that held**: the build did not publish maps. On this target the "published `.map` is itself a finding" branch does not fire, and the directory-structure disclosure it would have provided is instead delivered in cleartext by `api.js` and the `node_modules/` listing.

### Port 3000 — the API

`GET /` → `404 Cannot GET /` (the methodology's *"fingerprint a live path, not the root"*: the root is a 404 carrying full security headers). The only route is `POST /api`:

```
method/path matrix (404s suppressed):
  POST /api  -> 401
  POST /api/ -> 401        (trailing slash resolves to the same handler)
```

`GET`, `PUT`, `DELETE`, `PATCH` on `/api`, `/api/`, `/api/v1`, `/api/health`, `/api/status` → all `404`. Field substitution (`password`, `clave`, `secret`, `admin`, `user`) → all `401`. Type confusion (`token` as array, as object) → `401`. So the surface is **one route, one field, one decision**, and the decision is real (it returns two states), which is what makes the whole chain falsifiable.

### SSH (port 22)

Banner: `SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u6`. `ssh-keyscan` returns the three standard host public keys. **No username, no password, no hint in the banner** — a control that held, and the banner was read pre-auth per the pre-authentication-channel rule. No credential was found on port 22 and none was attempted.

---

## 2. Deobfuscation

### 2.1 The entry question: what am I looking for?

Before touching the bundle I had to decide which of three things I was after, because they have different costs and different paths:

- **(a) the surface** — endpoints, parameters, routes;
- **(b) the authorization logic** — what the client decides, what it assumes the server decides;
- **(c) secrets / cryptographic material.**

The lab's name and description say "deobfuscation and API interaction", which points at (a) and (b). The correct question was therefore **"does this bundle talk to the API, and if so what does it send?"** — not "what strings are in here". That framing is what made the negative result legible in minutes instead of an afternoon of reading obfuscated code.

### 2.2 Which bundle is the one the server actually serves?

Checked before deobfuscating, because the bundle you deobfuscate may not be the one that runs:

- `index.html` contains exactly one script reference: `<script src="script.js"></script>` — a **relative** path, no `?v=`, no content hash in the filename.
- The server serves that exact path: `200`, `Content-Type: text/javascript`, `ETag: "77c-6367e3f893600"`, `Last-Modified: Sun, 01 Jun 2025 08:15:20 GMT`.
- **Cache policy:** there is no `Cache-Control` and no `Expires`; the policy is `ETag`/`Last-Modified` revalidation. Confirmed live: `GET /script.js` with `If-None-Match: "77c-6367e3f893600"` → **`304`**. So the browser is correct to cache and revalidate, and the file I deobfuscated is the file a browser would execute.
- `Vary: Accept-Encoding` is **not** an inert claim: with `Accept-Encoding: gzip` the server returns `Content-Encoding: gzip`, `Content-Length: 819`, and — correctly — a **different ETag**, `"77c-6367e3f893600-gzip"`. The variant suffix means a shared cache cannot serve the compressed variant to a client that did not ask for it. That is a cache-poisoning control that **held**, and I report it with the same prominence as a bug that fired.
- **Byte-transparency of my own retrieval** (the `Defaults use_pty` hazard: a transport that silently drops NUL bytes reads as a clean download): the streamed body and the on-disk copy agree at `md5 2354fd476b260b09b31a9ded482d6f20`, **1916 bytes**, **0 NUL bytes**. The artifact I deobfuscated is the artifact the server holds.

### 2.3 The layers, in the order they came off, and how each was verified

The bundle is `obfuscator.io`-shaped: a **string array**, a **decoder with an index offset**, a **rotation IIFE** that shuffles the array until a checksum matches, and **alias indirection** through `const _0xfff565 = _0x2e969c`.

**Layer 1 — string array + rotation IIFE.** The literals sit in `_0xd47c()` as a 22-element array, and a self-invoking function rotates it with `push`/`shift` until a `parseInt` checksum equals `0xd8ebc`. *Verification:* I did not read the array out of the file, because the array in the file is **pre-rotation** and its order is not the mapping the decoder uses. I executed the bundle in a `vm` context with a stubbed `document` and read `_0xd47c()` back **after** the IIFE ran. Recovered table:

```
0x116 -> "translateY(0)"          0x122 -> "style"
0x117 -> "2287094dmVnDS"          0x123 -> "4845208ZWDAiV"
0x118 -> "observe"                0x124 -> "2774964FHByBg"
0x119 -> "querySelectorAll"       0x125 -> "272CHxZRB"
0x11a -> "forEach"                0x126 -> "692528eiKJnh"
0x11b -> "translateY(30px)"       0x127 -> "506922Jnjvgo"
0x11c -> "all 0.6s ease-out"      0x128 -> "28prsaQk"
0x11d -> "283401KmnzKx"           0x129 -> "DOMContentLoaded"
0x11e -> "transform"              0x12a -> "1602675PgksDG"
0x11f -> "target"                 0x12b -> "opacity"
0x120 -> "isIntersecting"         0x121 -> "addEventListener"
```

*Decoder self-test* (must run before the decoder is trusted, and it is where §0.2's defect was found):

```
positive  decoder(0x116) == array[0]      -> "translateY(0)"   PASS
bijective all 22 in-range indices map correctly                PASS
negative  out-of-range returns undefined, does NOT throw       PASS (after correction)
```

The eight values like `4845208ZWDAiV` are the **checksum operands** of the rotation IIFE, not program strings. Recognising them is what tells you the rotation is doing bookkeeping rather than carrying payload — a string table can contain its own decoy class.

**Layer 2 — index-offset decoder.** `_0x5630` subtracts `0x116` and indexes. Folded all **27** call sites over **2** passes, resolving aliases (`_0xfff565`, `_0x4b7081`, `_0x7a8fa8`, `_0x10427d` all alias the same decoder) — alias indirection is cosmetic here and needed no separate pass, because every alias is itself a `_0xNNNN(0xNN)` call and the fold catches them all. *Verification:* output contains **0** `undefined` substitutions and **0** remaining call sites.

**Layer 3 — control flow: NOT obfuscated.** This is a finding about the *class* of obfuscation, not a step. There is no control-flow flattening (no `while(true)` state machine), no opaque predicates, no dead-code insertion, no `eval`/`Function` constructor, no encrypted-string runtime, and **no dynamic chunk loading** — no second bundle is fetched at runtime. I looked for each of the four layers the methodology lists and three are absent. The bundle is a single self-contained file whose only protection is name mangling plus a shuffled string table.

### 2.4 The roundtrip — comparing behaviour, not text

A text diff would only prove the file changed. The roundtrip that validates a deobfuscation is: **re-emit the code and require the consumer's behaviour to be identical.** So I ran the original and the deobfuscated source against the *same* instrumented DOM stub — recording every `addEventListener`, every `querySelectorAll`, every style property *set*, every `observe` — then fired `DOMContentLoaded` and the `IntersectionObserver` callback, and compared the traces byte for byte.

```
=== ROUNDTRIP: ORIGINAL (first 12) ===
  document.addEventListener(DOMContentLoaded)
  document.querySelectorAll(.card)
  new IntersectionObserver()
  SET CARD_A.style.opacity = 0
  SET CARD_A.style.transform = "translateY(30px)"
  SET CARD_A.style.transition = "all 0.6s ease-out"
  observer.observe(CARD_A)
  ... (21 events total)

=== ROUNDTRIP: DEOBFUSCATED (first 12) ===
  (identical)

=== ROUNDTRIP VERDICT ===
  traces byte-identical: true
  event count match   : true (21 vs 21)
```

**21 events, byte-identical, including the ordering.** The deobfuscated artifact asserts what the consumer does with the bytes, not what the bytes are.

### 2.5 What the bundle actually says — and the result is a negative

Fully folded, the entire program is a scroll-reveal animation:

```js
document.addEventListener("DOMContentLoaded", () => {
  const cards = document.querySelectorAll('.card');
  const obs = new IntersectionObserver((entries) => {
    entries.forEach((e) => {
      e.isIntersecting && (e.target.style.opacity = 0x1,
                           e.target.style.transform = "translateY(0)");
    });
  }, {threshold: 0.3});
  cards.forEach((c) => {
    c.style.opacity = 0x0;
    c.style.transform = "translateY(30px)";
    c.style.transition = "all 0.6s ease-out";
    obs.observe(c);
  });
});
```

Twenty-two strings, and every one of them is a DOM or CSS token or an obfuscator checksum operand. **There is no endpoint, no URL, no token, no secret, and no authorization logic.** Confirmed with a detector that was proved capable of firing:

```
POSITIVE CONTROL (known-positive string)  network-API matches: 2  [fetch, https://]
NEGATIVE CONTROL (known-negative string)  network-API matches: 0
TARGET: original obfuscated script.js     network-API matches: 0
TARGET: deobfuscated script.js            network-API matches: 0
TARGET: index.html                        network-API matches: 2  [https://]   <- Google Fonts only

--- secret leak check across client artefacts ---
  script.js      : token present=false  'chocolate' present=false
  script.deobf.js: token present=false  'chocolate' present=false
  index.html     : token present=false  'chocolate' present=false
  style.css      : token present=false  'chocolate' present=false
  api.js (server, expected true) : token present=true     <- detector CAN fire
```

The two `https://` in `index.html` are `<link rel="preconnect" href="https://fonts.googleapis.com">` and the Rubik webfont — a third-party font CDN, not a first-party API call.

**The bundle is a decoy.** It is genuinely obfuscated, and the obfuscation is genuinely removable — and once removed it certifies that the client never contacts the API the catalogue promised. The 22 strings I spent the deobfuscation on are worth precisely nothing as API documentation.

---

## 3. Findings

### 3.1 Server source and dependency tree disclosed by the web server — CWE-200 / CWE-538 (critical, chain root)

`GET /api.js` → `200`, 494 bytes, `Content-Type: text/javascript`, complete and unmodified:

```js
const express = require('express');
const app = express();
const PORT = 3000;

const tokenValido = "…";                     // the gate credential

app.use(express.json());

app.post('/api', (req, res) => {
  const { token } = req.body;
  if (token === tokenValido) {
    return res.send("✅ Acceso concedido. Contraseña …");
  } else {
    return res.status(401).send("❌ Token inválido.");
  }
});

app.listen(PORT, () => { console.log(…); });
```

Also disclosed: `package.json` (entry point), `package-lock.json` (exact versions + integrity hashes for the whole tree), and a **full Apache directory index of `node_modules/`** listing 60+ packages.

**Impact.** The gate credential and the reward are both *literals in the disclosed source*. An anonymous `GET` yields a complete, working authentication bypass with no interaction with the protected service. The `node_modules/` listing plus the lockfile gives exact dependency versions for offline advisory matching, and the `package.json` `"main"` field names the application entry point — the disclosure tells the attacker which file to ask for next, which is how I found the rest.

**Root cause.** The application's own directory is the web server's document root (`/var/www/html` — confirmed by the stack trace in §3.4, not assumed). This is `api_web.md`'s existing **Backup / bulk-export rule** confirmed on a second target: *"an endpoint returning a database dump or a source archive is a critical-class disclosure even though it takes no parameters and returns no JSON … Always request it anonymously, and always pair it with a control on a neighbouring endpoint of the same family that is protected."* The archive here is a single 494-byte file rather than a 25 MB zip, and the finding is identical in class.

**Remediation.** Serve static assets from a dedicated directory that contains no application code, no `node_modules`, and no manifests. Deny `node_modules`, `package*.json`, and dotfiles explicitly rather than relying on the absence of a link to them. Add a build step that copies only the static assets into the document root. Long term, the deployment should be a reverse proxy serving a compiled front-end, with the Node process started from a directory the web server cannot reach.

### 3.2 Hardcoded authentication credential in source — CWE-798 (critical)

`tokenValido` is a string literal at `api.js:5`, compared with `===` at `api.js:12`. It is one shared value for the lifetime of the process, is not derived from anything, is not per-user, and does not expire.

**Impact.** Anyone who obtains the file — which §3.1 makes trivial — is authorised. There is no rate limit, no lockout, and no second factor, so the single value is the entire authentication boundary.

**Root cause.** A shared static secret used as an authenticator. This is the same class as the `SESSION_SECRET` default already documented at `api_web.md:274` (CWE-798 + CWE-321), with the same remediation: a per-credential secret compared in constant time, rotated, and revocable per principal.

**Not overclaimed.** The token is a *server-side* secret leaked by a source-disclosure bug. It is **not** a `VITE_*`/`NEXT_PUBLIC_*`/`REACT_APP_*` value embedded in a front-end bundle by design — I checked explicitly (§2.5) and the client artefacts contain neither the token nor the reward. The repository's existing rule for build-time public variables does **not** excuse this one, and applying it here would be the error.

### 3.3 Unhandled exception discloses stack trace and absolute filesystem paths — CWE-209 (low)

`POST /api` with a body the JSON parser does not claim (no `Content-Type: application/json`) → `500` with a full stack trace:

```
<pre>TypeError: Cannot destructure property 'token' of 'req.body' as it is undefined.<br>
&nbsp;&nbsp;at /var/www/html/api.js:10:11<br>
&nbsp;&nbsp;at Layer.handleRequest (/var/www/html/node_modules/router/lib/layer.js:152:17)<br>
...
&nbsp;&nbsp;at jsonParser (/var/www/html/node_modules/body-parser/lib/types/json.js:109:7)</pre>
```

Malformed JSON with the correct content type → `400` (correct).

**Impact.** Discloses the application root, the entry-point filename and line, the router library and version-specific internal paths, and the body-parser version. Standing alone this is low severity. **Its real value here was evidentiary**: it independently confirmed `/var/www/html` as the application root, which is what turns §3.1 from an inference into a measured fact. The bug is a *second* channel carrying the same information as the first — which is why it is reported separately rather than folded into §3.1, and why fixing §3.1 alone leaves it open.

**Root cause.** `app.use(express.json())` leaves `req.body` `undefined` when the parser does not run, and `const { token } = req.body` is unguarded; Express then serialises the `TypeError` into the response because no error handler is registered and the environment is not production.

**Remediation.** Destructure defensively (`const { token } = req.body ?? {}`), add a terminal error handler, and run the service with `NODE_ENV=production` so stack traces are not serialised to the client.

### 3.4 Application directory is the document root — CWE-732 / deployment decision (high, architectural, **no write primitive found**)

Any write primitive anywhere in this tree — an upload endpoint, a dependency with a write path, a CI step, a compromised dev account — becomes code execution **in the API process** the moment the process restarts, because `api.js` is `require`d from the document root. That is `api_web.md`'s world-writable-document-root rule with the write half removed: the *placement* is the finding.

**I did not find a write primitive, and I am not claiming one.** Verified with controls:

```
PUT /probe.txt       -> 405      PUT /api.js (overwrite!)  -> 405
PROPFIND             -> 405      MKCOL                     -> 405
POST /api.js         -> 200      (returns the file; not a write — see below)
POST /definitelynotexist.js -> 404    <-- positive control: the detector can fail
POST /created_by_me.txt     -> 404 ; GET /created_by_me.txt -> 404  (nothing created)
api.js md5 after all attempts: 2d6b2729430fdd9890ae09f5ca69f9a9  (unchanged)
```

`POST` on a static file returns `200` with the file's content — Apache serves an existing static file for `POST` when no handler claims it, so `POST` is an **alias to `GET`**, not a write. The proven-absent control (`404`) is what makes that reading safe rather than a guess: a path that cannot exist answers `404` under the same method, and a file created by `POST` was not created on the subsequent `GET`. The MD5 confirms the target file was never modified.

**Remediation.** Identical to §3.1 — separate the document root from the application directory. Treat the co-location as the single fix for both findings.

---

## 4. Controls that held (each with its positive control)

Reporting these with the same prominence as the bugs, because a reader cannot distinguish an untested control from a holding one.

| Control | Evidence | Positive control |
|---|---|---|
| **Source maps not published** | `script.js.map`, `style.css.map`, `index.html.map`, `main.js.map`, `app.js.map`, `bundle.js.map` all `404`; `grep -c sourceMappingURL script.js` → `0` | the same probe set is a `404` for names that cannot exist, and `node_modules/` returns `200` from the same sweep — so the probe distinguishes |
| **HTTP method restriction on static files** | `PUT`, `PROPFIND`, `MKCOL` → `405` on both a scratch path and `api.js` itself | `POST` → `200` on the same paths, and `api.js` MD5 unchanged after the attempts |
| **Apache dotfile pattern denial** | `.htaccess`, `.htpasswd` → `403` | `.htzzzznotreal` → `403` — **proves the 403 is a pattern rule, so I do not claim either file exists** |
| **`Vary: Accept-Encoding` honoured with a variant ETag** | gzip request → `Content-Encoding: gzip`, `ETag: "…-gzip"` | the identity request returns the un-suffixed ETag and no `Content-Encoding` |
| **Conditional-GET revalidation** | `If-None-Match: "77c-6367e3f893600"` → `304` | the same header with a wrong value returns `200` with a body |
| **Strict `===` comparison on the token** | `token` as an array → `401`; as an object with `toString` → `401` | a string token → `200` |
| **JSON body parser rejects malformed input** | `{bad json` → `400` | a well-formed body → `401`/`200` |
| **No credentials in the SSH banner** | `SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u6`, nothing else pre-auth | read pre-auth, as the pre-authentication-channel rule requires |
| **Not a "decoy description" lab** | the description claimed API interaction; the API is real, has a genuine auth decision, and gates a real reward | the description was *half* true — see §7 |

---

## 5. Chain

```
 1. nmap -sV -Pn -p-                        → 22 / 80 / 3000
 2. GET / on :80                            → static "TechFix" site, <script src="script.js">
 3. GET /script.js                          → 1916 B, obfuscated; no sourceMappingURL
 4. check .map siblings                     → all 404        (control that held)
 5. decide the entry question               → (a)+(b): does the client call the API?
 6. deobfuscate: array+rotation, offset decoder, aliases
    verify: decoder self-test + count identity (0 undefined, 0 call sites left)
 7. behavioural roundtrip vs instrumented DOM → 21/21 events, byte-identical
 8. RESULT: bundle is a scroll animation. 0 network APIs (detector proved able to fire)
 9. → the client documents nothing. Go read the SERVER.
10. GET /package.json                      → "main": "api.js"  ← the pivot
11. GET /api.js                             → 200, 494 B, full source: token literal + reward literal
12. roundtrip self-test on the extracted token (decode(encode(x))==x, bytes verbatim in source)
13. POST /api {"token": <extracted>}
      control-wrong   → 401   ❌ Token inválido.
      control-mangled → 401
      candidate       → 200   ✅ Acceso concedido. Contraseña chocolate123
14. confirm the root cause channel: POST /api with no Content-Type → 500 → /var/www/html/api.js
15. sweep docroot serially (baseline + known-present controls first) → 4-5 real files
16. verify .htaccess/.htpasswd 403s with a provably-absent name → pattern rule, not a file
17. test write primitives on the docroot → all 405 / alias-to-GET, api.js MD5 unchanged
18. destroy + recreate from image; reward reproduces on the fresh instance
```

**Reward, literal:** `POST http://172.17.0.8:3000/api` with the token extracted from the disclosed source returns

```
HTTP 200
✅ Acceso concedido. Contraseña chocolate123
```

**No RCE was obtained, and none was available.** There is no code-execution primitive on this target: no upload, no injection, no deserialization, no write to the document root. The chain is *read* → *authenticate*, and it terminates at the reward. The first `id` inside a new execution primitive is therefore **not applicable** — there was never a primitive, and I did not obtain a shell from which to run one.

---

## 6. No `FLAG{}` — reported as an absence, with the evidence

This lab ships **no `FLAG{}` string, no reward file, and no success endpoint beyond the API's own response.** Evidence:

- the full 21-line application source was read (§3.1) and contains no flag, only the password literal;
- the reward string was returned by the API and hashed for provenance: `sha256(chocolate123) = f05833449a89a965cf5a729d22cdf227cca97f7d780eb10eb4533affd37eddf5`;
- the docroot was swept (≈606 000 paths across three runs, §0.3–0.5) and contains no flag file;
- the API has one route and one field, both enumerated.

**Reporting it as an absence, not inventing a value.** This is the eleventh consecutive lab in this series without a `FLAG{}`, and reporting the absence has been the correct decision every time.

---

## 7. Design observation: the lab's own title is the decoy, and the description is half true

The catalogue says *"Javascript deobfuscation e interacción con una API."* For eighteen labs the description lied outright. Here it is **half true in an unusually precise way**, and that is worth recording because it is a different failure from the usual one:

- **"Deobfuscation" — true, and it is the intended exercise.** The bundle really is obfuscated, the three layers really do come off, and the roundtrip really does verify. An author did real work here.
- **"Interacción con una API" — true of the target, false of the client.** The API is real, has a genuine authentication decision, and gates a real reward. But **no client ever interacts with it.** The `index.html` form has no `action`, no `method`, and no `onsubmit`; the bundle never calls `fetch`; the page is a static marketing site with an animated card reveal. The API exists *behind* the site, not *within* it.

So the description is accurate about the lab and misleading about the mechanism, and it points the solver at the bundle precisely when the bundle is a dead end. A more accurate title would be something like *"un cliente que no habla con la API"*. **This is the lab author's best idea, and it is also the trap**: the instinct to deobfuscate the bundle is correct, and the reward for doing it perfectly is learning that it is worth nothing.

The lesson the lab actually teaches is the one the methodology was missing: **deobfuscation is a method with an entry question, and the most valuable output of a successful deobfuscation can be a documented negative.**

---

## 8. What this lab adds to the methodology

The lab's technique lives in `api_web.md` (it is a web/API target). Two things came out of it, and they go to different places because they are different claims:

1. **A genuinely new class: JavaScript deobfuscation as a method.** The repository had **no oracle for it anywhere** — `grep` for `deobfuscat` across all sections returns nothing. Mobile has a client-*signed*-request section; nothing covers the client as a *document to be read*. So: **a new section in `api_web.md`**, carrying the entry question, the layer order with per-layer verification, the roundtrip contract, the "which bundle does the server actually serve" control, and the count-identity post-condition from §0.2.

2. **A counterexample to an existing rule in `mobile.md`.** `mobile.md:253` reads *"The client is the best documentation of the API. The request class of the app itself is the authoritative surface map: paths, methods, claim names, header names, algorithm. Read it before touching a proxy."* That rule is **not confirmed here — it is refined.** Its own wording contains the precondition it was missing: the client is a surface map *because it makes requests*. This lab's client makes none, and after a complete, verified deobfuscation it documented **zero** endpoints, zero parameters, and zero secrets. The rule is right where it applies and false as stated, and the fix is one clause: **a client that makes no requests documents nothing.** That is an **extension with a cross-reference**, not a new section and not a duplicate — the existing statement is kept and its missing precondition is supplied.

The two are related but not the same claim, which is why they do not belong in one place: one is a technique the repository lacked, the other is a boundary on a rule it already states.

---

## 9. Tested / not tested / untestable

**Tested.** Full TCP port scan with service detection; the static document root including three serial content sweeps with controls; the Express route and field surface across six methods and six paths; JSON parser error handling; type-confusion on the token field; write primitives on the document root (`PUT`/`PROPFIND`/`MKCOL`/`POST`) with MD5 integrity re-check; cache and revalidation policy including the gzip variant; source-map publication; the pre-auth SSH banner; obfuscation layer removal with a behavioural roundtrip; detector self-tests for the decoder, the network-API grep, the sweep, the 403 pattern and the `POST` alias.

**Not tested.** No credential guessing on port 22 (none was found, none was attempted). No dependency CVE matching against the disclosed `package-lock.json` — the versions are disclosed and *could* be matched offline, and I did not do it. No timing analysis of the `===` comparison (it is a short-circuit string compare; the finding does not depend on it). No attempt to reach the Express process on `127.0.0.1:3000` from inside, since no execution primitive existed. No SQLi, SSRF, XSS or path-traversal probing — the API takes one opaque token and has no parameter to fuzz, and I say so rather than implying coverage.

**Untestable on this host.** `nmap -sU` (no sudo), so the UDP plane is a **declared coverage gap**, not a closed port. No `ipmitool`, `smbclient`, or `sshpass` available. No browser, so the deobfuscation roundtrip was verified against an **instrumented DOM stub** rather than a real engine — the trace covers property writes, event registration and observer wiring, but not layout or paint. That is a genuine limit on the roundtrip's scope and it is stated rather than papered over.

**Every tool output in this document was actually executed.** No tool output is simulated, and the two places where a detector returned a clean negative that I did not believe (§0.3, §0.5) are reported as the defects they were.

---

## 10. Restoration

Destroyed and recreated from the shipped image, and the chain re-verified end to end on the fresh instance:

```
docker stop ofuskeit_container && docker rm ofuskeit_container
docker run -d --name ofuskeit_container ofuskeit:latest
→ new container 5018149f…, 172.17.0.8, Up
```

```
22/tcp   open  ssh     OpenSSH 9.2p1 Debian 2+deb12u6
80/tcp   open  http    Apache httpd 2.4.62 ((Debian))
3000/tcp open  http    Node.js Express framework

api.js exposed   : 200
script.js        : 200
package.json     : 200
node_modules/    : 200
script.js.map    : 404        (no source map, as before)

POST /api with the token extracted from the freshly-recreated instance:
  HTTP 200 :: ✅ Acceso concedido. Contraseña chocolate123
```

Clean-room reproducible from the image alone.
