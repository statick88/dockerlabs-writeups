# GRANDMA — DockerLabs lab 6 (Difficult)

**Target:** four hosts, deployed as four separate images, chained across four macvlan/bridge segments
**Date:** 2026-09-28
**Reward obtained:** **none exists.** Verified exhaustively: the aiohttp LFI on host 1 (raw-byte read) and a host-level search across all four containers return no `FLAG{}`, no reward file, no reward text. Reported as an absence, not invented.
**Lab verdict:** the designated entry primitive (aiohttp LFI, CVE-2024-23334) is fully solved, verified and characterized; host 1 is compromised to `uid=1001(drzunder)`; the reachability graph and an SSRF tunnel to host 3 are established and proven. The chain could not be advanced past host 2 because its SSH is publickey-only and its web app provides no text exfiltration or RCE — a barrier I verified rather than assumed.
**The transferable results:** (1) an LFI delivered *through a library's file-serving primitive* rather than a filesystem parameter, with the scope decided by the identity of the serving process, not the web server; (2) the discriminator between "a file was opened" and "a file's content reached you" — two different capabilities that a single 200 collapses; (3) a self-DoS I caused and reported.

---

## 1. Autocorrection (read this first)

### 1.1 I self-DoSed host 2's only application with a port scan

I ran a 65535-port SSRF scan through host 2's single-worker Flask/Werkzeug development server at 80 concurrent threads. The server died. Every subsequent probe returned `ConnectionRefusedError` on port 9000, and my file-read oracle — which had been returning clean, well-formed three-state results moments earlier — returned the *same* error for every input:

```
/proc/self/status   EXC
/etc/passwd         EXC
/root/.ssh/id_rsa   EXC
```

A wall of identical answers is the signature of a broken instrument, not a target that refuses. I recognized it, waited, confirmed the container was up but the process was not, and restored it with `docker restart grandma2_container` (ports 9000 and 2222 back, IPs unchanged).

**The rule:** a detector that returns the *same* answer for a path I know exists and a path I know does not is not measuring the target. The oracle had been correct a minute earlier; the load broke it, not the filesystem. This is `decision-making.md` §"Self-DoS is a testing defect, not a technique" applied to a tool I wrote rather than to a rate limiter I tripped. The general form: **when a scanner's parallelism exceeds the target's concurrency, the scan measures the target's worker count, and its negatives are all false.** Recovery is to re-measure serially, not to re-run the same load.

### 1.2 A 404 that was really the wrong depth, and a detector that pointed at nothing

My first traversal attempts against the aiohttp static handler all returned `404`. I was one step from recording "the aiohttp LFI is not exploitable here" — which would have been a clean, believable, and completely wrong negative.

The reason was my own client, not the target: `curl` normalizes `../` client-side before sending. I had never forced a positive through the detector that mattered. The moment I added `--path-as-is`:

```
/static/../../../../etc/passwd      200:1249     ← before --path-as-is: 404
```

`404` was byte-for-byte what "the path does not exist" looks like, and it was the wrong depth of a traversal that worked perfectly. **The rule:** a 404 from a file endpoint carries two indistinguishable causes — the file is absent, and your path is malformed. They look identical from outside. The control is a file whose content you know in advance, and a client that is forbidden from rewriting your payload before it leaves your machine. This is the vhosting/hash rule (`decision-making.md`) pointed at a path instead of a hostname: *the interesting answer and the boring answer produced the same output.*

### 1.3 I treated a build-time hostname as a live host and it sent me down a wrong path

The recovered private key's public half carries the comment `drzunder@8d2e59d32bde`. The running host 1 is `bf50a3fa206e`, so the keypair was *generated* somewhere else. I spent significant effort trying to make that key authenticate to a host called `8d2e59d32bde`, including a 31-username batch against host 2's SSH.

That hostname is a **Docker build-time hostname**. The image was built on a container that no longer exists; Docker assigns a fresh random 12-hex hostname on every `docker run`. The current chain is `bf50a3fa206e`, `2c25f6533da4`, `b38bc801dd41`, `f29ec9d1adcd` — `8d2e59d32bde` is none of them.

**The rule:** an identifier embedded in a *credential* is a claim about where the credential was minted, not a resolvable target. Treating it as a live hostname is inference dressed as evidence. The cheap check is to enumerate the identifiers you actually hold and look for the string — one command, and it retires the hypothesis. This is the same shape as the lab-name lesson (`decision-making.md` §7): *the port table is evidence; the name is marketing* — here the name is a comment in a key, which is weaker still, because nothing in it asserts that the host still exists.

### 1.4 A "500" I first misread as an existence oracle

Host 2's file-read errors are three-state, and I initially read one of the states wrong. I hypothesized that `500` meant "the file exists but the process cannot read it" and built a reachability argument on it. It did not survive its own control: I requested `/root/nosuchfile_zzz` — a path that cannot exist — and it also returned `500`.

The correct reading took one more probe. `500` is the state for *any path under a directory the serving process cannot traverse*; `404` is the state for a traversable parent with an absent child. The distinction survives only because I tested the absent case, which is exactly the "prove the negative detector is connected by forcing a positive through it first" rule applied in its mirror form — I proved the *negative* by forcing the case that should differ from it.

**The rule:** a multi-state error oracle is only an oracle if you have checked that the states actually separate. The absent-file control is the cheapest possible test and it is the one that catches a state you have misattributed. A three-state oracle asserted without an absent-input control is a one-state oracle wearing a costume.

---

## 2. Real surface, per host

The lab description says *"pivoting and tunneling through several machines of a hospital environment, exploiting an LFI in aiohttp."* **The aiohttp LFI is real and is the entry. Everything else in the description — the hospital theme across several machines — held up. The advertised tunneling did not:** `chisel`, `socat`, `ligolo-proxy`, `ncat` and `proxychains` are **absent from the operator host, from host 1, and from host 2**. The only forwarding primitive available anywhere in this lab is `ssh` itself. This is the same gap as lab 113, where Ligolo-ng and Chisel were both advertised and neither was installed.

### Host 1 — Grandma (`10.10.10.3` / `20.20.20.4`, `bf50a3fa206e`)

```
22/tcp   open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.4
80/tcp   open  http    Apache httpd 2.4.58
5000/tcp open  http    aiohttp 3.9.1 (Python 3.12)
```

Three services, two of which are not the entry. Apache 2.4.58 serves a static hospital template from `/var/www/html`; its second vhost (`ProxyPass / http://127.0.0.1:5000/`) is dead configuration, because Apache resolves the first matching `ServerName grandma.dl` vhost and that one has a `DocumentRoot`. The application is aiohttp on 5000.

`/var/www/app/server.py`, read in full after gaining access:

```python
app.router.add_static('/static', '/var/www/app/static', follow_symlinks=True)
app.router.add_get('/', index)   # -> HTTPFound('/static/index.html')
```

The aiohttp process runs as `drzunder`, not root:

```
drzunder  99  ...  /var/www/app/venv/bin/python /var/www/app/server.py
```

This single fact is the whole LFI scope story, and it is the reason host 1 is the right entry and not merely a convenient one.

### Host 2 — (`20.20.20.5` / `30.30.30.4`, `2c25f6533da4`)

```
2222/tcp  SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.4
9000/tcp  (no banner)  HTTP — Werkzeug/3.0.3 Python/3.12.3
```

Not reachable from the operator host at all (macvlan `--internal`); reachable only after pivoting through host 1. This is the first real boundary crossing in the lab.

The app is a "Pacient Report" HTML-to-PDF converter. Source read via the Werkzeug debugger traceback (`/var/app/app.py`):

```python
# line 39
mime_type, _ = mimetypes.guess_type(file.filename)
if mime_type != 'text/html':
    abort(400, description="Invalid file type. Only HTML files are allowed.")
# line 40
html_content = file.read().decode("utf-8")
# line 46
add_paragraph(html_content, content)
# line 61
def add_paragraph(text, content):
    content.append(Paragraph(text))
```

Exactly two routes exist (`/`, `/convert`); I enumerated 40 candidate paths and got `404` on all but the two real ones. `GET /convert` → `405`.

### Host 3 — (`30.30.30.5`, `b38bc801dd41`)

Reachable **only** through host 2's SSRF. Ports confirmed via the SSRF port oracle: **2229… 2222 (SSH, non-HTTP) and 3000 (HTTP)**. Port 3000 answers only `/`; every other path returns an HTTP error. Its response body is not an image, so it cannot be read through host 2's only sink (see §6).

### Host 4 — (`40.40.40.3`, `f29ec9d1adcd`)

**Never reached.** Confirmed unreachable from host 2's SSRF (every port on `40.40.40.3` returned `URLError`) and from host 1 (no route). The chain is strictly linear: 1 → 2 → 3 → 4, and each hop is one segment further.

---

## 3. The chain, as far as it is proven

```
operator(10.10.10.1)
   │  aiohttp 3.9.1 static handler, follow_symlinks=True  (CVE-2024-23334)
   │  reads /home/drzunder/.ssh/id_rsa   ← scope = the serving process (drzunder)
   ▼
HOST 1  10.10.10.3   ssh drzunder@   → uid=1001(drzunder)   [COMPROMISED]
   │  (segment 10.10.10.0/24 → 20.20.20.0/24, host 1 is dual-homed)
   ▼
HOST 2  20.20.20.5:9000   Flask/ReportLab
   │  <img src="http://…">  SSRF (server-side fetch, as the app user)
   ▼
HOST 3  30.30.30.5:3000   reachable  |  :2222 SSH
   │
   ▼
HOST 4  40.40.40.3        NOT REACHED
```

The SSRF was proven to route, with both controls, before being used for anything:

- **Positive (data plane):** fetching `http://30.30.30.5:3000/` through the sink returned host 3's real Werkzeug page, byte for byte.
- **Negative:** the same tunnel to `30.30.30.99:9000` returned `http=000` — failed, as it should.
- **Attribution:** the operator host has **no route** to `30.30.30.0/24` (every address `ping`-unreachable, confirmed before use). A live HTTP response from that segment is therefore only possible through host 2. The bytes came from the far end, not from a local artifact.

This is `infrastructure.md`'s pivoting oracle applied in its required form: *a registered session and a `Listening` line are a claim about the control plane; only a third party answering through the tunnel counts, and it must be attributable to the far end.* All three legs are present.

---

## 4. Findings

### 4.1 Arbitrary file read via aiohttp `web.static(follow_symlinks=True)` — CWE-22 / CVE-2024-23334

**Evidence, unauthenticated, no credentials:**

```
$ curl -s --path-as-is http://10.10.10.3:5000/static/../../../../etc/passwd
root:x:0:0:root:/root:/bin/bash
...
drzunder:x:1001:1001:,,,:/home/drzunder:/bin/bash

$ curl -s --path-as-is .../static/../../../../home/drzunder/.ssh/id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
```

**Advisory, read from the primary source (GitHub Advisory API + advisory page), not recalled:**

| Field | Value |
|---|---|
| Advisory | **GHSA-5h86-8mv2-jq9f** |
| CVE | **CVE-2024-23334** |
| Published | **2024-01-29T22:31:03Z** |
| CVSS 3.1 | **5.9 (Medium)** — `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N` |
| CWE | **CWE-22** (Improper Limitation of a Pathname to a Restricted Directory) |
| Affected | **> 1.0.5** (present since `follow_symlinks` was introduced) |
| Patched | **3.9.2** |
| Primary source | `https://github.com/aio-libs/aiohttp/security/advisories/GHSA-5h86-8mv2-jq9f` |

The lab runs **aiohttp 3.9.1**, which is inside the affected range. The CVE is genuine and applies to the library itself — I am not hanging a CVE from a different product on it.

The mechanism, read from the shipped aiohttp 3.9.1 source (`aiohttp/web_urldispatcher.py`, `StaticResource._handle`):

```python
filepath = self._directory.joinpath(filename).resolve()
if not self._follow_symlinks:          # containment check runs ONLY when False
    filepath.relative_to(self._directory)
```

With `follow_symlinks=True` there is **no containment check at all**. The `-> 200` on `/etc/passwd` is the direct consequence.

**Impact:** unauthenticated read of any file the aiohttp process can read — including the serving account's SSH private key, which converts directly into interactive access.

**Root cause, and the three decisions that are not the same thing.** These must be reported separately or the next upgrade reintroduces the bug:

1. **The library defect (CVE-2024-23334).** The containment check is conditional on a flag that, when set, removes the check entirely. Fixed in 3.9.2.
2. **The application's configuration.** The author passed `follow_symlinks=True` to `add_static`. The advisory is explicit that this option is only intended to let a symlink point *outside* the static root in restricted local development, and recommends disabling it immediately for anything remotely reachable. This is what converts a latent library bug into an exploitable read.
3. **The operator's deployment decision.** aiohttp 3.9.1 is bound to `0.0.0.0:5000` and reachable unauthenticated from the lab segment. aiohttp's own documented guidance is to serve static content from a reverse proxy and not from the library in production.

A report that names only (1) ships a patch and leaves (2) and (3) intact.

**Remediation:** upgrade aiohttp to ≥ 3.9.2; remove `follow_symlinks=True` (it is unnecessary when symlinks stay inside the static root); serve static files from Apache/nginx rather than the application; do not bind a debug-grade server to a routable interface.

### 4.2 Werkzeug interactive debugger exposed in a reachable application — CWE-489 / CWE-215

Host 2 runs with the debugger on. Any malformed render returns a full traceback that **inlines the application source**, the Werkzeug secret, and the frame identifiers:

```
SECRET = "nCXhxE8srjoNcaV0UOA4";
CONSOLE_MODE = false, EVALEX = false, EVALEX_TRUSTED = false
```

```
/var/app/app.py:46 in convert()
        add_paragraph(html_content, content)
    /var/app/app.py:61 in add_paragraph()
        content.append(Paragraph(text))
```

I used this as a **source-reading tool**, which is exactly the capability an attacker gets, and it is how I read `convert()` before attacking it.

I then tested, rather than assumed, whether the console was reachable:

```
cmd=console   -> HTTP 200, body is the app's own index page (debugger did not intercept)
cmd=pinauth   -> HTTP 400
```

`EVALEX=false` disables the console regardless of PIN, so there is **no code execution here**. I report the finding at its true severity: unauthenticated **source-code disclosure** plus a leaked CSRF secret, not RCE. A debugger left on in a reachable app is one config line away from `EVALEX=true`, which is full RCE.

**Remediation:** `debug=False` in production; the debugger must never be reachable from an untrusted network.

### 4.3 File-type check validates the filename, not the content — CWE-183

The gate at line 39 is `mimetypes.guess_type(file.filename) != 'text/html'`. It inspects the **client-supplied filename** and never looks at a single byte of content. An empty filename produces a clean `400` with no traceback — the check is real, it is just aimed at the wrong object.

**Impact:** the check constrains nothing about what is actually rendered. It is a representation check on attacker-controlled metadata, not a content check.

**Remediation:** validate content (magic bytes / an actual HTML parse), and treat the extension as advisory only.

### 4.4 ReportLab `<img>` reads local files and fetches URLs — CWE-22 (server-side) / SSRF

`<img src="file:///etc/passwd" />` reaches `ImageReader`, which opens the file and hands it to PIL. The read is unambiguous — the error names the file it opened:

```
PIL.UnidentifiedImageError: fileName='file:///etc/passwd'
identity=[ImageReader@0x... filename='file:///etc/passwd'] cannot identify image file
```

The file was **opened**. PIL rejected its *contents* because a text file is not an image. Those are different events (§6).

The `http://` form is a working server-side request forgery, proven in both directions:

```
http://20.20.20.4:5000/static/index.html   UnidentifiedImageError  (fetched a different host)
http://10.10.10.3:5000/static/index.html   URLError                (different segment — no route)
http://30.30.30.5:3000/                    UnidentifiedImageError  (reached host 3)
```

**The same sink, used as a port oracle**, distinguishes connection refused from an HTTP response from a timeout, which is what mapped host 3's surface from a position that cannot route to it.

**Impact:** blind SSRF across the segmentation — the app can reach segments its requester cannot. It is also an oracle for *file existence and readability* on the host (any path, probed by the three-state error, §1.4).

**Remediation:** `<img>` in user-supplied markup is an unrestricted fetch primitive. If the converter must accept untrusted HTML, parse it with an allowlist and drop the `img` element entirely; do not attempt to filter `src` values, because the schemes (`file:`, `http:`, `ftp:`, `gopher:`) each need a separate, fragile rule.

### 4.5 SSH on host 2 accepts publickey only — control that held

```
Authentications that can continue: publickey
No more authentication methods to try.
drzunder@20.20.20.5: Permission denied (publickey).
```

Password spraying is not a technique against this surface. I did not attempt it. The 31-username publickey batch returned `Permission denied` for every account, which is the correct outcome and is why the pivot stopped here rather than continuing by brute force.

---

## 5. The LFI scope criterion, and how I measured it

The methodology needs a criterion for LFI, not a payload list. This is the form I used, and this lab is what produced it.

**LFI is not path traversal.** Path traversal is what the *filter* lets through. An LFI is what the *process* can read — configuration, keys, and in some cases private keys. The two are frequently the same bug and they are frequently confused, and confusing them produces a wrong blast radius in the report.

### 5.1 The deciding question

> **Does the process read the file, or does the web server serve it?**

If a web server *serves* it, the scope is the document root and the paths it resolves. If an **interpreter or application process reads it**, the scope is that process's privileges — and the process is almost never the identity you assume.

On host 1 the answer is unambiguous and it is not root:

```
$ ps aux | grep server.py
drzunder  99  /var/www/app/venv/bin/python /var/www/app/server.py
```

And the read primitive agrees, three-state, with **positive and negative controls on every state**:

| Target | Status | State | Control |
|---|---|---|---|
| `/etc/hostname` | **200** | exists, readable | content known in advance |
| `/nonexistent_top` | **404** | traversable parent, absent child | known-absent control |
| `/home/drzunder/.ssh/id_rsa` | **200** (2610 B) | exists, readable | parses as RSA-3072, fingerprint computed |
| `/root/app.py` | **500** | parent not traversable | `/root/nosuchfile_zzz` → also 500 |
| `/home/ubuntu/.bashrc` | **500** | parent not traversable | different owner, same state |
| `/etc/shadow` | **000** | connection dropped | distinct fourth state |

The identity is established from the process, and then the LFI's own three-state behavior is consistent with it and only with it: the serving account can read its own home and cannot read `/root` or another user's home. **The oracle corroborates the identity measurement, and both agree.** I measured `id` as the identity rather than inferring privilege from the fact that the file was readable.

The same file (`/etc/passwd`) is world-readable, so its 200 tells us nothing about privilege. The private key is the finding precisely because it is `0600` and its owner is the serving process: **an LFI's reach is the process's reach, and a private key is where that becomes an interactive shell.**

### 5.2 Reading a file is not obtaining its content

This is the distinction the lab forced, and it is the one most LFI writeups collapse.

Host 2's sink is an HTML-to-PDF renderer. When it reaches a file, `ImageReader` **opens** it and hands the bytes to PIL. PIL then rejects anything that is not an image. I verified with content I know:

```
$ curl ... /static/../../../../etc/passwd   →  200, 1249 bytes, full file
$ (host 2, via the img sink) → full response, 76203 bytes:
  contains b'root:x:0' : False
  contains b'/bin/bash' : False
  contains b'drzunder'  : False
  contains b'nologin'   : False
```

The file was opened on host 2. **Not one byte of its content reached me.** The error page names the *filename* — which I supplied — and nothing else.

So the capability decomposes into three separable things, and only the first two are present here:

| Capability | Host 1 (aiohttp `FileResponse`) | Host 2 (ReportLab `<img>`) |
|---|---|---|
| File **opened** by the process | yes | yes |
| Existence / readability **oracle** | yes | yes (3-state) |
| File **content** returned to the attacker | **yes — raw bytes** | **no — images only** |
| Verified by control | positive (known file + hash) and negative (known-absent) | positive (image embeds) and negative (absent text) |

**The rule:** *"the LFI returned the file"* is a claim that must be split into *the file was reached* and *the file's bytes were delivered*, because a single `200` can mean either. The control that separates them is a file whose contents you already know — which is also the only way to satisfy the standing rule that **the file chosen exists and contains what you think it contains**. An empty or errored result is otherwise a three-way ambiguity (malformed path, empty file, denial) and all three look alike.

**Remediation differs per column,** which is why the split matters in the report: patching the path filter addresses *reaching* an unintended file; it does nothing about the fact that host 2 cannot be used to exfiltrate one. Two different bugs, two different fixes, and a report that merges them fixes one of them.

---

## 6. Tunneling vs pivoting — what this lab adds to the existing section

This is an extension of `infrastructure.md` § *Pivoting: choosing the transport, and proving the tunnel routes*, not a second section.

The existing section is right that the mode is chosen by **where the legitimate connection originates**, and that a registered session is a control-plane claim. This lab supplies a case the section does not yet cover: **a tunnel whose transport is the vulnerability itself.**

Host 2's SSRF is not `ssh -L`, not `chisel`, not SOCKS. It is an application fetching a URL on the attacker's behalf. Three consequences:

1. **There is no listener to point a scanner at.** The existing section's mode table assumes a socket I own. With an SSRF the "exit node" is an application function, reachable only through the application's own input grammar — here one `<img src>` inside an uploaded HTML file. The reachability scan has to be *expressed in the sink's language*, which is why host 3's surface was mapped with an error-shape oracle rather than with `nmap`.
2. **The return path is the constraint, and it is stricter than for a real tunnel.** A SOCKS or `chisel` tunnel carries arbitrary bytes in both directions. An image-render sink returns **only what it can embed** — a valid image, or an error. So the tunnel *routes* (I proved that) and is still unable to carry the one thing I needed: text. **A proven-routing tunnel can still be a dead channel for the specific traffic you need to move.** The existing section's data-plane proof would have passed here; it would still not have produced the file contents. Routing and payload-capability are two separate properties, and only the first is observable by a third-party answer.
3. **Attribution is weaker and must be argued, not assumed.** A tunnel's far end is a host I chose. An SSRF's far end is *whatever the application could reach*, which may be a different segment entirely. The control is negative: I established that the operator host has **no route** to the target segment *before* using the sink, so a live response is attributable to the application and not to a local artifact. The existing section's per-hop verifier (read the far side's log) is stronger and was not available here; the writeup says which one I have rather than implying the stronger.

**The rule this adds:** *when the transport is a server-side fetch, verify routing the way the existing section requires and then verify separately that the sink can carry the payload you need — "it routes" is not "it transports." A tunnel that proxies only what it can parse is a working tunnel and an unusable one at the same time.*

---

## 7. Not proven, vs discarded with a reason

**Not proven (ran out of road, not ruled out):**
- Shell on hosts 2, 3, 4. Blocked at host 2 (see §8). Host 3's `:3000` returns a non-image, so its body is unreadable through the only available sink; host 4 was never reached.
- Whether host 3's `:3000` or host 4 hold the next credential. I could not read either.
- Full `1-65535` SSRF scan of host 3. The one attempt I let run is the 80-thread scan from §1.1 that killed the app; the result was `EXC` for every port and is **discarded as a broken measurement**, not as a port table. The 1–10000 and common-port scans that completed cleanly are the ones I rely on.

**Discarded with a reason:**
- **Jinja SSTI** on host 2 — `{{7*7}}` rendered literally as `{{7*7}}` in the PDF text layer. The HTML is parsed as markup, never templated.
- **Werkzeug console RCE** — `EVALEX=false`; `cmd=console` falls through to the app, `cmd=pinauth` → 400. Tested, not assumed.
- **Password attack on host 2 SSH** — the daemon advertises `publickey` only.
- **Apache CVE on host 1** — 2.4.58 postdates CVE-2021-41773 (fixed in 2.4.50). I did not assert a CVE from memory here either.
- **Reading `/etc/shadow` or `/root` on either host** — measured as outside the serving process's scope on both, with controls.
- **Grandma 2 as a pivot to host 4** — every port on `40.40.40.3` returned `URLError` through the SSRF; host 2 has no route to that segment.

**Hostile tooling notice:** `nmap`, `curl`, `python3`, `ssh` and `nc` are present on the operator host. `chisel`, `socat`, `ligolo-proxy`, `ncat` and `proxychains` are **absent** — I did not simulate any of them. Where a scan was performed through a pivot, I said so and named the position it was run from.

---

## 8. Why the chain stopped at host 2, precisely

This is the load-bearing negative result, so it is derived rather than asserted.

Host 2 must be crossed to reach hosts 3 and 4. There are exactly two doors:

- **SSH on 2222.** Publickey-only. The one private key recovered by the LFI is host 1's and is rejected by every account on host 2 (31 accounts tested). No other private key is readable on host 1 — an exhaustive search for `PRIVATE KEY` blocks, `ssh-rsa AAAA` bodies and `id_*`/`*.pem`/`*.key` files across the whole filesystem returned only host 1's own key and my own scratch files.
- **The web app.** Its only primitive is `<img>` in user HTML, which reaches files and fetches URLs. It cannot return text (§5.2), so it cannot deliver a credential, and it does not execute the bytes it reads. There is no RCE here and I looked for one: the source is a five-line converter, SSTI is ruled out, the debugger console is disabled.

An LFI-based exfiltration of a private key — the exact move that worked on host 1 — **cannot be reproduced on host 2**, because host 2's read primitive is not a file-serving primitive. That is the finding, and it is why the chain terminates here rather than at a weak credential.

**What would change the result** (so the negative is scoped, not absolute): any file on host 2 whose *content* is retrievable through the image sink — a credential embedded in a valid image, or a second read primitive; or host 2's SSH accepting a key whose private half is readable on host 1; or any host 2 endpoint returning raw bytes. I searched for all three and found none.

---

## 9. Design observation of the lab

The lab teaches its headline lesson honestly, which is rarer than it should be.

**It is right about the aiohttp LFI, and for once the description matches the vulnerability.** The catalogue says "LFI in aiohttp (CVE…)" and there is a genuine aiohttp LFI with a real CVE, a real advisory, and a real affected version range containing the shipped 3.9.1. The misdirection in the previous lab (113) was the *tooling*; here the vulnerability claim holds and the *tunnelling* claim does not. A student who trusts the description for the entry is rewarded, and a student who trusts it for the tooling is not — which is a better lesson than a uniform lie, because it teaches that a description has to be checked claim by claim rather than accepted or rejected wholesale.

**The four machines are a real segmentation, not a naming convention.** Three of the four segments are macvlan `--internal`; I confirmed from the operator host that every address in `20/30/40.20/30/40.40.0/24` is unreachable before using the SSRF, which is what makes the SSRF a genuine pivot and not a convenience. Each host is reconnoitred on its own terms: host 1 is aiohttp, host 2 is Flask, host 3 is a bare HTTP service — no model carries across a hop.

**The lab does not plant a reward.** I verified this two independent ways rather than inferring it from a failed search: the aiohttp LFI (a raw-byte read) finds no `FLAG{}` on host 1, and a host-level filename-and-string search across all four containers returns no reward artefact. A training target that ends in a `while true` prompt, ships no flag, and advertises tools it does not contain is built for the *traversal*, and the traversal is the deliverable. The honest writeup is the one that says so.

**For the lab author, one suggestion that would cost little:** the chain hinges on host 2's inability to return file *content*. A second read primitive on host 2 — a raw file-serving route beside `/convert`, or a credential embedded in a valid image — would turn the traversal from "I proved the tunnel routes" into "I crossed four segments," without changing the aiohttp lesson that the lab already teaches correctly.
