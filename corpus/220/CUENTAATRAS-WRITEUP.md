# 220 CuentaAtrás — writeup

**Lab:** 220 · *CuentaAtrás* · Medio
**Description (from the platform catalog and `tooling/labs.manifest:58`):** *"WordPress
platform; account lifecycle."* — `220|CuentaAtrás|medio|WordPress platform; account lifecycle`
**Target:** `172.17.0.5` — single container `cuentaatras_container`, image `cuentaatras:latest`.
**Stack (from the artefact, not from memory):** Ubuntu 24.04, Apache 2.4.58, PHP 8.3.6,
MariaDB on `127.0.0.1:3306`, **WordPress 6.9.1** hidden at
`/var/www/html/secret_portal_65hBlEo9OU`, plus a **bespoke 6-file PHP application** at the
document root that *is* the account lifecycle.
**Plugin:** `wpvivid-backuprestore` 0.9.123 (`active_plugins` contains exactly one entry).
**Result:** unauthenticated → account created → **state transition "exists → confirmed" forced
by guessing** → authenticated as an attacker-chosen account → the hidden WordPress path
disclosed by the dashboard. **`uid=33(www-data)` is the ceiling of the whole web surface, and
neither reward is reachable from it** (§8, §9).
**A reward exists — two of them** (§8).

**Topology.** `auto_deploy.sh` was read, never run. It creates **no network at all**: one
`docker run -d` on the default bridge (line 131) and one container (line 146 is the
`while true`). No macvlan, no second host, no pivot. Unlike labs 61 and 108 there is no
`--internal` network here, so the container **does** have egress; §9 shows that changed
nothing about the findings and I used it for nothing.

---

## 0. The headline: the state machine *is* the attack surface, and the "did it get sent?" question decides it

The brief asked for the boundary between **"a user exists"** and **"a user is confirmed"**, and
for the answer to *where mail actually goes in this lab*. The artefact answers the second
question decisively, and the answer is what turns the first one into a vulnerability.

> **There is no mail in this lab. There is no mail *transport* in this lab.**
>
> ```
> $ grep -rn "mail(" /var/www/html/*.php            -> zero hits
> $ which mail sendmail msmtp mutt                  -> not found
> $ ls -la /var/mail/                               -> total 12, empty
> $ ps aux | grep -iE "sendmail|smtp|mail"          -> (nothing)
> ```
>
> `register.php` writes the UI string *"Hemos enviado un código SMS de 4 dígitos a tu móvil
> registrado."* (`verify.php:53`) and the application **never sends anything**. The 4-digit
> code is generated (`register.php:13`), stored (`register.php:16-17`), compared
> (`verify.php:24`) — and delivered to no one, ever.

Everything below follows from that one fact, so it is stated as a rule rather than as a bug
in a file:

> **Rule (a state machine whose transition token is undeliverable is not a state machine).**
> A confirmation gate is a *transport* problem before it is a *secret* problem. If the token
> is generated, stored and checked, but **no channel carries it to the party that is supposed
> to present it**, then the gate has exactly one reachable transition for every party that
> did not legitimately receive the token: **guess it**. Every other property of the token —
> length, alphabet, entropy, CSPRNG vs `rand()`, storage, binding, expiry — is then a
> *second-order* property, because the first-order property (reachability of the honest path)
> is already false.
>
> The corollary is the part a tester has to check first, and it is cheap: **for each token the
> lifecycle issues, find the delivery channel in the artefact before you start attacking the
> token.** A grep for the send function answers it in seconds, and its absence reframes the
> entire engagement. Lab 61 and lab 108 both spent their whole budget on a *sink*; here the
> sink is unreachable and the *transition* is the whole lab.

And the general form of the class question — *"does anything check the difference between a
user and a confirmed user?"* — has a three-part answer, and **this lab contains all three
states and enforces only one of them**:

| The three states | Enforced here? | Where |
|---|---|---|
| **a user does not exist** | ✅ **yes** | `UNIQUE KEY username` on `ctf_db.users`; duplicate registration refused in three variants (§10, C2) |
| **a user exists but is not confirmed** | ✅ **yes** | `index.php:11-17` refuses the login with a byte-distinct message (§10, C4) |
| **a confirmation token is bound to the account it confirms** | ❌ **no** | the token is a 10⁴-space value with **no attempt counter, no lockout, no rate limit**, and the only thing that could have bound it to a requester was the fact that nobody can receive it (§4, F1) |

So: **the boundary between "exists" and "confirmed" is drawn, and something does check it — the
`is_verified` gate held against every test I threw at it. What does not exist is a second
boundary, between "the token was *issued*" and "the token was *delivered*", and the absence of
that boundary is what makes the first boundary decorative.** That is the transferable form, and
it is why the finding is filed as a lifecycle defect rather than as a weak-OTP defect: the OTP
is only weak *because* nothing delivers it.

### 0.1 The token-storage question, answered for this corpus's second recurring class

The brief also asked *where does a token live and who can read it*. This lab has **three**
answers, and the third is the sharpest:

| Token | Where it lives | Who can read it | Finding |
|---|---|---|---|
| the 4-digit account-confirmation code | `ctf_db.verifications.code`, **`varchar(4)`, plaintext**, `PRIMARY KEY (username)` | anyone with SQL on `ctf_db` — and the credential that opens it (`ctf_pass`) lives in **`/var/www/html/db.php`, a file in the served document root** | **F2** |
| the WordPress administrator password | `wp_users.user_pass` = a **bare, unsalted, single-round MD5** `49308bda8b5e0ab9688ec4bedf6d572c` — no `$P$`, no `$wp$`, no phpass | anyone who can read the row, at ~3·10⁶ hashes/second on this host | **F3** |
| the WPvivid site API keypair | `wp_options.wpvivid_api_token` — an **RSA private key, base64, in the options table**, and **regenerable by any unauthenticated client** | the web tier; and it is *rotatable* by the whole internet | **F4, F5** |

`db.php` deserves its own line, because it is the cleanest instance of the class in this corpus:

```php
// /var/www/html/db.php:2-6  — mode 0755, owner www-data, INSIDE DocumentRoot /var/www/html
$host = '127.0.0.1';
$db   = 'ctf_db';
$user = 'ctf_user';
$pass = 'ctf_pass';
```

`db.php` executes and returns **0 bytes** (I checked: `GET /db.php` → `200`, `size_download=0`),
so it discloses nothing *on its own*. Its significance is different and is the general rule:

> **Rule (a token store whose credential sits in the served tree is one web primitive away from
> a token disclosure).** I did not need to read `db.php` — I had `docker exec` — but the
> reason I could read `verifications.code` as ground truth at all is that the *intended*
> attacker path to it is: any file-read primitive anywhere in `/var/www/html` (a path
> traversal, an LFI, a mis-scoped `Alias`, a backup under the root) yields the credential,
> and the credential yields **every pending confirmation token for every account, in
> plaintext, in one query**. The 10⁴ brute force in §4 is not even the cheapest read of that
> table; it is the *second* cheapest.

---

## 1. Surface

```
$ nmap -sV -Pn -p- 172.17.0.5
Nmap scan report for 172.17.0.5
Host is up (0.000046s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.14 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.58 ((Ubuntu))
```

**What a TCP scan cannot see — measured, not assumed:**

```
$ docker exec cuentaatras_container cat /proc/net/udp
  sl  local_address rem_address st ... uid ...
  (header only — no rows)
$ docker exec cuentaatras_container cat /proc/net/udp6
  (header only — no rows)
$ docker inspect cuentaatras:latest -f '{{json .Config.ExposedPorts}}'  -> null
```

Zero UDP rows on both tables, so unlike lab 65 and lab 295 the `-p-` blind spot is empty here.
`ss -lntup` agrees and adds the two non-remote listeners:

```
tcp LISTEN 0 511   0.0.0.0:80        users:(("apache2",pid=33,fd=3))
tcp LISTEN 0 128   0.0.0.0:22        users:(("sshd",pid=15,fd=3))
tcp LISTEN 0 80    127.0.0.1:3306                          <- mariadbd, loopback-only
```

### 1.1 Two applications on one origin, and the second one is the secret

`/var/www/html` is **not** a WordPress install. It is a 6-file PHP application, and WordPress
is moved *underneath it* at a randomised path. This is the shape neither lab 61 nor lab 108
had, and it is why recon has to enumerate the root before it enumerates anything else:

| Path | Status / bytes | What it is |
|---|---|---|
| `/` | 200, 503 B | `index.php` — the login form |
| `/register.php` | 200, 734 B | **open registration** — the lifecycle's first transition |
| `/verify.php` | 200, ~960 B | the confirmation form; **302 → `register.php` without `$_SESSION['verify_user']`** |
| `/dashboard.php` | **302 → `index.php`** unauthenticated | the only page that prints the secret path |
| `/logout.php` | 302 | `session_destroy()` |
| `/db.php` | **200, 0 bytes** | the database credential, inside the document root (F2) |
| `/copy2321_.php` | 200 | **not PHP** — a raw captured HTTP request, left in the tree (§7, D8) |
| `/style.css` | 200 | 623 B, the only static asset |
| `/secret_portal_65hBlEo9OU/` | 200, 66138 B | WordPress 6.9.1 — **undiscoverable without `dashboard.php`** |

**The trípleta, applied to the one surface that matters:**

1. **Reachable** — `GET /secret_portal_65hBlEo9OU/` returns `200`, 66138 bytes.
2. **What the body carries** — `<title>Portal Corporativo</title>`, a WordPress 6.9.1 install,
   `wpvivid-backuprestore` active, one administrator `admin_master`.
3. **Decisive** — the path is a *string in a file*, `/etc/wp_secret_path`, mode
   `0644 root:root`, content `/secret_portal_65hBlEo9OU`, and `dashboard.php:4` prints it to
   any authenticated session. **A wordlist would never have found this path** (18 chars,
   mixed case, mixed alphabet, no dictionary word). The only route to it is the account
   lifecycle. That is the lab's design in one sentence.

### 1.2 Where the platform *is*, and what it exposes

```
$ for p in "" wp-login.php wp-admin/ "index.php?rest_route=/wp/v2/users" xmlrpc.php \
           generate_key.php generate_migration_key.php wp-json/ readme.html; do ... done
                                200 66138
wp-login.php                     200  4985
wp-admin/                        302     0
index.php?rest_route=/wp/v2/users 200   847
xmlrpc.php                       405    42
generate_key.php                 200    55     <- F5: unauthenticated keypair rotation
generate_migration_key.php       500  2653
wp-json/                         404   272     <- permalinks off; ?rest_route= is the live API
readme.html                      200  7425
```

Note the same trap lab 61 documented (`/wp-json/` → 404 here rather than 500) — the pretty REST
root does not exist because permalinks are off, and `?rest_route=/wp/v2/users` answers `200`
with the user list. I did not enumerate the REST surface further: `users_can_register=0`, one
administrator, and nothing in the plugin registers a REST route (`grep -rn register_rest_route`
over the plugin → **zero hits**).

---

## 2. The class

**Entry criterion:** *for each transition in the account lifecycle, find the token that
guards it and then find the channel that delivers it. Where the channel does not exist, the
transition is unguarded no matter how good the token looks.*

**Source that settled it:** `register.php` read in full, plus one `grep` for the send function
that returned nothing (§0). I did not fuzz anything first. Concretely, the four files that
matter are 5.7 KB of PHP total, and they answer every question in the class:

```
index.php     1348 B   login + the is_verified gate
register.php  1862 B   the INSERT, the token mint, the session write
verify.php    2426 B   the token compare, the expiry DELETE, the is_verified UPDATE
db.php         428 B   the credential, in the document root
```

**What they write, and what they send — the complete inventory:**

| Transition | Table / column written | Column read to gate it | Delivered to the user? |
|---|---|---|---|
| register | `users` (name, username, password, email, phone); `is_verified` left at its **default 0** | — | — |
| token mint | `verifications` (username, code, **plaintext**, expires_at = now+300) | — | **nothing — no transport exists** |
| confirm | `users.is_verified = 1`; `verifications` row deleted | `$_SESSION['verify_user']` **and** `$_POST['code']` | — |
| expiry cleanup | **`DELETE FROM users WHERE username = ?`** + `DELETE FROM verifications` | `time() > expires_at` | — |
| login | `$_SESSION['user']` | `password_verify()` **and** `$user['is_verified']` | — |

**The `email` and `phone` columns are collected, stored, and never read again.** `grep` proves
it: the only occurrences of `email` in the six files are the `INSERT` at `register.php:7,11`
and the `<input type="email">` at `register.php:35`. There is no email-verification step at
all — not a weak one, **not one**. And `users.email` has **no UNIQUE key** (F6).

---

## 3. The chain

Reproduced end to end on the **restored, shipped** container (§9). No client follows
redirects; each hop is asserted on its `Location` header.

```
$ U=demo$(date +%s)
$ curl -sS -D - -o /dev/null -c jar -X POST http://172.17.0.5/register.php \
    --data-urlencode "name=Demo" --data-urlencode "username=$U" \
    --data-urlencode "password=Passw0rd!220" --data-urlencode "email=$U@example.invalid" \
    --data-urlencode "phone=+34600000000"
HTTP/1.1 302 Found
Set-Cookie: PHPSESSID=jnqme978a8fegph9l0f4vd7m4q; path=/
Location: verify.php
```

```
$ python3 otp.py jar                       # the code is NEVER read from the database
SID=jnqme978a8fegph9l0f4vd7m4q
SESSION_LIVENESS status=200 timeLeft=300 bytes=960
WORK: attempts=3015 space=10000 elapsed=0.9s rate=3529/s
FOUND code=6994 status=302 location=index.php?msg=Registrado correctamente. Por favor inicia sesiÃ³n.
```

```
$ curl -sS -D - -o /dev/null -b jar -c jar -X POST http://172.17.0.5/index.php \
    --data-urlencode "username=$U" --data-urlencode "password=Passw0rd!220"
HTTP/1.1 302 Found
Location: dashboard.php

$ curl -sS -b jar -c jar http://172.17.0.5/dashboard.php
status=200 bytes=704
body contains: "migrado a una ruta segura secreta"  and  "/secret_portal_65hBlEo9OU"
```

```
$ docker exec cuentaatras_container mysql -u root -N -B ctf_db -e \
    "select username,is_verified from users; select count(*) from verifications;"
demo1790746303	1        <- the transition is committed
0                      <- and the token is consumed
```

| # | → | Mechanism | Identity proof |
|---|---|---|---|
| 1 | unauth | full TCP scan; `/proc/net/udp{,6}` empty | 65533 closed; **0** UDP rows on both tables |
| 2 | unauth | `POST /register.php` — open registration, `is_verified` defaults to 0 | `302 → verify.php`, `Set-Cookie: PHPSESSID=…`; `users` row with `is_verified=0` |
| 3 | unauth | **3 015 of 10 000 guesses** against a 4-digit token with no attempt counter | `302 → index.php?msg=Registrado correctamente…`; `is_verified=1` committed; token row deleted |
| 4 | unauth (session) | `POST /index.php` — the `is_verified` gate **passes** legitimately now | `302 → dashboard.php` |
| 5 | auth `uid=33` | `dashboard.php:4` reads `/etc/wp_secret_path` and `:13` prints it | Apache child `Uid: 33 33 33 33` — real **and** effective **and** fs = 33 (§6) |
| 6 | auth `uid=33` | WordPress 6.9.1 + `wpvivid-backuprestore` at the disclosed path | front page `200`, 66138 B; `?rest_route=/wp/v2/users` `200` |
| 7 | **blocked** | `wpvivid`'s unauthenticated `send_to_site` file-write primitive | its only gate is the RSA key in `wp_options`, which I could not obtain (§9) |
| 8 | **blocked** | `webmaster → sudo /usr/bin/tar → root` | the rung **works** (`sudo -u webmaster sudo -n tar --version` → `tar (GNU tar) 1.35`) and is **unreachable**: `sudo -l -U www-data` → *not allowed*; `find / -xdev -user webmaster` → **0 files** |

**The execution identity at every hop, as a `uid`/`euid` pair** (the RUNBOOK's rule 1):

```
pid=33   /usr/sbin/apache2-kstart   Uid:  0  0  0  0     <- apache master, real=euid=0
pid=38…42,534                     Uid: 33 33 33 33     <- the workers that execute every PHP request
pid=199  /usr/sbin/mariadbd        Uid: 103 103 103 103  Gid: 104 104 104 104
pid=72   /usr/bin/mariadbd-safe    Uid:  0  0  0  0     <- the wrapper, not the server
```

`pid 534` was the live child serving my request. **There is no privilege delta anywhere in the
web surface**: real = effective = saved = fs = 33. Every hop above is `uid=33(www-data)`.
This is the measurement that bounds the whole engagement, and it is why §8's conclusion is a
measurement rather than an opinion.

---

## 4. Findings

### F1 — The account-confirmation gate is not a gate: a 4-digit token, never delivered, checked with no attempt counter and no rate limit
**CWE-799 (improper control of interaction frequency) + CWE-330 (use of insufficiently random
values) + CWE-307 (improper restriction of excessive authentication attempts) · High**

Three independent conditions, each measured, each sufficient on its own to make the transition
forgeable, and together they are the lab:

**(a) The token is never delivered — there is no transport in the lab.**

```php
// register.php:13-17  — the entire "send" step
$code = str_pad(rand(0, 9999), 4, '0', STR_PAD_LEFT);
$expires = time() + 300; // 5 minutes
$stmt = $pdo->prepare('INSERT INTO verifications (username, code, expires_at) VALUES (?,?,?) ON DUPLICATE KEY UPDATE code=?, expires_at=?');
$stmt->execute([$username, $code, $expires, $code, $expires]);
```

`rand()`, `str_pad`, an INSERT. Then `register.php:19-21`: `$_SESSION['verify_user'] =
$username; header('Location: verify.php');`. The UI promises an SMS at `verify.php:53`
(*"Hemos enviado un código SMS de 4 dígitos a tu móvil registrado"*). §0 carries the grep that
proves no send function, no MTA and no spool exist. **The honest path is unreachable, so the
only remaining path is the guess.**

**(b) The token space is 10 000 and the generator is `rand()`, not `random_int()`.**

**(c) The comparison has no attempt counter, no lockout, no per-account or per-IP budget, and
no delay.** `verify.php:24` is the whole check:

```php
if (isset($_POST['code']) && $_POST['code'] === $verification['code']) { … }
```

Measured: **3 015 of 10 000 attempts in 0.9 s at 3 529 attempts/second**, ten concurrent
connections, zero throttling observed, and the 5-minute window is an inconvenience, not a
control. Three independent runs of the same exploit found the code at attempts 4 160, 3 015 and
(control) 1.

**Positive control first, as required for a state machine.** Before claiming any transition was
bypassed, I showed it succeeding for a legitimate path, on a fresh account, with the code read
from the artefact rather than guessed:

```
POSITIVE_CONTROL code=0267 -> status=302 location=index.php?msg=Registrado correctamente…
DB: username=pctl1790745615  is_verified=1   token row deleted
```

**The negative is proven too**, with its work count: eleven wrong codes against a fresh account
whose real code (`7055`) was deliberately withheld — `status=200`, body
`"Código incorrecto. Inténtalo de nuevo."`, and `is_verified` still `0`. So the check *does*
execute and *does* discriminate; the code reached the handler, and the handler simply has no
opinion about how many times it may be asked.

**Impact.** The `is_verified` boundary in `index.php:11-17` — the one control in this lab that
genuinely holds — becomes unconditional, because an unauthenticated client can put itself on
the verified side in under a second. Every downstream grant of a "confirmed" account is
consequently attacker-chosen, including the disclosure of the hidden WordPress path (§3, hop 5),
which is the gate to the entire second half of the lab.

**Remediation.** In order of how much each one is worth:
1. **Deliver the token, or do not gate on it.** A confirmation gate nobody can satisfy is a
   denial of service wearing a security control. If SMS is not available, fail the
   registration closed and say so — do not mint a token into a table and hope.
2. Replace `rand(0,9999)` with `random_int(0, 9999)` and, better, with a token of ≥ 128 bits:
   `bin2hex(random_bytes(16))`. A 4-digit code is a *second* factor, not an identity proof.
3. **Enforce the attempt budget in the datastore, not in the request.** There is no counter
   column in `verifications` — that is the root cause. Add `attempts`, `locked_until`, and a
   hard invalidation at N; delete the row on success as you already do.
4. Rate-limit `verify.php` per account and per source, and make the failure path constant-time
   and constant-body so it is not an oracle for a *valid* account.

### F2 — The confirmation token is stored in plaintext, keyed only by a client-supplied username, and the credential that reads it is inside the served document root
**CWE-256 (plaintext storage of a password) / CWE-312 / CWE-522 · High**

```sql
CREATE TABLE `verifications` (
  `username` varchar(50) NOT NULL,
  `code` varchar(4) DEFAULT NULL,      -- plaintext, 4 chars, the whole secret
  `expires_at` int(11) DEFAULT NULL,
  PRIMARY KEY (`username`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
```

```php
// /var/www/html/db.php:2-6 — mode 0755 www-data, DocumentRoot /var/www/html
$db = 'ctf_db'; $user = 'ctf_user'; $pass = 'ctf_pass';
```

Three separate defects, filed as one because they compose and each is independently wrong:

1. **Plaintext token in the database.** No hash, no HMAC, no per-token salt. There is nothing
   to steal *slowly*; a single `SELECT username, code FROM verifications` hands over every
   pending account confirmation in the installation, simultaneously, for every account, with
   zero cracking.
2. **The key is a client-supplied string, not an account identifier.** `PRIMARY KEY (username)`,
   and `username` is `$_POST['username']` verbatim. There is no foreign key to `users.id`, no
   binding to the `email` or `phone` that were collected alongside, and no binding to the
   session that requested it beyond `register.php:19` — which is a convenience, not a control
   (see §7, D4, for the one way I tried to break that binding and failed).
3. **The credential is in the served tree.** `GET /db.php` returns `200` with **0 bytes** — PHP
   executes it — so nothing leaks by fetching it. But the *distance* between "an arbitrary local
   file read in `/var/www/html`" and "every pending account token in the installation" is one
   `require`.

**Impact.** Any file-read primitive anywhere under `/var/www/html` — a traversal, an LFI, a
mis-scoped Apache `Alias` (lab 61 found `phpMyAdmin` exposed exactly this way), a stray backup
archive, a `.bak` of a config — becomes **mass account confirmation**, with no cracking and no
per-account effort. It is also the reason the brute force in F1 is not the cheapest attack: the
table can simply be read.

**Remediation.** Store `hash_hmac('sha256', $code, $per_account_salt)` and compare with
`hash_equals()`; key the row on `users.id` with a real foreign key; keep the token lifecycle
(outstanding → consumed → expired) in one place; and move `db.php` out of the document root
entirely — `chmod 640` and a path above `/var/www/html` is the minimum, and it should not be in
the tree at all.

### F3 — The WordPress administrator password is stored as a bare, unsalted, single-round MD5
**CWE-328 (use of weak hash) / CWE-916 (password hash with insufficient computational effort) · High**

```
$ mysql -u root -N -B wp_db -e "select ID,user_login,user_pass,user_email from wp_users"
1  admin_master  49308bda8b5e0ab9688ec4bedf6d572c  admin@example.local
```

**32 hex characters. No `$P$`, no `$wp$`, no phpass, no bcrypt, no salt, no rounds.** This is
not what `wp_hash_password()` produces and it is not what `wp_check_password()` expects to
verify — a WordPress install that stores this has had its credential column written by
something other than core (here: a setup script run at `2026-03-01 15:09:33`, ninety seconds
after the web server came up).

**Impact.** The entire administrator credential is recoverable **offline and instantly** by
anyone who can read one row: an unsalted MD5 runs at ~3·10⁶ candidates/second on one core of
this analysis host. There is no work factor at all. This is the credential that guards the
second half of the lab, and it is stored in the weakest form the platform can be made to store
anything in.

**I did not recover the plaintext**, and the negative carries its work count (§11, D2):
**483 466 186 candidates** hashed, 0 hits — all numerics `0 … 10⁸`, all lowercase-alphabetic
strings of length ≤ 6, all lowercase-alphanumeric of length ≤ 5, plus 540 952 lines from the
two wordlists on this host, plus a 4 062-candidate lab-themed set with 18 mutation rules. The
positive control passed first (my `md5()` byte-matched `openssl dgst -md5` on a
self-chosen string), so this is a real negative and not an untested one. **It is a limit of the
tooling available on this host, not evidence that the password is strong** — see §10.

**Remediation.** Never write `user_pass` directly. Provision the administrator through
`wp user create --role=administrator` (or `wp_hash_password()`), so the stored value is
phppass/bcrypt with a per-user salt; and add a startup assertion that every `wp_users.user_pass`
matches the expected prefix, because a bare 32-hex value is *mechanically* detectable and this
lab's credential was stored in exactly that shape for exactly this long.

### F4 — WPvivid's site API keypair lives in `wp_options` in plaintext, and it is the sole gate on an unauthenticated file-write primitive
**CWE-312 (cleartext storage of sensitive information) / CWE-922 (insecure storage of credentials) · High**

The plugin stores an **RSA-2048 keypair, base64-encoded, in the options table**, and the
private half is what decrypts every inbound transfer:

```php
// includes/customclass/class-wpvivid-send-to-site.php:596-601  (and :705-716, :952-960)
$option = get_option('wpvivid_api_token', $default);
if (empty($option)) { die(); }
if ($option['expires'] != 0 && $option['expires'] < time()) { die(); }
$crypt = new WPvivid_crypt(base64_decode($option['private_key']));
$body  = base64_decode($_POST['wpvivid_content']);
$data  = $crypt->decrypt_message($body);
```

And the **dispatcher for that primitive has no authorisation at all** — it runs on
`plugins_loaded` for any POST to any page on the site:

```php
// includes/customclass/class-wpvivid-send-to-site.php:37-62
public function plugins_loaded() {
    if (!empty($_POST) && isset($_POST['wpvivid_action'])) {
        if      ($_POST['wpvivid_action']=='send_to_site_connect') { $this->send_to_site_connect(); }
        else if ($_POST['wpvivid_action']=='send_to_site_finish')  { $this->send_to_site_finish(); }
        else if ($_POST['wpvivid_action']=='send_to_site')         { $this->send_to_site(); }
        else if ($_POST['wpvivid_action']=='send_to_site_file_status') { $this->send_to_site_file_status(); }
        else if ($_POST['wpvivid_action']=='clear_backup_cache')   { $this->clear_backup_cache(); }
        die();
    }
}
```

No `current_user_can`, no nonce, no `check_ajax_referer`, no rate limit. `send_to_site()`
then writes attacker-chosen bytes at an attacker-chosen `$params['offset']` into
`WP_CONTENT_DIR/<backupdir>/<$params['name']>` — and `wp-content/uploads` is executable
here, so a `.php` `name` is code execution as `www-data`.

**The design error is that the only thing standing between the open door and the file write is
a secret that is (i) stored in plaintext in the database, (ii) used as a *shared* symmetric
envelope key for an *asymmetric* channel, and (iii) rotatable by anyone (F5).** No
authentication, no replay window, no per-request nonce, no origin binding, no rate limit on
failed decryptions — a ciphertext oracle with no throttle.

**Impact.** Anyone who obtains the keypair — by F3, by any SQL read, by any file read of
`wp_options`, or by the migration-URL disclosure in F6 — writes arbitrary bytes anywhere under
`wp-content` as an unauthenticated client, and the tree executes them. The lab's own build-time
access log shows the author walking straight into this door and probing
`wp-content/uploads/*.php?cmd=id` (§7, D7).

**Remediation.** The dispatcher must require `current_user_can('manage_options')` and a
`check_ajax_referer()`; the transfer envelope needs a per-transfer nonce, a recipient-bound
timestamp and a single-use record, so a captured ciphertext cannot be replayed; and the
asymmetric key must never be used as a bulk symmetric envelope key.

### F5 — `generate_key.php` lets any unauthenticated client rotate the site's API keypair
**CWE-306 (missing authentication for critical function) / CWE-652 · Medium–High**

```php
// /var/www/html/secret_portal_65hBlEo9OU/generate_key.php:1-14  — mode 0644 root:root, in the docroot
require_once("wp-load.php");
include_once WPVIVID_PLUGIN_DIR . '/vendor/autoload.php';
$rsa = new Crypt_RSA();
$keys = $rsa->createKey(2048);
$options['public_key']  = base64_encode($keys['publickey']);
$options['private_key'] = base64_encode($keys['privatekey']);
$options['expires'] = time() + 86400;
$options['domain']   = home_url();
update_option('wpvivid_api_token', $options);
echo "Token generado y guardado en wp_options correctamente.\n";
```

**Proven by the artefact, not by the status code.** One anonymous `GET`, and the stored option
changes:

```
BEFORE md5(option_value) = ae86ba2e209553adaa280eb777afa9f3
$ curl -sS -i http://172.17.0.5/secret_portal_65hBlEo9OU/generate_key.php
HTTP/1.1 200 OK
Content-Length: 55
Token generado y guardado en wp_options correctamente.
AFTER  md5(option_value) = 2bcb520bc14d8989133116bd7778c294
$ …decode the new value…
public_key  -> -----BEGIN PUBLIC KEY-----
private_key -> -----BEGIN RSA PRIVATE KEY-----
```

And after `docker rm -f` + `docker run` from the image, the **shipped** value hashes to
`4c180c17019efed1ea607839d67b418b` — a **third** distinct value, which is the cleanest possible
demonstration that the rotation happened and was undone by the restore.

**Impact.** Two things, and the first is the finding rather than the second:
1. **Unauthenticated destructive write to a security-critical option.** Any anonymous client
   can permanently invalidate the site's configured remote backup/migration peer, and there is
   no recovery path short of an administrator. That is a denial of service on a data-protection
   feature, from a URL that ships in the image.
2. **A rotate primitive with no read primitive is still a read primitive for whoever rotates
   last.** An attacker who can reach the database — by F3 or F2 — rotates the key and then
   owns a keypair the legitimate operator has never seen, which is the precondition for F4.
   The reverse ordering is the danger: the *last* writer of `wpvivid_api_token` is the only
   party who can use the write primitive.

**Remediation.** Delete `generate_key.php` from the shipped image — it is a setup script that
was never meant to be web-reachable, and it has no authentication of any kind. Key management
belongs in a CLI-only path (`wp-cli` over a real shell) or in a settings screen behind
`manage_options` and a nonce, with the previous key retained and honoured until its own
expiry. `generate_migration_key.php` (500, `WPvivid_Crypt class not found`) is the same class
of leftover and should go with it.

### F6 — The account's email address is collected, never verified, never used, and is not a key
**CWE-620 (unverified password change) → CWE-287 (improper authentication) · Medium**

`register.php` takes an `email` and a `phone` and stores both. **No code anywhere reads them
again**, and there is no email-confirmation step of any kind — the lifecycle jumps straight
from "row exists" to "SMS code matched", skipping the ownership proof that the `email` field
exists to provide. Meanwhile `users` has a UNIQUE key on `username` and **none on `email`**:

```
$ register e1<t> with email shared-<t>@example.invalid  -> 302 verify.php
$ register e2<t> with the SAME email                    -> 302 verify.php
$ select group_concat(username) from users where email='shared-<t>@example.invalid'
e1<t>,e2<t>            <- two accounts, one address, no complaint
```

Contrast that with `username`, which *is* a key and which the application defends properly in
all three spellings (§10, C2). **So the identifier the application chose to enforce is the one
the user invents, and the identifier it chose to trust is the one it never checks.** That
inversion is the finding; the missing unique index is a consequence.

**Impact.** No direct takeover — nothing in the app acts on the email. The impact is
compositional and it is the reason the account list here is worthless as an attribution
boundary: the address a person is expected to prove ownership of is decorative, so two accounts
can present the same claimed identity, and any *future* feature that trusts it (password reset,
notifications, account recovery, an audit trail) inherits an unauthenticated assumption. Note
the WordPress half of the lab has the same shape for the same reason: `admin@example.local` is
unroutable, and there is no mailer, so WordPress's own `lostpassword` and `confirm_admin_email`
transitions **generate keys that cannot be delivered either** — the same defect, in the
platform's own account lifecycle, for the same reason.

**Remediation.** Either verify the address (send a link, store its state, and gate the
"confirmed" transition on it) or stop collecting it. Add `UNIQUE` on a normalised address, and
treat "an address already on file" as a *distinct* outcome from "a username already on file" —
the two need different messages for different reasons, and collapsing them into one
`PDOException` (`register.php:22-24`) is why neither one gets a correct answer.

### F7 — `verify.php`'s expiry path deletes the account row, keyed on a session-supplied username
**CWE-613 (insufficient session expiration) / CWE-20 (improper input validation) · Low–Medium, and it is a design smell worth naming**

```php
// verify.php:15-20
if (!$verification || time() > $verification['expires_at']) {
    $pdo->prepare('DELETE FROM users WHERE username = ?')->execute([$username]);
    $pdo->prepare('DELETE FROM verifications WHERE username = ?')->execute([$username]);
    unset($_SESSION['verify_user']);
    die("…El código SMS ha expirado. Tu cuenta temporal ha sido eliminada.…");
}
```

The `!$verification` branch means: **any request that reaches `verify.php` with a
`$_SESSION['verify_user']` naming an account that has no outstanding token deletes that
account.** The username comes from the session, and the session's only gate is that
`register.php` set it — so today the blast radius is "accounts you registered yourself",
because `ctf_db` ships empty. I did **not** demonstrate cross-account deletion (§11, D3), and
I am not claiming it. What makes it a finding rather than a note is the shape: a
*read-path* branch performing an unconditional **`DELETE`**, with the same `$username` string
that the whole lifecycle keys on, and with the error text advertising the deletion to whoever
triggered it.

**Remediation.** Garbage-collect abandoned registrations with a scheduled job keyed on
`users.created_at < now() - interval`, not from a request handler. A cleanup path should not be
reachable by naming a row, and it should never be the same code path that renders a message.

### F8 — Reflected XSS in the login page's `msg` parameter, correctly encoded, correctly reported
**CWE-79 · Low (reported because the corpus asked, and because the encoding is the point)**

```php
// index.php:26
<?php if(isset($_GET['msg'])) echo "<p style='color:green'>" . htmlspecialchars($_GET['msg']) . "</p>"; ?>
```

`htmlspecialchars()` with no `ENT_QUOTES` and no `charset` — the two omissions that matter in
modern PHP are irrelevant here because the element is an HTML text node. I verified the
encoding works: the reflection is inert. This is filed **Low** and explicitly **not** chained,
because there is no victim in a lab and the skill's own output contract asks for a separate
`unverified_leads[]` rather than an inflated severity. It is worth one line here for a different
reason: the *other* echo on the same page interpolates a variable (`index.php:27`,
`echo "<p style='color:red'>$error</p>"`) without `htmlspecialchars()`. That one is
server-generated and I could not reach it with attacker bytes — but it is the line that will
become exploitable the first time anyone puts a request value into `$error`, and the encoding
discipline of `:26` will not be copied there automatically.

---

## 5. The WordPress half: what is there, and what the artefacts say about it

| Component | Value | Sources that agree |
|---|---|---|
| WordPress core | **6.9.1** | `wp-includes/version.php:19` read from the **image** with `--entrypoint sh`; the running container; `readme.html` |
| Plugin | `wpvivid-backuprestore` **0.9.123** | `wpvivid-backuprestore.php` header; `readme.txt` `Stable tag: 0.9.123`; `wp_options.active_plugins` |
| Other plugins | `akismet`, `hello.php` — **present, not active** | `active_plugins` holds exactly one entry |
| Theme | `twentytwentyfive` active (three present) | `wp_options.template` / `stylesheet` |
| Users | **one**: `admin_master` / `admin@example.local`, `wp_capabilities = a:1:{s:13:"administrator";b:1;}` | `wp_users` + `wp_usermeta` |
| `users_can_register` | `0` | `wp_options` — **the custom app is the only registration path in the lab** |
| DB | `wp_db` / `wp_user`, `127.0.0.1` | `wp-config.php` |
| Salts | all eight = `'put your unique phrase here'` | `wp-config.php:10-17` — **discarded by core**, see C7 |

**The version did not move under me, and the reason is worth one line** because lab 108 lost
its headline to it. I pinned `6.9.1` from the image *before* the first request
(`docker run --rm --entrypoint sh cuentaatras:latest -c 'grep -n "wp_version =" …'`) and
re-read it from the live container after the engagement: `6.9.1` both times. This image sets no
`AUTOMATIC_UPDATER_DISABLED` and the container **does** have egress, so the exposure is the same
as lab 108's — it simply did not fire, because `wp-cron.php` only runs on a front-end request
and this WordPress has 1 post and no traffic. **Treat that as "has not happened yet", not as
"cannot happen".** A re-run with any traffic at all may pin a different number.

**`siteurl` points at an address that is not this container** (F9 below), which is the shipped
form of lab 108's `WP_HOME` trap and it has a concrete consequence: core's fatal-error loopback
(`wp-admin/plugin-editor.php` / `theme-editor.php`, which write, re-request the file over HTTP
and **revert on failure**) cannot complete, so **the plugin and theme editors are inert here and
return HTTP 200 while silently reverting** — lab 61's F1 verbatim. I did not exercise the
editors, so this is read from the configuration and reported as such, not as a measurement.

---

## 6. Controls that held

Every row has a positive control: a case where the same detector was **shown firing**.

| # | Control | Positive control that proves this detector works | Negative evidence, with work count |
|---|---|---|---|
| C1 | The `is_verified` gate refuses an unconfirmed account | a **guessed-correct** code → `302 → index.php?msg=Registrado correctamente…` and `is_verified=1` — the transition really does commit | right password + `is_verified=0` → `200`, no `Location`, body `"Cuenta no verificada. Por favor, regístrate de nuevo y completa la verificación SMS."`; a wrong password → `200` + `"Credenciales incorrectas."` Two byte-distinct failures |
| C2 | `username` is a real key; the token cannot be stolen by re-registration | a *different* username with the same address → `302 verify.php` (accepted), so the check discriminates | the same username three ways — identical, `UPPERCASE` (the column is `utf8mb4_general_ci`), and with a **trailing space** (MySQL VARCHAR comparison) — all three → `200` + `"El usuario ya existe o hubo un error."`, and `count(*) from verifications` for that username stayed at **1**. 3 tests |
| C3 | `verify.php` requires a session | a correct code **with** the session → `302 → index.php?msg=…` | a correct code **without** the cookie → `302 → register.php`, and the DB row was untouched (`is_verified=0`, token still present). The two outcomes are byte-distinguishable *because the Location differs* — which is the whole reason the account-lifecycle flow needs raw hop capture |
| C4 | The session liveness probe is a real probe | `GET /verify.php` with the session → `200`, `timeLeft = 300` parsed out of the body | the same GET without the cookie → `302 → register.php`, 0 bytes. The probe **asserts on a value read back from the response**, so a dead probe cannot masquerade as a live one |
| C5 | WPvivid's AJAX surface is authorised | a **real** nopriv action with the *same wrong* nonce — `action=heartbeat` → `200`, 48 B, `{"wp-auth-check":false,…}` (`md5=69adb6329ae8`). A wrong nonce is therefore **not** what produces the refusal | 4 actions × 2 variants (no nonce / forged user-0 nonce) — `wpvivid_get_setting`, `wpvivid_get_general_setting`, `wpvivid_export_setting`, `wpvivid_download_backup` — **all eight** returned `400`, **1 byte**, body `0`, `md5=cfcd208495d5`, **byte-identical**. 8 tests + 4 controls |
| C6 | The `send_to_site` write primitive is not open | the `plugins_loaded` dispatcher is reached by *any* POST with `wpvivid_action` set — I confirmed the code path exists and that the lab author's own build-time log drives it | the write itself is gated on `get_option('wpvivid_api_token')` being non-empty and unexpired (`send-to-site.php:597-601`), and the key exists only in `wp_options`, which I could not read. **The gate held against me.** Not tested: whether a forged ciphertext is accepted once the key is known (§11) |
| C7 | The salt trap still holds (labs 61/108 §C12, §3.3) | `wp-config.php:10-17` are all `'put your unique phrase here'` | core discards the placeholder and uses `wp_options` (`pluggable.php:2614/2638`); I did not attempt a forgery and **do not claim** these cookies are forgeable |
| C8 | The `wp_ajax_nopriv_*` restore endpoints are not a bypass | — | four handlers are registered for logged-out clients (`class-wpvivid-restore2.php:21-31`: `wpvivid_do_restore_2`, `wpvivid_get_restore_progress_2`, `wpvivid_finish_restore_2`, `wpvivid_restore_failed_2`) but each body opens with `check_ajax_referer('wpvivid_ajax','nonce')` **and** `current_user_can('manage_options')` — e.g. `do_restore()` at `:604-611`. Registration order in the constructor is a decoy; the body is the control |
| C9 | The privilege ladder is *capability*-sound, and that is not the same as reachable | `sudo -u webmaster sudo -n /usr/bin/tar --version` → `tar (GNU tar) 1.35`. **The rung works.** | `sudo -l -U www-data` → *"not allowed to run sudo"*; likewise for `ethan` and `bond`. `find / -xdev -user webmaster` → **0 files**. So unlike lab 61's F5 (a ladder with a missing first rung), this ladder is intact and has **no first rung at all** |
| C10 | The web surface has no privilege delta | Apache children: `Uid: 33 33 33 33` — real **and** effective **and** saved **and** fs all 33 | the master is `Uid: 0 0 0 0` (pid 33), which is why `docker exec` measurements are privileged instrumentation and are labelled as such everywhere in this writeup |
| C11 | No reward is reachable from the web identity | `cat /root/root.txt` as uid 33 → `Permission denied`; as uid 1001 → `Permission denied` (`/root` is `0700`) | `cat /home/bond/user.txt` as uid 1003 (`bond`) → the flag; as uid 1002 (`ethan`) → `Permission denied`. The `0700` and the `0750` are the controls, and both were **fired** |

---

## 7. Instrumentation defects

Seven. None is a defect in the target; all are defects in how I measured it, and **three of
them nearly became findings**. Read against the 19-entry catalogue in
[`method/self-corrections.md`](../../method/self-corrections.md) — this is the first corpus entry
to hit #1 (redirect-following) on a state machine and the first to hit #9
(`permission_callback`-before-argument-validation) in its **admin-ajax** rather than its REST
incarnation.

**7.1 A `400` from `admin-ajax.php` is the AJAX twin of `rest_missing_callback_param`, and it
told me nothing for four actions.** Catalogue #9 says WordPress validates required parameters
*before* `permission_callback`, so a 400 is evidence of a missing argument and never of a
reachable route. The same ordering exists in `admin-ajax.php`: `check_ajax_referer()` runs
first, so **every** refusal looks identical. My first pass recorded "4 wpvivid actions refused
unauthenticated" from the status code alone, which was a guess dressed as a measurement. The
discriminator is the **body**, and it needed a control that a wrong nonce does *not* produce:

```
wpvivid_get_setting      no nonce      400  1 B  md5=cfcd208495d5
wpvivid_get_setting      forged nonce  400  1 B  md5=cfcd208495d5     <- identical
wpvivid_get_setting      heartbeat     200 48 B  md5=69adb6329ae8     <- the control
```

*Rule: for an authorisation test on `admin-ajax.php`, the status code is not a verdict. Run a
real nopriv action with the same bad credential first; if it does not return the same bytes,
your detector works and the refusal is real.*

**7.2 `curl -b jar` without `-c jar` — the brief's own warning, and it cost me one false
negative shaped exactly like a failed exploit.** My positive control for F1 returned
`302 → register.php` with a **new** `Set-Cookie: PHPSESSID=…` and the account still
`is_verified=0`. The status code is the *same* one the session-missing case returns, so a
status-only read would have filed "the confirmation flow is broken". What saved it was that I
checked the **artefact** (`is_verified` in the table) rather than the status — and the artefact
said the transition had not happened, so the instrument was the suspect. Both `-b` alone and
`-b` + `-c` were then run against a fresh account and **both** produced the correct
`302 → index.php?msg=…` (C1), which located the fault in the earlier call, not in the server.
*Rule: on a state machine, the status code of a transition is not its outcome. The committed
state is.*

**7.3 The state file I used to name a variable did not set it — and the failure was silent and
plausible.** I wrote `echo "user=$U" > vars.env` in one shell and `source vars.env` in the next,
expecting `$U`; I got an empty `$U`, an empty jar name, no cookie, and a `302 → register.php`
that read exactly like the server refusing the session. Two different defects (the missing `-c`,
and this) produced **one** indistinguishable symptom, which is the real lesson: a
cross-invocation shell variable is an instrument with no work count. Caught by asserting
`SID=<non-empty>` and exiting the harness when the jar had no `PHPSESSID` — after which the
harness refused to run rather than report a zero. *Rule: a harness that cannot find its own
credential must abort, not proceed; "untested" and "refused" are the only two honest outcomes.*

**7.4 My own recon sweep destroyed the evidence for the finding it discovered.**
`generate_key.php` is a `GET`. My unauthenticated surface sweep (§1.2) hit it before I knew it
was state-changing, and it had already rotated `wpvivid_api_token` to `ae86ba2e…` before I took
the "before" reading. F5 would have been unprovable as written if I had not had a third data
point: the restore from the image produced `4c180c17…`, so the shipped value, my recon's value
and my deliberate test's value (`2bcb520b…`) are **three distinct hashes** and the rotation is
demonstrated without needing the original. I got lucky. *Rule: a recon sweep over a list of
paths is a set of state-changing requests until proven otherwise — `HEAD` first, or read the
handler before requesting it. This is lab 61's §13.2 lesson arriving through a different door:
the status code of my sweep was `200` and it changed the target.*

**7.5 `php -i` on the CLI reported the session configuration, and I nearly filed it as the
Apache configuration.** `session.upload_progress.enabled => On`, `cleanup => On`,
`session.use_strict_mode => Off`, `save_path => /var/lib/php/sessions` — all read from
`php -i` **on the command line**. The Apache SAPI reads
`/etc/php/8.3/apache2/php.ini`, which is a different file. I re-read all four values from the
Apache SAPI before relying on them (§11, D3), and the one that decided the outcome —
`upload_progress.cleanup` — had to be confirmed there.

**7.6 `cat`-ing "the entrypoint" printed 4.4 MB of `wp-cli.phar` into my transcript.** I ran
`cat /usr/local/bin/*` while looking for the image's start script, and the wrapper
(`#!/usr/bin/env php` + `Phar::mapPhar()`) is a PHP **phar**, so `cat` produced a wall of
compressed bytes with a few readable strings in it. Nothing was misread, but the tool was the
wrong question: the container's real entrypoint was in the `docker inspect` config and in
`auto_deploy.sh`, both of which I had already read. *Rule: identify a file before you print it
(`file`, `head -c`, first line). `cat` on a binary is not reconnaissance.*

**7.7 The corpus's own warning about a stray HTTP request file applies to this lab's tree.**
`/var/www/html/copy2321_.php` is **not PHP** — it is a raw captured request, 10 lines, with no
`<?php` tag, so Apache serves it as text. It contains
`Cookie: session_id=ZXRoYW46cGZMbVdWejJFR0tHcFJDbUFDVFAK`, which base64-decodes to
`ethan:pfLmWVz2EGKGpRCmACTP` — a name/secret pair for a persona belonging to a *different*
lab in this series (`Host: localhost:8080`, `GET /productos/lista`). I did not use it and did
not attempt it as a credential. It is reported because a file in a document root whose name ends
in `.php` and whose content is not PHP is exactly the artefact a tester will `curl` and then
`source`-interpret, and because the corpus has already been bitten twice by a value that
looked like a token and belonged to nothing here.

**7.8 The build-time access log is the single most useful reconnaissance artefact in this lab,
and it is a liability if you read it as a result.** `/var/log/apache2/access.log` is 33 MB and
144 976 lines, of which ~123 000 predate my engagement (dated `2026-03-01`) and record **the
lab author's own pentest**. It is the reason I know the intended path, and it is also the
reason a careless writeup would report someone else's 404s as my findings. I used it for
exactly three things: (i) confirming that registration + `verify.php` brute force is the
designed route — **17 419 POSTs at build time, ~6 `verify.php` attempts per second at
`15:13:58–15:14:01`**; (ii) confirming the author **never** reached `wp-login.php` with valid
credentials (108 `wp-login` hits, all WPScan, all `200`/2541 B = failed); and (iii) seeing that
the author *also* stalled at the same wpvivid door, probing
`wp-content/uploads/{pwn_remote,exploit,txdiki8k16gp5wjbjcgnu9on}.php?cmd=id` and
`{h18fv3j7ozwe,fthy9ktwkxoh,0ieemgucb6pb}.txt` — **every one a 404**. That is not evidence
about the target; it is evidence about the author's run, and I have kept the two apart
throughout.

---

## 8. Reward

**Two rewards exist in this lab, and neither was obtained by the chain.** Both are reported as
a measured presence with the search that established it, and both are marked with the identity
that can read them.

```
$ grep -rIl -E "DL\{|FLAG\{|flag\{" / --exclude-dir=proc --exclude-dir=sys --exclude-dir=dev
/root/root.txt
/home/bond/user.txt

$ stat -c '%n mode=%a owner=%U(%u)'
/root              mode=700 owner=root(0)
/root/root.txt     mode=600 owner=root(0)        -> DL{U31jcT3PzQGbsni7igEf}   [root only]
/home/bond         mode=750 owner=bond(1003)     [group = bond only]
/home/bond/user.txt mode=644 owner=ethan(1002)   -> DL{oDMEsGfekTxXB2KefL0v}     [bond only]
```

`DL{…}` values are truncated here; the full values are in those two files.

**The inverted ownership is deliberate and is itself worth a line:** `/home/bond/user.txt` is
**owned by `ethan`**, mode `0644`, inside a directory `0750 bond:bond`. So the file's *owner*
cannot read it, the directory's *group* cannot traverse into it, and only `bond` (or root) can.
Anyone reasoning from `ls -l` alone will conclude the wrong thing in both directions.

**Why neither is reachable from the web surface — a measured statement, not an estimate:**

| Requirement | Measured |
|---|---|
| the web tier's identity | `Uid: 33 33 33 33` — `www-data`, no delta (C10) |
| `www-data` can read `/root/root.txt` | `Permission denied` (C11) |
| `www-data` can read `/home/bond/user.txt` | `Permission denied` — `/home/bond` is `0750 bond:bond` (C11) |
| a sudo grant that would change that | `sudo -l -U www-data` → *not allowed*; `-U ethan` → *not allowed*; `-U bond` → *not allowed* (C9) |
| the one sudo grant on the host | `webmaster ALL=(ALL) NOPASSWD: /usr/bin/tar` — **functional** (C9) and **unreachable**: `webmaster` owns **0** files on the filesystem and has **no** `/home/webmaster` |
| a second `sudo` grant | `ubuntu ALL=(ALL:ALL) ALL` — **but** `ubuntu:!` in `/etc/shadow` is a **locked** password, so the account cannot log in at all |
| SSH reachability | `22/tcp` open, `Supported authentication methods: publickey, password`, banner `SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.14` — **no `authorized_keys` exists anywhere on the filesystem** |

**So the reward leg is blocked, and I am reporting it as blocked rather than as a lab defect.**
The escalation that *would* work is fully specified and measured: become `webmaster`, then
`sudo /usr/bin/tar` gives a root write primitive (lab 61's hop 7, same primitive, different
rung), and root reads `/root/root.txt`. **What is missing is a credential**, and the two
candidates are `admin_master`'s (F3: not recovered in 483 466 186 candidates) and a
`webmaster` SSH password (yescrypt, and §10's tooling limit). This is the "an escalation that
did not work is its own finding" case from the RUNBOOK, filed separately, because merging it
with the chain would tell the reader that patching the account lifecycle yields root. **It does
not.** The account lifecycle yields the *path* to WordPress; the WordPress leg is gated on
something the lifecycle does not touch.

**This is the twenty-eighth lab in this series with no `DL{}` obtained by the chain**, and the
first where the reward's existence is unambiguous (two files, both `DL{…}`) while remaining
unreachable from the demonstrated attack surface.

---

## 9. Restore

`docker rm -f cuentaatras_container` then `docker run -d` **from the image**, verified with
**eight positive checks** — each one a value that had to come back, never an absence:

```
1 front page                     : 200  503 bytes
2 wp_version from the image      : 6.9.1          (1 match)
3 ctf_db.users                   : 0 rows         (every account I created is gone)
4 ctf_db.verifications           : 0 rows         (every token is gone)
5 wp_users                       : 1 admin_master 49308bda8b5e0ab9688ec4bedf6d572c
6 portal answers                 : 200 66138 bytes
7 my accounts matching my prefixes: 0 rows
8 wpvivid_api_token              : md5 4c180c17019efed1ea607839d67b418b  <- the SHIPPED value
```

Check 8 is the one that matters: it is the third distinct hash of that option (§7.4), and it
proves the unauthenticated rotation in F5 was undone by recreating the container rather than
by any edit of mine.

**Two session files dated `2026-09-30` remain**, and I am reporting them rather than claiming
zero artefacts: they were created by my own two post-restore verification requests, because
`index.php:2` calls `session_start()` on every page view. The container is freshly created from
the image, so they are the only thing in it I produced, and they are 0-byte `0600 www-data`
files with no content. Everything else in the lab is as shipped.

---

## 10. NOT tested (scope, not gaps in effort)

- **Recovering `admin_master`'s password.** 483 466 186 candidates hashed, 0 hits, positive
  control green (§4, F3). Not attempted: a GPU cracker, a rules-based attack, or a corpus larger
  than the two wordlists on this host. **This is a limit of available tooling and is not
  evidence that the password is strong.**
- **Cracking the `webmaster` / `bond` / `ethan` shadow hashes.** All three are **yescrypt**
  (`$y$j9$…`). This host has **no cracker for it**: Python 3.14 has removed the `crypt` module,
  there is no `mkpasscrypt`, no `passlib`, and `openssl passwd` does not implement yescrypt.
  **Work count: zero candidates tested.** Per rule 14, that is **untested**, and it is listed
  here rather than as a negative.
- **A `webmaster → sudo tar → root` chain.** Never attempted, because webmaster was never
  obtained. The rung's *capability* is proven (C9); its *reachability* is not tested.
- **Exercising `wpvivid`'s unauthenticated `send_to_site` file write.** I did not forge a
  `wpvivid_content` ciphertext, because that requires the site keypair, which lives only in
  `wp_options`. **Not tested, not claimed.** The gate held against me (C6); whether it holds
  against a holder of the key is unknown to me.
- **The migration-URL disclosure at `class-wpvivid-migrate.php:966` and `:1026`.** Both
  `echo` a URL containing the site's **public key** as `&token=…`, and I read that from the
  source. I did **not** exercise it: the receiving end is a third-party service, and the
  engagement constraints forbid third-party infrastructure and public token-capture hosts. The
  finding is therefore sourced to `file:line` and **not** runtime-demonstrated, and that
  distinction is deliberate.
- **`generate_migration_key.php`.** Returns `500` and the body does not match any error string I
  grepped for; I did not chase it. **Work count: 1 request.**
- **Any CVE in `wpvivid-backuprestore` 0.9.123.** I read the plugin's own code for sinks and
  authorisation, and filed what the code shows. I did not attempt a known-CVE path, and a real
  third-party CVE would be documented, never tested.
- **Whether the target self-updates under load.** §5: the exposure is identical to lab 108's
  and it did not fire. Untested under traffic.
- **The WordPress REST surface beyond `/wp/v2/users`.** One request. The plugin registers **zero**
  REST routes (`grep -rn register_rest_route` → no hits), and `users_can_register=0`, so there
  was no reason to spend the budget.

## 11. Discarded with reason

| Hypothesis | Why discarded |
|---|---|
| The confirmation token is not bound to the account it confirms, via PHP's `session.upload_progress` primitive | `session.upload_progress.enabled=On` and `session.use_strict_mode=Off`, so `$_SESSION` is attacker-writable in principle. I injected `PHP_SESSION_UPLOAD_PROGRESS=x\|i:1;verify_user\|s:N:"<target>";` into a second session, but **`session.upload_progress.cleanup=On` removed it at request end**: the session file was **0 bytes** (`sess_5je85pngo9oo8k1q28d6icm8k2`) and `verify.php` returned `302 → register.php`, i.e. `verify_user` was not set. A concurrent-read race was **not** attempted. **The token binding held against this vector** — the session is a weak boundary in principle and an intact one in this configuration. *Instrumentation note: I read the session file with the **username** in the filename instead of the **session id**, so the first read reported `MISSING` for a file that existed — caught by listing the directory by mtime.* |
| The 4-digit code is time-seeded and therefore predictable without guessing | PHP 8.3's `rand()` is `mt_rand()`, auto-seeded from a CSPRNG since 7.1, so wall-clock prediction is out. I did not attempt to recover `mt_rand`'s internal state. The finding does not depend on it: F1 stands on "no delivery + no attempt counter", both measured, with the brute force succeeding in 0.9 s |
| A second registration for an existing username overwrites its token via `ON DUPLICATE KEY UPDATE` (`register.php:16-17`) | **Dead code, proven three ways** — identical, upper-case (`utf8mb4_general_ci`), and trailing-space username all hit `UNIQUE KEY username` first and are refused at `register.php:22-24`; the `verifications` row count stayed at 1. C2 |
| A SQL injection in the lifecycle | every statement is a prepared statement with `PDO::ATTR_EMULATE_PREPARES => false` (`db.php:8`) and bound parameters. `grep` of the six files finds no string-concatenated query. **6 files read in full** |
| A mail/SMS capture surface exists somewhere in the lab and the code is readable there | §0's grep, `which`, `/var/mail`, and `ps`. Zero. There is no capture surface because there is no sender |
| The 4-digit code leaks into a log, an error message or the HTML | the only place it appears is the `verifications` row. `verify.php` renders `$time_left` and the error string, never the code; `register.php` echoes nothing after the redirect |
| The `wpvivid` `wp_ajax_nopriv_*` restore endpoints are an unauthenticated database-restore primitive | four of them are registered for logged-out clients (`class-wpvivid-restore2.php:21-31`) but every body opens with `check_ajax_referer` + `current_user_can('manage_options')` (`do_restore()` at `:604-611`). The registration is a decoy; the body is the control. C8, C5 |
| `wpvivid`'s AJAX surface has a missing `permission_callback` (the lab-61 shape) | audited 8 of the 90 registered actions' handler bodies; every one opens with the same two-line guard. C5, with a byte-level control |
| `mysqld` running as root lets `LOAD_FILE('/root/root.txt')` reach the reward | `ps -o uid -C mariadbd` → `Uid: 103 103 103 103` (`mysql`/`mysql`). The **wrapper** `mariadbd-safe` (pid 72) is uid 0, and reading that first is exactly how one would report the wrong identity |
| A second virtual host, a renamed login path, or a backup artefact discloses a credential (labs 61/108/90 shapes) | one vhost (`000-default.conf`, `DocumentRoot /var/www/html`, `ServerName` unset); `/wp-login.php` → 200 canonical, nothing renamed; no `.sql`/`.bak`/`.zip`/`.tar` under any document root; `/wp-config.php` → 200 with 0 bytes; `phpMyAdmin` absent |
| `wordpress_logged_in` alone authenticates (lab 108's inverse finding) | not re-tested. `wp_config.php` salts are the placeholder and core discards them (C7), and I have no WordPress session to test with. **Not claimed either way** |
| The `ethan:pfLmWVz2EGKGpRCmACTP` pair in `copy2321_.php` is a credential for this lab | it belongs to a different lab in the series (`Host: localhost:8080`, `GET /productos/lista`, persona "Ethan"). Not attempted against SSH, and the shadow hashes are yescrypt anyway (§10) |

---

## 12. What feeds forward

**The rule this lab earns, and it extends rather than creates.**

Labs 61 and 108 built the WordPress *platform* section: cookies, salts, `active` vs `present`,
enumeration. This lab is the first **account-lifecycle** entry, and what it contributes is not
a new class but a **new entry criterion** for a class the corpus has as "credential attack":

> **For every token the lifecycle issues — confirmation, password reset, admin-email
> confirmation, session, API key — the first question is not "how strong is it" and not "where
> is it stored". It is: *what is the channel, and does it exist?* Enumerate the tokens the
> product issues; for each, name the delivery function and point at it in the source. If the
> function is absent, the token's strength is irrelevant and the transition is unguarded — and
> the correct entry criterion becomes *"is there an honest path to the confirmed state?"*, not
> *"can I guess the code?"*. A 4-digit code with no counter is only interesting **because**
> nobody can receive it.
>
> Three corollaries, each with its own measured instance here:
> - **A gate that nobody can satisfy is a denial of service wearing a security control.** Do
>   not ship a mint-and-check with no transport; that is a lab that cannot be solved honestly.
> - **A client-side field is not an account property.** `email` and `phone` are collected,
>   stored, and read by nothing (F6), while the field the application *does* enforce —
>   `username` — is the one the user invents. Invert that ordering and the account list stops
>   being an identity boundary.
> - **The state machine's own housekeeping is attack surface.** The cleanup branch that deletes
>   an abandoned account is reachable by naming a row (F7). In a lifecycle where a session can
>   be forged — or simply shared, or replayed — a `DELETE` in a request handler is a primitive,
>   and it should be a scheduled job.
>
> **And the token-storage class, third instance in this corpus** (after 172's CSRF token in the
> cookie and 108's backup credential in the docroot): here it is a **4-digit token in a
> plaintext table whose credential sits in a served PHP file** (F2), and a **2048-bit RSA
> private key in `wp_options` that the whole internet can rotate** (F4, F5). The pattern across
> all three is the same and it is worth stating once: *ask where the token lives, then ask who
> can read the thing that guards it, and treat the distance between those two answers as the
> finding.*

**For the parent, not for `method/`:** the two rows this writeup is evidence for are
(a) *credential attack* — the discriminator is now **"is the token deliverable?" before it is
"is the token strong?"**, and (b) a **new section on the account lifecycle**, justified against
the existing headings because none of them has an entry criterion: the existing rows are all
*sinks* (file upload, XXE, SSTI, SQLi, deserialisation, LFI), and this lab's entire attack
surface is a **transition**.
