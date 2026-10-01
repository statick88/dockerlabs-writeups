# 12 Collections — writeup

**Lab:** 12 · *Collections* · **medio**
**Description (full, from the platform catalog, `catalog.txt:159`):**
*"Laboratorio para practicar la explotación de WordPress mediante el plugin File Manager, con
escalada de privilegios apoyándose en MongoDB."*
**Target:** `172.17.0.13` — single container `collections_container`, image `collections:latest`.
**Result:** authenticated as `chocolate` (administrator) → code execution as **`uid=33(www-data)`**.
**No `FLAG{}`** — reported as a measured absence with the search (§8).

**Headline: the catalog's plugin and the catalog's escalation half are both wrong, and the
platform label is right for the wrong reason.** The queue's fourth field for this lab is
`WordPress platform; content-type handling`. The platform half checks out; the plugin is not
**File Manager**, and the MongoDB half cannot start on this host at all.

---

## 0. The generalisation verdict — is this lab about content-type handling?

The brief asks whether the contribution worth keeping is **content-type handling**: what a media
library does with a *declared* type versus a *sniffed* one, and whether the extension, the
`Content-Type` and the handler registration can disagree.

**Yes, but as a statement about the server, not about the plugin — and it is stated below as the
lab's real result. It is not what the lab was built to be.**

**Entry criterion, generally (the version I would put in the methodology):**

> A media library decides on a *declared* type. A web server decides on a *registered* handler.
> These are two grammars reading the same bytes, and they are written by different people in
> different configuration files. Ask three questions in order, and treat each as needing its own
> measurement:
> 1. **What does the framework's own type-check consume** — the filename extension, the request
>    `Content-Type` header, or the sniffed bytes? Call its getter; do not read the config file.
> 2. **Where is the content-type → handler map written, and is it inside or outside the upload
>    directory's own scope?** If the map is a global `SetHandler` on a filename pattern and there
>    is no `engine off` / `Require all denied` over the upload tree, then the *only* control
>    between an uploaded file and execution is answer 1 — and it is one allowlist in one PHP file.
> 3. **Do the two answers disagree on any input?** A filter that tests the extension *as a
>    substring anywhere in the name*, and a handler that tests the extension *at the end of the
>    name*, disagree on `poc.css.php` — and the disagreement is reachable, because `poc.css.php`
>    is the one name both grammars accept for opposite reasons.

**Measured in this lab, on this artefact:**

| Question | Answer | Where |
|---|---|---|
| 1. What the framework consumes | Both axes, separately, and they **disagree**: `wp_check_filetype()` reads the extension only; `wp_check_filetype_and_ext()` additionally reads the bytes and will **rename** the file | `wp-includes/functions.php`, called below |
| 2. Where the handler map lives | Global `SetHandler` in a `mods-enabled` symlink, keyed on the **end of the filename** — and **zero** `.htaccess` files anywhere under `uploads/` (count: 0) | `/etc/apache2/mods-available/php8.1.conf:1-3` |
| 3. Do they disagree | **Yes, live**, for any upload primitive that can control the stored name: a `.php` file placed in `wp-content/uploads/` executes as `uid=33` | §4 F1 |

**What the lab was actually declared to be, and whether it is:** a WordPress plugin RCE plus a
MongoDB privilege escalation. **The first half does not exist as shipped** (the plugin fatals
before its own handlers register — §4 F2) and **the second half cannot start on this CPU** (§4 F3).
So this is a lab that reproduces, correctly and usefully, a class the corpus already has
(`corpus/32` is the strongest instance), and adds two genuinely new artefacts on the content-type
question. Per the convergence rule, that is stated as a result, not inflated.

---

## 1. Surface

```
$ nmap -Pn -sV -p- --min-rate 2000 172.17.0.13
Host is up (0.000045s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.7 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

**TCP surface: 2 ports, 65 535 closed.** The non-TCP surface was checked separately rather than
inferred from `-p-`:

```
$ cat /proc/net/udp | awk 'NR>1 {split($2,a,":"); print strtonum("0x" a[2])}' | sort -n | uniq
(no output — 0 UDP sockets bound)
$ cat /proc/net/tcp | awk 'NR>1 && $4=="0A" {split($2,a,":"); print strtonum("0x" a[2])}' | sort -n | uniq
22
80
3306
```

MariaDB is bound (`3306`) but refused from outside — loopback only. **The image declares
`ExposedPorts: {'27017/tcp': {}}` and nothing is listening on 27017** (§4 F3), so a `-p-` scan
and this `/proc` read agree, and the declared port is the anomaly.

**Docroot.** `DocumentRoot /var/www/html`, and WordPress lives one level down in a directory
literally *named* `wordpress`, so the site is served at **`/wordpress/`**, not `/`. Measured,
not assumed — `GET /` returns a static `index.html` (10 671 bytes, `Last-Modified: Thu, 16 May
2024`) and `GET /wordpress/` returns the site (`<title>Mi Web Maravillosa</title>`). Two vhosts
are defined on `*:80`; **three `Host` values — the bare IP, `collections.dl`, and
`zzz-nonexistent.invalidtld` — produce identical behaviour (directory listing `200` in 3 of 3)**,
so `Host` selects nothing here and the vhost is a catch-all.

---

## 2. What the artefact actually is — and was the manifest's label right?

**Read from version-bearing files inside the image, before any request was sent.**

```
$ docker run --rm --entrypoint sh collections:latest -c 'grep -n "wp_version = " /var/www/html/wordpress/wp-includes/version.php'
19:$wp_version = '6.5.3'
```

```
$ cat /var/www/html/wordpress/wp-content/plugins/site-editor/readme.txt
=== Site Editor - WordPress Site Builder - Theme Builder and Page Builder ===
Requires at least: 4.7
Tested up to: 4.7.4
Stable tag: 1.1
```

| Axis | Catalog / queue says | Artefact says | Verdict |
|---|---|---|---|
| Platform | *WordPress* | `wp-includes/version.php:19` → `$wp_version = '6.5.3'` | **right** |
| Docroot | (not stated) | `/var/www/html` with the install in `/var/www/html/wordpress/` | **noted** |
| Plugin | *"el plugin File Manager"* | `wp-content/plugins/site-editor/readme.txt` → *Site Editor*, `Stable tag: 1.1`; `package.json` → `"version": "0.9.0"` | **WRONG** |
| Priv-esc half | *"escalada de privilegios apoyándose en MongoDB"* | MongoDB 7.0.9 installed, **cannot start here** (§4 F3); the seed data it would have loaded is still on disk unread by anything | **UNREACHABLE as shipped** |
| PHP | (not stated) | `PHP 8.1.2-1ubuntu2.17` via `mod_php` (`mods-enabled/php8.1.load`) | — |
| Web server | (not stated) | `Apache/2.4.52 (Ubuntu)` | — |

**This is the headline finding, and it is the queue's label rather than the artefact's fault.**
Per rule 1, the queue's platform label is a filename. Here the filename (`collections`) and the
queue field (`WordPress platform; content-type handling`) are both consistent with the truth at
the platform level, and the *catalog's own description* is what is wrong twice over. Note also
that the one directory in the whole tree not owned by `www-data` is the plugin:

```
drwxr-xr-x 8 root root  4096 May 16  2024 site-editor      <- root:root
drwxr-x--- 4 www-data www-data 4096 May  7 2024 akismet
```

That asymmetry is a build artefact of how the image was assembled, not a control: `wp-config.php`
is `-rw-rw-rw- 1 www-data www-data`, so the *web* identity can already write there.

---

## 3. The class and the chain

**Class:** upload content-type handling, and — for the entry criterion — the *declared vs sniffed
vs handler-registered* disagreement.

**Entry criterion that started it:** *does the upload path decide on the client-declared type
(the filename extension), and can the extension, the served `Content-Type` and Apache's handler
registration disagree?*

**Source that settled it:** the server's handler map, before touching the app —
`/etc/apache2/mods-available/php8.1.conf:1-3`:

```
<FilesMatch ".+\.ph(ar|p|tml)$">
    SetHandler application/x-httpd-php
</FilesMatch>
```

Key properties, both measured:

- The map is keyed on the **filename**, **anchored at the end** (`.+\.ph(ar|p|tml)$`). It never
  consults the MIME type and never consults the file's content.
- There is **no `php_admin_flag engine off` and no `Require all denied` over
  `wp-content/uploads`**. `find /var/www/html/wordpress/wp-content/uploads -name .htaccess | wc -l`
  → **0**. A full grep of `/etc/apache2/` for `AddType|AddHandler|SetHandler|ForceType` returns
  only `mods-available/php8.1.conf` and `mods-available/info.conf` — no lab-injected MIME rule
  (this is the shape of lab 146's finding, and here it is **absent**; that is a control that held).

### Chain

| # | → | Mechanism | Identity proof (verbatim, measured at the hop) |
|---|---|---|---|
| 0 | anonymous | Enumerate the author: `GET /wordpress/?author=1` → `author/chocolate/`; `GET /wordpress/?rest_route=/wp/v2/users` → `[{"id":1,"name":"chocolate", …}]`, 667 bytes | none needed |
| 0 | anonymous | Guess the password. **3 candidates tested, 1 accepted** (see §6 for the defective first run) | — |
| 1 | `chocolate`, **administrator** | `POST /wordpress/wp-login.php` → `302` + `wordpress_logged_in_dbfbe79f26a8e1bb7a80aae82cb7a4ab`. Reached `wp-admin/plugins.php` (`200`, 67 762 bytes), which requires `manage_options` | `USER=chocolate`, `CAP_manage_options=true`, `CAP_edit_theme_options=true` |
| 2 | `uid=33(www-data)` | `wp-admin/theme-editor.php` → write `wp-content/themes/twentytwentytwo/functions.php`, then `GET` it | **see below, verbatim** |

```
$ curl -s http://172.17.0.13/wordpress/wp-content/themes/twentytwentytwo/functions.php
MARK=DL12-1790758895-a1b2c3
SHELL-ID: uid=33(www-data) gid=33(www-data) groups=33(www-data)
PROC|Name:	apache2
PROC|Uid:	33	33	33	33
PROC|Gid:	33	33	33	33
PROC|Groups:	33
PROC|CapInh:	0000000000000000
PROC|CapPrm:	0000000000000000
PROC|CapEff:	0000000000000000
PROC|CapBnd:	00000000a80425fb
PROC|NoNewPrivs:	0
PROC|Seccomp:	2
SCRIPT: /var/www/html/wordpress/wp-content/themes/twentytwentytwo/functions.php
PWD: /var/www/html/wordpress/wp-content/themes/twentytwentytwo
```

**`uid=` and `euid=` at every hop, not just "root":** the `Uid:` line is read straight out of
`/proc/self/status` inside the executing process — all four fields (`real effective saved
filesystem`) are **33**, so there is **no setuid transition at this hop**, and the `CapEff` is
**all zeros**. `NoNewPrivs: 0` and `Seccomp: 2` are recorded because they decide whether a later
hop could gain anything. The `exec`-side `id` was captured separately in a second, independent
process and agrees: `PHPUSER=www-data`.

**Oracle manufactured, because this hop has none otherwise.** `system()` output is the result
here, but the *write* is the thing that needed proof, so a uniquely-marked file was written into
a path only the Apache identity can create and then pointed at:
`MARK=DL12-1790758895-a1b2c3`, verified on disk (`grep -c` → 1) **before** the HTTP read. The
marker was later re-checked after restore: `grep -rl DL12-1790758895 /var/www/html | wc -l` → **0**.

**Why the inactive theme.** `wp-admin/theme-editor.php` writes a `.php` file, then makes a
loopback HTTP request to `admin_url()` to check it did not white-screen the site, and **reverts
if the loopback cannot answer** (`wp-admin/includes/file.php:525-580`, the `wp_scrape_key` /
`###### wp_scraping_result_start` machinery). Here `siteurl` is `http://collections.dl/wordpress`,
which does not resolve from inside the container, so writes to the **active** theme
(`twentytwentyfour/functions.php`) failed with *"Ha ocurrido un error al tratar de actualizar el
archivo"* **while the file was byte-identical to the original** — `wc -c` before 5543, after 5543,
and no new entry in the error log. The identical write to the **inactive** theme
(`twentytwentytwo/functions.php`) returned `302` and persisted, because
`$is_active` is false there and the loopback is skipped. This is an instrument defect (§7) but
it is also a real property: **in this lab the theme editor silently reverts PHP edits to the
active theme**, and an analyst would reasonably read that as "the write was blocked".

---

## 4. Findings

### F1 — The PHP engine is unrestricted over `wp-content/uploads`; the extension allowlist is the *only* control (CWE-434 / CWE-16, configuration)

**Literal evidence, three states, one path.** Three files placed as `www-data` into
`/var/www/html/wordpress/wp-content/uploads/dl12test/` and fetched:

| File on disk | HTTP status | `Content-Type` served | Body | Meaning |
|---|---|---|---|---|
| `a_plain.php` (88 B) | `200` | `text/plain;charset=UTF-8` | `EXEC plain.php uid=33` (22 bytes) | **the engine runs inside `uploads/`** |
| `b_php_mid.css` (65 B) | `200` | `text/css` | the PHP source, verbatim (65 bytes) | **not executed** — the map is anchored at the filename end |
| `c_plain.txt` (7 B) | `200` | `text/plain` | `NOT-PHP` (7 bytes) | **positive control**: the path is web-reachable and the fetch is not lying |

`GET /wordpress/wp-content/uploads/dl12test/` → `200` with a genuine Apache autoindex
(`<h1>Index of /wordpress/wp-content/uploads/dl12test</h1>`), because the vhost carries
`Options Indexes`.

**Root cause.** The handler map is global
(`/etc/apache2/mods-available/php8.1.conf:1-3`, quoted verbatim in §3) and nothing narrows it
over the upload tree: **0** `.htaccess` files under `wp-content/uploads`, and no
`<Directory>`/`SetHandler` override. WordPress's own check does hold (§5) — but it is a single
allowlist in `wp-includes/functions.php`, and every upload primitive, plugin and future
mis-typed `AddType` inherits the whole blast radius from that one file.

**Impact.** `C:N/I:N/A:H` as measured. This is a **hardening finding, not a live
vulnerability**: I found no shipped upload path that lets a low-privilege caller choose a `.php`
filename, and I am not claiming one.

**Remediation.** Ship an `.htaccess` over the upload tree (the vhost has
`AllowOverride All`, so it would take effect — verified present in
`/etc/apache2/sites-enabled/000-default.conf`), or a `SetHandler none` /
`php_admin_flag engine Off` `<Directory>` block for `wp-content/uploads`:

```apache
<Directory /var/www/html/wordpress/wp-content/uploads>
    php_admin_flag engine Off
    SetHandler none
    RemoveHandler .php .phar .phtml .phpml
    <FilesMatch "\.(?i:php|phar|phtml|phpml|cgi|pl|py|s?html?|htaccess)$">
        Require all denied
    </FilesMatch>
</Directory>
```

### F2 — The shipped plugin is fatally incomplete: two required classes are absent, so **every one of its 15 registered AJAX actions dies at the same missing `require_once`** (lab-design / availability defect) — **4 of them were sent and returned HTTP 500; the other 11 are inferred from the shared load path, not probed**

The lab's declared attack surface is the plugin. It cannot be reached.

```
$ ls -la …/site-editor/editor/extensions/options-engine/includes/dependency/
total 12
drwxr-xr-x 2 root root 4096 Mar 12  2021 .
drwxr-xr-x 8 root root 4096 Mar 12  2021 ..
-rw------- 1 root root  659 Apr 19  2017 index.html.tmp
```

Two `require_once`s in `…/includes/site-editor-dependency-manager.class.php:42` and `:46` load
`dependency/site-editor-options-dependency.class.php` and
`dependency/site-editor-options-callback-dependency.class.php`. **Neither exists.** Verbatim
from the Apache error log:

```
PHP Fatal error:  Uncaught Error: Failed opening required
'/var/www/html/wordpress/wp-content/plugins/site-editor/editor/extensions/options-engine/includes/dependency/site-editor-options-dependency.class.php'
(include_path='.:/usr/share/php')
in …/includes/site-editor-dependency-manager.class.php on line 42
Stack trace:
#0 …/site-editor-options-manager.class.php(108): SiteEditorOptionsDependencyManager->__construct()
#1 …/options-engine.php(39): SiteEditorOptionsManager->__construct()
#2 …/options-engine.php(96): SedOptionsEngineExtension->__construct()
#3 …/site-editor-app.php(92): include_once('...')
…
#11 …/wp-includes/wp-settings.php(517): include_once('...')
#14 …/wp-admin/admin-ajax.php(22): require_once('...')
```

The plugin only enters this branch when its own AJAX flag is set
(`site-editor.php:299-305`: `if ( $this->is_request( 'editor' ) || … || $this->is_request( "sed_wp_ajax" ) ) { $this->load_editor(); }`),
which is why the ordinary admin pages render fine and only the plugin's own surface dies.

**Positive control for this negative — 4 of 4.** Four independent
`POST /wp-admin/admin-ajax.php` requests with `sed_page_ajax` set — `action=add_zipped_font`
(×3, once per freshly-minted nonce) and `action=sed_app_refresh_nonces` (×1) — all returned
**HTTP 500, 181 bytes, identical body**, and the fatal count in `/var/log/apache2/error.log`
rose from 1 to **5** (a **delta of 4**). `evidence/apache-error.log` holds **11** `PHP Fatal
error:` lines from **three unrelated causes**; the **5** that count here are the ones whose cause
is the missing dependency classes — 1 already present at 09:10:07 plus the 4 this control added
within 0.7 s at 09:13:19–09:13:20. The other 6 are not this finding: 3 from `create_function()`
being removed in PHP 8 (May 2024, 3 timestamps), 2 `add_action()` called before WordPress
loaded (09:01:53, 09:02:26), and 1 `Undefined constant "ABSPATH"` (09:06:02). A control that
has never fired is not a control; this one fired four times in a row.

**Consequence for the writeup.** The 15 registered actions —
`add_zipped_font`, `sed_upload_attachment`, `customize_save`, `sed_save_preset`, `sed_create_preset`,
`sed_load_options`, `load_medias`, `load_modules`, `load_skins`, `sed_delete_preset`, `sed_get_preset`,
`sed_module_presets`, `sed_save_presets`, `remove_icons_font`, `sed_app_refresh_nonces` — are all
**unreachable**. The declared chain for this lab does not exist as shipped.

### F3 — The declared MongoDB escalation surface cannot start: MongoDB 7.0.9 requires AVX, this CPU has none, and the failure **kills the container**

```
$ env PATH=/usr/bin:/bin docker logs collections_container
WARNING: MongoDB 5.0+ requires a CPU with AVX support, and your current system does not appear to have that!
  see https://jira.mongodb.org/browse/SERVER-54407
…
2026-09-30T08:57:18.810+0000	error connecting to host: failed to connect to mongodb://localhost/:
server selection error: … dial tcp [::1]:27017: connect: connection refused
```

```
$ grep -m1 'model name' /proc/cpuinfo
model name	: QEMU Virtual CPU version 2.5+
$ grep -ow -m1 'avx' /proc/cpuinfo
(no match — 0 occurrences)
$ docker run --rm --entrypoint mongod collections:latest --version
Illegal instruction (core dumped)
```

`mongod` cannot execute an instruction. The image's `Cmd` chains
`… && mongoimport … && rm … && tail -f /dev/null`, so `mongoimport`'s failure **terminates the
container** ~35 s after start. **Reproduced twice**, from a clean `docker run`, both times
`Exited (1)`. The declared escalation half is therefore untestable here, and the reason is
hardware, not configuration.

The seed data MongoDB was supposed to load is still on disk, **writable by `www-data`** (mode
`777` — the `rwx` bits are there too, but the fact this finding needs is world-**write**, and
quoting it as "666" understated the executable bit):

```
-rwxrwxrwx 1 root root 127 May 16  2024 /opt/accesos.usuarios.json
[{
  "_id": { "$oid": "6645f4456682cdae1b46b799" },
  "nombre": "dbadmin",
  "contraseña": "chocolaterequetebueno123"
}]
```

`/var/lib/mongo` **does not exist** (`exists=0`) — the database was never initialised.

**Consequence.** The engagement had to run with the container command overridden to skip the
`mongoimport` step (the deviation is stated in §9; sshd, MariaDB and Apache are started by the
image's own `Cmd` and are untouched). **This is an instrumentation defect with teeth** — see §7.

### F4 — `wp-config.php` is mode `666` (CWE-732)

```
-rw-rw-rw- 1 www-data www-data 3357 May 16  2024 /var/www/html/wordpress/wp-config.php
```

World-writable, and it holds the database password and all eight auth keys and salts
(`wp-config.php:29`, `:53-60`). Any local account — the container's sshd is running, so any
account that can log in — can rewrite it and become the web identity. It is also a
**second, independent write primitive into the web root**, which is why the write above could
have gone through `wp-config.php` as well.

### F5 — WordPress will auto-update core; nothing sets `AUTOMATIC_UPDATER_DISABLED`

Measured through the framework's own value, not by reading the file:

```
AUTOMATIC_UPDATER_DISABLED=false
wp_version_runtime=6.5.3
wp_db_version=6.5.3
```

The container has outbound network (`plugin-install.php?tab=upload` reached
`api.wordpress.org` and returned a live *"Ya está disponible WordPress 7.1.2"* nag), and
`wp-cron.php` is present and reachable (`GET /wordpress/wp-cron.php` → `200`, 0 bytes).
The version was **still 6.5.3 after ~20 minutes** of engagement, verified again on the restored
container. **Recorded as a hazard with a measured outcome, not as a finding against the lab** —
but the two numbers mean different things: *6.5.3 shipped* (`version.php:19`) and *6.5.3
running after 20 minutes* (runtime). Both are stated; neither is inferred from the other.

---

## 5. Controls that held

| Control | Positive control that proves the detector works |
|---|---|
| **`wp_check_filetype()` rejects every PHP-ish extension.** `.php`, `.phtml`, `.phar`, `.phpml`, `.pht`, `.php5`, `.inc`, `.shtml`, `.gif.php` → all `type=false ext=false` | The same function returns `type='image/jpeg' ext='jpg'` for `a.jpg` and `type='application/zip' ext='zip'` for `q.zip` in the same batch — so it is discriminating, not short-circuiting. **17 filenames, 17 verdicts, 0 errors** |
| **`wp_check_filetype_and_ext()` reads the bytes, and renames on disagreement.** `a.jpg` containing GIF bytes → `type='image/gif'`, `ext='gif'`, `proper_filename='a.gif'`; `c.php.jpg` → `proper_filename='c.php.gif'`; `j.jpeg` / `p.webp` / `i.txt` containing PHP bytes → rejected outright | Same batch, same function: `q.zip` with real zip bytes → accepted with `proper_filename=false` (no rename needed). The detector fires in both directions |
| **WordPress media upload rejects a `.php` upload.** `async-upload.php` with `filename=font.zip` → `{"success":true,…,"mime":"application\/zip"}` | The same endpoint accepted the request and returned the new attachment id — it is a working uploader, not a silent one. Had it rejected everything, the following `.zip` test would have been meaningless |
| **Apache's handler map is anchored at the filename end.** `b_php_mid.css` (PHP inside a `.css`) served as `Content-Type: text/css`, source returned verbatim, **not executed** | `a_plain.php` in the *same directory* executed in the same session. Same directory, same second, opposite outcomes — so the discriminator is the name, and the instrument distinguishes it |
| **`check_ajax_handler()` on `add_zipped_font`.** Requires `is_user_logged_in()`, `current_user_can('edit_theme_options')`, `check_ajax_referer('sed_app_icon_font_load_'.$stylesheet,'nonce')` and `$_POST['sed_page_ajax']=='icon_font_loader'` — read off `site-editor-manager.class.php:1379-1396` | Cannot be exercised positively: the handler is unreachable (F2). **This control is therefore listed as NOT proven** — see §6 |
| **No lab-injected MIME rule.** The grep of `/etc/apache2/` for `AddType|AddHandler|SetHandler|ForceType` returns only stock Ubuntu directives | Contrast with lab 146, where a global `AddType application/x-httpd-php .jpg` *was* the finding. Here the three shipped `.htaccess`-style explanations are simply absent: `.htaccess` count under the docroot is **1** (WordPress's own rewrite rules) and under `uploads` is **0** |

---

## 6. Every negative, with its work count

| Negative | Work count | Where it goes |
|---|---|---|
| No `FLAG{}` in the database | **5 table×column scans** (`wp_posts.post_content`, `wp_postmeta.meta_value`, `wp_options.option_value`, `wp_comments.comment_content`, `wp_users.user_url`), each a SQL `REGEXP 'FLAG\{|HTB\{|CTF\{'`, **0 matches**; DB contains 1 user, 10 posts, 161 options | Evidence, measured absence |
| No `FLAG{}` on the filesystem | **7 roots listed** (`/var/www/html`, `/opt`, `/root`, `/home`, `/etc`, `/tmp`, `/usr/local`), **26 698 files visited**, **605 996 069 bytes visited**, `grep -rIl` → **0 matches** | Evidence, measured absence |
| No privilege escalation from `www-data` | `sudo -n -l` → `sh: 1: sudo: not found` (**sudo is not installed**); `/etc/sudoers` `readable=0`; `/etc/sudoers.d` `scandir=ERR`; setuid sweep `find / -xdev -perm -4000` → **10 files, all stock** (`passwd`, `chsh`, `gpasswd`, `newgrp`, `chfn`, `mount`, `umount`, `su`, `ssh-keysign`, `dbus-daemon-launch-helper`); `/etc/cron.d` → **4 entries**, `/etc/crontab` `exists=0`, `/var/spool/cron/crontabs/root` `exists=0`; `users_with_uid0` → `root` only; `/etc/shadow` `readable=0`; `/root` `readable=0` | Evidence, measured absence |
| No MongoDB to attack | `mongod --version` → `Illegal instruction (core dumped)`; `/proc/net/tcp` listeners `22, 80, 3306` — **0** on 27017; `/proc/net/udp` — **0** sockets; `nmap -p-` → 65 535 closed; `/var/lib/mongo` `exists=0` | **NOT tested** — see below |
| Plugin AJAX surface dead | 4 requests, **4/4** HTTP 500, 181 bytes each; fatal count in the error log 1 → **5** (a **delta of +4**; the file's 11 `PHP Fatal error:` lines span 3 causes, 5 of them this one) | Evidence, measured absence — the remaining 11 actions are inferred from the shared load path, not probed |
| `weird.CSS` skipped by the plugin's filter | 9 entry names tested against the artefact's own regex list (`icon-library.php:247`): `ok.css` WRITE, `control.txt` SKIP, `poc.css.php` WRITE, `control.php.css` WRITE, `x.php` SKIP, `dir/ok.svg` WRITE, `weird.CSS` SKIP, `poc.phpml` SKIP, `a.json.php` WRITE — **9/9 verdicts** | Evidence (§7, defect 3) |
| Password guessing | First run: **15 candidates, all reported as successes** (defect below). Second run with a clean cookie jar: **3 candidates, 1 accepted**, 2 correctly rejected (`http=200, logged_in_cookies=0`) | The corrected run is the evidence; the first is §7 defect 1 |

### NOT tested (and why)

- **MongoDB privilege escalation.** The declared second half. Not testable: `mongod` cannot
  execute an instruction on this CPU (F3). Count of escalation attempts: **0**. This is an
  **untested** area, not a negative result.
- **`check_ajax_handler()` as a control on `add_zipped_font`.** Read from source
  (`site-editor-manager.class.php:1379-1396`), never exercised, because the handler is
  unreachable. I am reporting the *code*, not a measured outcome.
- **Cookie forgery from the salts.** Measured only what the framework consumes
  (`wp_salt('auth') strlen=128`, `AUTH_KEY defined=true strlen=64` — per rule 3, the getter,
  not `defined()`). The salts are real 64-character random values, not installer placeholders.
  **No forgery was attempted and none is claimed.**
- **Whether `uploads/` is reachable under a different `Host`, a different port, or through a
  rewrite.** 3 `Host` values tried, all identical; no other port open.
- **Root.** Every path beyond `uid=33` is blocked by one of the negatives above, all with counts.
  `uid=0` was never reached.

### Discarded with a reason

- **`?author=1` … `?author=5` enumeration** — discarded as an enumeration route once
  `?rest_route=/wp/v2/users` returned the same information in 667 bytes. 5 of 5 ids tried;
  ids 2–5 → `404`.
- **`wp-xmlrpc.php` `system.listMethods`** — returned 80 methods and a valid 405 from the
  endpoint, so the instrument worked, but credential brute force over XML-RPC is a worse oracle
  than `wp-login.php`, which distinguishes 302/200 *and* sets a `wordpress_logged_in` cookie.
  Discarded in favour of the better oracle.
- **Uploading a `.php` through `async-upload.php`.** Discarded before execution: `wp_check_filetype()`
  rejects it at the extension axis (measured), and the F1 demonstration shows the same result
  with a strictly better oracle (the file's own output) at strictly less cost.

---

## 7. Instrumentation defects

These are mine. They are separated from the findings because none of them is a property of the
target, and two of them would have shipped as results.

**1. A stale cookie jar reported 15 false positives in a row.** `curl -b jar -c jar` only rewrites
the jar when the response carries a cookie. After the *first* successful login, 14 subsequent
**failed** logins all printed `logged_in_cookies=1`, because the jar still held the cookie from
the success — and 15 of 15 lines printed `*** SUCCESS`. A naive re-run would have filed 15
working credentials. Caught because the first attempt also returned `http=302` while the rest
returned `200`; the cookie count and the status code disagreed, so the cookie count was the
unreliable one. Re-run with a fresh jar per attempt: **3 candidates, 1 success, 2 clean 200s.**
This is `self-corrections` §13's shape with the sign flipped — there, the detector was always
true and the answer was inverted; here the detector was stale-true.

**2. The container's death read as a negative.** The first deploy exited on its own. The obvious
conclusion — *the lab is broken, MongoDB is absent, there is no database* — is exactly the
`self-corrections` §14 shape: a zero that means *untested* wearing the clothes of a result. The
discriminator was external and cheap: `docker logs` named AVX, and the artefact's own
`ExposedPorts: {'27017/tcp': {}}` contradicted the "absent" reading. This is the single most
consequential defect of the engagement, because F3 (the declared escalation half being
unreachable) would have been filed as "no MongoDB attack surface here" — a claim about the
*class* dressed as a claim about the *instance*.

**3. A regex, read as a whitelist.** The plugin's filter is
`array('\.eot','\.svg','\.ttf','\.woff','\.json','\.css')` applied with
`preg_match("!".$regex."!", $entry, $matches)` over the **whole zip entry name**
(`icon-library.php:247` and `:281-289`). My first reading of that line was "the plugin
allowlists image/CSS/font extensions". It is not a whitelist of *extensions*; it is an
**unanchored substring test over the entire entry path**. `weird.CSS` → SKIP (case-sensitive),
`poc.css.php` → WRITE. §3's table is what forced the correction, and it is the reason the
generalised criterion in §0 asks for the *shape* of the predicate rather than the list it
contains.

**4. `docker logs` summarises.** The environment's wrapper returned a filtered, deduped view
(`[error] 1 errors (1 unique)`). The AVX warning text and the `mongoimport` error line were both
truncated out of it. Re-read with `env PATH=/usr/bin:/bin docker logs` to get the raw stream —
`self-corrections` §7, hit exactly as documented.

**5. A write that failed for a reason unrelated to the payload.** The first `.php` write went to
the **active** theme and came back *"Ha ocurrido un error al tratar de actualizar el archivo"*,
with the file byte-identical afterwards (`wc -c` 5543 → 5543, no error-log entry). The cause is
WordPress's own loopback fatal-scrape, which cannot reach `http://collections.dl/wordpress` from
inside the container. Had I attributed this to a permission or filter control, I would have
reported "the theme editor blocks `.php` writes" — a control that does not exist. The positive
control was the same payload against an **inactive** theme: `302`, persisted, executed.

**6. A parse error shipped into the target because I skipped the lint.** One probe revision
contained a stray line and returned HTTP 500 through WordPress's fatal handler. `php -l` before
each deploy caught every other one. Cheap, and it should not have been needed twice.

**7. A scaffold artefact that could have been mistaken for a finding.** `docker cp` wrote the
mu-plugin as `dbadmin:dbadmin` — an owner that exists in the MongoDB seed JSON but **not** in
`/etc/passwd` (the container's `users_with_uid0`/passwd read confirms `root` only, and
`dbadmin` is not a Unix account here). It is mine, from the `docker cp` uid mapping, and it was
gone after restore. Recorded because a reader who saw it in the evidence log would rightly ask.

---

## 8. Reward

**No `FLAG{}`, `HTB{}` or `CTF{}` exists in this lab.** Two independent searches, both with
counts, in §6: 5 database scans over 1 user / 10 posts / 161 options → 0 matches; 7 filesystem
roots / 26 698 files / 605 996 069 bytes → 0 matches. The only credential-shaped string in the
artefact is `dbadmin` / `chocolaterequetebueno123` in `/opt/accesos.usuarios.json` (§4 F3), which
is the seed data for the unreachable MongoDB half and is reported as a credential, not as a
reward.

The single source for "does this corpus have rewards" is the `FLAG{}` column of
[`../INDEX.md`](../INDEX.md) — this writeup asserts no position in any sequence.

---

## 9. Deployment, deviations and restore

**Topology.** `auto_deploy.sh` was **read, never run** (it ends in `while true; do sleep 1; done`
at line 109). It creates **no network**: a bare
`docker run -d --name $CONTAINER_NAME $IMAGE_NAME` (line 95), one container, no macvlan, no
`--internal`, no second host. The engagement stayed single-host and attacked nothing else.

**Deviation, stated.** The shipped `Cmd` cannot complete on this host (F3), so the engagement
ran with the container command overridden to the same `service ssh start && service mariadb start
&& service apache2 start` the image itself uses, with `mongod` still attempted (and still
failing), and `tail -f /dev/null` in place of the `&&`-chained `mongoimport`. **sshd, MariaDB
and Apache are started by the image's own script; nothing else about the lab was changed.**
Read-only inspection of the image used `docker run --rm --entrypoint sh collections:latest`.

**Restore — recreated from the image, not reverted (RUNBOOK §9).**

```
$ docker rm -f collections_container && docker run -d --name collections_container collections:latest …
```

**Positive verification** — the service is serving again:

```
site http        = 200
wp-login http    = 200
title            = <title>Mi Web Maravillosa
wp_version      = $wp_version = '6.5.3';
```

**Negative verification** — my artefacts are gone, with counts:

```
mu-plugins dir  = absent
dl12test dir    = absent
uploads tree    = (0 files)
plugins dir     = akismet  hello.php  index.php  site-editor
tt4 style.css L1= /*
tt2 functions L1= <?php
DL12 markers    = 0 files
```

One residue worth naming rather than hiding: `uploads/2026/09` exists as **two empty
directories**. They were created by ordinary front-end page renders of the shipped application,
not by any payload (`find …/uploads -type f | wc -l` → **0**).

**The image `collections:latest` is still loaded** and was deliberately not removed, so the next
worker can re-run this engagement without re-extracting 1.9 GB. Disk: 24 GB free at the end of
the engagement (91 % used, shared with 10+ lab containers). No `docker system prune`,
`docker image prune -a` or `docker volume prune` was run. The seven `cybervault-*` containers
were not touched.

---

## 10. What feeds forward

The methodology already carries this class. `corpus/146` filed *"MIME map"* and
`corpus/296` filed *"Upload sin restricción · MIME map"* — so **no new section is warranted**
(per `PIPELINE.md` §Convergence: density beats coverage). What this lab adds is **one extra step
to the existing "read the server's content-type → handler map" row**, and it is the step labs 146
and 296 both missed:

> A handler map that is **anchored at the end of the filename** agrees with an extension
> allowlist on ordinary inputs and disagrees on `poc.css.php`. So the question is not *"is the
> engine switched off in the upload directory?"* — 146 and 296 asked that and the answer was
> "no, the map is global" — it is **"do the application's extension test and the server's
> filename test accept the same set of names?"** Measure both predicates on the same input list.
> `icon-library.php`'s unanchored `preg_match` over a whole archive entry name and Apache's
> `\.ph(ar|p|tml)$` are the two halves of that, and the names they disagree on are exactly the
> names that work.

And, for the corpus's own instrumentation:

> **A container that exits on its own is a finding about the artefact, not an absence of the
> class.** This lab declares a MongoDB escalation that cannot start on an AVX-less CPU, and the
> container's own `&&` chain then dies. Reading that as "no database attack surface here" would
> have been filed as a negative result about MongoDB in general. It is not — see
> `self-corrections.md` §14, and the six instruments that would have deleted a finding.

---

## Relevant files

- `corpus/12/evidence/artefact-versions-and-missing-files.txt` — `$wp_version = '6.5.3'`,
  `Stable tag: 1.1`, and the empty `dependency/` directory
- `corpus/12/evidence/artefact-server-and-plugin-config.txt` — `php8.1.conf` verbatim, the second
  vhost, and `icon-library.php:245-300` (the filter and the write)
- `corpus/12/evidence/probe-content-type-and-privesc.txt` — the 17-filename type table, the
  9-entry plugin-filter table, and the privesc surface with counts
- `corpus/12/evidence/probe-reward-and-version.txt` — the DB reward scan, `wp_salt('auth')`,
  `AUTOMATIC_UPDATER_DISABLED=false`
- `corpus/12/evidence/container-shipped-cmd-boot.log` — the AVX warning and the `mongoimport`
  failure, raw
- `corpus/12/evidence/apache-error.log` — the four `site-editor-options-dependency` fatals
- `corpus/12/evidence/media-upload-fontzip.json` — the `.zip` media upload that succeeded
