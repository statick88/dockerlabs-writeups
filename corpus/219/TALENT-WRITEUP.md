# 219 Talent — DockerLabs Writeup

**Class:** a hardcoded default WordPress administrator credential in the image build artefact, used to reach an authenticated admin file-write primitive and execute code as `uid=33(www-data)`. The advertised Python privilege-escalation ladder is present in `sudoers` but **non-functional as shipped**, because the interpreter it names is not in the image.

**Target:** `http://172.17.0.2:80` (container `talent_container`, image `talent:latest`)
**Date:** 2026-10-01
**Outcome:** Reward recovered as `LNDSG98DSFG7D8SGY8SDFG9` through the web path. **Privilege escalation to `bobby` or `root` NOT achieved — the mechanism is broken in the shipped image, and §6 reports the absence with its work count and control.** The target was restored and verified with `stat -c`; the WordPress database was never modified.

**Headline:** the decisive control is not in the application, it is in `/entrypoint.sh` — and the third advertised element is a *dead grant*, not a hard target. Reading the sudoers file tells you a chain exists. Running it tells you it does not.

---

## 0. Lab identity

The platform catalogue entry for 219, quoted verbatim from `~/dockerlabs/catalog.txt:23`:

```
219|Talent|medio|Web de wordpress con una vulnerabilidad y escalada de privilegios en linux mediante python.
```

Difficulty `medio`. The catalogue is the authority, and it advertises **three** elements. All three were hunted, and the outcome for each differs:

| Advertised element | Outcome |
|---|---|
| A WordPress site | Confirmed and used as the entry surface |
| A vulnerability | Confirmed and decisive — a default admin credential |
| Linux privilege escalation via Python | **Present in configuration, absent in the binary. Not achievable.** §6 |

The narrower work-queue label for this lab reads "WordPress platform plus Linux privesc" and would have framed the Python element as the objective. Reading the catalogue instead, and then the artefact, is what surfaced that the escalation target does not exist and that the *reward sits at the first hop*, not at root.

### Stack, from version-bearing artefacts

| Layer | Value | Source |
|---|---|---|
| Base OS | Ubuntu 20.04.6 LTS (Focal Fossa) | `/etc/os-release:2-4` |
| Web server | Apache 2.4.41-4ubuntu3.23, `ServerTokens OS`, `ServerSignature On` | `/etc/apache2/conf-available/security.conf:25,36` |
| Vhost | `<VirtualHost *:80>`, `DocumentRoot /var/www/html` | `/etc/apache2/sites-enabled/000-default.conf:1,12` |
| PHP | 7.4.3-4ubuntu2.29 (`mod_php`) | `dpkg -l php7.4`; `phpinfo()` `PHP Version 7.4.3` |
| `disable_functions` | `pcntl_*` family **only** — `system`, `exec`, `shell_exec`, `passthru` all live | `r02_info.html` (phpinfo, parsed) |
| `open_basedir` | **no value** (unset) | `r02_info.html` |
| `file_uploads` / `allow_url_fopen` | `On` / `On` | `r02_info.html` |
| WordPress | **6.9.1** | `/var/www/html/wp-includes/version.php:19` |
| Plugin | **Pie Register - Basic 3.7.1.0** | `wp-content/plugins/pie-register/pie-register.php:7` |
| Theme | Twenty Twenty-Five 1.4 | `wp-content/themes/twentytwentyfive/style.css` |
| Database | MySQL 8.0.42-0ubuntu0.20.04.1, bound to loopback only | `/proc/net/tcp`; `mysqld --version` |
| DB credentials | `wpuser` / `wppass` on database `wordpress` | `/entrypoint.sh:37-44` |
| **Admin credential** | **`admin` / `admin`** | **`/entrypoint.sh:115-116`** |
| `info.php` | left in the docroot, `<?php phpinfo(); ?>` | `/entrypoint.sh:131` |
| Users | `bobby` uid 1000; `www-data` uid 33 (groups 33, **101 mysql**) | `/etc/passwd`; `id` |
| www-data sudo grant | `(bobby) NOPASSWD: /usr/bin/python3` | `/etc/sudoers:32` |
| bobby sudo grant | `(ALL) NOPASSWD: /usr/bin/python3 /opt/backup.py` | `/etc/sudoers:34` |
| Python interpreter | **absent — no `python`, `python2` or `python3` anywhere** | §6, five independent probes |
| `/opt` | `757 root:root` — **world-writable** | `stat -c`, measured as www-data |
| `/opt/backup.py` | `644 root:root`, 6871 bytes, requires uid 0 at `backup.py:188` | `stat -c`; `backup.py:187-188` |

`disable_functions` blocking only `pcntl_*` and `open_basedir` being unset are the two facts that make the admin file-write primitive convert cleanly into command execution later.

---

## 1. Surface

Re-measured from inside the container rather than assumed. `ss` and `netstat` are absent, so `/proc/net/tcp` is the source, as the brief requires:

```
00000000:0050   0.0.0.0:80       apache   world-reachable
0100007F:0CEA   127.0.0.1:3306   mysql    loopback only   (0x0CEA = 3306)
0100007F:8124   127.0.0.1:33060  mysql X  loopback only   (0x8124 = 33060)
```

**3 listener rows, matching the baseline.** Port 80 is the only externally reachable service.

**That negative is earned, not assumed.** The MySQL-not-reachable claim rests on the `0100007F` bind prefix, which is a *static* file read. To convert it into a measured negative I attempted the connection from outside: `curl http://172.17.0.2:3306/` returned `http=000` with curl exit **7** (connection refused) — *refused*, not filtered, which is the signature of a loopback bind rather than a firewall drop. The positive control for the client path is request 1 in §5's accounting: the same curl invocation against `:80` returned `200` moments earlier. The client worked; the bind refused it.

**Note on scan coverage:** this is a TCP read of `/proc/net/tcp` only. UDP was never examined — see §7.

Work count behind the HTTP surface: **38 requests total**, itemised in `evidence/workcount_full.txt`, of which 5 are explicit positive controls. The `find` sweeps behind the plugin and Python hunts are bounded and declared there as well.

---

## 2. The class

> A **hardcoded credential in the deployment artefact** is the whole vulnerability, and the advertised escalation is a **sudo grant whose target binary is absent** — a configuration that reads as an attack surface and behaves as a wall.

Two lessons a generic WordPress chapter does not teach:

**1. Read the build artefact, not just the app.** There is no WordPress misconfiguration here, no vulnerable plugin behaviour, no file-inclusion or deserialization sink. The path to administrator is `--admin_password="admin"` at `/entrypoint.sh:116`, passed to `wp core install` at `:111`. A chapter on WordPress CVEs would find Pie Register 3.7.1.0 interesting, would look for the plugin's known role-import flaw, and would miss the actual entry point entirely. **The credential is in the entrypoint; the entrypoint is not served by the web server.** It is only findable by reading the image, which is why "read the source first" is the highest-yield step and not a formality.

**2. A sudoers line is a claim, not a capability.** `/etc/sudoers:32` grants www-data a passwordless run of `/usr/bin/python3` as `bobby`, and `:34` lets `bobby` run `/opt/backup.py` as root. The design is complete and deliberate: `/opt` is `757` specifically so www-data can write there, and `/opt/backup.py:188` gates itself on `os.geteuid() != 0`. Every link of the ladder is present **except the interpreter**. Reporting "sudoers allows www-data to run python3 as bobby" would be a true statement about a file and a false statement about the machine.

---

## 3. Attack chain

```
artefact read: /entrypoint.sh:115-116  →  admin / admin
        │
        ▼
POST /wp-login.php                          302 + logged-in cookies
        │  control: same URL without the cookie → Login page (200, "Login – Mi sitio WordPress")
        ▼
GET /wp-admin/  →  <title>Dashboard</title>, "Howdy, admin"     [admin session proven]
        │
        ├── attempt A: plugin editor, new file in docroot        → HTTP 500 "File does not exist!"
        ├── attempt B: plugin editor, new file in pie-register/  → HTTP 500 "File does not exist!"
        │
        ▼  attempt C: POST /wp-admin/update.php?action=upload-plugin  (zip)
"Plugin installed successfully."
   → wp-content/plugins/lab219probe/lab219probe.php   644 www-data:www-data  792 bytes
   → requested DIRECTLY over HTTP, never activated, so the DB was never touched
        │
        ▼
uid=33(www-data) gid=33(www-data) groups=33(www-data),101(mysql)   [measured in the web process]
        │
        ├── witness: /tmp/lab219_witness_<nonce>  written-by-uid=33
        │            read back out of band → 644 www-data:www-data
        │            negative control: a nonce I never wrote does not exist
        │
        ├── REWARD  cat /home/flag.txt  →  LNDSG98DSFG7D8SGY8SDFG9
        │
        └── privesc, measured as uid=33:
             sudo -n -l                 → grant IS real: (bobby) NOPASSWD: /usr/bin/python3
             sudo -n -u bobby /usr/bin/python3 -c 'print(1)'
                                      → sudo: /usr/bin/python3: command not found   (rc=1)
             /opt  writable             → yes, measured
             /opt/backup.py  writable   → no,  measured
             /usr/bin        writable   → no,  measured
             ⇒ no root path exists. Chain broken at the interpreter.
```

### Hop 1 — the credential is in the build artefact

`/entrypoint.sh:111-118` runs `wp core install` with `--admin_user="admin"` and `--admin_password="admin"`, and the install is unconditional (`:117`, `if ! wp core is-installed`). The credential is not a leftover; it is written on every container start when the database is fresh.

### Hop 2 — login, with the control that makes it mean something

A `302` plus `Set-Cookie` is not proof of authentication; it is also what a redirect-before-check produces. The discriminating evidence is a **paired** request to the same URL:

- **with** the session cookie: `http=200`, `<title>Dashboard ‹ Mi sitio WordPress — WordPress</title>`, `Howdy, admin` (`evidence/r07_wpadmin.html`)
- **without** it: `http=200` after redirect to `/?page_id=6&...&reauth=1`, `<title>Login – Mi sitio WordPress</title>` (`evidence/ctl_noauth.html`)

Two different bodies for one URL, differing only in the cookie. That difference is the result; the `302` was not.

### Hop 3 — the write primitive, and two dead ends worth recording

The admin file-write primitive was reached via **plugin zip upload**, not the editor:

- `POST /wp-admin/update.php?action=upload-plugin` with a zip → `Plugin installed successfully.` and `wp-content/plugins/lab219probe/lab219probe.php` at `644 www-data:www-data`, 792 bytes.

**Why upload and not the editor:** WordPress 6.9.1's plugin editor refuses to create a file that does not exist. Attempts A and B both returned `HTTP 500` with the body `File does not exist! Please double check the name and try again.` — recorded in `evidence/r09_create.txt` and `r10_create2.txt`, and visible in the target's own `debug.log` as `file_get_contents(...zzlab219probe.php): failed to open`.

**The reason upload is the better primitive here, beyond convenience:** extracting the zip writes the `.php` into the docroot as `www-data`, and the file is then reachable **without ever being activated**. `wp option get active_plugins` still reads `["pie-register/pie-register.php"]` afterwards (`evidence/db_state_check.txt`). The WordPress database was therefore never modified, and the whole write was removable as a single directory.

### Hop 4 — execution identity, measured where the claim is made

`id` was read back **from inside the web process**, not from a `docker exec` harness:

```
IDENTITY:     uid=33(www-data) gid=33(www-data) groups=33(www-data),101(mysql)
EFFECTIVE_UID: 33
PHP_CWD:      /var/www/html/wp-content/plugins/lab219probe
```

This matters because `docker exec` runs as root and would have proved nothing about the web path. `groups=…,101(mysql)` is the group the entrypoint added at `/entrypoint.sh:66` (`usermod -aG mysql www-data`), and it is the reason the docroot is `www-data`-owned: `/entrypoint.sh:129` runs `chown -R www-data:www-data /var/www/html`.

### Hop 5 — the witness, green in both directions

Per the runbook's rule for vectors that need an oracle, the payload's effect was proved by an artefact the identity under test created, carrying a run nonce, read back **out of band** (a different channel from the one that wrote it):

```
out-of-band (docker exec):
  /tmp/lab219_witness_L219R7q2x9m4k  644 www-data:www-data  37 bytes
  content: written-by-uid=33 nonce=L219R7q2x9m4k
  negative control: /tmp/lab219_witness_NEVERWROTE999 -> No such file or directory
```

The witness is distinguishable by design (random nonce, `/tmp` path, ownership set by the writer), and the negative control proves the path was not pre-populated. Without the control, "the file exists" would be consistent with "something else put it there".

### Hop 6 — the reward, then the privesc that is not there

`cat /home/flag.txt` through the web path returned the reward. `/home/flag.txt` is `644 www-data:www-data`, which is why the reward is reachable at the **first** hop and the escalation is not needed to collect it. The escalation was then measured anyway, as `uid=33`, and found broken — §6.

---

## 4. Findings

Separated by what they actually are, never merged.

### Reachability

**R1 — Unauthenticated, state-changing AJAX handler in Pie Register.** `pie-register.php:615` registers `wp_ajax_nopriv_pireg_update_invitation_code`, so the handler at `pie-register.php:7212` is reachable with no session and processes attacker-supplied `$_POST['data']` (id, type, value), issuing an `UPDATE` against the plugin's code table.

Evidence with a control, unauthenticated in both cases:

| Request | Response |
|---|---|
| `POST admin-ajax.php?action=pireg_update_invitation_code` with `data[id]=999999` | `http=200`, body `error` (5 bytes) — handler ran |
| `POST admin-ajax.php?action=zz_no_such_action_9f3a` | `http=400`, body `0` (1 byte) |

**CWE-306 / CWE-862.** Impact is bounded: `$inv_code_id` is passed through `intval()` at `pie-register.php:7217` and the value through `$wpdb->prepare()` at `:7247`, so this is **not** an injection. The realistic consequence is an unauthenticated attacker renaming or re-scoping invitation codes, i.e. a registration-gating control can be tampered with without credentials. Low severity, but it is a genuine unauthenticated write and the `nopriv` registration is the whole finding. The `id` used here was chosen to match no row, so this test changed nothing in the database.

### Disclosed

**D1 — `phpinfo()` served from the docroot.** `/entrypoint.sh:131` writes `/var/www/html/info.php`, which answers `200` with 83351 bytes of PHP configuration.

*Positive control:* a URL that cannot exist returns `301`, not `200`. So the `200` is a real handler, not a catch-all. It discloses the exact `disable_functions` list, `open_basedir`, `DOCUMENT_ROOT`, absolute filesystem paths, and the loaded module set — the reconnaissance shortcut that removes most of the guesswork from the rest of the chain. **CWE-200. High value to an attacker, trivially removable by the operator.**

**D2 — Database credentials and the admin credential in the build artefact.** `wpuser`/`wppass` (`/entrypoint.sh:37-44`) and `admin`/`admin` (`:115-116`). D2 is the *decisive* finding as well; it is listed here because it is also disclosure. **CWE-798 (Use of Hard-coded Credentials).**

**D3 — Passwordless sudo grant naming an absent binary, and a world-writable `/opt`.** `/etc/sudoers:32,34` plus `/opt` at `757 root:root`. As shipped this grants nothing (§6), but the *configuration* would be a full `www-data → bobby → root` ladder the moment any interpreter appeared at that path. `www-data` is world-write-capable in `/opt`, so the design intent is unmistakable. **CWE-250 / CWE-732.**

### Decisive

**F1 — Default WordPress administrator credential gives full control of the application.** `admin`/`admin` from `/entrypoint.sh:115-116` authenticates to `/wp-admin/` and yields the plugin-upload primitive, which converts to arbitrary PHP execution as `uid=33(www-data)`. **CWE-798 / CWE-1392 (Use of Default Credentials).** Root cause: the credential is baked into the image build rather than supplied at deploy time, so every fresh deployment of this image ships the same administrator password. This is the vulnerability the catalogue advertises, and it is the only element needed to collect the reward.

**F2 — Full remote code execution as `www-data` via authenticated plugin upload.** Mechanism: administrator session → `update.php?action=upload-plugin` → attacker-controlled `.php` extracted into a web-reachable, executable path. `disable_functions` blocks only `pcntl_*`, so `shell_exec` executes. **CWE-434 (Unrestricted Upload of File with Dangerous Type)**. By design this requires administrator, so it is not an independent vulnerability — filed with F1 as the consequence, because a reader who patches only F1's credential still has F2, and a reader who patches only F2 still has F1.

**F3 — The advertised privilege escalation is non-functional in the shipped image.** Not a finding against the operator so much as a reportable defect in the lab, and the single most useful thing this engagement produced. Full evidence in §6. **CWE-284-adjacent: a privilege boundary expressed only in configuration, with no executable to enforce it.**

### A finding I deliberately did not file

**The Pie Register role-import flaw is not unauthenticated.** `import_user_from_json` at `pie-register.php:7351` takes the role straight from attacker-supplied JSON (`$user_role = $user['user']['roles'][0]` at `:7362`) and applies it with `set_role($user_field['role'])` at `:7400`. That is a textbook privilege-escalation primitive and it is the kind of finding a WordPress chapter would file as unauthenticated. **It is not.** The containing feature is gated at `pie-register.php:3088` (`add_submenu_page(..., 'manage_options', ...)`) and the handler is nonce-checked at `:5084`. Reaching it requires an existing administrator. Since an administrator can already assign any role, this is not a privilege boundary crossing at all. **Discarded with reason, not silently dropped** — see §7.

---

## 5. Instrument failures

The mandatory section, and the most valuable one. Every entry is a place where **my own instrument** lied, counted wrong, or handed me a clean negative it had not earned.

### I1 — `shell_exec` swallowed stderr and I nearly filed the privesc as "produces no output"

**Defect.** My first pass at the privesc measurement sent four commands through the probe's `shell_exec()` sink and got output for exactly one. `sudo -n -l` returned its policy; `ls -l /usr/bin/python3`, `command -v python3 python python2`, and `sudo -n -u bobby /usr/bin/python3 -c 'print(1)'; echo SUDO_RC=$?` all returned **completely empty bodies** with `http=200`.

**What it would have caused me to file.** "The sudo grant produces no output." Read as a *negative* that is a serious mistake, because the three silent commands are exactly the three that matter: an empty body from `ls` on a missing file and from `sudo`'s error is indistinguishable from "the command never ran" and from "sudo silently succeeded". I would have had a `200 OK` and a blank body backing a claim that the escalation was inert — the same claim the lab actually turns out to support, reached for the wrong reason. **A right answer for a wrong reason is how a false negative becomes a finding**, and §6's entire honest-negative argument rests on this observation being correct rather than accidentally correct.

**Class.** Instrument that captures only one of two output channels. `shell_exec()` returns stdout; `ls` writes "No such file or directory" to stderr and `sudo` writes "command not found" to stderr. `http=200` confirms the sink ran, not that it reported.

**Fix applied.** Re-ran all three with `2>&1` appended inside the command string. The negatives then became earned, with discriminating detail and exit codes:

```
ls: cannot access '/usr/bin/python3': No such file or directory      RC=2
command -v python3 python python2  (no output)                      RC=127
sudo: /usr/bin/python3: command not found                          SUDO_RC=1
```

**The general rule this earns:** a negative that arrives as an *empty success* is not a negative. It is an absence of observation. Every negative in §6 is quoted with its stderr and its exit code for this reason.

### I2 — I measured the identity on the wrong side of the trust boundary first

**Defect.** My first privesc measurements ran through `su -s /bin/sh www-data -c '...'` from a `docker exec` harness. That is a *correct* uid and it did prove the policy, but the brief's rule is stronger and I had adopted the weaker instrument by habit: the execution identity must be read back from inside the running context, because a harness proves the harness.

**What it would have caused me to file.** A chain step whose identity evidence is "I ran `su` and it said www-data" — which cannot distinguish "the web server runs as www-data" from "I can become www-data with root", the exact confusion the rule exists to prevent. In a lab whose whole escalation story turns on *which* identity holds the sudo grant, that is not a pedantic difference.

**Class.** Verification performed by the party whose privilege is in question. The instrument inherits the trust of the caller, so it cannot independently corroborate the caller's own claim.

**Fix applied.** Re-measured the identity, the sudo policy, the interpreter absence and every writability claim through the web path itself — `uid=33(www-data)`, read from PHP inside the running Apache child. All of §3 Hop 6 and §6 cite the web-path measurement. The `su` result is retained in this writeup only as corroboration, never as the load-bearing evidence.

### I3 — `-L` made a resource I had already deleted look like it still answered `200`

**Defect.** During restore verification I requested the probe URL with `curl -L` and recorded `http=200`. My restore was, in that moment, reported as **failed**.

**What it would have caused me to file.** Either a false finding ("cleanup failed, the webshell is still live") or, worse, a botched remediation — leaving a `lab219probe` directory in the docroot because I could not get a clean `404` out of it. The truthful state was that the resource was gone.

**Class.** Redirect-following collapses a response chain into one number. `-w '%{http_code}'` under `-L` reports the **last** hop, so a `301 Moved Permanently` to a nonexistent path — which is exactly what Apache emits for a deleted `.php` in a deleted directory — is reported as the final code, and WordPress renders its own soft page with `200`. The `-L` flag destroyed the very evidence that would have settled it.

**Fix applied.** Re-requested without `-L` and captured headers and body separately:

```
HTTP/1.1 301 Moved Permanently
Location: http://172.17.0.2/wp-content/plugins/lab219probe/lab219probe.php/
body: 0 bytes
```

and confirmed the filesystem state directly: `test -e` → `DIR-GONE`, `stat -c` → `No such file or directory`. The filesystem is the authority on whether a file exists; the HTTP layer was never going to give me a clean answer here.

**General rule:** verify restoration with `stat -c` on the path, and treat an HTTP status on a deleted resource as uninformative. An HTTP code answers "what did the server say", never "does this file exist".

### I4 — a docroot hash mismatch that I nearly filed as an incomplete restore

**Defect.** After removing the probe, the plugins directory was byte-identical to its pre-engagement snapshot, but the **whole-docroot** hash still differed:

```
pre : ecdffb96fd128b6e8a5e2f0cd7cc8d378aa62410c28dac0c6af550ad92b8f6e9
post: acc26d4352b399b5ff225a481e59058d464a83c7dc466b6797937ee21e360201
```

**What it would have caused me to file.** "Restore incomplete — unexplained modification to the target." A hash that does not return to its pre-engagement value is precisely the signature of a write I failed to account for, and the correct instinct is to treat it as a real residue rather than a rounding error.

**Class.** A hash answers "is this the same?" and not "what differs?". A single opaque digest gives a binary verdict with no attribution, so the reader — including me — is left to guess. The instinct to escalate on a mismatch is right; escalating without an attribution step is not.

**Fix applied.** Listed docroot files by modification time newer than the engagement start. Exactly one file qualified:

```
/var/www/html/wp-content/debug.log   644 www-data:www-data  1635 bytes
```

whose contents are my own error trail — the two `file_get_contents(...failed to open)` warnings from the rejected plugin-editor attempts, and one `wp_version_check()` warning. **This is the target writing about me**, not an artefact I left: `wp-config.php` sets `WP_DEBUG_LOG` true and `WP_DEBUG_DISPLAY` false (`/entrypoint.sh`, the `--extra-php` block), so the target's own telemetry records the engagement. That is the correct end state for a log, and truncating it would destroy the target's incident record. It is disclosed here rather than cleaned.

**What I still cannot state, honestly:** I snapshotted the plugins directory and the docroot hash before starting, but **not** `debug.log`'s size. So I can prove *which* file changed and *why*, and that it grew, but I **cannot** state the exact byte delta. That is a gap in my own instrumentation, recorded here instead of papered over.

### I5 — two `HTTP 500`s that read like "no write primitive exists"

**Defect.** Two attempts to create a PHP file through the WordPress plugin editor returned `HTTP 500` with the body `File does not exist! Please double check the name and try again.`

**What it would have caused me to file.** "No server-side file-write primitive is available; the admin session does not convert to code execution." A `500` is an unhandled-error code; in a lab with `display_errors` off and no PHP surface to read, an unhandled `500` is easy to attribute to the environment rather than to a specific business rule.

**Class.** Uninformative failure code standing in for a specific, documented rule. The status code says "the request broke"; only the body says *which rule* broke it. The rule here is benign and in fact helpful — WordPress 6.9.1's editor will only edit files that already exist — so the 500 was the application correctly refusing to create a file, not the application being broken.

**Fix applied.** Read the response body, which named the rule, and changed strategy to the upload path instead of retrying the editor. Both 500 bodies are retained (`r09_create.txt`, `r10_create2.txt`) precisely because a `500` with no body would have been unciteable.

### I6 — a `302` from the wrong endpoint, which is what success also looks like

**Defect.** I posted the plugin zip to `/wp-admin/plugin-install.php?tab=upload` and got `http=302`. I initially read that as "uploaded". It was not: the form's real action is `update.php?action=upload-plugin` (read from the form element), and the `302` was just a bounce. Verified out of band — the extracted file did not exist.

**What it would have caused me to file.** "Plugin upload succeeded" and then, having found no file, a contradictory "the upload silently failed", with a real RCE primitive discarded somewhere in between. The dangerous part is that `302` is genuinely ambiguous: it is what both success and a wrong-endpoint redirect produce.

**Class.** A status code shared by two opposite outcomes, in a workflow where the success artifact is not in the response body. **Fix applied:** resolved the real `action` attribute from the form, re-posted to it, got the body `Plugin installed successfully.`, and — decisively — verified the artifact on disk with `stat -c` out of band. Where a write either happens or does not, the filesystem is the oracle, not the status code.

### I7 — my evidence filenames collided, so two requests share an `r13` prefix

**Defect.** I saved the follow-up-to-`302` response as `r13_upload_result2.html` and the successful upload as `r13_upload_ok.html`. Two distinct requests, one request number, and the numbering skips nothing but is not unique.

**What it would have caused me to cite.** A reader mapping `evidence/` back to the work count in `workcount_full.txt` would find two files for request 13 and no way to order them. In a corpus whose §5 is specifically about instruments that produce confident-looking but untraceable output, shipping non-unique evidence identifiers is the same failure in miniature.

**Class.** Bookkeeping defect: identifiers allocated from a counter that was incremented by intent rather than by completion. **Fix applied:** the full request-to-file mapping is written out explicitly in `evidence/workcount_full.txt`, which is unambiguous even though the two filenames share a prefix. The collision is disclosed rather than renamed away, because renaming would hide that it happened.

### I8 — the narrow work-queue label pointed at the wrong objective

**Defect.** The work queue describes this lab as "WordPress platform plus Linux privesc", which frames the escalation as the goal. The catalogue — the authority — advertises a *site*, *a vulnerability*, and an *escalation*, and the artefact contradicts the queue on two counts: the decisive vulnerability is a build-artefact credential rather than a platform weakness, and the escalation cannot be completed at all.

**What it would have caused me to do.** Spend the engagement driving at root via a broken sudo grant, and — when that dead end arrived — either report a fabricated escalation or file a false negative against the lab's own advertised third element. The brief warns that a previous engagement in this repository was mis-scoped from a queue label and produced a false negative on three of four advertised elements. The correct response is to treat the queue label as a hypothesis and the catalogue plus the artefact as the facts.

**Class.** Scope inherited from a summary rather than read from the specification and the artefact. **Fix applied:** all three catalogue elements were tracked as separate objectives with separate outcomes (§0 table), and the element that could not be reached is reported as an explicit absence in §6 rather than dropped.

---

## 6. Reward

**The reward was recovered, through the web path, as `uid=33(www-data)`:**

```
LNDSG98DSFG7D8SGY8SDFG9
```

Obtained by `cat /home/flag.txt` executed by the probe through the authenticated web path (`evidence/flag_via_webpath.txt`), with the file's ownership independently measured as `644 www-data:www-data` (`evidence/final_state.txt`).

This is the **first** hop, not the end of the chain. `/home/flag.txt` is owned by `www-data` and world-readable, so the escalation is not required to collect it. The escalation was still measured, as `uid=33`, because the catalogue advertises it.

### The advertised Python privilege escalation: an explicit, measured absence

**Claim: `www-data` cannot become `bobby`, and `bobby` cannot become `root`, in this image. This is not a difficulty result — the mechanism is absent from the filesystem.**

Every observation below was made **from the web path as `uid=33(www-data)`**, not from a root harness (§5, I2).

**The ladder, exactly as configured** — `/etc/sudoers:32,34`:

```
www-data ALL=(bobby) NOPASSWD: /usr/bin/python3
bobby     ALL=(ALL)   NOPASSWD: /usr/bin/python3 /opt/backup.py
```

**The grant is real and sudo evaluates it** — this is the positive control, without which every negative below would be unearned:

```
$ sudo -n -l                       (as uid=33)
User www-data may run the following commands on 81548424282c:
    (bobby) NOPASSWD: /usr/bin/python3
```

sudo is present, functional, and parsing www-data's policy correctly. It is not that sudo is broken or that the rule is absent.

**The target of the grant does not exist:**

```
$ sudo -n -u bobby /usr/bin/python3 -c 'print(1)'    →  sudo: /usr/bin/python3: command not found   (rc=1)
$ ls -l /usr/bin/python3                              →  ls: cannot access ...: No such file or directory  (rc=2)
$ command -v python3 python python2                    →  (no output)  (rc=127)
```

**Work count behind this absence — 5 independent strategies, plus 4 corroborating from the source read:**

| # | Strategy | Result |
|---|---|---|
| 1 | `which python python2 python3` | nothing |
| 2 | `find / -xdev -name "python*" -o -name "*python*"` | only `/usr/share/gcc/python`, `/usr/share/nano/python.nanorc` — no interpreter |
| 3 | `find /` **without** `-xdev` (guards against a separate mount hiding it) | no interpreter |
| 4 | `find / -maxdepth 4 -name "python*" -type l` (symlink scan) | none |
| 5 | `dpkg -l \| grep -i python` (package database) | **no Python package installed at all** |
| 6 | `stat -c` on `/usr/bin/python3` directly | `cannot stat` |

**The gap cannot be closed from `www-data`.** The one remaining theoretical route would be to create the interpreter at the exact path sudo resolves:

```
/usr/bin      755 root:root   →  touch /usr/bin/.lab219  →  Permission denied  (USRBIN_NOT_WRITABLE)
/opt          757 root:root   →  touch /opt/.lab219_wtest  →  succeeded  (OPT_WRITABLE)
/opt/backup.py 644 root:root  →  write attempt  →  refused  (BACKUP_PY_NOT_WRITABLE)
```

`/opt` being `757` is the giveaway that the design is otherwise complete: the author *intended* www-data to stage a file there, which is what makes `bobby`'s `sudo /usr/bin/python3 /opt/backup.py` grant meaningful, and `backup.py:188` (`if os.geteuid() != 0`) confirms the script is built to run only as root. **Every link of the ladder is present except the interpreter.** `/usr/bin` is root-owned `755`, so www-data cannot supply the missing link either.

**Root cause, from the artefact.** `/home/bobby/.bash_history` records the image build's cleanup step:

```
apt-get clean
apt-get autoremove -y
rm -rf /var/lib/apt/lists/*
...
pip cache purge
```

The build installed tooling, then cleaned it out. The sudoers rules were left behind pointing at `/usr/bin/python3`, which the cleanup removed.

The precise mechanism is line 404, not lines 403 or 405. `apt-get clean` empties the package cache and
`rm -rf /var/lib/apt/lists/*` deletes the index; neither removes an installed binary from `/usr/bin`.
**`apt-get autoremove -y` is the command that deletes packages**, and it only touches packages apt recorded as
auto-installed. That the interpreter was auto-installed rather than requested explicitly is not directly provable
from the history, so this is the consistent explanation rather than a measured one — but it is the only line in that
history capable of producing the observed state, and the other two provably cannot. **This is a defect in the lab image, and it is reported as such rather than as a failed attack.** An operator reading this lab would otherwise reasonably believe the escalation is solvable and hunt for a technique that does not exist.

**If the interpreter were restored**, the intended chain would be: `www-data` → `sudo -u bobby /usr/bin/python3 <args>` (note the grant names the binary with **no argument restriction**, so this is an argument-injection primitive giving arbitrary code as `bobby`) → write `/opt/backup.py` as `bobby` (`/opt` is `757`) → `bobby` runs `sudo /usr/bin/python3 /opt/backup.py` as root. **I did not execute this**, because the first link cannot be taken; it is stated as the design read from `sudoers` and `/opt`, not as a result.

---

## 7. NOT tested

Kept strictly separate from the discarded-with-reason list in §4. These are untested, not closed.

| Not tested | Why it matters | Reason |
|---|---|---|
| **UDP of any kind** | The runbook is explicit that `nmap -p-` is TCP and hides whole classes (BMC/IPMI on `623/udp`). My surface came from `/proc/net/tcp`, which is **also TCP-only**. | `/proc/net/udp` was never read and no UDP probe was sent. **UDP is untested, not closed.** A management plane on UDP would be invisible to everything in §1. |
| **Root escalation by any route other than Python** | §6 proves the Python ladder is dead; it does **not** prove no root path exists. | I checked sudo policy, SUID, SGID, cron and writability of the key directories. I did not attempt kernel/container-escape classes, did not audit the full setuid binary surface against known local privesc, and did not test the MySQL service for a `LOAD DATA`/`INTO OUTFILE` write as `www-data` (group 101 `mysql`). **"The advertised escalation is broken" is a stronger claim than "no root exists", and only the first is proven.** |
| **`bobby`'s account directly** | `bobby` is the pivot in the intended chain. | No password attack on it. `/home/bobby` has no readable credential material and I did not attempt to obtain any. |
| **Pie Register's registration forms, login-security and 2FA features** | They are the plugin's main attack surface and could carry their own issues. | Registration is disabled at the WordPress level (`users_can_register=0`) and the plugin's own forms were not exercised. |
| **MySQL reachable on loopback** | `wpuser`/`wppass` are disclosed and the service is bound to `127.0.0.1`. | I confirmed the *external* negative (§1) but never connected to the loopback service to test what that credential can reach from inside. |
| **Akismet, Hello Dolly, the theme, and WordPress core 6.9.1 itself** | 6.9.1 is recent and the plugins are the default set. | No version-to-CVE mapping was attempted beyond noting the versions from the artefact. Not a clean bill of health — simply untested. |
| **Password spraying / rate ladder** | A rate-budget finding would be worth filing. | Moot: the credential came from the artefact, so no guessing was performed. **No rate control was exercised, and none is claimed.** |
| **What `/opt/backup.py` actually does when run as root** | It is the intended escalation payload. | It cannot be executed — the interpreter is absent and I have no root. It was read statically only. Its `os.geteuid() != 0` guard is confirmed at `backup.py:188`; **its behaviour as root is unverified.** |
| **Any second engagement / re-test of my own chain** | Freshness of the result. | Single pass. The reward was requested once through the web path. |

---

## 8. Evidence inventory

Only files a reader can obtain from the target, plus the measurements taken against it. All paths are relative to `corpus/219/evidence/`.

**Artefact and source reads (reproducible from the image)**

| File | Contents |
|---|---|
| `entrypoint.sh.txt` | `/entrypoint.sh` verbatim — the admin credential at `:115-116`, `info.php` at `:131`, the `chown -R` at `:129`, the `usermod -aG mysql www-data` at `:66` |
| `privesc_measured_from_webpath.txt` | First privesc pass, 4 commands, as `uid=33` — **the run that returned empty bodies. See §5 I1** |
| `privesc_stderr_captured.txt` | The same probes re-run with `2>&1`; the earned negatives with exit codes |
| `privesc_surface_from_webpath.txt` | `stat` of `/opt`, `/opt/backup.py`, `/usr/bin`, `/usr/local/bin` plus three write probes, as `uid=33` |
| `db_state_check.txt` | `wp plugin list` and `active_plugins`, proving the probe plugin was never activated |

**Recon and authentication**

| File | Contents |
|---|---|
| `recon_requests.txt` | Requests 1-4 with status and size |
| `info_control.txt` | Positive control that `info.php` is genuinely `phpinfo()` and that a nonexistent URL returns `301`, not `200` |
| `r02_info.html` | The `phpinfo()` output the stack table is parsed from |
| `r05_page6.html` | The login form (Pie Register serves `/wp-login.php` → `/?page_id=6`) |
| `r07_wpadmin.html` | Authenticated dashboard: `Howdy, admin` |
| `ctl_noauth.html` | The same URL with no session: the login page. The pair is the finding |
| `h06_headers_sanitized.txt` | Login response headers, cookie names and values redacted |

**Persistence and execution**

| File | Contents |
|---|---|
| `r08_plugineditor.html` | The plugin editor form and its nonce |
| `r09_create.txt`, `r10_create2.txt` | The two `HTTP 500` "File does not exist!" bodies (§5 I5) |
| `r11_upload.html` | The upload form, showing the real `action=update.php?action=upload-plugin` |
| `r13_upload_ok.html` | `Plugin installed successfully.` |
| `r14_identity.txt` | `uid=33(www-data) gid=33(www-data) groups=33(www-data),101(mysql)` read from inside the web process |
| `r15_witness_write.txt` | The witness write confirmation |
| `witness_oob_read.txt` | Out-of-band witness read: `644 www-data:www-data`, content, and the negative control for a nonce never written |
| `flag_via_webpath.txt` | The reward, obtained through the web path |
| `nopriv_handler_test.txt`, `nopriv_control.txt` | Finding R1 and its control |

**Restore**

| File | Contents |
|---|---|
| `prestate_plugins.txt`, `prestate_docroot_hash.txt` | Pre-engagement state: 828 paths with mode/owner/size, and the docroot digest |
| `poststate_plugins.txt`, `restore_diff_plugins.txt` | The diff showing exactly two added paths — both mine |
| `restore_actions.txt` | Removal of my two artefacts, and `stat -c` confirming both are gone |
| `restore_verification.txt` | Service still answering (`/` 200, `/wp-login.php` 302) and the misread probe status (§5 I3) |
| `restore_discrepancy_investigation.txt` | Attribution of the docroot hash mismatch to the target's own `debug.log` (§5 I4) |
| `final_state.txt` | Final state: `debug.log` is my error trail, `/tmp` clean, `/opt` holding only the shipped `backup.py` |
| `payload_probe.php` | The probe source that was uploaded, as written. **Removed from the target** |

**Accounting**

| File | Contents |
|---|---|
| `workcount_full.txt` | The **38-request** itemised accounting, the 5 explicit positive controls, and the declared bounds of every sweep |

### Restore statement

One write was made into the target: the plugin zip extraction at
`/var/www/html/wp-content/plugins/lab219probe/`. It was removed and verified with
`stat -c` (not a content check) plus a filesystem-level `test -e`, and the plugins
directory is **byte-identical to its pre-engagement snapshot (0 differences)**.
`/opt` and `/tmp` are clean. **The WordPress database was never modified** — the
probe plugin was never activated, so `active_plugins` is unchanged and no option,
user or post was touched. The only residual change is the target's **own**
`/var/www/html/wp-content/debug.log`, which grew because `WP_DEBUG_LOG` is enabled
in `wp-config.php` and it recorded my own rejected requests. That is the target's
telemetry behaving correctly; it was disclosed rather than truncated, because
deleting it would destroy the record of this engagement. Its exact pre-engagement
size was not snapshotted, so the byte delta cannot be stated (§5 I4).

**The container was left running and no image or container was removed, staged or
committed, per the brief.**
