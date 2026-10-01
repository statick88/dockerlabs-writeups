# 166 InfluencerHate — writeup

One authorized DockerLabs engagement. Id 166, name InfluencerHate, difficulty
`facil`. Target container `influencerhate_container`, image `influencerhate:latest`,
`172.17.0.3`.

---

## Headline: the queue's gap column changes the second route's class

`tooling/labs.manifest:79`

```
166|InfluencerHate|facil|brute force on a web form, then a second escalation route
```

The platform catalogue (`~/dockerlabs/catalog.txt:45`) reads, in full:

```
166|InfluencerHate|facil|Fuerza bruta en formulario web de apache y despu\u00e9s otra forma de fuerza bruta en formulario de login web.
```

That is *"brute force on an Apache web form and then **another form of brute
force** in a web login form."* The manifest replaced **"another form of brute
force"** with **"a second escalation route."** The second route is not an
escalation. There is **no escalation primitive anywhere on this host**, which is
a measured absence and not an inference:

| Primitive | Measurement |
|---|---|
| `sudo` | `ls: cannot access '/etc/sudoers': No such file or directory`; `ls: cannot access '/etc/sudoers.d': No such file or directory`; `which sudo` → not installed |
| cron daemon | `ps -eo pid,user,args \| grep -E "cron\|atd"` → `(none: cron not installed/running)`; `/var/spool/cron` does not exist. `/etc/cron.d/` holds only the stock `e2scrub_all` and `php` files |
| setuid | `find / -xdev -type f -perm -4000 \| wc -l` → **10**, all stock Debian (`passwd`, `su`, `mount`, `umount`, `newgrp`, `chfn`, `chsh`, `gpasswd`, `ssh-keysign`, `dbus-daemon-launch-helper`); none has a non-root-writable path to reach it (below) |
| nested container | `ls /var/run/docker.sock` → `No such file or directory`; `CapEff: 00000000a80425fb`, which is Docker's default mask, not the privileged `0x1ffffffffff` |
| file capabilities | `getcap -r /` → **empty**, `rc=0` |

There is no acronym in this catalogue entry to expand, so the self-correction
about abbreviations (`method/self-corrections.md` §28) does not apply. The
failure here is the neighbouring one: **the queue paraphrased the catalogue and
in doing so promoted a second brute force into an escalation**, which would have
put this lab in the privilege-escalation column of a class table it cannot
populate. This is a second instance of the §28 family with a different
mechanism — there, the queue expanded an abbreviation from memory; here, it
rewrote the sentence.

The platform label in the catalogue — *"formulario web de apache"* — **is
correct.** Read from version-bearing files, not from the queue:

```
$ apache2 -v
Server version: Apache/2.4.62 (Debian)
Server built:   2024-10-04T15:21:08

$ dpkg -l | grep '^ii  apache2  '
ii  apache2     2.4.62-1~deb12u2   amd64   Apache HTTP Server

$ php -v
PHP 8.2.28 (cli) (built: Mar 13 2025 18:21:38) (NTS)
ii  php8.2      8.2.28-1~deb12u1   all     PHP 8.2 (metapackage)
ii  php8.2-sqlite3  8:93           all     SQLite3 module for PHP [default]

$ cat /etc/os-release | head -3
PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
NAME="Debian GNU/Linux"
VERSION_ID="12"
```

---

## Surface

```
$ nmap -sV -Pn -p- 172.17.0.3
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u6 (protocol 2.0)
80/tcp open  http    Apache httpd 2.4.62
Service Info: Host: 172.17.0.3; OS: Linux
Not shown: 65533 closed tcp ports (conn-refused)
```

`nmap -p-` is TCP by definition, so the listening set was read from the
container's own kernel table as well:

```
$ docker exec influencerhate_container cat /proc/net/tcp
  sl  local_address rem_address st ...
   0: 00000000:0050 00000000:0000 0A ...     # 0x0050 = 80
   1: 00000000:0016 00000000:0000 0A ...     # 0x0016 = 22
```

Two sockets, both TCP. No UDP service, and none is claimed.

Startup (`PATH=/usr/bin:/bin docker logs`, **not** the environment's summarising
wrapper — see *Instrumentation defects*, item 5):

```
AH00558: apache2: Could not reliably determine the server's fully qualified domain name, using 172.17.0.3. Set the 'ServerName' directive globally to suppress this message
Starting Apache httpd web server: apache2.
Starting OpenBSD Secure Shell server: sshd.
```

### Every docroot path is behind one HTTP Basic challenge

`.htaccess` is honoured because the vhost sets `AllowOverride All`
(`/etc/apache2/sites-enabled/000-default.conf:11-15`, via
`sites-enabled/000-default.conf` → `sites-available/000-default.conf`):

```
    11	<Directory /var/www/html/>
    12	    Options Indexes FollowSymLinks
    13	    AllowOverride All
    14	    Require all granted
    15	</Directory>
```

Measured, unauthenticated:

| Request | Status | Bytes | Note |
|---|---|---|---|
| `GET /` | 401 | 457 | `WWW-Authenticate: Basic realm="Zona restringida"` |
| `GET /index.html` | 401 | 457 | |
| `GET /login.php` | 401 | 457 | |
| `GET /crear_db.php` | 401 | 457 | |
| `GET /database.db` | 401 | 457 | |
| `GET /.htaccess` | 403 | 275 | `Files` rule beats the authz gate |
| `GET /server-status` | 403 | 275 | `mod_status` loaded, restricted to `localhost` |
| `GET /icons/` | 403 | 275 | `No matching DirectoryIndex … and server-generated directory index forbidden by Options directive` |

---

## The two routes, and what actually separates them

The brief asks for the discriminator between the catalogue's two brute-force
routes. Stated generally:

> **They do not differ in transport and they do not differ in rate budget. They
> differ in the identity store and therefore in the KDF — one store runs apr1
> MD5-crypt, the other store has no KDF at all and holds the password in
> cleartext. Two stores, two principals, two implementations, two oracles, two
> remediations.**

| Axis | Route A | Route B | Same? |
|---|---|---|---|
| Transport | HTTP/80, Apache | HTTP/80, Apache | **yes** |
| Implementing component | `mod_auth_basic` + `mod_authn_file` (C) | PHP 8.2 + `php8.2-sqlite3` | no |
| Endpoint | `GET /login.php` with `Authorization: Basic` | `POST /login.php` form body | no |
| **Credential store** | `/home/.htpasswd`, flat file, mode `644 root:root` | `/var/www/html/database.db`, SQLite, mode `644 root:root` | no |
| Store contents | 1 entry | 1 row | — |
| Principal | `httpadmin` | `admin` | no |
| **KDF** | **`$apr1$` Apache MD5**, 1000 MD5 rounds | **none — the column *is* the password** | no |
| Success oracle | `200`, `WWW-Authenticate` challenge gone | **`200` either way**; body carries `alert-success`, 2943 B vs 2866 B | no |
| Failure oracle | `401`, 457 bytes | `200`, 2866 bytes, body carries `alert-danger` | no |
| **Rate budget** | **none** | **none** | **yes** |
| Reachable unauthenticated | yes | **no** — nested behind route A | no |

That table is the answer. Everything the two routes share is transport;
everything that matters is the store.

### Route A — Apache HTTP Basic against an apr1 htpasswd

`/var/www/html/.htaccess:1-4`, verbatim:

```
     1	AuthType Basic
     2	AuthName "Zona restringida"
     3	AuthUserFile /home/.htpasswd
     4	Require valid-user
```

`/home/.htpasswd:1`, verbatim, 48 bytes, mode `644 root:root`:

```
httpadmin:$apr1$xsEqxRe4$Zu0KmZkwmYS6PsUgLRG0P1$
```

`$apr1$` is Apache's MD5-based password hash. `mod_authn_file` is loaded
(`mods-enabled/authn_file.load`, `auth_basic.load`) and `Require valid-user`
resolves to `mod_authz_user`.

### Route B — a PHP form against a cleartext SQLite column

`/var/www/html/login.php:4-19`, verbatim:

```
     4	if ($_SERVER["REQUEST_METHOD"] == "POST") {
     5	    $usuario = $_POST["username"];
     6	    $contrasena = $_POST["password"];
     7	
     8	    $db = new SQLite3('database.db');
     9	    $stmt = $db->prepare("SELECT * FROM usuarios WHERE username = :user AND password = :pass");
    10	    $stmt->bindValue(':user', $usuario, SQLITE3_TEXT);
    11	    $stmt->bindValue(':pass', $contrasena, SQLITE3_TEXT);
    12	    $resultado = $stmt->execute();
    13	
    14	    if ($resultado->fetchArray()) {
    15	        $mensaje = "<div class='alert alert-success mt-3'>¡Login correcto! <strong>Enhorabuena! De parte del usuario balutin, te damos la enhorabuena</strong></div>";
    16	    } else {
    17	        $mensaje = "<div class='alert alert-danger mt-3'>Credenciales incorrectas.</div>";
    18	    }
    19	}
```

Line 9 binds `:pass` as a bound parameter, so the comparison at line 14 is a
plain SQL string equality against the stored column. **There is no KDF between
the request and the stored value.** Read out of the store with the container's
own PHP:

```
$ docker exec influencerhate_container php -r '$d=new SQLite3("/var/www/html/database.db");
  $r=$d->query("SELECT name,sql FROM sqlite_master"); while($x=$r->fetchArray(SQLITE3_ASSOC)) echo $x["name"]," | ",$x["sql"],"\n";
  $r=$d->query("SELECT rowid,username,password FROM usuarios"); while($x=$r->fetchArray(SQLITE3_ASSOC)) echo "row ",$x["rowid"]," user=",$x["username"]," pass=",$x["password"]," len=",strlen($x["password"]),"\n";'
usuarios | CREATE TABLE usuarios (username TEXT, password TEXT)
row 1 user=admin pass=chocolate len=9
```

**One row. No salt column, no hash column, `typeof(password)='text'`.** And the
credential is disclosed by a second artefact in the same docroot —
`/var/www/html/crear_db.php:1-9`, verbatim:

```
     1	<?php
     2	$db = new SQLite3('database.db');
     3	
     4	$db->exec("DROP TABLE IF EXISTS usuarios");
     5	$db->exec("CREATE TABLE usuarios (username TEXT, password TEXT)");
     6	$db->exec("INSERT INTO usuarios (username, password) VALUES ('admin', 'chocolate')");
     7	
     8	echo "Base de datos creada con usuario admin y contraseña chocolate.\n";
     9	?>
```

### Is route B genuinely a second finding?

Yes, on lab 243's test — *does fixing one fix the other?* — plus three more:

1. **Fixing route A does not fix route B.** The gate's remediation (throttle the
   Basic challenge, replace apr1, delete `.htaccess`) touches `mod_authn_file`
   and the htpasswd file. `login.php:9` still compares a cleartext column.
2. **Fixing route B does not fix route A.** Hashing the SQLite password with
   bcrypt and adding a lockout counter in `login.php` leaves the apr1 gate with
   no counter and no lockout.
3. **The principals are disjoint.** `httpadmin` exists in `/home/.htpasswd` and
   in no other store; `admin` exists in `usuarios` and in no other store.
   Success on one grants nothing on the other. Measured, not assumed: the
   shipped `/var/log/apache2/access.log` contains the author's own successful
   `httpadmin` sessions (`200`, rows 137-147) and *no* successful `admin`
   session in 88,369 POST rows.
4. **The oracles are independent and neither can stand in for the other.** Route
   A's oracle is a status-code transition (401 → 200). Route B returns **200 in
   both cases** — a status-code detector is always-true on route B.

So: **two findings, not one finding reported twice.** A route that differed only
in transport would be one finding; these differ in store, in KDF, in principal,
in implementing component and in oracle.

**But they are nested, not parallel, and a reviewer needs both facts.** Route B
is unreachable without route A. Measured: `POST /login.php` with the correct
`admin`/`chocolate` and **no** gate credential returns `401` / **457 bytes** —
Apache's stock 401 body, byte-identical to a route-A rejection. PHP never
executes. The byte count is what distinguishes "reached the PHP sink" from
"never reached it": 457 = Apache, 2866/2943 = `login.php`. **Consequence for the
remediation order: deleting the `.htaccess` to fix route A would expose route B
to unauthenticated reach.** That is the shape lab 220 recorded, and it is the
one thing a reviewer who merged the two findings would miss.

### A third route the catalogue does not name

Port 22 is a third credential store, and it is not in either the catalogue or
the manifest. `/etc/shadow`, mode `640 root:shadow`, quoted verbatim:

```
root:$y$j9T$AqUQ/eZw0AFIpz2wLD0ro/$8DoTsiBHjggoIgaqVCxWym.CktRR1.gEGd.StW9vUP0:20267:0:99999:7:::
balutin:$y$j9T$3QROnCz.BtcZZLtgrXDvd.$d3WTcjZJoWKT3.FufrvTBGwvIQBu7CdgSF16yJQZWnC:20267:0:99999:7:::
```

Two accounts with real yescrypt hashes, the rest `*` / `!` / `!*`. Measured on
it — see the rate table below. `docker history` was checked first (lab 188's
route) and carries nothing:

```
$ docker history --no-trunc influencerhate:latest
IMAGE    CREATED BY
sha256:ac334959...  15 months ago  CMD ["/bin/sh" "-c" "service apache2 start && service ssh start && tail -f /dev/null"]
<missing>            15 months ago  bash                    230MB
<missing>            15 months ago  # debian.sh --arch 'amd64' out/ 'bookworm' '@1749513600'   133MB   debuerreotype 0.15
```

A single squash layer. **No credential is recoverable from the build record**
here, which is the opposite of lab 188 and is reported as such.

---

## Rate: asserted in both directions

The corpus's standing measurement for "was the KDF actually running" is the
rate. A skipped KDF reads as the underlying primitive's own speed (the 44 M
candidates/s signature); a running KDF reads as the primitive divided by its
iteration count. Both directions are measured below, in one harness, with the
control that the oracle can report a match.

### Offline: apr1 versus a single MD5

`apr1.py` in `evidence/` is a transcription of `apr_md5_encode()`, read from
`apr_md5.c:504-666` fetched from `apache/apr` trunk, with per-line references in
its own comments. Its correctness is pinned against `openssl passwd -apr1`, not
against a second copy of itself:

```
$ for pw in password chocolate hunter2 "" "ñÁÉ" a "xxxxxxxx...(80)"; do
    a=$(python3 apr1.py "$pw" xsEqxRe4); b=$(openssl passwd -apr1 -salt xsEqxRe4 "$pw")
    echo "match=$([ "$a" = "$b" ] && echo YES || echo NO)"; done
match=YES   (x7, including the empty password and an 80-byte password)
```

Rate, 400 candidates per measurement, same process, same loop:

```
apr1:      candidates=400 elapsed=0.112s rate=3577.4/s
1x md5:    candidates=400 elapsed=0.000s rate=3263628.2/s
ratio apr1/1x-md5 = 912.3
```

Recomputed by hand from the rounded figures: `400 / 0.112 = 3571.4/s` for apr1
(the harness prints 3577.4 from an unrounded `perf_counter`), and
`3,263,628.2 / 3,577.4 = 912.3`. The apr1 iteration count in
`apr_md5_encode()` is **1000** (`apr_md5.c:617`), so a ratio of ~912 against a
single MD5 on the same inputs is the signature of **the KDF executing**. If the
hash function had been silently skipped or reduced to one MD5, this ratio would
be ≈1 and the apr1 rate ≈3.3 M/s. It is 3,577/s, three orders of magnitude
slower. Both directions asserted: the KDF is not running at 3.3 M/s, and it is
not running 1,000× slower than it should.

**Route B, by the same measure, has a rate of *zero* candidate evaluations per
full sweep, because there is nothing to crack.** That is the discriminator in
rate terms, and it is the reason the two routes cannot be one finding.

### In-band: the KDF ran on 82,674 requests, and Apache says so itself

`mod_auth_basic` emits two different message codes, and the difference is
exactly whether `mod_authn_file` reached the apr1 comparison:

```
AH01617: user httpadmin: authentication failure for "/login.php": Password Mismatch
AH01618: user admin not found: /login.php
```

`AH01617` can only be emitted after the user was located **and** apr1 was
evaluated **and** returned false. `AH01618` is returned before the KDF. So the
error log is an oracle that fires only when the KDF ran — which is stronger
evidence than any timing measurement, and it is the server's own count.

```
$ grep -c "AH01617: user httpadmin:" /var/log/apache2/error.log
82674
```

**82,674 KDF executions, all false.** Server-side, independent of my client's
bookkeeping. (Captured before the stage-9 restore, which resets the log — the
transcript and the exact command are in
`evidence/server-side-capture-pre-restore.txt`.)

### The ladder, against a latency baseline

Own harness rather than hydra: hydra's `-W`/`-T` is exactly the instrument that
produced lab 118's false negative, where the operator's own throttle read as
the target's filter. The ladder is therefore run with no client-side rate limit
at all, one keep-alive connection per worker, and a full status histogram per
rung so a block shows up as a *status change* and is never inferred from a
slowdown. The partition of candidates across workers is exact, asserted
non-overlapping and gap-free, and any rung that fills fewer slots **aborts the
ladder** instead of printing a rate.

**Route A** (`evidence/final_basic.out`):

```
BASELINE serial keep-alive candidates=120 elapsed=0.024s achieved=4963.1 cand/s median=0.0002s p95=0.0004s status={401: 120} oracle-hits=0
RUNG workers=64   candidates=20000 elapsed=1.322s achieved= 15126.2 cand/s status={401: 20000} bytes={457: 20000} median_latency=0.0005s hits=0
RUNG workers=128  candidates=20000 elapsed=1.488s achieved= 13444.2 cand/s status={401: 20000} bytes={457: 20000} median_latency=0.0008s hits=0
RUNG workers=256  candidates=20000 elapsed=1.575s achieved= 12700.1 cand/s status={401: 20000} bytes={457: 20000} median_latency=0.0014s hits=0
```

**Route B**, behind the gate (`evidence/final_form.out`):

```
BASELINE serial keep-alive candidates=120 elapsed=0.069s achieved=1728.8 cand/s median=0.0004s p95=0.0017s status={200: 120} oracle-hits=0
RUNG workers=64   candidates=20000 elapsed=2.258s achieved=  8858.5 cand/s status={200: 20000} bytes={2866: 20000} median_latency=0.0032s hits=0
RUNG workers=128  candidates=20000 elapsed=2.462s achieved=  8123.1 cand/s status={200: 20000} bytes={2866: 20000} median_latency=0.0032s hits=0
RUNG workers=256  candidates=20000 elapsed=2.619s achieved=  7635.9 cand/s status={200: 20000} bytes={2866: 20000} median_latency=0.0047s hits=0
```

A ten-rung ladder over both routes is in `evidence/ladder2_basic.out` and
`evidence/ladder4_form_gated.out`. Across every rung of both, **the status
histogram is a single key** — `{401: N}` on route A, `{200: N}` on route B — and
the byte count is a single value. No `429`, no `403`, no `Retry-After`, no
latency cliff.

Arithmetic, recomputed rather than read: `20,000 / 1.322 = 15,128.6 cand/s`
(harness prints 15,126.2 from an unrounded timer; 0.02% apart) and
`20,000 / 2.258 = 8,857.4 cand/s` (harness 8,858.5).

### The rate does not discriminate the two routes — stated because it is counter-intuitive

`15,126.2 / 8,858.5 = 1.71`. Route A is **1.7× faster in band** than route B,
despite running a KDF and route B running none. Route B pays PHP interpreter
start-up per request, which costs more than apr1's ~0.1 ms. **An in-band rate
ladder cannot tell these two routes apart**, and a report that leaned on rate as
the discriminator would have been wrong. The discriminator is the store.

### The rate budget on port 22 (`evidence/ssh_balutin.out`)

```
RUNG workers=1   attempts=60   elapsed=162.92s achieved=  0.37 attempts/s outcomes={'auth-fail': 60}                        median_latency=2.687s
RUNG workers=2   attempts=60   elapsed=83.65s  achieved=  0.72 attempts/s outcomes={'auth-fail': 60}                        median_latency=2.689s
RUNG workers=4   attempts=60   elapsed=43.37s  achieved=  1.38 attempts/s outcomes={'auth-fail': 60}                        median_latency=2.711s
RUNG workers=8   attempts=60   elapsed=26.90s  achieved=  2.23 attempts/s outcomes={'auth-fail': 55, 'ERR:SSHException': 5}   median_latency=2.697s
RUNG workers=16  attempts=60   elapsed=10.88s  achieved=  5.52 attempts/s outcomes={'auth-fail': 48, 'ERR:SSHException': 12}  median_latency=2.689s
RUNG workers=32  attempts=60   elapsed=8.16s   achieved=  7.35 attempts/s outcomes={'auth-fail': 40, 'ERR:SSHException': 20}  median_latency=2.714s
```

**Median latency is flat at 2.687–2.714 s across a 32× change in concurrency.**
A throttle would move; this does not. The achieved rate scales linearly
(0.37 × 32 = 11.8 predicted vs 7.35 measured, the shortfall being pre-auth
drops), which is the signature of a per-candidate CPU cost and nothing else.
There is no lockout: `sshd_config` has `MaxAuthTries`, `MaxStartups` and
`LoginGraceTime` **all commented out**, `/etc/ssh/sshd_config.d/` is **empty**,
and `UsePAM yes` is the only auth-related line set. The `ERR:SSHException`
entries are pre-auth connection drops (`Error reading SSH protocol banner` /
`Connection reset by peer`) — the default `MaxStartups 10:30:100` shedding load
on *concurrency*, which is a resource limit and **not** an authentication filter:
the attempts that survive still authenticate and still fail on the password.

---

## Chain

No chain closes on this lab. The identity measurements below are the whole
chain, because the point of this engagement is the credential store, not a
traversal.

| # | → | Mechanism | Identity proof |
|---|---|---|---|
| — | operator host | — | `uid=1000(search14) gid=1000(search14) groups=1000(search14),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),100(users),101(lxd),107(docker),1001(docs_tthh),1002(docs_ti),1003(docs_financiero),1004(docs_general),1005(docs_clasificador)` |
| 0 | `docker exec` into container | default identity, **root** | `uid=0(root) gid=0(root) groups=0(root)` |
| 0 | Apache master | starts as root | `/proc/25/status`: `Uid: 0  0  0  0` / `Gid: 0  0  0  0` |
| 0 | **Apache worker (per request)** | prefork drops privileges | `/proc/186/status`: `Uid: 33  33  33  33`; `/proc/187`, `/proc/240`, `/proc/241`, `/proc/258` all `33 33 33 33` |
| 0 | the identity `mod_authn_file` and PHP run as | `www-data` | `uid=33(www-data) gid=33(www-data) groups=33(www-data)` |
| 0 | the only non-system account | `balutin` | `uid=1000(balutin) gid=1000(balutin) groups=1000(balutin),100(users)` |
| 0 | container capability set | Docker default, not privileged | `CapEff: 00000000a80425fb` = Docker default (14 caps: `CHOWN DAC_OVERRIDE FOWNER FSETID KILL SETGID SETUID SETPCAP NET_BIND_SERVICE NET_RAW SYS_CHROOT MKNOD AUDIT_WRITE SETFCAP`), ≠ privileged `0x1ffffffffff`; `Seccomp: 2` |

**There is no setuid transition anywhere in this engagement**, and the claim is
backed by the full inventory rather than by an absence of mentions. All 14
setuid/setgid binaries, mode read with `stat` (**not** the `ls -l` size column,
which lab 83 mistook for a mode):

```
2755 root:shadow      /usr/bin/chage
4755 root:root        /usr/bin/chfn
4755 root:root        /usr/bin/chsh
2755 root:shadow      /usr/sbin/expiry
4755 root:root        /usr/bin/gpasswd
4755 root:root        /usr/bin/mount
4755 root:root        /usr/bin/newgrp
4755 root:root        /usr/bin/passwd
2755 root:_ssh        /usr/bin/ssh-agent
4755 root:root        /usr/bin/su
4755 root:root        /usr/bin/umount
4754 root:messagebus  /usr/lib/dbus-1.0/dbus-daemon-launch-helper
4755 root:root        /usr/lib/openssh/ssh-keysign
2755 root:shadow      /usr/sbin/unix_chkpwd
```

Every one is stock Debian; `getcap -r /` returns empty; and none was reached,
because no non-root identity can write anything on its path — measured with two
independent tools, below.

---

## Findings

### F1 — HTTP Basic auth on the whole docroot, no rate budget — CWE-307 (Improper Restriction of Excessive Authentication Attempts)

`.htaccess:1-4` puts every file under `/var/www/html/` behind
`AuthType Basic` + `Require valid-user`, and nothing counts attempts.

**Evidence.** 82,674 server-side `AH01617` KDF evaluations for `httpadmin`, all
false. 20,000 candidates in a single rung at **15,126.2 cand/s** (`20,000 /
1.322 s`), `status={401: 20000}`, `bytes={457: 20000}` — one status, one byte
count, 20,000 times. No `429`, no `403`, no `Retry-After` header, no latency
cliff at any of ten concurrency rungs from 1 to 512.

**No rate budget, proven from configuration and from measurement** — both, so
neither can be the only evidence:

| Mechanism | State |
|---|---|
| `fail2ban` | `which fail2ban-client` → absent; `/etc/fail2ban` → `No such file or directory` |
| host firewall | `iptables: command not found` |
| `mod_evasive` | not in `mods-enabled/`; not loaded (`apache2ctl -M \| grep -Ei "auth\|limit\|evasive\|throttle"` → `auth_basic_module`, `authn_core_module`, `authn_file_module`, `authz_core_module`, `authz_host_module`, `authz_user_module` only) |
| `mod_ratelimit` | present in `mods-available/ratelimit.load`, **not enabled** in `mods-enabled/` |
| `mod_security` | not loaded |
| application-level lockout | `.htaccess` has no counter and no database |

**Root cause.** `mod_authn_file` is a stateless comparator. Nothing in the
shipped configuration accumulates failures, and Apache ships with no
out-of-the-box brute-force defence. `mod_ratelimit` — the one module that could
have bounded throughput — is available in the image and simply not enabled,
which is worth saying to a client: the fix is a configuration line, not a
package.

**Impact.** Full docroot read at 15 k candidates/second with a single account
guessed from any wordlist. `httpadmin` is a web-only principal (absent from
`/etc/passwd`), so its compromise is bounded by what the docroot exposes —
which, per F2, is everything including a database.

**Remediation.** Enable `fail2ban` with an `apache-auth` jail, or enable
`mod_ratelimit`/`mod_evasive` at the vhost. Move off apr1: `$apr1$` is MD5 with
1000 rounds and 8 characters of salt, and it is the format `htpasswd -B` exists
to replace — bcrypt via `htpasswd -B`. Rotate `httpadmin`. Delete
`crear_db.php` (F2).

### F2 — The credential store is downloadable over HTTP — CWE-538 (Insertion of Sensitive Information into Externally-Accessible File) / CWE-312 (Cleartext Storage of Sensitive Information)

Both files that hold or disclose a credential sit **inside the document root**
and are served verbatim. Measured, behind the gate:

```
$ curl -u "<gate>" -D - http://172.17.0.3/crear_db.php
HTTP/1.1 200 OK
Content-Length: 64
Content-Type: text/html; charset=UTF-8

Base de datos creada con usuario admin y contraseña chocolate.

$ curl -u "<gate>" -o dl.db -w 'code=%{http_code} bytes=%{size_download}\n' http://172.17.0.3/database.db
code=200 bytes=8192

$ python3 -c "import sqlite3; c=sqlite3.connect('dl.db'); print(c.execute('select sql from sqlite_master where name=\"usuarios\"').fetchone()[0]);
             [print(r) for r in c.execute('select rowid,username,password,length(password),typeof(password) from usuarios')]"
CREATE TABLE usuarios (username TEXT, password TEXT)
(1, 'admin', 'chocolate', 9, 'text')
```

The 8,192-byte SQLite file downloads intact; the recovered copy in
`evidence/dl.db` opens and yields the row. `strings -a` on it reads
`adminchocolate` as one literal.

**This is what makes route B not a brute force at all.** The catalogue promises
a second brute-force form; an attacker who gets past F1 does not brute force it,
they download the store, or they `GET /crear_db.php` and read the credential out
of the response body. Both routes of obtaining `admin`'s password were measured.

**Root cause.** `database.db` — the live credential store — was created inside
the document root (`$db = new SQLite3('database.db')`, resolved relative to the
script at `crear_db.php:2` and `login.php:8`), and the setup script that
discloses the password was deployed alongside it.

**Remediation.** Move both outside the docroot; `database.db` to `/var/lib/` with
`640 www-data:www-data`; delete `crear_db.php` from the image, not just
chmod it, since its whole function is to print the credential.

### F3 — Cleartext password storage, no KDF, no salt — CWE-256 (Plaintext Storage of a Password)

`login.php:9` binds the submitted password as a SQL parameter and compares it to
the stored column; `usuarios` has two `TEXT` columns and no hash, no salt, no
work factor. `typeof(password)='text'`, `length=9`, value `chocolate`. One row.

**Evidence.** The store's own `CREATE TABLE` statement and the row, read two
independent ways — through the container's PHP (`row 1 user=admin pass=chocolate
len=9`) and through the HTTP-downloaded copy on the host (`(1, 'admin',
'chocolate', 9, 'text')`).

**Rate consequence, and this is the point.** Route A's store costs an attacker
3,577.4 candidate evaluations per full sweep, because every candidate must run
apr1. **Route B's store costs zero**, because there is nothing to evaluate — the
submitted string *is* the stored string. The two routes differ by a factor that
is not a finite number.

**Remediation.** `password_hash($contrasena, PASSWORD_DEFAULT)` (bcrypt/argon2)
and `password_verify()` on read. Never compare a submitted secret to a stored
secret with `=`.

### F4 — Username enumeration through the server error log — CWE-203 (Observable Discrepancy)

`mod_auth_basic` distinguishes AH01617 (user found, password mismatch) from
AH01618 (user not found) **in `/var/log/apache2/error.log`**, which is written at
the stock `LogLevel` and readable by anyone in group `adm`
(`-rw-r----- 1 root adm 640`). Over 82,674 of my requests:

```
$ grep -oE "AH0161[78]: [^:]*: ?" /var/log/apache2/error.log | sort | uniq -c
 10433 AH01617: user httpadmin:      <- KDF ran, result false
   200 AH01617: user zzcontrol:
    25 AH01618: user admin not found:
    26 AH01618: user <other> not found:
   ... 50 further distinct usernames, all AH01618
```

Every account in a wordlist is resolvable to "exists / does not exist" by anyone
who can read the log. This is the same message that proved the KDF runs, so it
is one artefact serving two purposes — the disclosure is in Apache's default
logging, not in the lab's configuration.

**It is not remotely exploitable and I am not claiming it is.** Measured
negatives, 200 requests per case: the `401` body is **457 bytes and
byte-identical** for a present username, an absent username and a present
username with a wrong password; and the timing is not separable —
present-with-wrong-password median **0.0003 s**, absent-username median
**0.0002 s**, present-and-correct median **0.0004 s**, with p10 of the
present case (0.0002 s) equal to the absent median. A 0.1 ms difference does not
survive jitter at 0.1 ms resolution. **No usable HTTP oracle; a usable log
oracle.**

**Remediation.** Do not log which stage of authentication failed — set
`LogLevel auth_basic:warn` or higher for that module, or accept the log-side
enumeration as an accepted risk with awareness.

### F5 — Debian Apache logs `%O`, so the access-log size column includes headers — a measurement trap, not an attacker-facing bug

`/etc/apache2/apache2.conf:213`:

```
LogFormat "%h %l %u %t \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i\"" combined
```

The size column is **`%O`** (bytes sent including HTTP headers), not `%b`
(body only). Any corpus technique that discriminates by byte count — a hash of a
normalised body, a size delta between the success and failure bodies — reads the
log and is wrong by a constant.

Measured for one request at one instant, by two independent clients:

```
python http.client : status=200  Content-Length header = 2866   len(body) = 2866
curl              : code=200  size_download=2866  size_header=173
/var/log/apache2/access.log              : "POST /login.php HTTP/1.1" 200 3039
```

`3039 − 2866 = 173`, which is exactly curl's `size_header`. Recomputed for the
success body: `3116 − 2943 = 173`. And for the GET:
`2971 − 2798 = 173`. Three independent pairs, one constant.

The correct in-band discriminator for route B is therefore **2866 vs 2943 bytes
off the wire** — a 77-byte difference — and *not* the 3039 vs 3116 the log
shows. Both deltas happen to survive, but only one of them is the body.

**This is reported as a finding because it produced a confident wrong number in
my own engagement before I caught it.** It is also a live hazard for anyone
reading these artefacts later. One residue is unresolved and is *not* guessed
away: 357 of 76,240 POST rows (0.47%) logged `3058`, a header size of 192 —
19 bytes more than 173, exactly `len("Connection: close\r\n")`. I did not isolate
which client path produced it.

### F6 — The gate's own password store is world-readable — CWE-732 (Incorrect Permission Assignment for Critical Resource)

`/home/.htpasswd` is `-rw-r--r-- 1 root root 48`. With the positive control that
the mode is not a boundary for the identity that matters:

```
$ su -s /bin/bash www-data -c "cat /home/.htpasswd"
httpadmin:$apr1$xsEqxRe4$Zu0KmZkwmYS6PsUgLRG0P1
rc=0
```

`www-data` — the identity the webserver runs as — reads the hash file, and so
does the one non-system account. Measured as each identity, not inferred from the
mode:

| identity | reads `/home/.htpasswd` | writes it | reads `/var/www/html/database.db` | writes it |
|---|---|---|---|---|
| `root` (`uid=0`) | YES | YES | YES | YES |
| `www-data` (`uid=33`) | YES | **NO** | YES | **NO** |
| `balutin` (`uid=1000`) | YES | **NO** | YES | **NO** |

So this is read-only disclosure, not tampering — the `644` is not a privilege
boundary in either direction. Standard `htpasswd` practice is
`640 root:www-data`.

The same table covers the SQLite store (`-rw-r--r-- 1 root root`), and there the
disclosure is complete rather than partial — see F2.

---

## Controls that held

Each control is paired with the positive control that proves its detector can
fire. A control that has never reported a success is not a control, so the
positive ran **before** each negative and, where the oracle is cheap, **after** it
as well.

| Control | Held? | Positive control that proves this detector works |
|---|---|---|
| HTTP Basic gate over the whole docroot | **yes** | `curl -u httpadmin:wrong` → `401`, 457 B, `WWW-Authenticate: Basic realm="Zona restringida"`; the correct-credential probe below returns `200`, 2798 B |
| `AllowOverride All` is real, not decorative | yes | the gate fires on 5 of 8 probed paths with a consistent `401`+`WWW-Authenticate` pair, and the 3 `403`s are explained by `Files`/autoindex rules, not by the authz gate |
| Apache does not enumerate usernames over HTTP | yes | 3 cases × 200 requests: present+wrong, absent, present+correct. Bodies 457/457/457 **byte-identical**; medians 0.0003/0.0002/0.0004 s — not separable |
| `mod_status` is restricted | yes | `GET /server-status` → `403`, `AH01630: client denied by server configuration` |
| dotfiles are not served | yes | `GET /.htaccess` → `403`, `AH01630` — the gate config is not itself readable |
| `login.php`'s query is parameterised — **no SQLi** | yes | control fired **twice**, before and after: `admin`/`chocolate` → `200`, 2943 B, `alert-success` **both times**. Between them, 5 injection payloads all → `200`, 2866 B, `alert-danger`: `' OR 1=1-- ` on username, on password, `admin' OR '1'='1`, `' UNION SELECT 1,2-- `, and `chocolate'`. Bracketing the negatives with two firings of the oracle is stronger than one |
| No non-root identity can write any file on a privilege path | yes | two independent tools, disagreeing is the point: `find / -xdev -type f -writable \| wc -l` → **12275** (run as root, therefore meaningless — see defects), while `test -w` run *as* each identity says `NO` for `/etc/passwd`, `/etc/shadow`, `/home/.htpasswd`, `/var/www/html/database.db`, `login.php`, `.htaccess`, `apache2.conf`. Filtering the root-run `find` by non-root owner yields only **4** files, all of them `/home/balutin`'s own dotfiles |
| Container is not privileged and exposes no socket | yes | `Privileged=false CapAdd=[] SecurityOpt=[]`; `CapEff=00000000a80425fb` = Docker default; `ls /var/run/docker.sock` → absent. **Contrast lab 141**, where the socket was exposed and a container *with* the socket was the positive control |
| No setuid-to-root path | yes | `find / -xdev -type f -perm -4000 \| wc -l` → **10**, all enumerated by `stat` above, all stock, none with a non-root-writable parent; `getcap -r /` → empty |
| The archive is not holding a secret | yes | `docker history --no-trunc` → 3 rows, one `bash` squash layer of 230 MB plus a `debian.sh` base layer; no `chpasswd`, no credential |

### The two credential-store oracles, proved green

**Route A** — a manufactured same-code-path positive control. An entry
`zzcontrol:$apr1$ZZZctrl0$…` was appended to `/home/.htpasswd`, then queried
over HTTP with that same code path (`mod_auth_basic` → `mod_authn_file` →
`apr1`):

```
POSITIVE CONTROL status=200 bytes=2798 oracle_fires=True
body head: \n<!DOCTYPE html>\n<html lang="es">\n<head>\n    <meta charset="UTF-8">\n    <title>Login - Cr\xc3\xadtica a los Youtubers</title>
```

and, to close the loop, the *same* store entry with a wrong password:

```
zzcontrol   /WRONG_PASSWORD_166   n=200 status={401: 200}  -> KDF ran, result false
zznosuch    /WRONG_PASSWORD_166   n=200 status={401: 200}  -> mod_authn_file returned before the KDF
zzcontrol   /zz_control_password_166 n=200 status={200: 200} -> KDF ran, result true
```

**Route B** — `admin`/`chocolate` against the real SQLite store, behind the gate:

```
user=admin  pass='chocolate'   status=200 bytes=2943 success=True  danger=False
user=admin  pass='chocola'     status=200 bytes=2866 success=False danger=True
user=admi   pass='chocolate'   status=200 bytes=2866 success=False danger=True
user=admin  pass='chocolate '  status=200 bytes=2866 success=False danger=True
```

**Both control entries were removed and the store was byte-verified afterwards.**
This is the discipline, not a formality — the mutation is recorded here with its
checksum:

```
before:  2b102cb638ef39066188ab952f27634fe19d81dedd2fe152ca78b5987c0599c1  /home/.htpasswd   (48 bytes, 644 root:root)
after:   2b102cb638ef39066188ab952f27634fe19d81dedd2fe152ca78b5987c0599c1  /home/.htpasswd
after:   c31f313852dcfc4fdc57d4fa48ca532f  /var/www/html/database.db
after:   ls -la /home/ -> .htpasswd only; no .htpasswd.bak, no .htpasswd.166bak
```

The round trip was performed **four** times (route-A oracle, timing probe, route-B
ladder gate, `/crear_db.php` and `/database.db` retrieval) and the sha256 matched
the shipped value every time. `crear_db.php` was executed once, deliberately: it
runs `DROP TABLE IF EXISTS usuarios` followed by an identical `INSERT`, and
`database.db`'s md5 is **unchanged** across it, so the store's *content* was
value-preserving — stated here because a reader deserves to know the credential
store was written to once and why it is still correct.

---

## Negatives, each with its work count

Every negative below carries the count of work that produced it. **A count of
zero is UNTESTED and appears in the NOT-tested list, not here.**

### `httpadmin`'s password was not recovered — 759,617 candidates, 0 matches

The shipped apr1 hash resisted every dictionary available on this host. All of
it offline, at ~3,500 candidates/s, against the KDF this engagement proved is
running:

| Dictionary | Bytes read | Unique candidates | Result |
|---|---|---|---|
| `PenTestMethodology/wordlists/Passwords.txt` | 5,166,141 | 421,445 | no hit |
| `PenTestMethodology/wordlists/sorted-passwords.txt` | 1,093,766 | 0 (fully contained in the above) | no hit |
| `PenTestMethodology/wordlists/2025-sort-uniq-words.txt` | 1,174,030 | 125,472 | no hit |
| `/usr/share/nmap/nselib/data/passwords.lst` | 40,146 | 2,267 | no hit |
| **subtotal** | | **549,184** | **NO HIT** — `evidence/crack.out`, 170.16 s, 3,227.5 cand/s |
| thematic list derived from the page text and the lab's own vocabulary | — | 1,241 | no hit |
| second thematic list (2-word combinations, case and suffix variants) | — | 2,432 | no hit |
| numeric range 0-99,999 + zero-padded + 7 stems × 0-999 | — | 117,007 | no hit |
| suffix/prefix/case mutations of the top 6,000 of `Passwords.txt` | — | 89,753 | no hit |
| **total** | | **759,617** | **0 matches** |

Recomputed: `549,184 + 1,241 + 2,432 + 117,007 + 89,753 = 759,617`.

One source of guesses came from the image itself:
`/root/.local/share/nano/search_history`, 40 bytes, quoted verbatim —
`youtube`, `solo`, `tutoriales`, `admin`, `fuerza` — the author's own notes.
All five, and combinations, are in the 1,241 and 2,432 buckets. No hit.

**So F1's impact rests on the absence of a rate budget, not on a recovered
credential.** The impact was established instead by a manufactured same-code-path
control (`zzcontrol` → `200`), which is a control and is labelled as one: **a
control on an added entry is evidence that the oracle works; it is not a claim
that the shipped credential was recovered.** That distinction is lab 25's rule
and it is why the summary row does not claim a credential.

### Other measured negatives

| Negative | Work count | How it is proven |
|---|---|---|
| No `FLAG{}` or any `prefix{…}` | **12,275** files searched at `euid=0`, **6** patterns (`FLAG{` `flag{` `CTF{` `WOPR{` `DL{` `dl{`), each a `grep -rIl -F`, **0 hits each** | searcher proven by **3** positive controls — see below |
| No SQLi in `login.php` | **5** injection payloads, all `200`/2866 B/`alert-danger` | oracle fired **twice** bracketing them, 2943 B each |
| No HTTP username enumeration on route A | **600** requests, 3 cases × 200 | bodies byte-identical (457 B); medians 0.0003/0.0002/0.0004 s |
| No rate limit on any of the three stores | **20,000** + **20,000** + **540** candidates/attempts across 10+6+6 rungs | single-key status histograms; `grep -cE "\" 429 "` → **0** |
| No usable HTTP timing oracle on route B | **12,000** + **20,000** POSTs, all identical bodies | `alert-danger` vs `alert-success` is a byte difference, not a time one |
| No non-root-writable file on any privilege path | `find -writable` → 12,275 (as root), filtered by non-root owner → **4**, all `/home/balutin` dotfiles; `test -w` as `www-data` and `balutin` → **NO** on **7** of **7** target files | two independent tools that disagree by design |
| No escalation primitive | sudo absent, cron daemon absent, `setuid -4000` = **10** stock binaries, `getcap` empty, no socket | inventory, not absence of mentions |
| No credential in the image build record | `docker history --no-trunc` → **3** rows | full output quoted above |
| No other listening port, UDP included | `/proc/net/tcp` → **2** sockets; `nmap -p-` → 65,535 ports scanned, 2 open | both TCP and kernel table read |

### The reward search, and its positive controls

Discipline first: **the searcher's own corpus was searched for the pattern
before the target was.** `grep -rIn -- 'FLAG{\|flag{\|CTF{\|WOPR{\|DL{\|dl{'`
over `/tmp/opencode/166/` returned **no output** — my probe scripts, my ladder
output and the downloaded `dl.db` do not contain the literal. Lab 168 found
`FLAG{` in its own probe script, and lab 82 read a `.ui-icon-flag{` CSS rule as
a hit; on a 12,275-file tree the pattern is distinctive enough that this check is
not ceremonial.

Then, at `euid=0`, the searcher was proved capable of firing **three** ways
before its zero was believed:

```
-- control 1: a literal that IS on disk --
$ grep -rIn -F "Zona restringida" /var/www/html/
/var/www/html/.htaccess:2:AuthName "Zona restringida"

-- control 2: a literal that IS in a shadow file --
$ grep -c -F "balutin" /etc/shadow
1

-- control 3: a marker only I can create, created then removed --
$ printf "166_probe_marker_CONTROL\n" > /root/.166_control
$ grep -rIl -F "166_probe_marker_CONTROL" /root
/root/.166_control
$ rm -f /root/.166_control
$ grep -rIl -F "166_probe_marker_CONTROL" /root     # must be silent again
(no output)

-- then the negative, re-run after the marker was removed --
FLAG{ -> 0    flag{ -> 0    CTF{ -> 0    WOPR{ -> 0    DL{ -> 0    dl{ -> 0
files searched: 12275
```

**Result: no reward.** Not "no `FLAG{}`" as a claim about the platform — a
measured absence over 12,275 files, six patterns, at `euid=0`, with the searcher
proven green three separate ways including a marker round-trip.

---

## NOT tested — separated from what was discarded, and why

- **Isolating the yescrypt cost on port 22 from the PAM and transport cost.**
  Measured: 2.687–2.714 s median per attempt, flat across 32× concurrency. Not
  measured: how much of that 2.7 s is the KDF. **Reason:** this host has no
  yescrypt implementation to measure offline — no `hashcat`, no `john`, no
  `passlib`, and Python 3.14 has **removed** the `crypt` module
  (`ModuleNotFoundError: No module named 'crypt'`); the container has no
  `python3` at all. A per-user comparison was attempted instead and **failed to
  attribute the difference to the KDF**: `balutin` 2.691 s, absent user 2.336 s,
  `root` 1.920 s — and `root` *exists with a yescrypt hash* yet is the fastest,
  so the ordering does not follow existence. n=60 per user, with `MaxStartups`
  drops mixed in. The honest statement is the whole per-attempt cost, not the
  KDF's marginal share.
- **Whether any SSH credential exists that survives a real dictionary.** Port 22
  was measured for its **rate budget** (the brief's question) and not cracked;
  `/etc/shadow` is `640 root:shadow` and the intended third route is not in the
  catalogue. **Reason:** no yescrypt cracker available (above), and a 540-attempt
  ladder is not a dictionary.
- **Identifying the 192-byte-header variant** behind the 357 `3058` rows
  (0.47%). **Reason:** not isolated; recorded as a residue with its count in F5
  rather than guessed at. The body size is unaffected either way.
- **`nmap -sU` and `/proc/net/udp` as an explicit pair.** The kernel's TCP table
  was read (`/proc/net/tcp`, 2 sockets) and `nmap -p-` covered all 65,535 TCP
  ports. UDP was not enumerated directly; **the claim is bounded to "2 listening
  TCP sockets", not to "no UDP service exists".**
- **Executing `crear_db.php` under concurrency**, and whether the concurrent
  `DROP TABLE`/`INSERT` window can be caught mid-flight to deny route B. It was
  executed **once**, deliberately, with the content verified value-preserving by
  md5. Racing it was not attempted.
- **Any exploitation of F5, F6 or F4.** None of them is attacker-reachable from
  outside the container without already holding F1, and the engagement's scope is
  the credential stores. **Stated so a reader does not infer more than is there.**

### Discarded, with the reason

- **`docker history` as a credential source.** Not pursued past the first read:
  three rows, one squash layer, no `chpasswd`. Unlike lab 188, there is nothing
  there. *Discarded on evidence, not on assumption.*
- **`/root/.local/share/nano/search_history` as a credential source rather than a
  wordlist.** Used as candidates (all 5 tried, no hit), **not** reported as a
  disclosure finding: it is the author's editor state in an image layer, it
  contains no credential, and calling it a leak would be lab 188's mistake
  repeated.
- **Hydra as the ladder instrument.** Discarded in favour of a purpose-built
  harness because `-W`/`-T` is the exact mechanism of lab 118's false negative.
  `hydra -V` confirms it is present and was not used.

---

## Instrumentation defects

Four of these are mine and shaped like results. Three of the four would have
deleted or invented a finding. This is the section worth reading.

### 1. An always-true oracle that reported 100% success

Revision 1 of the ladder harness asserted, for route A:

```python
return r.status, len(b), time.perf_counter() - t, b"Set-Cookie" in r.headers or r.status
```

`r.status` is the integer `401` for a rejected candidate, and `401` is truthy.
The oracle fired on **600 of 600** candidates and printed `hits=600`. Read
naively that is a total compromise of the credential gate. It was caught because
the number was implausible in the wrong direction and because the same harness's
route-B mode used a different, correct oracle — two oracles disagreeing is the
tell.

This is `method/self-corrections.md` §6 and §1 in one shape: **an oracle that
always resolves the same way is a bias wearing the shape of an answer.** The fix
was a strict predicate (`r.status == 200`) *and* a manufactured positive control
run before any negative was believed — which is the only reason the negative is
worth anything.

### 2. A partition that overlapped, left holes, and then reported a candidate count anyway

```python
for a, b in ((w, w + (n // workers + 1)) for w in range(0, n, max(1, n // workers)))
```

with `step = max(1, n // workers)` and `width = n // workers + 1`. For
`n=1200, workers=64` that is `step=18, width=19` — 67 chunks of 19 covering
[0, 670) for 1,200 slots: **overlapping and gapped simultaneously.** And the
function returned `len(out)` as the work count, where `out` was a list
pre-filled with `n` `None`s, so `done` was **`n` by construction** regardless of
how many slots were actually filled. The reported "candidates=1200" was fiction
at every worker count above 4, and the rate derived from it was an upper bound of
unknown tightness.

Fixed by an exact partition with an assertion that fails loudly:

```python
step = -(-n // w)
parts = [list(range(i, min(i + step, n))) for i in range(0, n, step)]
flat = [i for p in parts for i in p]
assert sorted(flat) == list(range(n)) and len(flat) == len(set(flat)) == n
```

…plus `assert len(vals) == N` on the filled results, so a rung that does less
work than it claims **aborts the ladder** instead of printing a rate. That
assertion then fired for real on the first keep-alive revision's port exhaustion
(item 4) rather than letting a fake number through.

### 3. Route B measured 12,000 times and did zero work

The first route-B ladder sent `POST /login.php` with **no** Basic credential.
Every rung reported `status={401: 1200}`, `hits=0` — a clean, quiet, entirely
uninformative negative, of exactly the family `method/self-corrections.md` §14
catalogue. The tell was **the byte count**: 457 bytes, not 2866. 457 is Apache's
stock 401 page. **PHP never executed once across 12,000 requests.**

Under `method/self-corrections.md` §14 that negative is not a negative at all; it
is zero work and belongs in NOT-tested. Had the harness only asserted on status
code, this would have been filed as "the login form resists 12,000 candidates",
which is a claim about a class wearing the clothes of a claim about an instance.

Fixed by gating route B and by making the ladder report a **byte histogram per
rung**, so a response that never reached the sink is visible as a byte count
rather than inferred. `457 = Apache, 2866/2943 = login.php` is now the first
thing every route-B number is checked against.

### 4. Host port exhaustion, which reads exactly like a target refusal

After ~22,500 connections (revisions 1–3 each opened a fresh TCP connection per
candidate), the **operator's host** ran out of ephemeral ports and every worker
above 4 raised:

```
OSError: [Errno 99] Cannot assign requested address
```

`ss -s` at that moment: `TCP: 28393 (timewait 28261)` against
`/proc/sys/net/ipv4/ip_local_port_range` = `32768 60999` — 28,232 ports,
28,261 sockets in `TIME_WAIT`. **The instrument failed, not the target.** Read
as a target result it says "the host refuses concurrent authentication at
workers≥8", which would have become a finding about the target that is entirely
about the laptop.

Fixed by one keep-alive connection per worker — which is also what a real
credential-attack tool does, and which is why the final numbers (15,126.2 cand/s)
are 4× the earlier ones (3,836 cand/s) for the same target: **removing the
TCP-setup cost from my own harness changed the measured rate by a factor of four.**
Any rate figure from a connection-per-candidate harness is a measurement of the
harness.

### 5. The summarising `docker logs` wrapper

`docker logs influencerhate_container` returned a summary and nothing else:

```
Log Summary
   [error] 0 errors (0 unique)
   [warn] 0 warnings (0 unique)
   [info] 0 info messages
```

The container was, at that moment, writing thousands of `AH01617` lines a second
into its error log — the line my entire KDF-running proof depends on. The
wrapper is `method/self-corrections.md` §7: a container-management wrapper is a
filter, and a filter is an instrument. Reading the raw stream with
`PATH=/usr/bin:/bin docker logs` produced the real two lines. Every log read in
this writeup was taken from the file inside the container, not through the
wrapper.

### 6. `grep 429` on a rate-limit hunt matched 559 timestamps

Not a target property — a defect in my own reasoning, recorded because it is the
exact shape the corpus keeps producing. Searching for rate limiting:

```
$ grep -ciE "429|too many|locked out|limit|MaxStartups|dropping" /var/log/apache2/error.log
559
```

Decomposed: `429` → 559; `too many` → 0; `locked out` → 0; `limit` → 0;
`MaxStartups` → 0; `dropping` → 0. The lines:

```
[Thu Oct 01 00:11:34.424299 2026] [auth_basic:error] [pid 32:tid 32] [client 172.17.0.1:55540] AH01617: user httpadmin: authentication failure for "/login.php": Password Mismatch
[Thu Oct 01 00:11:34.429072 2026] [auth_basic:error] [pid 30:tid 30] [client 172.17.0.1:55772] AH01617: user httpadmin: authentication failure for "/login.php": Password Mismatch
```

Every match was the digits `429` inside the **microsecond field of the
timestamp**. Corrected checks: `grep -cE "\b429\b"` → **0**,
`grep -cE "\" 429 " /var/log/apache2/access.log` → **0**. **A timestamp fraction
is not a status code.** Read as a sweep result, this would have been filed as
"559 rate-limit events observed" on a host that has no rate limiter at all —
i.e. it would have *manufactured the control* that my no-rate-budget finding
denies.

### 7. `find -writable` as root, and `faillog` beside 492 real failures

Two tools in this engagement answered a question they were not asked.

`find / -xdev -type f -writable | wc -l` → **12,275**, run through `docker exec`
as root. Every file root can write is "writable", so the number is a fact about
root, not about the target. Cross-checked with `test -w` run as the identity
whose capability actually matters — `www-data` and `balutin` — which answered
**`NO`** on 7 of 7 target files. `find -writable` is not even busybox here
(`rc=0`, and it did read something), so this is `method/self-corrections.md` §2
without the §11 excuse: the predicate was correct, the identity was wrong.

`faillog -a`, same instant as a `btmp` holding **492** failure records:

```
Login       Failures Maximum Latest                   On
root            0        0   01/01/70 00:00:00 +0000
balutin         0        0   01/01/70 00:00:00 +0000
```

`/var/log/faillog` is **0 bytes**; `last -b` prints **0** lines; `/var/log/wtmp`
is **0 bytes**; and there is no `/var/log/auth.log` and no journald. So the
492-record `btmp` is the *only* readable failed-login accounting on this host,
and the tool a reader would reach for first reports zero. That is
`method/self-corrections.md` §16 — a tool reporting nothing beside data that
exists. It is also F-adjacent as a *defensive* gap: **an operator attacking port
22 here leaves exactly one audit trail, and the conventional one is absent.**

### 8. A first apr1 implementation that did not match, twice

Worth one line each, because both times the mismatch was caught by an external
oracle rather than by inspection. The first transcription of `apr_md5_encode()`
used `md5(pw || "$apr1$" || salt || pw)` for the inner digest; the second got
the 1000-iteration loop's update order right but still had the magic string in
the wrong place. Both produced well-formed 22-character `$apr1$` strings that
matched **nothing**. They were caught because the check was
`openssl passwd -apr1` — a *different* implementation — rather than a second run
of my own code. The final transcription is pinned with line references into
`apr_md5.c` and matches `openssl` on **7 of 7** cases including the empty
password and an 80-byte password.

---

## Reward

**None.** No `FLAG{}`, and no `prefix{…}` token of any format.

The search that establishes it: **12,275** regular files at `euid=0`, six
patterns (`FLAG{`, `flag{`, `CTF{`, `WOPR{`, `DL{`, `dl{`), each searched with
`grep -rIl -F`, **0 files matched for every pattern**. The searcher's own corpus
was searched for the same patterns first and was clean, so no hit is my own
artefact. The searcher was proven capable of firing three ways beforehand,
including a marker file created at `/root/.166_control`, found by the pattern,
removed, and confirmed gone.

Per `corpus/INDEX.md`, the `FLAG{}` column is the single source for this
question; no position is claimed in any sequence.

---

## Lab-design observation

The lab is well-constructed as two separate credential stores and it is
**broken as two brute-force challenges**, for a reason worth recording:

1. **Route B's "brute force" is unnecessary and the lab ships the answer.** The
   password is in cleartext in `crear_db.php:6`, in cleartext in the database
   row, and `GET /crear_db.php` and `GET /database.db` both serve it over HTTP
   behind the gate. The only *forced* work in the whole lab is route A, whose
   password resisted 759,617 candidates here.
2. **The nesting inverts the intended order.** The catalogue presents route A
   then route B. But route B sits *behind* route A, and route A is the hard one.
   An attacker who solves route A by reading source never needs route B at all.
   The natural fix — remove the `.htaccess` — is the one action that makes route
   B reachable by an unauthenticated client, so the lab's own remediation
   guidance is not obvious and is not stated anywhere in the image.
3. **The gate is untestable by design as shipped.** `AllowOverride All` plus
   `AuthUserFile /home/.htpasswd` is a correct, working control; the defect is
   the *absence of a counter*, which is Apache's default, not a lab error. A
   solver can therefore prove F1 without ever recovering the password — which is
   the honest shape of this engagement.

Not filed as a lab-design *defect* in the corpus's sense (112's chain cannot run,
220's reward is unreachable): the lab runs, its advertised steps are reachable,
and nothing about it is broken. It is a design that is stricter than its own
description.

---

## Cross-read against sibling writeups

Per `method/self-corrections.md` §21 — a rule sampled once has not been tested —
lab 166 agrees with and extends two siblings, and contradicts none.

- **Lab 243 (Duque)**, whose discriminator is *"dos bugs web, y son
  independientes"* — tested with "the admin logs in with no injection at all, so
  fixing the SQLi does not fix the other". Lab 166 applies the same test to two
  credential stores and reaches the same verdict by a different route: fixing
  `.htaccess` does not fix `login.php:9`, and vice versa. **Lab 243 supplies the
  test; lab 166 extends it with a case 243 did not have — two findings that are
  independent in store but NESTED in reach**, where fixing the outer one
  *widens* the inner one's exposure. That combination is not in the corpus and
  is worth a row.
- **Lab 118 (los40ladrones)**, the corpus's other credential-attack row, whose
  brute force was cut short by the operator's own `-W 3`. Lab 166 reaches the
  opposite operational state — **no client-side throttle at all, and still no
  target-side one** — and reaches it by ladder first, so the negative cannot be
  the harness. The two are compatible: 118 documents a false negative from an
  operator's throttle, 166 documents what is left when the throttle is removed.
- **Lab 36 (Verdejo)** establishes that the rate is the standing measurement for
  "was the KDF running", via a yescrypt scanner that reported `10705.7
  candidates/s` because it never executed `crypt()`. Lab 166 runs the same test
  in the other direction and against a *different* KDF: `apr1` at **3,577.4/s**
  against a single MD5 at **3,263,628.2/s`, a ratio of **912.3** where the
  iteration count is 1000. Both the "KDF skipped" signature and the "KDF ran"
  signature are now measured on the same harness, in one table.
- **Lab 102 (Escolares)** found a login returning HTTP 200 with an error body, so
  a status-code detector reports success as failure. Lab 166 is the mirror image
  and the reason the rule generalises: `login.php` returns **200 on both
  success and failure** (2943 vs 2866 bytes), so a status-code detector reports
  failure as success. **The transferable sentence is not "watch for 200" but
  "a status code is not an oracle for a login form; name the body marker."**
- **Lab 141 (DockerLabs)** is the container-security control this lab passes:
  `Privileged=false`, Docker's default `CapEff`, no socket. Recorded here so the
  contrast is on the record rather than assumed.

**No sibling contradicts lab 166.** Where a sibling and this lab touch the same
rule, they agree.

---

## Restore

Stage 9: recreated from the image, not by undoing edits, and verified
**positively** — the check is that the service answers and the checksums match,
not that the command exited 0.

```
$ docker rm -f influencerhate_container && docker run -d --name influencerhate_container influencerhate:latest
$ docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' influencerhate_container
172.17.0.3

$ docker exec influencerhate_container sha256sum /home/.htpasswd
2b102cb638ef39066188ab952f27634fe19d81dedd2fe152ca78b5987c0599c1  /home/.htpasswd     <- shipped value
$ docker exec influencerhate_container md5sum /var/www/html/database.db
c31f313852dcfc4fdc57d4fa48ca532f  /var/www/html/database.db        <- shipped value
$ docker exec influencerhate_container ls -la /home/ /var/www/html/
-rw-r--r-- 1 root root  48 .htpasswd        (no .bak, no .166bak, no control entry)
drwx------ 2 balutin balutin 4096 balutin    (only the three stock dotfiles)

$ curl -s -o /dev/null -w '%{http_code} %{size_download}B' http://172.17.0.3/
401 457B                                                          <- the shipped state
$ bash -c 'exec 3<>/dev/tcp/172.17.0.3/22 && head -1 <&3'
SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u6                             <- the shipped banner
```

Reclaimed by name only, never with a global prune: this lab's docker image and
its extracted archive. No `docker system prune`, no `docker image prune -a`, no
`docker volume prune` — seven `cybervault-*` containers from another project are
running on the same host and a volume prune would destroy their databases.

---

## Feed-forward

Per `RUNBOOK.md` stage 10, checked against `INDEX.md` first:

- **Credential attack** — the class **already exists** (`RUNBOOK.md` §5, row
  *"Is there a rate budget? → A ladder of rates against a latency baseline"*).
  Lab 166 is a **fresh case that the row survives**, so the row is extended
  rather than a new class added. Two things the existing row does not yet say,
  which this lab measured:
  1. **A ladder of rates does not tell you which of two web routes you are
     looking at.** Route A ran a KDF at 15,126.2 cand/s and route B ran none at
     8,858.5 cand/s — route A is *faster*. The discriminator is the store, not
     the rate, and the two differ by a non-finite factor (3,577 candidate
     evaluations per sweep vs zero).
  2. **A ladder measured without a gate credential measures zero work.** 12,000
     requests answered `401`/457 bytes and PHP never executed. A per-rung **byte
     histogram**, not just a status histogram, is what exposes it.
- **Two web bugs that are independent but nested** — lab 243's discriminator,
  extended with the nesting case. This lab shows that *independence of defects*
  and *parallelism of reach* are separate properties, and that fixing the outer
  defect can widen the inner one's exposure.
- **Platform fingerprinting / queue-entry accuracy** — lab 166's headline is a
  **second instance** of the `method/self-corrections.md` §28 family, different
  mechanism: no acronym to expand, but the queue paraphrased the catalogue and
  changed the class of the second route from *brute force* to *escalation*.
  The existing rule covers abbreviations; this case shows the rule needs its
  sibling sentence too: **compare the manifest's paraphrase against the
  catalogue's original text before believing the paraphrase.**
- **A new observation, with no existing row to extend**: Debian bookworm's Apache
  `LogFormat` uses `%O` rather than `%b`, so the access-log size column includes
  response headers (F5). Any byte-count discriminator that reads the log is
  wrong by a constant. Small, cheap, and it bit me — worth one line in the
  retrieval-hazards table rather than a new class.

**No new class.** Four of the classes this lab touches already have rows, and
duplicating them would be the failure the runbook warns about.

---

## Evidence index

Everything below is in `corpus/166/evidence/`.

| File | What it is |
|---|---|
| `server-side-capture-pre-restore.txt` | Server-side counts and log lines read from the live container **before** the stage-9 restore, with the exact command and the reconciliation for each. Includes the refutation of the `429` grep. |
| `final_basic.out` | Route A ladder, final: 3 rungs × 20,000 candidates, keep-alive. 15,126.2 cand/s peak. |
| `final_form.out` | Route B ladder, final, behind the gate: 3 rungs × 20,000 candidates. 8,858.5 cand/s peak. |
| `ladder4_form_gated.out` | Route B ten-rung ladder, workers 1→512, 1,200 candidates per rung. |
| `ladder2_basic.out` | Route A ten-rung ladder, workers 1→512. |
| `ladder_basic.out` | Route A ladder, **revision 1, kept deliberately** — its `hits=600` is the always-true oracle of defect 1. |
| `ssh_balutin.out` | Port 22 ladder, 6 rungs, 540 attempts. |
| `crack.out` | The 549,184-candidate offline sweep: byte counts per dictionary, total, elapsed, rate, `NO HIT`. |
| `apr1.py` | Transcription of `apr_md5_encode()` with per-line references into `apr_md5.c`, and the openssl cross-check. |
| `ladder4.py` | The final harness, whose docstring carries the three earlier defects. |
| `sshladder.py` | The port-22 harness. No hydra `-W`/`-T`, by construction. |
| `dl.db` | The 8,192-byte SQLite credential store, downloaded over HTTP from `GET /database.db`, opening to the single cleartext row. |