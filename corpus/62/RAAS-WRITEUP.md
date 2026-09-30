# RAAS — DockerLabs lab 62 (Difficult)

**Image:** `raas:latest` (Ubuntu 24.04.1 LTS, amd64) — **not** a Windows container.
**Deployed:** `docker run -d --name raas_container --hostname dockerlabs raas:latest`
**Container IP:** `172.17.0.11`
**Entry point:** `service ssh start && service smbd start && tail -f /dev/null`
**Catalog description:** *"SMB enumeration and reversing with Ghidra of a ransomware binary (AES-256-CBC) to decrypt the information."*

Every claim below was executed. Where something could not be tested, it is in
§7 under *could not test*, with the reason — not in the findings.

---

## 1. Autocorrection (read this first)

Five times during this engagement the wrong conclusion was available and cheap. Four of
the five were **defects in my own instrumentation**, and each one looked like a fact
about the target.

### 1.1 I "recovered" a key that was 37 bytes, and 33, and neither was a target fact

My first attempt to rebuild the key concatenated the character chunks pulled out of
`recon()` and stripped trailing NULs. That produced a 37-byte string, because the NUL
terminator `recon()` writes after each chunk is **not** trailing — it is written at
`buf+strlen(buf)` and then **overwritten by the next chunk**. Stripping NULs from a
concatenation keeps five bytes that are not in the key.

My second attempt modelled the buffer but computed the append offset as `len(buf)`
instead of the index of the first NUL. That produced 38 bytes. My third produced 33 —
32 key bytes plus the C-string terminator.

The fix was to stop modelling the *characters* and emulate the *buffer*: for each
immediate, `off = buf.index(b"\0") if 0 in buf else len(buf)`, write the immediate's
little-endian bytes at `off`, and slice `[..:32]` at the end.

**The generalisable defect:** three consecutive plausible-looking wrong keys, none of
which raised an error, because "extract the printable chunks and concatenate" *is* the
right idea applied to the wrong representation. Had I stopped at the first one and
reported "the key is probably 37 bytes", the report would have been confidently wrong.
The assertion `len(key) == 32` is what turned three silent wrong answers into three
loud ones. This is `decision-making.md` §"Assert what the consumer will do with the
bytes, not what the bytes are" applied to a disassembler's output rather than a payload:
**the consumer here is AES, which accepts a 32-byte key and nothing else**, so the
length is not a detail of the key, it *is* the check.

### 1.2 `nmap --script smb-enum-shares` returned nothing, and I nearly recorded that as "no shares"

`nmap -Pn -p139,445 --script smb-enum-shares,smb-enum-users` produced **no share output
at all** — only `smb2-time` and `smb-protocols` returned data. My first conclusion was
that anonymous enumeration was closed.

It is not. The real client disagrees:

```
$ printf 'ls\nquit\n' | smbclient.py 172.17.0.11 -no-pass
# Share Name                Type            Comment
----------------------------------------------------------------------
print$                    DISK            Printer Drivers
ransomware                DISK
IPC$                      IPC (SPECIAL)   IPC Service (dockerlabs server (Samba, Ubuntu))
```

Anonymous share **listing** works. What fails is anonymous **access**:
`curl smb://172.17.0.11/ransomware/` returns `curl: (67) Login denied`.

So the truth is two different controls with two different states — `browsable = yes`
lets the name be enumerated, the share ACL stops the content — and my tool reported
*neither*, it reported "nothing". This is the `decision-making.md` "silence indicts
your framing, not the target" rule: a script that returned no data has no discriminating
power about the state of the service.

### 1.3 `curl smb://` reported every credentialed attempt as `rc=7 Could not connect to server`

I used this to "prove" that bob was denied the share. It was not proof of anything:

```
$ curl -sS -v -u 'bob:56000nmqpL' 'smb://172.17.0.11/ransomware/'
* Established connection to 172.17.0.11 (172.17.0.11 port 445) from 172.17.0.1 port 52706
* closing connection #0
curl: (7) Could not connect to server
```

`rc=7` is a transport error and the TCP connection demonstrably succeeded. I had
collapsed three distinct outcomes — `LOGON_FAILURE`, `ACCESS_DENIED`, and
`LISTED` — into one exit code, and I was about to write "bob is denied" as a **control
that held** when I had measured a libcurl limitation. The fix was a reference client
(impacket), which reported the truth immediately and in a form that separates the three
states. A "control that held" claim is a claim about the *target*, and it is only
worth making if the tool can tell the difference between holding and being broken.

### 1.4 `STATUS_LOGON_FAILURE` for bob was correct, and I blamed the domain first

impacket rejected bob's logon with `0xc000006d`. My first hypothesis was the domain:
I had passed `WORKGROUP` (the workgroup) for a standalone server, and the correct
value is the server name. Retrying with `DOCKERLABS` **also** failed — and that failure
was the real finding: **bob's Samba password differs from his Unix/SSH password.** The
decrypted note says "las credenciales **ssh**", and it means exactly that. The share ACL
(`valid users = patricio, calamardo`) and the password split are two independent
controls, and only reading the first would have made me report the second as broken.

I nearly discarded a correct result because I had a tidy explanation for it. The lesson
is the inverse of the usual one: **a result that survives your first explanation is
more interesting, not less.**

### 1.5 I nearly reported "I decrypted a binary" from a file that was never encrypted

This is the one the lab plants for you, and I walked into it.

`/home/bob/pokemongo` — same name, **same size (17592)**, executable bit set. I
decrypted it with the recovered key and got:

```
first 64 bytes hex:
 7f454c4602010100000000000000000003003e0001000000f0110000000000004...
ELF magic after decrypt? True
```

`\x7fELF`. A valid ELF header, from a file that `file` calls `data`. If I had stopped
there — "recovered key successfully decrypts the second binary" — it would have been a
confident false positive, and the false-positive rate for a wrong key producing
`\x7fELF` is 2⁻³², so it *felt* like proof.

It is a trap. Three independent checks kill it, and the first is arithmetic:

| Check | `private.txt` (real) | `/home/bob/pokemongo` (decoy) |
|---|---|---|
| `size mod 16` | `48 mod 16 = 0` | `17592 mod 16 = 8` — **impossible for CBC output** |
| PKCS#7 last byte | `0x0a` = 10, valid | `0xd2` = 210, **> 16, invalid** |
| Decrypts to a coherent whole | yes | **no** — perfect for 16384 bytes, then diverges |

The file is `AES-256-CBC(real_binary[0:16384]) ‖ real_binary[16384:17592]` — the first
16 KB genuinely encrypted, the last 1208 bytes **verbatim plaintext, never encrypted**.
The divergence begins at exactly `0x4000`, and the tail is byte-identical to the real
binary.

**The rule this teaches is the one I would have written into the methodology if it were
not already there:** *checking the first block is not checking the file.* A
plausible-prefix oracle is the weakest oracle there is, and the failure is
invisible — the first 16 KB are perfect, so every spot check passes. The two checks
that cost nothing are the ones that caught it: **a cipher's output length is
constrained by its block size**, and **padding is a claim the plaintext makes about
itself that a wrong key cannot satisfy.**

---

## 2. Real surface

```
$ nmap -sV -Pn -p- 172.17.0.11
PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 9.6p1 Ubuntu 3ubuntu13.5 (Ubuntu Linux; protocol 2.0)
139/tcp open  netbios-ssn Samba smbd 4
445/tcp open  netbios-ssn Samba smbd 4
Service Info: OS: Linux; CPE: cpe:/o/linux:linux_kernel
Not shown: 65532 closed tcp ports (conn-refused)
```

**Three ports. No HTTP.** The catalog says "SMB enumeration and reversing"; the
description is directionally right and otherwise uninformative. The name "RAAS"
(Ransomware-as-a-Service) is, per the eight-lab pattern, narrative and not evidence.

Not present, despite being installed: **Apache 2.4 + PHP 8.3 are installed and
configured** (`/etc/apache2/`, `/etc/php/8.3/`, default `index.html` in
`/var/www/html`) but **nothing listens on 80**. Residual from the base image, not a
vector. Recorded so that a later reader does not go looking for a web tier.

### 2.1 Accounts

| Unix | uid | role in the lab |
|---|---|---|
| `ubuntu` | 1000 | default image account, no shell activity, `!` (locked) in shadow |
| `patricio` | 1001 | **owner of `/srv/ransom`**, author of the ransom note, published the binary |
| `bob` | 1002 | **ran the ransomware**; the reward is his SSH password; holds the core dump |
| `calamardo` | 1003 | **the account the note addresses**; the sudo target |

Samba accounts exist for `patricio`, `bob`, `calamardo` only. No account has an empty
or locked password (`/etc/shadow`: every service account is `*`, the three users are
yescrypt `$y$` hashes).

### 2.2 SMB

`/etc/samba/smb.conf` (non-comment), verbatim:

```
[global]
   workgroup = WORKGROUP
   server string = %h server (Samba, Ubuntu)
   map to guest = bad user
   usershare allow guests = yes
[printers]   browseable = no   guest ok = no   read only = yes
[print$]     browseable = yes  guest ok = no   read only = yes
[ransomware] path = /srv/ransom
             valid users = patricio, calamardo
             read only = yes
             browsable = yes
```

Share contents (`/srv/ransom`, dir `drwxrwxr-x patricio:patricio`, files `-rw-rw-r--`):

| File | Size | md5 |
|---|---|---|
| `nota.txt` | 379 | `3538717285104cf0a92139f4b5718b2c` |
| `pokemongo` | 17592 | `615b385a7ce450fa35acdd6af917420a` |
| `private.txt` | 48 | `be5ce413f47722a0421d6dcdd7946eb4` |

`nota.txt` (the intended hint, in Spanish):

> estuve analizando el ransomware que el estupido de bob ejecuto para ver si lograba
> desencriptar sus archivos pero hasta ahora no he conseguido nada, me esta costando mas
> de lo que pensaba, asi que comparto el binario para que calamardo vea si puede hacer algo
> por bob.
>
> Calamardo, si logras conseguir algo, lo mas urgente es que desencriptes el archivo
> "private.txt" por favor

`private.txt` is 48 bytes of ciphertext, `57119752b10e1f05dcf793563c0224 13c2b67ebf6848227eaa6792d976be0f d52c0e54855ef292b028968b88cc756 886`.

### 2.3 The deployed surface I could not reach, and why

**The lab has no black-box entry path to the artifacts, and I want to be exact about
that rather than paper over it.** The binary and the ciphertext live in two places, and
every account that can read them needs a password that is nowhere on the box:

- `/srv/ransom/*` — mode `664`, dir `775`, so world-**readable** on the filesystem, but
  the share's `valid users` restricts it to `patricio, calamardo` over SMB.
- `/home/bob/{pokemongo,private.txt,core.63123}` — mode `750` home owned by `bob`.
- **The only credential anywhere on the machine is inside `private.txt` itself.**

I swept for a pre-auth credential and found none: the SSH banner is the stock
`SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5` with no `Banner` directive configured;
`/etc/issue.net` is the stock `Ubuntu 24.04.1 LTS`; there are no SSH keys in any home;
`.bash_history` is symlinked to `/dev/null` in all four homes; no cron job, no
`/opt` payload, no environment file. `nmap -sU` was **not** run (needs root, unavailable
on this host) — declared as a coverage gap in §7, though the port table plus
`/proc/net/tcp` and the absence of any UDP service config make a UDP plane unlikely.

**How I obtained the artifacts, stated plainly:** I used `docker exec` into the
container as `uid=0(root)`. That is a **lab-harness capability, not an attack path.** I
am not going to present it as a first hop, and the chain in §5 starts at the reversing
for that reason. Everything from the reversing onward is reachable over the network by
anybody who has a shell on the box.

### 2.4 Reading the deployment before attacking it

Per the `decision-making.md` rule that a management plane *is* configuration: the most
valuable single artifact in this lab is `smb.conf`, and it is readable before any packet
is sent. It gives the share name, the exact path, the ACL, both guards' marker files
and the read-only posture — none of which is visible from a port scan. The
`sudoers.d` rule is likewise a configuration fact, not a runtime discovery.

---

## 3. Findings

### 3.1 Hard-coded AES-256 key and static IV, recoverable from the binary — CWE-321 / CWE-329

**The whole lab is this finding.** The key is a 32-byte ASCII string built at runtime
and the IV is a second hard-coded 16-byte ASCII string, both recoverable statically.

**Impact:** complete confidentiality loss for every file the binary touched. Anyone
holding the binary — which is published on the share *and* readable by every local
account — can decrypt every victim file. The "ransomware" provides no protection against
its own author, its host administrator, or any user on the machine.

**Root cause:** key material embedded in the client, plus a **constant IV reused for
every file**. The IV is not merely fixed, it is *readable text*: `1234567890123456`.
With CBC, a fixed IV means files with a common prefix produce a common ciphertext
prefix, so the scheme additionally leaks plaintext structure across files.

**Remediation:** generate a fresh cryptographically random IV **per file** and store it
in the file (it is not secret); derive the key from a passphrase with
`PBKDF2-HMAC-SHA256` (or scrypt/Argon2) with a per-victim salt, and keep it out of the
binary; for recoverable enterprise deployment, use a managed key-escrow rather than
embedding anything.

**Evidence** — `main`, verbatim:

```
0x00001838      48b8313233..   movabs rax, 0x3837363534333231 ; '12345678'
0x00001842      48ba393031..   movabs rdx, 0x3635343332313039 ; '90123456'
0x0000184c      488985d0fb..   mov qword [var_430h], rax
0x00001853      488995d8fb..   mov qword [var_428h], rdx
0x0000185a      488d95d0fb..   lea rdx, [var_430h]     ; &IV   (16 bytes)
0x00001861      488d85e0fb..   lea rax, [var_420h]     ; &KEY  (32 bytes)
0x00001868      4889c6         mov rsi, rax            ; arg2 = key
0x0000186b      488d050d08..   lea rax, [str._home_]   ; "/home/"
0x00001872      4889c7         mov rdi, rax
0x00001875      e849fcffff     call sym.encrypt_files_in_directory
```

and the key, built by the function **named `recon`** — see §4.2.

Recovered material:

```
key (32 B) = y0qpfjxbd79047929ew0omqad3f4gscl
iv  (16 B) = 1234567890123456
```

**Proof of correctness — roundtrip, not plausibility.** "Readable plaintext" is a weak
oracle. The proof is that re-encrypting the recovered plaintext reproduces the original
ciphertext byte for byte, which validates key, IV, mode and key↔file association at
once:

```
original ciphertext : 48 bytes  sha256=7a5808b9a7c7a599d74f9fe00f571544a859327c5a6d11de12caf27fab837951
recovered plaintext : 41 bytes  b'las credenciales ssh son: bob:56000nmqpL\n'
padded              : 48 bytes (3 blocks)
re-encrypted        : 57119752b10e1f05dcf793563c022413c2b67ebf6848227eaa6792d976be0f
                      d52c0e54855ef292b028968b88cc756886
original            : 57119752b10e1f05dcf793563c022413c2b67ebf6848227eaa6792d976be0f
                      d52c0e54855ef292b028968b88cc756886
ROUNDTRIP MATCH     : True
```

### 3.2 SSH account allows passwordless execution of a general-purpose interpreter as another user — CWE-269 / CWE-250

```
# /etc/sudoers.d/  (via sudo -n -l as bob)
User bob may run the following commands on dockerlabs:
    (calamardo) NOPASSWD: /bin/node
```

`/bin/node` is a full interpreter, so the rule is not "run one program" — it is "execute
arbitrary code as `calamardo` with no password":

```
$ sudo -n -u calamardo /bin/node -e 'console.log(require("os").userInfo().username, process.getuid())'
calamardo 1003
```

**Impact:** any code execution as `bob` becomes code execution as `calamardo`,
password-free, with no further exploit. Identity boundary crossed on the first use.

**Root cause:** the rule pins a *binary* rather than a *behaviour*. An interpreter has
no fixed behaviour to pin, so a rule naming one is equivalent to granting a shell.

**Remediation:** remove the rule. If a specific automation genuinely needs to run
something as `calamardo`, grant the narrowest possible wrapper — a root-owned script
with a fixed argument list, `root:root 0755` — rather than an interpreter. Prefer a
purpose-built service account over a human user's account.

**The privilege boundary above `calamardo` held.** Measured from the `calamardo`
identity: `/bin/node` `0755` root-owned and not writable; `/etc/sudoers.d`, `/etc/cron.d`,
`/opt`, `/var/www/html`, `/usr/local/bin` all root-owned and not writable; `/root` is
`0700`; `sudo -n -l` returns `rc=1` (password required); `su - root` times out
awaiting a password. `calamardo` reads `/srv/ransom/*` (world-readable `664`) and cannot
read `/home/bob` or `/home/patricio`. **There is no third hop.** See §4 for the full
measurement table.

### 3.3 Samba logging redirected to `/dev/null` — CWE-778

```
$ ls -la /var/log/samba/
lrwxrwxrwx 1 root root    9 Jan  5  2025 log. -> /dev/null
lrwxrwxrwx 1 root root    9 Jan  5  2025 log.smbd -> /dev/null
lrwxrwxrwx 1 root root    9 Jan  5  2025 log.172.17.0.1 -> /dev/null
... (13 symlinks, all -> /dev/null)
```

Every SMB log, including the per-client ones, is a symlink to `/dev/null`.

**Impact:** no authentication record for a service holding victim data. Failed
logons, share accesses and the exact moment of the mass encryption are all unrecoverable
after the fact. The log also happens to remove *my* best diagnostic (§4.1).

**Remediation:** write to `/var/log/samba/` with log rotation and ship off-host.

**Why this is worth reporting beyond the missing-log cliché:** it destroyed a specific,
documented investigative technique. `infrastructure.md` → *Monitoring Agents* records a
verified oracle where a correctly framed request from the network returned nothing while
the daemon's log named the exact control that rejected it. That oracle is **structurally
unavailable here**, and the config that removes it is a single readable line.

### 3.4 Encrypted artifacts and a core dump retained in a user home directory — CWE-530 / CWE-497

`/home/bob/` contains `pokemongo` (the ransomware), `private.txt` (its ciphertext) and
`core.63123`, a **1 110 016-byte core dump of the encryption process**:

```
core.63123: ELF 64-bit LSB core file, x86-64, version 1 (SYSV), SVR4-style,
            from './encript2', real uid: 1002, effective uid: 1002,
            execfn: './encript2'
```

**Impact:** the process image contains the key **and** the IV **in cleartext, on the
stack, contiguously** (see §4.3). Recovery does not require reversing at all — a
`strings` call is sufficient. Any account that reaches the home directory — a backup, a
snapshot, a forensic image, a misconfigured share — recovers every plaintext in one
command. Retaining a core dump of a cryptographic process is equivalent to retaining
the key.

**Remediation:** disable core dumps for processes that handle key material
(`fs.suid_dumpable=0`, a restrictive `/proc/sys/kernel/core_pattern`, `ulimit -c 0` in
the service unit), and treat any core dump as secret material.

### 3.5 The binary is designed to refuse analysis and to destroy data in place — CWE-733 / CWE-693

Three gates in `main` before any encryption, all exiting `1` with
`Ten cuidado con lo que ejecutas!`:

1. `gethostname(buf, 0x400)` then `strcmp(buf, "dockerlabs")` — the host **must** be
   named `dockerlabs`.
2. `file_exists("/opt/ak.pk1")` — a 2-byte marker file (`\n`), root-owned.
3. `file_exists("/bin/12bn")` — a 2-byte marker file, root-owned.

All three were confirmed empirically (§4.4) by driving them with an `LD_PRELOAD` shim
that overrides `gethostname`/`stat` on a **copy** of the binary, with an interlock on
`opendir` so the encryption path was unreachable by construction.

Impact of gate 1 in a real incident: the operator who renames the host — the standard
first response to an active encryption — **stops the malware from running further**,
which is a dual-edged control. The gates are anti-analysis, not anti-remediation, and
the markers in `/bin` and `/opt` mean the presence check is itself evidence the host
was targeted before.

---

## 4. Reverse engineering: entry criterion, and how the key was proved

### 4.1 The entry criterion, and what I discarded

This is the part the methodology lacked, so it is worth stating as a decision rather
than a transcript.

**A ransomware binary has an expected shape, and the *imports* tell you which parts are
present before you read a single instruction.** The lookups, in order:

| Looking for | Why | Found? |
|---|---|---|
| a KDF (`PBKDF2`, `scrypt`, `Argon2`, `bcrypt`) | if one exists, the key is *derived* and you must find the passphrase — a completely different, much longer engagement | **absent** |
| `EVP_EncryptInit_ex` / `EVP_CIPHER_CTX_new` | names the library and version | present, `OPENSSL_3.0.0` |
| `EVP_aes_256_cbc` | **names the algorithm, key size and mode in one symbol** | present |
| `EVP_Decrypt*` | tells you whether the author shipped a decryptor | **absent** |
| `gethostname`, `snprintf` | non-crypto string building; often the key/IV assembly | present |
| `malloc(size+16)` next to the read | the `+16` is PKCS#7 block slack | present |

One `rabin2 -i` therefore decided the whole strategy. **No KDF import ⇒ the key is not
derived ⇒ it is a literal in the image, and the engagement is minutes, not days.** If a
KDF *had* been present, every minute spent on the binary would have been wasted and the
correct next step would have been the passphrase, not the code.

What I explicitly discarded, and why:

- **`/home/patricio/.ssh/python3`** — 8 MB, executable, sitting in a `.ssh` directory:
  the shape of a stashed backdoor. It is **byte-identical to `/usr/bin/python3`**
  (md5 `67e2b7af8c0f36110c6704b9e7e8a699` both). Not SUID, so running it as any identity
  grants nothing. Decoy.
- **`/home/bob/pokemongo`** — same name, **same size**, executable bit. Not an ELF
  (`file` says `data`), 7.817 bits/byte entropy, and a **half-encrypted** file. The
  single cheapest discriminator between the two copies is `file`: one line, and it
  returns the answer that a full reversing budget would have wasted hours on.
- **`/opt/ak.pk1`** and **`/bin/12bn`** — 2-byte files, `root:root 0644`. Gate markers,
  not payloads.
- **The `recon` symbol name** — see §4.2.

**The single most valuable instruction in this engagement was the *absence* of an import.**

### 4.2 `recon()` does no reconnaissance — the symbol name is a lie

`recon` is the most attractive symbol in the binary and it is not what it says. It
performs no scanning, touches no network, and returns no data. It is the **key builder**:

```
0x00001301  mov dword [rax],        0x70713079          ; 'y0qp'
0x00001307  mov byte  [rax+4],      0x00                ; terminator
0x00001312  call sym.imp.strlen                          ; find the append point
0x00001321  mov dword [rax],        0x62786a66          ; 'fjxb'
0x00001327  mov word  [rax+4],      0x0064              ; 'd'
0x00001343  mov dword [rax],        0x34303937          ; '7904'
0x00001349  mov word  [rax+4],      0x0037              ; '7'
0x00001365  mov dword [rax],        0x65393239          ; '929e'
0x0000136b  mov word  [rax+4],      0x0077              ; 'w'
0x00001387  movabs   rcx,           0x66336461716d6f30  ; '0omqad3f'
0x00001394  mov byte  [rax+8],      0x00
0x000013ae  mov dword [rax],        0x63736734          ; '4gsc'
0x000013b4  mov word  [rax+4],      0x006c              ; 'l'
```

32 characters. The `H` suffix on the immediates in a `strings` dump is the x86-64
64-bit-immediate display convention — `0x0omqad3fH` is not hex, it is eight ASCII bytes
being displayed as a qword, and reading it as a number is how you lose an afternoon.

This is `decision-making.md` §7 landing in a symbol table: **a name is a claim about
intent, and intent is not behaviour.** `recon` was the most confident-looking label in
the binary and it pointed at the answer while describing something else. A
label-confirming hypothesis is a stopping condition wherever it appears — a comment, a
function name, a lab name, a catalog description.

### 4.3 Recognising cryptographic material — and why the *contrast* is the method

The task's real question is how to tell a key from data from a pointer. Here the
discriminator was not magic, it was **co-location and adjacency**.

**In the disassembly.** High-entropy-looking 64-bit immediates are weak evidence on
their own — the AES round constant `0x63636363` and the S-box bytes are the classic
false positives, and so is any compiler-materialised pointer. What settles it is
**which buffer the pointer is passed to and when**. Tracing the `EVP_EncryptInit_ex`
call resolves the register shuffle unambiguously:

```
0x000013ed  call sym.imp.EVP_aes_256_cbc
0x000013f2  mov rsi, rax            ; type   = EVP_aes_256_cbc()
0x000013f5  mov rcx, qword [var_30h]; arg4
0x000013f9  mov rdx, qword [var_28h]; arg3
0x00001401  mov r8, rcx
0x00001404  mov rcx, rdx            ; key    = arg3
0x00001407  mov edx, 0              ; impl   = NULL
0x0000140c  mov rdi, rax            ; ctx
0x0000140f  call sym.imp.EVP_EncryptInit_ex
```

`EVP_EncryptInit_ex(ctx, type, impl, key, iv)` ⇒ `arg3 = key`, `arg4 = iv`. A 5-argument
call with a constant in the 5th slot is a *structural* signature of a key and an IV, and
it does not require recognising any constant by value. **Prefer the call site to the
constant table.**

**In the core dump — the same answer, with no reversing at all.** `core.63123` contains:

```
1105712:1234567890123456
1105728:y0qpfjxbd79047929ew0omqad3f4gscl
```

Two high-entropy 16/32-byte runs of printable ASCII, **exactly 16 bytes apart**, inside
a core dump of the encryption process. Adjacency is the tell: a key and its IV are
allocated as sibling locals in one stack frame, so in a memory image they appear next to
each other. Random key material in a heap would not be 16-byte aligned against an IV.

And the stack layout independently corroborates the disassembly:
`var_430h` (IV) and `var_420h` (key) are 16 bytes apart in `main`'s frame
(`sub rsp, 0x430`), which is exactly the gap observed in the core. **Two methods, one
answer, from unrelated evidence — that is what makes it a result rather than a guess.**

### 4.4 Descifrar vs. adivinar: the oracle, and the one that is not enough

This is the distinction the methodology was missing, and the lab contains a clean
demonstration of why the *usual* oracle is insufficient.

Decryption is CBC, so `plaintext_i = AES-128-block-decrypt_K(C_i) XOR C_{i-1}`, with
`C_0 = IV`. Two consequences fall straight out, and they are the whole oracle:

- **Changing the key corrupts every block**, because every block's first step is
  decryption under `K`.
- **Changing the IV corrupts only block 0**, because `C_0` appears in exactly one XOR.

Measured, with the recovered key and a deliberately corrupted IV:

```
--- POSITIVE  recovered key + recovered IV ---
  pkcs7_valid  : True
  printable    : 100.0%
  plaintext    : b'las credenciales ssh son: bob:56000nmqpL\n'

--- NEGATIVE  correct key, wrong IV ---
  pkcs7_valid  : True          <-- PASSES the padding check
  printable    : 97.6%
  plaintext    : b']S@\x14VDR\\\\^R[RXPD ssh son: bob:56000nmqpL\n'

--- NEGATIVE  zero key + zero IV ---
  pkcs7_valid  : False
  printable    : 29.2%

--- NEGATIVE  key with last byte flipped ---
  pkcs7_valid  : False
  printable    : 39.6%
```

**`pkcs7_valid` is not a sufficient oracle, and this is the finding.** A correct key with
a wrong IV *passes* PKCS#7 validation and is 97.6% printable, because padding lives in
the last block and the last block never depends on the IV. Reporting "padding valid" as
proof of a key recovery would have been wrong in the one case that matters.

What the negative controls do give you is a **positional** signal that is worth more
than any single pass/fail:

- **Tail perfect, head garbage ⇒ wrong IV, right key.** Block 0 is the only block the IV
  touches. This is the inverse of the usual "plausible first block then it degrades"
  heuristic, and it is the same measurement read from the other end.
- **Everything degrades together ⇒ wrong key.**

And a wrong key does not fail uniformly — it fails as *entropy*. A correct key yields
100% printable; a wrong key yields 29–40% printable, which is what random bytes look
like. `printable ratio` is a continuous, quantitative oracle that needs no reference
value, and it separates the hypotheses that a binary pass/fail merges.

The three checks that are stronger than any of the above, in increasing cost:

1. **Length vs. block size.** CBC output is always a multiple of 16. `48 mod 16 = 0` for
   the real ciphertext; `17592 mod 16 = 8` for the decoy, which falsifies the decoy with
   one number and no decryption at all.
2. **Padding validity.** `0x0a` = 10 on the real file; `0xd2` = 210 on the decoy, which
   is > 16 and therefore not a padding byte.
3. **Roundtrip.** Re-encrypt and compare to the original. `ROUNDTRIP MATCH: True` with
   identical sha256. This is the only one that validates the key, the IV, the mode *and*
   the key↔file association together, because all four enter the ciphertext.

### 4.5 Cost of the dynamic approach, honestly

- **`LD_PRELOAD` shim — the cheapest dynamic instrument here, and the one I would
  recommend.** Overriding `gethostname`/`stat` drove all three anti-reproduction guards
  to their refusal branch and confirmed them behaviourally, on a copy, with an
  `opendir` interlock making the destructive path unreachable. Cost: ~30 lines of C.
  It tests *behaviour*; it cannot tell you the key.
- **Core dump — better than reversing for this class, and free.** It gave the key and IV
  directly, with the 16-byte adjacency as free corroboration. Whenever a target has
  already run, a memory image beats a static analysis, and reversing the binary is only
  needed when no image exists.
- **Ghidra was not available on this host** (`which ghidra analyzeHeadless` → nothing).
  radare2 with `aa; pdf` was used instead, and the binary is **not stripped**, so
  `sym.encrypt`, `sym.recon`, `sym.main` and `sym.file_exists` resolve directly. I am
  flagging this as a **difficulty caveat**: an unstripped 64-bit ELF with named symbols
  and no anti-debug is the easy case. None of the reasoning above would be available
  from a stripped binary — the key builder would have to be found from
  `strlen`-in-a-loop plus `EVP_EncryptInit_ex` call sites, and the argument mapping would
  have to be inferred from stack layout rather than read. I did not get to measure that
  gap, so I am not claiming it.
- **What headless Ghidra would still not have given me:** the argument shuffle at
  `0x13f2-0x140c` (§4.3) and the adjacency observation in the core (§4.3). Those are
  semantic questions about which value is a key, and no batch extractor answers them.

---

## 5. Chain, in order, with each jump justified

| # | Step | Justification | Identity after |
|---|---|---|---|
| 0 | Obtain `pokemongo` + `private.txt` | **Lab-harness access, not an attack path** (§2.3). No credential for `patricio`/`calamardo` exists on the box. | `uid=0` *in-container, via `docker exec`* |
| 1 | `rabin2 -i` → no KDF, `EVP_aes_256_cbc` present | Entry criterion (§4.1). Decides the whole strategy in one command. | — |
| 2 | `r2 -c 'aa; s sym.main; pdf'` → IV from two `movabs`, key from `recon()` | Key is a literal, so it is in the image. | — |
| 3 | `recon` immediates → key, **emulating the buffer, not concatenating chars** | §1.1. Three plausible wrong keys otherwise. | — |
| 4 | Decrypt `private.txt`, **verify by roundtrip** | §4.4. Plausibility is not decryption. | — |
| 5 | `ssh bob@172.17.0.11` → **`id` first** | `decision-making.md` §8. Measured, not assumed. | **`uid=1002(bob)`** |
| 6 | `sudo -n -l` → read the deployment, not just try things | The sudoers rule is configuration. | `bob` |
| 7 | `sudo -n -u calamardo /bin/node -e ...` | CWE-269 (§3.2). The rule names an interpreter, so it is arbitrary code. | **`uid=1003(calamardo)`** |
| 8 | Read `/srv/ransom/*` as `calamardo` | Confirms the intended identity — the note addresses `calamardo`. | `calamardo` |
| 9 | **Stop.** No third hop. | Every candidate root path measured and denied (§4 of this table / §3.2). | — |

**Hop count: 2.** Planned from the sudoers rule and the note: 2. The important part is
not that the number matched — it is that **the boundary above `calamardo` held**, and
that is a result rather than an absence of one.

---

## 6. Reward — literal

There is **no `FLAG{}`** in this lab. The reward is the plaintext of `private.txt`:

```
las credenciales ssh son: bob:56000nmqpL
```

i.e. *"the SSH credentials are"*, and the credential is:

```
user: bob
pass: 56000nmqpL
```

Verified by use, not by inspection — the first command over SSH was `id`:

```
$ ssh bob@172.17.0.11 'id; hostname'
uid=1002(bob) gid=1002(bob) groups=1002(bob),100(users)
dockerlabs
```

`private.txt` md5 `be5ce413f47722a0421d6dcdd7946eb4`, ciphertext sha256
`7a5808b9a7c7a599d74f9fe00f571544a859327c5a6d11de12caf27fab837951`.

---

## 7. Tested / not tested / could not test

**Tested.** Full TCP port scan with version detection; anonymous SMB share enumeration
with a real client; share ACL behaviour for anonymous / `bob` / wrong-password; the SMB
vs. Unix password split; SSH banner; `/etc/issue.net`; `smb.conf` and `sudoers.d` in
full; account and shadow enumeration; SUID/SGID sweep; writability and reachability of
every plausible escalation target from the `calamardo` identity; static analysis of the
binary to its argument flow; all three anti-reproduction guards, empirically; key
recovery by two independent methods; decryption validated by roundtrip; the decoy
falsified by three independent checks.

**Not tested (out of scope, stated so it is not assumed).** Brute-force or
password-spraying any account — the notes contain no password-hint and guessing is not
a technique (`decision-making.md`, RoE). Whether the `pokemongo` key material is
reused by any *other* sample. Whether `patricio`/`calamardo` are weak, since neither
hash was attacked.

**Could not test, with reasons.**

1. **`nmap -sU`** — needs root; no sudo on this host. The Baremetal lesson applies
   directly: a `-p-` scan is a **TCP** statement. Mitigated but not closed by
   `/proc/net/tcp` and the absence of any UDP service in the image config; the
   `623/udp` case from that lab cannot be excluded by evidence I gathered.
2. **Executing the binary's success path.** Deliberately not run. `main` calls
   `encrypt_files_in_directory("/home/", ...)` **unconditionally and recursively**, and
   it destroys files in place (`fseek(0)` + `fwrite`, no rename, no extension change, no
   original retained). Running it would have destroyed the shipped lab state, and the
   binary hardcodes `/home/` so `HOME` cannot redirect it. The three refusal branches
   were exercised instead, with an `opendir` interlock; the encryption path was
   unreachable by construction. I therefore assert the *guards* behaviourally and the
   *encryption* only from disassembly plus the roundtrip.
3. **UTS namespace isolation** to drive the hostname guard natively — `unshare -u`
   fails `Operation not permitted` even as container root. Worked around with
   `LD_PRELOAD`, which is why the guard evidence is from the shim and not from a real
   hostname change.
4. **What a stripped binary would have cost.** No Ghidra on this host and the sample is
   unstripped, so the gap between "named symbols available" and "symbols stripped" is
   unmeasured. I am not claiming a number for it.
5. **Whether `calamardo` can read the private key of anything.** No key material was
   present in that home directory.

---

## 8. Controls that held

Reported with the same prominence as the findings, because a reader cannot tell an
untested control from a holding one.

1. **Samba share ACL — held.** `valid users = patricio, calamardo` excluded `bob`,
   whose *Unix* account is otherwise valid in Samba's database. `bob` is a Samba user
   (`pdbedit -L` lists him) and still cannot use the share.
2. **Anonymous SMB access — held.** `curl: (67) Login denied`; the share content is not
   reachable without a credential. *(Listing the share *name* is allowed — `browsable =
   yes` — which is a weaker exposure and is called out as such, not conflated.)*
3. **The SSH/SMB password separation — held, and is load-bearing.** `bob`'s SSH password
   is rejected by SMB with `STATUS_LOGON_FAILURE`, so recovering the reward does not
   hand over the share. This is why the lab's own design does not collapse into a
   one-credential win.
4. **The privilege boundary above `calamardo` — held.** No SUID path (`/bin/node` is
   `0755` root-owned, not writable, not setuid), no writable root-executed directory,
   `/root` `0700`, `sudo -n -l` requires a password, `su - root` blocked. The chain
   stopped at `uid=1003` because the configuration says so.
5. **No credential in any pre-auth channel — held.** Stock SSH banner, stock
   `/etc/issue.net`, no `Banner` directive, no SSH keys, all `.bash_history` symlinked to
   `/dev/null`. The Acme-style pre-auth banner disclosure did **not** occur here.
6. **The anti-reproduction guards — held, and I proved it three ways.** A renamed host
   or a deleted marker file stops the binary before it touches anything, which is
   anti-analysis rather than a security control against the attacker.
7. **`/root/.node_repl_history` (mode `0600`) — held.** `EACCES` from both `bob` and
   `calamardo`.

---

## 9. Design observations about the lab

- **The description is honest about the class and silent about the port.** Seven labs in
  a row lied in the name or the description; this one is the first where the
  description's *only* error is under-specification, and the entry mechanism is absent
  entirely (§2.3). If a participant is told to start "from the IP", there is no first
  move. Adding one weak credential for `calamardo` — who the note already addresses —
  would close it without touching the reversing at all.
- **The binary is not stripped and has no anti-debug.** For a lab billed *Difficult*,
  the reversing is the easy part for the reason in §4.1: the absence of a KDF import
  reduces a hard problem to reading a string builder. The genuine difficulty is the
  decoy, and the decoy is a *reasoning* trap, not a reversing one.
- **`/home/bob/pokemongo` is the best thing in the lab.** It is the same size, the same
  name and executable, it decrypts to a valid ELF header, and it is not a program. A
  participant who stops at "I got an ELF" ships a false positive. The three cheap
  discriminators (§1.5) are all arithmetic or `file`, and none of them require the
  binary to be stripped.
- **The core dump is a shortcut that makes the intended reversing unnecessary.** It is
  mode `600` in a `750` home, so it is *not* reachable before the reversing — the
  design places it correctly. But once you are `bob` (via the reward), `strings` beats
  Ghidra, and the writeup should say so rather than pretending otherwise.
- **The narrative is unusually well-constructed** and the characters have real
  motivations: `patricio` publishes the binary out of spite, `calamardo` is asked to
  help, `bob` is the victim who ran the malware and kept a core dump. The
  `sudoers` rule is the only place where the fiction and the mechanics meet, and it is
  placed exactly where the note points.
- **`docker exec` is a hole in the lab's own model.** For any DockerLabs target, root in
  the container is one command away, which means "did you get in from outside?" is not
  answerable from the artefacts alone. Worth stating as a property of the whole
  platform.

---

## 10. Restoration

Left as shipped, verified by hash.

| Path | md5 before | md5 after |
|---|---|---|
| `/srv/ransom/nota.txt` | `3538717285104cf0a92139f4b5718b2c` | `3538717285104cf0a92139f4b5718b2c` |
| `/srv/ransom/pokemongo` | `615b385a7ce450fa35acdd6af917420a` | `615b385a7ce450fa35acdd6af917420a` |
| `/srv/ransom/private.txt` | `be5ce413f47722a0421d6dcdd7946eb4` | `be5ce413f47722a0421d6dcdd7946eb4` |
| `/home/bob/private.txt` | `be5ce413f47722a0421d6dcdd7946eb4` | `be5ce413f47722a0421d6dcdd7946eb4` |
| `/home/bob/core.63123` | `9528e9cefe4b31d5d26d6c40fb6115f0` | `9528e9cefe4b31d5d26d6c40fb6115f0` |

**The binary was never executed on the target**, so the destructive path was never
entered — see §7 item 2. All work was read-only (`docker exec` reads, `docker cp` out,
SFTP read). No file on the container was created, modified or deleted. `auto_deploy.sh`
was **not** run, as instructed; the container was managed directly and removed with
`docker rm -f`.
