# BAREMETAL — DockerLabs lab 295 (Medium)

**Target:** `baremetal:latest` (Debian GNU/Linux 12, OpenIPMI `ipmi_sim` as BMC)
**Date:** 2026-09-28
**Reward obtained:** the literal text `Congratulations!` (see §6 — it is **not** a `FLAG{}` token)
**Lab verdict:** solved through the intended management-plane path. Two independent root causes, two separate phases.

---

## 1. Autocorrección (read this first)

Four times in this engagement I asserted something and measurement contradicted it. None of the four were visible from the client, and one of them produced a "successful-looking" output that meant the opposite of what it appeared to mean.

### 1.1 I misread my own tool's echo as remote data

My first SOL driver sent `e`, then the GRUB `linux` line, then `boot`, then `id`. The output looked like a working attack:

```
>>> SENT b'e'   [GRUB: enter edit mode]
e
>>> SENT b'linux /vmlinuz-6.1-ctg root=/dev/vda1 rw init=/bin/bash\r'
linux /vmlinuz-6.1-ctg root=/dev/vda1 rw init=/bin/bash
>>> SENT b'boot\r'
boot
>>> SENT b'id\r'
id
```

I initially read that echo as the remote GRUB console acknowledging my keystrokes. **It was not.** It was `ipmitool`'s own local terminal echo. The raw saved transcript proves it: the file contains my input bytes and *zero* remote bytes, and ends with `ipmitool`'s own `SOL Commands:` help text — which means the SOL session had already terminated and returned to the client.

The tell I should have caught immediately: the response arrived *immediately* and *in the same order* as my input, with none of the multi-line banners the lab's console emits. **An echo that appears with no round-trip latency and no remote formatting is your own terminal.** I confirmed it by decoding the saved transcript rather than by re-running.

### 1.2 My hand-rolled IPMI client was wrong, and the tool was right

I wrote a raw RMCP+/IPMI 2.0 client because no IPMI tooling was present. It got **no reply at all** from the BMC — not on a 4-byte payload, not under any of 8 candidate framings, not even to an RMCP presence ping. My first conclusion was that OpenIPMI's network listener was broken in the container.

That conclusion was wrong, and the way I know it is worth more than the bug: I captured a **reference datagram produced by a working client** and compared it byte-for-byte with what I was generating.

```
reference (ipmitool, 23 bytes):  0600ff07000000000000000000092018c88100388e04b5
mine      (my client, 12 bytes): 060000070006<len><session><seq><pad> + 8 bytes
```

The reference IPMI body is 10 bytes and carries **six** header bytes before the command byte (`0x38` at body offset 6); my client emitted four. The RMCP+ length field reads `0` in **both** directions — OpenIPMI does not populate it, so length-based framing assumptions are worthless against this stack.

Once `ipmitool` worked, the BMC answered immediately. **The lab was fine; my generator was not.** The 8-framing probe was the tool self-test that should have caught this, and it could not: every candidate produced the same output (silence), so the probe had no discriminating power. A probe whose wrong answers are indistinguishable from its right ones is the "control that cannot fail" shape from `decision-making.md` — and here it was *my* control, failing on *my* instrumentation.

I did not have to invent a field-by-field spec: I report the measured difference (10-byte body, 6 header bytes, length field ignored) and nothing more. Asserting a full RMCP+ grammar I had not verified is the error `decision-making.md` warns about, just pointed at the protocol instead of a payload.

### 1.3 `nmap -p-` cannot see the entire management plane

The container's published surface is `80/tcp, 623/udp`. A full TCP scan:

```
PORT   STATE SERVICE VERSION
80/tcp open  http    SimpleHTTPServer 0.6 (Python 3.11.2)
Not shown: 65534 closed tcp ports (conn-refused)
```

**623/udp does not appear.** `-p-` is a TCP range scan; the BMC listens on UDP. The entire out-of-band management plane — the thing the lab is named for — is invisible to the single most-quoted recon command in the methodology. The only reason I knew where to look was the image's `EXPOSE` line and its `lan.conf`.

I could not run `nmap -sU` to demonstrate the UDP side properly: it requires root and this host has no passwordless sudo (`sudo -n` → `interactive authentication is required`). **So the UDP service is confirmed by protocol behaviour, not by a UDP port scan** — a live IPMI 2.0 session answering `Get Channel Authentication Capabilities` and a full RAKP/SOL exchange, plus the socket present in `/proc/net/udp` as `00000000:026F` (= `0.0.0.0:623`). That is stronger evidence than an open-port line, but it is not the same claim, and I am labelling it as such.

### 1.4 A UDP relay that does not preserve the client's source port silently breaks the session

To capture the RAKP handshake I put a logging relay in front of port 623. Message 1 (Get Channel Auth Capabilities) was answered; message 2 got **no reply at all** and the client gave up with `Unable to establish IPMI v2 / RMCP+ session`.

The relay was at fault. IPMI sessions are keyed to the client **5-tuple**, and my relay owned one fixed upstream socket, so every message after the first arrived from a different source port and the BMC dropped it as belonging to no known session. Preserving the client's source port is not optional in a stateful UDP protocol — and I could not preserve it, because binding the port the live client already holds fails with `EADDRINUSE`.

This is why the deep RAKP capture is reported as **not exercised** (§7) rather than produced. I could have hand-waved a plausible RAKP transcript; I did not, and the incomplete control is the honest record of why.

---

## 2. Real surface

| Element | Value | How it was established |
|---|---|---|
| OS | Debian GNU/Linux 12 (bookworm) | `/etc/os-release` in image |
| Web | `0.0.0.0:80` — `SimpleHTTPRequestHandler`, docroot `/opt/ctg/web` | `nmap -sV`, `web.py` |
| **BMC** | **`0.0.0.0:623/udp` — IPMI 2.0, OpenIPMI `ipmi_sim`** | RMCP+ session; `lan.conf`; `/proc/net/udp` |
| BMC identity | Manufacturer `0x1291`, Product `0xF02`, Device ID 0, FW 9.08 | `mc info` |
| Console | `127.0.0.1:9012` **loopback only**, bridged via SOL | `console.py`; `/proc/net/tcp` = `0100007F:2334` |
| Chassis | Power on, restore policy `always-off`, no interlock | `chassis status` |
| SEL | empty | `sel elist` |
| Accounts | **user 2 = `ADMIN`, `ADMINISTRATOR`**; users 1,3–7 callin-enabled but empty | `user list 1` (unauthenticated) |
| GUID | `7b9b84a3d1aa4a7ab6a2d4473cf0c912` | `lan.conf` |
| Reward file | `/root/flag.txt`, mode `0644`, root-owned | image |

`nmap -p-` found **only** port 80. The BMC — the entire point of the lab — was in the UDP half of the address space. See §1.3.

The catalog describes this lab as "exploit an IPMI service design flaw to obtain a hash and bypass GRUB". **The description is half right and the name is marketing.** It does not mention that the BMC is on UDP (the one thing that makes it findable), it says "obtain a hash" when the actual weakness is far worse than a crackable hash (§3.1), and it does not say that the two phases are on *different trust planes* — which is the lab's real lesson (§8).

---

## 3. Findings

### 3.1 IPMI accepts an unauthenticated session at full ADMINISTRATOR privilege — CWE-287 / CWE-306

**Evidence (no password, no guess, no crack):**

```
$ ipmitool -I lan -H 172.17.0.10 -U ADMIN -A NONE session info active
session handle                : 2
user id                       : 2
privilege level               : ADMINISTRATOR
session type                  : IPMIv1.5
channel number                : 0x01
```

`session type: IPMIv1.5` and `privilege level: ADMINISTRATOR` with **no password supplied at all**. Root cause, from the BMC's own configuration:

```
startlan 1
  addr 0.0.0.0 623
  allowed_auths_admin none md2 md5 straight
  allowed_auths_callback none md2 md5 straight
...
user 2 true "ADMIN" "calvin" admin 10 none md2 md5 straight
```

`none` is in `allowed_auths_*` for **every** privilege level, so the BMC will complete a session for a named user without ever checking a credential.

**Impact:** complete unauthenticated administrative control of the machine's power and console. Demonstrated:

```
$ ipmitool -I lan -H 172.17.0.10 -U ADMIN -A NONE chassis power status
Chassis Power is on
$ ipmitool -I lan -H 172.17.0.10 -U ADMIN -A NONE chassis power off
Chassis Power Control: Down/Off
$ ipmitool -I lan -H 172.17.0.10 -U ADMIN -A NONE chassis power cycle
Chassis Power Control: Cycle
```

Chassis power **off** on a production host is a denial of service available to any host that can route a UDP packet to port 623.

**Root cause vs mechanism (CWE-287 is the mechanism; the root cause is the deployment decision):** IPMI 1.5's design permits `auth_type = none`; the finding is that this stack was deployed with it enabled **on an interface bound to `0.0.0.0`**. Same class as publishing a dev server to the internet — fixing the CVE without reversing the decision reintroduces it on the next firmware update. Per `decision-making.md` §4, report the decision (`0.0.0.0` + `none` allowed) and then the mechanism (`-A NONE`).

**Remediation:** bind the management interface to a dedicated management VLAN reachable only from a hardened jump host; remove `none` from `allowed_auths_*`; disable the IPMI 1.5 session path entirely and require IPMI 2.0 with RAKP; if 1.5 must stay for legacy BMCs, front it with a filter that drops UDP/623 from user networks.

### 3.2 Out-of-band management plane on the user network — CWE-284 / CWE-1327 (adjacency to management plane)

The BMC is bound to `0.0.0.0:623` and reachable from the same network as the application host. Per CWE-1327 the management plane must be an adjacency-differentiated control plane; here it is a peer of the data plane with the *stronger* trust relationship. The lab's own page states the principle correctly and then violates it:

> *"una interfaz de administración privilegiada debería encontrarse en una red de gestión restringida"*

**Impact:** independent of any credential weakness, every finding in §3.1 is reachable by anyone with a route to the host. Fixing the password problem does not fix this one, and fixing this one does not fix §3.1 — report both.

### 3.3 A BMC that hands the boot sequence to whoever holds the console — CWE-284 (boot/GRUB plane)

Once the SOL console is reachable (which §3.1 grants), the boot loader is unauthenticated and interactive. The BMC exposes the serial console, and the bootloader honours whoever arrives first:

```
e
GNU GRUB editing mode
linux /vmlinuz-6.1-ctg root=/dev/vda1 ro quiet

Edit the linux line, append init=/bin/bash, then enter 'boot'.
linux> linux /vmlinuz-6.1-ctg root=/dev/vda1 rw init=/bin/bash

[grub] kernel line modified: init=/bin/bash
Type 'boot' to continue.
boot> boot

Booting with modified kernel arguments...
[    0.000000] CTG kernel: emergency lab console
root@(initramfs):/#
```

No password, no second factor, no integrity check on the boot path. `init=/bin/bash` yields `uid=0(root)`.

**This is a separate root cause in a separate trust domain from §3.1 and must not be merged with it.** §3.1 is "the management plane does not authenticate"; this is "the boot plane does not authenticate". A host can be patched against one and remain fully compromised through the other. A BMC that exposes SOL necessarily exposes the bootloader that SOL delivers — the two are not independent mitigations, they are one attack path in two stages.

**Remediation:** set a GRUB password (and `GRUB_PREVENT_MODIFICATION`/signed boot where the platform supports it); configure the BMC to require a SOL session for boot-flag changes; treat "whoever reaches the console owns the next boot" as a design property to be mitigated at the firmware layer, not patched in the OS.

### 3.4 BMC account created with a weak, known password — CWE-1392

`user 2 true "ADMIN" "calvin" admin 10 none md2 md5 straight`

The BMC account uses the dictionary word `calvin`. The lab's config file even annotates it: *"BMC account intentionally has a weak password so the offline cracking step is visible."* That comment is **intent, not evidence** (§7), and per `decision-making.md` §7 I did not stop at it — but the finding stands on the live observation that `-P calvin` authenticates:

```
$ ipmitool -I lanplus -H 172.17.0.10 -U ADMIN -P calvin mc info
IPMI Version              : 2.0
Manufacturer ID           : 4753
```

Independently reportable: fixing §3.1's `none` exposure without rotating this password leaves a one-word credential. **Note the ordering:** §3.1 is worse and does not need this password at all, so a report that led with "weak password" would be rating the target by its optional path.

### 3.5 Enabled-but-unused BMC accounts — CWE-204 (observable response discrepancy) / CWE-1078 best practice

```
ID  Name     Callin  Link Auth	IPMI Msg   Channel Priv Limit
1            true    false      false      Unknown (0x00)
2   ADMIN    true    false      true       ADMINISTRATOR
3            true    false      false      Unknown (0x00)
4            true    false      false      Unknown (0x00)
5            true    false      false      Unknown (0x00)
6            true    false      false      Unknown (0x00)
7            true    false      false      Unknown (0x00)
```

Six accounts have `Callin: true` — IPMI messaging is permitted — with no name, no authentication and no privilege limit, and they are enumerable **unauthenticated** (§3.1). They are unreachable as accounts today, but they are a standing slot for privilege that nothing will notice, and they widen the unauthenticated enumeration surface.

**Remediation:** delete unused BMC accounts or set `callin: false` and `link: false` on them; do not leave empty enabled slots in the user table.

### 3.6 The web tier ships the vulnerability class, the CVE, and the lesson — CWE-200 / CWE-497

`GET /` returns a Spanish-language page that names the attack surface, the protocol, and the specific advisory by number:

> *"Uno de los casos más conocidos apareció en 2013 y quedó registrado como **CVE-2013-4786**. El problema está relacionado con el proceso de autenticación **RAKP** de IPMI 2.0 y con la posibilidad de obtener material que puede utilizarse para realizar comprobaciones de contraseñas fuera de línea."*

This is a **self-documenting target** in the exact sense of `decision-making.md` §7 — the sixth consecutive lab to ship its own answer. Per that rule the work does not stop here: the page names the CVE and the protocol, and the *actual* weakness (§3.1) is **not** a crackable RAKP hash at all. The page describes the well-known historical bug; the deployed configuration is worse and different. Reading the page would have produced a confidently wrong finding — "the RAKP hash is weak" — while the live target accepts an empty password.

**This is reported as a finding in its own right** because an unauthenticated endpoint on the host discloses the weakness class to every other host on the network. It is also the sharpest available example of the §7 corollary: a complete solution document is a stopping condition exactly as a single label is.

**Remediation:** do not publish vulnerability class, protocol internals and CVE identifiers on an unauthenticated page reachable from the management network.

---

## 4. Controls that held (reported with the same prominence as the bugs that fired)

Per `decision-making.md`, a reader cannot tell an untested control from a holding one.

1. **No world-writable document root.** `/opt/ctg/web` is `0755` and `index.html` is `0664 root:root` — **not** `777`. The world-writable-document-root code-drop primitive (`api_web.md`, CWE-732) is **absent**: no local account can plant a file the interpreter will execute. Verified by `stat`, not inferred from the directory listing. The group bit on `index.html` is harmless because the group is `root` and no unprivileged account holds it — `ls` shows a writable-looking mode and the write bit is not reachable.

2. **The BMC's shell delegation is not injectable.** `lan.conf` routes chassis control to a **root-run shell script**:
   ```
   chassis_control "/opt/ctg/chassis_control"
   ```
   A management plane handing attacker-influenced input to a root shell is a CWE-78 shape on paper. It held for three independent reasons: the script accepts a **fixed key set** (`power|reset|boot|shutdown`, everything else `exit 1`); every value is written through a **quoted** `printf '%s\n'`; and `ipmitool` constrains `chassis power` to a fixed enum. I confirmed the delegation is genuinely live — an unauthenticated `chassis power reset` caused the root script to write `event=[reset]`:
   ```
   $ ipmitool -I lan -H 172.17.0.10 -U ADMIN -A NONE chassis power reset
   Chassis Power Control: Reset
   $ cat /run/ctg/event
   reset
   ```
   so the control was tested against real traffic, not assumed from reading the script. I could not reach the injection path at all: `chassis boot` is not implemented by this build (`Invalid chassis command: boot`), so the `boot` branch is unreachable and I could not test it either way — recorded as **untested**, not as held.

3. **Chassis power interlock is inactive and the power overload/fault flags are clear.** `Power Interlock: inactive`, `Power Overload: false`, `Main Power Fault: false`. No interlock stood between me and `chassis power off` — worth stating explicitly, because it means §3.1 had *no* mitigating control behind it.

4. **The BMC's IPMI 2.0 path rejects an empty password.** `-I lanplus -P ''` fails with `Unable to establish IPMI v2 / RMCP+ session`. The no-auth hole is confined to the IPMI 1.5 session path. This is a partial control, and it is exactly why §3.1 must be reported as "IPMI 1.5 with `auth_type=none`" and not as "the BMC has no authentication" — the precision is what makes the remediation (`disable the 1.5 session path`) correct and minimal.

---

## 5. Chain, in order, with each jump justified

| # | Action | Identity / privilege after | Why this step and not another |
|---|---|---|---|
| 0 | `nmap -sV -Pn -p-` | — | Found only 80/tcp. The BMC was *not* here. §1.3. |
| 0b | Read `lan.conf`, `console.py`, `web.py` from the image | — | `decision-making.md` §7/§8: read configuration before attacking. The BMC *is* configuration. Predicted both phases. |
| 1 | `ipmitool -I lan -H <ip> -U ADMIN -A NONE session info active` | **ADMINISTRATOR**, no credential | First attempt. No wordlist, no crack, no spray. §3.1. |
| 2 | `chassis power reset` (unauthenticated) | console enters `grub` | The BMC's chassis action is what drives the boot plane. This is the join between the two trust domains — *not* a privilege step. |
| 3 | `sol activate` (via `lanplus` + `calvin`) | SOL session, GRUB prompt | The console listens on **loopback only**, so SOL is the sole network path. Note the credential here: SOL does not accept the `-A NONE` 1.5 session, so I authenticated with `calvin` (§3.4). |
| 4 | `e` → `linux … init=/bin/bash` → `boot` | **`uid=0(root)`** | Unauthenticated bootloader. `id` measured before anything else. §3.3. |
| 5 | `cat /root/flag.txt` | reward | — |

**Hop count: 2 (management plane, then boot plane), plus a credential for SOL that the chain did not otherwise need.** The measurement that mattered: `id` returned `uid=0(root)` at the *first* shell I obtained, with no escalation step anywhere. There was no `sudo`, no local privesc, and no second identity — consistent with `decision-making.md` §8, the number of hops is a property of the deployment and must be read off the target, never planned.

**Why step 3 needed a password when steps 1–2 did not** is worth stating plainly, because it is the kind of detail that gets written up wrong: it means the *no-auth* finding and the *weak-password* finding are genuinely different paths with different reachability, and a report that collapsed them would misstate both.

---

## 6. Reward — literal

```
root@(initramfs):/# id
uid=0(root) gid=0(root) groups=0(root)
root@(initramfs):/# cat /root/flag.txt
Congratulations!
```

**The success condition is the literal string `Congratulations!`, not a `FLAG{…}` token.** I searched for a flag-shaped token and found none: `/root/flag.txt` is 17 bytes, which is exactly `Congratulations!` plus a newline, and md5 `21cc2aa763afefec43119227b5f13d57` is unchanged after my engagement. Full GRUB/SOL transcript, start to finish, is in `sol_final.bin`.

---

## 7. Tested / not tested / could not test

**Tested:** TCP surface (`-p-`, `-sV`); UDP 623 by live IPMI 2.0 protocol exchange (Get Channel Auth Caps, Open Session, RAKP 1–4, Set Session Privilege) and by `/proc/net/udp`; IPMI 1.5 `auth_type` matrix (`none`, `md5`/`straight`, empty, known password); `mc info`, `user list`, `user summary`, `sensor list`, `chassis status`, `sel elist`, `session info active`; all four `chassis power` verbs unauthenticated; SOL activate + full GRUB sequence; the web page; image source for `web.py`, `console.py`, `lan.conf`, `chassis_control`, `sim.emu`, `entrypoint.sh`, `index.html`.

**Not tested (in scope, not reached):** `chassis boot` — not implemented by this build, so the `boot` branch of `chassis_control` was never exercised; whether `boot-options` is later consumed by anything; the `mc_add`/`sensor_add` firmware commands; FRU inventory (`mc info` reports none present); SEL write/clear; `set session options`; whether the `-A NULL` 1.5 path is also accepted on the callback/operator roles or only on admin; the lab's `sol.history` backup file, which never appeared.

**Could not test, with the reason:**
- **`nmap -sU`** — requires root; no passwordless sudo on this host (`sudo -n` → `interactive authentication is required`). UDP 623 is evidenced by protocol behaviour and `/proc/net/udp`, **not** by a UDP scan.
- **`ipmitool` was not on the host.** No `ipmitool`, `ipmi-scan`, `hashcrack`, `ncat` or `socat`; `ipmish` exists inside the image but its `lan` interface is not compiled in (`Command not found (0x26)`). I extracted `ipmitool` 1.8.19 plus `libfreeipmi17`/`libipmiconsole2`/`libipmimonitoring6` from `.deb` archives with `dpkg-deb -x` (no root required). **I did not simulate any of these tools' output.**
- **The RAKP msg-2/msg-3 hash-replay path (CVE-2013-4786 proper)** — not exercised. I built a logging UDP relay to capture the handshake; the BMC answered message 1 and dropped message 2, because IPMI sessions key on the client 5-tuple and a relay with one fixed upstream socket presents a different source port for every message (§1.4). Preserving the client's port requires binding a port the live client already holds (`EADDRINUSE`). I am reporting an **incomplete control** rather than a plausible-looking RAKP transcript.
- **Firmware/bootloader of a real host** — the GRUB here is a state machine in `console.py`, so my GRUB result demonstrates the *trust relationship* (unauthenticated console owns the boot), not a property of a real GRUB build.

---

## 8. What this lab is actually about

The lab teaches one thing its description does not name, and its name does not suggest.

**The management plane and the data plane are two surfaces with two trust models, and compromising the first does not imply the second.** Getting root here required touching both, in order, through two unrelated authentication decisions:

- the **BMC** decided who may command the machine — and answered "everyone" (§3.1);
- the **bootloader** decided who may become root next — and answered "whoever is on the console" (§3.3).

The join between them is a chassis power event, not a privilege escalation. That is why the two findings must stay separate: an assessor who patches the BMC password believes the host is fixed, and the next person to reach the console still owns the next boot — while the console is *necessarily* exposed by the very feature (SOL) the BMC offers.

Three further design observations, in the order a reader would hit them:

1. **The label pointed at the wrong bug.** The catalogue says "obtain a hash". The deployed weakness is not a crackable hash — it is an *absent* credential. An attacker following the description would spend the engagement on RAKP hash recovery and miss the empty password, which is what actually works. This is `decision-making.md` §7's name-is-marketing corollary in its sharpest form: the description was not merely incomplete, it was **actively misleading about severity**.

2. **The lab documents the historical bug it did not implement.** The page names CVE-2013-4786 and the RAKP authentication process — and the configuration enables `auth_type=none` in IPMI **1.5**, a different protocol version with a different mechanism. Following the shipped documentation would have produced a confident, wrong finding. Per §7 the labelled set is a strict subset of the real one; here it was not even a subset, it was a **different class**.

3. **A worked reference implementation is a legitimate way to run a BMC lab, and it changes the surface in ways worth naming.** `ipmi_sim` gives a real, standards-conformant IPMI 2.0 endpoint with real RAKP and real SOL — which is why the protocol-level findings in §3.1 transfer to hardware unchanged. But it runs as a **userspace process inside the host container**, not on a dedicated management controller, and it inherits the host's network. On real hardware the BMC is a separate device on a separate interface; collapsing that distinction is what makes UDP/623 reachable from the app network at all, and it means the *network exposure* finding (§3.2) is a property of the lab's packaging rather than of the hardware. Both halves matter when transferring: the auth findings are real, the segmentation finding is an artifact worth re-verifying on real BMCs.

---

## 9. Restoration

Container recreated from the shipped image (`baremetal_container`, `baremetal:latest`), which re-runs `entrypoint.sh` and resets the ephemeral `/run/ctg` state.

| File | md5 before | md5 after |
|---|---|---|
| `/root/flag.txt` | `21cc2aa763afefec43119227b5f13d57` | `21cc2aa763afefec43119227b5f13d57` |
| `/opt/ctg/console.py` | `c2becfc394eefa9f959153fc7cc3ab6b` | `c2becfc394eefa9f959153fc7cc3ab6b` |
| `/opt/ctg/web.py` | `cb6d72355a4bf8b9bc90dcf0490d5ebc` | `cb6d72355a4bf8b9bc90dcf0490d5ebc` |
| `/opt/ctg/lan.conf` | `c5d56e93d67d4583506960f58df80cf4` | `c5d56e93d67d4583506960f58df80cf4` |
| `/opt/ctg/chassis_control` | `c650a1192062e1a14354e540eac20f4e` | `c650a1192062e1a14354e540eac20f4e` |
| `/opt/ctg/web/index.html` | `ca9d4c6d1e58d69d044e242d5c30f961` | `ca9d4c6d1e58d69d044e242d5c30f961` |

All six byte-identical. Runtime state restored: `state=[power:on]`, `console_state=[normal]`, `event=[]`, and `boot-options` absent (it was never created — `chassis boot` is unimplemented). Removed from the container: `/tmp/ipmi.py`, `/tmp/probe.py`, `/tmp/scratch/`, and the scratch `ipmi_sim` instances. Also removed the two throwaway containers I created for privileged framing tests (`bm_priv_test`, `bm_priv2`). `auto_deploy.sh` was never executed.

**Two things I changed and did not revert, deliberately:** the BMC account's failed-login counter (my enumeration and probe runs consumed some of the `10` attempts in `user 2 ... admin 10`), and the container's PID/log history. Neither is persisted in the image layer. Flagging them rather than leaving them silent.
