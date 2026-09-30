# INDEX — engagement → class → methodology rule

The point of separating this corpus from the methodology is that the two answer
different questions. **The methodology answers *how to decide*. This corpus is the
evidence that any of it is worth believing.**

Every row below was verified to point at a heading that exists and says what this
table claims it says. Line numbers are as of the last commit of the methodology
repo; the headings are the stable reference, the numbers are a convenience.

- **Methodology**: [`PenTestMethodology`](https://github.com/statick88/PenTestMethodology)
- **Line numbers verified against** `sections/api_web.md`, `sections/infrastructure.md`,
  `sections/decision-making.md`, `sections/mobile.md`

## How to read a row

The middle column is the vulnerability class. The right column is where the
distilled rule landed. Where a rule says **extended**, the class already existed
and the engagement sharpened it — those are the rows worth reading first, because
an existing rule that survived a new case is stronger than a new rule that has
only ever had one.

---

## Batch 1 — the pilot

| # | Lab | Class | Landed in the methodology |
|---|-----|-------|--------------------------|
| 296 | Asturias | Unrestricted upload; endpoint exposed by middleware **registration order** | `api_web.md` upload oracle, axes (a)–(d); `infrastructure.md` *Web server configuration* (MIME map) |
| 292 | Acme | Credentials in a **pre-auth** channel; world-writable document root; execution identity | `api_web.md` pre-auth channels; `infrastructure.md` world-writable; `decision-making.md` §8 |
| 281 | PipePwned | SSTI → CI runner; **writer identity vs executor identity** | `api_web.md` SSTI; `infrastructure.md` *CI/CD Runners*; `decision-making.md` §8 |
| 293 | Zabbixploit | SQLi; session hijack; a **working** allowlist as a finding | `api_web.md` session-hijack proof, session-secret oracle |
| 271 | BaluHome | Stored XSS → session cookie without `httpOnly` → RCE | `api_web.md` XSS sink-context oracle, cookie-attribute rating |

## Batch 2 — the gaps the pilot named

| # | Lab | Class | Landed in the methodology |
|---|-----|-------|--------------------------|
| 295 | Baremetal | **A management plane on UDP is invisible to a TCP-only scan** | `infrastructure.md` out-of-band management |
| 62 | Raas | Reversing; **padding validation proves nothing in CBC**; SMB | `infrastructure.md` *Reverse engineering a binary*, *SMB shares* |
| 209 | Profetas | XXE; `.pyc` reversing; a decrypted sudoers grant | `api_web.md` XXE oracle; `infrastructure.md` *Reverse engineering a `.pyc`* |
| 146 | Elevator | The MIME map decides the executable extension; a six-rung sudoers ladder | `infrastructure.md` *Web server configuration*, sudoers ladder |
| 255 | PinguPenguin | Diagnostic surfaces: **name, masked value and value are three different things** | `api_web.md` diagnostic-surfaces oracle |
| 186 | Tokenaso | Concurrency: the window is a property of the code | `api_web.md` *Concurrency oracle* |
| 26 | 404-not-found | Described as LDAP injection and **was not**; catch-all vhost as baseline | `decision-making.md` §1; `api_web.md` vhost enumeration |
| 148 | Spain | Buffer overflow; Python `pickle` deserialization; sudoers argument injection | `infrastructure.md` memory corruption, pickle gadget chain |

## Batch 3 — pivoting, vhosts, LFI, SUID

| # | Lab | Class | Landed in the methodology |
|---|-----|-------|--------------------------|
| 113 | Road_To_Olympus | **A registered tunnel session is a control-plane claim, not a data-plane measurement** | `infrastructure.md` *Pivoting* |
| 65 | Seeker | Vhost enumeration in both directions: one hash = nothing, three = everything | `api_web.md` virtual host enumeration |
| 6 | Grandma | **Reading a file ≠ obtaining its content**; a real CVE read from source | `api_web.md` *Local file inclusion*; `infrastructure.md` *Pivoting* (extended) |
| 23 | reverse | Log poisoning: **the field is the finding**, not the payload | `api_web.md` *Log poisoning* |
| 33 | chmod-4755 | Restricted shells measured in two layers; **whether the euid survives is a property of the binary** | `infrastructure.md` *Restricted shells and SUID binaries* |

## Batch 4 — the surface the platform finally had labs for

| # | Lab | Class | Landed in the methodology |
|---|-----|-------|--------------------------|
| 163 | Ofuskeit | Client-side deobfuscation; **refuted** "the client documents the API" | `api_web.md` *Client-side JavaScript as a source*; `mobile.md` precondition (extended) |
| 238 | Autoescuela | **An HTTP scanner sees nothing** of a WebSocket; the lab misattributed its own CVE | `api_web.md` *WebSockets* |
| 141 | DockerLabs | Container trust boundary: privilege, socket, capabilities, identity | `infrastructure.md` *Container Security* |
| 118 | Los 40 Ladrones | Port knocking as state authentication; **credential attacks are a measurement, not a success** | `infrastructure.md` *Port knocking*, *Credential attacks* |
| 129 | DockHackLab | `authorized_keys` injection: measure the two identities | `infrastructure.md` *SSH authorized_keys injection* |

## Batch 5 — the classes that were still absent

| # | Lab | Class | Landed in the methodology |
|---|-----|-------|--------------------------|
| 90 | Norc | A real CVE; **CVSS Scope disagreement between CNA and NVD**; a SUID sweep that cannot find file capabilities | `infrastructure.md` SUID sweep (extended), advisory discipline |
| 283 | Los 3 Hackers | Filter evasion: **prevents vs detects**, and a denylist is judged by what it omits | `api_web.md` *Filter evasion and denylist auditing* |
| 93 | Pinguinazo | A sudo grant that names an interpreter: **argument-taking vs runtime-spawned shell** | `infrastructure.md` interpreter-grant criterion |
| 36 | Verdejo | Offline cracking: hash, scheme, cost; **the baseline is a control, not a document** | `infrastructure.md` *Cracking offline* |

---

## Two rows to read first

**Lab 36 (Verdejo), the baseline is a control you build.** The agent was about to
file CWE-916 for a low cost parameter, then built a throwaway account in the same
image with the same build tool and found the same parameter. Worse: `crypt(pw,
"$y$")` returns `*0` on an empty salt, so **there is no API to ask for "the
default"** — the only way to know a baseline is to fabricate a hash with the
library and read your own parameters back. Two of the two hashes in that lab are
**not** weak-hash findings; the weakness was entirely in the sudoers line.

**Lab 129 (DockHackLab), the folklore was in the brief, not the target.** The
finding under audit claimed `0644` on `authorized_keys` fails. Measured across six
modes it does not. But two rows claiming `0664` and `0620` also succeeded, and
`openssh-portable/misc.c:2352` shows the check is `(st_mode & 022) != 0` with an
**owner-uid test that never looks at the group** — so a stock daemon refuses both
and the table contradicted its own mechanism. The refutation of `0644` survived;
the rows did not.

## Reading order for a new engagement

If you are starting a real engagement and have an hour, read in this order:

1. `method/self-corrections.md` — the failures that recur across all 27. They are
   the ones that survive review and reach a client.
2. `method/retrieval-hazards.md` — the ways a scanner confidently reports nothing.
3. The four rows in the tables marked **extended** rather than **new**.
4. The writeup of the lab whose class your target has.
