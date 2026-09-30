# 264 ApkAdmin — Android exported Activity: the gate is a value the caller supplies

**Lab:** 264 · *ApkAdmin* · facil
**Description (full, from the platform catalog):** *"Análisis de APK vulnerable para lograr acceder a una activity que no deberíamos de tener acceso."*
**Target:** `172.17.0.4` — single container `apkadmin_container`, image `apkadmin:latest`, `ExposedPorts 22/tcp, 80/tcp`
**Stack (from the artefact, not from memory):** `package="com.ctf.adminbypass"`, `versionCode=1`, `versionName=1.0`, `compileSdkVersion=34`, `minSdkVersion=24`, `targetSdkVersion=34`; Kotlin, 3 DEX files; host side is `openssh-server` + `python3 -m http.server` on Debian bookworm
**Artefact integrity:** served APK `sha256 4c44625dfc2bbc8a2eb0d127c5d268e1f775a4cc8f126f1d90c88e13b21df985`, byte-identical to the one analysed (verified from inside the container and outside it)
**Outcome:** an activity the UI never links to is declared `android:exported="true"` with **no `android:permission` and no intent-filter**, and its only access control is a boolean intent extra that the *caller* supplies. The credential it discloses is a compile-time string constant in `classes3.dex`, and that same literal authenticates as `uid=1000(pingu)` and then as `uid=0(root)`.

**This is the first mobile/APK writeup in this corpus.** There is no prior mobile art to
imit, so §1 defines the class from scratch and §10 states the rules it yields. The
generalisable claim is deliberately narrow and is stated in the entry criterion, because
*"an activity that should not be reachable"* is not a vulnerability class — it is a
sentence.

---

## 1. The class gap, stated before the findings

"Should not be reachable" compresses five different mechanisms with five different
root causes and five different fixes. This lab was checked against all five before any
of them was written up, because filing the wrong one teaches the reader the wrong thing.

| # | Family | What it requires to be true | Present here? |
|---|---|---|---|
| C1 | **Not exported, but reachable** via an explicit `intent` from an exported component, a `pendingIntent`, a deep link, or a `WebView` JS bridge | the component says `exported="false"` *and* something outside the app can still start it | **No.** `UserActivity` is `exported="false"` (`AndroidManifest.xml:39`) and nothing reaches it from outside. No `PendingIntent`, no `WebView`, no `addJavascriptInterface`, no deep-link `intent-filter` — the four greps in §4 returned nothing |
| C2 | **Exported without a permission**, or with a `permission` that is not enforced | an external principal can start the component and the system imposes nothing | **Yes — this is the lab.** `AdminActivity`: `android:exported="true"` (`:42`), no `android:permission`, no `intent-filter` |
| C3 | **Task hijacking / `taskAffinity` / `allowBackup`** carrying private state across | `taskAffinity` reuse, or backup that moves state out of the sandbox | **No as a bypass.** `taskAffinity`, `allowTaskReparent` and `launchMode` are **entirely absent** from the manifest. `allowBackup="true"` (`:22`) is present but the app **persists nothing**, so there is no private state to carry — see Finding 4 |
| C4 | **Client code as attack surface** | a secret, debug flag, cleartext override, or JS bridge in the shipped client | **Yes, twice.** Hardcoded login pair `admin` / `admin123` (`MainActivity.java:19-20`) and a reward credential compiled into the DEX (`AdminActivity.java:21`). No `network_security_config`, no hardcoded base URL, no WebView |
| C5 | **The server side** | the unlocked surface buys something the *server* authorises | **Partly, and it is the most important row.** The *activity* unlock is **100% client-side** — the disclosed credential is a string constant, and the app package contains **zero network calls**. But the credential it discloses is a **real host credential**, and the reuse to `uid=0(root)` is a genuine server-side authorisation failure |

**Entry criterion (the generalisable one):** *a component, route, or credential that the
application never intended to expose, reached without the authorisation the manifest
claims to require.*

Two clauses in that sentence carry the weight, and both are what makes C2 a *finding* and
not an observation:

1. **"the manifest claims to require."** A component that is exported *and meant to be* is
   not a finding. `MainActivity` is exported and meant to be — the positive control in §5.
   The discriminator is never `exported="true"`; it is `exported="true"` **on a component
   the app's own UI never links to**, which here is corroborated by the platform page:
   *"ningun boton de la app te lleva"* and *"no hay forma de llegar a el desde la
   interfaz."* Intent is established from the shipped UI and code, not inferred from the
   absence of a link.
2. **"the authorisation the manifest claims to require."** This is what forces the
   three-way control in §5 rather than a boolean. A manifest that says `exported="false"`
   claims a protection; one that says `exported="true"` with no `permission` claims
   nothing at all — and the interesting case is the one where the *code* supplies a
   gate, so that the app's authors believe something is protected while the manifest
   authorises the world. That inversion is this lab's whole shape.

**The decisive artefact** is `AndroidManifest.xml` lines 30-42 read together with
`AdminActivity.java:19-25`. Nothing about the *response* distinguishes a correctly
protected activity from this one; only the manifest and the DEX do — the same
"read the source first" rule the web labs obey.

---

## Surface

```
$ nmap -sV -Pn -p- 172.17.0.4
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u10 (protocol 2.0)
80/tcp open  http    SimpleHTTPServer 0.6 (Python 3.11.2)
Service Info: OS: Linux; CPE: cpe:/o/linux:linux_kernel
```

Two ports, both on the plain bridge — `auto_deploy.sh` was **read, not run** (`:193` is
the `while true; do sleep 1; done` that never returns). It declares **no** networks, **no**
`macvlan --internal` segments, and exactly **one** `docker run -d` (`:179`), so the
one-container topology is the intended one. The image history confirms a single stage
with no second service.

**Hidden surface found — and the decisive fact about this lab: the lab ships no device.**
`ExposedPorts` is `22/tcp, 80/tcp`; the image contains `openssh-server` and `python3`
and nothing else (`/app` does not exist; the Dockerfile installs no Android SDK, no
`adb`, no emulator). The APK is served as a **static file** over port 80:

```
$ curl -s http://172.17.0.4/                      → 200, 7668 bytes  (the lab briefing page)
$ curl -s -o AdminBypassCTF.apk \
       http://172.17.0.4/AdminBypassCTF.apk       → 200, 5791613 bytes
```

The host environment compounds this: `adb`, `emulator`, `avdmanager`, `sdkmanager`,
`scrcpy` and `qemu-system-x86_64` are all **absent**, and `/dev/kvm` does not exist. So
there is **no runtime path to the Activity at all** in this engagement. That is recorded
as *untested*, never as a negative — see §8. The APK-level analysis is static and
labelled as such; the SSH/root half of the chain was executed live and measured.

**What TCP cannot see, checked and recorded:** this host exposes no UDP service of
interest (`nmap -p-` is TCP-only, so I state this from the image's `ExposedPorts` and the
absence of any UDP listener in the single container, not from a scan I did not run).
There is no management plane, no nonstandard port, and no renamed path — port 80 serves
exactly two files, both listed above.

**A note on the lab's own page, because it changes the threat model:** `index.html` is the
briefing *and* the hint. It states the exported-component mechanism, names the boolean
extra, and hands out the SSH and `su` steps verbatim. Any analysis that reaches the
finding by reading the page has not analysed the APK. The writeup below rests on the
manifest and the DEX, and cites the page only for the authors' stated intent — which is
exactly what the entry criterion needs.

---

## The class

**Entry criterion question that started it:** *which components does the manifest let
outside callers start, and what does each one do when a caller supplies its arguments?*

**Source that settled it:** `AndroidManifest.xml:40-42` — three lines, and the whole
engagement is in the difference between them:

```xml
<activity android:name="com.ctf.adminbypass.MainActivity"    android:exported="true"/>   ← + LAUNCHER filter
<activity android:name="com.ctf.adminbypass.UserActivity"    android:exported="false"/>
<activity android:name="com.ctf.adminbypass.AdminActivity"   android:exported="true"/>   ← no permission, no filter
```

**The sharpest single fact in the engagement.** On `targetSdkVersion="34"`
(`AndroidManifest.xml:12`) — Android 12+ — an activity with **no** `intent-filter`
**must** declare `android:exported` explicitly or the install fails. So
`android:exported="true"` on `AdminActivity` is not an inherited default and not an
oversight of omission: **the author had to type it.** There is no version of this
manifest where `AdminActivity` is accidentally public.

**And the gate is the wrong shape entirely.** `AdminActivity.java:19-25`:

```java
boolean isAdmin = getIntent().getBooleanExtra("isAdmin", false);
if (isAdmin) {
    flagView.setText("Acceso SSH\n\nUsuario: pingu\nContrasena: chocolate");
} else {
    Toast.makeText(this, R.string.access_denied, 0);
    finish();
}
```

The value that decides authorisation is read **from the intent** — i.e. from the caller.
The activity's entire access model is *"trust a boolean the attacker chose."* There is no
`getCallingPackage()`, no `checkPermission()`, no signature check, no server call. The
`else` branch is the *only* thing resembling a control, and it is a `Toast` plus
`finish()` — a decision made **after** the activity has already been admitted by the
system, in the attacker's own process, on a screen the attacker asked for.

**The command the manifest authorises** (derived, not executed — see §8):

```bash
adb shell am start -n com.ctf.adminbypass/.AdminActivity --ez isAdmin true
```

`-n` resolves an explicit component; `--ez` sets the boolean extra. The system will not
prompt, because the manifest imposed no permission to prompt about.

---

## Chain

The APK half is static. The host half was executed, and **every identity was measured
rather than assumed**.

| # | → | Mechanism | Identity proof |
|---|----|-----------|----------------|
| 0 | served APK | `GET /AdminBypassCTF.apk` | `sha256 4c44625d…1df985`, identical inside and outside the container |
| 1 | **`AdminActivity`, exported to any caller** | `am start -n com.ctf.adminbypass/.AdminActivity --ez isAdmin true`; manifest imposes nothing (`AndroidManifest.xml:42`), gate reads the caller's own extra (`AdminActivity.java:19`) | **not executed** — no device; static, see §8. Manifest path proven twice independently (§4) |
| 2 | credential disclosure | `flagView.setText("…Usuario: pingu\nContrasena: chocolate")` — a **string constant in `classes3.dex`**, not a server token | `strings -a classes3.dex` → `Usuario: pingu`, `Contrasena: chocolate` |
| 3 | `pingu` | SSH with the disclosed literal | `uid=1000(pingu) gid=1000(pingu) groups=1000(pingu)`, `CapEff: 0000000000000000` |
| 4 | **`uid=0(root)`** | `su` with **the same literal** | before: `uid=1000(pingu)`; after: `uid=0(root) gid=0(root) groups=0(root)`, `Uid: 0 0 0 0`, `CapEff: 00000000a80425fb` |

Hop 4 is reported as a **crossing from `uid=1000` to `uid=0` measured in the same
shell**, not as "root": the escalation is only a finding if the uid actually changed, and
the before/after pair is the evidence. `CapEff` is empty for `pingu` and populated for
root — the unprivileged session genuinely held no capabilities, so nothing was
pre-granted.

### Evidence — hop 3 and hop 4, executed

```
[INTENDED]  pingu@172.17.0.4
  AUTH OK
  $ id
    uid=1000(pingu) gid=1000(pingu) groups=1000(pingu)
  $ egrep '^(Uid|Gid|CapEff)' /proc/self/status
    Uid:	1000	1000	1000	1000
    CapEff:	0000000000000000

BEFORE (the same shell that will su):
    uid=1000(pingu) gid=1000(pingu) groups=1000(pingu)
    home: /home/pingu   -> .bash_logout .bashrc .profile   (nothing planted)

NEGATIVE: su with a WRONG password (must fail):
    stdout: ''   stderr: Password: su: Authentication failure

ATTACK: su with the SAME literal from AdminActivity.java:21
    stdout: uid=0(root) gid=0(root) groups=0(root)
    Uid:	0	0	0	0
    CapEff:	00000000a80425fb
```

### Evidence — a 2×2, because one success proves nothing

A single successful login cannot distinguish "the credential works" from "sshd accepts
anything". Both directions were run for both accounts, so the detector is shown to fire
and to fail:

| | `chocolate` | `wrongpw-ctrl` |
|---|---|---|
| `pingu` (uid 1000) | AUTH OK → `uid=1000(pingu)` | `AuthenticationException: Authentication failed.` |
| `root` | AUTH OK → `uid=0(root)` | `AuthenticationException: Authentication failed.` |

The same matrix at the `su` boundary: wrong password → `su: Authentication failure`,
correct password → `uid=0(root)`. **The rejection is byte-distinguishable from success**,
so these are real controls and not an always-true oracle.

---

## Findings

### Finding 1 — `AdminActivity` is exported with no permission and no filter (CWE-926)

**Evidence — `AndroidManifest.xml:40-42`:**

```xml
<activity
    android:name="com.ctf.adminbypass.AdminActivity"
    android:exported="true"/>
```

No `android:permission`. No `<intent-filter>`, so it is not a launcher and has no
implicit entry point either — it is reachable **only** by explicit component name, which
is what makes it a target for a deliberate `am start` and what makes it invisible to a
casual UI walkthrough. On `targetSdkVersion="34"` this attribute is mandatory and was
therefore authored deliberately (see §3).

**Impact:** any application on the device — or any process holding the `adb shell`
identity, i.e. any user with USB debugging enabled — can display a screen the vendor
never intended anyone to see, and can choose the argument that screen branches on.

**Root cause:** export status chosen per-component with no threat model behind it, and
the security decision pushed into the Activity's own `onCreate` where the only input is
the attacker's intent extra.

**Remediation:** `android:exported="false"`, full stop. If a legitimate cross-process
entry is ever needed, declare a `signature`-protection-level permission and check it —
and note that a check *inside* the activity is strictly worse than the manifest flag,
because the system has already launched the process by then.

### Finding 2 — The access control is a boolean the caller supplies (CWE-807, CWE-602)

**Evidence — `AdminActivity.java:19`:** `getIntent().getBooleanExtra("isAdmin", false)`.

This is a distinct defect from Finding 1 and would remain a finding if the activity were
`exported="false"`: any *internal* component, a `pendingIntent`, or a future exported
entry point inherits the same broken check. The grep for the four APIs that would
constitute a real caller check returned **nothing**:

```
$ grep -rn "getCallingPackage\|getCallingActivity\|checkPermission\|enforcePermission" com/ctf/adminbypass/
(no output)
```

**Root cause:** authorisation decided from untrusted input. `isAdmin` is an *attestation*,
not a *fact*: nothing in the system can make it true, so its only possible value is
whatever the caller chose.

**Remediation:** derive the privilege decision from state the app controls — a
`signature`-verified identity, a `PendingIntent` whose creator the system attributes, or
a server-side session. Never from an extra.

### Finding 3 — Hardcoded login credentials in the client (CWE-798)

**Evidence — `MainActivity.java:19-20`:**

```java
private final String validUser = "admin";
private final String validPassword = "admin123";
```

Used at `MainActivity.java:42` (`Intrinsics.areEqual`) to gate the transition to
`UserActivity`. Recovered independently of jadx from the raw DEX
(`strings -a classes3.dex` → `admin123`).

**Impact:** the app's login screen provides no security. Anyone who unzips the APK is
authenticated. This is the lab's own "user screen", and it is not the finding the lab is
about — but it is the same root cause as the headline: **secrets and decisions in the
client.**

**Remediation:** authenticate against a server; the client holds a session token, not a
password.

### Finding 4 — `android:debuggable="true"` and `android:allowBackup="true"` — real, but carrying nothing here (CWE-489, CWE-530)

**Evidence:** `AndroidManifest.xml:21-22`, with `android:fullBackupContent="@xml/backup_rules"`
and `android:dataExtractionRules="@xml/data_extraction_rules"`, both of which decode to
**empty rule sets**:

```xml
<full-backup-content/>
<data-extraction-rules><cloud-backup/></data-extraction-rules>
```

An empty `<full-backup-content/>` backs up **everything by default**, and
`debuggable="true"` means any process that can attach a debugger — or simply `run-as` on
a debuggable build — reads the app's private data directly.

**Reported honestly, and deliberately *not* inflated:** I grepped the app package for
persistence and found **none**:

```
$ grep -rn "SharedPreferences\|openFileOutput\|SQLiteDatabase\|MODE_WORLD" com/ctf/adminbypass/
(no output)
```

The credential is a compile-time constant (`AdminActivity.java:21`), not stored state.
So **`allowBackup` carries no private state in this app, and it is not on the path to
this lab's unlock.** It is filed because the pairing is a real production weakness that
would become critical the moment this app stored a session or a token — and because the
empty rule sets are a default nobody chose deliberately.

**Remediation:** `debuggable="false"` in the shipped manifest; scope the backup rules to
explicit non-sensitive paths, and set `android:allowBackup="false"` unless backup is a
product requirement.

### Finding 5 — A real host credential, reused across a privilege boundary (CWE-521)

**Evidence — from the client artefact, then confirmed live.** The literal
`Contrasena: chocolate` at `AdminActivity.java:21` authenticates as **two different
identities** on the host (§4, 2×2). Independently, the image's own build layer sets
`PermitRootLogin yes`, `PasswordAuthentication yes`, and provisions `root` with the same
secret as the unprivileged account.

**Impact:** the mobile finding is the delivery mechanism and the credential reuse is the
impact. The activity discloses a password whose blast radius is the host's root account,
not a phone screen. This is the part of the lab that generalises past Android: **treat a
credential disclosed by a client-side artefact as a host credential, and check every
account it opens before celebrating the mobile bypass.**

**Remediation:** distinct secrets per privilege tier; `PermitRootLogin no` and
`PasswordAuthentication no` with key-only auth on internet-reachable hosts.

---

## Controls that held

Each row is a control that was **observed to fire**, with the positive control that
proves the detector is not simply broken. A control that has never seen a success is not
a control.

The honest difficulty: **no runtime positive control was possible for the Activity layer**
(§8). So the manifest is exercised as a **three-way** control, which is the strongest
statement the static evidence supports. One procedure — read `exported` and `permission`
for every component — produces all three outcomes:

| Component | `exported` | `permission` | Reachable externally by design? | Reachable in fact? |
|---|---|---|---|---|
| `MainActivity` (`:30-31`) | `true` | — | **Yes** — LAUNCHER, meant to be | yes — this is the **positive control** |
| `UserActivity` (`:38-39`) | `false` | — | **No** — correct | **no** — the **negative control** |
| `AdminActivity` (`:41-42`) | `true` | **none** | **No** — never linked from UI | **yes** — **the finding** |

This matters more than a boolean would. If the procedure flagged every `exported="true"`
it would flag `MainActivity` too, and the writeup would be reporting a launcher as a
vulnerability. The fact that the same procedure *refuses* `UserActivity` is what
establishes the discriminator is real and not just "exported = bad".

| Control | Where | Positive control that proves this detector works |
|---|---|---|
| **`exported="false"` on `UserActivity`** | `AndroidManifest.xml:39` | Read-only, **static** — the gate cannot be exercised without a device. The discriminator is the three-way table above: the identical procedure returns "reachable" for `MainActivity` and "not reachable" for `UserActivity`, so it distinguishes. See §8 |
| **sshd password authentication actually rejects** | 2×2 matrix, §4 | **Proven in both directions on both accounts.** Wrong password → `Authentication failed`; correct password → a session and a measured `id`. The detector fires and fails; it is not always-true |
| **`su` password check actually rejects** | `su -c id`, §4 | Wrong → `su: Authentication failure`; correct → `uid=0(root)`. Same shape, same proof |
| **Unprivileged session holds no capabilities** | `/proc/self/status` | `CapEff: 0000000000000000` for `pingu` vs `00000000a80425fb` for root. The escalation is not an artefact of pre-granted privilege |
| **The app persists nothing** | grep, Finding 4 | Absence of `SharedPreferences`/`SQLiteDatabase`/`openFileOutput` — which is what stops `allowBackup` from being over-claimed |
| **The label `textFlag` is not trusted as an oracle** | `activity_admin.xml` | `@+id/textFlag` is an empty `TextView` that starts as `android:text=""`; the credential is `setText()` at `AdminActivity.java:21` only. A reader looking for a pre-baked flag in the layout finds nothing — and the `find`-for-a-flag search in §9 is the same check |

**The reportable negative:** the `else` branch (`Toast` + `finish()`) is a control that
fires and *is* distinguishable from success — it shows `"Acceso denegado"` and never sets
the text. But it cannot prevent anything: by the time it runs, the activity is already
on screen in a process the caller chose. A control that runs **after** admission is a
report, not a gate — the same rule the web corpus states for a CSRF `is_exploit` check
placed after its write.

---

## NOT tested vs discarded with reason

**NOT tested** — honest gaps, not conclusions:

- **`am start` was never executed.** No `adb`, no emulator, no `/dev/kvm`, no SDK, and the
  lab image ships no device. Hop 1 is derived from the manifest and the DEX and is
  labelled static everywhere it appears. No runtime positive control exists for the
  Activity layer, and the "controls that held" table says so rather than implying
  otherwise.
- **Signing identity.** `keytool -printcert -jarfile` returned `Not a signed jar file` —
  the APK carries an **APK Signature Scheme v2/v3** block, not v1 JAR signing, so this
  tool is the wrong reader. `apksigner` is absent. **Signing identity: unretrieved.**
  Not "untrusted", not "debug-signed" — simply not read.
- **The `else` branch's user-visible behaviour** (`Toast` + `finish()`) is read from
  source, never observed on a screen.
- **Whether any real-world launcher or OEM skin auto-starts `AdminActivity`.** It has no
  intent-filter, so a bare `LAUNCHER` intent cannot reach it; I did not test OEM-specific
  deep-link or assistant behaviours.
- **Post-root persistence, other accounts, and lateral movement** from `uid=0(root)`. The
  lab's stated success criterion is `id`, and nothing past it is in scope.

**Discarded with reason** — each on evidence, not on absence of trying:

- **C1, exported-component-reachability (`pendingIntent`, deep link, WebView bridge).**
  Discarded on four greps over the whole app package, all returning nothing:
  `WebView`, `JavascriptInterface`, `PendingIntent`, `getCallingPackage`. The manifest
  has exactly one `intent-filter` and it is the `LAUNCHER` pair on `MainActivity`.
- **C3, task hijacking.** `taskAffinity`, `allowTaskReparent`, `launchMode` and
  `documentLaunchMode` are **absent from the manifest entirely** (grep returned nothing).
  With no `taskAffinity` override there is no cross-application task reuse to hijack.
- **C4, cleartext / `network_security_config`.** **No `network_security_config.xml` exists
  in the APK** (`find` returned nothing), so there is no cleartext override to widen. And
  the app makes no network calls at all — `HttpURLConnection`, `Retrofit`, `OkHttp`,
  `Socket` and `openConnection` are all absent from the app package, and there is no
  hardcoded URL. There is no client→server channel to attack, which is also why the
  unlock is provably client-side.
- **Signing-certificate trust / repackaging.** Not attempted; out of scope and no tool.
- **Container escape.** The container is a plain `docker run -d` on the default bridge,
  no `docker.sock`, no `--privileged`, no extra capabilities. Not pursued further.

---

## Instrumentation defects

Per the runbook this is the most valuable section. Two of these **nearly** produced a
false finding, and one produced a false confirmation.

### 1. My ad-hoc AXML string-pool parser produced a **confidently wrong manifest string list**

I wrote a binary `AndroidManifest.xml` parser to get a second, jadx-independent read of
the shipped artefact. It reported 64 string-pool entries, and the first two were
`'theme'`, `'theme'`. **No real manifest has `theme` as a string-pool entry twice, let
alone as the first entry.** I had mis-placed the offset table: it lives at
`headerSize`, and I had also mis-handled the `flags & UTF8` bit, so the pointer table
and the string data were off by a fixed amount and every entry decoded to the same
wrong bytes.

**What caught it:** the repeated `theme`. A parser that has silently mis-offset a string
table does not produce *no* output — it produces **plausible-looking wrong output**, and
I nearly quoted it as independent corroboration of the manifest.

**Lesson — the generalisable form, and it applies to every mobile lab:** for AXML, do not
hand-roll. Use `aapt2 dump xmltree` / `apkanalyzer` / `apktool`. If those are missing,
say the manifest was read through exactly one path and do not claim corroboration you
did not obtain. I replaced it with a real second path (§4).

### 2. The second path I did get: UTF-16LE strings on the binary manifest

```
$ strings -a -e l raw/AndroidManifest.xml | grep -E 'adminbypass|exported|Activity'
debuggable
exported
allowBackup
com.ctf.adminbypass
<com.ctf.adminbypass.AdminActivity
 com.ctf.adminbypass.MainActivity
 com.ctf.adminbypass.UserActivity
```

This confirms the component names and the `exported` attribute exist **in the shipped
binary** and are not a jadx rendering artefact. Note the first attempt used plain
`strings -a` and returned **nothing at all** — the AXML string pool is UTF-16, so the
default single-byte scan cannot see it. An analyst who ran only `strings` would have
concluded the manifest was clean. The same `-e l` on `classes3.dex` is what produced the
independent `isAdmin` / `chocolate` / `admin123` evidence.

### 3. `keytool -printcert` is the wrong tool for a modern APK, and its output reads like a verdict

`Not a signed jar file` looks like a statement about trust. It is a statement about
**v1 JAR signing**, which this APK does not use — it carries a v2/v3 APK Signing Block
(`file(1)` confirms `with APK Signing Block`). Without `apksigner` the honest result is
**"signing identity unretrieved"**, not "unsigned" and certainly not "untrusted".

### 4. `jadx` finished with `ERROR - finished with errors, count: 19` on a 2704-class APK

19 decompilation errors on a Kotlin/AndroidX build is ordinary, and the three classes
that matter (`MainActivity`, `AdminActivity`, `UserActivity`, all in `classes3.dex`)
decoded cleanly to readable Java with intact control flow. **This was verified, not
assumed:** the `isAdmin` branch and the credential literal are visible in both the jadx
output and the raw DEX strings. The count alone is not a licence to trust the output —
it is a licence to check the specific classes that carry the finding.

### 5. `sshpass` is absent — recorded as untested, not as a negative

`sshpass` was not installed. Rather than treat the SSH leg as blocked, I used
`paramiko` — which is also a **different invocation path** for the same test, so the
credential results do not depend on one client. The 2×2 in §4 is the control for this.

### 6. "Not a signed jar file" and "no flag file" are both *absence of evidence*

Two searches in this engagement returned nothing — the `keytool` output and the
flag search in §9. One is a wrong-tool artefact (defect 3). The other is a real absence
and is reported as a measured absence **with the search that established it**, never as
a negative result derived from a tool that could not have found it.

---

## Reward

**No `FLAG{}`, `DL{}` or `CTF{}` exists in this lab.** Three searches, and the *method*
of each is stated so the absence is auditable:

```
1. Decoded app + resources:
   $ grep -rniE "flag\{|DL\{|CTF\{|FLAG:|Congratulations" sources/com/ctf/ res/values/strings.xml
   (no output)

2. Raw DEX — all three files, independent of jadx:
   $ for d in raw/classes*.dex; do strings -a $d | grep -E 'flag\{|FLAG\{|DL\{|CTF\{'; done
   (no output)

3. Host, as root, and the served page:
   $ grep -rIl "flag{" /var/www /opt /root /home
   (no paths above — no flag file)
   $ grep -oiE 'flag\{[^}]*\}|Congratulations' index.html
   (no output)
   $ ls -la /var/www      ->  AdminBypassCTF.apk, index.html   (only two files)
```

`/opt`, `/root` and `/home` were searched at `uid=0(root)` after the escalation, so
search 3 is not a permissions-limited negative.

**The lab's actual reward is the identity transition itself**, and the lab states its own
success criterion plainly: *"Si `id` devuelve `uid=0(root)`, has completado el
laboratorio."* That is what was measured — `uid=0(root) gid=0(root) groups=0(root)` —
and the credential pair `pingu` / `chocolate` is **not** a flag: it is a hardcoded
compile-time constant at `AdminActivity.java:21`, reachable without difficulty, which is
the entire point of the lab.

---

## Restore

```
$ docker rm -f apkadmin_container && docker run -d --name apkadmin_container apkadmin:latest
restored IP=172.17.0.4
```

Recreated **from the image**, not by undoing edits — so the SSH login trail could not
survive by construction. Verified **positively**, not by "the container is up":

```
GET /index.html            -> HTTP 200, 7668 bytes
GET /AdminBypassCTF.apk    -> HTTP 200, 5791613 bytes
$ docker exec apkadmin_container id
uid=0(root) gid=0(root) groups=0(root)
```

And the negative side, so "restored" means the artefacts are gone rather than the
service merely answering:

```
$ wc -l < /var/log/auth.log
sh: 1: cannot open /var/log/auth.log: No such file
$ ls -A /root        -> .bashrc .cache .profile      (as shipped; .bash_history absent)
$ ls -A /home/pingu  -> .bash_logout .bashrc .profile (as shipped)
```

I used non-interactive `paramiko.exec_command` throughout, which writes no
`~/.bash_history`; the pre-restore listing was identical to the post-restore listing, so
no in-container artefact needed removing. **Nothing was written under
`~/dockerlabs/labs/`** — the APK, the jadx tree and the probe scripts live
in `/tmp/opencode/264`. `git commit` and `git push` were **not** run; `git status` /
`git diff` read-only.

---

## Feed-forward — the APK class this methodology lacks

Mobile is new to the corpus, and the platform description for this lab is a symptom of
why: *"acceder a una activity que no deberíamos de tener acceso"* names no attack
surface, no mechanism, and no control. A reader who has not seen a manifest cannot act
on it. The seven rules below are what this engagement produced, in the order they would
have saved time.

1. **Separate the five families before testing any of them, and say which the lab has.**
   "Exported component" and "should not be reachable" are not a class; §1's C1-C5 table
   is the smallest unit that generalises. Filings that collapse C1 (not exported but
   reached) into C2 (exported with no permission) give the client a fix for the wrong bug
   — in this lab, fixing C2 by adding a caller check inside `onCreate` would leave C2
   open and give false assurance.

2. **On `targetSdk ≥ 31`, a missing-`intent-filter` activity's `exported` attribute is
   authored, never inherited.** The install fails without it. So `exported="true"` on such
   a component is a decision someone typed, and the writeup should say so — it removes the
   single most common "it was just a default" explanation.

3. **A gate that reads the intent is not a gate.** `getIntent().getBooleanExtra(...)` used
   to decide privilege is the recurring pattern in this family, and it is
   CWE-807 every time. The tell is structural: the value comes from *outside* the trust
   boundary. Grep `getCallingPackage|checkPermission|enforcePermission` — all four
   returning nothing is the positive evidence of absence, and it is a stronger artefact
   than any response code.

4. **Run the manifest through a three-way control, never a boolean.** Enumerate every
   component as (intended-reachable / intended-unreachable) × (reachable-in-fact /
   not). You need at least one of each. This lab supplies all three for free —
   `MainActivity` (yes/yes), `UserActivity` (no/no), `AdminActivity` (no/yes) — and the
   middle row is what stops the launcher being filed as a finding. A detector that flags
   every `exported="true"` is not a detector.

5. **Establish intent from the shipped artefact, not from the absence of a link.** In
   this lab the corroboration came from the platform page (*"ningun boton de la app te
   lleva"*) plus the absence of any `startActivity`/`Intent` naming `AdminActivity` in the
   DEX. Both are needed: a missing link alone is weak, because apps do link hidden
   screens from notifications or shortcuts.

6. **A credential disclosed by a mobile artefact must be run through every account it
   opens, on every tier, before the mobile finding is written up.** The activity bug here
   is the delivery; the impact is `uid=0(root)`. Analysts habitually stop at "I reached the
   admin screen" and file the blast radius as a phone screen. Measure `id` on the far
   side of the credential — and measure the *unprivileged* side too, so the crossing is a
   before/after pair rather than an assertion.

7. **State the runtime you had.** When no device ships and no `adb`/emulator/KVM exists,
   the Activity half is **static**, the manifest is a **three-way static control**, and
   there is **no runtime positive control** for it. Say that in the writeup instead of
   letting a manifest read pass as an exploit. The host half, by contrast, was executed
   with a 2×2 and a `su` negative — and that asymmetry is the honest shape of this lab.

**One structural note for the class:** Android's authorisation model is **declared in
the manifest and enforced by the system**, so the manifest is the whole security
boundary. That is the opposite of a web app, where the code is the boundary and the
config is a hint. The transferable habit is not "read AndroidManifest.xml" — it is
**find the artefact where your platform's boundary is actually written, and read it
before you touch the app.** For a web lab that file is often the route table plus its
middleware registration order; here it is 40 lines of XML that decide everything.
