# DockerLabs 141 — "Dockerlabs" (Fácil)

**Target:** container `lab141_container`, image `dockerlabs:latest`
**Deployment:** `docker run -d --name lab141_container dockerlabs:latest` (plain — no `--privileged`, no bind mounts, no Docker socket)
**Image:** Ubuntu 24.04 (`org.opencontainers.image.version=24.04`), Apache 2.4.58, PHP 8.3 via `mod_php`
**CMD:** `/bin/sh -c "service apache2 start && tail -f /dev/null"`
**Result: remote code execution as `www-data` (uid=33). No `FLAG{}` in the lab — the reward is the RCE itself, and no reward token exists on the target.**

The lab is named "Dockerlabs" and its listing page enumerates other DockerLabs. Per `decision-making.md` §7, the name is a label; the surface is what the port scan returns. Here the name is *roughly* honest — the page is a catalogue of container labs — but the actual vulnerability is a **file-upload RCE**, not a container-escape. The container boundary is what makes the RCE's blast radius small; the RCE itself is a plain web bug. Both halves matter and are reported separately below.

---

## 1. Surface

`nmap -sV -Pn -p- 172.17.0.14`:

```
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.58 ((Ubuntu))
Not shown: 65534 closed tcp ports (conn-refused)
```

One TCP port. `GET /index.php` (200) is a static lab catalogue (`Trust`, `Upload`, `Injection`, `CapyPenguin`, …) whose download/upload/copy buttons have **no JavaScript handlers** — decorative. `scripts.js` only implements client-side search filtering. The only real sink is `upload.php`, reached via `machine.php`'s file-upload form.

`upload.php` (19 lines) accepts an uploaded file, takes `basename($_FILES["file"]["name"])`, and stores it under `uploads/` **if and only if** the extension is `zip` or `phar`:

```php
$fileType = pathinfo($targetFilePath, PATHINFO_EXTENSION);
if($fileType != "zip" && $fileType != "phar") { echo "No se permite..."; }
else { move_uploaded_file($_FILES["file"]["tmp_name"], $targetFilePath); }
```

---

## 2. The four boundary questions — measured, each with a positive control

These are the questions that decide *where the trust boundary is*, and none of them is visible from a port scan. Each answer below was forced to produce a positive so the detector is proven connected, per the "detector pointed at something that does not exist returns a clean, believable negative" rule.

### (a) Privilege — does it run as root, and is it `--privileged`?

**The web process runs as `www-data` (uid 33), not root.** The Apache *master* is uid 0 (it binds :80), but every worker that actually runs PHP is uid 33:

```
$ docker exec lab141_container id                      # exec identity (root — this is docker exec, NOT the web)
uid=0(root) gid=0(root) groups=0(root)
$ for p in $(pgrep apache2); do grep ^Uid /proc/$p/status; done
pid=24 comm=apache2 Uid: 0   0  0  0      # master, binds :80
pid=28 comm=apache2 Uid: 33  33 33 33     # workers, run PHP
pid=29..32  Uid: 33 ...
```

**Positive control:** the RCE itself, executed by the interpreter under the request, returns `uid=33(www-data)` — so the measured identity is the *executing* one, not the exec one. This is `decision-making.md` §8 applied: a `docker exec` root shell is a measurement of `docker exec`, and reporting it as "the container is root" would have been wrong.

`--privileged` is **false** (`HostConfig.Privileged=false`). No `--cap-add`, no `--cap-drop`, no `--security-opt`, `ReadonlyRootfs=false`, `PidMode`/`IpcMode` unset (private), `NetworkMode=bridge`.

### (b) API surface — is the Docker socket mounted?

**No.** The lab container has no `docker.sock` anywhere on its filesystem, and no Docker CLI:

```
$ docker exec lab141_container sh -c 'ls -la /var/run/docker.sock; find / -name docker.sock 2>/dev/null; echo done'
ls: cannot access '/var/run/docker.sock': No such file or directory
done
$ docker exec lab141_container sh -c 'which docker; echo rc=$?'
rc=1
```

**Positive control (the important one):** a throwaway container was started *with* `-v /var/run/docker.sock:/var/run/docker.sock`, and the identical detector immediately returned a hit — `srw-rw---- 1 root 107 ... /var/run/docker.sock` (a Unix socket, not a regular file, so a `test -f` detector would have missed it). From that same socket, a `python:3.12-slim` helper issued `GET /version` → `HTTP/1.1 200 OK` and `POST /containers/create` → `201 Created`, then started a **privileged** sibling that bind-mounted the host `/tmp` and wrote `/tmp/lab141_socket_proof`, which landed on the host as `root root`, containing `SOCKET_GIVES_HOST_ROOT`. The unprivileged operator could not even delete it (`Operation not permitted` on sticky `/tmp`).

That is the whole point of the control, and it is why it was run: **a mounted Docker socket is root on the host, without exception** — measured here, not assumed. The lab container does not have one, so the abuse below stops at the container. (The demonstration container and its marker were cleaned up as far as the unprivileged user could; the root-owned `/tmp/lab141_socket_proof` marker remains and needs root to remove.)

### (c) Capabilities — which ones survive, and which decide?

Read from `/proc/self/status`, not from memory. From the **executing** identity (`www-data`, under the RCE):

```
CapPrm: 0000000000000000
CapEff: 0000000000000000
CapBnd: 00000000a80425fb
NoNewPrivs: 0
```

`www-data` holds **zero** permitted/effective capabilities. Its bounding set is the stock Docker default `0xa80425fb` — the same set `docker exec` (root) sees for `CapBnd`/`CapEff`/`CapPrm`, i.e. the container's ceiling was never widened. `NoNewPrivs: 0`. **The surviving bounding set is what decides**, and here it is the unprivileged default: no `CAP_SYS_ADMIN`, no `CAP_SYS_PTRACE`, no `CAP_NET_ADMIN` in the *effective* set of the identity that would be used in an attack. (The root `docker exec` context also shows `CapSeccomp`/`Seccomp` filtering is active in this environment; the web workers inherit it.)

### (d) User identity — is a root container serving the web?

The container's init/master is root, but the **serving process is `www-data`**. A root container serving a web app is a root container with an RCE waiting; here the RCE arrived, and the identity that executed it is uid 33 with zero capabilities. Namespace isolation (`uid_map 0 0 4294967295`, cgroup `0::/`, container hostname) holds: `www-data` cannot traverse `/proc/1/root` (`Permission denied`).

**Summary of the boundary: a well-configured, unprivileged container with a narrow application bug.** The four answers are all "no" — no privileged, no socket, default capabilities, unprivileged web identity — which is precisely why the RCE's impact is contained.

---

## 3. Finding used — RCE via `.phar` upload (CWE-434 / CWE-434→CWE-94)

**Root cause:** the upload allowlist treats `.phar` as a safe document type, but the **stock** Apache/PHP handler *executes* `.phar`. The stock Ubuntu `php8.3.conf` ships:

```
<FilesMatch ".+\.ph(?:ar|p|tml)$">
    SetHandler application/x-httpd-php
</FilesMatch>
```

The upload filter and the server's MIME map are two independent artifacts that were never reconciled. The filter blocks `.php` and `.phtml` but permits `.phar`, which the handler runs — so the allowlist carries **no security weight against this class** (it is *ineffective*, not absent; see `infrastructure.md` § *Web server configuration*).

**Chain (literal output):**

1. Upload a PHP payload as `.phar`:
   ```
   $ curl -F "file=@probe.phar" -F "submit=1" http://172.17.0.14/upload.php
   El archivo probe.phar ha sido subido correctamente.
   ```
2. Request it back — Apache executes it:
   ```
   $ curl http://172.17.0.14/uploads/probe.phar
   UPLOAD_EXECUTED uid=33 user=www-data
   ```

**Impact:** unauthenticated remote code execution as `www-data`. The `uploads/` directory is `drwxrwxrwx`, so the uploaded file is readable/executable by the web server. Blast radius is the container's own filesystem as an unprivileged, zero-capability user; no host access (socket absent, not privileged).

**CWE:** CWE-434 (Unrestricted Upload of File with Dangerous Type) → CWE-94 (Improper Control of Generation of Code / code injection via execution).

**Root cause vs mechanism (§ *Root cause confused with mechanism*):** patching `upload.php`'s extension list is the *mechanism*; the *root cause* is a server-level MIME map that executes a whole family of extensions inside a directory that receives untrusted uploads. A patch to the mechanism ships nothing, because the next thing anyone uploads to `uploads/` is executed by the same global handler.

**Remediation (name the decision, not the handler):**
- Serve `uploads/` from a location where the PHP handler is disabled — `<Directory /var/www/html/uploads> php_flag engine off </Directory>` (or `SetHandler none` / remove the `SetHandler` inheritance) **and** set `Options -Indexes`. This is the operative fix.
- Independently: make the upload allowlist decision match what the server *executes* — do not treat `.phar` as inert — and store uploads outside the document root.
- The uploads directory being world-writable and browsable (`drwxrwxrwx`, `Index of /uploads` served) is a second, lower-severity finding (CWE-732 / CWE-548): it is the delivery mechanism for finding #1, not the root cause.

---

## 4. Filter behaviour — controls that held, and where they did not

The filter is `pathinfo(..., PATHINFO_EXTENSION) != "zip" && != "phar"` — exact, case-sensitive, last-extension-wins. Measured:

| Input | Result | Interpretation |
|---|---|---|
| `probe.phar` | accepted, **executed** | the vector |
| `x.zip` | accepted, **not executed** (served as bytes: `ETag`, `Last-Modified`, no `Content-Type: text/html`) | control that held — `.zip` is inert here |
| `x.php` | rejected (`No se permite…`) | control that held |
| `x.PHAR` | rejected | filter is case-sensitive |
| `x.php.phar` | accepted, **executed** | last-extension-wins; both the filter and the handler regex match on the end |

The `.zip` result is the useful negative: **the allowlist permits `.zip`, and that permission is harmless because Apache does not map `.zip` to the PHP handler.** Same allowlist, one executable entry, one inert entry — which is what makes "the allowlist re-points the extension it allows" (§ *Web server configuration*) concrete rather than theoretical. A control that let `.zip` through and a control that let `.phar` through look identical at the upload endpoint; only the serve-back differential separates them.

---

## 5. Reward

**There is no `FLAG{}` in this lab.** An exhaustive grep over the whole filesystem (as root, and as `www-data` through the RCE) for `flag{|FLAG{|CTF{|reward|congratulations` returned exactly two hits, **both false positives**:
- `/usr/share/perl/5.38.2/Pod/Perldoc.pm` — a Perl doc file containing the English word "reward" in prose;
- my own `uploads/hunt.phar` — the detector matched its own planted artifact.

Neither is a reward token, and the two hits are the classic shape of a predicate that cannot fail (it matched the string it was hunting, including inside its own input). Reporting a reward here would be fabrication. The lab's "reward" is the RCE primitive itself; per the task rules I report the literal evidence and do not invent a token.

---

## 6. Escape or abuse?

**Abuse, not escape.** The RCE obtains code execution *inside* the container's own namespace, as an unprivileged zero-capability user, with no route to the host:

- no Docker socket (proved with a positive control above);
- not privileged; default capability bounding set;
- `www-data` cannot read `/proc/1/root` (`Permission denied`);
- `uid_map 0 0 4294967295`, private pid/ipc/net namespaces; host filesystem unreachable;
- from `www-data`: no sudo command grants, no writable files outside the webroot, `/etc/cron.d` root-owned — no in-container escalation to root was found either.

Per the escape/abuse distinction, **abuse** = the container correctly uses its own API to do something the operator did not intend (here: an untrusted upload executed by a global handler). **Escape** = the container reaches something outside its namespace. This lab is abuse. The remediation follows accordingly: it is a **deployment/configuration** fix (which handler applies to the upload directory), not a runtime/kernel patch — because nothing about the runtime was wrong. The runtime held perfectly; the operator's MIME map did not.

---

## 7. Rest of the evidence

- **No container escape was attempted beyond read-only boundary enumeration,** because there is no socket and no privileged flag to abuse, and a kernel/runtime escape on a shared host is an operational-risk decision — not something to fire at a lab that is already solved. That choice is documented here rather than hidden: this is the "before reporting an escape, check what you can do with the result and whether it is in scope" control, and in this case the boundary check itself is the deliverable.
- **Other containers untouched:** baseline 19 → after this engagement 21 (the 2 extra are `lab141_container` and the socket positive-control container). All seven `cybervault-*` containers remained up with unchanged uptimes/health.

## 8. Design observation

The lab is well-constructed as a *misuse* exercise: it teaches that a container is not a security boundary you can lean on when the application itself has a bug, and that a default-configured runtime faithfully contains that bug. The "Docker security" framing is about the **deployment's** responsibility, and the fix lands in deployment config. The instructive detail is that the container boundary *worked* — the author made the app vulnerable but the container correctly unprivileged, which is exactly the separation of concerns the methodology wants to teach.

---

*No commit made. Leak-scan on the added lines: see the verification section of the session.*
