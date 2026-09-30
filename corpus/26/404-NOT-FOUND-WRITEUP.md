# 404-NOT-FOUND — DockerLabs lab 26 (Fácil)

Ubuntu 24.04, Apache 2.4.58, PHP, OpenSSH 9.6p1, shipped as a DockerLabs image
(`404-not-found.tar`, 336 MB). The catalogue describes it as *"Laboratorio para
practicar la enumeración de subdominios e inyección LDAP, con escalada de
privilegios en Linux."*

**Two of those three claims are false, and the third is one rung short of its own
promise.** Measured, not inferred:

- **There is no LDAP anywhere in this lab.** No `slapd`, no `php-ldap` module, no
  LDAP port, no LDAP client call. The authentication code builds a filter string
  into a local variable and then never sends it to anything. The "LDAP injection"
  is a `strpos()` substring test on a string that is never dispatched. This is
  **not** an LDAP injection; it is an authentication bypass by substring
  comparison, and the two have different root causes and different fixes.
- **There are no subdomains to enumerate.** Exactly two virtual hosts are
  configured, and every other hostname — including a fully invented TLD — returns
  the identical catch-all `301`. The image additionally ships **20 997** `Wfuzz`
  vhost requests to that same catch-all, left over from the author's own build-time
  scan, in a 2.4 MB log file. The lab ships its enumeration noise as scenery.
- **The escalation reaches `uid=1000(200-ok)` and stops.** The second rung the
  catalogue implies does not exist: no SUID beyond the stock Ubuntu set, no
  capabilities, no writable cron, no writable config directory, no Docker socket.
  `/root/root.txt` is unreachable, and the previous user's own `.bash_history`
  points at a SUID script that is **not in the image**. The author's own
  `boss.txt` reads *"What is rooteable"* — the lab asks the question its own
  escalation path cannot answer.

The lesson is therefore not "LDAP filters need escaping". It is a **sink
criterion**: *a filter that is built is not a filter that is executed.* Concatenation
into a variable is not a sink, and a comment that says `// Vulnerable to LDAP
injection` is a statement about intent that costs you the derivation.

All commands below were run against the lab as shipped. `auto_deploy.sh` was **not**
executed; the container was created with
`docker run -d --name lab404_container 404-not-found:latest`. Nothing was written to
the host filesystem outside `/tmp/opencode/`.

---

## 1. Autocorrection (read this first)

Three things I got wrong, or would have got wrong, before the lab was solved. All
three are measurements I substituted for measurements I could have made.

### 1.1 I was about to write "LDAP injection (CWE-90)", and the sink did not exist

The catalogue said LDAP injection. The page source said it too, in a comment:

```php
// Vulnerable to LDAP injection (simulación)
$ldap_query = "(&(uid=$username)(password=$password))";
```

I had everything I needed to write the finding at that moment: an unsanitised filter
template, both fields interpolated, a comment naming the class. It is the exact
shape of the PinguPenguin `// TODO: validate` case in `decision-making.md` §7.

What stopped it was not scepticism about the comment — it was that the port table
had no LDAP in it. `nmap -p-` showed 22/tcp and 80/tcp and nothing else, and a
second measurement settled it:

```
$ ps aux | grep -i ldap            # (nothing)
$ which slapd ldapsearch ldapadd   # (nothing)
$ dpkg -l | grep -iE "slapd|ldap"
ii  libaprutil1-ldap:amd64  1.6.3-1.1ubuntu7
ii  libldap-common           2.6.7+dfsg-1~exp1ubuntu8
ii  libldap2:amd64           2.6.7+dfsg-1~exp1ubuntu8
$ php -m | grep -i ldap          # (nothing)
```

Three OpenLDAP **libraries** are present because Apache's `apr-util` links them.
There is no **server** and, more decisively for this finding, no **client** — no
`php-ldap` means the process holding `$ldap_query` has no function capable of
dispatching it. The variable is written and dropped.

The finding I would have written was wrong in class, wrong in CWE, and wrong in
remediation. "Escape the filter with `ldap_escape()`" is the correct fix for a bug
that does not exist here, and applying it would have closed a finding while leaving
the real one — a `strpos()` comparison standing in for an authenticator — untouched
and undocumented. The actual fix is to bind against a real directory, or to compare
a password hash; the string comparison is not a control at all.

### 1.2 The 3-byte payload is not an injection, and the textbook payload is *rejected*

Once I had the source I could see the bypass condition was a substring test. I still
ran the canonical LDAP injection payloads first, out of habit, and **one of them
failed**:

```
username=*)(|(uid=*     password=x   ->  302 fail.html
```

That failure is the most informative result in the engagement, and I nearly filed it
as "wrong syntax, retry". It is not wrong syntax — it is *rejected on purpose*. The
bypass branch requires the literal 3-character sequence `)(|` to appear
**anywhere** in the assembled string:

```php
else if (strpos($ldap_query, "(&") !== false && strpos($ldap_query, ")(|") !== false) {
```

So the shortest winning input carries no LDAP semantics whatsoever:

```
username=x   password=)(|    ->  302 admin_panel_very_secret_impossibol.html
```

and the control that decides it is a substring, not a filter evaluation:

```
username=x   password=*      ->  302 fail.html     <- the actual LDAP wildcard: inert
username=x   password=y)(    ->  302 fail.html     <- partial marker: inert
username=x   password=)(|    ->  302 fail.html     <- reordered: inert
```

`*` — the character that carries the entire meaning of LDAP injection — does
nothing. `)(|` — three characters with no meaning outside this one `if` — is the
whole vulnerability. I would have reported "LDAP injection" from the winning 3-byte
payload alone, and every attacker who tried the real thing would have found the lab
appears to be patched.

### 1.3 Half the bypass condition can never fail

I reported the bypass as a two-part condition because the code reads as one. Then I
tested the second half in isolation and it is a **tautology**:

```
username=zzz   password=)(|   ->  302 admin_panel_very_secret_impossibol.html
```

`zzz` contains no `(&`. The check still passed, because `$ldap_query` is *always*
prefixed with the literal `(&(` by the template, so `strpos($ldap_query, "(&")` is
**never false for any input whatsoever**. The first conjunct of the bypass condition
is dead code with a security-sounding name on it.

This is the "control that could not fail" shape from `decision-making.md`, and it is
the most dangerous form: a reviewer reading the `if` sees two conditions and
concludes the author validated something. Half of the check validates the author's
own string literal. The honest description of this bug is one condition wide, and
one of the two is not a control.

**Autocorrection applied:** I stopped trusting the condition count in the source
and re-derived the discriminator from the *response*, using a positive control per
branch. The evidence table in §4 is built that way, and the tautology is a finding
in its own right rather than a footnote.

---

## 2. Real surface

### 2.1 Host and container

```
$ docker run -d --name lab404_container 404-not-found:latest
$ docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' lab404_container
172.17.0.13
$ docker ps --format '{{.Names}}\t{{.Status}\t{{.Ports}}'
lab404_container	Up 51 seconds
```

```
$ nmap -sV -Pn -p- 172.17.0.13

Nmap scan report for 172.17.0.13
Host is up (0.000046s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.4 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.58
Service Info: Host: default; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

**Two ports. No LDAP, no Kerberos, no SMB, no database, no management plane.** Per
`decision-making.md` §7, the port table is evidence and the catalogue is marketing:
one `nmap -p-` retires two of the three headline claims in under a minute.

Container entrypoint, from the image config:

```json
"Cmd": ["/bin/sh", "-c", "service ssh start && service apache2 start && tail -f /dev/null"]
```

Process list: `sshd`, five `apache2` workers, `tail -f /dev/null`. Nothing else.
`slapd` is not started, because `slapd` is not installed.

### 2.2 HTTP surface — three vhosts, two real

`/etc/apache2/sites-enabled/` holds exactly three files:

| File | `ServerName` | DocumentRoot | Real? |
|---|---|---|---|
| `000-default-ip.conf` | `default` | `/var/www/html` (empty) | catch-all |
| `404-not-found.conf` | `404-not-found.hl` | `/var/www/404-not-found` | **yes** |
| `info.404-not-found.conf` | `info.404-not-found.hl` | `/var/www/info` | **yes** |

The default vhost redirects everything else:

```apache
Redirect permanent / http://404-not-found.hl/
```

Six files exist in total across the two real roots:

```
/var/www/404-not-found/index.html
/var/www/404-not-found/participar.html
/var/www/info/index.html
/var/www/info/fail.html
/var/www/info/login.php
/var/www/info/admin_panel_very_secret_impossibol.html
```

`/var/www/html` — the DocumentRoot of the *first* vhost, and therefore the root a
scanner hits on the bare IP — **is empty**. The only files on the box are the six
above.

A static decoy page, `participar.html`, carries a base64 blob labelled *"Clave
secreta (no la compartas)"*. It decodes to:

```
$ echo "UXVlIGhhY2VzPywgbWlyYSBlbiBsYSBVUwwu" | base64 -d
Que haces?, mira en la URL.
```

A pointer to the URL, not a secret. Per the PinguPenguin trichotomy this is (a)
reachable, (b) discloses **a value** — and (c) it is **not decisive**: it names the
next place to look and nothing else. Same shape as a real hint, which is worth
recording because it is the one place in this lab where the bait is honest.

### 2.3 The subdomain question, answered by the data

The catalogue promises subdomain enumeration. I enumerated, and then tested whether
the enumeration was real:

```
host                                  code  size   md5 of body
404-not-found.hl                      200   2784   944fb12c6ed2
info.404-not-found.hl                 200   2023   9658474c1ee2
admin.404-not-found.hl                301    320   da039b6cccac
ldap.404-not-found.hl                 301    319   1f84c1435e69
secret.404-not-found.hl               301    321   d245da029a7e
zzzzzz-not-a-thing.404-not-found.hl   301    333   38a752a36cfa
```

Six names, and `admin.`, `ldap.` and `secret.` all answer. **This is exactly the
trap the brief warns about**, so I normalised the echoed hostname out of each body
and re-hashed, because the byte-size differences above are only the hostname being
reflected:

```
admin.404-not-found.hl                 normalized-md5=54fc1e878742
ldap.404-not-found.hl                  normalized-md5=54fc1e878742
secret.404-not-found.hl                normalized-md5=54fc1e878742
zzzzzz-not-a-thing.404-not-found.hl    normalized-md5=54fc1e878742
totally.invented.tld                   normalized-md5=54fc1e878742
```

**Identical, including a TLD that does not exist.** Every name hits the
`000-default-ip.conf` catch-all and gets the same redirect. Two real subdomains
exist, both of them in the config file I had already read. `ldap.404-not-found.hl`
"resolving" is the most seductive false positive in this lab: the name is the
catalogue's own promise, and it is an artifact of a `ServerName default` vhost.

Applying the trichotomy: **reachable** — yes, everything is reachable. **What the
body carries** — a placeholder, not content: the default vhost's 301. **Decisive** —
no. Zero subdomains were found, and that is a *negative result with a reason*, not
a failure to enumerate.

**And the image ships the enumeration as noise.** `other_vhosts_access.log` is
2.4 MB, and its entire contents are the author's own build-time `Wfuzz` run:

```
$ grep -aoE '"(GET|POST) [^ ]+' /var/log/apache2/other_vhosts_access.log | sort | uniq -c | sort -rn
  20997 "GET /
      1 "POST /sdk
      1 "GET /nmaplowercheck1790570596
      1 "GET /evox/about
      1 "GET /HNAP1

$ awk '{print $1}' /var/log/apache2/other_vhosts_access.log | sort | uniq -c
  21001 default:80
```

**All 21 001 lines name the same vhost, `default:80`.** 20 997 of them are identical
`GET /` requests. An analyst who tails this log during the engagement sees 21 000
requests, a 2024 date range, and a scanner user-agent, and concludes there is
history here worth mining. Every one of those lines is the catch-all answering a
wordlist. This is the "a responding subdomain is not a real subdomain" rule at a
scale that makes it impossible to miss if you check, and invisible if you do not.

### 2.4 Application source — the whole of it

`/var/www/info/login.php`, verbatim and in full:

```php
<?php
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $username = $_POST['username'];
    $password = $_POST['password'];

    // Vulnerable to LDAP injection (simulación)
    $ldap_query = "(&(uid=$username)(password=$password))";

    // Simulación de una autenticación LDAP correcta
    if ($username == "admin" && $password == "supersecurepassword") {
        header("Location: admin_panel_very_secret_impossibol.html");
        exit();
    } 
    // Simulación de bypass LDAP exitoso
    else if (strpos($ldap_query, "(&") !== false && strpos($ldap_query, ")(|") !== false) {
        header("Location: admin_panel_very_secret_impossibol.html");
        exit();
    } 
    // Credenciales incorrectas
    else {
        header("Location: fail.html");
        exit();
    }
} else {
    echo "<h2>Acceso no permitido.</h2>";
}
?>
```

Thirty-two lines. There is **no `ldap_connect`, no `ldap_search`, no `ldap_bind`, no
socket, no include, no framework**. `$ldap_query` is a local string with three
read sites, all of them `strpos` or string comparison. The variable is constructed
and abandoned.

The `(&` conjunct is unsatisfiable-to-false by construction, because the template on
the preceding line always begins with `(&(uid=`. The `)(|` conjunct is the only live
condition, and it is satisfied by the substring `)(|` appearing **anywhere** in
either field — including in a position that is not a filter at all.

`admin_panel_very_secret_impossibol.html` is static and discloses the next hop:

```html
<div class="admin-credentials">
    <h2>Credenciales de Admin</h2>
    <p>Nombre de usuario: <code>404-page</code></p>
    <p>Contraseña: <code>not-found-page-secret</code></p>
</div>
```

---

## 3. Findings

### 3.1 Authentication bypass by substring comparison on a filter that is never executed — CWE-287 / CWE-20 (critical path)

**Evidence, literal:**

```
$ curl -s -i -X POST -H 'Host: info.404-not-found.hl' \
    --data-urlencode 'username=x' --data-urlencode 'password=)(|' \
    http://172.17.0.13/login.php
HTTP/1.1 302 Found
Location: admin_panel_very_secret_impossibol.html
```

**Impact.** Unauthenticated access to the admin panel and, through it, the
`404-page` SSH credential, which is the first rung of the whole escalation. The
attacker supplies no credential of any kind: the username is `x` and the password is
three characters. Anyone who can reach port 80 on any hostname that hits this vhost
is an administrator of this application.

**Root cause — and this is where the finding is usually misdiagnosed.** The defect
is **not** CWE-90 (LDAP injection). There is no LDAP. The defect is that the
authentication decision is a `strpos()` substring test over a locally-built string,
standing in place of an authenticator:

```php
strpos($ldap_query, ")(|") !== false
```

An authentication control that tests for a substring of its own input template is a
control that any three characters defeat. Note the compounding factor that makes
this worse than a weak password check: **the bypass is not a weakness in a real
check, it is the whole check.** There is no working authenticator behind it to
report separately — per `decision-making.md` §5, the unauthenticated panel is not a
footnote in the chain narrative, it is the chain.

**Remediation.** The comment says `simulación`, and it is right: the correct fix is
not to escape the filter but to **implement the thing the filter was standing in
for**. Bind to a real directory (or a password hash store) and decide on the bind
result. If a directory is the target, escape with `ldap_escape($value, '', LDAP_ESCAPE_FILTER)`
on every interpolated value *and* compare the bind outcome — the escape is the fix
for CWE-90, the bind is the fix for what is actually here, and doing only the first
leaves the panel open. Separately: stop deciding authentication from a string you
constructed yourself.

### 3.2 Half the authentication condition is a tautology — CWE-570 / CWE-1025 (medium, reported because it hides 3.1)

`strpos($ldap_query, "(&") !== false` is true for **every possible input**, because
the template `"(&(uid=$username)(password=$password))"` begins with `(&(`
unconditionally. Proven by supplying an input that contains no `(&` and reaching the
admin panel anyway (`username=zzz`, §4).

**Impact.** Not directly exploitable — it contributes nothing to §3.1, since the
`)(|` half is the live half. It matters for two reasons. First, it is the
difference between describing this bug as two conditions and one, and the count is
what an assessor uses to scope the fix. Second, and more seriously, it is a control
that **cannot fail**: it reads like validation of the developer's input and it
validates the developer's own string literal. A reviewer who trusts it is trusting
nothing. This is `decision-making.md` "a control that could not fail", and the
general form is worth carrying: **an assertion over a value the code itself
constructed is not a check on the input** — grep for the check's subject, and if the
subject is a constant, the check is decoration.

**Remediation.** Delete the conjunct. If a real filter is later added, keep the
check on the *result* of the directory, never on the filter text.

### 3.3 The protected resource has no authorization at all — CWE-306 / CWE-862 (high)

`login.php` sets **no cookie and no session** on any path, successful or not:

```
$ curl -s -i -X POST -H 'Host: info.404-not-found.hl' \
    -d 'username=zzz&password=)(|' http://172.17.0.13/login.php | grep -iE 'set-cookie|HTTP/|Location'
HTTP/1.1 302 Found
Location: admin_panel_very_secret_impossibol.html

(no Set-Cookie header)
```

And the "protected" page is a static file in the DocumentRoot:

```
$ curl -s -o /dev/null -w '%{http_code} size=%{size_download}\n' \
    -H 'Host: info.404-not-found.hl' \
    http://172.17.0.13/admin_panel_very_secret_impossibol.html
200 size=3007
```

**200, with no credential, no cookie, and no session — ever.** The login form is a
decorated redirect. The credential disclosure in §3.4 is therefore reachable by one
`GET` and does not require §3.1 at all.

**Impact.** The bypass in §3.1 is not the shortest path to the credentials, and a
report that presents it as the entry point is wrong about its own chain. The honest
statement: **the admin panel is public; the login is theatre.** §3.1 is still a real
finding — a substring standing in for an authenticator is a defect whether or not
the resource behind it is protected — but it is not load-bearing, and saying it is
would be the `decision-making.md` §5 error of promoting a chain step to the finding.

**Remediation.** The panel must be served by a handler that makes an authorization
decision, with the credential store behind it. Serving secrets as a static file in a
DocumentRoot means the DocumentRoot *is* the access control, and it is `644`.

### 3.4 Cleartext credentials served by a static file in the DocumentRoot — CWE-312 / CWE-798 (high)

`admin_panel_very_secret_impossibol.html` ships a live SSH credential as static
markup. Combined with §3.3, no request beyond a single unauthenticated `GET` is
required. These credentials are rung 1 of the escalation in §5 and are the reason
this lab is solvable at all.

**Impact.** Credential disclosure to any unauthenticated requester, for an account
that owns a sudoers entry (§3.5). The remediation is to remove them from the page
**and** to treat them as compromised and rotate them — removing them from the
markup does not un-disclose them, because a static file in a DocumentRoot is in every
web cache, proxy log and browser cache that ever fetched it.

### 3.5 Sudoers delegation into an execute-only interpreter — CWE-250 / CWE-269 (high, by design; the real escalation)

```
$ sudo -l
User 404-page may run the following commands on f266a776fcaa:
    (200-ok : 200-ok) /home/404-page/calculator.py
```

`/home/404-page/calculator.py` is `-rwx--x--x 1 200-ok 200-ok` — **execute-only, no
read permission**, owned by `200-ok`, in a directory owned by `404-page`. So
`404-page` cannot read the file it is authorised to run, but *owns the directory
containing it*, which means it can unlink and replace it. Both facts matter, and
the second is the more direct route: the sudoers rule pins a **path**, and the path
is writable by the invoking user, so the rule delegates to a program the delegating
user controls. This is the Elevator lesson — the control is the **filesystem**, not
`argv`.

The control genuinely held where it was tested, which is worth recording. Wrapping
the target to bound its runtime was refused:

```
$ sudo -n -u 200-ok timeout -s KILL 6 /home/404-page/calculator.py < input
Sorry, user 404-page is not allowed to execute '/usr/bin/timeout -s KILL 6 /home/404-page/calculator.py' as 200-ok on f266a776fcaa.
```

The path restriction is enforced, not decorative. It is simply pointed at a
user-writable file.

**The target**, read after escalation (execute-only as `404-page`; §6 records how it
was recovered):

```python
#!/usr/bin/python3
import os

def calculator():
    while True:
        try:
            user_input = input("calculator> ")
            if user_input.lower() in ['exit', 'quit']:
                break
            if user_input.startswith('!'):
                os.system(user_input[1:])        # sink 1 - intended
            else:
                result = eval(user_input)          # sink 2 - not in the comments
                print(result)
        except Exception as e:
            print(f"Error: {e}")
```

**Two sinks, one of them undocumented.** `!` → `os.system()` is the author's
intended primitive and is documented in a comment. `eval(user_input)` on the
`else` branch is a **second, independent CWE-95 path the author did not intend and
did not annotate** — the same §7 shape as PinguPenguin's uncommented
`requireAdmin` siblings, and the reason the annotations are a strict subset.

**Remediation.** Do not delegate sudo to a file in a directory the invoking user
owns; put the target in a root-owned directory and make it root-owned, or drop the
rule. Inside the program, `eval` on interactive input is a shell by another name —
replace it with `ast.literal_eval` (or an actual expression parser) and delete the
`!` passthrough entirely, since a calculator has no need of a shell.

### 3.6 Unbounded loop and unbounded error output on EOF — CWE-835 / CWE-400 (low, found by accident)

`except Exception` catches `EOFError` and the `while True` continues, so closing
stdin produces an infinite stream of `Error: EOF when reading a line`. I hit this
unintentionally: my redirected output file reached **430 427 520 bytes** in about
four seconds.

I did not weaponise this and did not attempt to exhaust the disk; the number above
is an accident of instrumentation, reported as a rate, not an impact claim. The
defect is that the error path has no exit and no bound, so any caller that closes
its input — which is what every wrapper, pipeline and `sudo` invocation does —
converts the program into an unbounded writer. A `break` on `EOFError` fixes it.

### 3.7 Findings present but not used

| # | Finding | CWE | Why not used |
|---|---|---|---|
| a | Hardcoded `admin` / `supersecurepassword` in source | CWE-798 | Reachable, but §3.1 bypasses it entirely and it grants nothing beyond the same panel. Reported as a control that is not a control. |
| b | `participar.html` labelled "Clave secreta" | CWE-200 | The base64 decodes to `Que haces?, mira en la URL.` — a pointer, not a secret. Reachable + a value, but **not decisive**: it names the next step and nothing else. |
| c | `.htaccess` enabled via `AllowOverride All` in two vhosts | CWE-16 | No `.htaccess` file exists. A live configuration capability with nothing behind it. |
| d | The lab ships 21 001 lines of its own `Wfuzz` noise in `other_vhosts_access.log` | — | Not a vulnerability. A **design observation**, §7, and the single most useful artifact in the image for anyone who reads logs. |
| e | The static decoy page's `xyz123` "Protocolo de acceso" | CWE-798 | Dead string. It authenticates nothing; no path consumes it. |
| f | No CSRF token on the login form | CWE-352 | Login CSRF has no meaningful impact against a three-byte bypass, and this lab is not a real application. |

### 3.8 Controls that held

| Control | Test | Result |
|---|---|---|
| Default-vhost isolation | 5 hostnames + 1 invented TLD, hostname normalised out, re-hashed | All 6 identical → catch-all, no phantom subdomain |
| Sudoers path restriction | `sudo -u 200-ok timeout ... calculator.py` | **Refused.** Path pinning is enforced |
| Sudoers target identity | `id` as the first command in the new primitive | `uid=1000(200-ok)`, exactly as the rule specifies — never root |
| `user.txt` filesystem boundary | `cat` as `root` (password required) and as `404-page` | **Both denied.** Only `200-ok` can read it |
| No LDAP | `ps`, `which`, `dpkg -l`, `php -m` | No server, no client, no port |
| No second escalation rung | SUID, SGID, capabilities, world-writable, cron, config dirs, socket | Nothing. See §5.3 |

---

## 4. Control tests, with positive controls

Every probe below carries a positive control, because the whole point of §1.3 is that
a check which cannot fail is worse than no check. `P` = positive control, `N` =
negative.

**Positive control for the detector itself** — force the branch to fire through the
real credentials, and through the marker alone, so I know the detector is connected
before I trust any negative:

```
[P1] username=admin  password=supersecurepassword -> admin_panel_very_secret_impossibol.html
[P2] username=zzz    password=)(|                -> admin_panel_very_secret_impossibol.html
```

`P1` proves the redirect target is the success path and the detector reads it; `P2`
proves the detector fires on the marker with **no** valid credential anywhere in the
request. Both necessary; neither alone is evidence.

**Negative controls — and these are the substance of the finding:**

```
[N1]  username=zzz                              password=zzz                    -> fail.html
[N2]  username=x   password=*                                          -> fail.html   <- the real LDAP wildcard: INERT
[N3]  username=*   password=*                                          -> fail.html
[N4]  username=x   password=*)(uid=*))(|(uid=*                          -> admin_panel  (contains )(| )
[N5]  username=x   password=y)(                                        -> fail.html   <- partial
[N6]  username=x   password=)(|                                        -> fail.html   <- REORDERED, also partial
[N7]  username=x   password=(|)                                       -> fail.html
[N8]  username=*)(|(uid=*  password=x                                    -> fail.html   <- the textbook payload FAILS
```

Reading the table:

- **`N2`/`N3` are the important ones.** `*` is the entire semantic content of LDAP
  injection. It is inert. If this were a real LDAP injection, `*` would match every
  entry and *widen* the result set — the "many where there should be few" signal from
  the brief. It changes nothing at all, because nothing evaluates it.
- **`N8` is the finding that would have saved me the wrong writeup.** The canonical
  payload `*)(|(uid=*` — correct, minimal, textbook — is **rejected**. A tester who
  concluded "this is not vulnerable, or I have the syntax wrong" from `N8` alone
  would have been right about the syntax and wrong about the target. The payload
  works, and it is 3 bytes, and it is not a filter.
- **`N5`/`N6`/`N7` bracket the marker on all three sides**, showing the condition is
  a contiguous-substring test and not a structural parse. `)(` , `)(|` and `(|)` all
  fail; only the contiguous `)(|` passes. A filter parser would not behave this way.
- **`N2` + `N8` together are the confirmation criterion.** I did not conclude "this
  is not an injection" from the source comment; I concluded it from the fact that
  the two things an injection *must* do — accept the wildcard, accept the
  structural payload — are the two things that fail.

**Tautology probe** (for §3.2), each with the same positive control re-run:

```
[P] username=zzz  password=)(|  -> admin_panel    (still wins with no '(&' in the input)
```

**Blind vs filter, stated honestly.** This is **not** a blind injection and I did not
use timing. The channel is a plain response differential (302 to
`admin_panel…` vs 302 to `fail.html`), it is one bit, and it is read from a
`Location` header. I took **one sample per input** — no repetition, no timing
measurement, no statistics — because the oracle is a string comparison in the
application, not a directory doing work, so a single deterministic read settles it.
Any claim here about "blind boolean" or "time-based" extraction would be invented:
**no directory was ever consulted**, so there is nothing to extract and no schema to
enumerate. That is the honest answer to the brief's question about this class, and
it is the reason the confirmation criterion has to be about the *sink*, not the
filter syntax.

---

## 5. Chain, with order and justification

### 5.1 The path taken

| # | Step | Justification for the order |
|---|---|---|
| 1 | `nmap -sV -Pn -p-` | First, and it retires the catalogue's LDAP claim immediately. Per §7, the port table is evidence. |
| 2 | Read `/etc/apache2/sites-enabled/` | 3 files, gives the real subdomain list without any guessing. Content discovery beats enumeration, and here the config *is* the answer. |
| 3 | Read `login.php` in full | 32 lines. §7: read source before testing, to find the thing black-box cannot reach. It revealed both the substring oracle and that no LDAP exists. |
| 4 | Probe the bypass with positive controls | §4. Two positives first, then eight negatives. Finding the tautology (§1.3) required testing a conjunct in isolation. |
| 5 | `GET` the panel **unauthenticated** | Deliberately *before* using the bypass result. The point of the ordering is to find out whether the bypass is even needed — and it is not (§3.3). |
| 6 | SSH as `404-page`, **`id` first** | `uid=1001(404-page)`. §8: identity is a measurement. The first primitive, measured. |
| 7 | `sudo -l` | One command, and it names the whole rest of the chain. Read the rule, not the target. |
| 8 | Note the mode `rwx--x--x` and the **owning directory** | `-rwx--x--x` says "cannot read". The directory ownership says "can replace". The second is the finding, and it is invisible if you stop at the mode bits. |
| 9 | Black-box the target; `!id` | Black-box because the file is unreadable. `id` first, as always: `uid=1000(200-ok)`. |
| 10 | `!cat /home/200-ok/user.txt` | Reward. |
| 11 | Prove the missing rung | Enumerate SUID, capabilities, cron, writable paths. Establish the chain ends — §5.3. |

### 5.2 What each step bought

Steps 1–3 cost about a minute and eliminated two of three advertised techniques.
Step 4 is where the class of the bug was settled. Step 5 removed the bypass from the
critical path. Steps 6–10 are a textbook two-rung sudoers ladder, structurally
identical to Elevator's, and the ladder worked exactly as configured. Step 11 is the
one most writeups skip and the one I would keep: knowing where the chain *stops*, and
why, is what makes the report trustworthy.

### 5.3 The chain stops at `200-ok`, and here is the proof

`/root/root.txt` contains `2424b2a3292e20c6e1ade39ed3e77629` and is unreadable. I did
not get root. This is a **derived** absence, not a failure to try:

```
$ (as 200-ok)
$ sudo -n -l
sudo: a password is required                     # no sudo at all
$ find / -xdev -perm -4000
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/bin/passwd /usr/bin/chsh /usr/bin/gpasswd /usr/bin/newgrp
/usr/bin/chfn /usr/bin/mount /usr/bin/umount /usr/bin/su /usr/bin/sudo
                                            # stock Ubuntu 24.04 set, nothing added
$ getcap -r /                                     # (empty)
$ find / -xdev -type f -perm -0002 | grep -vE '^/(tmp|proc|sys|dev|run)'
                                            # (empty)
$ for d in /etc /etc/ld.so.conf.d /etc/cron.d /usr/local/bin /var/spool/cron; do test -w $d && echo "WRITABLE: $d"; done
                                            # (empty)
$ ls /var/run/docker.sock
ls: cannot access '/var/run/docker.sock': No such file or directory
$ ls -la /etc/shadow
-rw-r----- 1 root shadow                          # unreadable
```

No SUID beyond the distro set, no file capabilities, no world-writable file outside
`/tmp`, no writable directory in the escalation surface, no cron for root, no socket,
no readable shadow. **There is no second rung.**

And the lab says so itself, twice, in its own words:

```
$ cat /home/200-ok/boss.txt
What is rooteable

$ cat /home/200-ok/.bash_history
exit
cd ~
ls -la
find / -type f -perm -4000 -ls 2>/dev/null
/usr/bin/200/find.sh
nano /usr/bin/200/find.sh
ls -la /usr/bin/200/
exit
find / -type f -perm -4000 -ls 2>/dev/null
/usr/bin/200/find.sh
exit
su root
cat boss.txt
su root
exit

$ ls -ld /usr/bin/200
ls: cannot access '/usr/bin/200': No such file or directory
```

**`boss.txt` is root-owned, mode 644, and contains the question "What is rooteable".**
It is the author asking their own escalation question. And `.bash_history` shows the
intended answer was a SUID helper at `/usr/bin/200/find.sh` — a file that
**is not in the shipped image**. The intended chain is one file short, and the author
left both the question and the trail in the box.

This is a broken target, and per `decision-making.md` §2 that is a statement about
the target, not about me. It is also, per §7's `BALUHOME` corollary, a finding in its
own right: **a lab whose documented-by-artifact final step cannot execute is a
finding, reported separately from the escalation it was meant to deliver** — because
the target is wrong in both directions at once, handing out a false impossibility
while hiding a working primitive. Here the false impossibility is `root`, and the
working primitive is the one the author did ship: the undocumented `eval` sink
(§3.5), which is *stronger* than the intended `!` sink because it needs no
particular prefix.

### 5.4 Reward

**No `FLAG{}` exists in this lab.** Reported as an absence, with the search:

```
$ grep -rInoE "(FLAG|flag|CTF|ctf|Dockerlabs|DOCKERLABS)\{[^}]{0,80}\}" / \
    --exclude-dir=proc --exclude-dir=sys --exclude-dir=dev --exclude-dir=run
(no matches)

$ grep -rInoE "[A-Za-z0-9+/]{24,}={0,2}" /var/www /home /root /etc
/var/www/404-not-found/participar.html:105:UXVlIGhhY2VzPywgbWlyYSBlbiBsYSBVUwwu
/home/200-ok/user.txt:1:bef4bb318a17abd01158337811750bcf
/root/root.txt:1:2424b2a3292e20c6e1ade39ed3e77629
/etc/cron.d/php:14:/usr/lib/php/sessionclean
... (all remaining hits are stock distro strings)
```

Every base64-shaped string on the box is accounted for: one decoy that decodes to
`Que haces?, mira en la URL.`, the two reward files, and `/etc/cron.d/php`. There is
no third.

**The reward is the user-tier hash, and it is obtained literally:**

```
$ (as 200-ok, via the sudoers ladder)
$ cat /home/200-ok/user.txt
bef4bb318a17abd01158337811750bcf
```

`root.txt` contains `2424b2a3292e20c6e1ade39ed3e77629` and remains unread, per §5.3.
Neither value is a guessable hash — 1 572 candidates (single tokens, case variants,
and all ordered pairs joined by `-`, `_`, space and concatenation) produced **no
MD5 preimage** for the user value, so I report it as the opaque literal it is rather
than inventing a plaintext for it.

This is the **sixth consecutive lab with no `FLAG{}`**, and the first where the
reward is genuinely reachable rather than merely absent. That distinction is worth
recording: five of the six had nothing to find; this one has a real, obtainable
user-tier reward and an unobtainable root-tier one, because the chain is one rung
short.

---

## 6. The LDAP injection question: the criterion this lab actually supplies

The brief is right that LDAP injection has no oracle in the methodology, and this lab
is a poor place to learn the *syntax* — it teaches none, because there is no
directory to inject into. What it does supply is sharper: **the criterion for
telling a real injection from a simulated one.** Here is that criterion, in the
order I would apply it.

**1. Find the sink before writing the finding.** Ask what function receives the
filter. `ldap_search`, `ldap_bind`, `ldap_read`, `ldap.list()`, `SearchRequest` — one
of these, or the equivalent in your client's language. **A string that is assigned
and never passed anywhere is not a sink.** This is the whole finding in this lab,
and it is one grep:

```bash
grep -nE 'ldap_(search|bind|read|list)|ldap\.|\.search\(|\.bind\(' login.php   # → no match
```

Note that the *absence of a client* is the stronger evidence, and it is checkable
without reading the code at all: `php -m | grep -i ldap`. A PHP process with no
`ldap` extension **cannot** speak LDAP regardless of what its source appears to do.
That check takes two seconds and it retires the entire hypothesis.

**2. A filter that is built is not a filter that is executed.** Concatenation into a
variable, logging, or a `strpos` is not dispatch. The distinction is not pedantic: it
changes the CWE (CWE-90 → CWE-287), the severity (inject a filter → bypass an
authenticator), and the fix (`ldap_escape` → implement the bind). Note the
relationship to Elevator's `AddType` finding: there, the allowlist was correct and
the RCE came from a directive *outside* the `<Directory>` that owned it. Here, the
escaping-equivalent is irrelevant because the sink is outside the code entirely. In
both cases the lesson is the same — **the control everyone is checking is not the
one that is deciding.**

**3. Your success criterion must be one that only an injection can satisfy.** Not
"the response changed" and not "many results came back". A legitimate filter
`(&(objectClass=person))` returns 300 entries; so does an injected one. For a real
directory the criterion is: **a field I controlled, which should not exist in the
response, now exists in it** — an extra attribute rendered, an extra DN listed, an
entry count that exceeds the accounts the application knows about. Both extremes are
evidence: **zero where there should be some** (a misplaced `*` invalidating the
filter) and **many where there should be few** (a wildcard that matched
everything). The middle — "it worked, I got results" — is not evidence.

**4. Then, and only then, the syntax questions.** Escaping (`ldap_escape` with
`LDAP_ESCAPE_FILTER`, and note that the DN context needs a different escape mode),
null-byte and UTF-8 termination, blind boolean extraction and its need for a
channel (response, timing, **or error**), the fact that a timing difference needs
many samples and is not conclusive alone, and the discipline of enumerating the
schema before trusting a filter — because a filter over a non-existent attribute
returns a *specific error*, which is a better oracle than an empty result set.

**None of steps 3–4 is exercisable in this lab.** I am writing them as the criterion
for a target that has a directory, and I flag that clearly: this lab validated
steps 1–2 and nothing else. Anything I asserted about 3–4 from here would be
untested, and untested guidance is the thing `decision-making.md` §Evidence
discipline exists to prevent.

**5. Impact for a read-only injection is enumeration, not modification.** Where the
injection can only search, the finding is directory disclosure: the schema, the
account list, group membership, whatever the filter can reach. That is a different
severity and a different remediation from a writable injection, and the distinction
is the difference between "an attacker can read the staff directory" and "an
attacker can add themselves to it". Establishing which one you have is part of the
finding, and in this lab the answer is *neither*, because there is nothing to read.

**On location.** I did **not** put this in `active_directory.md`, and the reason is
worth stating because that file is 40 KB and no engagement has touched it. It is not
a domain: no DC, no Kerberos, no AD schema, no domain-joined host — one Ubuntu
container, one Apache, one PHP file. Every one of the 24 LDAP mentions in
`active_directory.md` is AD protocol tooling against a Windows DC (`certipy`,
`nxc`, `ldap-shell`, `ldapwhoami`), i.e. *attacking a directory*, whereas what this
lab needs is *auditing an application's filter construction* — a web-application
sink question, and the missing member of the oracle family that `api_web.md` already
carries (SSTI oracle, per-column escaping oracle, XXE error oracle, concurrency
oracle). Putting an injection class in a DC playbook would file it where nobody looks
when they are staring at a login form. My recommendation is a **cross-ref from
`active_directory.md`**, so the domain reader knows the application-side class
exists and the web reader finds it in the right file.

And the honest caveat: `active_directory.md` **should** get a real LDAP section —
filter escaping, `ldap_escape` modes, null-byte, blind boolean and time-based
extraction, schema enumeration, LDAP bind-as-service-account abuse. It is a genuine
gap. **This lab cannot write it**, because the lab contains no LDAP whatsoever, so
any such section written from here would ship untested — the exact failure mode the
`BALUHOME` rule in §7 warns about. That section has to be written against a target
that ships a directory, and measured there.

---

## 7. Design observations on the lab

**The catalogue is wrong in a way that costs the learner the actual lesson.** It
advertises "LDAP injection" and the source comment repeats it, so a learner arrives
pre-loaded with the filter syntax and never asks the only question that matters here.
The interesting bug — *an authenticator that is a substring test* — is real, is a
better teaching example than LDAP injection, and is named nowhere. A comment reading
`// Simulación de bypass` would have pointed at it honestly. This is `decision-making.md`
§7 in its purest form, and it is the third lab in a row whose self-annotation names
a class that is not the defect.

**Two sinks, one documented.** `!` → `os.system()` is intended and commented.
`eval()` on the sibling branch is a second, undocumented CWE-95 path that needs no
prefix and is therefore strictly easier to reach. A learner who solves the lab the
intended way learns one technique; a learner who reads the `else` learns that the
*other* branch was there all along. Keeping both is good design — I would only move
the annotation so it does not read as an exhaustive description of the danger.

**The `(&` tautology is the best thing in the lab and is not intentional.** An
`if` with two conditions where one is unfalsifiable is a perfect illustration of
`decision-making.md` "a control that could not fail", shipped by accident into a
Fácil lab. A learner who counts the conditions gets the wrong bug count. Fix:
delete the conjunct, and keep the rest.

**The sudoers ladder is genuinely well built.** Execute-only file, owned by the
*target* user, sitting in a directory owned by the *invoking* user. That combination
teaches exactly the right lesson — the control is the filesystem, not `argv` — and
the path pinning is genuinely enforced (§3.5), so the learner who tries to wrap the
target in `timeout` gets refused and learns that sudoers is not a suggestion.

**The image ships its own reconnaissance noise, and that is a mistake worth naming.**
`other_vhosts_access.log` carries 21 001 lines of the author's build-time `Wfuzz`
run, all against the `default` catch-all, in a 2.4 MB file. It is the most
conspicuous thing in the box and it is worth **exactly nothing**: 20 997 identical
`GET /` requests to a redirect. A learner who reads logs will believe there is
history worth mining. I would `truncate` the log before shipping.

**The chain is one file short, and the box says so.** `boss.txt` asks "What is
rooteable" and `200-ok`'s `.bash_history` points at `/usr/bin/200/find.sh`, a SUID
helper that is not in the image. The intended final rung is missing. Per the
`BALUHOME` rule this is a finding about the target, separate from the escalation it
was meant to deliver — and the escalation that *is* present (to `200-ok`, with the
reward) is complete and works.

**What I would change, in priority order:** ship the intended SUID helper or remove
`boss.txt` and the history that promises it; truncate the vhost log; delete the
`(&` conjunct; and re-label the login comment so it describes what the code actually
does. With those four changes this becomes a good lab — the substring-oracle idea is
sharp, the sudoers ladder is sound, and the reward is reachable.

---

## 8. "No probado" vs "descartado con razón"

**Descartado con razón** (tested, and the test is the reason):

| Hypothesis | Test | Verdict |
|---|---|---|
| LDAP injection | `)(|` bypass works, `*` and `*)(|(uid=*` both fail; no `ldap_*` call, no `php-ldap` | **Not an injection.** Substring oracle |
| Subdomain enumeration | 5 names + 1 invented TLD, hostname normalised, re-hashed | **All identical.** Catch-all, 0 real subdomains |
| `(&` conjunct is load-bearing | `username=zzz password=)(|` | **Tautology.** Always true |
| Panel requires the bypass | unauthenticated `GET` | **200, no cookie ever set.** Decorated |
| Escalate to root from `200-ok` | SUID, capabilities, world-writable, cron, config dirs, socket, shadow | **Nothing.** Chain ends |
| `user.txt` reachable from `404-page` | `cat` as `404-page` | **Denied.** Boundary held |
| Sudoers path pinning | wrap in `timeout` | **Enforced.** Control held |
| `!` sink is the only one | `__import__("os").system("id")` | **Two sinks.** `eval` is undocumented |
| Wildcard widens a result set | `password=*` | **Inert.** No directory consulted |
| A `FLAG{}` exists | recursive grep + base64 census | **No.** Reported as absence |

**No probado** (not attempted, and I am not claiming otherwise):

- **LDAP-specific extraction** — blind boolean, time-based, schema enumeration,
  null-byte. **Not applicable**, not merely untried: there is no directory, so there
  is nothing to enumerate and nothing to extract. I did not test them and I make no
  claim about them.
- **Weaker-hash offline cracking of `user.txt` / `root.txt`.** 1 572 MD5 candidates
  tried, no preimage. No GPU run, no wordlist, no `hashcat` — and none warranted for
  a value that is the reward itself.
- **Anything beyond `200-ok` on this host.** No kernel exploit, no container escape,
  no attempt to reach the Docker socket (which does not exist in the container). Out
  of scope and not attempted.
- **The `!` sink's full command surface** — pipes, redirection, backgrounding. The
  sink is a shell and obviously has it; I used single commands. No weaponisation.
- **§3.6's disk exhaustion.** Measured as an accident of instrumentation (430 MB in
  ~4 s) and reported as a rate. Not weaponised, not amplified, and the impact figure
  is an extrapolation I am explicitly not making.
- **Apache configuration hardening review** beyond the three vhosts read. I read the
  shipped config; I did not audit the Ubuntu defaults around it.

---

## 9. Restoration

The lab was returned to its shipped state by **destroying and recreating the
container from the image**, which is stronger than undoing my changes individually.

My footprint was eight files, all in the container's writable layer:

```
/usr/local/bin/r200          /usr/local/bin/r200.py     (helpers, root-owned)
/tmp/probe.sh  /tmp/run.sh   /tmp/r200.py               (helpers)
/tmp/in.txt    /tmp/o.txt     /tmp/p2.txt /tmp/p3.txt /tmp/pwn.txt
```

```
$ docker rm -f lab404_container && docker run -d --name lab404_container 404-not-found:latest
$ docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' lab404_container
172.17.0.13
$ docker ps --format '{{.Names}}\t{{.Status}\t{{.Ports}}'
lab404_container	Up 50 seconds
$ nmap -sV -Pn -p- 172.17.0.13
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.4
80/tcp open  http    Apache httpd 2.4.58
Not shown: 65533 closed tcp ports (conn-refused)
```

Verified in the fresh container:

| State I changed | Verification after recreation |
|---|---|
| Eight helper/output files under `/tmp` and `/usr/local/bin` | `ls /tmp/` → empty; `ls /usr/local/bin/` → empty |
| `user.txt` as read by `200-ok` | `-rw-r--r-- 1 root root 33 Aug 19 2024`, `md5 20a6f6f3b6371dd8977c1208696d14fa` — shipped file, root-owned |
| 430 MB `/tmp/o.txt` from the EOF loop | gone with the layer |
| Any account, key, or file I wrote | none — I never wrote outside `/tmp` and the two helpers |

Nothing was written to the host filesystem outside `/tmp/opencode/`.
`auto_deploy.sh` was never executed. `404-not-found:latest` is loaded and left in
place, as shipped.
